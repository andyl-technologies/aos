//! Durable legacy and authority-bound effect records.
//!
//! Version 1 retains the original generic request format byte-for-byte.
//! Version 2 binds an ownership-gated effect to one exact publication draft
//! template. Attempt material is added only after publication selection and is
//! retained before any external broker call.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_core::{BrokerAudience, ObjectDigest, OperationId, RawPairedClockSample};
use sha2::{Digest as _, Sha256};

use super::{EffectReceipt, ReconcilerError};
use crate::{BrokerDispatchAttemptV1, BrokerDispatchSemanticIdentityV1};

pub(super) const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024;
pub(super) const MAXIMUM_RECEIPT_BYTES: usize = 64 * 1024;
pub(super) const MAXIMUM_DIAGNOSTIC_BYTES: usize = 4096;
const LEGACY_EFFECT_VERSION: u8 = 1;
const AUTHORITY_EFFECT_VERSION: u8 = 2;
const MAXIMUM_DISPATCH_PACKET_BYTES: usize = MAXIMUM_REQUEST_BYTES;
const BODY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-body.v2\0";
const BINDING_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-binding.v2\0";
const ATTEMPT_TOKEN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-attempt-token.v1\0";

/// Selects the sole fixed-function boundary allowed to execute an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EffectDomain {
    /// Typed systemd, cgroup, runtime, and freeze operations.
    Host = 1,
    /// Typed dataset, snapshot, hold, clone, quota, and destroy operations.
    Storage = 2,
    /// Descriptor-only mount preparation and namespace publication.
    Mount = 3,
    /// Typed network namespace, link, route, and packet-gate operations.
    Network = 4,
    /// Assignment ownership and fail-stop lease operations.
    Guardian = 5,
    /// Authenticated in-guest readiness, execution, and quiesce operations.
    Guest = 6,
}

impl EffectDomain {
    pub(super) fn from_byte(value: u8) -> Result<Self, ReconcilerError> {
        match value {
            1 => Ok(Self::Host),
            2 => Ok(Self::Storage),
            3 => Ok(Self::Mount),
            4 => Ok(Self::Network),
            5 => Ok(Self::Guardian),
            6 => Ok(Self::Guest),
            _ => Err(ReconcilerError::CorruptLedger("unknown effect domain")),
        }
    }

    pub(super) const fn from_audience(audience: BrokerAudience) -> Self {
        match audience {
            BrokerAudience::Host => Self::Host,
            BrokerAudience::Storage => Self::Storage,
            BrokerAudience::Mount => Self::Mount,
            BrokerAudience::Network => Self::Network,
        }
    }
}

/// Defines one ordered, idempotent request to a fixed effect boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectPlan {
    pub(super) domain: EffectDomain,
    pub(super) request: Vec<u8>,
    pub(super) authority: Option<AuthorityEffectBindingV2>,
}

impl EffectPlan {
    /// Constructs a bounded legacy effect plan from validated request bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for an empty or oversized request.
    pub fn new(domain: EffectDomain, request: Vec<u8>) -> Result<Self, ReconcilerError> {
        if request.is_empty() || request.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ReconcilerError::InvalidPlan(
                "invalid effect request length",
            ));
        }
        Ok(Self {
            domain,
            request,
            authority: None,
        })
    }

    /// Returns the fixed boundary selected for this effect.
    #[must_use]
    pub const fn domain(&self) -> EffectDomain {
        self.domain
    }

    /// Returns the exact idempotent request bytes sent to the executor.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub(super) fn authority(&self) -> Option<&AuthorityEffectBindingV2> {
        self.authority.as_ref()
    }
}

/// Freezes one exact draft-derived broker effect for gated admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBoundEffectPlanV2 {
    plan: EffectPlan,
    source_draft_digest: ObjectDigest,
    audience: BrokerAudience,
    template_digest: ObjectDigest,
    descriptor_free: bool,
}

impl AuthorityBoundEffectPlanV2 {
    pub(crate) fn from_template(
        source_draft_digest: ObjectDigest,
        audience: BrokerAudience,
        method: BrokerMethod,
        template_digest: ObjectDigest,
        body: &[u8],
        semantics: BrokerDispatchSemanticIdentityV1,
        descriptor_free: bool,
    ) -> Result<Self, ReconcilerError> {
        if body.is_empty() || body.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ReconcilerError::InvalidPlan(
                "invalid authority effect body",
            ));
        }
        let domain = EffectDomain::from_audience(audience);
        let body_digest = effect_body_digest(body);
        let semantic_digest = crate::dispatch::semantic_identity_digest(semantics);
        Ok(Self {
            plan: EffectPlan {
                domain,
                request: body.to_vec(),
                authority: Some(AuthorityEffectBindingV2 {
                    source_draft_digest,
                    audience,
                    method,
                    template_digest,
                    body_digest,
                    semantic_digest,
                    descriptor_free,
                    operation_id: OperationId::from_bytes([0; 16]),
                    step: 0,
                    digest: ObjectDigest::from_bytes([0; 32]),
                }),
            },
            source_draft_digest,
            audience,
            template_digest,
            descriptor_free,
        })
    }

    /// Returns the publication draft that supplied the exact template.
    #[must_use]
    pub fn source_draft_digest(&self) -> ObjectDigest {
        self.source_draft_digest
    }

    /// Returns the exact selected dispatch-template digest.
    #[must_use]
    pub fn template_digest(&self) -> ObjectDigest {
        self.template_digest
    }

    /// Returns the broker audience derived from the selected template.
    #[must_use]
    pub fn audience(&self) -> BrokerAudience {
        self.audience
    }

    /// Returns the exact deadline-free request body committed by the template.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        &self.plan.request
    }

    pub(super) fn is_supported_host_apply(&self) -> bool {
        matches!(self.audience, BrokerAudience::Host)
            && matches!(self.plan.authority.as_ref(), Some(binding) if matches!(binding.method, BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME))
            && self.descriptor_free
    }

    pub(super) fn into_inner(mut self, operation_id: OperationId, step: u32) -> EffectPlan {
        if let Some(binding) = &mut self.plan.authority {
            binding.operation_id = operation_id;
            binding.step = step;
            binding.digest = effect_binding_digest(
                operation_id,
                step,
                binding.source_draft_digest,
                binding.audience,
                binding.method,
                binding.template_digest,
                binding.body_digest,
                binding.semantic_digest,
            );
        }
        self.plan
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorityEffectBindingV2 {
    pub(super) operation_id: OperationId,
    pub(super) step: u32,
    pub(super) source_draft_digest: ObjectDigest,
    pub(super) audience: BrokerAudience,
    pub(super) method: BrokerMethod,
    pub(super) template_digest: ObjectDigest,
    pub(super) body_digest: ObjectDigest,
    pub(super) semantic_digest: ObjectDigest,
    pub(super) descriptor_free: bool,
    pub(super) digest: ObjectDigest,
}

/// Supplies advisory clock facts used to attenuate one durable broker attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityEffectAttemptTimingV1 {
    clock: RawPairedClockSample,
    deadline_boottime_nanoseconds: u64,
}

impl AuthorityEffectAttemptTimingV1 {
    /// Constructs timing input checked against the selected signed authority.
    #[must_use]
    pub const fn new(clock: RawPairedClockSample, deadline_boottime_nanoseconds: u64) -> Self {
        Self {
            clock,
            deadline_boottime_nanoseconds,
        }
    }

    pub(super) const fn clock(self) -> RawPairedClockSample {
        self.clock
    }

    pub(super) const fn deadline(self) -> u64 {
        self.deadline_boottime_nanoseconds
    }
}

/// Carries the exact broker request made durable before external I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAuthorityEffectV2 {
    binding_digest: ObjectDigest,
    publication_digest: ObjectDigest,
    preparation_wall_seconds: i64,
    preparation_boottime_nanoseconds: u64,
    attempt: BrokerDispatchAttemptV1,
}

impl PreparedAuthorityEffectV2 {
    pub(crate) const fn new(
        binding_digest: ObjectDigest,
        publication_digest: ObjectDigest,
        preparation_clock: RawPairedClockSample,
        attempt: BrokerDispatchAttemptV1,
    ) -> Self {
        Self {
            binding_digest,
            publication_digest,
            preparation_wall_seconds: preparation_clock.wall_seconds(),
            preparation_boottime_nanoseconds: preparation_clock.boottime_nanoseconds(),
            attempt,
        }
    }

    pub(crate) const fn from_durable_parts(
        binding_digest: ObjectDigest,
        publication_digest: ObjectDigest,
        preparation_wall_seconds: i64,
        preparation_boottime_nanoseconds: u64,
        attempt: BrokerDispatchAttemptV1,
    ) -> Self {
        Self {
            binding_digest,
            publication_digest,
            preparation_wall_seconds,
            preparation_boottime_nanoseconds,
            attempt,
        }
    }

    /// Validates Host completion bytes against this exact persisted Apply.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] when the receipt is
    /// malformed or does not name the Apply request's exact fence and handle.
    pub fn validate_host_receipt(
        &self,
        bytes: Vec<u8>,
    ) -> Result<ValidatedHostEffectReceiptV1, ReconcilerError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid Host effect receipt length",
            ));
        }
        aos_sandbox_protocol::validate_runtime_effect_receipt_for_apply(
            &bytes,
            self.attempt.body(),
        )
        .map_err(|_| ReconcilerError::InvalidExecutorOutput("invalid Host effect receipt"))?;
        Ok(ValidatedHostEffectReceiptV1 {
            bytes,
            binding_digest: self.binding_digest,
            attempt_digest: attempt_token_digest(&self.attempt),
        })
    }

    pub(crate) const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the exact current publication selected for this attempt.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.publication_digest
    }

    /// Returns the byte-exact deadline-bearing broker attempt.
    ///
    /// Its packet is the original Apply carrier retained for either direct
    /// transmission or construction of an authenticated effect query after a
    /// crash or ambiguous response.
    #[must_use]
    pub const fn attempt(&self) -> &BrokerDispatchAttemptV1 {
        &self.attempt
    }

    pub(crate) const fn preparation_wall_seconds(&self) -> i64 {
        self.preparation_wall_seconds
    }

    pub(crate) const fn preparation_boottime_nanoseconds(&self) -> u64 {
        self.preparation_boottime_nanoseconds
    }
}

/// Carries a Host completion receipt validated against one exact persisted Apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostEffectReceiptV1 {
    bytes: Vec<u8>,
    binding_digest: ObjectDigest,
    attempt_digest: ObjectDigest,
}

impl ValidatedHostEffectReceiptV1 {
    pub(super) fn into_effect_receipt_for(
        self,
        prepared: &PreparedAuthorityEffectV2,
    ) -> Result<EffectReceipt, ReconcilerError> {
        if self.binding_digest != prepared.binding_digest
            || self.attempt_digest != attempt_token_digest(prepared.attempt())
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "Host effect receipt belongs to another durable attempt",
            ));
        }
        Ok(EffectReceipt(self.bytes))
    }
}

/// Reports authenticated Host observation for one exact persisted Apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityEffectObservationV2 {
    /// The Host durably proves the exact request is absent.
    Absent,
    /// The Host has admitted the exact request but has not completed it.
    Pending,
    /// The Host completed the exact request with validated receipt bytes.
    Applied(ValidatedHostEffectReceiptV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum EffectState {
    Planned,
    Applying {
        attempt: u32,
        diagnostic: String,
    },
    Applied {
        attempt: u32,
        receipt: EffectReceipt,
    },
    PermanentlyBlocked {
        attempt: u32,
        diagnostic: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EffectLedgerRecord {
    pub(super) plan: EffectPlan,
    pub(super) state: EffectState,
    pub(super) dispatch: Option<PreparedAuthorityEffectV2>,
}

pub(super) fn encode_effect(record: &EffectLedgerRecord) -> Result<Vec<u8>, ReconcilerError> {
    let (state, attempt, receipt, diagnostic) = state_parts(&record.state);
    validate_lengths(&record.plan, receipt, diagnostic)?;
    let request_length = u32::try_from(record.plan.request.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect request exceeds bounds"))?;
    let receipt_length = u32::try_from(receipt.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect receipt exceeds bounds"))?;
    let diagnostic_length = u16::try_from(diagnostic.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect diagnostic exceeds bounds"))?;
    let dispatch_shape_valid = if record.plan.authority.is_some() {
        matches!(
            (&record.state, &record.dispatch),
            (EffectState::Planned, None)
                | (EffectState::Applying { .. }, Some(_))
                | (EffectState::Applied { .. }, Some(_))
                | (EffectState::PermanentlyBlocked { .. }, Some(_))
        )
    } else {
        record.dispatch.is_none()
    };
    if !dispatch_shape_valid {
        return Err(ReconcilerError::InvalidPlan(
            "effect dispatch does not match record version or state",
        ));
    }
    let dispatch_body_length = record
        .dispatch
        .as_ref()
        .map_or(0, |dispatch| dispatch.attempt.body().len());
    let dispatch_packet_length = record
        .dispatch
        .as_ref()
        .map_or(0, |dispatch| dispatch.attempt.packet().len());
    if dispatch_body_length > MAXIMUM_REQUEST_BYTES
        || dispatch_packet_length > MAXIMUM_DISPATCH_PACKET_BYTES
    {
        return Err(ReconcilerError::InvalidPlan(
            "authority effect dispatch exceeds bounds",
        ));
    }
    let authority_length = if record.plan.authority.is_some() {
        359 + dispatch_body_length + dispatch_packet_length
    } else {
        0
    };
    let mut bytes = Vec::with_capacity(
        18 + authority_length + record.plan.request.len() + receipt.len() + diagnostic.len(),
    );
    bytes.push(if record.plan.authority.is_some() {
        AUTHORITY_EFFECT_VERSION
    } else {
        LEGACY_EFFECT_VERSION
    });
    bytes.push(record.plan.domain as u8);
    bytes.push(state);
    bytes.push(0);
    bytes.extend_from_slice(&attempt.to_le_bytes());
    bytes.extend_from_slice(&request_length.to_le_bytes());
    bytes.extend_from_slice(&receipt_length.to_le_bytes());
    bytes.extend_from_slice(&diagnostic_length.to_le_bytes());
    if let Some(binding) = &record.plan.authority {
        bytes.extend_from_slice(binding.operation_id.as_bytes());
        bytes.extend_from_slice(&binding.step.to_be_bytes());
        bytes.extend_from_slice(binding.source_draft_digest.as_bytes());
        bytes.push(audience_code(binding.audience));
        bytes.extend_from_slice(&(binding.method as i32).to_be_bytes());
        bytes.extend_from_slice(binding.template_digest.as_bytes());
        bytes.extend_from_slice(binding.body_digest.as_bytes());
        bytes.extend_from_slice(binding.semantic_digest.as_bytes());
        bytes.extend_from_slice(binding.digest.as_bytes());
        bytes.push(u8::from(binding.descriptor_free));
        bytes.push(0);
        if let Some(dispatch) = &record.dispatch {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(dispatch.binding_digest.as_bytes());
            bytes.extend_from_slice(dispatch.publication_digest.as_bytes());
            bytes.extend_from_slice(dispatch.attempt.template_digest().as_bytes());
            bytes.extend_from_slice(dispatch.attempt.lease_digest().as_bytes());
            bytes.extend_from_slice(&dispatch.attempt.lease_generation().to_be_bytes());
            bytes.extend_from_slice(
                &dispatch
                    .attempt
                    .deadline_boottime_nanoseconds()
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&dispatch.preparation_wall_seconds.to_be_bytes());
            bytes.extend_from_slice(&dispatch.preparation_boottime_nanoseconds.to_be_bytes());
            bytes.extend_from_slice(
                &u32::try_from(dispatch_body_length)
                    .map_err(|_| ReconcilerError::InvalidPlan("dispatch body exceeds bounds"))?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(
                &u32::try_from(dispatch_packet_length)
                    .map_err(|_| ReconcilerError::InvalidPlan("dispatch packet exceeds bounds"))?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(dispatch.attempt.body());
            bytes.extend_from_slice(dispatch.attempt.packet());
        } else {
            bytes.extend_from_slice(&[0; 172]);
        }
    }
    bytes.extend_from_slice(&record.plan.request);
    bytes.extend_from_slice(receipt);
    bytes.extend_from_slice(diagnostic.as_bytes());
    Ok(bytes)
}

pub(super) fn decode_effect(bytes: &[u8]) -> Result<EffectLedgerRecord, ReconcilerError> {
    if bytes.len() < 18
        || !matches!(bytes[0], LEGACY_EFFECT_VERSION | AUTHORITY_EFFECT_VERSION)
        || bytes[3] != 0
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid effect record header",
        ));
    }
    let version = bytes[0];
    let domain = EffectDomain::from_byte(bytes[1])?;
    let state_code = bytes[2];
    let attempt = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid effect attempt"))?,
    );
    let request_length = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid request length"))?,
    ) as usize;
    let receipt_length = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid receipt length"))?,
    ) as usize;
    let diagnostic_length = u16::from_le_bytes(
        bytes[16..18]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid diagnostic length"))?,
    ) as usize;
    let mut cursor = 18;
    let (authority, dispatch) = if version == AUTHORITY_EFFECT_VERSION {
        let operation_bytes = take_array(bytes, &mut cursor)?;
        if operation_bytes == [0; 16] {
            return Err(ReconcilerError::CorruptLedger(
                "zero authority effect operation identity",
            ));
        }
        let operation_id = OperationId::from_bytes(operation_bytes);
        let step = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let source_draft_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let audience = audience_from_code(take_array::<1>(bytes, &mut cursor)?[0])?;
        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let method = match method_code {
            1 => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            4 => BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            7 => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            9 => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            _ => {
                return Err(ReconcilerError::CorruptLedger(
                    "unknown authority effect method",
                ));
            }
        };
        let template_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let body_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let semantic_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let descriptor_free = take_array::<1>(bytes, &mut cursor)?[0];
        if take_array::<1>(bytes, &mut cursor)? != [0]
            || descriptor_free != 1
            || domain != EffectDomain::Host
            || audience != BrokerAudience::Host
            || method != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        {
            return Err(ReconcilerError::CorruptLedger(
                "invalid authority effect binding",
            ));
        }
        let binding = AuthorityEffectBindingV2 {
            operation_id,
            step,
            source_draft_digest,
            audience,
            method,
            template_digest,
            body_digest,
            semantic_digest,
            descriptor_free: true,
            digest,
        };
        let dispatch_present = take_array::<1>(bytes, &mut cursor)?[0];
        if take_array::<3>(bytes, &mut cursor)? != [0; 3] {
            return Err(ReconcilerError::CorruptLedger(
                "invalid effect dispatch reserved bytes",
            ));
        }
        let dispatch_binding_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let publication_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let dispatch_template = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let lease_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let lease_generation = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let deadline = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let clock_wall = i64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let clock_boottime = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let body_length = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        let packet_length = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        let dispatch = match dispatch_present {
            0 if publication_digest.as_bytes() == &[0; 32]
                && dispatch_binding_digest.as_bytes() == &[0; 32]
                && dispatch_template.as_bytes() == &[0; 32]
                && lease_digest.as_bytes() == &[0; 32]
                && lease_generation == 0
                && deadline == 0
                && clock_wall == 0
                && clock_boottime == 0
                && body_length == 0
                && packet_length == 0 =>
            {
                None
            }
            1 if publication_digest.as_bytes() != &[0; 32]
                && dispatch_template == template_digest
                && lease_digest.as_bytes() != &[0; 32]
                && lease_generation != 0
                && deadline != 0
                && body_length != 0
                && body_length <= MAXIMUM_REQUEST_BYTES
                && packet_length != 0
                && packet_length <= MAXIMUM_DISPATCH_PACKET_BYTES =>
            {
                let body = take_vec(bytes, &mut cursor, body_length)?;
                let packet = take_vec(bytes, &mut cursor, packet_length)?;
                Some(PreparedAuthorityEffectV2::from_durable_parts(
                    dispatch_binding_digest,
                    publication_digest,
                    clock_wall,
                    clock_boottime,
                    BrokerDispatchAttemptV1::from_durable_parts(
                        dispatch_template,
                        lease_digest,
                        lease_generation,
                        deadline,
                        body,
                        packet,
                    ),
                ))
            }
            _ => {
                return Err(ReconcilerError::CorruptLedger(
                    "invalid authority effect dispatch",
                ));
            }
        };
        (Some(binding), dispatch)
    } else {
        (None, None)
    };
    let expected = cursor
        .checked_add(request_length)
        .and_then(|n| n.checked_add(receipt_length))
        .and_then(|n| n.checked_add(diagnostic_length))
        .ok_or(ReconcilerError::CorruptLedger("effect length overflow"))?;
    if expected != bytes.len()
        || request_length == 0
        || request_length > MAXIMUM_REQUEST_BYTES
        || receipt_length > MAXIMUM_RECEIPT_BYTES
        || diagnostic_length > MAXIMUM_DIAGNOSTIC_BYTES
    {
        return Err(ReconcilerError::CorruptLedger("invalid effect lengths"));
    }
    let request_end = cursor + request_length;
    let receipt_end = request_end + receipt_length;
    let request = bytes[cursor..request_end].to_vec();
    let receipt = bytes[request_end..receipt_end].to_vec();
    let diagnostic = std::str::from_utf8(&bytes[receipt_end..])
        .map_err(|_| ReconcilerError::CorruptLedger("diagnostic is not UTF-8"))?
        .to_owned();
    if let Some(binding) = &authority
        && (binding.body_digest != effect_body_digest(&request)
            || binding.digest
                != effect_binding_digest(
                    binding.operation_id,
                    binding.step,
                    binding.source_draft_digest,
                    binding.audience,
                    binding.method,
                    binding.template_digest,
                    binding.body_digest,
                    binding.semantic_digest,
                ))
    {
        return Err(ReconcilerError::CorruptLedger(
            "authority effect binding digest mismatch",
        ));
    }
    let state = decode_state(state_code, attempt, receipt, diagnostic)?;
    let dispatch_shape_valid = if authority.is_some() {
        matches!(
            (&state, &dispatch),
            (EffectState::Planned, None)
                | (EffectState::Applying { .. }, Some(_))
                | (EffectState::Applied { .. }, Some(_))
                | (EffectState::PermanentlyBlocked { .. }, Some(_))
        )
    } else {
        dispatch.is_none()
    };
    if !dispatch_shape_valid {
        return Err(ReconcilerError::CorruptLedger(
            "effect dispatch does not match authority state",
        ));
    }
    Ok(EffectLedgerRecord {
        plan: EffectPlan {
            domain,
            request,
            authority,
        },
        state,
        dispatch,
    })
}

fn state_parts(state: &EffectState) -> (u8, u32, &[u8], &str) {
    match state {
        EffectState::Planned => (1, 0, &[], ""),
        EffectState::Applying {
            attempt,
            diagnostic,
        } => (2, *attempt, &[], diagnostic),
        EffectState::Applied { attempt, receipt } => (3, *attempt, receipt.as_bytes(), ""),
        EffectState::PermanentlyBlocked {
            attempt,
            diagnostic,
        } => (4, *attempt, &[], diagnostic),
    }
}

fn validate_lengths(
    plan: &EffectPlan,
    receipt: &[u8],
    diagnostic: &str,
) -> Result<(), ReconcilerError> {
    if plan.request.is_empty()
        || plan.request.len() > MAXIMUM_REQUEST_BYTES
        || receipt.len() > MAXIMUM_RECEIPT_BYTES
        || diagnostic.len() > MAXIMUM_DIAGNOSTIC_BYTES
    {
        return Err(ReconcilerError::InvalidPlan("effect record exceeds bounds"));
    }
    Ok(())
}

fn decode_state(
    state: u8,
    attempt: u32,
    receipt: Vec<u8>,
    diagnostic: String,
) -> Result<EffectState, ReconcilerError> {
    match state {
        1 if attempt == 0 && receipt.is_empty() && diagnostic.is_empty() => {
            Ok(EffectState::Planned)
        }
        2 if attempt > 0 && receipt.is_empty() => Ok(EffectState::Applying {
            attempt,
            diagnostic,
        }),
        3 if attempt > 0 && !receipt.is_empty() && diagnostic.is_empty() => {
            Ok(EffectState::Applied {
                attempt,
                receipt: EffectReceipt(receipt),
            })
        }
        4 if attempt > 0 && receipt.is_empty() && !diagnostic.is_empty() => {
            Ok(EffectState::PermanentlyBlocked {
                attempt,
                diagnostic,
            })
        }
        _ => Err(ReconcilerError::CorruptLedger(
            "invalid effect state fields",
        )),
    }
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ReconcilerError> {
    let end = cursor.checked_add(N).ok_or(ReconcilerError::CorruptLedger(
        "effect binding length overflow",
    ))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ReconcilerError::CorruptLedger("truncated effect binding"))?;
    *cursor = end;
    value
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("truncated effect binding"))
}

fn take_vec(bytes: &[u8], cursor: &mut usize, length: usize) -> Result<Vec<u8>, ReconcilerError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ReconcilerError::CorruptLedger(
            "effect dispatch length overflow",
        ))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ReconcilerError::CorruptLedger("truncated effect dispatch"))?
        .to_vec();
    *cursor = end;
    Ok(value)
}

pub(super) fn effect_body_digest(body: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(BODY_DIGEST_DOMAIN);
    digest.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(body);
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn effect_binding_digest(
    operation_id: OperationId,
    step: u32,
    source: ObjectDigest,
    audience: BrokerAudience,
    method: BrokerMethod,
    template: ObjectDigest,
    body: ObjectDigest,
    semantics: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(BINDING_DIGEST_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(step.to_be_bytes());
    digest.update(source.as_bytes());
    digest.update([audience_code(audience)]);
    digest.update((method as i32).to_be_bytes());
    digest.update(template.as_bytes());
    digest.update(body.as_bytes());
    digest.update(semantics.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn attempt_token_digest(attempt: &BrokerDispatchAttemptV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ATTEMPT_TOKEN_DIGEST_DOMAIN);
    digest.update(
        u64::try_from(attempt.packet().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(attempt.packet());
    ObjectDigest::from_bytes(digest.finalize().into())
}

const fn audience_code(audience: BrokerAudience) -> u8 {
    match audience {
        BrokerAudience::Host => 1,
        BrokerAudience::Mount => 2,
        BrokerAudience::Storage => 3,
        BrokerAudience::Network => 4,
    }
}

fn audience_from_code(value: u8) -> Result<BrokerAudience, ReconcilerError> {
    match value {
        1 => Ok(BrokerAudience::Host),
        2 => Ok(BrokerAudience::Mount),
        3 => Ok(BrokerAudience::Storage),
        4 => Ok(BrokerAudience::Network),
        _ => Err(ReconcilerError::CorruptLedger(
            "unknown authority effect audience",
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn legacy_v1_effect_bytes_remain_exact_in_every_state() {
        let record = EffectLedgerRecord {
            plan: EffectPlan::new(EffectDomain::Host, b"abc".to_vec()).unwrap(),
            state: EffectState::Planned,
            dispatch: None,
        };
        let expected = vec![
            1, 1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', b'c',
        ];
        assert_eq!(encode_effect(&record).unwrap(), expected);
        assert_eq!(decode_effect(&expected).unwrap(), record);

        let cases = [
            (
                EffectState::Applying {
                    attempt: 2,
                    diagnostic: "try".to_owned(),
                },
                vec![
                    1, 1, 2, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0, b'a', b'b', b'c', b't',
                    b'r', b'y',
                ],
            ),
            (
                EffectState::Applied {
                    attempt: 3,
                    receipt: EffectReceipt::new(vec![9, 8]).unwrap(),
                },
                vec![
                    1, 1, 3, 0, 3, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, b'a', b'b', b'c', 9, 8,
                ],
            ),
            (
                EffectState::PermanentlyBlocked {
                    attempt: 4,
                    diagnostic: "no".to_owned(),
                },
                vec![
                    1, 1, 4, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, b'a', b'b', b'c', b'n',
                    b'o',
                ],
            ),
        ];
        for (state, expected) in cases {
            let record = EffectLedgerRecord {
                plan: EffectPlan::new(EffectDomain::Host, b"abc".to_vec()).unwrap(),
                state,
                dispatch: None,
            };
            assert_eq!(encode_effect(&record).unwrap(), expected);
            assert_eq!(decode_effect(&expected).unwrap(), record);
        }
    }
}
