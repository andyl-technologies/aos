//! Authenticated one-transaction Network worker protocol.
//!
//! The capability-free broker may issue this message only for an exact durable
//! `Ambiguous` preparation. The fixed privileged worker independently opens the
//! cleartext catalog, fence, effect, and dispatch records with its protected
//! Network authority before it can obtain a mutation authorization. The local
//! dispatch record binds the complete canonical kernel plan to the durable
//! request; caller-selected interface names, commands, or descriptor numbers
//! never cross this boundary.
//!
//! Version one admits only the preparation effect. Observation and exact-owner
//! cleanup use separate future message kinds so decoding this format can never
//! accidentally authorize either operation.
//!
//! ```text
//! AOSNWR01 | version:u16 | kind:u8 | reserved:u8 | total:u32
//! request-id:16 | effect-digest:32
//! lengths:(request, plan, catalog, catalog-seal, current-fence,
//!          operation-fence, effect, dispatch-seal):u32[8]
//! payloads:length-delimited bytes in the same order
//! ```

use aos_proto::aos::sandbox::local::v1::{ApplyNetworkRequest, Audience};
use aos_sandbox_broker::{
    BrokerAuthorizationFenceV1, BrokerEffectIntentV2, BrokerEffectStatusV2, BrokerLocalRecordDomain,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerGrantTarget, BrokerVerb, DesiredGeneration,
    IncarnationId, ObjectDigest, SandboxId,
};
use aos_sandbox_protocol::semantics::network::{CanonicalNetworkSemanticsV1, NetworkOperation};
use aos_sandbox_protocol::{MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::NetworkAdmissionError;
use crate::authorization::NetworkAuthorityV1;
use crate::catalog::{
    AuthenticatedNetworkPreparationV1, ResolvedEndpointV1, ResolvedNetworkPreparationV1,
    encode_authenticated_resolution,
};
use crate::kernel_plan::NetworkKernelPlanV1;
use crate::state::{AmbiguousNetworkDispatchV1, effect_digest};
use crate::worker_replay::NetworkWorkerReplayLedger;

const REQUEST_MAGIC: &[u8; 8] = b"AOSNWR01";
const REQUEST_VERSION: u16 = 1;
const PREPARE_EFFECT_KIND: u8 = 1;
const REQUEST_HEADER_BYTES: usize = 96;
const REQUEST_FIELD_COUNT: usize = 8;

const DISPATCH_MAGIC: &[u8; 8] = b"AOSNDP01";
const DISPATCH_VERSION: u16 = 1;
const DISPATCH_PAYLOAD_BYTES: usize = 260;

const MAXIMUM_KERNEL_PLAN_BYTES: usize = 512 * 1024;
const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024;
const MAXIMUM_AUTHORITY_RECORD_BYTES: usize = 1028 * 1024;
const MAXIMUM_DISPATCH_RECORD_BYTES: usize = 64 * 1024;
/// Maximum encoded request accepted by the fixed Network worker.
pub const MAXIMUM_NETWORK_WORKER_REQUEST_BYTES: usize = 5 * 1024 * 1024;

fn dispatch_domain() -> Result<BrokerLocalRecordDomain, NetworkWorkerProtocolError> {
    BrokerLocalRecordDomain::new(*b"AOSNETDISPATCH01")
        .map_err(|_| NetworkWorkerProtocolError::Authority)
}

/// Reports malformed, oversized, or unauthenticated Network worker input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NetworkWorkerProtocolError {
    /// A field or the complete message exceeded its fixed version-one ceiling.
    #[error("Network worker message exceeds its fixed byte ceiling")]
    TooLarge,
    /// The versioned wire record was truncated, noncanonical, or inconsistent.
    #[error("Network worker message is invalid: {0}")]
    InvalidWire(&'static str),
    /// Protected authority did not authenticate every linked record.
    #[error("Network worker authority was rejected")]
    Authority,
    /// The protected exactly-once ledger was unsafe, corrupt, unavailable, or full.
    #[error("Network worker replay ledger was rejected")]
    ReplayStore,
    /// The request identity already has a durable worker claim.
    #[error("Network worker request was already claimed")]
    Replay,
}

/// Carries one exact preparation effect from the broker to the fixed worker.
///
/// Decoding validates only the bounded canonical framing. Call
/// [`Self::authenticate`] before using any field as authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPrepareWorkerDispatchV1 {
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    request_body: Vec<u8>,
    kernel_plan: NetworkKernelPlanV1,
    catalog: AuthenticatedNetworkPreparationV1,
    current_fence: Vec<u8>,
    operation_fence: Vec<u8>,
    effect: Vec<u8>,
    dispatch: Vec<u8>,
}

impl NetworkPrepareWorkerDispatchV1 {
    /// Decodes one bounded canonical worker record without trusting its contents.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError`] for an unsupported kind or
    /// version, malformed lengths, oversized fields, a noncanonical catalog,
    /// or an invalid canonical kernel plan.
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkWorkerProtocolError> {
        if bytes.len() > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES {
            return Err(NetworkWorkerProtocolError::TooLarge);
        }
        if bytes.len() < REQUEST_HEADER_BYTES {
            return invalid("truncated header");
        }

        let mut decoder = Decoder::new(bytes);
        if decoder.take::<8>()? != *REQUEST_MAGIC
            || decoder.u16()? != REQUEST_VERSION
            || decoder.byte()? != PREPARE_EFFECT_KIND
        {
            return invalid("unsupported message kind or version");
        }
        if decoder.byte()? != 0 {
            return invalid("nonzero reserved field");
        }
        let total = decoder.usize_u32()?;
        if total != bytes.len() {
            return invalid("declared length is not exact");
        }
        let request_id = decoder.take()?;
        let effect_digest = ObjectDigest::from_bytes(decoder.take()?);
        let mut lengths = [0_usize; REQUEST_FIELD_COUNT];
        for length in &mut lengths {
            *length = decoder.usize_u32()?;
        }
        validate_lengths(lengths, bytes.len())?;

        let request_body = decoder.bytes(lengths[0])?.to_vec();
        let kernel_plan = NetworkKernelPlanV1::decode(decoder.bytes(lengths[1])?)
            .map_err(|_| NetworkWorkerProtocolError::InvalidWire("invalid kernel plan"))?;
        let catalog_payload = decoder.bytes(lengths[2])?;
        let (assignment, resolution) = decode_catalog(catalog_payload)?;
        let catalog = AuthenticatedNetworkPreparationV1 {
            resolution,
            assignment,
            sealed: decoder.bytes(lengths[3])?.to_vec(),
        };
        let current_fence = decoder.bytes(lengths[4])?.to_vec();
        let operation_fence = decoder.bytes(lengths[5])?.to_vec();
        let effect = decoder.bytes(lengths[6])?.to_vec();
        let dispatch = decoder.bytes(lengths[7])?.to_vec();
        if !decoder.finished() {
            return invalid("trailing bytes");
        }

        let message = Self {
            request_id,
            effect_digest,
            request_body,
            kernel_plan,
            catalog,
            current_fence,
            operation_fence,
            effect,
            dispatch,
        };
        message.validate_shape()?;
        if message.encode()? != bytes {
            return invalid("noncanonical encoding");
        }
        Ok(message)
    }

    /// Encodes this record in the canonical bounded version-one format.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError`] if a field was substituted with
    /// an invalid or oversized value after decoding.
    pub fn encode(&self) -> Result<Vec<u8>, NetworkWorkerProtocolError> {
        self.validate_shape()?;
        let catalog =
            encode_authenticated_resolution(self.catalog.assignment, &self.catalog.resolution);
        let fields: [&[u8]; REQUEST_FIELD_COUNT] = [
            &self.request_body,
            self.kernel_plan.as_bytes(),
            &catalog,
            &self.catalog.sealed,
            &self.current_fence,
            &self.operation_fence,
            &self.effect,
            &self.dispatch,
        ];
        let total = fields
            .iter()
            .try_fold(REQUEST_HEADER_BYTES, |total, field| {
                total
                    .checked_add(field.len())
                    .ok_or(NetworkWorkerProtocolError::TooLarge)
            })?;
        if total > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES {
            return Err(NetworkWorkerProtocolError::TooLarge);
        }

        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&REQUEST_VERSION.to_be_bytes());
        bytes.push(PREPARE_EFFECT_KIND);
        bytes.push(0);
        push_length(&mut bytes, total)?;
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(self.effect_digest.as_bytes());
        for field in fields {
            push_length(&mut bytes, field.len())?;
        }
        for field in fields {
            bytes.extend_from_slice(field);
        }
        Ok(bytes)
    }

    /// Independently authenticates every durable and dispatch relationship.
    ///
    /// This step does not establish time freshness. The worker must next call
    /// [`AuthenticatedNetworkPrepareWorkerDispatchV1::authorize_mutation`] with
    /// a fresh protected clock sample immediately before its first effect.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError::Authority`] unless the exact raw
    /// request, canonical plan, catalog resolution, current fence, operation
    /// fence, pending effect, and local dispatch record form one association
    /// under the worker's protected authority.
    pub fn authenticate(
        self,
        authority: &NetworkAuthorityV1,
    ) -> Result<AuthenticatedNetworkPrepareWorkerDispatchV1, NetworkWorkerProtocolError> {
        let semantics = decode_admitted_semantics(&self.request_body)?;
        let assignment = self.kernel_plan.assignment();
        let resolution = authority
            .validate_catalog(&self.catalog, assignment)
            .map_err(|_| NetworkWorkerProtocolError::Authority)?;
        let current_fence = authority
            .open_fence(&self.request_id_sandbox(), &self.current_fence)
            .map_err(|_| NetworkWorkerProtocolError::Authority)?;
        let operation_fence = authority
            .open_operation_fence(&self.request_id, &self.operation_fence)
            .map_err(|_| NetworkWorkerProtocolError::Authority)?;
        let effect = authority
            .validate_operation_links(
                &self.request_id_sandbox(),
                &self.request_id,
                &self.operation_fence,
                &self.effect,
            )
            .map_err(|_| NetworkWorkerProtocolError::Authority)?;

        let transport_digest = ObjectDigest::from_bytes(Sha256::digest(&self.request_body).into());
        let observed_effect_digest =
            effect_digest(self.request_id, transport_digest, &self.catalog.resolution);
        let expected_dispatch = dispatch_payload(
            self.request_id,
            transport_digest,
            semantics.argument_commitment().digest(),
            self.effect_digest,
            self.kernel_plan.digest(),
            &self.catalog.resolution,
        );
        let opened_dispatch = authority
            .open_local(&self.request_id, dispatch_domain()?, &self.dispatch)
            .map_err(|_| NetworkWorkerProtocolError::Authority)?;

        let operation_is_prepare =
            matches!(semantics.operation(), NetworkOperation::Prepare { .. });
        let endpoint_ids_match = semantics
            .operation()
            .endpoint_ids()
            .iter()
            .eq(resolution.endpoints().iter().map(|endpoint| endpoint.id()));
        if self.request_id == [0; 16]
            || self.effect_digest.as_bytes() == &[0; 32]
            || semantics.header().request_id() != &self.request_id
            || semantics.fence().sandbox_id() != assignment.sandbox().as_bytes()
            || semantics.fence().incarnation_id() != assignment.incarnation().as_bytes()
            || semantics.fence().assignment_epoch() != assignment.epoch().get()
            || semantics.fence().desired_generation() != assignment.desired_generation().get()
            || semantics.fence().assignment_digest() != assignment.digest().as_bytes()
            || !operation_is_prepare
            || !endpoint_ids_match
            || current_fence != operation_fence
            || current_fence.assignment() != assignment
            || effect.status() != BrokerEffectStatusV2::Pending
            || effect.request_id() != &self.request_id
            || effect.transport_request_digest() != transport_digest
            || effect.request_digest() != semantics.argument_commitment().digest()
            || effect.verb() != BrokerVerb::NetworkPrepare
            || effect.target() != BrokerGrantTarget::Assignment
            || !kernel_plan_matches_catalog(&self.kernel_plan, resolution)
            || observed_effect_digest != self.effect_digest
            || opened_dispatch != expected_dispatch
        {
            return Err(NetworkWorkerProtocolError::Authority);
        }
        authority
            .check_current_fence(&current_fence)
            .map_err(|_| NetworkWorkerProtocolError::Authority)?;

        Ok(AuthenticatedNetworkPrepareWorkerDispatchV1 {
            request: self,
            current_fence,
            effect,
        })
    }

    fn request_id_sandbox(&self) -> [u8; 16] {
        *self.kernel_plan.assignment().sandbox().as_bytes()
    }

    fn validate_shape(&self) -> Result<(), NetworkWorkerProtocolError> {
        let catalog =
            encode_authenticated_resolution(self.catalog.assignment, &self.catalog.resolution);
        let lengths = [
            self.request_body.len(),
            self.kernel_plan.as_bytes().len(),
            catalog.len(),
            self.catalog.sealed.len(),
            self.current_fence.len(),
            self.operation_fence.len(),
            self.effect.len(),
            self.dispatch.len(),
        ];
        let total = lengths
            .iter()
            .try_fold(REQUEST_HEADER_BYTES, |total, length| {
                total
                    .checked_add(*length)
                    .ok_or(NetworkWorkerProtocolError::TooLarge)
            })?;
        validate_lengths(lengths, total)?;
        if self.request_id == [0; 16]
            || self.effect_digest.as_bytes() == &[0; 32]
            || catalog.is_empty()
        {
            return invalid("reserved identity or empty catalog");
        }
        Ok(())
    }
}

/// Carries a fully authenticated request before its first freshness gate.
///
/// This type deliberately exposes no kernel plan. Consuming it through
/// [`Self::authorize_mutation`] is the only way to obtain mutation inputs.
pub struct AuthenticatedNetworkPrepareWorkerDispatchV1 {
    request: NetworkPrepareWorkerDispatchV1,
    current_fence: BrokerAuthorizationFenceV1,
    effect: BrokerEffectIntentV2,
}

impl AuthenticatedNetworkPrepareWorkerDispatchV1 {
    /// Rechecks current authority and effect time immediately before mutation.
    ///
    /// The returned non-clone authorization is the input to the future kernel
    /// mutator. This check must happen before namespace, policy, or link state
    /// is created; the initial policy installed by that mutator is default-drop.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError::Authority`] for a changed
    /// protected authority, expired plan or lease, reboot, clock substitution,
    /// backwards time, or excessive paired-clock drift. Returns
    /// [`NetworkWorkerProtocolError::Replay`] when the request identity was
    /// already claimed, or [`NetworkWorkerProtocolError::ReplayStore`] when
    /// the protected claim ledger is unavailable, corrupt, or exhausted.
    pub fn authorize_mutation<F>(
        self,
        authority: &NetworkAuthorityV1,
        replay: &mut NetworkWorkerReplayLedger,
        trusted_clock: &mut F,
    ) -> Result<NetworkMutationAuthorizationV1, NetworkWorkerProtocolError>
    where
        F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, NetworkAdmissionError>,
    {
        check_freshness(authority, &self.current_fence, &self.effect, trusted_clock)?;
        let dispatch_digest =
            ObjectDigest::from_bytes(Sha256::digest(&self.request.dispatch).into());
        replay.claim(
            self.request.request_id,
            self.request.effect_digest,
            self.request.kernel_plan.digest(),
            dispatch_digest,
        )?;
        // A claim consumes the attempt even when authority expires immediately
        // afterwards. This second check ensures no mutation occurs in that gap.
        check_freshness(authority, &self.current_fence, &self.effect, trusted_clock)?;
        Ok(NetworkMutationAuthorizationV1 {
            authenticated: self,
        })
    }
}

/// Authorizes one first mutation for an exact canonical preparation plan.
///
/// The value is intentionally non-clone. Before exposing a prepared namespace
/// to any veth peer or publication target, the worker must call
/// [`Self::authorize_activation`] and pass the returned token to that step.
pub struct NetworkMutationAuthorizationV1 {
    authenticated: AuthenticatedNetworkPrepareWorkerDispatchV1,
}

impl NetworkMutationAuthorizationV1 {
    /// Returns the exact canonical plan authorized for kernel realization.
    #[must_use]
    pub const fn kernel_plan(&self) -> &NetworkKernelPlanV1 {
        &self.authenticated.request.kernel_plan
    }

    /// Returns the stable durable request identity.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.authenticated.request.request_id
    }

    /// Returns the exact durable preparation-effect identity.
    #[must_use]
    pub const fn effect_digest(&self) -> ObjectDigest {
        self.authenticated.request.effect_digest
    }

    /// Rechecks current authority and effect time immediately before activation.
    ///
    /// The returned borrowed token prevents an activation API from accepting a
    /// raw plan. The future mutator must retain default-drop while constructing
    /// the namespace and may expose the first link only after this second gate.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError::Authority`] for a changed
    /// protected authority, expired plan or lease, reboot, clock substitution,
    /// backwards time, or excessive paired-clock drift.
    pub fn authorize_activation<'a, F>(
        &'a self,
        authority: &NetworkAuthorityV1,
        trusted_clock: &mut F,
    ) -> Result<NetworkActivationAuthorizationV1<'a>, NetworkWorkerProtocolError>
    where
        F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, NetworkAdmissionError>,
    {
        check_freshness(
            authority,
            &self.authenticated.current_fence,
            &self.authenticated.effect,
            trusted_clock,
        )?;
        Ok(NetworkActivationAuthorizationV1 { mutation: self })
    }
}

/// Proves a fresh second authority check for one activation step.
pub struct NetworkActivationAuthorizationV1<'a> {
    mutation: &'a NetworkMutationAuthorizationV1,
}

impl NetworkActivationAuthorizationV1<'_> {
    /// Returns the exact canonical plan whose activation was freshly admitted.
    #[must_use]
    pub const fn kernel_plan(&self) -> &NetworkKernelPlanV1 {
        self.mutation.kernel_plan()
    }
}

pub(crate) fn issue_prepare_dispatch(
    authority: &NetworkAuthorityV1,
    durable: AmbiguousNetworkDispatchV1,
    request_body: &[u8],
    kernel_plan: NetworkKernelPlanV1,
) -> Result<NetworkPrepareWorkerDispatchV1, NetworkWorkerProtocolError> {
    let transport_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
    if transport_digest != durable.transport_digest
        || durable.request_id == [0; 16]
        || durable.sandbox_id != *kernel_plan.assignment().sandbox().as_bytes()
        || !kernel_plan_matches_catalog(&kernel_plan, &durable.catalog)
        || durable.effect_digest
            != effect_digest(
                durable.request_id,
                durable.transport_digest,
                &durable.catalog,
            )
    {
        return Err(NetworkWorkerProtocolError::Authority);
    }
    let semantics = decode_admitted_semantics(request_body)?;
    let assignment = kernel_plan.assignment();
    if semantics.header().request_id() != &durable.request_id
        || semantics.argument_commitment().digest() != durable.semantic_digest
        || semantics.fence().sandbox_id() != assignment.sandbox().as_bytes()
        || semantics.fence().incarnation_id() != assignment.incarnation().as_bytes()
        || semantics.fence().assignment_epoch() != assignment.epoch().get()
        || semantics.fence().desired_generation() != assignment.desired_generation().get()
        || semantics.fence().assignment_digest() != assignment.digest().as_bytes()
    {
        return Err(NetworkWorkerProtocolError::Authority);
    }
    let current_fence = authority
        .open_fence(&durable.sandbox_id, &durable.current_fence)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    if current_fence.assignment() != assignment {
        return Err(NetworkWorkerProtocolError::Authority);
    }
    authority
        .check_current_fence(&current_fence)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;

    let catalog = authority
        .authenticate_protected_catalog_for_assignment(durable.catalog, assignment)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let payload = dispatch_payload(
        durable.request_id,
        durable.transport_digest,
        durable.semantic_digest,
        durable.effect_digest,
        kernel_plan.digest(),
        &catalog.resolution,
    );
    let dispatch = authority
        .seal_local(&durable.request_id, dispatch_domain()?, &payload)
        .map_err(|_| NetworkWorkerProtocolError::Authority)?;
    let request = NetworkPrepareWorkerDispatchV1 {
        request_id: durable.request_id,
        effect_digest: durable.effect_digest,
        request_body: request_body.to_vec(),
        kernel_plan,
        catalog,
        current_fence: durable.current_fence,
        operation_fence: durable.operation_fence,
        effect: durable.effect,
        dispatch,
    };
    request.validate_shape()?;
    Ok(request)
}

fn check_freshness<F>(
    authority: &NetworkAuthorityV1,
    fence: &BrokerAuthorizationFenceV1,
    effect: &BrokerEffectIntentV2,
    trusted_clock: &mut F,
) -> Result<(), NetworkWorkerProtocolError>
where
    F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, NetworkAdmissionError>,
{
    authority
        .check_current_fence(fence)
        .and_then(|()| authority.check_before_effect(effect, trusted_clock))
        .map_err(|_| NetworkWorkerProtocolError::Authority)
}

fn kernel_plan_matches_catalog(
    plan: &NetworkKernelPlanV1,
    catalog: &ResolvedNetworkPreparationV1,
) -> bool {
    let expectation = plan.observation_expectation();

    plan.network_handle() == catalog.reserved_network_handle()
        && expectation.profile_digest() == catalog.profile_digest()
        && expectation
            .policy()
            .endpoints()
            .iter()
            .zip(catalog.endpoints())
            .all(|(planned, resolved)| {
                planned.endpoint_id().as_bytes() == resolved.id()
                    && planned.digest() == resolved.policy_digest()
            })
        && expectation.policy().endpoints().len() == catalog.endpoints().len()
}

fn decode_admitted_semantics(
    bytes: &[u8],
) -> Result<CanonicalNetworkSemanticsV1, NetworkWorkerProtocolError> {
    let request = ApplyNetworkRequest::decode_from_slice(bytes)
        .map_err(|_| NetworkWorkerProtocolError::InvalidWire("malformed request body"))?;
    let header = request
        .header
        .as_option()
        .ok_or(NetworkWorkerProtocolError::InvalidWire(
            "missing request header",
        ))?;
    let audience = header
        .audience
        .as_known()
        .filter(|audience| *audience != Audience::AUDIENCE_UNSPECIFIED)
        .ok_or(NetworkWorkerProtocolError::InvalidWire(
            "invalid request audience",
        ))?;

    // Peer identity was already kernel-bound before the durable effect was
    // sealed. Re-decoding here closes protobuf and semantic shape; the sealed
    // effect, rather than this synthetic equal peer pair, carries authority.
    CanonicalNetworkSemanticsV1::decode(
        bytes,
        PeerCredentials {
            uid: 0,
            gid: 0,
            pid: None,
        },
        PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience,
        },
        0,
    )
    .map_err(|_| NetworkWorkerProtocolError::InvalidWire("invalid request semantics"))
}

fn dispatch_payload(
    request_id: [u8; 16],
    transport_digest: ObjectDigest,
    semantic_digest: ObjectDigest,
    effect_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    catalog: &ResolvedNetworkPreparationV1,
) -> [u8; DISPATCH_PAYLOAD_BYTES] {
    let mut bytes = [0_u8; DISPATCH_PAYLOAD_BYTES];
    let mut offset = 0;
    copy_field(&mut bytes, &mut offset, DISPATCH_MAGIC);
    copy_field(&mut bytes, &mut offset, &DISPATCH_VERSION.to_be_bytes());
    copy_field(&mut bytes, &mut offset, &[0, 0]);
    copy_field(&mut bytes, &mut offset, &request_id);
    copy_field(&mut bytes, &mut offset, transport_digest.as_bytes());
    copy_field(&mut bytes, &mut offset, semantic_digest.as_bytes());
    copy_field(&mut bytes, &mut offset, effect_digest.as_bytes());
    copy_field(&mut bytes, &mut offset, kernel_plan_digest.as_bytes());
    copy_field(
        &mut bytes,
        &mut offset,
        &catalog.binding().generation().to_be_bytes(),
    );
    copy_field(
        &mut bytes,
        &mut offset,
        catalog.binding().digest().as_bytes(),
    );
    copy_field(&mut bytes, &mut offset, catalog.reserved_network_handle());
    copy_field(&mut bytes, &mut offset, catalog.profile_digest().as_bytes());
    bytes
}

fn copy_field<const N: usize>(target: &mut [u8; N], offset: &mut usize, field: &[u8]) {
    let end = *offset + field.len();
    target[*offset..end].copy_from_slice(field);
    *offset = end;
}

fn decode_catalog(
    bytes: &[u8],
) -> Result<(BrokerAssignment, ResolvedNetworkPreparationV1), NetworkWorkerProtocolError> {
    if bytes.len() > MAXIMUM_CATALOG_BYTES || bytes.len() < 154 {
        return invalid("invalid catalog length");
    }
    let mut decoder = Decoder::new(bytes);
    let assignment = BrokerAssignment::new(
        SandboxId::from_bytes(decoder.take()?),
        IncarnationId::from_bytes(decoder.take()?),
        AssignmentEpoch::new(decoder.u64()?),
        DesiredGeneration::new(decoder.u64()?),
        ObjectDigest::from_bytes(decoder.take()?),
    )
    .map_err(|_| NetworkWorkerProtocolError::InvalidWire("invalid catalog assignment"))?;
    let generation = decoder.u64()?;
    let network_handle = decoder.take()?;
    let profile_digest = ObjectDigest::from_bytes(decoder.take()?);
    let endpoint_count = usize::from(decoder.u16()?);
    let expected = 154_usize
        .checked_add(
            endpoint_count
                .checked_mul(48)
                .ok_or(NetworkWorkerProtocolError::TooLarge)?,
        )
        .ok_or(NetworkWorkerProtocolError::TooLarge)?;
    if expected != bytes.len() {
        return invalid("catalog endpoint length is not exact");
    }
    let mut endpoints = Vec::with_capacity(endpoint_count);
    for _ in 0..endpoint_count {
        endpoints.push(
            ResolvedEndpointV1::new(decoder.take()?, ObjectDigest::from_bytes(decoder.take()?))
                .map_err(|_| NetworkWorkerProtocolError::InvalidWire("invalid catalog endpoint"))?,
        );
    }
    if !decoder.finished() {
        return invalid("trailing catalog bytes");
    }
    let resolution =
        ResolvedNetworkPreparationV1::new(generation, network_handle, profile_digest, endpoints)
            .map_err(|_| NetworkWorkerProtocolError::InvalidWire("invalid catalog resolution"))?;
    if encode_authenticated_resolution(assignment, &resolution) != bytes {
        return invalid("noncanonical catalog");
    }
    Ok((assignment, resolution))
}

fn validate_lengths(
    lengths: [usize; REQUEST_FIELD_COUNT],
    total: usize,
) -> Result<(), NetworkWorkerProtocolError> {
    let limits = [
        MAXIMUM_REQUEST_BYTES,
        MAXIMUM_KERNEL_PLAN_BYTES,
        MAXIMUM_CATALOG_BYTES,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        MAXIMUM_AUTHORITY_RECORD_BYTES,
        MAXIMUM_DISPATCH_RECORD_BYTES,
    ];
    if lengths
        .iter()
        .zip(limits)
        .any(|(length, limit)| *length == 0 || *length > limit)
    {
        return Err(NetworkWorkerProtocolError::TooLarge);
    }
    let expected = lengths
        .iter()
        .try_fold(REQUEST_HEADER_BYTES, |sum, length| {
            sum.checked_add(*length)
                .ok_or(NetworkWorkerProtocolError::TooLarge)
        })?;
    if expected != total || total > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES {
        return Err(NetworkWorkerProtocolError::TooLarge);
    }
    Ok(())
}

fn push_length(target: &mut Vec<u8>, length: usize) -> Result<(), NetworkWorkerProtocolError> {
    let length = u32::try_from(length).map_err(|_| NetworkWorkerProtocolError::TooLarge)?;
    target.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn invalid<T>(message: &'static str) -> Result<T, NetworkWorkerProtocolError> {
    Err(NetworkWorkerProtocolError::InvalidWire(message))
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], NetworkWorkerProtocolError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| NetworkWorkerProtocolError::InvalidWire("fixed field has invalid length"))
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], NetworkWorkerProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(NetworkWorkerProtocolError::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(NetworkWorkerProtocolError::InvalidWire("truncated field"))?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, NetworkWorkerProtocolError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, NetworkWorkerProtocolError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, NetworkWorkerProtocolError> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, NetworkWorkerProtocolError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn usize_u32(&mut self) -> Result<usize, NetworkWorkerProtocolError> {
        usize::try_from(self.u32()?).map_err(|_| NetworkWorkerProtocolError::TooLarge)
    }

    const fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn lengths_fail_before_payload_allocation() {
        let mut bytes = vec![0_u8; REQUEST_HEADER_BYTES];
        bytes[..8].copy_from_slice(REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&REQUEST_VERSION.to_be_bytes());
        bytes[10] = PREPARE_EFFECT_KIND;
        bytes[12..16].copy_from_slice(&(REQUEST_HEADER_BYTES as u32).to_be_bytes());
        bytes[16..32].copy_from_slice(&[1; 16]);
        bytes[32..64].copy_from_slice(&[2; 32]);
        bytes[64..68].copy_from_slice(&u32::MAX.to_be_bytes());

        assert_eq!(
            NetworkPrepareWorkerDispatchV1::decode(&bytes),
            Err(NetworkWorkerProtocolError::TooLarge)
        );
    }

    #[test]
    fn unknown_kind_and_reserved_bits_fail_closed() {
        let mut bytes = vec![0_u8; REQUEST_HEADER_BYTES];
        bytes[..8].copy_from_slice(REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&REQUEST_VERSION.to_be_bytes());
        bytes[10] = 2;
        bytes[12..16].copy_from_slice(&(REQUEST_HEADER_BYTES as u32).to_be_bytes());

        assert!(matches!(
            NetworkPrepareWorkerDispatchV1::decode(&bytes),
            Err(NetworkWorkerProtocolError::InvalidWire(_))
        ));

        bytes[10] = PREPARE_EFFECT_KIND;
        bytes[11] = 1;
        assert!(matches!(
            NetworkPrepareWorkerDispatchV1::decode(&bytes),
            Err(NetworkWorkerProtocolError::InvalidWire(_))
        ));
    }

    #[test]
    fn catalog_decoder_rejects_noncanonical_or_trailing_data() {
        assert!(matches!(
            decode_catalog(&[0; 154]),
            Err(NetworkWorkerProtocolError::InvalidWire(_))
        ));

        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .expect("assignment");
        let resolution = ResolvedNetworkPreparationV1::new(
            6,
            [7; 32],
            ObjectDigest::from_bytes([8; 32]),
            Vec::new(),
        )
        .expect("resolution");
        let mut bytes = encode_authenticated_resolution(assignment, &resolution);
        bytes.push(0);
        assert!(matches!(
            decode_catalog(&bytes),
            Err(NetworkWorkerProtocolError::InvalidWire(_))
        ));
    }
}
