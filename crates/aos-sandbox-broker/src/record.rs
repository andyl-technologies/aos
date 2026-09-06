//! Authenticated broker-authorization records stored in the common journal.
//!
//! The common journal provides atomic transactions, durable commit ordering,
//! and unkeyed corruption detection. This module adds authentication for the
//! privileged broker's authorization-bearing values. The node-local MAC covers the
//! journal namespace, exact record key, payload kind, and payload bytes, so a
//! valid value cannot be moved to another logical location or reinterpreted as
//! another record type.
//!
//! ```text
//! authenticated-value-v1 =
//!   magic(8) || version(u16) || kind(u8) || reserved(u8) ||
//!   key-id(16) || payload-length(u32) || payload || hmac-sha256(32)
//!
//! broker-authorization-fence-v1 =
//!   magic(8) || version(u16) || assignment || node-id || plan-digest ||
//!   plan-expiry(i64) || ownership-key-reference || local-lease-record(234)
//!
//! broker-effect-intent-v2 =
//!   magic(8) || version(u16) || status(u8) || verb(u8) || target(tag + 64) ||
//!   request-id || transport-digest || semantic-digest || plan-digest ||
//!   lease-digest || ceilings || expiries || boot-id || boottime-deadline ||
//!   clock-provenance || admitted-clock-pair || request/effect deadlines ||
//!   local-lease-record(234) || receipt-length(u32) || receipt
//! ```
//!
//! Integers use network byte order. These records do not provide rollback
//! resistance: a deployment with adversarial durable storage must additionally
//! compare recovered state with a trusted non-rollback source.

use aos_sandbox::journal::RecordNamespace;
use aos_sandbox_core::model::{KeyReference, KeyUsage, StableKeyId};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAdmissionIntersection, BrokerAssignment, BrokerGrantTarget,
    BrokerResourceHandle, BrokerVerb, DesiredGeneration, IncarnationId, LocalLeaseRecord, NodeId,
    ObjectDigest, RawPairedClockSample, SandboxId, decode_local_lease_record,
    encode_local_lease_record,
};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use zeroize::Zeroizing;

const AUTHENTICATED_VERSION: u16 = 1;
const AUTHENTICATED_FIXED_BYTES: usize = 8 + 2 + 1 + 1 + 16 + 4 + 32;
const MAXIMUM_JOURNAL_KEY_BYTES: usize = 1_024;
const MAXIMUM_RECEIPT_BYTES: usize = 1_024 * 1_024;
const MAXIMUM_AUTHENTICATED_PAYLOAD_BYTES: usize = MAXIMUM_RECEIPT_BYTES + 2_048;
const LOCAL_RECORD_DOMAIN_BYTES: usize = 16;

const FENCE_VERSION: u16 = 1;
const LOCAL_LEASE_RECORD_BYTES: usize = 234;
const MAXIMUM_STABLE_KEY_ID_BYTES: usize = 255;

const EFFECT_VERSION: u16 = 2;
const MAXIMUM_REQUEST_BYTES: u32 = 16 * 1024 * 1024;
const MAXIMUM_DESCRIPTORS: u16 = 16;

type HmacSha256 = Hmac<Sha256>;

/// Separates durable authentication and payload formats between brokers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerDomain {
    /// Host lifecycle and system-manager effects.
    Host,
    /// Detached mount and namespace attachment effects.
    Mount,
    /// Storage workspace and immutable-version effects.
    Storage,
    /// Network preparation and lease-gate effects.
    Network,
}

impl BrokerDomain {
    const fn authenticated_magic(self) -> &'static [u8; 8] {
        match self {
            Self::Host => b"AOSHAJ\0\0",
            Self::Mount => b"AOSMAJ\0\0",
            Self::Storage => b"AOSSAJ\0\0",
            Self::Network => b"AOSNAJ\0\0",
        }
    }

    const fn authentication_domain(self) -> &'static [u8] {
        match self {
            Self::Host => b"aos.host.journal-authentication.v1\0",
            Self::Mount => b"aos.mount.journal-authentication.v1\0",
            Self::Storage => b"aos.storage.journal-authentication.v1\0",
            Self::Network => b"aos.network.journal-authentication.v1\0",
        }
    }

    const fn fence_magic(self) -> &'static [u8; 8] {
        match self {
            Self::Host => b"AOSHAF\0\0",
            Self::Mount => b"AOSMAF\0\0",
            Self::Storage => b"AOSSAF\0\0",
            Self::Network => b"AOSNAF\0\0",
        }
    }

    const fn effect_magic(self) -> &'static [u8; 8] {
        match self {
            Self::Host => b"AOSHAE\0\0",
            Self::Mount => b"AOSMAE\0\0",
            Self::Storage => b"AOSSAE\0\0",
            Self::Network => b"AOSNAE\0\0",
        }
    }
}

/// Reports malformed or unauthenticated broker authorization journal state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorizationRecordError {
    /// The configured local key or key identifier uses the zero sentinel.
    #[error("invalid node-local journal authentication key")]
    InvalidKey,
    /// The authenticated wrapper is malformed, truncated, or too large.
    #[error("invalid authenticated journal value framing")]
    InvalidFraming,
    /// The value was not authenticated by the configured key and location.
    #[error("journal value authentication failed")]
    AuthenticationFailed,
    /// The authenticated payload has an unknown or unexpected record kind.
    #[error("authenticated journal value has the wrong payload kind")]
    WrongKind,
    /// The authenticated payload violates its closed durable schema.
    #[error("invalid durable broker authorization payload")]
    InvalidPayload,
}

/// Holds one node-local journal authentication key without exposing its bytes.
///
/// The type is deliberately non-`Clone`; its secret bytes are zeroized on
/// drop. A stable key identifier supports deliberate key rotation but is not
/// itself secret.
pub struct NodeJournalMacKey {
    domain: BrokerDomain,
    key_id: [u8; 16],
    secret: Zeroizing<[u8; 32]>,
}

impl NodeJournalMacKey {
    /// Constructs one locally provisioned journal authentication key.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRecordError::InvalidKey`] when either identifier
    /// or secret is the reserved all-zero value.
    pub fn new(
        domain: BrokerDomain,
        key_id: [u8; 16],
        secret: [u8; 32],
    ) -> Result<Self, AuthorizationRecordError> {
        let secret = Zeroizing::new(secret);
        if key_id == [0; 16] || secret.as_ref() == [0; 32] {
            return Err(AuthorizationRecordError::InvalidKey);
        }
        Ok(Self {
            domain,
            key_id,
            secret,
        })
    }

    /// Returns the non-secret key-generation identifier.
    #[must_use]
    pub const fn key_id(&self) -> &[u8; 16] {
        &self.key_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum AuthenticatedValueKind {
    AuthorizationFence = 1,
    EffectIntent = 2,
    LocalRecord = 3,
}

/// Domain-separates one audience-specific authenticated local record format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerLocalRecordDomain([u8; 16]);

impl BrokerLocalRecordDomain {
    /// Constructs a nonzero fixed-width application record domain.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRecordError::InvalidPayload`] for the zero sentinel.
    pub fn new(bytes: [u8; 16]) -> Result<Self, AuthorizationRecordError> {
        if bytes == [0; 16] {
            Err(AuthorizationRecordError::InvalidPayload)
        } else {
            Ok(Self(bytes))
        }
    }
}

/// Stores the highest plan and lease fence accepted for one assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerAuthorizationFenceV1 {
    assignment: BrokerAssignment,
    node: NodeId,
    plan_digest: ObjectDigest,
    plan_expires_seconds: i64,
    ownership_authority: KeyReference,
    local_lease_record: LocalLeaseRecord,
}

impl BrokerAuthorizationFenceV1 {
    /// Constructs one internally consistent authorization fence.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRecordError::InvalidPayload`] for sentinel plan
    /// fields, a non-ownership key, or a local lease bound to another
    /// assignment or node.
    pub fn new(
        assignment: BrokerAssignment,
        node: NodeId,
        plan_digest: ObjectDigest,
        plan_expires_seconds: i64,
        ownership_authority: KeyReference,
        local_lease_record: LocalLeaseRecord,
    ) -> Result<Self, AuthorizationRecordError> {
        let record = Self {
            assignment,
            node,
            plan_digest,
            plan_expires_seconds,
            ownership_authority,
            local_lease_record,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the exact broker-plan assignment.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }

    /// Returns the exact node admitted by the plan and lease.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the verified broker-plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    /// Returns the exact ownership-authority key generation.
    #[must_use]
    pub const fn ownership_authority(&self) -> &KeyReference {
        &self.ownership_authority
    }

    /// Returns the nested node-local lease record.
    #[must_use]
    pub const fn local_lease_record(&self) -> &LocalLeaseRecord {
        &self.local_lease_record
    }

    fn validate(&self) -> Result<(), AuthorizationRecordError> {
        let lease_assignment = self.local_lease_record.assignment();
        if self.node.as_bytes() == &[0; 16]
            || self.plan_digest.as_bytes() == &[0; 32]
            || self.plan_expires_seconds <= 0
            || self.ownership_authority.usage() != KeyUsage::OwnershipLease
            || self.ownership_authority.generation() == 0
            || self.ownership_authority.public_key_sha256().as_bytes() == &[0; 32]
            || self.local_lease_record.authority_expires_seconds() <= 0
            || lease_assignment.sandbox() != self.assignment.sandbox()
            || lease_assignment.incarnation() != self.assignment.incarnation()
            || lease_assignment.epoch() != self.assignment.epoch()
            || lease_assignment.digest() != self.assignment.digest()
            || self.local_lease_record.node() != self.node
        {
            return Err(AuthorizationRecordError::InvalidPayload);
        }
        Ok(())
    }
}

/// Identifies whether a durable effect is pending or has a stored receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerEffectStatusV2 {
    /// The durable intent is committed but completion is not recorded.
    Pending,
    /// The effect has a nonempty bounded durable receipt.
    Complete,
}

/// Retains every field of a non-authorizing broker admission intersection.
///
/// This value is durable evidence of an admitted intent. It is not itself an
/// executable capability; the broker must authenticate it after journal
/// recovery and recheck its wall-clock, boot, and BOOTTIME limits immediately
/// before performing an effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerEffectIntentV2 {
    status: BrokerEffectStatusV2,
    request_id: [u8; 16],
    transport_request_digest: ObjectDigest,
    request_digest: ObjectDigest,
    plan_digest: ObjectDigest,
    lease_digest: ObjectDigest,
    verb: BrokerVerb,
    target: BrokerGrantTarget,
    maximum_request_bytes: u32,
    maximum_descriptors: u16,
    plan_expires_seconds: i64,
    authority_expires_seconds: i64,
    host_boot_id: [u8; 16],
    fail_stop_boottime_nanoseconds: u64,
    clock_provenance: [u8; 16],
    admitted_wall_seconds: i64,
    admitted_boottime_nanoseconds: u64,
    request_deadline_boottime_nanoseconds: u64,
    effect_deadline_boottime_nanoseconds: u64,
    local_lease_record: LocalLeaseRecord,
    receipt: Vec<u8>,
}

impl BrokerEffectIntentV2 {
    /// Captures one exact non-authorizing intersection as pending intent.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRecordError::InvalidPayload`] if the nested
    /// lease does not exactly support the intersection or any retained field
    /// uses a reserved value.
    pub fn pending(
        intersection: &BrokerAdmissionIntersection,
        transport_request_digest: ObjectDigest,
        local_lease_record: LocalLeaseRecord,
        admission_clock: RawPairedClockSample,
        request_deadline_boottime_nanoseconds: u64,
        effect_deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, AuthorizationRecordError> {
        let intent = Self {
            status: BrokerEffectStatusV2::Pending,
            request_id: *intersection.request_id(),
            transport_request_digest,
            request_digest: intersection.request_digest(),
            plan_digest: intersection.plan_digest(),
            lease_digest: intersection.lease_digest(),
            verb: intersection.verb(),
            target: intersection.target(),
            maximum_request_bytes: intersection.maximum_request_bytes(),
            maximum_descriptors: intersection.maximum_descriptors(),
            plan_expires_seconds: intersection.plan_expires_seconds(),
            authority_expires_seconds: intersection.authority_expires_seconds(),
            host_boot_id: *intersection.host_boot_id(),
            fail_stop_boottime_nanoseconds: intersection.fail_stop_boottime_nanoseconds(),
            clock_provenance: admission_clock.provenance().as_bytes(),
            admitted_wall_seconds: admission_clock.wall_seconds(),
            admitted_boottime_nanoseconds: admission_clock.boottime_nanoseconds(),
            request_deadline_boottime_nanoseconds,
            effect_deadline_boottime_nanoseconds,
            local_lease_record,
            receipt: Vec::new(),
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Converts a pending intent into a completed durable record.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRecordError::InvalidPayload`] unless this record
    /// is pending and the receipt is nonempty and at most one MiB.
    pub fn complete(mut self, receipt: Vec<u8>) -> Result<Self, AuthorizationRecordError> {
        if self.status != BrokerEffectStatusV2::Pending
            || receipt.is_empty()
            || receipt.len() > MAXIMUM_RECEIPT_BYTES
        {
            return Err(AuthorizationRecordError::InvalidPayload);
        }
        self.status = BrokerEffectStatusV2::Complete;
        self.receipt = receipt;
        Ok(self)
    }

    /// Returns the durable effect status.
    #[must_use]
    pub const fn status(&self) -> BrokerEffectStatusV2 {
        self.status
    }

    /// Returns the exact consumed request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Returns SHA-256 over the exact received request body for idempotency.
    #[must_use]
    pub const fn transport_request_digest(&self) -> ObjectDigest {
        self.transport_request_digest
    }

    /// Returns the canonical semantic request digest.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the verified plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    /// Returns the verified ownership lease digest.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the exact admitted semantic verb.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        self.verb
    }

    /// Returns the exact admitted grant target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the signed request-body ceiling.
    #[must_use]
    #[cfg(test)]
    pub const fn maximum_request_bytes(&self) -> u32 {
        self.maximum_request_bytes
    }

    /// Returns the signed descriptor-count ceiling.
    #[must_use]
    #[cfg(test)]
    pub const fn maximum_descriptors(&self) -> u16 {
        self.maximum_descriptors
    }

    /// Returns the exclusive plan wall-clock expiry.
    #[must_use]
    pub const fn plan_expires_seconds(&self) -> i64 {
        self.plan_expires_seconds
    }

    /// Returns the exclusive ownership-authority wall-clock expiry.
    #[must_use]
    pub const fn authority_expires_seconds(&self) -> i64 {
        self.authority_expires_seconds
    }

    /// Returns the boot identity under which the local deadline was derived.
    #[must_use]
    pub const fn host_boot_id(&self) -> &[u8; 16] {
        &self.host_boot_id
    }

    /// Returns the protected reader identity used at admission.
    #[must_use]
    pub const fn clock_provenance(&self) -> &[u8; 16] {
        &self.clock_provenance
    }

    /// Returns the wall-clock second sampled at admission.
    #[must_use]
    pub const fn admitted_wall_seconds(&self) -> i64 {
        self.admitted_wall_seconds
    }

    /// Returns the `CLOCK_BOOTTIME` nanoseconds sampled at admission.
    #[must_use]
    pub const fn admitted_boottime_nanoseconds(&self) -> u64 {
        self.admitted_boottime_nanoseconds
    }

    /// Returns the exclusive intersection deadline for the effect.
    #[must_use]
    pub const fn effect_deadline_boottime_nanoseconds(&self) -> u64 {
        self.effect_deadline_boottime_nanoseconds
    }

    /// Returns the completion receipt, or an empty slice while pending.
    #[must_use]
    pub fn receipt(&self) -> &[u8] {
        &self.receipt
    }

    fn validate(&self) -> Result<(), AuthorizationRecordError> {
        let target_valid = match (self.verb, self.target) {
            (BrokerVerb::HostLaunch | BrokerVerb::HostInventory, BrokerGrantTarget::Assignment) => {
                true
            }
            (
                BrokerVerb::HostStop
                | BrokerVerb::HostFreeze
                | BrokerVerb::HostThaw
                | BrokerVerb::HostKill
                | BrokerVerb::HostObserve,
                BrokerGrantTarget::Resource(_),
            ) => true,
            (
                BrokerVerb::MountCreate | BrokerVerb::MountMaterializeDestinationSlot,
                BrokerGrantTarget::Assignment,
            ) => true,
            (
                BrokerVerb::MountInstall
                | BrokerVerb::MountDetach
                | BrokerVerb::MountRelease
                | BrokerVerb::MountReapDestinationSlot,
                BrokerGrantTarget::Resource(_),
            ) => true,
            (
                BrokerVerb::MountReplace,
                BrokerGrantTarget::ResourcePair {
                    previous,
                    successor,
                },
            ) => previous != successor,
            (
                BrokerVerb::StorageCreateWorkspace | BrokerVerb::NetworkPrepare,
                BrokerGrantTarget::Assignment,
            ) => true,
            (
                BrokerVerb::StorageSnapshot
                | BrokerVerb::StorageHoldSnapshot
                | BrokerVerb::StorageReleaseHold
                | BrokerVerb::StorageClone
                | BrokerVerb::StorageSetQuota
                | BrokerVerb::StorageDestroy
                | BrokerVerb::NetworkArmLease
                | BrokerVerb::NetworkRenewLease
                | BrokerVerb::NetworkDisarm
                | BrokerVerb::NetworkDestroy,
                BrokerGrantTarget::Resource(_),
            ) => true,
            _ => false,
        };
        let receipt_valid = match self.status {
            BrokerEffectStatusV2::Pending => self.receipt.is_empty(),
            BrokerEffectStatusV2::Complete => {
                !self.receipt.is_empty() && self.receipt.len() <= MAXIMUM_RECEIPT_BYTES
            }
        };
        let conservative_plan_deadline = self
            .plan_expires_seconds
            .checked_sub(self.admitted_wall_seconds)
            .and_then(|seconds| seconds.checked_sub(1))
            .and_then(|seconds| u64::try_from(seconds).ok())
            .filter(|seconds| *seconds > 0)
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|duration| self.admitted_boottime_nanoseconds.checked_add(duration));
        if self.request_id == [0; 16]
            || self.transport_request_digest.as_bytes() == &[0; 32]
            || self.request_digest.as_bytes() == &[0; 32]
            || self.plan_digest.as_bytes() == &[0; 32]
            || self.lease_digest.as_bytes() == &[0; 32]
            || self.maximum_request_bytes == 0
            || self.maximum_request_bytes > MAXIMUM_REQUEST_BYTES
            || self.maximum_descriptors > MAXIMUM_DESCRIPTORS
            || self.plan_expires_seconds <= 0
            || self.authority_expires_seconds <= 0
            || self.host_boot_id == [0; 16]
            || self.fail_stop_boottime_nanoseconds == 0
            || self.clock_provenance == [0; 16]
            || self.request_deadline_boottime_nanoseconds <= self.admitted_boottime_nanoseconds
            || self.effect_deadline_boottime_nanoseconds <= self.admitted_boottime_nanoseconds
            || self.effect_deadline_boottime_nanoseconds
                > self.request_deadline_boottime_nanoseconds
            || self.effect_deadline_boottime_nanoseconds > self.fail_stop_boottime_nanoseconds
            || conservative_plan_deadline
                .is_none_or(|deadline| self.effect_deadline_boottime_nanoseconds > deadline)
            || self.local_lease_record.lease_digest() != self.lease_digest
            || self.local_lease_record.authority_expires_seconds() != self.authority_expires_seconds
            || self.local_lease_record.host_boot_id() != &self.host_boot_id
            || self.local_lease_record.clock_provenance() != &self.clock_provenance
            || self.local_lease_record.fail_stop_boottime_nanoseconds()
                != self.fail_stop_boottime_nanoseconds
            || !target_valid
            || !receipt_valid
        {
            return Err(AuthorizationRecordError::InvalidPayload);
        }
        Ok(())
    }
}

/// Encodes and authenticates one assignment authorization fence.
///
/// # Errors
///
/// Returns [`AuthorizationRecordError`] for an invalid fence, journal key, or
/// payload bound.
pub fn seal_authorization_fence(
    mac_key: &NodeJournalMacKey,
    namespace: RecordNamespace,
    journal_key: &[u8],
    fence: &BrokerAuthorizationFenceV1,
) -> Result<Vec<u8>, AuthorizationRecordError> {
    fence.validate()?;
    let payload = encode_fence(fence, mac_key.domain)?;
    seal(
        mac_key,
        namespace,
        journal_key,
        AuthenticatedValueKind::AuthorizationFence,
        &payload,
    )
}

/// Authenticates and decodes one assignment authorization fence.
///
/// Authentication covers the exact namespace and journal key and completes
/// before any fence fields are decoded.
///
/// # Errors
///
/// Returns [`AuthorizationRecordError`] for malformed, unauthenticated,
/// misplaced, unknown-kind, or semantically invalid bytes.
pub fn open_authorization_fence(
    mac_key: &NodeJournalMacKey,
    namespace: RecordNamespace,
    journal_key: &[u8],
    bytes: &[u8],
) -> Result<BrokerAuthorizationFenceV1, AuthorizationRecordError> {
    let payload = open(
        mac_key,
        namespace,
        journal_key,
        AuthenticatedValueKind::AuthorizationFence,
        bytes,
    )?;
    decode_fence(payload, mac_key.domain)
}

/// Encodes and authenticates one durable broker effect intent.
///
/// # Errors
///
/// Returns [`AuthorizationRecordError`] for an invalid intent, journal key, or
/// payload bound.
pub fn seal_effect_intent(
    mac_key: &NodeJournalMacKey,
    namespace: RecordNamespace,
    journal_key: &[u8],
    intent: &BrokerEffectIntentV2,
) -> Result<Vec<u8>, AuthorizationRecordError> {
    intent.validate()?;
    let payload = encode_effect(intent, mac_key.domain)?;
    seal(
        mac_key,
        namespace,
        journal_key,
        AuthenticatedValueKind::EffectIntent,
        &payload,
    )
}

/// Authenticates and decodes one durable broker effect intent.
///
/// Authentication covers the exact namespace and journal key and completes
/// before any effect fields are decoded.
///
/// # Errors
///
/// Returns [`AuthorizationRecordError`] for malformed, unauthenticated,
/// misplaced, unknown-kind, or semantically invalid bytes.
pub fn open_effect_intent(
    mac_key: &NodeJournalMacKey,
    namespace: RecordNamespace,
    journal_key: &[u8],
    bytes: &[u8],
) -> Result<BrokerEffectIntentV2, AuthorizationRecordError> {
    let payload = open(
        mac_key,
        namespace,
        journal_key,
        AuthenticatedValueKind::EffectIntent,
        bytes,
    )?;
    decode_effect(payload, mac_key.domain)
}

pub(crate) fn seal_local_record(
    mac_key: &NodeJournalMacKey,
    namespace: RecordNamespace,
    journal_key: &[u8],
    domain: BrokerLocalRecordDomain,
    payload: &[u8],
) -> Result<Vec<u8>, AuthorizationRecordError> {
    let framed_length = LOCAL_RECORD_DOMAIN_BYTES
        .checked_add(payload.len())
        .filter(|length| *length <= MAXIMUM_AUTHENTICATED_PAYLOAD_BYTES)
        .ok_or(AuthorizationRecordError::InvalidFraming)?;
    let mut framed = Vec::with_capacity(framed_length);
    framed.extend_from_slice(&domain.0);
    framed.extend_from_slice(payload);
    seal(
        mac_key,
        namespace,
        journal_key,
        AuthenticatedValueKind::LocalRecord,
        &framed,
    )
}

pub(crate) fn open_local_record<'a>(
    mac_key: &NodeJournalMacKey,
    namespace: RecordNamespace,
    journal_key: &[u8],
    domain: BrokerLocalRecordDomain,
    bytes: &'a [u8],
) -> Result<&'a [u8], AuthorizationRecordError> {
    let framed = open(
        mac_key,
        namespace,
        journal_key,
        AuthenticatedValueKind::LocalRecord,
        bytes,
    )?;
    if framed.len() < LOCAL_RECORD_DOMAIN_BYTES || framed[..LOCAL_RECORD_DOMAIN_BYTES] != domain.0 {
        return Err(AuthorizationRecordError::WrongKind);
    }
    Ok(&framed[LOCAL_RECORD_DOMAIN_BYTES..])
}

fn seal(
    mac_key: &NodeJournalMacKey,
    namespace: RecordNamespace,
    journal_key: &[u8],
    kind: AuthenticatedValueKind,
    payload: &[u8],
) -> Result<Vec<u8>, AuthorizationRecordError> {
    validate_wrapper_bounds(journal_key, payload)?;
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| AuthorizationRecordError::InvalidFraming)?;
    let mut bytes = Vec::with_capacity(AUTHENTICATED_FIXED_BYTES + payload.len());
    bytes.extend_from_slice(mac_key.domain.authenticated_magic());
    bytes.extend_from_slice(&AUTHENTICATED_VERSION.to_be_bytes());
    bytes.push(kind as u8);
    bytes.push(0);
    bytes.extend_from_slice(mac_key.key_id());
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.extend_from_slice(payload);
    let tag = authentication_tag(mac_key, namespace, journal_key, kind as u8, payload)?;
    bytes.extend_from_slice(&tag);
    Ok(bytes)
}

fn open<'a>(
    mac_key: &NodeJournalMacKey,
    namespace: RecordNamespace,
    journal_key: &[u8],
    expected_kind: AuthenticatedValueKind,
    bytes: &'a [u8],
) -> Result<&'a [u8], AuthorizationRecordError> {
    if journal_key.is_empty()
        || journal_key.len() > MAXIMUM_JOURNAL_KEY_BYTES
        || bytes.len() < AUTHENTICATED_FIXED_BYTES
        || &bytes[..8] != mac_key.domain.authenticated_magic()
        || u16::from_be_bytes([bytes[8], bytes[9]]) != AUTHENTICATED_VERSION
        || bytes[11] != 0
    {
        return Err(AuthorizationRecordError::InvalidFraming);
    }
    if bytes[12..28] != mac_key.key_id[..] {
        return Err(AuthorizationRecordError::AuthenticationFailed);
    }
    let payload_length = u32::from_be_bytes(
        bytes[28..32]
            .try_into()
            .map_err(|_| AuthorizationRecordError::InvalidFraming)?,
    ) as usize;
    if payload_length > MAXIMUM_AUTHENTICATED_PAYLOAD_BYTES
        || bytes.len() != AUTHENTICATED_FIXED_BYTES + payload_length
    {
        return Err(AuthorizationRecordError::InvalidFraming);
    }
    let payload_end = 32 + payload_length;
    let payload = &bytes[32..payload_end];
    let tag = &bytes[payload_end..];
    let mut mac = new_mac(mac_key)?;
    update_authentication_input(
        &mut mac,
        mac_key.domain,
        mac_key.key_id(),
        namespace,
        journal_key,
        bytes[10],
        payload,
    )?;
    mac.verify_slice(tag)
        .map_err(|_| AuthorizationRecordError::AuthenticationFailed)?;

    let actual_kind = match bytes[10] {
        1 => AuthenticatedValueKind::AuthorizationFence,
        2 => AuthenticatedValueKind::EffectIntent,
        3 => AuthenticatedValueKind::LocalRecord,
        _ => return Err(AuthorizationRecordError::WrongKind),
    };
    if actual_kind != expected_kind {
        return Err(AuthorizationRecordError::WrongKind);
    }
    Ok(payload)
}

fn authentication_tag(
    mac_key: &NodeJournalMacKey,
    namespace: RecordNamespace,
    journal_key: &[u8],
    kind: u8,
    payload: &[u8],
) -> Result<[u8; 32], AuthorizationRecordError> {
    let mut mac = new_mac(mac_key)?;
    update_authentication_input(
        &mut mac,
        mac_key.domain,
        mac_key.key_id(),
        namespace,
        journal_key,
        kind,
        payload,
    )?;
    Ok(mac.finalize().into_bytes().into())
}

fn new_mac(mac_key: &NodeJournalMacKey) -> Result<HmacSha256, AuthorizationRecordError> {
    HmacSha256::new_from_slice(mac_key.secret.as_ref())
        .map_err(|_| AuthorizationRecordError::InvalidKey)
}

fn update_authentication_input(
    mac: &mut HmacSha256,
    domain: BrokerDomain,
    key_id: &[u8; 16],
    namespace: RecordNamespace,
    journal_key: &[u8],
    kind: u8,
    payload: &[u8],
) -> Result<(), AuthorizationRecordError> {
    validate_wrapper_bounds(journal_key, payload)?;
    let key_length =
        u16::try_from(journal_key.len()).map_err(|_| AuthorizationRecordError::InvalidFraming)?;
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| AuthorizationRecordError::InvalidFraming)?;
    mac.update(domain.authentication_domain());
    mac.update(&AUTHENTICATED_VERSION.to_be_bytes());
    mac.update(key_id);
    mac.update(&[namespace as u8]);
    mac.update(&key_length.to_be_bytes());
    mac.update(journal_key);
    mac.update(&[kind]);
    mac.update(&payload_length.to_be_bytes());
    mac.update(payload);
    Ok(())
}

fn validate_wrapper_bounds(
    journal_key: &[u8],
    payload: &[u8],
) -> Result<(), AuthorizationRecordError> {
    if journal_key.is_empty()
        || journal_key.len() > MAXIMUM_JOURNAL_KEY_BYTES
        || payload.len() > MAXIMUM_AUTHENTICATED_PAYLOAD_BYTES
    {
        Err(AuthorizationRecordError::InvalidFraming)
    } else {
        Ok(())
    }
}

fn encode_fence(
    fence: &BrokerAuthorizationFenceV1,
    domain: BrokerDomain,
) -> Result<Vec<u8>, AuthorizationRecordError> {
    let stable_key_id = fence
        .ownership_authority
        .stable_key_id()
        .as_str()
        .as_bytes();
    let stable_key_id_length =
        u8::try_from(stable_key_id.len()).map_err(|_| AuthorizationRecordError::InvalidPayload)?;
    let lease_bytes = encode_local_lease_record(&fence.local_lease_record);
    if lease_bytes.len() != LOCAL_LEASE_RECORD_BYTES {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let mut bytes = Vec::with_capacity(408 + stable_key_id.len());
    bytes.extend_from_slice(domain.fence_magic());
    bytes.extend_from_slice(&FENCE_VERSION.to_be_bytes());
    encode_assignment(&mut bytes, fence.assignment);
    bytes.extend_from_slice(fence.node.as_bytes());
    bytes.extend_from_slice(fence.plan_digest.as_bytes());
    bytes.extend_from_slice(&fence.plan_expires_seconds.to_be_bytes());
    bytes.push(stable_key_id_length);
    bytes.extend_from_slice(stable_key_id);
    bytes.extend_from_slice(&fence.ownership_authority.generation().to_be_bytes());
    bytes.extend_from_slice(fence.ownership_authority.public_key_sha256().as_bytes());
    bytes.push(key_usage_code(fence.ownership_authority.usage())?);
    bytes.extend_from_slice(&lease_bytes);
    Ok(bytes)
}

fn decode_fence(
    bytes: &[u8],
    domain: BrokerDomain,
) -> Result<BrokerAuthorizationFenceV1, AuthorizationRecordError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take::<8>()? != *domain.fence_magic() || decoder.u16()? != FENCE_VERSION {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let assignment = decode_assignment(&mut decoder)?;
    let node = NodeId::from_bytes(decoder.take::<16>()?);
    let plan_digest = ObjectDigest::from_bytes(decoder.take::<32>()?);
    let plan_expires_seconds = decoder.i64()?;
    let stable_key_id_length = decoder.u8()? as usize;
    if stable_key_id_length == 0 || stable_key_id_length > MAXIMUM_STABLE_KEY_ID_BYTES {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let stable_key_id_text = std::str::from_utf8(decoder.bytes(stable_key_id_length)?)
        .map_err(|_| AuthorizationRecordError::InvalidPayload)?;
    let stable_key_id = StableKeyId::new(stable_key_id_text.to_owned())
        .map_err(|_| AuthorizationRecordError::InvalidPayload)?;
    let authority_generation = decoder.u64()?;
    let authority_public_key = ObjectDigest::from_bytes(decoder.take::<32>()?);
    let authority_usage = decode_key_usage(decoder.u8()?)?;
    let ownership_authority = KeyReference::new(
        stable_key_id,
        authority_generation,
        authority_public_key,
        authority_usage,
    );
    let local_lease_record = decode_local_lease_record(decoder.bytes(LOCAL_LEASE_RECORD_BYTES)?)
        .map_err(|_| AuthorizationRecordError::InvalidPayload)?;
    decoder.finish()?;
    BrokerAuthorizationFenceV1::new(
        assignment,
        node,
        plan_digest,
        plan_expires_seconds,
        ownership_authority,
        local_lease_record,
    )
}

fn encode_effect(
    intent: &BrokerEffectIntentV2,
    domain: BrokerDomain,
) -> Result<Vec<u8>, AuthorizationRecordError> {
    let lease_bytes = encode_local_lease_record(&intent.local_lease_record);
    let receipt_length = u32::try_from(intent.receipt.len())
        .map_err(|_| AuthorizationRecordError::InvalidPayload)?;
    let encoded_verb = verb_code(domain, intent.verb);
    if encoded_verb == 0 {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let mut bytes = Vec::with_capacity(554 + intent.receipt.len());
    bytes.extend_from_slice(domain.effect_magic());
    bytes.extend_from_slice(&EFFECT_VERSION.to_be_bytes());
    bytes.push(match intent.status {
        BrokerEffectStatusV2::Pending => 0,
        BrokerEffectStatusV2::Complete => 1,
    });
    bytes.push(encoded_verb);
    encode_target(&mut bytes, intent.target);
    bytes.extend_from_slice(&intent.request_id);
    bytes.extend_from_slice(intent.transport_request_digest.as_bytes());
    bytes.extend_from_slice(intent.request_digest.as_bytes());
    bytes.extend_from_slice(intent.plan_digest.as_bytes());
    bytes.extend_from_slice(intent.lease_digest.as_bytes());
    bytes.extend_from_slice(&intent.maximum_request_bytes.to_be_bytes());
    bytes.extend_from_slice(&intent.maximum_descriptors.to_be_bytes());
    bytes.extend_from_slice(&intent.plan_expires_seconds.to_be_bytes());
    bytes.extend_from_slice(&intent.authority_expires_seconds.to_be_bytes());
    bytes.extend_from_slice(&intent.host_boot_id);
    bytes.extend_from_slice(&intent.fail_stop_boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(&intent.clock_provenance);
    bytes.extend_from_slice(&intent.admitted_wall_seconds.to_be_bytes());
    bytes.extend_from_slice(&intent.admitted_boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(&intent.request_deadline_boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(&intent.effect_deadline_boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(&lease_bytes);
    bytes.extend_from_slice(&receipt_length.to_be_bytes());
    bytes.extend_from_slice(&intent.receipt);
    Ok(bytes)
}

fn decode_effect(
    bytes: &[u8],
    domain: BrokerDomain,
) -> Result<BrokerEffectIntentV2, AuthorizationRecordError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take::<8>()? != *domain.effect_magic() || decoder.u16()? != EFFECT_VERSION {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let status = match decoder.u8()? {
        0 => BrokerEffectStatusV2::Pending,
        1 => BrokerEffectStatusV2::Complete,
        _ => return Err(AuthorizationRecordError::InvalidPayload),
    };
    let verb = decode_verb(domain, decoder.u8()?)?;
    let target = decode_target(&mut decoder)?;
    let request_id = decoder.take::<16>()?;
    let transport_request_digest = ObjectDigest::from_bytes(decoder.take::<32>()?);
    let request_digest = ObjectDigest::from_bytes(decoder.take::<32>()?);
    let plan_digest = ObjectDigest::from_bytes(decoder.take::<32>()?);
    let lease_digest = ObjectDigest::from_bytes(decoder.take::<32>()?);
    let maximum_request_bytes = decoder.u32()?;
    let maximum_descriptors = decoder.u16()?;
    let plan_expires_seconds = decoder.i64()?;
    let authority_expires_seconds = decoder.i64()?;
    let host_boot_id = decoder.take::<16>()?;
    let fail_stop_boottime_nanoseconds = decoder.u64()?;
    let clock_provenance = decoder.take::<16>()?;
    let admitted_wall_seconds = decoder.i64()?;
    let admitted_boottime_nanoseconds = decoder.u64()?;
    let request_deadline_boottime_nanoseconds = decoder.u64()?;
    let effect_deadline_boottime_nanoseconds = decoder.u64()?;
    let local_lease_record = decode_local_lease_record(decoder.bytes(LOCAL_LEASE_RECORD_BYTES)?)
        .map_err(|_| AuthorizationRecordError::InvalidPayload)?;
    let receipt_length = decoder.u32()? as usize;
    if receipt_length > MAXIMUM_RECEIPT_BYTES {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let receipt = decoder.bytes(receipt_length)?.to_vec();
    decoder.finish()?;
    let intent = BrokerEffectIntentV2 {
        status,
        request_id,
        transport_request_digest,
        request_digest,
        plan_digest,
        lease_digest,
        verb,
        target,
        maximum_request_bytes,
        maximum_descriptors,
        plan_expires_seconds,
        authority_expires_seconds,
        host_boot_id,
        fail_stop_boottime_nanoseconds,
        clock_provenance,
        admitted_wall_seconds,
        admitted_boottime_nanoseconds,
        request_deadline_boottime_nanoseconds,
        effect_deadline_boottime_nanoseconds,
        local_lease_record,
        receipt,
    };
    intent.validate()?;
    Ok(intent)
}

fn encode_assignment(bytes: &mut Vec<u8>, assignment: BrokerAssignment) {
    bytes.extend_from_slice(assignment.sandbox().as_bytes());
    bytes.extend_from_slice(assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(assignment.digest().as_bytes());
}

fn decode_assignment(
    decoder: &mut Decoder<'_>,
) -> Result<BrokerAssignment, AuthorizationRecordError> {
    BrokerAssignment::new(
        SandboxId::from_bytes(decoder.take::<16>()?),
        IncarnationId::from_bytes(decoder.take::<16>()?),
        AssignmentEpoch::new(decoder.u64()?),
        DesiredGeneration::new(decoder.u64()?),
        ObjectDigest::from_bytes(decoder.take::<32>()?),
    )
    .map_err(|_| AuthorizationRecordError::InvalidPayload)
}

fn encode_target(bytes: &mut Vec<u8>, target: BrokerGrantTarget) {
    match target {
        BrokerGrantTarget::Assignment => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 64]);
        }
        BrokerGrantTarget::Resource(handle) => {
            bytes.push(1);
            bytes.extend_from_slice(handle.as_bytes());
            bytes.extend_from_slice(&[0; 32]);
        }
        BrokerGrantTarget::ResourcePair {
            previous,
            successor,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(previous.as_bytes());
            bytes.extend_from_slice(successor.as_bytes());
        }
    }
}

fn decode_target(decoder: &mut Decoder<'_>) -> Result<BrokerGrantTarget, AuthorizationRecordError> {
    let tag = decoder.u8()?;
    let first = decoder.take::<32>()?;
    let second = decoder.take::<32>()?;
    match tag {
        0 if first == [0; 32] && second == [0; 32] => Ok(BrokerGrantTarget::Assignment),
        1 if second == [0; 32] => Ok(BrokerGrantTarget::Resource(resource_handle(first)?)),
        2 => Ok(BrokerGrantTarget::ResourcePair {
            previous: resource_handle(first)?,
            successor: resource_handle(second)?,
        }),
        _ => Err(AuthorizationRecordError::InvalidPayload),
    }
}

fn resource_handle(bytes: [u8; 32]) -> Result<BrokerResourceHandle, AuthorizationRecordError> {
    BrokerResourceHandle::from_bytes(bytes).map_err(|_| AuthorizationRecordError::InvalidPayload)
}

const fn verb_code(domain: BrokerDomain, verb: BrokerVerb) -> u8 {
    match (domain, verb) {
        (BrokerDomain::Host, BrokerVerb::HostLaunch)
        | (BrokerDomain::Mount, BrokerVerb::MountCreate) => 1,
        (BrokerDomain::Host, BrokerVerb::HostStop)
        | (BrokerDomain::Mount, BrokerVerb::MountInstall) => 2,
        (BrokerDomain::Host, BrokerVerb::HostFreeze)
        | (BrokerDomain::Mount, BrokerVerb::MountReplace) => 3,
        (BrokerDomain::Host, BrokerVerb::HostThaw)
        | (BrokerDomain::Mount, BrokerVerb::MountDetach) => 4,
        (BrokerDomain::Host, BrokerVerb::HostKill)
        | (BrokerDomain::Mount, BrokerVerb::MountRelease) => 5,
        (BrokerDomain::Mount, BrokerVerb::MountMaterializeDestinationSlot) => 6,
        (BrokerDomain::Mount, BrokerVerb::MountReapDestinationSlot) => 7,
        (BrokerDomain::Storage, BrokerVerb::StorageCreateWorkspace)
        | (BrokerDomain::Network, BrokerVerb::NetworkPrepare) => 1,
        (BrokerDomain::Storage, BrokerVerb::StorageSnapshot)
        | (BrokerDomain::Network, BrokerVerb::NetworkArmLease) => 2,
        (BrokerDomain::Storage, BrokerVerb::StorageHoldSnapshot)
        | (BrokerDomain::Network, BrokerVerb::NetworkRenewLease) => 3,
        (BrokerDomain::Storage, BrokerVerb::StorageReleaseHold)
        | (BrokerDomain::Network, BrokerVerb::NetworkDisarm) => 4,
        (BrokerDomain::Storage, BrokerVerb::StorageClone)
        | (BrokerDomain::Network, BrokerVerb::NetworkDestroy) => 5,
        (BrokerDomain::Storage, BrokerVerb::StorageSetQuota) => 6,
        (BrokerDomain::Storage, BrokerVerb::StorageDestroy) => 7,
        _ => 0,
    }
}

fn decode_verb(domain: BrokerDomain, code: u8) -> Result<BrokerVerb, AuthorizationRecordError> {
    match (domain, code) {
        (BrokerDomain::Host, 1) => Ok(BrokerVerb::HostLaunch),
        (BrokerDomain::Host, 2) => Ok(BrokerVerb::HostStop),
        (BrokerDomain::Host, 3) => Ok(BrokerVerb::HostFreeze),
        (BrokerDomain::Host, 4) => Ok(BrokerVerb::HostThaw),
        (BrokerDomain::Host, 5) => Ok(BrokerVerb::HostKill),
        (BrokerDomain::Mount, 1) => Ok(BrokerVerb::MountCreate),
        (BrokerDomain::Mount, 2) => Ok(BrokerVerb::MountInstall),
        (BrokerDomain::Mount, 3) => Ok(BrokerVerb::MountReplace),
        (BrokerDomain::Mount, 4) => Ok(BrokerVerb::MountDetach),
        (BrokerDomain::Mount, 5) => Ok(BrokerVerb::MountRelease),
        (BrokerDomain::Mount, 6) => Ok(BrokerVerb::MountMaterializeDestinationSlot),
        (BrokerDomain::Mount, 7) => Ok(BrokerVerb::MountReapDestinationSlot),
        (BrokerDomain::Storage, 1) => Ok(BrokerVerb::StorageCreateWorkspace),
        (BrokerDomain::Storage, 2) => Ok(BrokerVerb::StorageSnapshot),
        (BrokerDomain::Storage, 3) => Ok(BrokerVerb::StorageHoldSnapshot),
        (BrokerDomain::Storage, 4) => Ok(BrokerVerb::StorageReleaseHold),
        (BrokerDomain::Storage, 5) => Ok(BrokerVerb::StorageClone),
        (BrokerDomain::Storage, 6) => Ok(BrokerVerb::StorageSetQuota),
        (BrokerDomain::Storage, 7) => Ok(BrokerVerb::StorageDestroy),
        (BrokerDomain::Network, 1) => Ok(BrokerVerb::NetworkPrepare),
        (BrokerDomain::Network, 2) => Ok(BrokerVerb::NetworkArmLease),
        (BrokerDomain::Network, 3) => Ok(BrokerVerb::NetworkRenewLease),
        (BrokerDomain::Network, 4) => Ok(BrokerVerb::NetworkDisarm),
        (BrokerDomain::Network, 5) => Ok(BrokerVerb::NetworkDestroy),
        _ => Err(AuthorizationRecordError::InvalidPayload),
    }
}

const fn key_usage_code(usage: KeyUsage) -> Result<u8, AuthorizationRecordError> {
    match usage {
        KeyUsage::BrokerAuthorization => Ok(1),
        KeyUsage::OwnershipLease => Ok(2),
        KeyUsage::Policy => Ok(3),
        KeyUsage::Tree => Ok(4),
        KeyUsage::Snapshot => Ok(5),
        KeyUsage::Distribution => Ok(6),
        // This journal is assignment-bound broker evidence, not a portable
        // key registry. Publisher authority must not acquire a record code.
        KeyUsage::PublisherAuthorization => Err(AuthorizationRecordError::InvalidPayload),
    }
}

fn decode_key_usage(code: u8) -> Result<KeyUsage, AuthorizationRecordError> {
    match code {
        1 => Ok(KeyUsage::BrokerAuthorization),
        2 => Ok(KeyUsage::OwnershipLease),
        3 => Ok(KeyUsage::Policy),
        4 => Ok(KeyUsage::Tree),
        5 => Ok(KeyUsage::Snapshot),
        6 => Ok(KeyUsage::Distribution),
        _ => Err(AuthorizationRecordError::InvalidPayload),
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], AuthorizationRecordError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| AuthorizationRecordError::InvalidPayload)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], AuthorizationRecordError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(AuthorizationRecordError::InvalidPayload)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AuthorizationRecordError::InvalidPayload)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, AuthorizationRecordError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, AuthorizationRecordError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, AuthorizationRecordError> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, AuthorizationRecordError> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn i64(&mut self) -> Result<i64, AuthorizationRecordError> {
        Ok(i64::from_be_bytes(self.take::<8>()?))
    }

    fn finish(self) -> Result<(), AuthorizationRecordError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(AuthorizationRecordError::InvalidPayload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::InvalidBrokerAuthorizationPlan;
    use sha2::Digest as _;

    #[test]
    fn publisher_registration_does_not_expand_broker_journal_key_usage_codes() {
        let usages = [
            KeyUsage::BrokerAuthorization,
            KeyUsage::OwnershipLease,
            KeyUsage::Policy,
            KeyUsage::Tree,
            KeyUsage::Snapshot,
            KeyUsage::Distribution,
        ];
        for (code, usage) in (1u8..=6).zip(usages) {
            assert_eq!(key_usage_code(usage), Ok(code));
            assert_eq!(decode_key_usage(code), Ok(usage));
        }
        assert_eq!(
            key_usage_code(KeyUsage::PublisherAuthorization),
            Err(AuthorizationRecordError::InvalidPayload)
        );
        for code in [0, 7, 255] {
            assert_eq!(
                decode_key_usage(code),
                Err(AuthorizationRecordError::InvalidPayload)
            );
        }
    }

    const LOCAL_LEASE_HEX: &str = "414f534c4c520000000101010101010101010101010101010101020202020202020202020202020202020000000000000003050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606000000000000000750eaa2c31b835f37356d5208fd40899bbbb3b0f08bcfdbf257bab78e32b7adb60909090909090909090909090909090900000000000000c81414141414141414141414141414141408080808080808080808080808080808000000082629a1e858e97bc412c719f27e387e104300c6082338a6cf4bfac5d9adc0dcacb7a633d7";

    fn mac_key() -> NodeJournalMacKey {
        NodeJournalMacKey::new(BrokerDomain::Mount, [90; 16], [91; 32])
            .unwrap_or_else(|error| panic!("key: {error}"))
    }

    fn local_lease() -> LocalLeaseRecord {
        let bytes = hex::decode(LOCAL_LEASE_HEX).unwrap_or_else(|error| panic!("hex: {error}"));
        decode_local_lease_record(&bytes).unwrap_or_else(|error| panic!("lease: {error}"))
    }

    #[test]
    fn local_records_are_bound_to_domain_location_and_payload() {
        let domain = BrokerLocalRecordDomain::new(*b"AOSNETSTATEV0001")
            .unwrap_or_else(|error| panic!("domain: {error}"));
        let other = BrokerLocalRecordDomain::new(*b"AOSNETSTATEV0002")
            .unwrap_or_else(|error| panic!("domain: {error}"));
        let sealed = seal_local_record(
            &mac_key(),
            RecordNamespace::Operation,
            b"request-a",
            domain,
            b"payload",
        )
        .unwrap_or_else(|error| panic!("seal: {error}"));
        assert_eq!(
            open_local_record(
                &mac_key(),
                RecordNamespace::Operation,
                b"request-a",
                domain,
                &sealed,
            )
            .unwrap_or_else(|error| panic!("open: {error}")),
            b"payload"
        );
        assert!(
            open_local_record(
                &mac_key(),
                RecordNamespace::Operation,
                b"request-b",
                domain,
                &sealed,
            )
            .is_err()
        );
        assert!(
            open_local_record(
                &mac_key(),
                RecordNamespace::Operation,
                b"request-a",
                other,
                &sealed,
            )
            .is_err()
        );
        let maximum_local_payload =
            vec![0; MAXIMUM_AUTHENTICATED_PAYLOAD_BYTES - LOCAL_RECORD_DOMAIN_BYTES];
        assert!(
            seal_local_record(
                &mac_key(),
                RecordNamespace::Operation,
                b"request-a",
                domain,
                &maximum_local_payload,
            )
            .is_ok()
        );
        let oversized_local_payload =
            vec![0; MAXIMUM_AUTHENTICATED_PAYLOAD_BYTES - LOCAL_RECORD_DOMAIN_BYTES + 1];
        assert_eq!(
            seal_local_record(
                &mac_key(),
                RecordNamespace::Operation,
                b"request-a",
                domain,
                &oversized_local_payload,
            ),
            Err(AuthorizationRecordError::InvalidFraming)
        );
    }

    fn assignment() -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap_or_else(|error| panic!("assignment: {error}"))
    }

    fn authority() -> KeyReference {
        KeyReference::new(
            StableKeyId::new("ownership-primary".to_owned())
                .unwrap_or_else(|error| panic!("stable key: {error}")),
            4,
            ObjectDigest::from_bytes([73; 32]),
            KeyUsage::OwnershipLease,
        )
    }

    fn fence() -> BrokerAuthorizationFenceV1 {
        BrokerAuthorizationFenceV1::new(
            assignment(),
            NodeId::from_bytes([6; 16]),
            ObjectDigest::from_bytes([72; 32]),
            190,
            authority(),
            local_lease(),
        )
        .unwrap_or_else(|error| panic!("fence: {error}"))
    }

    fn seal_test_payload(kind: u8, payload: &[u8]) -> Vec<u8> {
        let key = mac_key();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BrokerDomain::Mount.authenticated_magic());
        bytes.extend_from_slice(&AUTHENTICATED_VERSION.to_be_bytes());
        bytes.push(kind);
        bytes.push(0);
        bytes.extend_from_slice(key.key_id());
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        let tag = authentication_tag(
            &key,
            RecordNamespace::DesiredState,
            b"fence-key",
            kind,
            payload,
        )
        .unwrap_or_else(|error| panic!("tag: {error}"));
        bytes.extend_from_slice(&tag);
        bytes
    }

    #[test]
    fn fence_round_trip_is_authenticated_and_location_bound() {
        let key = mac_key();
        let fence = fence();
        let bytes =
            seal_authorization_fence(&key, RecordNamespace::DesiredState, b"fence-key", &fence)
                .unwrap_or_else(|error| panic!("seal: {error}"));
        assert_eq!(
            open_authorization_fence(&key, RecordNamespace::DesiredState, b"fence-key", &bytes,),
            Ok(fence)
        );
        assert_eq!(
            open_authorization_fence(&key, RecordNamespace::Effect, b"fence-key", &bytes,),
            Err(AuthorizationRecordError::AuthenticationFailed)
        );
        assert_eq!(
            open_authorization_fence(&key, RecordNamespace::DesiredState, b"another-key", &bytes,),
            Err(AuthorizationRecordError::AuthenticationFailed)
        );
    }

    #[test]
    fn mount_profile_sealed_records_match_fixed_compatibility_goldens() {
        // These digests were captured from the mount-owned encoder before the
        // shared extraction. Any framing, domain, payload, or MAC drift changes
        // them and would strand already-durable broker state.
        let key = mac_key();
        let fence =
            seal_authorization_fence(&key, RecordNamespace::DesiredState, b"fence-key", &fence())
                .unwrap_or_else(|error| panic!("seal: {error}"));
        let effect = seal_effect_intent(
            &key,
            RecordNamespace::Effect,
            &[15; 16],
            &decode_effect(&sample_effect(), BrokerDomain::Mount)
                .unwrap_or_else(|error| panic!("effect: {error}")),
        )
        .unwrap_or_else(|error| panic!("seal: {error}"));
        assert_eq!(
            hex::encode(Sha256::digest(fence)),
            "14923caa5f36efa27d114b640072c1cb4e7afbfd18425757d27e38498457effc"
        );
        assert_eq!(
            hex::encode(Sha256::digest(effect)),
            "7a46ceb9d8e4a62b314f8c70c145e9163f4cd7db23d2b9bfe0208209bc1c1f87"
        );
    }

    #[test]
    fn broker_domains_cannot_open_each_others_records() {
        let domains = [
            BrokerDomain::Host,
            BrokerDomain::Mount,
            BrokerDomain::Storage,
            BrokerDomain::Network,
        ];
        for sealing_domain in domains {
            let sealing_key = NodeJournalMacKey::new(sealing_domain, [90; 16], [91; 32])
                .unwrap_or_else(|error| panic!("key: {error}"));
            let bytes = seal_authorization_fence(
                &sealing_key,
                RecordNamespace::DesiredState,
                b"fence-key",
                &fence(),
            )
            .unwrap_or_else(|error| panic!("seal: {error}"));
            for opening_domain in domains {
                let opening_key = NodeJournalMacKey::new(opening_domain, [90; 16], [91; 32])
                    .unwrap_or_else(|error| panic!("key: {error}"));
                let result = open_authorization_fence(
                    &opening_key,
                    RecordNamespace::DesiredState,
                    b"fence-key",
                    &bytes,
                );
                if opening_domain == sealing_domain {
                    assert_eq!(result, Ok(fence()));
                } else {
                    assert!(result.is_err());
                }
            }
        }
    }

    #[test]
    fn host_profile_round_trips_its_own_verb_vocabulary() {
        let key = NodeJournalMacKey::new(BrokerDomain::Host, [90; 16], [91; 32])
            .unwrap_or_else(|error| panic!("key: {error}"));
        let mut intent = decode_effect(&sample_effect(), BrokerDomain::Mount)
            .unwrap_or_else(|error| panic!("effect: {error}"));
        intent.verb = BrokerVerb::HostStop;
        intent.target = BrokerGrantTarget::Resource(
            BrokerResourceHandle::from_bytes([7; 32])
                .unwrap_or_else(|error| panic!("resource: {error}")),
        );

        let sealed =
            seal_effect_intent(&key, RecordNamespace::Effect, intent.request_id(), &intent)
                .unwrap_or_else(|error| panic!("seal: {error}"));
        let opened =
            open_effect_intent(&key, RecordNamespace::Effect, intent.request_id(), &sealed)
                .unwrap_or_else(|error| panic!("open: {error}"));

        assert_eq!(opened, intent);
        assert_eq!(opened.verb(), BrokerVerb::HostStop);
    }

    #[test]
    fn every_effect_verb_round_trips_only_in_its_broker_domain() {
        let cases = [
            (BrokerDomain::Host, BrokerVerb::HostLaunch, 1),
            (BrokerDomain::Host, BrokerVerb::HostStop, 2),
            (BrokerDomain::Host, BrokerVerb::HostFreeze, 3),
            (BrokerDomain::Host, BrokerVerb::HostThaw, 4),
            (BrokerDomain::Host, BrokerVerb::HostKill, 5),
            (BrokerDomain::Mount, BrokerVerb::MountCreate, 1),
            (BrokerDomain::Mount, BrokerVerb::MountInstall, 2),
            (BrokerDomain::Mount, BrokerVerb::MountReplace, 3),
            (BrokerDomain::Mount, BrokerVerb::MountDetach, 4),
            (BrokerDomain::Mount, BrokerVerb::MountRelease, 5),
            (
                BrokerDomain::Mount,
                BrokerVerb::MountMaterializeDestinationSlot,
                6,
            ),
            (BrokerDomain::Mount, BrokerVerb::MountReapDestinationSlot, 7),
            (BrokerDomain::Storage, BrokerVerb::StorageCreateWorkspace, 1),
            (BrokerDomain::Storage, BrokerVerb::StorageSnapshot, 2),
            (BrokerDomain::Storage, BrokerVerb::StorageHoldSnapshot, 3),
            (BrokerDomain::Storage, BrokerVerb::StorageReleaseHold, 4),
            (BrokerDomain::Storage, BrokerVerb::StorageClone, 5),
            (BrokerDomain::Storage, BrokerVerb::StorageSetQuota, 6),
            (BrokerDomain::Storage, BrokerVerb::StorageDestroy, 7),
            (BrokerDomain::Network, BrokerVerb::NetworkPrepare, 1),
            (BrokerDomain::Network, BrokerVerb::NetworkArmLease, 2),
            (BrokerDomain::Network, BrokerVerb::NetworkRenewLease, 3),
            (BrokerDomain::Network, BrokerVerb::NetworkDisarm, 4),
            (BrokerDomain::Network, BrokerVerb::NetworkDestroy, 5),
        ];
        let domains = [
            BrokerDomain::Host,
            BrokerDomain::Mount,
            BrokerDomain::Storage,
            BrokerDomain::Network,
        ];
        let resource = BrokerResourceHandle::from_bytes([7; 32])
            .unwrap_or_else(|error| panic!("resource: {error}"));
        let successor = BrokerResourceHandle::from_bytes([8; 32])
            .unwrap_or_else(|error| panic!("resource: {error}"));

        for (domain, verb, stable_code) in cases {
            let mut intent = sample_intent();
            intent.verb = verb;
            intent.target = match verb {
                BrokerVerb::HostLaunch
                | BrokerVerb::MountCreate
                | BrokerVerb::MountMaterializeDestinationSlot
                | BrokerVerb::StorageCreateWorkspace
                | BrokerVerb::NetworkPrepare => BrokerGrantTarget::Assignment,
                BrokerVerb::MountReplace => BrokerGrantTarget::ResourcePair {
                    previous: resource,
                    successor,
                },
                _ => BrokerGrantTarget::Resource(resource),
            };

            let bytes = encode_effect(&intent, domain)
                .unwrap_or_else(|error| panic!("encode {domain:?}/{verb:?}: {error}"));
            assert_eq!(verb_code(domain, verb), stable_code);
            assert_eq!(bytes[11], stable_code);
            assert_eq!(
                decode_effect(&bytes, domain),
                Ok(intent.clone()),
                "round trip failed for {domain:?}/{verb:?}"
            );
            for wrong_domain in domains {
                if wrong_domain != domain {
                    assert_eq!(
                        encode_effect(&intent, wrong_domain),
                        Err(AuthorizationRecordError::InvalidPayload),
                        "{verb:?} encoded in {wrong_domain:?}"
                    );
                    assert_eq!(
                        decode_effect(&bytes, wrong_domain),
                        Err(AuthorizationRecordError::InvalidPayload),
                        "{verb:?} decoded in {wrong_domain:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_domain_rejects_unknown_effect_verb_codes() {
        for domain in [
            BrokerDomain::Host,
            BrokerDomain::Mount,
            BrokerDomain::Storage,
            BrokerDomain::Network,
        ] {
            let mut bytes = sample_effect();
            bytes[..8].copy_from_slice(domain.effect_magic());
            bytes[11] = u8::MAX;
            assert_eq!(
                decode_effect(&bytes, domain),
                Err(AuthorizationRecordError::InvalidPayload)
            );
        }
    }

    #[test]
    fn every_authenticated_region_rejects_bit_flips() {
        let key = mac_key();
        let bytes =
            seal_authorization_fence(&key, RecordNamespace::DesiredState, b"fence-key", &fence())
                .unwrap_or_else(|error| panic!("seal: {error}"));
        for offset in 0..bytes.len() {
            let mut corrupted = bytes.clone();
            corrupted[offset] ^= 1;
            assert!(
                open_authorization_fence(
                    &key,
                    RecordNamespace::DesiredState,
                    b"fence-key",
                    &corrupted,
                )
                .is_err(),
                "bit flip at offset {offset} was accepted"
            );
        }
    }

    #[test]
    fn wrong_secret_key_id_truncation_and_oversize_fail_closed() {
        let key = mac_key();
        let bytes =
            seal_authorization_fence(&key, RecordNamespace::DesiredState, b"fence-key", &fence())
                .unwrap_or_else(|error| panic!("seal: {error}"));
        let wrong_secret = NodeJournalMacKey::new(BrokerDomain::Mount, [90; 16], [92; 32])
            .unwrap_or_else(|error| panic!("key: {error}"));
        assert_eq!(
            open_authorization_fence(
                &wrong_secret,
                RecordNamespace::DesiredState,
                b"fence-key",
                &bytes,
            ),
            Err(AuthorizationRecordError::AuthenticationFailed)
        );
        let wrong_id = NodeJournalMacKey::new(BrokerDomain::Mount, [89; 16], [91; 32])
            .unwrap_or_else(|error| panic!("key: {error}"));
        assert_eq!(
            open_authorization_fence(
                &wrong_id,
                RecordNamespace::DesiredState,
                b"fence-key",
                &bytes,
            ),
            Err(AuthorizationRecordError::AuthenticationFailed)
        );
        for length in 0..bytes.len() {
            assert!(
                open_authorization_fence(
                    &key,
                    RecordNamespace::DesiredState,
                    b"fence-key",
                    &bytes[..length],
                )
                .is_err()
            );
        }
        assert_eq!(
            seal(
                &key,
                RecordNamespace::Effect,
                b"request",
                AuthenticatedValueKind::EffectIntent,
                &vec![0; MAXIMUM_AUTHENTICATED_PAYLOAD_BYTES + 1],
            ),
            Err(AuthorizationRecordError::InvalidFraming)
        );
    }

    #[test]
    fn authenticated_unknown_and_substituted_kinds_are_rejected() {
        let key = mac_key();
        let unknown = seal_test_payload(99, b"opaque");
        assert_eq!(
            open(
                &key,
                RecordNamespace::DesiredState,
                b"fence-key",
                AuthenticatedValueKind::AuthorizationFence,
                &unknown,
            ),
            Err(AuthorizationRecordError::WrongKind)
        );
        let fence_bytes =
            seal_authorization_fence(&key, RecordNamespace::DesiredState, b"fence-key", &fence())
                .unwrap_or_else(|error| panic!("seal: {error}"));
        assert_eq!(
            open_effect_intent(
                &key,
                RecordNamespace::DesiredState,
                b"fence-key",
                &fence_bytes,
            ),
            Err(AuthorizationRecordError::WrongKind)
        );
    }

    #[test]
    fn authenticated_payload_is_validated_only_after_mac() {
        let key = mac_key();
        let malformed = seal_test_payload(AuthenticatedValueKind::AuthorizationFence as u8, b"bad");
        assert_eq!(
            open_authorization_fence(
                &key,
                RecordNamespace::DesiredState,
                b"fence-key",
                &malformed,
            ),
            Err(AuthorizationRecordError::InvalidPayload)
        );
        let mut unauthenticated = malformed;
        unauthenticated[32] ^= 1;
        assert_eq!(
            open_authorization_fence(
                &key,
                RecordNamespace::DesiredState,
                b"fence-key",
                &unauthenticated,
            ),
            Err(AuthorizationRecordError::AuthenticationFailed)
        );
    }

    #[test]
    fn payload_decoder_rejects_unknown_tags_trailing_bytes_and_bounds() {
        let valid_fence = encode_fence(&fence(), BrokerDomain::Mount)
            .unwrap_or_else(|error| panic!("fence: {error}"));
        let mut trailing = valid_fence.clone();
        trailing.push(0);
        assert_eq!(
            decode_fence(&trailing, BrokerDomain::Mount),
            Err(AuthorizationRecordError::InvalidPayload)
        );
        let stable_key_length_offset = 10 + 16 + 16 + 8 + 8 + 32 + 16 + 32 + 8;
        let mut empty_key_id = valid_fence;
        empty_key_id[stable_key_length_offset] = 0;
        assert_eq!(
            decode_fence(&empty_key_id, BrokerDomain::Mount),
            Err(AuthorizationRecordError::InvalidPayload)
        );

        let mut effect = sample_effect();
        effect[10] = 9;
        assert_eq!(
            decode_effect(&effect, BrokerDomain::Mount),
            Err(AuthorizationRecordError::InvalidPayload)
        );
        let mut target = sample_effect();
        target[12] = 9;
        assert_eq!(
            decode_effect(&target, BrokerDomain::Mount),
            Err(AuthorizationRecordError::InvalidPayload)
        );
        let receipt_length_offset = sample_effect().len() - 4;
        let mut oversized_receipt = sample_effect();
        oversized_receipt[receipt_length_offset..]
            .copy_from_slice(&((MAXIMUM_RECEIPT_BYTES + 1) as u32).to_be_bytes());
        assert_eq!(
            decode_effect(&oversized_receipt, BrokerDomain::Mount),
            Err(AuthorizationRecordError::InvalidPayload)
        );
    }

    fn sample_intent() -> BrokerEffectIntentV2 {
        let lease = local_lease();
        BrokerEffectIntentV2 {
            status: BrokerEffectStatusV2::Pending,
            request_id: [15; 16],
            transport_request_digest: ObjectDigest::from_bytes([11; 32]),
            request_digest: ObjectDigest::from_bytes([12; 32]),
            plan_digest: ObjectDigest::from_bytes([72; 32]),
            lease_digest: lease.lease_digest(),
            verb: BrokerVerb::MountCreate,
            target: BrokerGrantTarget::Assignment,
            maximum_request_bytes: 4_096,
            maximum_descriptors: 0,
            plan_expires_seconds: 190,
            authority_expires_seconds: lease.authority_expires_seconds(),
            host_boot_id: *lease.host_boot_id(),
            fail_stop_boottime_nanoseconds: lease.fail_stop_boottime_nanoseconds(),
            clock_provenance: *lease.clock_provenance(),
            admitted_wall_seconds: 150,
            admitted_boottime_nanoseconds: 100,
            request_deadline_boottime_nanoseconds: 1_000,
            effect_deadline_boottime_nanoseconds: 500,
            local_lease_record: lease,
            receipt: Vec::new(),
        }
    }

    fn sample_effect() -> Vec<u8> {
        encode_effect(&sample_intent(), BrokerDomain::Mount)
            .unwrap_or_else(|error| panic!("effect: {error}"))
    }

    #[test]
    fn effect_round_trip_retains_intersection_and_receipt_fields() {
        let pending = decode_effect(&sample_effect(), BrokerDomain::Mount)
            .unwrap_or_else(|error| panic!("decode: {error}"));
        assert_eq!(pending.status(), BrokerEffectStatusV2::Pending);
        assert_eq!(pending.request_id(), &[15; 16]);
        assert_eq!(
            pending.transport_request_digest(),
            ObjectDigest::from_bytes([11; 32])
        );
        assert_eq!(pending.request_digest(), ObjectDigest::from_bytes([12; 32]));
        assert_eq!(pending.plan_digest(), ObjectDigest::from_bytes([72; 32]));
        assert_eq!(pending.verb(), BrokerVerb::MountCreate);
        assert_eq!(pending.target(), BrokerGrantTarget::Assignment);
        assert_eq!(pending.maximum_request_bytes(), 4_096);
        assert_eq!(pending.maximum_descriptors(), 0);
        assert_eq!(pending.plan_expires_seconds(), 190);
        assert_eq!(pending.authority_expires_seconds(), 200);
        assert_eq!(pending.host_boot_id(), &[8; 16]);
        assert!(pending.receipt().is_empty());

        let complete = pending
            .complete(b"durable receipt".to_vec())
            .unwrap_or_else(|error| panic!("complete: {error}"));
        let key = mac_key();
        let bytes = seal_effect_intent(
            &key,
            RecordNamespace::Effect,
            complete.request_id(),
            &complete,
        )
        .unwrap_or_else(|error| panic!("seal: {error}"));
        assert_eq!(
            open_effect_intent(&key, RecordNamespace::Effect, complete.request_id(), &bytes,),
            Ok(complete)
        );
    }

    #[test]
    fn invalid_keys_and_semantic_substitution_are_rejected() {
        assert!(matches!(
            NodeJournalMacKey::new(BrokerDomain::Mount, [0; 16], [1; 32]),
            Err(AuthorizationRecordError::InvalidKey)
        ));
        assert!(matches!(
            NodeJournalMacKey::new(BrokerDomain::Mount, [1; 16], [0; 32]),
            Err(AuthorizationRecordError::InvalidKey)
        ));
        let wrong_usage = KeyReference::new(
            StableKeyId::new("controller".to_owned())
                .unwrap_or_else(|error| panic!("key ID: {error}")),
            1,
            ObjectDigest::from_bytes([3; 32]),
            KeyUsage::BrokerAuthorization,
        );
        assert_eq!(
            BrokerAuthorizationFenceV1::new(
                assignment(),
                NodeId::from_bytes([6; 16]),
                ObjectDigest::from_bytes([72; 32]),
                190,
                wrong_usage,
                local_lease(),
            ),
            Err(AuthorizationRecordError::InvalidPayload)
        );
    }

    #[test]
    fn target_codec_rejects_noncanonical_padding_and_equal_pair() {
        let mut assignment_bytes = Vec::new();
        encode_target(&mut assignment_bytes, BrokerGrantTarget::Assignment);
        assignment_bytes[1] = 1;
        assert_eq!(
            decode_target(&mut Decoder::new(&assignment_bytes)),
            Err(AuthorizationRecordError::InvalidPayload)
        );

        let handle = BrokerResourceHandle::from_bytes([7; 32])
            .unwrap_or_else(|error: InvalidBrokerAuthorizationPlan| panic!("handle: {error}"));
        let mut equal_pair = Vec::new();
        encode_target(
            &mut equal_pair,
            BrokerGrantTarget::ResourcePair {
                previous: handle,
                successor: handle,
            },
        );
        let decoded = decode_target(&mut Decoder::new(&equal_pair))
            .unwrap_or_else(|error| panic!("target decode: {error}"));
        let lease = local_lease();
        let intent = BrokerEffectIntentV2 {
            status: BrokerEffectStatusV2::Pending,
            request_id: [1; 16],
            transport_request_digest: ObjectDigest::from_bytes([1; 32]),
            request_digest: ObjectDigest::from_bytes([2; 32]),
            plan_digest: ObjectDigest::from_bytes([3; 32]),
            lease_digest: lease.lease_digest(),
            verb: BrokerVerb::MountReplace,
            target: decoded,
            maximum_request_bytes: 1,
            maximum_descriptors: 0,
            plan_expires_seconds: 190,
            authority_expires_seconds: lease.authority_expires_seconds(),
            host_boot_id: *lease.host_boot_id(),
            fail_stop_boottime_nanoseconds: lease.fail_stop_boottime_nanoseconds(),
            clock_provenance: *lease.clock_provenance(),
            admitted_wall_seconds: 150,
            admitted_boottime_nanoseconds: 100,
            request_deadline_boottime_nanoseconds: 1_000,
            effect_deadline_boottime_nanoseconds: 500,
            local_lease_record: lease,
            receipt: Vec::new(),
        };
        assert_eq!(
            intent.validate(),
            Err(AuthorizationRecordError::InvalidPayload)
        );
    }
}
