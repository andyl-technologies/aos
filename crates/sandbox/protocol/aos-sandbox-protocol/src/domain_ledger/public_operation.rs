//! Owns public-operation ledger metadata, authorization DATA and resource projection.
//!
//! Public metadata is appended only to V2 operation records. The fixed-width
//! representation keeps method, accepted generation, audit identity, and
//! timestamps restart-stable while the enclosing operation record remains the
//! atomic state-transition authority.
//!
//! These values contain immutable historical DATA. Construction, decoding and
//! projection do not authenticate a caller, sample a protected clock, validate
//! the enclosing Effect ledger, or grant current admission or mutation authority.
//! The Domain owner supplies those checks before consuming the projected resource.
//! The durable method registry is separate from the public wire registry.
//!
//! The 64-byte metadata uses little-endian integers:
//!
//! ```text
//! method:u8 | recovery-kind:u8 | reserved[6]=0 | accepted-generation:u64 | observation-sequence:u64 |
//! audit-id[16] | accepted-wall:i64 | last-reconciliation-wall:i64 | completed-wall:i64
//! ```
//!
//! An absent completion is encoded as `i64::MIN`. Authorization uses canonical
//! selector JSON and big-endian framing:
//!
//! ```text
//! AOSOPAU1 | version:u16=1 | reserved[2]=0 | project[16] | resource-kind:u8 |
//! reserved[3]=0 | selector-length:u32 | selector-json | domain-separated-SHA256[32]
//! ```
//!
//! # Examples
//!
//! ```no_run
//! use aos_sandbox_model::{ProjectId, ResourceId, ResourceKind, Selector};
//! use aos_sandbox_protocol::domain_ledger::public_operation::{
//!     OperationState, PublicOperationAdmissionV1, PublicOperationAuthorizationV1,
//! };
//! use aos_sandbox_protocol::public_api::PublicOperationMethodV1;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let scope = PublicOperationAuthorizationV1::new(
//!     ProjectId::from_bytes([1; 16]), ResourceKind::Sandbox,
//!     Selector::Resource { resource: ResourceId::from_bytes([3; 16]) },
//! )?;
//! let metadata = PublicOperationAdmissionV1::new(
//!     PublicOperationMethodV1::CreateSandbox, 1, [2; 16], 100, scope,
//! )?.durable();
//! let next = metadata.advance(OperationState::Applying, 101)?;
//! let mut bytes = Vec::new();
//! next.encode(&mut bytes);
//! assert_eq!(bytes.len(), 64);
//! # Ok(())
//! # }
//! ```

use aos_sandbox_api::aos::sandbox::v1::{
    Operation, OperationPhase, OperationProgress, RetryClass, Timestamp,
};
use aos_sandbox_model::{OperationId, ProjectId, ResourceKind, Selector};
use sha2::{Digest as _, Sha256};

use crate::public_api::PublicOperationMethodV1;

/// Reports invalid public-operation DATA without wrapping a protected owner cause.
#[derive(Debug, thiserror::Error)]
pub enum PublicOperationDataError {
    /// A supplied metadata or selector value violates the durable DATA bounds.
    #[error("invalid reconciliation plan: {0}")]
    InvalidPlan(&'static str),
    /// Encoded history violates the closed durable format or its canonical binding.
    #[error("corrupt durable effect ledger: {0}")]
    CorruptLedger(&'static str),
    /// A supplied transition timestamp is invalid or moves backward.
    #[error("public operation clock observation is missing or invalid")]
    PublicOperationClock,
    /// A transition would overflow the monotone observation sequence.
    #[error("public operation observation sequence is exhausted")]
    PublicOperationSequenceExhausted,
}

/// Identifies the durable operation state without admitting a state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperationState {
    /// Work was durably accepted and has not started reconciliation.
    Accepted = 1,
    /// Reconciliation has started and remains nonterminal.
    Applying = 2,
    /// The enclosing ledger records successful completion.
    Succeeded = 3,
    /// The enclosing ledger records a permanent block.
    PermanentlyBlocked = 4,
    /// Work remains blocked on its original ownership gate.
    OwnershipPending = 5,
    /// The operation was canceled before its commit boundary.
    CanceledBeforeCommit = 6,
    /// The operation failed before its commit boundary.
    FailedBeforeCommit = 7,
    /// Desired Stop committed; native containment left explicit Capture cleanup debt.
    CommittedWithResidualCleanup = 8,
}

impl OperationState {
    /// Decodes the closed native operation-state discriminant.
    ///
    /// # Errors
    /// Returns [`PublicOperationDataError::CorruptLedger`] for an unknown code.
    pub fn from_byte(value: u8) -> Result<Self, PublicOperationDataError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Applying),
            3 => Ok(Self::Succeeded),
            4 => Ok(Self::PermanentlyBlocked),
            5 => Ok(Self::OwnershipPending),
            6 => Ok(Self::CanceledBeforeCommit),
            7 => Ok(Self::FailedBeforeCommit),
            8 => Ok(Self::CommittedWithResidualCleanup),
            _ => Err(PublicOperationDataError::CorruptLedger(
                "unknown operation state",
            )),
        }
    }

    /// Reports whether the durable state requires a completion timestamp.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::PermanentlyBlocked
                | Self::CanceledBeforeCommit
                | Self::FailedBeforeCommit
                | Self::CommittedWithResidualCleanup
        )
    }
}

/// Bounds the complete fixed-width public metadata appended to a V2 Operation row.
pub const PUBLIC_OPERATION_RECORD_BYTES: usize = 64;
const PUBLIC_OPERATION_RESOURCE_VERSION_DOMAIN: &[u8] =
    b"aos.sandbox.public-operation-resource-version.v1\0";
const PUBLIC_OPERATION_AUTHORIZATION_MAGIC: &[u8; 8] = b"AOSOPAU1";
const PUBLIC_OPERATION_AUTHORIZATION_VERSION: u16 = 1;
const PUBLIC_OPERATION_AUTHORIZATION_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.public-operation-authorization.v1\0";
const PUBLIC_OPERATION_AUTHORIZATION_FIXED_BYTES: usize = 68;
const MAXIMUM_AUTHORIZATION_SELECTOR_BYTES: usize = 64 * 1024;
const NO_COMPLETION_TIMESTAMP: i64 = i64::MIN;
const MINIMUM_PROTO_SECONDS: i64 = -62_135_596_800;
const MAXIMUM_PROTO_SECONDS: i64 = 253_402_300_799;

// These discriminants belong to the native durable record, not the public wire registry.
/// Decodes one of the 26 closed native durable method codes.
///
/// Unknown codes return `None`; this registry does not select a public wire route.
pub const fn public_operation_method_from_record_code_v1(
    value: u8,
) -> Option<PublicOperationMethodV1> {
    match value {
        0 => Some(PublicOperationMethodV1::CreateSandbox),
        1 => Some(PublicOperationMethodV1::UpdatePolicy),
        2 => Some(PublicOperationMethodV1::StartSandbox),
        3 => Some(PublicOperationMethodV1::StopSandbox),
        4 => Some(PublicOperationMethodV1::SuspendSandbox),
        5 => Some(PublicOperationMethodV1::ResumeSandbox),
        6 => Some(PublicOperationMethodV1::DeleteSandbox),
        7 => Some(PublicOperationMethodV1::CreateExecution),
        8 => Some(PublicOperationMethodV1::CancelExecution),
        9 => Some(PublicOperationMethodV1::CreateView),
        10 => Some(PublicOperationMethodV1::AttachView),
        11 => Some(PublicOperationMethodV1::ReplaceAttachment),
        12 => Some(PublicOperationMethodV1::DetachView),
        13 => Some(PublicOperationMethodV1::ReleaseView),
        14 => Some(PublicOperationMethodV1::CreateSnapshot),
        15 => Some(PublicOperationMethodV1::RestoreSnapshot),
        16 => Some(PublicOperationMethodV1::ForkSnapshot),
        17 => Some(PublicOperationMethodV1::DeleteSnapshot),
        18 => Some(PublicOperationMethodV1::RenewCapability),
        19 => Some(PublicOperationMethodV1::RevokeCapability),
        20 => Some(PublicOperationMethodV1::CancelOperation),
        21 => Some(PublicOperationMethodV1::ControlExecution),
        22 => Some(PublicOperationMethodV1::AttenuateCapability),
        23 => Some(PublicOperationMethodV1::PinCacheObject),
        24 => Some(PublicOperationMethodV1::UnpinCacheObject),
        25 => Some(PublicOperationMethodV1::OperatorRecover),
        _ => None,
    }
}

/// Returns the native durable method code, independently of the public wire registry.
pub const fn public_operation_method_record_code_v1(method: PublicOperationMethodV1) -> u8 {
    method as u8
}

/// Distinguishes metadata reconciliation from the established recovery results.
///
/// The ordinary discriminant preserves existing Retry, Repair and Abandon bytes.
/// Metadata completion is a separate zero-effect public operation; its stored
/// tag never admits recovery, restores native custody or authorizes an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicRecoveryKindV1 {
    /// Preserves the established operation semantics and wire projection.
    Ordinary = 0,
    /// Records a separately admitted metadata-only Create recovery.
    MetadataComplete = 1,
    /// Records a fresh Recover that may complete only its exact protected Stop.
    StopCleanup = 2,
    /// Records a new Recover for the exact protected Execution NoApply target.
    ExecutionNoApply = 3,
}

/// Supplies immutable public fields when admitting an operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicOperationAdmissionV1 {
    method: PublicOperationMethodV1,
    recovery_kind: PublicRecoveryKindV1,
    accepted_generation: u64,
    audit_id: [u8; 16],
    accepted_wall_seconds: i64,
    authorization: PublicOperationAuthorizationV1,
}

/// Binds a public operation to its project and capability selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicOperationAuthorizationV1 {
    project: ProjectId,
    resource_kind: ResourceKind,
    selector: Selector,
}

impl PublicOperationAuthorizationV1 {
    /// Constructs checked immutable authorization-scope DATA.
    ///
    /// The stored scope does not prove current capability or policy authorization.
    ///
    /// # Errors
    ///
    /// Returns [`PublicOperationDataError::InvalidPlan`] for a zero project identity or
    /// a selector whose canonical JSON encoding exceeds the durable bound.
    pub fn new(
        project: ProjectId,
        resource_kind: ResourceKind,
        selector: Selector,
    ) -> Result<Self, PublicOperationDataError> {
        if project.as_bytes() == &[0; 16] {
            return Err(PublicOperationDataError::InvalidPlan(
                "public operation authorization has a zero project",
            ));
        }
        let encoded = serde_json::to_vec(&selector).map_err(|_| {
            PublicOperationDataError::InvalidPlan("public operation selector cannot be encoded")
        })?;
        if encoded.is_empty() || encoded.len() > MAXIMUM_AUTHORIZATION_SELECTOR_BYTES {
            return Err(PublicOperationDataError::InvalidPlan(
                "public operation selector exceeds its durable bound",
            ));
        }

        Ok(Self {
            project,
            resource_kind,
            selector,
        })
    }

    /// Returns the project boundary fixed at operation admission.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the closed capability resource kind.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    /// Returns the exact logical capability selector.
    #[must_use]
    pub const fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Bounds the existing selector validation and encoding destinations.
    ///
    /// The genuine producer pays this passive bound before constructing its
    /// authorization model. It uses the sole codec limit, including a complete
    /// selector and encoded row, and grants no admission or capacity.
    pub const fn maximum_receiving_bytes_v1() -> usize {
        3 * (PUBLIC_OPERATION_AUTHORIZATION_FIXED_BYTES + MAXIMUM_AUTHORIZATION_SELECTOR_BYTES)
            + 2 * std::mem::size_of::<Self>()
    }

    /// Encodes the canonical bounded authorization row and its digest.
    ///
    /// # Errors
    /// Returns [`PublicOperationDataError::InvalidPlan`] if selector encoding
    /// fails or exceeds its durable bound.
    pub fn encode(&self) -> Result<Vec<u8>, PublicOperationDataError> {
        let selector = serde_json::to_vec(&self.selector).map_err(|_| {
            PublicOperationDataError::InvalidPlan("public operation selector cannot be encoded")
        })?;
        if selector.is_empty() || selector.len() > MAXIMUM_AUTHORIZATION_SELECTOR_BYTES {
            return Err(PublicOperationDataError::InvalidPlan(
                "public operation selector exceeds its durable bound",
            ));
        }
        let selector_length = u32::try_from(selector.len()).map_err(|_| {
            PublicOperationDataError::InvalidPlan(
                "public operation selector exceeds its durable bound",
            )
        })?;
        let mut bytes =
            Vec::with_capacity(PUBLIC_OPERATION_AUTHORIZATION_FIXED_BYTES + selector.len());
        bytes.extend_from_slice(PUBLIC_OPERATION_AUTHORIZATION_MAGIC);
        bytes.extend_from_slice(&PUBLIC_OPERATION_AUTHORIZATION_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.push(resource_kind_code(self.resource_kind));
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&selector_length.to_be_bytes());
        bytes.extend_from_slice(&selector);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_OPERATION_AUTHORIZATION_DIGEST_DOMAIN)
            .chain_update(&bytes)
            .finalize()
            .into();
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    /// Decodes an exact canonical historical authorization row.
    ///
    /// # Errors
    /// Returns [`PublicOperationDataError::CorruptLedger`] for malformed framing,
    /// reserved bytes, identities, resource kind, selector JSON or digest binding.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicOperationDataError> {
        if bytes.len() < PUBLIC_OPERATION_AUTHORIZATION_FIXED_BYTES
            || &bytes[..8] != PUBLIC_OPERATION_AUTHORIZATION_MAGIC
            || u16::from_be_bytes(read_array(&bytes[8..10])?)
                != PUBLIC_OPERATION_AUTHORIZATION_VERSION
            || bytes[10..12] != [0; 2]
            || bytes[29..32] != [0; 3]
        {
            return Err(PublicOperationDataError::CorruptLedger(
                "invalid public operation authorization header",
            ));
        }
        let project = ProjectId::from_bytes(read_array(&bytes[12..28])?);
        let resource_kind = resource_kind_from_code(bytes[28]).ok_or(
            PublicOperationDataError::CorruptLedger("unknown public operation resource kind"),
        )?;
        let selector_length = u32::from_be_bytes(read_array(&bytes[32..36])?) as usize;
        let expected_length = PUBLIC_OPERATION_AUTHORIZATION_FIXED_BYTES
            .checked_add(selector_length)
            .ok_or(PublicOperationDataError::CorruptLedger(
                "public operation authorization length overflow",
            ))?;
        if selector_length == 0
            || selector_length > MAXIMUM_AUTHORIZATION_SELECTOR_BYTES
            || bytes.len() != expected_length
        {
            return Err(PublicOperationDataError::CorruptLedger(
                "invalid public operation authorization length",
            ));
        }
        let selector_end = 36 + selector_length;
        let selector_bytes = &bytes[36..selector_end];
        let selector: Selector = serde_json::from_slice(selector_bytes).map_err(|_| {
            PublicOperationDataError::CorruptLedger("invalid public operation selector")
        })?;
        let canonical = serde_json::to_vec(&selector).map_err(|_| {
            PublicOperationDataError::CorruptLedger("invalid public operation selector")
        })?;
        let recorded_digest = &bytes[selector_end..];
        let expected_digest: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_OPERATION_AUTHORIZATION_DIGEST_DOMAIN)
            .chain_update(&bytes[..selector_end])
            .finalize()
            .into();
        if project.as_bytes() == &[0; 16]
            || canonical != selector_bytes
            || recorded_digest != expected_digest
        {
            return Err(PublicOperationDataError::CorruptLedger(
                "invalid public operation authorization binding",
            ));
        }

        Ok(Self {
            project,
            resource_kind,
            selector,
        })
    }
}

impl PublicOperationAdmissionV1 {
    /// Constructs checked immutable public operation metadata.
    ///
    /// The timestamp intentionally has second precision because the protected
    /// controller clock supplies Unix wall seconds paired with boot time.
    ///
    /// # Errors
    ///
    /// Returns [`PublicOperationDataError::InvalidPlan`] for a zero generation or audit
    /// identity, or a timestamp outside the protobuf timestamp range.
    pub fn new(
        method: PublicOperationMethodV1,
        accepted_generation: u64,
        audit_id: [u8; 16],
        accepted_wall_seconds: i64,
        authorization: PublicOperationAuthorizationV1,
    ) -> Result<Self, PublicOperationDataError> {
        if accepted_generation == 0
            || audit_id == [0; 16]
            || !valid_timestamp(accepted_wall_seconds)
        {
            return Err(PublicOperationDataError::InvalidPlan(
                "invalid public operation admission metadata",
            ));
        }

        Ok(Self {
            method,
            recovery_kind: PublicRecoveryKindV1::Ordinary,
            accepted_generation,
            audit_id,
            accepted_wall_seconds,
            authorization,
        })
    }

    /// Borrows the immutable authorization scope fixed in this metadata.
    pub const fn authorization(&self) -> &PublicOperationAuthorizationV1 {
        &self.authorization
    }

    /// Returns the immutable public method stored at admission.
    pub const fn method(&self) -> PublicOperationMethodV1 {
        self.method
    }

    /// Returns the supplied second-precision admission timestamp.
    pub const fn accepted_wall_seconds(&self) -> i64 {
        self.accepted_wall_seconds
    }

    /// Returns the project from the stored authorization scope.
    pub const fn project(&self) -> ProjectId {
        self.authorization.project()
    }

    /// Produces initial nonterminal metadata with observation sequence one.
    ///
    /// The enclosing operation owner must separately admit and persist its state.
    pub const fn durable(&self) -> DurablePublicOperationV1 {
        DurablePublicOperationV1 {
            method: self.method,
            recovery_kind: self.recovery_kind,
            accepted_generation: self.accepted_generation,
            observation_sequence: 1,
            audit_id: self.audit_id,
            accepted_wall_seconds: self.accepted_wall_seconds,
            last_reconciliation_wall_seconds: self.accepted_wall_seconds,
            completed_wall_seconds: None,
        }
    }

    /// Produces initial completed metadata for an independently admitted local result.
    ///
    /// Completion uses the original accepted timestamp and observation sequence one.
    pub const fn durable_completed(&self) -> DurablePublicOperationV1 {
        DurablePublicOperationV1 {
            method: self.method,
            recovery_kind: self.recovery_kind,
            accepted_generation: self.accepted_generation,
            observation_sequence: 1,
            audit_id: self.audit_id,
            accepted_wall_seconds: self.accepted_wall_seconds,
            last_reconciliation_wall_seconds: self.accepted_wall_seconds,
            completed_wall_seconds: Some(self.accepted_wall_seconds),
        }
    }
}

/// Retains the exact 64-byte public metadata of a separately validated Operation row.
///
/// Decoding validates metadata consistency, not the surrounding ledger or current
/// authority. Its private fields preserve checked metadata construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurablePublicOperationV1 {
    method: PublicOperationMethodV1,
    recovery_kind: PublicRecoveryKindV1,
    accepted_generation: u64,
    observation_sequence: u64,
    audit_id: [u8; 16],
    accepted_wall_seconds: i64,
    last_reconciliation_wall_seconds: i64,
    completed_wall_seconds: Option<i64>,
}

impl DurablePublicOperationV1 {
    /// Constructs fixed-width initial metadata-completion DATA without allocation.
    ///
    /// The actual protected owner separately authenticates and atomically admits
    /// its observation, Operation and authorization; these bytes grant no authority.
    ///
    /// # Errors
    /// Refuses a zero audit identity or invalid public timestamp.
    pub fn metadata_complete_initial_v1(audit_id: [u8; 16], wall_seconds: i64)
        -> Result<Self, PublicOperationDataError> {
        Self::closed_recovery_initial_v1(audit_id, wall_seconds, PublicRecoveryKindV1::MetadataComplete)
    }

    /// Constructs a distinct accepted Stop-cleanup Recover as passive metadata.
    ///
    /// Its zero Effect count never permits generic reconciliation to complete
    /// it. The actual cleanup driver must retain the new authorization, exact
    /// old Pending target, native effects and terminal transaction separately.
    ///
    /// # Errors
    /// Refuses a zero audit identity or invalid public timestamp.
    pub fn stop_cleanup_initial_v1(audit_id: [u8; 16], wall_seconds: i64)
        -> Result<Self, PublicOperationDataError> {
        Self::closed_recovery_initial_v1(audit_id, wall_seconds, PublicRecoveryKindV1::StopCleanup)
    }

    /// Constructs a distinct zero-effect NoApply recovery metadata operation.
    ///
    /// # Errors
    /// Refuses sentinel audit identity or invalid accepted wall time.
    pub fn execution_no_apply_initial_v1(audit_id: [u8; 16], wall_seconds: i64)
        -> Result<Self, PublicOperationDataError> {
        Self::closed_recovery_initial_v1(audit_id, wall_seconds, PublicRecoveryKindV1::ExecutionNoApply)
    }

    fn closed_recovery_initial_v1(audit_id: [u8; 16], wall_seconds: i64,
        recovery_kind: PublicRecoveryKindV1,
    ) -> Result<Self, PublicOperationDataError> {
        if audit_id == [0; 16] || !valid_timestamp(wall_seconds) {
            return Err(PublicOperationDataError::InvalidPlan(
                "invalid public operation admission metadata"));
        }
        Ok(Self {
            method: PublicOperationMethodV1::OperatorRecover,
            recovery_kind,
            accepted_generation: 1,
            observation_sequence: 1,
            audit_id,
            accepted_wall_seconds: wall_seconds,
            last_reconciliation_wall_seconds: wall_seconds,
            completed_wall_seconds: None,
        })
    }

    /// Returns the immutable public method stored in the durable metadata.
    pub const fn method(self) -> PublicOperationMethodV1 {
        self.method
    }

    /// Returns the explicit historical recovery kind without granting authority.
    pub const fn recovery_kind_v1(self) -> PublicRecoveryKindV1 {
        self.recovery_kind
    }

    /// Returns the original admission wall second preserved across transitions.
    pub const fn accepted_wall_seconds_v1(self) -> i64 {
        self.accepted_wall_seconds
    }

    /// Returns the recorded terminal wall second as historical DATA.
    pub const fn completed_wall_seconds_v1(self) -> Option<i64> {
        self.completed_wall_seconds
    }

    /// Returns the immutable generation fixed at original admission.
    pub const fn accepted_generation(self) -> u64 {
        self.accepted_generation
    }

    /// Reconstructs historical admission DATA with a separately decoded scope.
    ///
    /// The caller verifies the scope's original enclosing ledger association.
    pub const fn into_admission(
        self,
        authorization: PublicOperationAuthorizationV1,
    ) -> PublicOperationAdmissionV1 {
        PublicOperationAdmissionV1 {
            method: self.method,
            recovery_kind: self.recovery_kind,
            accepted_generation: self.accepted_generation,
            audit_id: self.audit_id,
            accepted_wall_seconds: self.accepted_wall_seconds,
            authorization,
        }
    }

    /// Advances observation metadata using a supplied state and wall timestamp.
    ///
    /// This pure transition does not acquire a protected clock or admit work.
    /// It checks the timestamp before sequence overflow and then records completion.
    ///
    /// # Errors
    /// Returns [`PublicOperationDataError::PublicOperationClock`] for an invalid
    /// or backward timestamp, or [`PublicOperationDataError::PublicOperationSequenceExhausted`]
    /// when the observation sequence cannot advance.
    pub fn advance(
        self,
        state: OperationState,
        wall_seconds: i64,
    ) -> Result<Self, PublicOperationDataError> {
        if state == OperationState::CommittedWithResidualCleanup
            && self.method != PublicOperationMethodV1::StopSandbox {
            return Err(PublicOperationDataError::CorruptLedger("residual completion is not Stop"));
        }
        if !valid_timestamp(wall_seconds) || wall_seconds < self.last_reconciliation_wall_seconds {
            return Err(PublicOperationDataError::PublicOperationClock);
        }
        let observation_sequence = self
            .observation_sequence
            .checked_add(1)
            .ok_or(PublicOperationDataError::PublicOperationSequenceExhausted)?;
        let completed_wall_seconds = if state.is_terminal() {
            Some(wall_seconds)
        } else {
            None
        };

        Ok(Self {
            observation_sequence,
            last_reconciliation_wall_seconds: wall_seconds,
            completed_wall_seconds,
            ..self
        })
    }

    /// Appends the exact 64-byte native metadata encoding to the supplied buffer.
    pub fn encode(self, bytes: &mut Vec<u8>) {
        bytes.push(public_operation_method_record_code_v1(self.method));
        bytes.push(self.recovery_kind as u8);
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.accepted_generation.to_le_bytes());
        bytes.extend_from_slice(&self.observation_sequence.to_le_bytes());
        bytes.extend_from_slice(&self.audit_id);
        bytes.extend_from_slice(&self.accepted_wall_seconds.to_le_bytes());
        bytes.extend_from_slice(&self.last_reconciliation_wall_seconds.to_le_bytes());
        bytes.extend_from_slice(
            &self
                .completed_wall_seconds
                .unwrap_or(NO_COMPLETION_TIMESTAMP)
                .to_le_bytes(),
        );
    }

    /// Decodes fixed-width metadata consistent with the supplied durable state.
    ///
    /// # Errors
    /// Returns [`PublicOperationDataError::CorruptLedger`] for an incorrect width,
    /// unknown method, reserved bytes, sentinel identity, invalid timestamp or
    /// generation/sequence, or inconsistent completion and terminal state.
    pub fn decode(bytes: &[u8], state: OperationState) -> Result<Self, PublicOperationDataError> {
        let bytes: &[u8; PUBLIC_OPERATION_RECORD_BYTES] = bytes.try_into().map_err(|_| {
            PublicOperationDataError::CorruptLedger("invalid public operation metadata length")
        })?;
        let method = public_operation_method_from_record_code_v1(bytes[0]).ok_or(
            PublicOperationDataError::CorruptLedger("unknown public operation method"),
        )?;
        let recovery_kind = match (method, bytes[1]) {
            (_, 0) => PublicRecoveryKindV1::Ordinary,
            (PublicOperationMethodV1::OperatorRecover, 1) => PublicRecoveryKindV1::MetadataComplete,
            (PublicOperationMethodV1::OperatorRecover, 2) => PublicRecoveryKindV1::StopCleanup,
            (PublicOperationMethodV1::OperatorRecover, 3) => PublicRecoveryKindV1::ExecutionNoApply,
            _ => return Err(PublicOperationDataError::CorruptLedger(
                "invalid public operation recovery kind",
            )),
        };
        if bytes[2..8] != [0; 6] {
            return Err(PublicOperationDataError::CorruptLedger(
                "nonzero public operation reserved bytes",
            ));
        }
        let accepted_generation = read_u64(&bytes[8..16])?;
        let observation_sequence = read_u64(&bytes[16..24])?;
        let audit_id: [u8; 16] = bytes[24..40].try_into().map_err(|_| {
            PublicOperationDataError::CorruptLedger("invalid public operation audit ID")
        })?;
        let accepted_wall_seconds = read_i64(&bytes[40..48])?;
        let last_reconciliation_wall_seconds = read_i64(&bytes[48..56])?;
        let completion = read_i64(&bytes[56..64])?;
        let completed_wall_seconds = (completion != NO_COMPLETION_TIMESTAMP).then_some(completion);
        if state == OperationState::CommittedWithResidualCleanup
            && method != PublicOperationMethodV1::StopSandbox {
            return Err(PublicOperationDataError::CorruptLedger("residual completion is not Stop"));
        }
        if (matches!(recovery_kind, PublicRecoveryKindV1::MetadataComplete | PublicRecoveryKindV1::StopCleanup | PublicRecoveryKindV1::ExecutionNoApply)
                && !(matches!((state, observation_sequence),
                    (OperationState::Accepted, 1) | (OperationState::Succeeded, 2))
                    || (recovery_kind == PublicRecoveryKindV1::StopCleanup
                        && state == OperationState::PermanentlyBlocked
                        && observation_sequence == 2)))
            || accepted_generation == 0
            || observation_sequence == 0
            || audit_id == [0; 16]
            || !valid_timestamp(accepted_wall_seconds)
            || !valid_timestamp(last_reconciliation_wall_seconds)
            || last_reconciliation_wall_seconds < accepted_wall_seconds
            || completed_wall_seconds.is_some_and(|completed| {
                !valid_timestamp(completed)
                    || completed < accepted_wall_seconds
                    || completed > last_reconciliation_wall_seconds
            })
            || state.is_terminal() != completed_wall_seconds.is_some()
        {
            return Err(PublicOperationDataError::CorruptLedger(
                "invalid public operation metadata",
            ));
        }

        Ok(Self {
            method,
            recovery_kind,
            accepted_generation,
            observation_sequence,
            audit_id,
            accepted_wall_seconds,
            last_reconciliation_wall_seconds,
            completed_wall_seconds,
        })
    }

    /// Projects the established resource for a separately validated Repair failure.
    ///
    /// The caller retains the original ledger checks; this changes only the
    /// projected milestone to `original-precondition-replaced`.
    pub fn project_original_precondition_replaced(
        self,
        operation_id: OperationId,
        operation_record: &[u8],
        effect_records: &[&[u8]],
    ) -> Operation {
        let mut operation = self.project(operation_id, OperationState::PermanentlyBlocked,
            1, 0, true, false, operation_record, effect_records);
        operation.progress = Some(OperationProgress {
            milestone: "original-precondition-replaced".to_owned(),
            completed_units: 0,
            total_units: 1,
            ..Default::default()
        }).into();
        operation
    }

    /// Projects public Operation DATA from the supplied validated ledger observations.
    ///
    /// The caller verifies the enclosing Operation and Effect rows, counts, state
    /// and cancelability. The resourceVersion binds those exact ordered bytes;
    /// the returned protobuf conveys no current authorization.
    pub fn project(
        self,
        operation_id: OperationId,
        state: OperationState,
        effect_count: u32,
        applied_effects: u32,
        controller_orchestration: bool,
        cancelable: bool,
        operation_record: &[u8],
        effect_records: &[&[u8]],
    ) -> Operation {
        let (phase, milestone, retry_class) = match (state, controller_orchestration) {
            (OperationState::PermanentlyBlocked, _)
                if self.recovery_kind == PublicRecoveryKindV1::StopCleanup => (
                    OperationPhase::OPERATION_PHASE_PERMANENTLY_BLOCKED,
                    "superseded-by-stop-completion",
                    RetryClass::RETRY_CLASS_NEVER,
                ),
            (OperationState::Accepted, _)
                if matches!(self.recovery_kind, PublicRecoveryKindV1::StopCleanup | PublicRecoveryKindV1::ExecutionNoApply) => (
                    OperationPhase::OPERATION_PHASE_ACCEPTED,
                    "reconciling",
                    RetryClass::RETRY_CLASS_SAME_REQUEST,
                ),
            (OperationState::Succeeded, _)
                if matches!(self.recovery_kind, PublicRecoveryKindV1::StopCleanup | PublicRecoveryKindV1::ExecutionNoApply) => (
                    OperationPhase::OPERATION_PHASE_SUCCEEDED,
                    "complete",
                    RetryClass::RETRY_CLASS_NEVER,
                ),
            (OperationState::Accepted, _)
                if self.recovery_kind == PublicRecoveryKindV1::MetadataComplete => (
                    OperationPhase::OPERATION_PHASE_ACCEPTED,
                    "metadata-verification-pending",
                    RetryClass::RETRY_CLASS_SAME_REQUEST,
                ),
            (OperationState::Succeeded, _)
                if self.recovery_kind == PublicRecoveryKindV1::MetadataComplete => (
                    OperationPhase::OPERATION_PHASE_SUCCEEDED,
                    "metadata-complete",
                    RetryClass::RETRY_CLASS_NEVER,
                ),
            (OperationState::Accepted, true) => (
                OperationPhase::OPERATION_PHASE_ACCEPTED,
                "accepted",
                RetryClass::RETRY_CLASS_SAME_REQUEST,
            ),
            (OperationState::Applying, true) => (
                OperationPhase::OPERATION_PHASE_PREPARING,
                "preparing",
                RetryClass::RETRY_CLASS_SAME_REQUEST,
            ),
            (OperationState::OwnershipPending, _) => (
                OperationPhase::OPERATION_PHASE_COMMITTED,
                "blocked",
                RetryClass::RETRY_CLASS_AFTER_STATE_CHANGE,
            ),
            (OperationState::Accepted | OperationState::Applying, false) => (
                OperationPhase::OPERATION_PHASE_COMMITTED,
                "reconciling",
                RetryClass::RETRY_CLASS_SAME_REQUEST,
            ),
            (OperationState::Succeeded, _)
                if self.method == PublicOperationMethodV1::OperatorRecover && effect_count == 0 =>
            {
                (
                    OperationPhase::OPERATION_PHASE_SUCCEEDED,
                    "abandon-acknowledged",
                    RetryClass::RETRY_CLASS_NEVER,
                )
            }
            (OperationState::Succeeded, _) => (
                OperationPhase::OPERATION_PHASE_SUCCEEDED,
                "complete",
                RetryClass::RETRY_CLASS_NEVER,
            ),
            (OperationState::CanceledBeforeCommit, _) => (
                OperationPhase::OPERATION_PHASE_CANCELED_BEFORE_COMMIT,
                "complete",
                RetryClass::RETRY_CLASS_NEVER,
            ),
            (OperationState::FailedBeforeCommit, _) => (
                OperationPhase::OPERATION_PHASE_FAILED_BEFORE_COMMIT,
                "complete",
                RetryClass::RETRY_CLASS_NEVER,
            ),
            (OperationState::CommittedWithResidualCleanup, _) => (
                OperationPhase::OPERATION_PHASE_COMMITTED_WITH_RESIDUAL_CLEANUP,
                "cleanup",
                RetryClass::RETRY_CLASS_AFTER_STATE_CHANGE,
            ),
            (OperationState::PermanentlyBlocked, _) => (
                OperationPhase::OPERATION_PHASE_PERMANENTLY_BLOCKED,
                "blocked",
                RetryClass::RETRY_CLASS_NEVER,
            ),
        };
        let completed_at = self.completed_wall_seconds.map(timestamp);

        Operation {
            operation_id: operation_id.into_bytes().to_vec(),
            resource_version: resource_version(operation_id, operation_record, effect_records)
                .to_vec(),
            method: self.method.as_str().to_owned(),
            phase: phase.into(),
            accepted_generation: self.accepted_generation,
            progress: Some(OperationProgress {
                milestone: milestone.to_owned(),
                completed_units: applied_effects,
                total_units: effect_count,
                ..Default::default()
            })
            .into(),
            retry_class: retry_class.into(),
            audit_id: self.audit_id.to_vec(),
            accepted_at: Some(timestamp(self.accepted_wall_seconds)).into(),
            completed_at: completed_at.into(),
            cancelable,
            observation_sequence: self.observation_sequence,
            last_successful_reconciliation_time: Some(timestamp(
                self.last_reconciliation_wall_seconds,
            ))
            .into(),
            ..Default::default()
        }
    }
}

const fn valid_timestamp(seconds: i64) -> bool {
    seconds >= MINIMUM_PROTO_SECONDS && seconds <= MAXIMUM_PROTO_SECONDS
}

/// Measures the closed zero-effect MetadataComplete resource projection.
///
/// The same `project` body allocates three byte identities, the method and
/// milestone strings, one progress message and three timestamp messages. This
/// cost-only bound covers construction, retained response and return carriers;
/// it grants no operation admission, observation or mutation authority.
#[must_use]
pub fn metadata_complete_projection_receiving_bytes_v1() -> Option<usize> {
    let dynamic = 16_usize.checked_add(32)?.checked_add(16)?
        .checked_add(PublicOperationMethodV1::OperatorRecover.as_str().len())?
        .checked_add("metadata-verification-pending".len().max("metadata-complete".len())
            .max("superseded-by-stop-completion".len()))?;
    std::mem::size_of::<Operation>().checked_add(std::mem::size_of::<OperationProgress>())?
        .checked_add(3 * std::mem::size_of::<Timestamp>())?
        .checked_add(dynamic)?.checked_mul(3)
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp {
        seconds,
        nanoseconds: 0,
        ..Default::default()
    }
}

/// Commits the operation identity and exact ordered native Operation/Effect bytes.
///
/// Length framing and the domain separator are fixed. This digest is an
/// observation version, never evidence of protected custody or current admission.
pub fn resource_version(
    operation_id: OperationId,
    operation_record: &[u8],
    effect_records: &[&[u8]],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(PUBLIC_OPERATION_RESOURCE_VERSION_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update((operation_record.len() as u64).to_be_bytes());
    digest.update(operation_record);
    for effect in effect_records {
        digest.update((effect.len() as u64).to_be_bytes());
        digest.update(effect);
    }
    digest.finalize().into()
}

fn read_u64(bytes: &[u8]) -> Result<u64, PublicOperationDataError> {
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
        PublicOperationDataError::CorruptLedger("invalid public operation integer")
    })?))
}

fn read_i64(bytes: &[u8]) -> Result<i64, PublicOperationDataError> {
    Ok(i64::from_le_bytes(bytes.try_into().map_err(|_| {
        PublicOperationDataError::CorruptLedger("invalid public operation timestamp")
    })?))
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PublicOperationDataError> {
    bytes.try_into().map_err(|_| {
        PublicOperationDataError::CorruptLedger("truncated public operation authorization")
    })
}

const fn resource_kind_code(kind: ResourceKind) -> u8 {
    kind as u8
}

const fn resource_kind_from_code(value: u8) -> Option<ResourceKind> {
    match value {
        0 => Some(ResourceKind::Sandbox),
        1 => Some(ResourceKind::Execution),
        2 => Some(ResourceKind::Snapshot),
        3 => Some(ResourceKind::Tree),
        4 => Some(ResourceKind::LiveExport),
        5 => Some(ResourceKind::PrivateDelta),
        6 => Some(ResourceKind::Secret),
        7 => Some(ResourceKind::Device),
        8 => Some(ResourceKind::NetworkEndpoint),
        9 => Some(ResourceKind::IpcService),
        10 => Some(ResourceKind::CacheRead),
        11 => Some(ResourceKind::CachePublish),
        12 => Some(ResourceKind::Environment),
        13 => Some(ResourceKind::AttachmentSlot),
        14 => Some(ResourceKind::ChildDelegation),
        15 => Some(ResourceKind::Capability),
        16 => Some(ResourceKind::Operation),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_operation_method_record_registry_round_trips() {
        let methods = [
            PublicOperationMethodV1::CreateSandbox,
            PublicOperationMethodV1::UpdatePolicy,
            PublicOperationMethodV1::StartSandbox,
            PublicOperationMethodV1::StopSandbox,
            PublicOperationMethodV1::SuspendSandbox,
            PublicOperationMethodV1::ResumeSandbox,
            PublicOperationMethodV1::DeleteSandbox,
            PublicOperationMethodV1::CreateExecution,
            PublicOperationMethodV1::CancelExecution,
            PublicOperationMethodV1::CreateView,
            PublicOperationMethodV1::AttachView,
            PublicOperationMethodV1::ReplaceAttachment,
            PublicOperationMethodV1::DetachView,
            PublicOperationMethodV1::ReleaseView,
            PublicOperationMethodV1::CreateSnapshot,
            PublicOperationMethodV1::RestoreSnapshot,
            PublicOperationMethodV1::ForkSnapshot,
            PublicOperationMethodV1::DeleteSnapshot,
            PublicOperationMethodV1::RenewCapability,
            PublicOperationMethodV1::RevokeCapability,
            PublicOperationMethodV1::CancelOperation,
            PublicOperationMethodV1::ControlExecution,
            PublicOperationMethodV1::AttenuateCapability,
            PublicOperationMethodV1::PinCacheObject,
            PublicOperationMethodV1::UnpinCacheObject,
            PublicOperationMethodV1::OperatorRecover,
        ];

        for (code, method) in methods.into_iter().enumerate() {
            assert_eq!(public_operation_method_record_code_v1(method) as usize, code);
            assert_eq!(
                public_operation_method_from_record_code_v1(
                    public_operation_method_record_code_v1(method),
                ),
                Some(method),
            );
        }

        assert_eq!(public_operation_method_from_record_code_v1(26), None);
    }

    #[test]
    fn completed_abandon_projects_an_acknowledgment_milestone() {
        let public = DurablePublicOperationV1 {
            method: PublicOperationMethodV1::OperatorRecover,
            recovery_kind: PublicRecoveryKindV1::Ordinary,
            accepted_generation: 1,
            observation_sequence: 1,
            audit_id: [2; 16],
            accepted_wall_seconds: 1,
            last_reconciliation_wall_seconds: 1,
            completed_wall_seconds: Some(1),
        };
        let operation_id = OperationId::from_bytes([3; 16]);

        let acknowledgment = public.project(
            operation_id,
            OperationState::Succeeded,
            0,
            0,
            false,
            false,
            b"record",
            &[],
        );
        crate::public_api::CheckedOperationResourceV1::try_from(acknowledgment.clone()).unwrap();
        assert_eq!(
            acknowledgment
                .progress
                .as_option()
                .expect("progress")
                .milestone,
            "abandon-acknowledged"
        );

        let effect_completion = public.project(
            operation_id,
            OperationState::Succeeded,
            1,
            1,
            false,
            false,
            b"record",
            &[],
        );
        assert_eq!(
            effect_completion
                .progress
                .as_option()
                .expect("progress")
                .milestone,
            "complete"
        );
    }

    #[test]
    fn cleanup_purposes_have_distinct_pending_and_terminal_metadata_without_effect_aliases() {
        for kind in [
            PublicRecoveryKindV1::StopCleanup,
            PublicRecoveryKindV1::ExecutionNoApply,
        ] {
            use crate::domain_ledger::operation::{
                OperationRecord, decode_operation, encode_operation_record,
            };
            let operation = OperationId::from_bytes([4; 16]);
            let initial = match kind {
                PublicRecoveryKindV1::StopCleanup => {
                    DurablePublicOperationV1::stop_cleanup_initial_v1([4; 16], 100)
                }
                PublicRecoveryKindV1::ExecutionNoApply => {
                    DurablePublicOperationV1::execution_no_apply_initial_v1([4; 16], 100)
                }
                _ => unreachable!(),
            }
            .unwrap();
            let accepted =
                OperationRecord::new(OperationState::Accepted, 0, false, None, Some(initial));
            let encoded = encode_operation_record(accepted);
            assert_eq!(encoded[41], kind as u8);
            assert_eq!(decode_operation(&encoded).unwrap(), accepted);
            assert_eq!(initial.recovery_kind_v1(), kind);
            for invalid in [
                OperationRecord::new(OperationState::Accepted, 1, false, None, Some(initial)),
                OperationRecord::new(OperationState::Accepted, 0, true, None, Some(initial)),
            ] {
                assert!(decode_operation(&encode_operation_record(invalid)).is_err());
            }
            let pending = initial.project(
                operation,
                OperationState::Accepted,
                0,
                0,
                false,
                false,
                &encoded,
                &[],
            );
            assert_eq!(
                pending.progress.as_option().unwrap().milestone,
                "reconciling"
            );
            assert!(pending.completed_at.as_option().is_none());
            crate::public_api::CheckedOperationResourceV1::try_from(pending.clone()).unwrap();
            for replacement in 0..4 {
                let mut changed = pending.clone();
                match replacement {
                    0 => changed.method = PublicOperationMethodV1::StopSandbox.as_str().to_owned(),
                    1 => changed.progress.get_or_insert_default().total_units = 1,
                    2 => changed.cancelable = true,
                    _ => changed.retry_class = RetryClass::RETRY_CLASS_AFTER_STATE_CHANGE.into(),
                }
                assert!(crate::public_api::CheckedOperationResourceV1::try_from(changed).is_err());
            }

            let completed = initial.advance(OperationState::Succeeded, 101).unwrap();
            let record =
                OperationRecord::new(OperationState::Succeeded, 0, false, None, Some(completed));
            let encoded = encode_operation_record(record);
            assert_eq!(decode_operation(&encoded).unwrap(), record);
            let result = completed.project(
                operation,
                OperationState::Succeeded,
                0,
                0,
                false,
                false,
                &encoded,
                &[],
            );
            assert_eq!(result.progress.as_option().unwrap().milestone, "complete");
            crate::public_api::CheckedOperationResourceV1::try_from(result).unwrap();

            let mut metadata = Vec::new();
            initial.encode(&mut metadata);
            assert!(DurablePublicOperationV1::decode(&metadata, OperationState::Applying).is_err());
            metadata[0] = public_operation_method_record_code_v1(PublicOperationMethodV1::StopSandbox);
            assert!(DurablePublicOperationV1::decode(&metadata, OperationState::Accepted).is_err());
        }
    }

    #[test]
    fn metadata_completion_is_pending_until_its_distinct_terminal_transition() {
        use crate::domain_ledger::operation::{OperationRecord, decode_operation, encode_operation_record};
        let operation = OperationId::from_bytes([4; 16]);
        let initial = DurablePublicOperationV1::metadata_complete_initial_v1([4; 16], 100).unwrap();
        let accepted = OperationRecord::new(OperationState::Accepted, 0, false, None, Some(initial));
        let accepted_bytes = encode_operation_record(accepted);
        assert_eq!(accepted_bytes.len(), 104);
        assert_eq!(accepted_bytes[41], 1);
        assert_eq!(decode_operation(&accepted_bytes).unwrap(), accepted);
        let pending = initial.project(operation, OperationState::Accepted, 0, 0,
            false, false, &accepted_bytes, &[]);
        assert_eq!(pending.progress.as_option().unwrap().milestone, "metadata-verification-pending");
        assert!(pending.completed_at.as_option().is_none());
        crate::public_api::CheckedOperationResourceV1::try_from(pending.clone()).unwrap();

        let completed = initial.advance(OperationState::Succeeded, 101).unwrap();
        let succeeded = accepted.with_state_and_public_operation(OperationState::Succeeded, Some(completed));
        let bytes = encode_operation_record(succeeded);
        assert_eq!(decode_operation(&bytes).unwrap(), succeeded);
        let projected = completed.project(operation, OperationState::Succeeded, 0, 0,
            false, false, &bytes, &[]);
        assert_eq!(projected.progress.as_option().unwrap().milestone, "metadata-complete");
        assert_eq!(projected.completed_at.as_option().unwrap().seconds, 101);
        let checked = crate::public_api::CheckedOperationResourceV1::try_from(projected.clone()).unwrap();
        assert_eq!(checked.milestone(), crate::public_api::PublicMilestoneV1::MetadataComplete);

        let mut wrong_method = projected.clone();
        wrong_method.method = PublicOperationMethodV1::StartSandbox.as_str().to_owned();
        assert!(crate::public_api::CheckedOperationResourceV1::try_from(wrong_method).is_err());
        let mut wrong_units = pending.clone();
        wrong_units.progress.as_option_mut().unwrap().total_units = 1;
        assert!(crate::public_api::CheckedOperationResourceV1::try_from(wrong_units).is_err());
        let mut cancelable = pending.clone();
        cancelable.cancelable = true;
        assert!(crate::public_api::CheckedOperationResourceV1::try_from(cancelable).is_err());
        let mut wrong_retry = pending;
        wrong_retry.retry_class = RetryClass::RETRY_CLASS_NEVER.into();
        assert!(crate::public_api::CheckedOperationResourceV1::try_from(wrong_retry).is_err());

        // Kinds2 and3 select genuine cleanup recovery. An unknown kind must
        // remain refused without narrowing those independently tested branches.
        for (offset, value) in [(40, 0), (41, u8::MAX), (42, 1), (4, 1), (1, OperationState::Applying as u8)] {
            let mut substituted = accepted_bytes.clone();
            substituted[offset] = value;
            assert!(decode_operation(&substituted).is_err());
        }
        // Clearing the tag cannot make an ordinary empty Accepted operation valid.
        let mut ordinary = accepted_bytes;
        ordinary[41] = 0;
        assert!(decode_operation(&ordinary).is_err());
    }

}

#[cfg(test)]
mod stop_residual_tests;
