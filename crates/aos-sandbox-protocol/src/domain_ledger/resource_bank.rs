//! Owns canonical shared-bank records and complete passive replay.
//!
//! Image policy, inclusive account heads, claims, co-issuance and terminal
//! history are DATA. Decoding or assembling them grants no enrollment, clock,
//! writer, allocation permit or current Q04 authority. Native owners retain
//! every original descriptor, accepted identity and final crossing.
//!
//! ```text
//! bank = AOSRSH01 heads + AOSRSC02..08 claims + AOSRSP01 preparation
//!        + AOSRSQ01..02 co-issuance + AOSRST01..02 terminal history
//! image = AOSRSB01..06 closed full-vector image policy
//! ```

mod account;
mod bootstrap;
mod codec;
mod q04;
mod replay;
mod settlement;

use std::collections::BTreeMap;

use aos_sandbox_core::{AccountingError, ObjectDigest, RecordNamespace, ResourceAccount, ResourceVector};
use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_policy::{PublisherPolicyDataError, RetainedPublisherCompilerOriginV3};

use super::create_q04_history::Q04CutIdentityV1;
use super::protected_names::ProtectedJournalNamesV1;
use super::transaction::{JournalRecord, JournalTransaction};
use super::{JournalTransactionDataError, ProtectedHistoryDataErrorV1};

pub use account::{first_global_prefix_append_bytes, project_child, project_grant_claim, project_preparation_claim, require_grant_generation, reserve_head, settled_pair};
pub use bootstrap::{initial_enrollment_claims, prepare_enrollment_subdivisions};
pub use codec::{decode_image_policy, decode_pid1_delivery, IMAGE_POLICY_BYTES, HOST_IMAGE_POLICY_BYTES, FIRST_GLOBAL_IMAGE_POLICY_BYTES, NIX_INTAKE_IMAGE_POLICY_BYTES, Q04_INTAKE_IMAGE_POLICY_BYTES, ROOT_IMAGE_POLICY_BYTES};
pub use q04::{BANK_MEMBERS, inclusive_claim_for_cut, retained_use_claim_for_cut, sandbox_child, require_input_history};
pub use replay::{find_head, has_head, prior_initial_project_grant, validate};
pub use settlement::{PhysicalHistory, transaction_digest};

/// Borrows complete historical bank rows without retaining a protected owner.
type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Reports passive record, arithmetic and replay failures.
#[derive(Debug, thiserror::Error)]
pub enum ResourceBankDataError {
    /// Complete replay or a canonical record is malformed.
    #[error("shared resource ledger is corrupt")]
    CorruptLedger,
    /// The retained predecessor or proposed exact mutation differs.
    #[error("shared resource predecessor changed")]
    Conflict,
    /// Closed image enrollment DATA is absent or invalid.
    #[error("shared resource enrollment is unavailable")]
    EnrollmentUnavailable,
    /// Existing resource arithmetic retains its original refusal.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    /// Historical name decoding retains its DATA cause.
    #[error(transparent)]
    Names(#[from] ProtectedHistoryDataErrorV1),
    /// Existing transaction construction retains its DATA cause.
    #[error(transparent)]
    Transaction(#[from] JournalTransactionDataError),
    /// Existing framing retains its original cause.
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// Distinguishes retained Policy decoding from its four fixed identity joins.
#[derive(Debug, thiserror::Error)]
pub enum OriginIdentityDataError {
    /// The sole retained Policy codec refused its bytes.
    #[error(transparent)]
    Policy(#[from] PublisherPolicyDataError),
    /// Decoded provenance differs from the specified historical cut.
    #[error("retained input identity differs")]
    IdentityMismatch,
}

/// Carries two inert byte widths sampled from actual Native types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLayoutDemand {
    q04_attempt_bytes: usize,
    preparation_attempt_bytes: usize,
}

impl NativeLayoutDemand {
    /// Assembles two inert Native layout widths without computing demand.
    ///
    /// The Native caller supplies widths from its actual types. This value carries no
    /// owner or proof that a layout fits the failure allowance.
    pub const fn new(q04_attempt_bytes: usize, preparation_attempt_bytes: usize) -> Self {
        Self { q04_attempt_bytes, preparation_attempt_bytes }
    }
}

/// Retains the five historical enrollment comparison identities.
///
/// Canonical enrollment DATA does not retain PID1 descriptors or establish enrollment custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentIdentity {
    node: [u8; 16],
    epoch: [u8; 16],
    boot: [u8; 16],
    invocation: [u8; 16],
    manifest: [u8; 32],
}

// These bytes describe trusted image policy, but are not enrollment custody.
// The producer must additionally own the actual original image FD and epoch.
/// Retains the complete closed image capacity and subdivision policy.
///
/// The six image formats share one decoder and validation recipe. Native owners
/// must independently bind the original image and producer before enrollment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageBootstrapPolicy {
    node: [u8; 16],
    epoch: [u8; 16],
    capacity: ResourceVector,
    baseline: ResourceVector,
    controller: ResourceVector,
    components: ResourceVector,
    host: Option<HostComponentPolicy>,
    first_global_prefix: Option<ResourceVector>,
    nix_original_start_intake: Option<ResourceVector>,
    q04_original_intake: Option<ResourceVector>,
    root_receiving: Option<ResourceVector>,
}

// Both image-owned vectors are subdivisions of Components, not Node issuers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostComponentPolicy {
    service: ResourceVector,
    control: ResourceVector,
}

impl ImageBootstrapPolicy {
    fn validate(self, layout: NativeLayoutDemand) -> Result<(), ResourceBankDataError> {
        if self.node == [0; 16] || self.epoch == [0; 16] {
            return Err(ResourceBankDataError::EnrollmentUnavailable);
        }
        ResourceAccount::from_usage(
            aos_sandbox_core::ResourceCeilings::bounded(self.capacity),
            self.baseline,
            ResourceVector::ZERO,
        )?.reserve(self.controller)?.reserve(self.components)?;
        for envelope in [self.controller, self.components] {
            for dimension in [
                aos_sandbox_core::ResourceDimension::MemoryBytes,
                aos_sandbox_core::ResourceDimension::Pids,
                aos_sandbox_core::ResourceDimension::OpenFiles,
                aos_sandbox_core::ResourceDimension::ConcurrentOperations,
            ] {
                if envelope.get(dimension) == 0 {
                    return Err(ResourceBankDataError::EnrollmentUnavailable);
                }
            }
        }
        if let Some(host) = self.host {
            let amount = host.service.checked_add(host.control)?;
            self.components.checked_sub(amount)?;
            for envelope in [host.service, host.control] {
                for dimension in [
                    aos_sandbox_core::ResourceDimension::MemoryBytes,
                    aos_sandbox_core::ResourceDimension::Pids,
                    aos_sandbox_core::ResourceDimension::OpenFiles,
                    aos_sandbox_core::ResourceDimension::ConcurrentOperations,
                ] {
                    if envelope.get(dimension) == 0 {
                        return Err(ResourceBankDataError::EnrollmentUnavailable);
                    }
                }
            }
        }
        if let Some(prefix) = self.first_global_prefix {
            // The prefix is a subdivision of the already-paid Controller,
            // never another immediate Node grant.
            if self.host.is_none() {
                return Err(ResourceBankDataError::EnrollmentUnavailable);
            }
            self.controller.checked_sub(prefix)?;
            for dimension in [
                aos_sandbox_core::ResourceDimension::CpuMicrosPerPeriod,
                aos_sandbox_core::ResourceDimension::MemoryBytes,
                aos_sandbox_core::ResourceDimension::Pids,
                aos_sandbox_core::ResourceDimension::OpenFiles,
                aos_sandbox_core::ResourceDimension::ConcurrentOperations,
            ] {
                if prefix.get(dimension) == 0 {
                    return Err(ResourceBankDataError::EnrollmentUnavailable);
                }
            }
        }
        if let Some(intake) = self.nix_original_start_intake {
            let prefix = self.first_global_prefix
                .ok_or(ResourceBankDataError::EnrollmentUnavailable)?;
            self.controller.checked_sub(prefix)?.checked_sub(intake)?;
            for dimension in [
                aos_sandbox_core::ResourceDimension::CpuMicrosPerPeriod,
                aos_sandbox_core::ResourceDimension::MemoryBytes,
                aos_sandbox_core::ResourceDimension::Pids,
                aos_sandbox_core::ResourceDimension::OpenFiles,
                aos_sandbox_core::ResourceDimension::ConcurrentOperations,
            ] {
                if intake.get(dimension) == 0 {
                    return Err(ResourceBankDataError::EnrollmentUnavailable);
                }
            }
        }
        if let Some(intake) = self.q04_original_intake {
            intake.checked_sub(minimum_q04_failure_demand(layout)?)?;
            let prefix = self.first_global_prefix
                .ok_or(ResourceBankDataError::EnrollmentUnavailable)?;
            if intake.get(aos_sandbox_core::ResourceDimension::CpuMicrosPerPeriod)
                < prefix.get(aos_sandbox_core::ResourceDimension::CpuMicrosPerPeriod)
            {
                return Err(ResourceBankDataError::EnrollmentUnavailable);
            }
            let nix = self.nix_original_start_intake
                .ok_or(ResourceBankDataError::EnrollmentUnavailable)?;
            self.controller.checked_sub(prefix)?.checked_sub(nix)?.checked_sub(intake)?;
            for dimension in [
                aos_sandbox_core::ResourceDimension::CpuMicrosPerPeriod,
                aos_sandbox_core::ResourceDimension::MemoryBytes,
                aos_sandbox_core::ResourceDimension::Pids,
                aos_sandbox_core::ResourceDimension::OpenFiles,
                aos_sandbox_core::ResourceDimension::ConcurrentOperations,
            ] {
                if intake.get(dimension) == 0 {
                    return Err(ResourceBankDataError::EnrollmentUnavailable);
                }
            }
        }
        if let Some(root) = self.root_receiving {
            let host = self.host.ok_or(ResourceBankDataError::EnrollmentUnavailable)?;
            self.q04_original_intake
                .ok_or(ResourceBankDataError::EnrollmentUnavailable)?;
            self.components.checked_sub(host.service)?.checked_sub(host.control)?
                .checked_sub(root)?;
            require_root_service_envelope(root)?;
        }

        Ok(())
    }
}

/// Identifies a closed historical account role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountKind {
    /// Image-enrolled Node account.
    Node,
    /// Inclusive Controller account.
    Controller,
    /// Inclusive component envelope.
    Components,
    /// Inclusive Project account.
    Project,
    /// Inclusive Sandbox account.
    Sandbox,
    /// Historical operation or Host component account.
    Operation,
}

/// Retains one complete inclusive account head and its recorded usage.
///
/// A head is historical DATA, not an allocation permit or current account owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountHead {
    enrollment: EnrollmentIdentity,
    id: [u8; 16],
    parent: [u8; 16],
    kind: AccountKind,
    generation: u64,
    project: [u8; 16],
    sandbox: [u8; 16],
    tree_revision: [u8; 32],
    baseline: ResourceVector,
    account: ResourceAccount,
}

/// Identifies the retained accounting disposition of a claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimState {
    /// The amount remains reserved.
    Reserved,
    /// The amount is recorded as committed usage.
    Committed,
    /// The retained tombstone records a released reservation.
    Released,
}

/// Identifies the closed purpose admitted by the canonical claim family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimPurpose {
    /// Initial inclusive Controller grant.
    ControllerBootstrap,
    /// Initial inclusive component grant.
    ComponentEnvelope,
    /// Inclusive Project or Sandbox child grant.
    InclusiveGrant,
    /// Historical Sandbox snapshot use.
    Snapshot,
    /// Historical Project preparation reservation.
    ProjectPreparation,
    /// Retained Q04 use within its inclusive child grant.
    Q04Preparation,
    /// Image-owned Host component subdivision.
    HostComponentBootstrap,
    /// Reserved Host control interval.
    HostControlInterval,
    /// Once-paid first Global prefix subdivision.
    ControllerFirstGlobalPrefix,
    /// Once-paid original Nix intake subdivision.
    NixOriginalStartIntake,
    /// Once-paid original Q04 intake subdivision.
    Q04OriginalIntake,
    /// Distinct Root receiving subdivision.
    RootReceiving,
}


/// Retains the historical boot or sampled operation clock cut.
///
/// These comparison values do not sample a clock or retain a current clock owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimCut {
    /// The claim retains a boot-lifetime cut.
    BootLifetime,
    /// The claim retains the original sampled operation interval.
    Operation {
        /// Original wall-clock seconds.
        original_wall_seconds: i64,
        /// Original sampled boot time.
        original_boottime_nanoseconds: u64,
        /// Recorded boot-time deadline.
        deadline_boottime_nanoseconds: u64,
    },
}

/// Retains a complete historical resource claim and its inclusive joins.
///
/// Released claims remain replay tombstones; their presence does not prove cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Claim {
    enrollment: EnrollmentIdentity,
    id: [u8; 16],
    account: [u8; 16],
    // A nonzero child names the inclusive grant, not an additional use charge.
    child: [u8; 16],
    owner: [u8; 32],
    purpose: ClaimPurpose,
    operation: [u8; 16],
    project: [u8; 16],
    sandbox: [u8; 16],
    tree_revision: [u8; 32],
    cut: ClaimCut,
    genesis_instance: [u8; 32],
    amount: ResourceVector,
    state: ClaimState,
}

/// Retains the complete historical Project preparation association.
///
/// Physical names and commitments do not retain the original Controller or Source loans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationBinding {
    claim: Claim,
    nonce: [u8; 16],
    controller_names: ProtectedJournalNamesV1,
    source_names: ProtectedJournalNamesV1,
    source_sequence: u64,
    floor: [u8; 32],
    tree_head: [u8; 32],
    lineage_head: [u8; 32],
}

/// Retains the complete historical inclusive-grant and retained-use association.
///
/// The record contains Spec, candidate and optional input-provenance comparisons.
/// It does not retain the Native prepared specification, clock or current Q04 cut.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CoissuanceBinding {
    original: PreparationBinding,
    grant: Claim,
    use_claim: Claim,
    specification: [u8; 32],
    specification_size: u64,
    specification_record: [u8; 32],
    specification_operation: [u8; 16],
    specification_request: [u8; 32],
    candidate: [u8; 32],
    policy_binding: [u8; 32],
    origin: Option<InputAssociation>,
}

/// Retains the complete passive input-provenance and continuation association.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InputAssociation {
    normalized: [u8; 32],
    digest: [u8; 32],
    bytes: u64,
    continuation: ResourceVector,
    intake: [u8; 16],
    observations: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CommitPosition {
    commit_sequence: u64,
    durable_bytes: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Origin {
    id: [u8; 16],
    members: [u8; 32],
    returned: CommitPosition,
}

/// Retains the complete terminal commitment and eight historical origin positions.
///
/// Recorded sequences and offsets are DATA. Actual returned commits and the final
/// Root check remain with the Native terminal owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TerminalBinding {
    input_origin: bool,
    original: [u8; 16],
    coissuance: [u8; 32],
    transaction: [u8; 16],
    names: ProtectedJournalNamesV1,
    next: u64,
    prior_end: u64,
    root_final: [u8; 32],
    origins: [Origin; 8],
}

/// Specifies the fixed retained negative-intake memory allowance in bytes.
///
/// Native full-entry pricing and the checked minimum share this allowance;
/// the constant does not establish that either demand fits an image provision.
pub const FAILURE_MEMORY_BYTES: u64 = 2 * 1024 * 1024;

/// Computes the original checked negative-intake allowance from inert widths.
///
/// # Errors
/// Rejects checked arithmetic overflow or a payload beyond the fixed allowance.
pub fn minimum_q04_failure_demand(layout: NativeLayoutDemand) -> Result<ResourceVector, ResourceBankDataError> {
    // These are fixed retained slots, not observations or retry allowances:
    // original, receiver, preparation, initial clock, Controller/Source/profile/
    // CPU posts, LAST, clock comparison, and the CPU owner's native failure.
    // Before attachment, journal errors carry static reasons or raw errno;
    // Linux path/CPU/boot errors have only closed messages below 128 bytes.
    let error_slots = 1_usize + 1 + 1 + 1 + 4 + 1 + 1 + 1;
    let errors = error_slots.checked_mul(128)
        .ok_or(ResourceBankDataError::Conflict)?;
    // Journal basenames are bounded at 255 bytes. The lock suffix adds five;
    // the two writers' name checks and two independent posts are distinct.
    // Source's fixed ancestry walk holds only its current directory pair.
    let names = (255_usize + 5 + 1).checked_mul(4)
        .and_then(|bytes| bytes.checked_add(2 * (4096 + 1)))
        .ok_or(ResourceBankDataError::Conflict)?;
    // kernel_pair reads boot_id twice per sample. Its genuine procfs ABI is
    // 37 bytes; Rust 1.98.1 fs::read/default_read_to_end uses a 32-byte probe
    // and at most a 64-byte Vec for this zero-size, 37-byte kernel file.
    // Include both samples, probes, and the fixed pathname conversion.
    let clocks = 2_usize * 2 * (64 + 32 + 37);
    let payload = layout.q04_attempt_bytes
        .checked_add(errors)
        .and_then(|bytes| bytes.checked_add(names))
        .and_then(|bytes| bytes.checked_add(clocks))
        .and_then(|bytes| bytes.checked_add(layout.preparation_attempt_bytes))
        // Existing fixed policy/enrollment buffers and the two CPU read arrays
        // are included even though their owning readers need not enter on no-fit.
        .and_then(|bytes| bytes.checked_add(codec::Q04_INTAKE_IMAGE_POLICY_BYTES + 152 + 2 * 257))
        .ok_or(ResourceBankDataError::Conflict)?;
    if u64::try_from(payload).map_err(|_| ResourceBankDataError::Conflict)? > FAILURE_MEMORY_BYTES {
        return Err(ResourceBankDataError::Conflict);
    }
    Ok(ResourceVector::new([
        // One cell per possible owned byte bounds the fixed owners without an
        // invented entry count. Full history, native append and archive rows
        // are priced separately before their first allocation or effect.
        1, FAILURE_MEMORY_BYTES, 1, 4, 0, 0, 0, 0, 0, 0, FAILURE_MEMORY_BYTES, 0, 0, 0,
        FAILURE_MEMORY_BYTES, 0, 0, 0, 0, FAILURE_MEMORY_BYTES, FAILURE_MEMORY_BYTES, 1,
    ]))
}

/// Checks the complete closed receiving-service envelope shape.
///
/// # Errors
/// Rejects zero, unaligned, overflowing or undersized receiving dimensions.
pub fn require_root_service_envelope(
    envelope: ResourceVector,
) -> Result<(), ResourceBankDataError> {
    let cpu = envelope.get(aos_sandbox_core::ResourceDimension::CpuMicrosPerPeriod);
    let memory = envelope.get(aos_sandbox_core::ResourceDimension::MemoryBytes);
    if cpu == 0 || cpu % 1000 != 0 || cpu.checked_mul(10).is_none()
        || memory == 0 || memory % 4096 != 0
        || envelope.get(aos_sandbox_core::ResourceDimension::Pids) < 2 || envelope.get(aos_sandbox_core::ResourceDimension::Pids) == u64::MAX
        || envelope.get(aos_sandbox_core::ResourceDimension::OpenFiles) < 80 || envelope.get(aos_sandbox_core::ResourceDimension::OpenFiles) == u64::MAX
        || envelope.get(aos_sandbox_core::ResourceDimension::ConcurrentOperations) == 0
    {
        return Err(ResourceBankDataError::EnrollmentUnavailable);
    }
    Ok(())
}


/// Compares complete retained Policy provenance with the four Q04 preimages.
///
/// # Errors
/// Retains Policy decoding failures; rejects a project, target, input or candidate mismatch.
pub fn require_origin_identity(
    bytes: &[u8],
    identity: &Q04CutIdentityV1,
) -> Result<(), OriginIdentityDataError> {
    let original = RetainedPublisherCompilerOriginV3::from_record_bytes(bytes)
        .map_err(OriginIdentityDataError::Policy)?;
    if original.project() != identity.project() || original.original_target() != identity.sandbox()
        || original.normalized_input() != ObjectDigest::from_bytes(fixed_identity(identity.bytes(), 456))
        || original.candidate() != ObjectDigest::from_bytes(fixed_identity(identity.bytes(), 488))
    {
        return Err(OriginIdentityDataError::IdentityMismatch);
    }
    Ok(())
}

fn fixed_identity<const SIZE: usize>(bytes: &[u8], start: usize) -> [u8; SIZE] {
    let mut value = [0; SIZE];
    value.copy_from_slice(&bytes[start..start + SIZE]);
    value
}

/// Names the fixed retained input-origin row without constructing an origin.
pub const CONTROLLER_INPUT_ORIGIN_KEY: &[u8] = b"\0aos-controller-q04-input-origin-v1\0";

fn matches_record(record: &JournalRecord, prefix: u8, id: [u8; 16], bytes: &[u8]) -> bool {
    record.namespace() == RecordNamespace::ControllerResourceReservation
        && record.key() == replay::key(prefix, id)
        && record.value() == Some(bytes)
}

/// Borrows one full proposed account mutation without Native custody.
pub struct AccountMutation<'a> {
    transaction_id: &'a [u8; 16],
    before: &'a AccountHead,
    after: &'a AccountHead,
    claim: &'a Claim,
    previous_claim: &'a Option<Claim>,
    child: &'a Option<AccountHead>,
    preparation: &'a Option<PreparationBinding>,
    terminal: &'a Option<TerminalBinding>,
}

impl<'a> AccountMutation<'a> {
    /// Borrows the eight existing fields without validation or allocation.
    pub fn new(parts: (&'a [u8; 16], &'a AccountHead, &'a AccountHead, &'a Claim, &'a Option<Claim>, &'a Option<AccountHead>, &'a Option<PreparationBinding>, &'a Option<TerminalBinding>)) -> Self {
        let (transaction_id, before, after, claim, previous_claim, child, preparation, terminal) = parts;
        Self { transaction_id, before, after, claim, previous_claim, child, preparation, terminal }
    }
}

/// Borrows every passive enrollment row without original PID1 custody.
pub struct EnrollmentMutation<'a> {
    transaction_id: &'a [u8; 16],
    heads: &'a [AccountHead; 3],
    claims: &'a [Claim; 2],
    host: &'a Option<(AccountHead, [Claim; 2])>,
    first_global: &'a Option<Claim>,
    nix_intake: &'a Option<Claim>,
    q04_intake: &'a Option<Claim>,
    root_receiving: &'a Option<Claim>,
}

impl<'a> EnrollmentMutation<'a> {
    /// Borrows the eight existing fields without admission or account issuance.
    pub fn new(parts: (&'a [u8; 16], &'a [AccountHead; 3], &'a [Claim; 2], &'a Option<(AccountHead, [Claim; 2])>, &'a Option<Claim>, &'a Option<Claim>, &'a Option<Claim>, &'a Option<Claim>)) -> Self {
        let (transaction_id, heads, claims, host, first_global, nix_intake, q04_intake, root_receiving) = parts;
        Self { transaction_id, heads, claims, host, first_global, nix_intake, q04_intake, root_receiving }
    }
}

/// Borrows the complete historical co-issuance mutation without a current cut.
pub struct CoissuanceMutation<'a> {
    before: &'a AccountHead,
    after: &'a AccountHead,
    residual: &'a Claim,
    child: &'a AccountHead,
    binding: &'a CoissuanceBinding,
}

impl<'a> CoissuanceMutation<'a> {
    /// Borrows the five original DATA fields without a specification or clock loan.
    pub fn new(parts: (&'a AccountHead, &'a AccountHead, &'a Claim, &'a AccountHead, &'a CoissuanceBinding)) -> Self {
        let (before, after, residual, child, binding) = parts;
        Self { before, after, residual, child, binding }
    }
}

/// Copies the finite historical EnrollmentIdentity comparison fields.
///
/// These writable snapshot values establish no Native authority.
#[derive(Clone, Copy)]
pub struct EnrollmentIdentityFields {
    /// Historical Node identity.
    pub node: [u8; 16],
    /// Historical boot identity.
    pub boot: [u8; 16],
    /// Historical producer invocation.
    pub invocation: [u8; 16],
}

/// Copies the finite historical ImageBootstrapPolicy comparison fields.
///
/// These writable snapshot values establish no Native authority.
#[derive(Clone, Copy)]
pub struct BootstrapProvisions {
    /// Optional paid-prefix subdivision DATA.
    pub first_global_prefix: Option<ResourceVector>,
    /// Optional original Nix intake subdivision DATA.
    pub nix_original_start_intake: Option<ResourceVector>,
    /// Optional original Q04 intake subdivision DATA.
    pub q04_original_intake: Option<ResourceVector>,
    /// Optional Root receiving subdivision DATA.
    pub root_receiving: Option<ResourceVector>,
}

/// Copies the finite historical AccountHead comparison fields.
///
/// These writable snapshot values establish no Native authority.
#[derive(Clone, Copy)]
pub struct AccountHeadFields {
    /// Historical enrollment identity.
    pub enrollment: EnrollmentIdentity,
    /// Account identity.
    pub id: [u8; 16],
    /// Closed account kind.
    pub kind: AccountKind,
    /// Historical account generation.
    pub generation: u64,
    /// Historical Project identity.
    pub project: [u8; 16],
    /// Historical tree revision commitment.
    pub tree_revision: [u8; 32],
}

/// Copies the finite historical Claim comparison fields.
///
/// These writable snapshot values establish no Native authority.
#[derive(Clone, Copy)]
pub struct ClaimFields {
    /// Historical enrollment identity.
    pub enrollment: EnrollmentIdentity,
    /// Historical claim identity.
    pub id: [u8; 16],
    /// Charged account identity.
    pub account: [u8; 16],
    /// Closed historical claim purpose.
    pub purpose: ClaimPurpose,
    /// Historical clock-cut DATA.
    pub cut: ClaimCut,
    /// Recorded resource amount.
    pub amount: ResourceVector,
    /// Closed historical claim state.
    pub state: ClaimState,
}

/// Copies the finite historical CoissuanceBinding comparison fields.
///
/// These writable snapshot values establish no Native authority.
#[derive(Clone, Copy)]
pub struct CoissuanceFields {
    /// Original preparation claim DATA.
    pub original_claim: Claim,
    /// Retained use claim DATA.
    pub use_claim: Claim,
    /// Specification commitment.
    pub specification: [u8; 32],
    /// Specification-record commitment.
    pub specification_record: [u8; 32],
    /// Presence of retained input association DATA.
    pub has_input_origin: bool,
}

/// Copies the finite historical TerminalBinding comparison fields.
///
/// These writable snapshot values establish no Native authority.
#[derive(Clone, Copy)]
pub struct TerminalFields {
    /// Original preparation claim identity.
    pub original_id: [u8; 16],
    /// Historical physical names DATA.
    pub names: ProtectedJournalNamesV1,
}

impl EnrollmentIdentity {
    /// Returns the three historical identity comparison values.
    ///
    /// The writable Copy snapshot establishes no Native acceptance or currentness.
    pub const fn native_fields(self) -> EnrollmentIdentityFields {
        EnrollmentIdentityFields {
            node: self.node,
            boot: self.boot,
            invocation: self.invocation,
        }
    }

    /// Compares Node, policy epoch and manifest with the supplied image DATA.
    ///
    /// The Native caller retains its separate boot, descriptor and producer checks.
    pub fn matches_image(self, policy: ImageBootstrapPolicy, manifest: [u8; 32]) -> bool {
        self.node == policy.node && self.epoch == policy.epoch && self.manifest == manifest
    }

    /// Compares the four supplied historical Host identity fields.
    ///
    /// Recipient invocation and Host policy comparisons remain separate.
    pub fn matches_host_fields(self, node: [u8; 16], epoch: [u8; 16], manifest: [u8; 32], producer: [u8; 16]) -> bool {
        self.node == node && self.epoch == epoch && self.manifest == manifest && self.invocation == producer
    }

    /// Computes the existing canonical account identity for the supplied role bytes.
    pub fn account_id(self, role: &[u8]) -> [u8; 16] {
        bootstrap::account_id(self, role)
    }
}

impl ImageBootstrapPolicy {
    /// Returns the four optional image subdivision values in their original order.
    pub const fn bootstrap_provisions(self) -> BootstrapProvisions {
        BootstrapProvisions {
            first_global_prefix: self.first_global_prefix,
            nix_original_start_intake: self.nix_original_start_intake,
            q04_original_intake: self.q04_original_intake,
            root_receiving: self.root_receiving,
        }
    }

    /// Compares the complete fixed Host service and control subdivisions.
    pub fn host_matches(self, service: ResourceVector, control: ResourceVector) -> bool {
        self.host == Some(HostComponentPolicy { service, control })
    }
}

impl AccountHead {
    /// Decodes a complete canonical historical account head.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, checksum, enrollment, closed kind or account shape.
    /// Retains resource-account arithmetic failures.
    pub fn decode(bytes: &[u8]) -> Result<Self, ResourceBankDataError> {
        codec::decode_head(bytes)
    }

    /// Returns the six historical account comparison values.
    ///
    /// The writable Copy snapshot establishes no Native acceptance or currentness.
    pub const fn native_fields(self) -> AccountHeadFields {
        AccountHeadFields {
            enrollment: self.enrollment,
            id: self.id,
            kind: self.kind,
            generation: self.generation,
            project: self.project,
            tree_revision: self.tree_revision,
        }
    }

    /// Replaces only the historical generation without validating currentness.
    pub const fn with_generation(self, generation: u64) -> Self {
        Self { generation, ..self }
    }

    /// Reserves the recorded amount and installs the already-computed generation.
    ///
    /// # Errors
    ///
    /// Retains the original resource-account reservation failure.
    pub fn reserve_at_generation(self, generation: u64, amount: ResourceVector) -> Result<Self, ResourceBankDataError> {
        Ok(Self { generation, account: self.account.reserve(amount)?, ..self })
    }

    /// Reads every account dimension as a finite historical ceiling.
    ///
    /// # Errors
    ///
    /// Rejects an unbounded dimension in the original registry order.
    pub fn finite_ceilings(self) -> Result<ResourceVector, ResourceBankDataError> {
        replay::finite_ceilings(self)
    }
}

impl Claim {
    /// Decodes a complete canonical historical claim.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, checksum, enrollment, purpose, state or clock-cut
    /// shape, including a purpose unsupported by the selected format.
    pub fn decode(bytes: &[u8]) -> Result<Self, ResourceBankDataError> {
        codec::decode_claim(bytes)
    }

    /// Returns the seven historical claim comparison values.
    ///
    /// The writable Copy snapshot establishes no Native acceptance or currentness.
    pub const fn native_fields(self) -> ClaimFields {
        ClaimFields {
            enrollment: self.enrollment,
            id: self.id,
            account: self.account,
            purpose: self.purpose,
            cut: self.cut,
            amount: self.amount,
            state: self.state,
        }
    }

    /// Replaces only the historical amount without issuing a reservation.
    pub const fn with_amount(self, amount: ResourceVector) -> Self {
        Self { amount, ..self }
    }
}

impl PreparationBinding {
    /// Assembles the eight ordered historical preparation fields without validation.
    ///
    /// The tuple contains claim, nonce, Controller names, Source names, Source sequence,
    /// floor, tree head and lineage head. No original loan is retained.
    pub fn from_parts(parts: (Claim, [u8; 16], ProtectedJournalNamesV1, ProtectedJournalNamesV1, u64, [u8; 32], [u8; 32], [u8; 32])) -> Self {
        let (claim, nonce, controller_names, source_names, source_sequence, floor, tree_head, lineage_head) = parts;
        Self { claim, nonce, controller_names, source_names, source_sequence, floor, tree_head, lineage_head }
    }

    /// Returns the complete historical preparation claim.
    pub const fn claim(self) -> Claim { self.claim }

    /// Compares operation, Project, nonce and floor with the historical Q04 cut.
    pub fn matches_q04_cut(self, identity: &Q04CutIdentityV1) -> bool {
        self.claim.operation == identity.operation().into_bytes()
            && self.claim.project == identity.project().into_bytes()
            && self.nonce == identity.nonce()
            && self.floor == *identity.gen1_floor().as_bytes()
    }

    /// Compares a complete decoded preparation record with this historical value.
    ///
    /// # Errors
    ///
    /// Retains framing, nested claim, historical-name and canonical re-encoding failures.
    /// A well-formed differing value returns `false`.
    pub fn matches_canonical(self, bytes: &[u8]) -> Result<bool, ResourceBankDataError> {
        Ok(codec::decode_preparation(bytes)? == self)
    }
}

impl InputAssociation {
    /// Assembles the six ordered input-association fields without validation.
    ///
    /// The tuple contains normalized-input digest, original-byte digest, original-byte
    /// count, continuation amount, intake identity and observer quota.
    pub fn from_parts(parts: ([u8; 32], [u8; 32], u64, ResourceVector, [u8; 16], u64)) -> Self {
        let (normalized, digest, bytes, continuation, intake, observations) = parts;
        Self { normalized, digest, bytes, continuation, intake, observations }
    }
}

impl CoissuanceBinding {
    /// Assembles all eleven ordered co-issuance fields without validation.
    ///
    /// The tuple contains original preparation, inclusive grant, retained use, Spec
    /// commitment and byte count, Spec-record commitment and operation, Spec request,
    /// candidate, policy binding and optional input association. It retains no Native
    /// Spec, original input owner, clock or authority.
    pub fn from_parts(parts: (PreparationBinding, Claim, Claim, [u8; 32], u64, [u8; 32], [u8; 16], [u8; 32], [u8; 32], [u8; 32], Option<InputAssociation>)) -> Self {
        let (original, grant, use_claim, specification, specification_size, specification_record, specification_operation, specification_request, candidate, policy_binding, origin) = parts;
        Self { original, grant, use_claim, specification, specification_size, specification_record, specification_operation, specification_request, candidate, policy_binding, origin }
    }

    /// Returns the five historical co-issuance comparison values.
    ///
    /// The writable Copy snapshot establishes no Native acceptance or currentness.
    pub const fn native_fields(self) -> CoissuanceFields {
        CoissuanceFields {
            original_claim: self.original.claim,
            use_claim: self.use_claim,
            specification: self.specification,
            specification_record: self.specification_record,
            has_input_origin: self.origin.is_some(),
        }
    }

    /// Hashes the complete canonical co-issuance encoding.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent preparation, grant, use, Spec or input associations and
    /// retains nested canonical encoding and resource arithmetic failures.
    pub fn commitment(self) -> Result<[u8; 32], ResourceBankDataError> {
        use sha2::{Digest as _, Sha256};
        Ok(Sha256::digest(q04::encode(self)?).into())
    }

    /// Compares the complete original-byte digest and decoded provenance joins.
    ///
    /// # Errors
    ///
    /// After matching byte count and digest, rejects malformed retained Policy bytes.
    /// Missing association or differing byte count, digest or joins returns `false`.
    pub fn matches_origin_bytes(self, bytes: &[u8]) -> Result<bool, ResourceBankDataError> {
        q04::matches_origin_bytes(self, bytes)
    }

    /// Requires every original association and current historical bank row.
    ///
    /// # Errors
    ///
    /// Rejects missing, malformed or differing claim, child, preparation, co-issuance,
    /// terminal or input rows and retains resource arithmetic failures.
    pub fn require_replayed(self, state: &State) -> Result<(), ResourceBankDataError> {
        q04::require_replayed(state, self)
    }
}

impl TerminalBinding {
    fn original_id(self) -> [u8; 16] { self.original }

    /// Assembles the complete terminal association without accepting a returned commit.
    ///
    /// The ordered tuple contains input-presence flag, original claim identity,
    /// co-issuance commitment, terminal transaction identity, names, next sequence,
    /// prior end, Root-final commitment and eight origin position tuples. Each origin
    /// contains transaction identity, member commitment, commit sequence and durable
    /// end. The Native caller retains its actual results and final checks.
    pub fn from_parts(parts: (bool, [u8; 16], [u8; 32], [u8; 16], ProtectedJournalNamesV1, u64, u64, [u8; 32], [([u8; 16], [u8; 32], u64, u64); 8])) -> Self {
        let (input_origin, original, coissuance, transaction, names, next, prior_end, root_final, positions) = parts;
        let origins = positions.map(|(id, members, commit_sequence, durable_bytes)| Origin {
            id, members, returned: CommitPosition { commit_sequence, durable_bytes },
        });
        Self { input_origin, original, coissuance, transaction, names, next, prior_end, root_final, origins }
    }

    /// Returns the two historical terminal comparison values.
    ///
    /// The writable Copy snapshot establishes no Native acceptance or currentness.
    pub const fn native_fields(self) -> TerminalFields {
        TerminalFields {
            original_id: self.original,
            names: self.names,
        }
    }

    /// Compares a complete decoded terminal record with this historical value.
    ///
    /// # Errors
    ///
    /// Rejects invalid framing, historical names, origin positions or canonical bytes.
    /// A well-formed differing value returns `false`.
    pub fn matches_canonical(self, bytes: &[u8]) -> Result<bool, ResourceBankDataError> {
        Ok(settlement::decode(bytes)? == self)
    }

    /// Checks the full terminal predecessor against the supplied historical mutation.
    ///
    /// # Errors
    ///
    /// Rejects missing or inconsistent original co-issuance and replay rows, an already
    /// recorded terminal, or differing transaction, claim or account predecessors.
    pub fn require_predecessor(self, state: &State, mutation: AccountMutation<'_>) -> Result<(), ResourceBankDataError> {
        settlement::require_predecessor(state, self, &mutation)
    }
}

/// Borrows the exact retained claim bytes from the supplied historical state.
///
/// The returned slice shares the state lifetime. Absence returns `None`; this
/// lookup does not decode, normalize or establish currentness.
pub fn claim_bytes(state: &State, id: [u8; 16]) -> Option<&[u8]> {
    replay::record_bytes(state, replay::CLAIM_PREFIX, id)
}

/// Borrows the exact retained preparation bytes from the supplied historical state.
///
/// The returned slice shares the state lifetime. Absence returns `None`; this
/// lookup does not decode, normalize or establish currentness.
pub fn preparation_bytes(state: &State, id: [u8; 16]) -> Option<&[u8]> {
    replay::record_bytes(state, replay::PREPARATION_PREFIX, id)
}

/// Borrows the exact retained terminal bytes from the supplied historical state.
///
/// The returned slice shares the state lifetime. Absence returns `None`; this
/// lookup does not decode, normalize or establish currentness.
pub fn terminal_bytes(state: &State, id: [u8; 16]) -> Option<&[u8]> {
    replay::record_bytes(state, settlement::PREFIX, id)
}

/// Recognizes the bank namespace and account-head key prefix.
///
/// Complete key and record validation belongs to the later canonical decoder and replay.
pub fn is_head_entry(namespace: RecordNamespace, key: &[u8]) -> bool {
    namespace == RecordNamespace::ControllerResourceReservation && key.first() == Some(&replay::HEAD_PREFIX)
}

#[cfg(test)]
mod physical_history_tests {
    use sha2::{Digest as _, Sha256};

    use super::*;
    use aos_sandbox_core::ResourceDimension;

    // This fixture contains historical DATA; it owns no original files or loans.
    fn historical_coissuance(names: ProtectedJournalNamesV1) -> CoissuanceBinding {
        let identity = EnrollmentIdentity {
            node: [1; 16], epoch: [2; 16], boot: [3; 16],
            invocation: [4; 16], manifest: [5; 32],
        };
        let original = Claim {
            enrollment: identity, id: [6; 16], account: [7; 16], child: [0; 16],
            owner: [8; 32], purpose: ClaimPurpose::ProjectPreparation,
            operation: [9; 16], project: [10; 16], sandbox: [0; 16],
            tree_revision: [11; 32],
            cut: ClaimCut::Operation {
                original_wall_seconds: 1, original_boottime_nanoseconds: 2,
                deadline_boottime_nanoseconds: 3,
            },
            genesis_instance: [12; 32],
            amount: ResourceVector::new([3; ResourceDimension::COUNT]),
            state: ClaimState::Reserved,
        };
        let grant = Claim {
            id: [13; 16], child: [14; 16], sandbox: [14; 16],
            purpose: ClaimPurpose::InclusiveGrant,
            amount: ResourceVector::new([1; ResourceDimension::COUNT]), ..original
        };
        let use_claim = Claim {
            id: [15; 16], account: grant.child, child: [0; 16],
            purpose: ClaimPurpose::Q04Preparation, ..grant
        };
        CoissuanceBinding {
            original: PreparationBinding {
                claim: original, nonce: [16; 16], controller_names: names,
                source_names: names, source_sequence: 1, floor: [17; 32],
                tree_head: [18; 32], lineage_head: [19; 32],
            },
            grant, use_claim, specification: [20; 32], specification_size: 1,
            specification_record: [21; 32], specification_operation: [22; 16],
            specification_request: [23; 32], candidate: [24; 32],
            policy_binding: [25; 32], origin: None,
        }
    }

    #[test]
    fn retained_physical_history_requires_exact_adjacency_and_all_origins() {
        let names = ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap();
        let original = historical_coissuance(names);
        let transactions: [JournalTransaction; 8] = std::array::from_fn(|index| {
            let mut records = vec![JournalRecord::put(
                RecordNamespace::ControllerPolicyHold, vec![0], vec![1],
            )];
            if index == 0 {
                for key in 1..8 {
                    records.push(JournalRecord::put(
                        RecordNamespace::ControllerPolicyHold, vec![key], vec![1],
                    ));
                }
                records.push(JournalRecord::put(
                    RecordNamespace::ControllerResourceReservation,
                    replay::key(q04::PREFIX, original.original.claim.id).to_vec(),
                    q04::encode(original).unwrap().to_vec(),
                ));
            }
            JournalTransaction::new([u8::try_from(index + 1).unwrap(); 16], records).unwrap()
        });
        let origins = std::array::from_fn(|index| Origin {
            id: *transactions[index].id(),
            members: settlement::transaction_digest(&transactions[index]).unwrap(),
            returned: CommitPosition {
                commit_sequence: 11 + u64::try_from(index).unwrap() * 3,
                durable_bytes: u64::try_from(index + 1).unwrap() * 100,
            },
        });
        let terminal = TerminalBinding {
            input_origin: false, original: original.original.claim.id,
            coissuance: Sha256::digest(q04::encode(original).unwrap()).into(),
            transaction: [30; 16], names, next: 33, prior_end: 800,
            root_final: [31; 32], origins,
        };
        let mut state = State::new();
        state.insert((RecordNamespace::ControllerResourceReservation,
            replay::key(q04::PREFIX, terminal.original).to_vec()),
            q04::encode(original).unwrap().to_vec());
        state.insert((RecordNamespace::ControllerResourceReservation,
            replay::key(settlement::PREFIX, terminal.original).to_vec()),
            settlement::encode(terminal).unwrap().to_vec());

        // Correct digest and returned positions cannot replace physical adjacency.
        for (begin_sequence, begin_offset) in [(11, 100), (12, 99)] {
            let mut history = PhysicalHistory::new(&state).unwrap();
            assert!(matches!(
                history.observe(&transactions[1], begin_sequence, 14, begin_offset, 200),
                Err(ResourceBankDataError::CorruptLedger)
            ));
        }

        let mut history = PhysicalHistory::new(&state).unwrap();
        for (index, transaction) in transactions.iter().enumerate() {
            let begin = if index == 0 { 1 } else { origins[index - 1].returned.commit_sequence + 1 };
            let offset = if index == 0 { 0 } else { origins[index - 1].returned.durable_bytes };
            history.observe(transaction, begin, origins[index].returned.commit_sequence,
                offset, origins[index].returned.durable_bytes).unwrap();
        }
        let (claim, head) = settlement::current_use(&state, original).unwrap();
        let committed = JournalTransaction::new(terminal.transaction, vec![
            JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                replay::key(replay::HEAD_PREFIX, head.id).to_vec(), codec::encode_head(head).unwrap().to_vec()),
            JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, claim.id).to_vec(), codec::encode_claim(claim).unwrap().to_vec()),
            JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                replay::key(settlement::PREFIX, terminal.original).to_vec(), settlement::encode(terminal).unwrap().to_vec()),
        ]).unwrap();
        history.observe(&committed, 33, 37, 800, 900).unwrap();
        let mut ids = transactions.iter().map(|transaction| *transaction.id())
            .chain(std::iter::once(terminal.transaction)).collect::<std::collections::BTreeSet<_>>();

        history.finish(&ids, names).unwrap();
        ids.remove(&origins[7].id);
        assert!(matches!(history.finish(&ids, names), Err(ResourceBankDataError::CorruptLedger)));
    }

    #[test]
    fn retained_origin_decode_cause_is_rich_before_coarse_history_projection() {
        let mut body = [1; 680];
        body[48..64].copy_from_slice(&[9; 16]);
        body[96..104].copy_from_slice(&1_u64.to_be_bytes());
        body[104..112].fill(0);
        body[128..136].copy_from_slice(&1_u64.to_be_bytes());
        body[136..144].copy_from_slice(&60_000_000_001_u64.to_be_bytes());
        body[144..152].copy_from_slice(&2_u64.to_be_bytes());
        body[152..160].copy_from_slice(&65_000_000_002_u64.to_be_bytes());
        let identity = Q04CutIdentityV1::from_body(body).unwrap();
        let malformed = [1, 2, 3];
        let mut binding = historical_coissuance(ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap());
        binding.origin = Some(InputAssociation {
            normalized: [1; 32], digest: Sha256::digest(malformed).into(),
            bytes: 3, continuation: ResourceVector::ZERO, intake: [26; 16], observations: 27,
        });
        let mut state = State::new();
        state.insert((RecordNamespace::ControllerResourceReservation,
            replay::key(q04::PREFIX, binding.original.claim.id).to_vec()),
            q04::encode(binding).unwrap().to_vec());

        assert!(matches!(require_origin_identity(&malformed, &identity),
            Err(OriginIdentityDataError::Policy(_))));
        assert!(matches!(require_input_history(&state, &identity, Some(&malformed)),
            Err(ResourceBankDataError::CorruptLedger)));
    }
}
