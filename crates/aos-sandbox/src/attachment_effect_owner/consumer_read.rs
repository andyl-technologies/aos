//! Holds the Controller component of a later filesystem consumer read.
//!
//! The accepted Attachment lease and original View revision outlive the initial
//! Attach caller and Host preparation deadline. This owner joins those exact
//! resources to a fresh signed assignment without issuing another lease or
//! reconstructing live Host/Mount/worker custody. Its journal borrow remains
//! exclusive through nonauthorizing preparation and exact readback.
//!
//! `ResourcePrepared` is not a read admission. A genuine original Ready-worker
//! and kernel-request producer, Policy/Root, Source, Cache and reply-scoped
//! barrier are still missing. No method here signs, dispatches, reads backing
//! bytes, acknowledges worker readiness or releases external pins. The closed
//! local suffix records quarantine only; later effects require a separately
//! reviewed protocol and complete remaining-capacity reservation.

use std::path::Path;

use aos_sandbox_core::{
    AttachmentId, ObjectDescriptor, ProjectId, RawPairedClockSample, SandboxId,
};

use super::ProtectedAttachmentEffectOwnerV1;
use crate::attachment_slot_state::{self, DurableAttachmentSlotV1};
use crate::attachment_state::{self, DurableAttachmentDesiredStateV1};
use crate::filesystem_view_state::{self, DurableFilesystemViewRevisionV1};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_authority::RuntimeAuthorityLimits;
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityStore};
use crate::runtime_scope::{
    self, CurrentAssignmentTarget, CurrentRuntimeScopePolicy, RuntimeScopeHolder,
};
use crate::{Journal, JournalError};

mod attempt;
mod source;
#[cfg(test)]
mod tests;

pub use attempt::{
    ConsumerReadRequestDataV1, ConsumerResourceAttemptLimitsV1, ConsumerResourceAttemptPhaseV1,
    DurableConsumerResourceAttemptV1,
};

const CONTROLLER_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

pub(crate) fn validate_consumer_resource_transaction(
    journal: &Journal,
    transaction: &crate::JournalTransaction,
    allow_capacity: bool,
    settling: Option<[u8; 32]>,
) -> Result<(), JournalError> {
    attempt::require_transition(journal, transaction, allow_capacity, settling)
}

/// Reports changed accepted resources or unavailable protected preparation.
#[derive(Debug, thiserror::Error)]
pub enum ConsumerResourceErrorV1 {
    /// The actual fixed writer, durable append or remaining capacity failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Current explicit FUSE desired state or its accepted lease failed.
    #[error(transparent)]
    Attachment(#[from] crate::attachment_state::AttachmentDesiredStateError),
    /// The original immutable View or its logical availability failed.
    #[error(transparent)]
    View(#[from] crate::filesystem_view_state::FilesystemViewRevisionStateError),
    /// The accepted destination slot is absent, released or substituted.
    #[error(transparent)]
    Slot(#[from] crate::attachment_slot_state::AttachmentSlotStateError),
    /// Signed current ownership or its original nonrenewable window failed.
    #[error(transparent)]
    Assignment(#[from] crate::runtime_scope::CurrentRuntimeScopeError),
    /// The protected original allocation/runtime history failed.
    #[error(transparent)]
    Namespace(#[from] crate::runtime_scope::NamespaceTargetError),
    /// Protected holder history failed validation.
    #[error(transparent)]
    Authority(#[from] crate::runtime_authority::RuntimeAuthorityError),
    /// The exact accepted authority publication is unavailable or inconsistent.
    #[error(transparent)]
    Publication(#[from] crate::publication::AuthorityPublicationError),
    /// The exact selected resource, binding, request or journal head changed.
    #[error("Controller consumer resource changed")]
    Changed,
    /// Comparison data, a closed record or configured ceiling is invalid.
    #[error("Controller consumer resource preparation is invalid")]
    Invalid,
    /// Configured resource-preparation capacity is exhausted.
    #[error("Controller consumer resource preparation capacity is exhausted")]
    Capacity,
}

enum Location {
    FixedController,
    #[cfg(test)]
    Fixture(std::path::PathBuf),
}

impl Location {
    fn recheck(&self, journal: &Journal, uid: u32) -> Result<(), JournalError> {
        match self {
            Self::FixedController => journal.validate_held_owned_at_for_uid(
                Path::new(CONTROLLER_DIRECTORY),
                CONTROLLER_JOURNAL,
                uid,
            ),
            #[cfg(test)]
            Self::Fixture(path) => {
                journal.validate_held_protected_at_uid_for_test(path, CONTROLLER_JOURNAL, uid)
            }
        }
    }
}

/// Borrows actual accepted resources without conferring disclosure permission.
///
/// The value cannot be cloned, deserialized or minted from a worker plan. It
/// selects one current assignment/ownership revision and never extends that
/// selection's deadline. Its namespace origin is a protected historical join,
/// not proof that the original worker connection is Ready or still retained.
#[must_use = "retain the actual Controller writer through preparation/readback"]
pub struct CurrentControllerConsumerResourceV1<'owner> {
    journal: &'owner mut Journal,
    assignment: CurrentAssignmentTarget,
    binding: RuntimeAuthorityBindingV1,
    runtime_limits: RuntimeAuthorityLimits,
    desired: DurableAttachmentDesiredStateV1,
    view: DurableFilesystemViewRevisionV1,
    slot: DurableAttachmentSlotV1,
    origin: runtime_scope::ConsumerNamespaceOriginV1,
    source: source::ResourceSource,
    location: Location,
    owner_uid: u32,
    sequence: u64,
    request: Option<ConsumerReadRequestDataV1>,
    policy_flight_used: bool,
    unavailable: bool,
}

impl ProtectedAttachmentEffectOwnerV1<'_> {
    /// Holds accepted FUSE resources under fresh assignment-only verification.
    ///
    /// The attachment identity selects protected desired state. Sandbox,
    /// incarnation, holder, original View, slot and Policy are derived from the
    /// actual journal and authenticated assignment, not supplied as claims.
    /// This performs no Host query, lease renewal or worker/read admission.
    ///
    /// # Errors
    ///
    /// Rejects a foreign fixed journal, absent/released/non-FUSE resources,
    /// expired accepted lease, broken holder continuity, substituted namespace
    /// history, signed authority or changed physical names.
    pub fn hold_current_consumer_resource<'owner, T>(
        &'owner mut self,
        attachment: AttachmentId,
        policy: CurrentRuntimeScopePolicy,
        clock: &mut T,
    ) -> Result<CurrentControllerConsumerResourceV1<'owner>, ConsumerResourceErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        capture(
            self.journal,
            attachment,
            policy,
            clock,
            Location::FixedController,
        )
    }

    /// Records historical quarantine without reopening or renewing a read.
    ///
    /// This retires only the local nonauthorizing preparation-capacity claim.
    /// It neither proves no disclosure nor releases a Mount/Cache/Source hold.
    /// A cold record can never reconstruct a live consumer resource guard.
    ///
    /// # Errors
    ///
    /// Rejects foreign named custody, malformed or changed original records,
    /// missing capacity and ambiguous durable append.
    pub fn quarantine_consumer_resource_preparation(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<DurableConsumerResourceAttemptV1, ConsumerResourceErrorV1> {
        let uid = self.journal.protected_owner_uid()?;
        Location::FixedController.recheck(self.journal, uid)?;
        let result = attempt::quarantine(self.journal, request_id)?;
        Location::FixedController.recheck(self.journal, uid)?;
        Ok(result)
    }
}

fn capture<'owner, T>(
    journal: &'owner mut Journal,
    attachment: AttachmentId,
    policy: CurrentRuntimeScopePolicy,
    clock: &mut T,
    location: Location,
) -> Result<CurrentControllerConsumerResourceV1<'owner>, ConsumerResourceErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let owner_uid = journal.protected_owner_uid()?;
    location.recheck(journal, owner_uid)?;
    let desired =
        attachment_state::get(journal, attachment)?.ok_or(ConsumerResourceErrorV1::Changed)?;
    let (sandbox, incarnation) = desired.intent().consumer();
    let current = RuntimeAuthorityStore::load(journal, policy.runtime_limits)?
        .current(sandbox)?
        .ok_or(ConsumerResourceErrorV1::Changed)?;
    let holder = current.holder().ok_or(ConsumerResourceErrorV1::Changed)?;
    let runtime_limits = policy.runtime_limits;
    let assignment = runtime_scope::acquire_current_assignment(
        journal,
        RuntimeScopeHolder { sandbox, holder },
        policy,
        clock,
    )?;
    let binding = assignment.binding().clone();
    if assignment.incarnation() != incarnation
        || assignment.namespace_generation()
            != desired.intent().expected_namespace_generation().get()
    {
        return Err(ConsumerResourceErrorV1::Changed);
    }
    let origin = runtime_scope::current_consumer_namespace_origin(journal, &assignment)?;
    let (view_id, revision) = desired.intent().source_view();
    // The accepted revision stays fixed even after a newer View publication.
    let view = filesystem_view_state::get_revision(journal, view_id, revision)?
        .ok_or(ConsumerResourceErrorV1::Changed)?;
    let slot = attachment_slot_state::get_current(journal, desired.intent().destination_slot())?
        .ok_or(ConsumerResourceErrorV1::Changed)?;
    if slot.sandbox_spec() != binding.manifest().manifest().sandbox_spec() {
        return Err(ConsumerResourceErrorV1::Changed);
    }
    let (lease, fresh) = assignment.verified_plan_lease(journal, clock)?;
    attachment_state::validate_current_fuse_reserve_source(
        journal,
        &desired,
        fresh.wall_seconds(),
    )?;
    let source = source::ResourceSource::capture(
        &binding,
        &desired,
        &view,
        &slot,
        &origin,
        (lease.canonical_lease(), lease.canonical_signature()),
        fresh,
        assignment.deadline_boottime_nanoseconds(),
    )?;
    let sequence = journal.snapshot_sequence();
    let mut held = CurrentControllerConsumerResourceV1 {
        journal,
        assignment,
        binding,
        runtime_limits,
        desired,
        view,
        slot,
        origin,
        source,
        location,
        owner_uid,
        sequence,
        request: None,
        policy_flight_used: false,
        unavailable: false,
    };
    held.recheck(clock)?;
    Ok(held)
}

impl CurrentControllerConsumerResourceV1<'_> {
    // Consumes only availability, never creates read/Ready authority. Even an
    // unsent or denied flight cannot reconnect this same preparation/borrow.
    pub(crate) fn begin_pre_root_policy_flight<T>(
        &mut self,
        clock: &mut T,
    ) -> Result<(ProjectId, SandboxId, u64), ConsumerResourceErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.policy_flight_used {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        let selected = self.prepared_policy_selector(clock)?;
        self.policy_flight_used = true;
        Ok(selected)
    }

    // The in-memory request is assigned before planning. Only the actual
    // retained row and its live terminal reservation can select this flight.
    pub(crate) fn prepared_policy_selector<T>(
        &mut self,
        clock: &mut T,
    ) -> Result<(ProjectId, SandboxId, u64), ConsumerResourceErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.recheck(clock)?;
        let request = self.request.ok_or(ConsumerResourceErrorV1::Changed)?;
        attempt::require_retained_prepared(self.journal, request, &self.source)?;
        self.recheck(clock)?;
        let manifest = self.binding.manifest().manifest();
        Ok((manifest.project(), manifest.sandbox(), request.deadline))
    }

    /// Borrows the exact accepted Attachment desired record.
    #[must_use]
    pub const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        &self.desired
    }

    /// Borrows the original accepted immutable View revision.
    #[must_use]
    pub const fn original_view(&self) -> &DurableFilesystemViewRevisionV1 {
        &self.view
    }

    /// Borrows the Policy descriptor selected by the actual signed assignment.
    #[must_use]
    pub fn accepted_policy(&self) -> &ObjectDescriptor {
        self.binding.manifest().manifest().policy()
    }

    /// Revalidates the same named writer and complete frozen resource cut.
    ///
    /// # Errors
    ///
    /// Rejects changed desired/View/slot/allocation/binding/lease, revoked holder
    /// continuity, changed journal names or an expired original request/window.
    pub fn recheck<T>(&mut self, clock: &mut T) -> Result<(), ConsumerResourceErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.unavailable {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        self.location.recheck(self.journal, self.owner_uid)?;
        if self.sequence != self.journal.snapshot_sequence() {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        self.assignment.recheck(self.journal, clock)?;
        let current = RuntimeAuthorityStore::load(self.journal, self.runtime_limits)?
            .current(self.binding.sandbox())?;
        if current.as_ref() != Some(&self.binding) {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        if runtime_scope::current_consumer_namespace_origin(self.journal, &self.assignment)?
            != self.origin
        {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        let (lease, fresh) = self.assignment.verified_plan_lease(self.journal, clock)?;
        attachment_state::validate_current_fuse_reserve_source(
            self.journal,
            &self.desired,
            fresh.wall_seconds(),
        )?;
        attachment_slot_state::recheck_current(self.journal, &self.slot)?;
        let (view_id, revision) = self.desired.intent().source_view();
        if filesystem_view_state::get_revision(self.journal, view_id, revision)?.as_ref()
            != Some(&self.view)
            || !self.source.matches_lease(&lease)
            || self
                .request
                .is_some_and(|request| fresh.boottime_nanoseconds() >= request.deadline)
        {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        self.location.recheck(self.journal, self.owner_uid)?;
        Ok(())
    }

    /// Durably retains bounded comparison input before any later owner join.
    ///
    /// No genuine kernel-request or Ready-worker origin is claimed. The exact
    /// data and exclusive deadline become immutable, and the entire local
    /// quarantine suffix is capacity-reserved before this method returns.
    /// Repeating preparation cannot renew a deadline or create another worker.
    ///
    /// # Errors
    ///
    /// Rejects expired/substituted input, another original request, configured
    /// capacity exhaustion, changed current custody or ambiguous append.
    pub fn retain_resource_prepared<T>(
        &mut self,
        request: ConsumerReadRequestDataV1,
        limits: ConsumerResourceAttemptLimitsV1,
        clock: &mut T,
    ) -> Result<DurableConsumerResourceAttemptV1, ConsumerResourceErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.recheck(clock)?;
        if self.request.is_some_and(|original| original != request)
            || request.deadline > self.assignment.deadline_boottime_nanoseconds()
        {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        self.request = Some(request);
        self.recheck(clock)?;
        let prepared = attempt::prepare(self.journal, request, &self.source, limits)?;
        self.recheck(clock)?;
        let record = match attempt::commit(self.journal, prepared) {
            Ok(record) => record,
            Err(error) => {
                self.unavailable = true;
                return Err(error);
            }
        };
        // Only our exact append may advance the expected sequence. The full
        // resource projection is independently checked after durable readback.
        self.sequence = self.journal.snapshot_sequence();
        if let Err(error) = self.recheck(clock) {
            // An attempted append or failed readback leaves only historical
            // cleanup. This borrow can never regain preparation availability.
            self.unavailable = true;
            return Err(error);
        }
        Ok(record)
    }
}
