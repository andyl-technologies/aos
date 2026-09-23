//! Joins protected attachment intent with live namespace and Mount evidence.
//!
//! The production effect callback already owns the protected controller journal.
//! This narrow owner lets that callback reuse the attachment state machine and
//! reconciler without granting authority from public projections or durable
//! inventory alone. A mutation still requires a freshly bound namespace target;
//! reconciliation requires an authenticated current-target Mount inventory.

use aos_sandbox_core::model::{AttachmentLease, InvalidDomainModel};
use aos_sandbox_core::{
    AttachmentId, AttachmentSlotId, BrokerAuthorizationPlan, LeaseId, OperationId,
    RawPairedClockSample, RevocationScopeId,
};

use crate::attachment_mount::{
    self, AttachmentMountError, CompletedCurrentAttachmentMountAttemptV1,
    DurableCurrentAttachmentMountAttemptV1, PreparedCurrentAttachmentMountCatalogQueryV1,
    PreparedCurrentAttachmentMountDispatchV1, PreparedCurrentAttachmentMountV1,
};
use crate::attachment_reconciliation::{
    self, AttachmentReconciliationError, CurrentAttachmentReconciliationV1,
};
use crate::attachment_slot_state::{
    self, AttachmentSlotMutationV1, AttachmentSlotStateError, CommittedCurrentAttachmentSlotV1,
    DurableAttachmentSlotV1,
};
use crate::attachment_source::{
    self, AttachmentSourceBoundsV1, AttachmentSourceError, CurrentAttachmentSourcePlanV1,
};
use crate::attachment_state::{
    self, AttachmentDesiredMutationV1, AttachmentDesiredStateError,
    CommittedCurrentAttachmentDesiredStateV1, DurableAttachmentDesiredStateV1,
};
use crate::destination_slot_effect::{
    self, CompletedCurrentDestinationSlotAttemptV1, DestinationSlotEffectError,
    DurableCurrentDestinationSlotAttemptV1, PreparedCurrentDestinationSlotDispatchV1,
    PreparedCurrentDestinationSlotResumeDispatchV1, PreparedCurrentDestinationSlotResumeV1,
    PreparedCurrentDestinationSlotV1,
};
use crate::destination_slot_inventory::{
    self, CurrentDestinationSlotReconciliationV1, DestinationSlotInventoryObservationFenceV1,
    DurableDestinationSlotInventorySnapshotV1,
};
use crate::mount_attempt::{
    CurrentMountInventoryReconciliationV1, DurableMountInventorySnapshotV1, MountAttemptError,
    MountInventoryObservationFenceV1,
};
use crate::mount_observation_state::{
    CurrentMountFilesystemInventoryV1, MountFilesystemInventoryError,
};
use crate::mount_source_acquisition_inventory::{
    self, DurableMountSourceAcquisitionInventorySnapshotV1, MountSourceAcquisitionInventoryError,
    MountSourceAcquisitionInventoryObservationFenceV1,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{
    self, CurrentAssignmentTarget, CurrentNamespaceTarget, CurrentRuntimeScopeError,
    CurrentRuntimeScopePolicy, NamespaceTargetError, NamespaceTargetOutcome,
    RuntimeGenerationError, RuntimeScopeClient, RuntimeScopeHolder,
};
use crate::{Journal, JournalError, SignedBrokerPlan};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

/// Reports failure to bind a fresh Host observation to protected namespace authority.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedAttachmentTargetErrorV1 {
    /// Protected journal custody was unavailable or unhealthy.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Current holder, signed authority, or Host payload observation failed.
    #[error(transparent)]
    Runtime(#[from] CurrentRuntimeScopeError),
    /// The observed execution changed or its audit history failed.
    #[error(transparent)]
    Generation(#[from] RuntimeGenerationError),
    /// The signed namespace target changed or needs an assignment successor.
    #[error(transparent)]
    Target(#[from] NamespaceTargetError),
}

/// Reports why a live namespace target cannot issue a bounded attachment lease.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedAttachmentLeaseErrorV1 {
    /// The target no longer matches protected namespace or signed authority.
    #[error(transparent)]
    Target(#[from] NamespaceTargetError),
    /// The observation or ownership lease expired before issue.
    #[error(transparent)]
    Runtime(#[from] CurrentRuntimeScopeError),
    /// The resulting lease interval is not representable.
    #[error(transparent)]
    Model(#[from] InvalidDomainModel),
}

/// Borrows protected controller custody for one attachment effect step.
pub struct ProtectedAttachmentEffectOwnerV1<'journal> {
    journal: &'journal mut Journal,
}

impl<'journal> ProtectedAttachmentEffectOwnerV1<'journal> {
    /// Opens the attachment effect seam against protected controller custody.
    ///
    /// # Errors
    ///
    /// Rejects an unhealthy journal or one without protected-open provenance.
    pub fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        journal.ensure_protected_authority()?;
        Ok(Self { journal })
    }

    /// Issues one attachment lease within a fresh verified Host window.
    ///
    /// The current namespace target rechecks protected assignment and Host
    /// scope while the signed ownership lease supplies the exclusive expiry
    /// after clock skew and safety margin. The caller must atomically commit
    /// this lease within exact desired state;
    /// replay must reuse the committed lease, never issue a replacement.
    ///
    /// # Errors
    ///
    /// Rejects stale namespace or ownership authority, clock disagreement,
    /// expired observation, or an invalid lease interval.
    pub fn issue_current_lease<T>(
        &mut self,
        target: &CurrentNamespaceTarget,
        clock: &mut T,
    ) -> Result<AttachmentLease, ProtectedAttachmentLeaseErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        target.recheck(self.journal, clock)?;
        let scope = target.runtime_generation().scope();
        let (issued, expires) = scope.attachment_lease_bounds(self.journal, clock)?;
        let lease = AttachmentLease::new(LeaseId::new(), issued, expires)?;
        target.recheck(self.journal, clock)?;
        Ok(lease)
    }

    /// Binds a fresh authenticated Host observation to its signed namespace target.
    ///
    /// Trusted deployment supplies the holder selector, single-use Host channel,
    /// pinned verification policy, and paired clock. The journal selects and
    /// rechecks actual current authority. A returned advancement proposal is
    /// inert until a signed assignment successor is published and a new Host
    /// observation is acquired.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, missing or changed authority, a failed Host
    /// observation, invalid audit history, or stale namespace allocation.
    pub fn observe_current_target<T>(
        &mut self,
        holder: RuntimeScopeHolder,
        client: RuntimeScopeClient,
        policy: CurrentRuntimeScopePolicy,
        clock: &mut T,
    ) -> Result<NamespaceTargetOutcome, ProtectedAttachmentTargetErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        let scope =
            runtime_scope::acquire_current_runtime(self.journal, holder, client, policy, clock)?;
        let generation =
            runtime_scope::CurrentRuntimeGeneration::track(scope, self.journal, clock)?;
        Ok(CurrentNamespaceTarget::bind(
            generation,
            self.journal,
            clock,
        )?)
    }

    /// Loads the current desired generation, including a release tombstone.
    ///
    /// This is readback, not live namespace or Mount authority.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy custody and invalid attachment history.
    pub fn current(
        &self,
        attachment_id: AttachmentId,
    ) -> Result<Option<DurableAttachmentDesiredStateV1>, AttachmentDesiredStateError> {
        self.journal.ensure_protected_authority()?;
        attachment_state::get(self.journal, attachment_id)
    }

    /// Loads the exact current destination-slot binding, including a tombstone.
    ///
    /// This structural readback cannot prove a live Mount-owned descriptor.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody or invalid slot history.
    pub fn current_slot(
        &self,
        slot_id: AttachmentSlotId,
    ) -> Result<Option<DurableAttachmentSlotV1>, AttachmentSlotStateError> {
        self.journal.ensure_protected_authority()?;
        attachment_slot_state::get_current(self.journal, slot_id)
    }

    /// Commits a destination slot declared by the current signed sandbox spec.
    ///
    /// The existing slot state machine derives its binding from the fresh
    /// namespace target and compare-and-swaps the exact operation. This only
    /// records the logical slot; Mount must separately materialize and confirm
    /// its physical destination before an attachment can use it.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale target authority, undeclared slots,
    /// conflicting history, or failed durability.
    pub fn commit_current_slot<T>(
        &mut self,
        target: CurrentNamespaceTarget,
        mutation: AttachmentSlotMutationV1,
        clock: &mut T,
    ) -> Result<CommittedCurrentAttachmentSlotV1, AttachmentSlotStateError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        attachment_slot_state::commit_current(self.journal, target, mutation, clock)
    }

    /// Captures controller state before an authenticated Mount slot query.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody or invalid prior inventory.
    pub fn begin_authenticated_slot_inventory(
        &mut self,
    ) -> Result<DestinationSlotInventoryObservationFenceV1, MountAttemptError> {
        self.journal.ensure_protected_authority()?;
        destination_slot_inventory::authenticated::begin_observation(self.journal)
    }

    /// Commits a complete Mount slot inventory from a current authenticated session.
    ///
    /// The session owner must recheck terminal currentness immediately before
    /// completion. The snapshot remains nonauthorizing observation evidence.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, changed controller state, a wrong method
    /// or direction, malformed or regressing inventory, and failed durability.
    pub fn complete_authenticated_slot_inventory(
        &mut self,
        fence: DestinationSlotInventoryObservationFenceV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<DurableDestinationSlotInventorySnapshotV1, MountAttemptError> {
        self.journal.ensure_protected_authority()?;
        destination_slot_inventory::authenticated::complete_observation(
            self.journal,
            fence,
            outcome,
        )
    }

    /// Captures controller state before an authenticated Mount resource query.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody or invalid prior Mount inventory.
    pub fn begin_authenticated_mount_inventory(
        &mut self,
    ) -> Result<MountInventoryObservationFenceV1, MountAttemptError> {
        self.journal.ensure_protected_authority()?;
        crate::mount_attempt::authenticated_inventory::begin_observation(self.journal)
    }

    /// Commits a complete resource inventory from the retained Mount session.
    ///
    /// The session owner must recheck terminal currentness before completion.
    /// This is observation evidence, not an attachment-effect permit.
    ///
    /// # Errors
    ///
    /// Rejects changed controller state, malformed or regressing inventory,
    /// wrong method or direction, and failed durability.
    pub fn complete_authenticated_mount_inventory(
        &mut self,
        fence: MountInventoryObservationFenceV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<DurableMountInventorySnapshotV1, MountAttemptError> {
        self.journal.ensure_protected_authority()?;
        crate::mount_attempt::authenticated_inventory::complete_observation(
            self.journal,
            fence,
            outcome,
        )
    }

    /// Captures protected state before an authenticated Mount source query.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody or invalid prior source inventory.
    pub fn begin_authenticated_source_inventory(
        &mut self,
    ) -> Result<
        MountSourceAcquisitionInventoryObservationFenceV1,
        MountSourceAcquisitionInventoryError,
    > {
        mount_source_acquisition_inventory::authenticated::begin_observation(self.journal)
    }

    /// Commits one complete authenticated Mount source-acquisition inventory.
    ///
    /// # Errors
    ///
    /// Rejects changed protected state, wrong signed outcome, invalid or
    /// regressing source rows, and failed durability.
    pub fn complete_authenticated_source_inventory(
        &mut self,
        fence: MountSourceAcquisitionInventoryObservationFenceV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<
        DurableMountSourceAcquisitionInventorySnapshotV1,
        MountSourceAcquisitionInventoryError,
    > {
        mount_source_acquisition_inventory::authenticated::complete_observation(
            self.journal,
            fence,
            outcome,
        )
    }

    /// Joins fresh resource and source inventories at one Mount journal boundary.
    ///
    /// # Errors
    ///
    /// Rejects stale protected snapshots or any differing controller, boot,
    /// Mount process, or broker-journal identity.
    pub fn join_current_mount_filesystem_inventory(
        &mut self,
        resources: DurableMountInventorySnapshotV1,
        sources: DurableMountSourceAcquisitionInventorySnapshotV1,
    ) -> Result<CurrentMountFilesystemInventoryV1, MountFilesystemInventoryError> {
        CurrentMountFilesystemInventoryV1::join(self.journal, resources, sources)
    }

    /// Selects one nonauthorizing source-custody action from exact current state.
    ///
    /// # Errors
    ///
    /// Rejects changed desired state, stale Host or Mount observations,
    /// conflicting custody, and invalid provider bounds.
    pub fn plan_current_source<T>(
        &mut self,
        desired: DurableAttachmentDesiredStateV1,
        inventory: CurrentMountFilesystemInventoryV1,
        target: CurrentNamespaceTarget,
        bounds: AttachmentSourceBoundsV1,
        clock: &mut T,
    ) -> Result<CurrentAttachmentSourcePlanV1, AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        attachment_source::plan_current(self.journal, desired, inventory, target, bounds, clock)
    }

    /// Joins a fresh Mount resource inventory to one current namespace target.
    ///
    /// # Errors
    ///
    /// Rejects stale target, changed inventory or attempt history, or
    /// contradictory resource and controller correlation.
    pub fn reconcile_current_mount_inventory<T>(
        &mut self,
        target: CurrentNamespaceTarget,
        snapshot: DurableMountInventorySnapshotV1,
        clock: &mut T,
    ) -> Result<CurrentMountInventoryReconciliationV1, MountAttemptError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        crate::mount_attempt::reconcile_current_inventory(self.journal, target, snapshot, clock)
    }

    /// Classifies an exact current logical slot against a retained Mount query.
    ///
    /// The classification is nonauthorizing. Effect preparation must recheck
    /// the slot, inventory, and current signed assignment.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, changed slot or inventory state, invalid
    /// Mount correlation, or malformed protected history.
    pub fn reconcile_current_slot(
        &mut self,
        slot: DurableAttachmentSlotV1,
        snapshot: DurableDestinationSlotInventorySnapshotV1,
    ) -> Result<CurrentDestinationSlotReconciliationV1, MountAttemptError> {
        self.journal.ensure_protected_authority()?;
        destination_slot_inventory::reconcile_current(self.journal, slot, snapshot)
    }

    /// Prepares a signed-plan candidate for exact slot materialization or reap.
    ///
    /// The prepared request cannot be dispatched until a separately signed
    /// Mount plan is bound and a protected attempt is durably admitted.
    ///
    /// # Errors
    ///
    /// Rejects stale slot, inventory, or signed assignment authority, an
    /// action without a new effect, invalid request semantics, or expired time.
    pub fn prepare_current_slot_effect<T>(
        &mut self,
        reconciliation: CurrentDestinationSlotReconciliationV1,
        target: CurrentAssignmentTarget,
        clock: &mut T,
    ) -> Result<PreparedCurrentDestinationSlotV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::prepare_current(self.journal, reconciliation, target, clock)
    }

    /// Builds the sole Mount plan from a prepared slot request and live lease.
    ///
    /// The revocation scope must come from independently pinned Mount deployment
    /// credentials, never a public request or the Host plan. The plan still
    /// requires a signature and exact bind before an attempt may be admitted.
    ///
    /// # Errors
    ///
    /// Rejects stale assignment, slot, inventory, or ownership authority,
    /// expired time, and unrepresentable request bounds.
    pub fn current_slot_plan<T>(
        &mut self,
        prepared: &PreparedCurrentDestinationSlotV1,
        mount_revocation_scope: RevocationScopeId,
        clock: &mut T,
    ) -> Result<BrokerAuthorizationPlan, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        prepared.plan_at(self.journal, mount_revocation_scope, clock)
    }

    /// Rebinds a pending slot effect to its original protected attempt bytes.
    ///
    /// Recovery cannot substitute a newly signed plan or current inventory for
    /// the original request; the existing state machine checks every durable
    /// correlation before returning a resumable candidate.
    ///
    /// # Errors
    ///
    /// Rejects absent or changed attempts, stale slot or assignment authority,
    /// invalid original request bytes, and expired time.
    pub fn prepare_current_slot_resume<T>(
        &mut self,
        reconciliation: CurrentDestinationSlotReconciliationV1,
        target: CurrentAssignmentTarget,
        clock: &mut T,
    ) -> Result<PreparedCurrentDestinationSlotResumeV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::prepare_current_resume(self.journal, reconciliation, target, clock)
    }

    /// Binds a separately signed Mount plan to exact new slot-effect semantics.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale assignment or inventory, a plan
    /// signed outside current authority, or a grant that differs from the
    /// prepared request.
    pub fn bind_current_slot_plan<T>(
        &mut self,
        prepared: PreparedCurrentDestinationSlotV1,
        signed_plan: SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<PreparedCurrentDestinationSlotDispatchV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::bind_signed_plan(self.journal, prepared, signed_plan, clock)
    }

    /// Binds the exact original signed Mount plan to a recovered slot attempt.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale authority, or a plan whose digest or
    /// semantics differ from the original durable attempt.
    pub fn bind_current_slot_resume_plan<T>(
        &mut self,
        prepared: PreparedCurrentDestinationSlotResumeV1,
        signed_plan: SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<PreparedCurrentDestinationSlotResumeDispatchV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::bind_resume_signed_plan(self.journal, prepared, signed_plan, clock)
    }

    /// Durably admits an exact signed slot effect before any Mount I/O.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale authority, a deadline outside the
    /// retained lease, conflicting attempts, or failed durability.
    pub fn admit_current_slot_effect<T>(
        &mut self,
        prepared: PreparedCurrentDestinationSlotDispatchV1,
        deadline_boottime_nanoseconds: u64,
        clock: &mut T,
    ) -> Result<DurableCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::admit_current(
            self.journal,
            prepared,
            deadline_boottime_nanoseconds,
            clock,
        )
    }

    /// Reopens the original durable slot attempt under current authority.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale authority, a changed attempt or
    /// original plan, and an elapsed protected deadline.
    pub fn resume_current_slot_effect<T>(
        &mut self,
        prepared: PreparedCurrentDestinationSlotResumeDispatchV1,
        clock: &mut T,
    ) -> Result<DurableCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::resume_current(self.journal, prepared, clock)
    }

    /// Commits one terminal result from the retained authenticated Mount session.
    ///
    /// The session owner must recheck terminal currentness immediately before
    /// this call. Exact signed request bytes and the durable attempt are matched
    /// before the receipt is committed. A subsequent fresh authenticated slot
    /// inventory must confirm physical Ready independently.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale assignment or attempt authority,
    /// wrong method, direction or request bytes, broker failure, a mismatched
    /// receipt, or failed completion durability.
    pub fn complete_authenticated_slot_effect<T>(
        &mut self,
        attempt: DurableCurrentDestinationSlotAttemptV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        clock: &mut T,
    ) -> Result<CompletedCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::complete_authenticated_current(
            self.journal,
            attempt,
            outcome,
            clock,
        )
    }

    /// Loads the exact historical generation committed by an operation.
    ///
    /// A successor can replace the current public projection before an older
    /// operation's effect receipt is recovered. The operation index retains its
    /// original desired bytes without making them current again.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy custody and invalid attachment history.
    pub fn operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<DurableAttachmentDesiredStateV1>, AttachmentDesiredStateError> {
        self.journal.ensure_protected_authority()?;
        attachment_state::get_operation(self.journal, operation_id)
    }

    /// Commits an exact desired generation under a live namespace target.
    ///
    /// The existing state machine checks the target before and after the
    /// commit, including source revision, destination slot, and predecessor
    /// fences. A successful return records intent only; Mount remains separate.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale live authority, invalid intent or
    /// predecessors, conflicting slot or source state, and failed durability.
    pub fn commit_current<T>(
        &mut self,
        target: CurrentNamespaceTarget,
        mutation: AttachmentDesiredMutationV1,
        clock: &mut T,
    ) -> Result<CommittedCurrentAttachmentDesiredStateV1, AttachmentDesiredStateError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        attachment_state::commit_current(self.journal, target, mutation, clock)
    }

    /// Plans the next step from exact desired state and fresh Mount inventory.
    ///
    /// The result is nonauthorizing. A later broker effect must use the
    /// existing guarded Mount preparation and dispatch path.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale namespace or inventory evidence,
    /// changed desired state, invalid history, or failed clock sampling.
    pub fn reconcile_current<T>(
        &mut self,
        desired: DurableAttachmentDesiredStateV1,
        inventory: CurrentMountInventoryReconciliationV1,
        clock: &mut T,
    ) -> Result<CurrentAttachmentReconciliationV1, AttachmentReconciliationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal
            .ensure_protected_authority()
            .map_err(AttachmentDesiredStateError::from)?;
        attachment_reconciliation::reconcile_current(self.journal, desired, inventory, clock)
    }

    /// Builds an exact Host-authorized Mount catalog query from reconciliation.
    ///
    /// The returned query is not an Apply permit. Its eventual signed response
    /// must be completed against the same desired, inventory, and live target.
    ///
    /// # Errors
    ///
    /// Rejects stale protected evidence, unsupported actions, failed Host
    /// authority, invalid source revision, or an expired request deadline.
    pub fn prepare_authenticated_mount_catalog_query<T>(
        &mut self,
        reconciliation: CurrentAttachmentReconciliationV1,
        request_id: [u8; 16],
        session_deadline_boottime_nanoseconds: u64,
        clock: &mut T,
    ) -> Result<PreparedCurrentAttachmentMountCatalogQueryV1, AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        attachment_mount::prepare_current_authenticated_catalog_query(
            self.journal,
            reconciliation,
            request_id,
            session_deadline_boottime_nanoseconds,
            clock,
        )
    }

    /// Builds an independent Mount grant for an exact Host-backed Apply body.
    ///
    /// # Errors
    ///
    /// Rejects stale desired, inventory, namespace or ownership authority, an
    /// expired catalog, or unrepresentable plan bounds.
    pub fn current_mount_plan<T>(
        &mut self,
        prepared: &PreparedCurrentAttachmentMountV1,
        mount_revocation_scope: RevocationScopeId,
        clock: &mut T,
    ) -> Result<BrokerAuthorizationPlan, AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        prepared.plan_at(self.journal, mount_revocation_scope, clock)
    }

    /// Binds a separately signed Mount plan to the exact prepared Apply body.
    ///
    /// # Errors
    ///
    /// Rejects changed authority, stale reconciliation, or a mismatched plan.
    pub fn bind_current_mount_plan<T>(
        &mut self,
        prepared: PreparedCurrentAttachmentMountV1,
        signed_plan: SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<PreparedCurrentAttachmentMountDispatchV1, AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        attachment_mount::bind_signed_plan(self.journal, prepared, signed_plan, clock)
    }

    /// Durably admits the exact signed Apply packet before external I/O.
    ///
    /// # Errors
    ///
    /// Rejects stale authority, changed desired state, invalid packet bounds,
    /// conflicting attempt history, or failed protected durability.
    pub fn admit_current_mount_effect<T>(
        &mut self,
        prepared: PreparedCurrentAttachmentMountDispatchV1,
        deadline_boottime_nanoseconds: u64,
        clock: &mut T,
    ) -> Result<DurableCurrentAttachmentMountAttemptV1, AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        attachment_mount::admit_current(
            self.journal,
            prepared,
            deadline_boottime_nanoseconds,
            clock,
        )
    }

    /// Commits one exact authenticated Mount Apply success receipt.
    ///
    /// Completion does not itself prove installed presence or post-attach
    /// verification; a later fresh authenticated inventory remains mandatory.
    ///
    /// # Errors
    ///
    /// Rejects unrelated or failed signed outcomes, changed authority, invalid
    /// receipts, conflicting replay, or failed protected durability.
    pub fn complete_authenticated_mount_effect<T>(
        &mut self,
        attempt: DurableCurrentAttachmentMountAttemptV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        clock: &mut T,
    ) -> Result<CompletedCurrentAttachmentMountAttemptV1, AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        attachment_mount::complete_authenticated_current(self.journal, attempt, outcome, clock)
    }
}
