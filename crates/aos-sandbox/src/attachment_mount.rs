//! Turns one exact attachment-reconciliation decision into a Mount attempt.
//!
//! The attachment planner retains desired state, a complete authenticated
//! inventory, and live namespace authority. This module consumes that proof,
//! derives every Apply field itself, and keeps the planning inputs current
//! until the exact attempt becomes durable:
//!
//! ```text
//! current attachment reconciliation
//!     -> catalog preparation or catalogless release
//!     -> separately signed exact Mount plan
//!     -> durable-before-I/O attachment attempt or exact pending resume
//! ```
//!
//! Catalog-backed actions use Mount's descriptor acquisition path. Release is
//! deliberately catalogless because it removes only broker custody after a
//! mount is already detached or draining. Once admission writes a new attempt,
//! the old inventory snapshot is expected to become stale; the live token
//! instead keeps the exact desired generation and lease state as its dispatch
//! guard.
//!
//! Restart recovery begins only from an authenticated `Wait` decision. It
//! reacquires the original catalog commitment, re-verifies the exact signed plan
//! with a current ownership lease, and reconstructs an envelope whose Apply body
//! and deadline remain identical to the durable attempt. It cannot extend an
//! expired operation or create a replacement request under the guise of replay.

use aos_proto::aos::sandbox::local::v1::{
    ApplyMountRequest, Descriptor, MountAction, MountAttributes as WireMountAttributes,
    MountSourceConsistency,
};
use aos_sandbox_core::model::{AttachmentIntent, ViewMutation};
use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, RawPairedClockSample};
use aos_sandbox_protocol::{ValidatedMountInventoryRecord, ValidatedMountRecipe};

use crate::attachment_reconciliation::{
    AttachmentReconciliationActionV1, AttachmentReconciliationError,
    AttachmentReconciliationEvidenceV1, CurrentAttachmentReconciliationV1,
};
use crate::attachment_state::{self, AttachmentDesiredPresenceV1, DurableAttachmentDesiredStateV1};
use crate::mount_attempt::{
    CompletedCurrentMountAttemptV1, DurableCurrentMountAttemptV1, MountAttemptError,
    MountDispatchClient,
};
use crate::mount_preparation::{
    self, MountCatalogClient, MountCatalogIntentV1, MountCatalogPreparationError,
    PreparedCurrentMountCatalogV1, PreparedCurrentMountDispatchV1,
    PreparedCurrentMountReleaseDispatchV1, PreparedCurrentMountReleaseV1,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::CurrentNamespaceTarget;
use crate::{
    BrokerDispatchSemanticIdentityV1, BrokerDispatchTemplateV1, Journal, SignedBrokerPlan,
};

/// Supplies the action-specific live input needed for Mount preparation.
pub enum AttachmentMountPreparationInputV1 {
    /// Uses Mount's Host-backed descriptor catalog for create or namespace work.
    Catalog(MountCatalogClient),
    /// Prepares a release that removes broker custody without namespace access.
    Release,
}

/// Reports a stale plan, invalid action/input pairing, or Mount workflow failure.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentMountError {
    /// The retained reconciliation inputs or selected action are no longer current.
    #[error(transparent)]
    Reconciliation(#[from] AttachmentReconciliationError),
    /// The selected observation is not a Mount effect that can be prepared.
    #[error("attachment reconciliation did not select a preparable Mount action")]
    NotPreparable,
    /// The selected observation is not one exact pending Mount attempt.
    #[error("attachment reconciliation did not select a resumable Mount attempt")]
    NotResumable,
    /// The caller supplied a catalog channel for release or omitted it otherwise.
    #[error("attachment Mount action and preparation input do not match")]
    PreparationInputMismatch,
    /// Catalog acquisition, plan binding, or live-target validation failed.
    #[error(transparent)]
    Preparation(#[from] MountCatalogPreparationError),
    /// Durable admission, authenticated dispatch, or receipt recording failed.
    #[error(transparent)]
    Attempt(#[from] MountAttemptError),
}

/// Retains a plan-derived Mount operation until its exact signed plan is bound.
pub struct PreparedCurrentAttachmentMountV1 {
    evidence: AttachmentReconciliationEvidenceV1,
    operation: PreparedAttachmentMountOperation,
}

enum PreparedAttachmentMountOperation {
    Catalog(PreparedCurrentMountCatalogV1),
    Release(PreparedCurrentMountReleaseV1),
}

impl PreparedAttachmentMountOperation {
    fn target(&self) -> &CurrentNamespaceTarget {
        match self {
            Self::Catalog(prepared) => prepared.target(),
            Self::Release(prepared) => prepared.target(),
        }
    }

    fn catalog_commitment(&self) -> Option<ObjectDigest> {
        match self {
            Self::Catalog(prepared) => Some(prepared.catalog_commitment()),
            Self::Release(_) => None,
        }
    }

    fn valid_until_boottime_nanoseconds(&self) -> u64 {
        match self {
            Self::Catalog(prepared) => prepared.valid_until_boottime_nanoseconds(),
            Self::Release(prepared) => prepared.valid_until_boottime_nanoseconds(),
        }
    }

    fn body_without_deadline(&self) -> &[u8] {
        match self {
            Self::Catalog(prepared) => prepared.body_without_deadline(),
            Self::Release(prepared) => prepared.body_without_deadline(),
        }
    }

    fn semantics(&self) -> BrokerDispatchSemanticIdentityV1 {
        match self {
            Self::Catalog(prepared) => prepared.semantics(),
            Self::Release(prepared) => prepared.semantics(),
        }
    }

    fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), MountCatalogPreparationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        match self {
            Self::Catalog(prepared) => prepared.recheck(journal, clock),
            Self::Release(prepared) => prepared.recheck(journal, clock),
        }
    }
}

impl PreparedCurrentAttachmentMountV1 {
    /// Borrows the exact desired generation from which the request was derived.
    #[must_use]
    pub const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        self.evidence.desired()
    }

    /// Returns the exact closed reconciliation action being prepared.
    #[must_use]
    pub const fn action(&self) -> AttachmentReconciliationActionV1 {
        self.evidence.action()
    }

    /// Returns the opaque catalog commitment, absent only for release.
    #[must_use]
    pub fn catalog_commitment(&self) -> Option<ObjectDigest> {
        self.operation.catalog_commitment()
    }

    /// Returns the exact portable identity that a signed Mount grant must match.
    #[must_use]
    pub fn semantics(&self) -> BrokerDispatchSemanticIdentityV1 {
        self.operation.semantics()
    }

    /// Returns the exclusive lifetime inherited from current live authority.
    #[must_use]
    pub fn valid_until_boottime_nanoseconds(&self) -> u64 {
        self.operation.valid_until_boottime_nanoseconds()
    }

    /// Borrows the exact deadline-free Apply body used by signed-plan binding.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        self.operation.body_without_deadline()
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.evidence
            .recheck(journal, self.operation.target(), clock)?;
        self.operation.recheck(journal, clock)?;
        self.evidence
            .recheck(journal, self.operation.target(), clock)?;
        Ok(())
    }
}

/// Retains a plan-derived operation and its separately verified signed plan.
pub struct PreparedCurrentAttachmentMountDispatchV1 {
    evidence: AttachmentReconciliationEvidenceV1,
    operation: PreparedAttachmentMountDispatch,
}

enum PreparedAttachmentMountDispatch {
    Catalog(PreparedCurrentMountDispatchV1),
    Release(PreparedCurrentMountReleaseDispatchV1),
}

impl PreparedAttachmentMountDispatch {
    fn target(&self) -> &CurrentNamespaceTarget {
        match self {
            Self::Catalog(prepared) => prepared.catalog().target(),
            Self::Release(prepared) => prepared.release().target(),
        }
    }

    fn template(&self) -> &BrokerDispatchTemplateV1 {
        match self {
            Self::Catalog(prepared) => prepared.template(),
            Self::Release(prepared) => prepared.template(),
        }
    }

    fn catalog_commitment(&self) -> Option<ObjectDigest> {
        match self {
            Self::Catalog(prepared) => Some(prepared.catalog().catalog_commitment()),
            Self::Release(_) => None,
        }
    }

    fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), MountCatalogPreparationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        match self {
            Self::Catalog(prepared) => prepared.recheck(journal, clock),
            Self::Release(prepared) => prepared.recheck(journal, clock),
        }
    }
}

impl PreparedCurrentAttachmentMountDispatchV1 {
    /// Borrows the exact desired generation retained through plan binding.
    #[must_use]
    pub const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        self.evidence.desired()
    }

    /// Returns the exact reconciliation action bound into the signed plan.
    #[must_use]
    pub const fn action(&self) -> AttachmentReconciliationActionV1 {
        self.evidence.action()
    }

    /// Borrows the verified deadline-free dispatch template.
    #[must_use]
    pub fn template(&self) -> &BrokerDispatchTemplateV1 {
        self.operation.template()
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.evidence
            .recheck(journal, self.operation.target(), clock)?;
        self.operation.recheck(journal, clock)?;
        self.evidence
            .recheck(journal, self.operation.target(), clock)?;
        Ok(())
    }
}

/// Retains one exact pending attempt after reacquiring its live preparation.
pub struct PreparedCurrentAttachmentMountResumeV1 {
    evidence: AttachmentReconciliationEvidenceV1,
    record: crate::mount_attempt::Record,
    mount_action: MountAction,
    operation: PreparedAttachmentMountOperation,
}

impl PreparedCurrentAttachmentMountResumeV1 {
    /// Borrows the current desired generation guarding the pending operation.
    #[must_use]
    pub const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        self.evidence.desired()
    }

    /// Returns the exact durable request identity selected for resumption.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id()
    }

    /// Returns the original Mount action whose durable intent remains pending.
    #[must_use]
    pub const fn mount_action(&self) -> MountAction {
        self.mount_action
    }

    /// Returns the reacquired catalog commitment, absent only for release.
    #[must_use]
    pub fn catalog_commitment(&self) -> Option<ObjectDigest> {
        self.operation.catalog_commitment()
    }

    /// Returns the exact portable identity the reproduced signed plan must grant.
    #[must_use]
    pub fn semantics(&self) -> BrokerDispatchSemanticIdentityV1 {
        self.operation.semantics()
    }

    /// Returns the exact original broker plan the caller must reproduce.
    #[must_use]
    pub const fn broker_plan_digest(&self) -> ObjectDigest {
        self.record.plan_digest()
    }

    /// Returns the original exclusive deadline, which resumption cannot extend.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.record.deadline_boottime_nanoseconds()
    }

    /// Borrows the original deadline-free Apply body byte for byte.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        self.record.body_without_deadline()
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.evidence
            .recheck(journal, self.operation.target(), clock)?;
        recheck_resume_record(
            journal,
            &self.evidence,
            self.operation.target(),
            &self.record,
            self.mount_action,
            self.operation.catalog_commitment(),
            self.operation.body_without_deadline(),
        )?;
        self.operation.recheck(journal, clock)?;
        self.evidence
            .recheck(journal, self.operation.target(), clock)?;
        Ok(())
    }
}

/// Retains a pending attempt and its reverified exact signed plan.
pub struct PreparedCurrentAttachmentMountResumeDispatchV1 {
    evidence: AttachmentReconciliationEvidenceV1,
    record: crate::mount_attempt::Record,
    mount_action: MountAction,
    operation: PreparedAttachmentMountDispatch,
}

impl PreparedCurrentAttachmentMountResumeDispatchV1 {
    /// Borrows the current desired generation guarding resumed dispatch.
    #[must_use]
    pub const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        self.evidence.desired()
    }

    /// Returns the original Mount request identity retained by the broker.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id()
    }

    /// Returns the original Mount action whose durable intent remains pending.
    #[must_use]
    pub const fn mount_action(&self) -> MountAction {
        self.mount_action
    }

    /// Borrows the exact original signed template with the original Apply body.
    #[must_use]
    pub fn template(&self) -> &BrokerDispatchTemplateV1 {
        self.operation.template()
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.evidence
            .recheck(journal, self.operation.target(), clock)?;
        recheck_resume_record(
            journal,
            &self.evidence,
            self.operation.target(),
            &self.record,
            self.mount_action,
            self.operation.catalog_commitment(),
            self.operation.template().body_without_deadline(),
        )?;
        if !self
            .record
            .matches_resume_template(self.operation.template())
        {
            return Err(AttachmentMountError::NotResumable);
        }
        self.operation.recheck(journal, clock)?;
        self.evidence
            .recheck(journal, self.operation.target(), clock)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum AttachmentAttemptMode {
    Present,
    Drain,
}

struct AttachmentAttemptGuard {
    desired: DurableAttachmentDesiredStateV1,
    action: AttachmentReconciliationActionV1,
    mount_action: MountAction,
    mode: AttachmentAttemptMode,
}

impl AttachmentAttemptGuard {
    fn new(
        desired: DurableAttachmentDesiredStateV1,
        action: AttachmentReconciliationActionV1,
    ) -> Result<Self, AttachmentMountError> {
        let (mode, mount_action) = match action {
            AttachmentReconciliationActionV1::Prepare { .. } => (
                AttachmentAttemptMode::Present,
                MountAction::MOUNT_ACTION_CREATE_DETACHED,
            ),
            AttachmentReconciliationActionV1::Install { .. } => (
                AttachmentAttemptMode::Present,
                MountAction::MOUNT_ACTION_INSTALL,
            ),
            AttachmentReconciliationActionV1::Replace { .. } => (
                AttachmentAttemptMode::Present,
                MountAction::MOUNT_ACTION_REPLACE,
            ),
            AttachmentReconciliationActionV1::Detach { .. } => (
                AttachmentAttemptMode::Drain,
                MountAction::MOUNT_ACTION_DETACH,
            ),
            AttachmentReconciliationActionV1::Release { .. } => (
                AttachmentAttemptMode::Drain,
                MountAction::MOUNT_ACTION_RELEASE,
            ),
            _ => return Err(AttachmentMountError::NotPreparable),
        };
        Ok(Self {
            desired,
            action,
            mount_action,
            mode,
        })
    }

    fn new_resume(
        desired: DurableAttachmentDesiredStateV1,
        action: AttachmentReconciliationActionV1,
        mount_action: MountAction,
    ) -> Result<Self, AttachmentMountError> {
        if !matches!(action, AttachmentReconciliationActionV1::Wait { .. }) {
            return Err(AttachmentMountError::NotResumable);
        }
        let mode = match mount_action {
            MountAction::MOUNT_ACTION_CREATE_DETACHED
            | MountAction::MOUNT_ACTION_INSTALL
            | MountAction::MOUNT_ACTION_REPLACE => AttachmentAttemptMode::Present,
            MountAction::MOUNT_ACTION_DETACH | MountAction::MOUNT_ACTION_RELEASE => {
                AttachmentAttemptMode::Drain
            }
            MountAction::MOUNT_ACTION_UNSPECIFIED => {
                return Err(AttachmentMountError::NotResumable);
            }
        };
        Ok(Self {
            desired,
            action,
            mount_action,
            mode,
        })
    }

    fn recheck<T>(&self, journal: &mut Journal, clock: &mut T) -> Result<(), AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        attachment_state::recheck_current(journal, &self.desired)
            .map_err(AttachmentReconciliationError::from)?;
        let now_seconds = clock()
            .map_err(AttachmentReconciliationError::from)?
            .wall_seconds();
        let lease = self.desired.intent().lease();
        let present = self.desired.presence() == AttachmentDesiredPresenceV1::Present;
        let valid = match self.mode {
            AttachmentAttemptMode::Present => {
                present
                    && now_seconds >= lease.issued_seconds()
                    && now_seconds < lease.expires_seconds()
            }
            AttachmentAttemptMode::Drain => !present || now_seconds >= lease.expires_seconds(),
        };
        if !valid {
            return Err(AttachmentReconciliationError::ActionChanged.into());
        }
        attachment_state::recheck_current(journal, &self.desired)
            .map_err(AttachmentReconciliationError::from)?;
        Ok(())
    }
}

/// Retains a Mount attempt whose exact Apply request was durable before I/O.
///
/// A resumed token additionally retains its authenticated pending inventory
/// evidence until dispatch. A first-issue token cannot do so because admitting
/// the new attempt intentionally makes its source inventory snapshot stale.
pub struct DurableCurrentAttachmentMountAttemptV1 {
    guard: AttachmentAttemptGuard,
    resume_evidence: Option<AttachmentReconciliationEvidenceV1>,
    attempt: DurableCurrentMountAttemptV1,
}

impl DurableCurrentAttachmentMountAttemptV1 {
    /// Borrows the current desired generation guarding dispatch.
    #[must_use]
    pub const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        &self.guard.desired
    }

    /// Returns the exact reconciler-selected action admitted for dispatch.
    #[must_use]
    pub const fn action(&self) -> AttachmentReconciliationActionV1 {
        self.guard.action
    }

    /// Returns the exact Mount effect issued or resumed by this token.
    #[must_use]
    pub const fn mount_action(&self) -> MountAction {
        self.guard.mount_action
    }

    /// Borrows the durable-before-I/O lower-level Mount attempt.
    #[must_use]
    pub const fn attempt(&self) -> &DurableCurrentMountAttemptV1 {
        &self.attempt
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.guard.recheck(journal, clock)?;
        if let Some(evidence) = &self.resume_evidence {
            evidence.recheck(journal, self.attempt.target(), clock)?;
        }
        self.attempt.recheck(journal, clock)?;
        if let Some(evidence) = &self.resume_evidence {
            evidence.recheck(journal, self.attempt.target(), clock)?;
        }
        self.guard.recheck(journal, clock)
    }
}

/// Retains a successful exact attachment Mount result after durable recording.
pub struct CompletedCurrentAttachmentMountAttemptV1 {
    guard: AttachmentAttemptGuard,
    completion: CompletedCurrentMountAttemptV1,
}

impl CompletedCurrentAttachmentMountAttemptV1 {
    /// Borrows the desired generation that authorized this completed effect.
    #[must_use]
    pub const fn desired(&self) -> &DurableAttachmentDesiredStateV1 {
        &self.guard.desired
    }

    /// Returns the exact reconciler-selected action completed by Mount.
    #[must_use]
    pub const fn action(&self) -> AttachmentReconciliationActionV1 {
        self.guard.action
    }

    /// Returns the exact Mount effect proven by the successful receipt.
    #[must_use]
    pub const fn mount_action(&self) -> MountAction {
        self.guard.mount_action
    }

    /// Borrows the exact durable Mount completion and validated result.
    #[must_use]
    pub const fn completion(&self) -> &CompletedCurrentMountAttemptV1 {
        &self.completion
    }
}

pub(crate) fn prepare_current<T>(
    journal: &mut Journal,
    reconciliation: CurrentAttachmentReconciliationV1,
    input: AttachmentMountPreparationInputV1,
    clock: &mut T,
) -> Result<PreparedCurrentAttachmentMountV1, AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let (evidence, target) = reconciliation.into_evidence_and_target();
    evidence.recheck(journal, &target, clock)?;
    let request = request_for_action(
        evidence.desired().intent(),
        evidence.action(),
        evidence.snapshot().inventory().mounts(),
    )?;

    let operation = match (evidence.action(), input) {
        (
            AttachmentReconciliationActionV1::Prepare { .. }
            | AttachmentReconciliationActionV1::Install { .. }
            | AttachmentReconciliationActionV1::Replace { .. }
            | AttachmentReconciliationActionV1::Detach { .. },
            AttachmentMountPreparationInputV1::Catalog(client),
        ) => {
            let intent = MountCatalogIntentV1::new(request)?;
            PreparedAttachmentMountOperation::Catalog(mount_preparation::prepare_current(
                journal, target, &intent, client, clock,
            )?)
        }
        (
            AttachmentReconciliationActionV1::Release { .. },
            AttachmentMountPreparationInputV1::Release,
        ) => PreparedAttachmentMountOperation::Release(mount_preparation::prepare_current_release(
            journal, target, request, clock,
        )?),
        (
            AttachmentReconciliationActionV1::Prepare { .. }
            | AttachmentReconciliationActionV1::Install { .. }
            | AttachmentReconciliationActionV1::Replace { .. }
            | AttachmentReconciliationActionV1::Detach { .. }
            | AttachmentReconciliationActionV1::Release { .. },
            _,
        ) => return Err(AttachmentMountError::PreparationInputMismatch),
        _ => return Err(AttachmentMountError::NotPreparable),
    };

    let prepared = PreparedCurrentAttachmentMountV1 {
        evidence,
        operation,
    };
    prepared.recheck(journal, clock)?;
    Ok(prepared)
}

pub(crate) fn prepare_current_resume<T>(
    journal: &mut Journal,
    reconciliation: CurrentAttachmentReconciliationV1,
    input: AttachmentMountPreparationInputV1,
    clock: &mut T,
) -> Result<PreparedCurrentAttachmentMountResumeV1, AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let (evidence, target) = reconciliation.into_evidence_and_target();
    evidence.recheck(journal, &target, clock)?;
    let (request_id, expected_mount_handle) = wait_identity(evidence.action())?;
    let record = crate::mount_attempt::replay_record(journal, request_id, &target)?;
    let mount_action = record.action()?;
    if record.mount_handle()? != expected_mount_handle {
        return Err(AttachmentMountError::NotResumable);
    }

    let operation = match (record.catalog_commitment(), input) {
        (Some(expected_catalog), AttachmentMountPreparationInputV1::Catalog(client)) => {
            PreparedAttachmentMountOperation::Catalog(mount_preparation::prepare_current_replay(
                journal,
                target,
                record.body_without_deadline(),
                record.deadline_boottime_nanoseconds(),
                expected_catalog,
                client,
                clock,
            )?)
        }
        (None, AttachmentMountPreparationInputV1::Release) => {
            PreparedAttachmentMountOperation::Release(
                mount_preparation::prepare_current_release_replay(
                    journal,
                    target,
                    record.body_without_deadline(),
                    record.deadline_boottime_nanoseconds(),
                    clock,
                )?,
            )
        }
        _ => return Err(AttachmentMountError::PreparationInputMismatch),
    };

    let prepared = PreparedCurrentAttachmentMountResumeV1 {
        evidence,
        record,
        mount_action,
        operation,
    };
    prepared.recheck(journal, clock)?;
    Ok(prepared)
}

pub(crate) fn bind_signed_plan<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentAttachmentMountV1,
    signed_plan: SignedBrokerPlan,
    clock: &mut T,
) -> Result<PreparedCurrentAttachmentMountDispatchV1, AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    let PreparedCurrentAttachmentMountV1 {
        evidence,
        operation,
    } = prepared;
    let operation = match operation {
        PreparedAttachmentMountOperation::Catalog(catalog) => {
            PreparedAttachmentMountDispatch::Catalog(mount_preparation::bind_signed_mount_plan(
                journal,
                catalog,
                signed_plan,
                clock,
            )?)
        }
        PreparedAttachmentMountOperation::Release(release) => {
            PreparedAttachmentMountDispatch::Release(
                mount_preparation::bind_signed_mount_release_plan(
                    journal,
                    release,
                    signed_plan,
                    clock,
                )?,
            )
        }
    };
    let prepared = PreparedCurrentAttachmentMountDispatchV1 {
        evidence,
        operation,
    };
    prepared.recheck(journal, clock)?;
    Ok(prepared)
}

pub(crate) fn bind_resume_signed_plan<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentAttachmentMountResumeV1,
    signed_plan: SignedBrokerPlan,
    clock: &mut T,
) -> Result<PreparedCurrentAttachmentMountResumeDispatchV1, AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    let PreparedCurrentAttachmentMountResumeV1 {
        evidence,
        record,
        mount_action,
        operation,
    } = prepared;
    let operation = match operation {
        PreparedAttachmentMountOperation::Catalog(catalog) => {
            PreparedAttachmentMountDispatch::Catalog(mount_preparation::bind_signed_mount_plan(
                journal,
                catalog,
                signed_plan,
                clock,
            )?)
        }
        PreparedAttachmentMountOperation::Release(release) => {
            PreparedAttachmentMountDispatch::Release(
                mount_preparation::bind_signed_mount_release_plan(
                    journal,
                    release,
                    signed_plan,
                    clock,
                )?,
            )
        }
    };
    let prepared = PreparedCurrentAttachmentMountResumeDispatchV1 {
        evidence,
        record,
        mount_action,
        operation,
    };
    prepared.recheck(journal, clock)?;
    Ok(prepared)
}

pub(crate) fn admit_current<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentAttachmentMountDispatchV1,
    deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<DurableCurrentAttachmentMountAttemptV1, AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    let guard = AttachmentAttemptGuard::new(
        prepared.evidence.desired().clone(),
        prepared.evidence.action(),
    )?;
    guard.recheck(journal, clock)?;
    let PreparedCurrentAttachmentMountDispatchV1 {
        evidence: _,
        operation,
    } = prepared;
    let attempt = match operation {
        PreparedAttachmentMountDispatch::Catalog(prepared) => crate::mount_attempt::admit_current(
            journal,
            prepared,
            deadline_boottime_nanoseconds,
            clock,
        )?,
        PreparedAttachmentMountDispatch::Release(prepared) => {
            crate::mount_attempt::admit_current_release(
                journal,
                prepared,
                deadline_boottime_nanoseconds,
                clock,
            )?
        }
    };

    // Admission intentionally invalidates the inventory snapshot it postdates.
    // The desired generation and live target remain mandatory dispatch guards.
    guard.recheck(journal, clock)?;
    let durable = DurableCurrentAttachmentMountAttemptV1 {
        guard,
        resume_evidence: None,
        attempt,
    };
    durable.recheck(journal, clock)?;
    Ok(durable)
}

pub(crate) fn resume_current<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentAttachmentMountResumeDispatchV1,
    clock: &mut T,
) -> Result<DurableCurrentAttachmentMountAttemptV1, AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    let guard = AttachmentAttemptGuard::new_resume(
        prepared.evidence.desired().clone(),
        prepared.evidence.action(),
        prepared.mount_action,
    )?;
    guard.recheck(journal, clock)?;
    let PreparedCurrentAttachmentMountResumeDispatchV1 {
        evidence,
        record,
        mount_action: _,
        operation,
    } = prepared;
    let attempt = match operation {
        PreparedAttachmentMountDispatch::Catalog(prepared) => {
            crate::mount_attempt::resume_current(journal, record, prepared, clock)?
        }
        PreparedAttachmentMountDispatch::Release(prepared) => {
            crate::mount_attempt::resume_current_release(journal, record, prepared, clock)?
        }
    };

    guard.recheck(journal, clock)?;
    let durable = DurableCurrentAttachmentMountAttemptV1 {
        guard,
        resume_evidence: Some(evidence),
        attempt,
    };
    durable.recheck(journal, clock)?;
    Ok(durable)
}

pub(crate) fn dispatch_current<T>(
    journal: &mut Journal,
    attempt: DurableCurrentAttachmentMountAttemptV1,
    client: MountDispatchClient,
    clock: &mut T,
) -> Result<CompletedCurrentAttachmentMountAttemptV1, AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    attempt.recheck(journal, clock)?;
    let DurableCurrentAttachmentMountAttemptV1 {
        guard,
        resume_evidence: _,
        attempt,
    } = attempt;
    let completion = crate::mount_attempt::dispatch_current(journal, attempt, client, clock)?;

    // Mount may have completed even if desired state changed during I/O. Its
    // receipt is already durable; withhold a live completion when the guard is stale.
    guard.recheck(journal, clock)?;
    Ok(CompletedCurrentAttachmentMountAttemptV1 { guard, completion })
}

fn wait_identity(
    action: AttachmentReconciliationActionV1,
) -> Result<([u8; 16], [u8; 32]), AttachmentMountError> {
    match action {
        AttachmentReconciliationActionV1::Wait {
            request_id,
            mount_handle,
            ..
        } => Ok((request_id, mount_handle)),
        _ => Err(AttachmentMountError::NotResumable),
    }
}

fn recheck_resume_record(
    journal: &mut Journal,
    evidence: &AttachmentReconciliationEvidenceV1,
    target: &CurrentNamespaceTarget,
    record: &crate::mount_attempt::Record,
    mount_action: MountAction,
    catalog_commitment: Option<ObjectDigest>,
    body_without_deadline: &[u8],
) -> Result<(), AttachmentMountError> {
    let (request_id, mount_handle) = wait_identity(evidence.action())?;
    let current = crate::mount_attempt::replay_record(journal, request_id, target)?;
    if &current != record
        || record.namespace_target() != target.durable_reference()
        || record.mount_handle()? != mount_handle
        || record.action()? != mount_action
        || record.catalog_commitment() != catalog_commitment
        || record.body_without_deadline() != body_without_deadline
    {
        return Err(AttachmentMountError::NotResumable);
    }
    Ok(())
}

fn request_for_action(
    intent: &AttachmentIntent,
    action: AttachmentReconciliationActionV1,
    resources: &[ValidatedMountInventoryRecord],
) -> Result<ApplyMountRequest, AttachmentMountError> {
    let (mount_action, resource, detached_mount_handle, replacement_mount_handle) = match action {
        AttachmentReconciliationActionV1::Prepare { .. } => (
            MountAction::MOUNT_ACTION_CREATE_DETACHED,
            None,
            Vec::new(),
            Vec::new(),
        ),
        AttachmentReconciliationActionV1::Install { mount_handle } => (
            MountAction::MOUNT_ACTION_INSTALL,
            Some(resource(resources, mount_handle)?),
            mount_handle.to_vec(),
            Vec::new(),
        ),
        AttachmentReconciliationActionV1::Replace {
            mount_handle,
            replacement_mount_handle,
        } => (
            MountAction::MOUNT_ACTION_REPLACE,
            Some(resource(resources, mount_handle)?),
            mount_handle.to_vec(),
            replacement_mount_handle.to_vec(),
        ),
        AttachmentReconciliationActionV1::Detach { mount_handle } => (
            MountAction::MOUNT_ACTION_DETACH,
            Some(resource(resources, mount_handle)?),
            mount_handle.to_vec(),
            Vec::new(),
        ),
        AttachmentReconciliationActionV1::Release { mount_handle } => (
            MountAction::MOUNT_ACTION_RELEASE,
            Some(resource(resources, mount_handle)?),
            mount_handle.to_vec(),
            Vec::new(),
        ),
        _ => return Err(AttachmentMountError::NotPreparable),
    };
    let carries_recipe = mount_action == MountAction::MOUNT_ACTION_CREATE_DETACHED;
    let carries_view = matches!(
        mount_action,
        MountAction::MOUNT_ACTION_CREATE_DETACHED
            | MountAction::MOUNT_ACTION_INSTALL
            | MountAction::MOUNT_ACTION_REPLACE
    );
    let recipe = resource.map(ValidatedMountInventoryRecord::recipe);
    let lease = intent.lease();
    let desired_generation = intent.desired_generation().get();

    let (
        attachment_id,
        destination_slot_id,
        view_revision,
        source_generation,
        resource_generation,
        source_view_id,
        source_incarnation_id,
        source_consistency,
        attributes,
    ) = if carries_recipe {
        let (source_view, source_generation) = intent.source_view();
        (
            intent.id().as_bytes().to_vec(),
            intent.destination_slot().as_bytes().to_vec(),
            descriptor(intent.view()),
            source_generation.get(),
            desired_generation,
            source_view.as_bytes().to_vec(),
            intent
                .source_incarnation()
                .map_or_else(Vec::new, |value| value.as_bytes().to_vec()),
            source_consistency(intent)?,
            desired_wire_attributes(intent),
        )
    } else {
        let recipe = recipe.ok_or(AttachmentMountError::NotPreparable)?;
        (
            recipe.attachment_id().to_vec(),
            recipe.destination_slot_id().to_vec(),
            descriptor(recipe.view_revision()),
            recipe.source_generation(),
            recipe.resource_attachment_generation(),
            recipe.source_view_id().to_vec(),
            recipe
                .source_incarnation_id()
                .map_or_else(Vec::new, |value| value.to_vec()),
            recipe.source_consistency(),
            inventoried_wire_attributes(recipe),
        )
    };

    Ok(ApplyMountRequest {
        action: mount_action.into(),
        attachment_id,
        destination_slot_id,
        view_revision: carries_view.then_some(view_revision).into(),
        detached_mount_handle,
        replacement_mount_handle,
        attributes: carries_view.then_some(attributes).into(),
        source_generation,
        desired_attachment_generation: desired_generation,
        resource_attachment_generation: resource_generation,
        source_view_id,
        source_incarnation_id,
        source_consistency: source_consistency.into(),
        attachment_lease_id: lease.id().as_bytes().to_vec(),
        attachment_lease_issued_seconds: lease.issued_seconds(),
        attachment_lease_expires_seconds: lease.expires_seconds(),
        ..Default::default()
    })
}

fn resource(
    resources: &[ValidatedMountInventoryRecord],
    handle: [u8; 32],
) -> Result<&ValidatedMountInventoryRecord, AttachmentMountError> {
    resources
        .iter()
        .find(|resource| resource.mount_handle() == &handle)
        .ok_or(AttachmentReconciliationError::ActionChanged.into())
}

fn descriptor(value: &ObjectDescriptor) -> Descriptor {
    Descriptor {
        media_type: value.media_type().as_str().to_owned(),
        sha256: value.digest().as_bytes().to_vec(),
        encoded_size: value.encoded_size(),
        ..Default::default()
    }
}

fn desired_wire_attributes(intent: &AttachmentIntent) -> WireMountAttributes {
    let attributes = intent.mount_attributes();

    WireMountAttributes {
        read_only: attributes.read_only(),
        no_exec: attributes.no_exec(),
        no_suid: attributes.no_suid(),
        no_device: attributes.no_dev(),
        no_atime: attributes.no_atime(),
        recursive: attributes.recursive(),
        mutation_mode: mutation_mode(intent.mutation()),
        ..Default::default()
    }
}

fn inventoried_wire_attributes(recipe: &ValidatedMountRecipe) -> WireMountAttributes {
    let attributes = recipe.attributes();

    WireMountAttributes {
        read_only: attributes.read_only(),
        no_exec: attributes.no_exec(),
        no_suid: attributes.no_suid(),
        no_device: attributes.no_device(),
        no_atime: attributes.no_atime(),
        recursive: attributes.recursive(),
        mutation_mode: attributes.mutation_mode(),
        ..Default::default()
    }
}

fn source_consistency(
    intent: &AttachmentIntent,
) -> Result<MountSourceConsistency, AttachmentMountError> {
    match intent.consistency() {
        aos_sandbox_core::model::AttachmentConsistency::ImmutableRevision => {
            Ok(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION)
        }
        aos_sandbox_core::model::AttachmentConsistency::LocalLive => {
            Ok(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE)
        }
        aos_sandbox_core::model::AttachmentConsistency::BestEffortReplica => {
            Ok(MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA)
        }
        aos_sandbox_core::model::AttachmentConsistency::TransactionalService => {
            Err(AttachmentMountError::NotPreparable)
        }
    }
}

const fn mutation_mode(value: ViewMutation) -> u32 {
    match value {
        ViewMutation::ReadOnly => 0,
        ViewMutation::ReadWrite => 1,
        ViewMutation::PrivateCow => 2,
        ViewMutation::AppendOnly => 3,
        ViewMutation::Service => 4,
    }
}

#[cfg(test)]
mod tests;
