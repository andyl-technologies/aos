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
//! instead keeps the exact desired generation, lease state, and any LocalLive
//! source Host scope as its dispatch guard.
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
use aos_sandbox_core::model::{AttachmentConsistency, AttachmentIntent, ViewMutation};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, InvalidBrokerAuthorizationPlan,
    ProtocolId, RevocationScopeId,
};
use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, RawPairedClockSample, encode_view_source};
use aos_sandbox_protocol::{ValidatedMountInventoryRecord, ValidatedMountRecipe};

use crate::attachment_reconciliation::{
    self, AttachmentReconciliationActionV1, AttachmentReconciliationError,
    AttachmentReconciliationEvidenceV1, CurrentAttachmentReconciliationV1,
};
use crate::attachment_state::{self, AttachmentDesiredPresenceV1, DurableAttachmentDesiredStateV1};
use crate::filesystem_view_state::{
    self, FilesystemViewRevisionPresenceV1, FilesystemViewRevisionStateError,
};
use crate::mount_attempt::{
    CompletedCurrentMountAttemptV1, DurableCurrentMountAttemptV1, MountAttemptError,
    MountDispatchClient,
};
use crate::mount_preparation::{
    self, MountCatalogClient, MountCatalogIntentV1, MountCatalogPreparationError,
    PreparedCurrentMountCatalogQueryV1, PreparedCurrentMountCatalogV1,
    PreparedCurrentMountDispatchV1, PreparedCurrentMountReleaseDispatchV1,
    PreparedCurrentMountReleaseV1,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{CurrentNamespaceTarget, CurrentRuntimeScope, CurrentRuntimeScopeError};
use crate::{
    BrokerDispatchSemanticIdentityV1, BrokerDispatchTemplateV1, Journal, SignedBrokerPlan,
};

mod recovery;

pub use recovery::{
    PreparedCurrentAttachmentMountRecoveryV1, PreparedCurrentAttachmentMountReplayCatalogQueryV1,
    PreparedCurrentAttachmentMountResumeDispatchV1, PreparedCurrentAttachmentMountResumeV1,
};
pub(crate) use recovery::{
    bind_resume_signed_plan, prepare_current_authenticated_recovery, prepare_current_resume,
    resume_current,
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
    /// The exact durable view revision could not supply source authority.
    #[error(transparent)]
    FilesystemViewRevision(#[from] FilesystemViewRevisionStateError),
    /// Current Host-backed ownership authority is unavailable for a Mount plan.
    #[error(transparent)]
    Runtime(#[from] CurrentRuntimeScopeError),
    /// The exact Mount plan cannot be represented.
    #[error(transparent)]
    Plan(#[from] InvalidBrokerAuthorizationPlan),
}

/// Retains a plan-derived Mount operation until its exact signed plan is bound.
pub struct PreparedCurrentAttachmentMountV1 {
    evidence: AttachmentReconciliationEvidenceV1,
    operation: PreparedAttachmentMountOperation,
}

/// Retains exact attachment reconciliation beside a live authenticated catalog query.
#[must_use = "complete the exact authenticated Mount catalog exchange"]
pub struct PreparedCurrentAttachmentMountCatalogQueryV1 {
    evidence: AttachmentReconciliationEvidenceV1,
    query: PreparedCurrentMountCatalogQueryV1,
}

impl PreparedCurrentAttachmentMountCatalogQueryV1 {
    /// Rechecks source, desired, inventory, and target before catalog I/O.
    ///
    /// # Errors
    ///
    /// Rejects changed protected or Host authority.
    pub fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.evidence.recheck(journal, self.query.target(), clock)?;
        Ok(())
    }

    /// Borrows the exact Host-authorized Mount query for retained session custody.
    #[must_use]
    pub const fn query(&self) -> &PreparedCurrentMountCatalogQueryV1 {
        &self.query
    }

    /// Completes the authenticated catalog query under the original reconciliation.
    ///
    /// # Errors
    ///
    /// Rejects a changed desired generation, inventory, namespace, lease or
    /// authenticated response, or a catalog that expired before completion.
    pub fn complete_authenticated<T>(
        self,
        journal: &mut Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        clock: &mut T,
    ) -> Result<PreparedCurrentAttachmentMountV1, AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let catalog = self.query.complete_authenticated(journal, outcome, clock)?;
        let prepared = PreparedCurrentAttachmentMountV1 {
            evidence: self.evidence,
            operation: PreparedAttachmentMountOperation::Catalog(catalog),
        };
        prepared.recheck(journal, clock)?;
        Ok(prepared)
    }
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

    fn bind_signed_plan<T>(
        self,
        journal: &mut Journal,
        signed_plan: SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<PreparedAttachmentMountDispatch, AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        match self {
            Self::Catalog(catalog) => Ok(PreparedAttachmentMountDispatch::Catalog(
                mount_preparation::bind_signed_mount_plan(journal, catalog, signed_plan, clock)?,
            )),
            Self::Release(release) => Ok(PreparedAttachmentMountDispatch::Release(
                mount_preparation::bind_signed_mount_release_plan(
                    journal,
                    release,
                    signed_plan,
                    clock,
                )?,
            )),
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

    /// Constructs one Mount-only plan for the exact prepared Apply semantics.
    ///
    /// The independent Mount revocation scope must come from deployment
    /// credentials. This plan still requires an independent signature and
    /// exact bind before any durable attempt or broker exchange.
    ///
    /// # Errors
    ///
    /// Rejects stale reconciliation, Host or ownership authority, an expired
    /// catalog, or unrepresentable request and grant bounds.
    pub fn plan_at<T>(
        &self,
        journal: &mut Journal,
        mount_revocation_scope: RevocationScopeId,
        clock: &mut T,
    ) -> Result<BrokerAuthorizationPlan, AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.recheck(journal, clock)?;
        let scope = self.operation.target().runtime_generation().scope();
        let (lease, fresh) = scope.verified_plan_lease(journal, clock)?;
        let manifest = scope.binding().manifest().manifest();
        let request = crate::dispatch::durable_attempt_body(
            self.body_without_deadline(),
            self.valid_until_boottime_nanoseconds(),
        )
        .map_err(|_| MountAttemptError::CorruptState)?;
        let maximum_request_bytes =
            u32::try_from(request.len()).map_err(|_| MountAttemptError::Capacity)?;
        let semantics = self.semantics();
        let grant = BrokerGrant::new(
            semantics.verb(),
            semantics.target(),
            semantics.argument_commitment(),
            maximum_request_bytes,
            0,
        )?;
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            mount_preparation::MOUNT_VERSION,
            scope
                .binding()
                .manifest()
                .broker_assignment()
                .map_err(|_| MountAttemptError::CorruptState)?,
            manifest.node(),
            lease.signer().clone(),
            vec![grant],
            manifest.policy().digest(),
            mount_revocation_scope,
            fresh.wall_seconds(),
            scope.expires_wall_seconds(),
            Vec::new(),
        )?;
        self.recheck(journal, clock)?;
        Ok(plan)
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

fn recheck_present_source_scope<T>(
    journal: &mut Journal,
    guard: &AttachmentAttemptGuard,
    target: &CurrentNamespaceTarget,
    scope: &CurrentRuntimeScope,
    clock: &mut T,
) -> Result<(), AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let intent = guard.desired.intent();
    if !matches!(guard.mode, AttachmentAttemptMode::Present)
        || intent.consistency() != AttachmentConsistency::LocalLive
    {
        return Err(AttachmentReconciliationError::ActionChanged.into());
    }
    let incarnation = intent
        .source_incarnation()
        .ok_or(AttachmentReconciliationError::ActionChanged)?;
    let source = attachment_reconciliation::exact_source_handle(journal, intent)?;
    let consumer_node = target
        .runtime_generation()
        .scope()
        .binding()
        .manifest()
        .manifest()
        .node();
    scope.verify_local_live_source(journal, &source, incarnation, consumer_node, clock)?;
    Ok(())
}

/// Retains a Mount attempt whose exact Apply request was durable before I/O.
///
/// A resumed token additionally retains its authenticated pending inventory
/// evidence until dispatch. A first-issue token cannot do so because admitting
/// the new attempt intentionally makes its source inventory snapshot stale.
pub struct DurableCurrentAttachmentMountAttemptV1 {
    guard: AttachmentAttemptGuard,
    // Admission invalidates the old inventory, but cannot discard the live
    // source Host scope before a LocalLive Present Apply is sent and completed.
    source_scope: Option<CurrentRuntimeScope>,
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

    /// Rechecks desired, consumer Host, and any independent source Host scope.
    ///
    /// # Errors
    ///
    /// Rejects changed protected authority, expired live observations, a
    /// mismatched source View, or substituted durable Mount custody.
    pub fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.guard.recheck(journal, clock)?;
        if matches!(self.guard.mode, AttachmentAttemptMode::Present)
            && self.guard.desired.intent().consistency() == AttachmentConsistency::LocalLive
            && self.source_scope.is_none()
            && self
                .resume_evidence
                .as_ref()
                .and_then(AttachmentReconciliationEvidenceV1::source_scope)
                .is_none()
        {
            return Err(AttachmentReconciliationError::ActionChanged.into());
        }
        if let Some(scope) = &self.source_scope {
            recheck_present_source_scope(
                journal,
                &self.guard,
                self.attempt.target(),
                scope,
                clock,
            )?;
        }
        if let Some(evidence) = &self.resume_evidence {
            evidence.recheck(journal, self.attempt.target(), clock)?;
        }
        self.attempt.recheck(journal, clock)?;
        if let Some(evidence) = &self.resume_evidence {
            evidence.recheck(journal, self.attempt.target(), clock)?;
        }
        if let Some(scope) = &self.source_scope {
            recheck_present_source_scope(
                journal,
                &self.guard,
                self.attempt.target(),
                scope,
                clock,
            )?;
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
        journal,
        evidence.desired().intent(),
        evidence.action(),
        evidence.snapshot().inventory().mounts(),
        evidence
            .source_scope()
            .map(|scope| scope.binding().assignment_digest()),
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

/// Derives the exact catalog-backed Apply request from current reconciliation.
///
/// The request's source, recipe, destination, and consumer remain derived from
/// protected desired state and fresh authenticated Mount inventory. The caller
/// must send the returned query on the retained authenticated Mount session.
///
/// # Errors
///
/// Rejects an inapplicable action, stale evidence or target, invalid source
/// revision, failed Host authorization, or an expired session deadline.
pub fn prepare_current_authenticated_catalog_query<T>(
    journal: &mut Journal,
    reconciliation: CurrentAttachmentReconciliationV1,
    request_id: [u8; 16],
    session_deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<PreparedCurrentAttachmentMountCatalogQueryV1, AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let (evidence, target) = reconciliation.into_evidence_and_target();
    evidence.recheck(journal, &target, clock)?;
    if !matches!(
        evidence.action(),
        AttachmentReconciliationActionV1::Prepare { .. }
            | AttachmentReconciliationActionV1::Install { .. }
            | AttachmentReconciliationActionV1::Replace { .. }
            | AttachmentReconciliationActionV1::Detach { .. }
    ) {
        return Err(AttachmentMountError::NotPreparable);
    }
    let request = request_for_action(
        journal,
        evidence.desired().intent(),
        evidence.action(),
        evidence.snapshot().inventory().mounts(),
        evidence
            .source_scope()
            .map(|scope| scope.binding().assignment_digest()),
    )?;
    let intent = MountCatalogIntentV1::new(request)?;
    let query = mount_preparation::prepare_current_authenticated_query(
        journal,
        target,
        &intent,
        request_id,
        session_deadline_boottime_nanoseconds,
        clock,
    )?;
    Ok(PreparedCurrentAttachmentMountCatalogQueryV1 { evidence, query })
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
    let operation = operation.bind_signed_plan(journal, signed_plan, clock)?;
    let prepared = PreparedCurrentAttachmentMountDispatchV1 {
        evidence,
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
        evidence,
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
        source_scope: evidence.into_source_scope(),
        resume_evidence: None,
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
        source_scope,
        resume_evidence,
        attempt,
    } = attempt;
    let completion = crate::mount_attempt::dispatch_current(journal, attempt, client, clock)?;

    // Mount may have completed even if desired state changed during I/O. Its
    // receipt is already durable; withhold a live completion when the guard is stale.
    guard.recheck(journal, clock)?;
    if let Some(scope) =
        source_scope.or_else(|| resume_evidence.and_then(|evidence| evidence.into_source_scope()))
    {
        recheck_present_source_scope(
            journal,
            &guard,
            completion.attempt().target(),
            &scope,
            clock,
        )?;
    }
    Ok(CompletedCurrentAttachmentMountAttemptV1 { guard, completion })
}

pub(crate) fn complete_authenticated_current<T>(
    journal: &mut Journal,
    attempt: DurableCurrentAttachmentMountAttemptV1,
    outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    clock: &mut T,
) -> Result<CompletedCurrentAttachmentMountAttemptV1, AttachmentMountError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    attempt.recheck(journal, clock)?;
    let DurableCurrentAttachmentMountAttemptV1 {
        guard,
        source_scope,
        resume_evidence,
        attempt,
    } = attempt;
    let completion =
        crate::mount_attempt::complete_authenticated_current(journal, attempt, outcome, clock)?;

    // The signed result is durable even if desired state changed during I/O.
    guard.recheck(journal, clock)?;
    if let Some(scope) =
        source_scope.or_else(|| resume_evidence.and_then(|evidence| evidence.into_source_scope()))
    {
        recheck_present_source_scope(
            journal,
            &guard,
            completion.attempt().target(),
            &scope,
            clock,
        )?;
    }
    Ok(CompletedCurrentAttachmentMountAttemptV1 { guard, completion })
}

fn request_for_action(
    journal: &Journal,
    intent: &AttachmentIntent,
    action: AttachmentReconciliationActionV1,
    resources: &[ValidatedMountInventoryRecord],
    source_assignment: Option<ObjectDigest>,
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
        source_assignment_digest,
        source_consistency,
        source_handle,
        attributes,
    ) = if carries_recipe {
        let (source_view, source_generation) = intent.source_view();
        let durable_source =
            filesystem_view_state::get_revision(journal, source_view, source_generation)?
                .filter(|source| {
                    source.presence() == FilesystemViewRevisionPresenceV1::Available
                        && source.descriptor() == intent.view()
                })
                .ok_or(AttachmentMountError::NotPreparable)?;
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
            source_assignment.map_or_else(Vec::new, |digest| digest.as_bytes().to_vec()),
            source_consistency(intent)?,
            encode_view_source(durable_source.source_handle()),
            desired_wire_attributes(intent),
        )
    } else {
        let recipe = recipe.ok_or(AttachmentMountError::NotPreparable)?;
        let source_handle = recipe.source().source();
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
            recipe
                .source_assignment_digest()
                .map_or_else(Vec::new, |digest| digest.as_bytes().to_vec()),
            recipe.source_consistency(),
            encode_view_source(source_handle),
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
        source_assignment_digest,
        source_consistency: source_consistency.into(),
        source_handle,
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
