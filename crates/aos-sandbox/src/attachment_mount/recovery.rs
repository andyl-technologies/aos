//! Rebinds a protected pending Mount Apply from authenticated Wait evidence.
//!
//! Catalog replay reacquires the original commitment; release remains catalogless.
//! Neither path changes the durable Apply body, request identity, or deadline.

use aos_proto::aos::sandbox::local::v1::MountAction;
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};

use super::{
    AttachmentAttemptGuard, AttachmentMountError, AttachmentMountPreparationInputV1,
    DurableCurrentAttachmentMountAttemptV1, PreparedAttachmentMountDispatch,
    PreparedAttachmentMountOperation,
};
use crate::attachment_reconciliation::{
    AttachmentReconciliationActionV1, AttachmentReconciliationEvidenceV1,
    CurrentAttachmentReconciliationV1,
};
use crate::attachment_state::DurableAttachmentDesiredStateV1;
use crate::mount_preparation::{self, PreparedCurrentMountCatalogQueryV1};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::CurrentNamespaceTarget;
use crate::{
    BrokerDispatchSemanticIdentityV1, BrokerDispatchTemplateV1, Journal, SignedBrokerPlan,
};

/// Retains one exact pending attempt after reacquiring its live preparation.
pub struct PreparedCurrentAttachmentMountResumeV1 {
    evidence: AttachmentReconciliationEvidenceV1,
    record: crate::mount_attempt::Record,
    mount_action: MountAction,
    operation: PreparedAttachmentMountOperation,
}

/// Retains a Wait decision while its exact prior Mount Apply is rebound.
pub enum PreparedCurrentAttachmentMountRecoveryV1 {
    /// The original catalog must be reacquired through authenticated Mount.
    Catalog(PreparedCurrentAttachmentMountReplayCatalogQueryV1),
    /// The original release had no catalog and is ready for plan recovery.
    Release(PreparedCurrentAttachmentMountResumeV1),
}

/// Retains an authenticated catalog query and the original durable Apply record.
#[must_use = "complete the exact authenticated Mount replay catalog exchange"]
pub struct PreparedCurrentAttachmentMountReplayCatalogQueryV1 {
    evidence: AttachmentReconciliationEvidenceV1,
    record: crate::mount_attempt::Record,
    mount_action: MountAction,
    query: PreparedCurrentMountCatalogQueryV1,
}

impl PreparedCurrentAttachmentMountReplayCatalogQueryV1 {
    /// Rechecks fresh replay evidence before querying Mount's original catalog.
    ///
    /// # Errors
    ///
    /// Rejects changed desired, inventory, target, or source Host authority.
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

    /// Borrows the exact authenticated Mount catalog query.
    #[must_use]
    pub const fn query(&self) -> &PreparedCurrentMountCatalogQueryV1 {
        &self.query
    }

    /// Completes a fresh catalog query only if it reproduces the original Apply.
    ///
    /// # Errors
    ///
    /// Rejects stale reconciliation, a changed catalog, original request, or deadline.
    pub fn complete_authenticated<T>(
        self,
        journal: &mut Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        clock: &mut T,
    ) -> Result<PreparedCurrentAttachmentMountResumeV1, AttachmentMountError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let catalog = self.query.complete_authenticated(journal, outcome, clock)?;
        if Some(catalog.catalog_commitment()) != self.record.catalog_commitment()
            || catalog.body_without_deadline() != self.record.body_without_deadline()
            || self.record.deadline_boottime_nanoseconds()
                > catalog.valid_until_boottime_nanoseconds()
        {
            return Err(AttachmentMountError::NotResumable);
        }
        let prepared = PreparedCurrentAttachmentMountResumeV1 {
            evidence: self.evidence,
            record: self.record,
            mount_action: self.mount_action,
            operation: PreparedAttachmentMountOperation::Catalog(catalog),
        };
        prepared.recheck(journal, clock)?;
        Ok(prepared)
    }
}

impl PreparedCurrentAttachmentMountResumeV1 {
    /// Recovers the original signed Mount plan bytes as nonauthorizing evidence.
    ///
    /// # Errors
    ///
    /// Rejects a malformed or substituted durable Apply packet.
    pub fn original_plan_artifacts(&self) -> Result<(Vec<u8>, Vec<u8>), AttachmentMountError> {
        Ok(self.record.original_plan_artifacts()?)
    }

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

pub(crate) fn prepare_current_authenticated_recovery<T>(
    journal: &mut Journal,
    reconciliation: CurrentAttachmentReconciliationV1,
    clock: &mut T,
) -> Result<PreparedCurrentAttachmentMountRecoveryV1, AttachmentMountError>
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

    if record.catalog_commitment().is_some() {
        let query = mount_preparation::prepare_current_authenticated_replay_query(
            journal,
            target,
            record.body_without_deadline(),
            record.deadline_boottime_nanoseconds(),
            clock,
        )?;
        let recovery = PreparedCurrentAttachmentMountReplayCatalogQueryV1 {
            evidence,
            record,
            mount_action,
            query,
        };
        recovery
            .evidence
            .recheck(journal, recovery.query.target(), clock)?;
        Ok(PreparedCurrentAttachmentMountRecoveryV1::Catalog(recovery))
    } else {
        let operation = PreparedAttachmentMountOperation::Release(
            mount_preparation::prepare_current_release_replay(
                journal,
                target,
                record.body_without_deadline(),
                record.deadline_boottime_nanoseconds(),
                clock,
            )?,
        );
        let prepared = PreparedCurrentAttachmentMountResumeV1 {
            evidence,
            record,
            mount_action,
            operation,
        };
        prepared.recheck(journal, clock)?;
        Ok(PreparedCurrentAttachmentMountRecoveryV1::Release(prepared))
    }
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
    let operation = operation.bind_signed_plan(journal, signed_plan, clock)?;
    let prepared = PreparedCurrentAttachmentMountResumeDispatchV1 {
        evidence,
        record,
        mount_action,
        operation,
    };
    prepared.recheck(journal, clock)?;
    Ok(prepared)
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
        source_scope: None,
        resume_evidence: Some(evidence),
        attempt,
    };
    durable.recheck(journal, clock)?;
    Ok(durable)
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
