//! Prearms and retains the exact newly authorized metadata-only Controller CAS.
//!
//! A private paid association connects the same active Recover original to its
//! real Root socket owner. The actual joint transaction is constructed only
//! from current protected rows and that completed owner's actual Root sample.
//! All models and native results remain here through independent outer posts.

use super::*;
use std::mem::size_of;

use crate::journal::{
    CommitResult, CreateStoppedMetadataTransitionOriginalV1, JournalError, JournalTransaction,
    RecordNamespace,
};
use crate::normal_root::RootFinalityRecoverClientOriginalV1 as RootClient;
use aos_sandbox_protocol::domain_ledger::{
    effect_history::{
        CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1, EffectHistoryDataError, EffectLedgerRecord,
        EffectState, decode_effect,
    },
    operation::{decode_operation, effect_key},
    provisioning_root::finality_recover::{
        CreateFinalityObservationAdmissionDataV1 as Admission, FinalityRecoverQueryDataV1 as Query,
        finality_admission_commitment_v1, finality_controller_transaction_commitment_v1,
        public_operation::{
            metadata_complete_terminal_transaction_v1,
            require_metadata_complete_completed_operation_v1,
        },
    },
};

/// Has no public constructor and is allocated only by the same paid Recover.
pub(crate) struct RecoverRootAssociationV1 {
    query: Query,
    controller_next: u64,
    operation: [u8; 16],
    target: [u8; 16],
    project: [u8; 16],
    sandbox: [u8; 16],
    source_terminal: [u8; 32],
    controller_identity: crate::journal::source_provisioning::CreateStoppedControllerIdentityV1,
}

#[derive(Clone, Copy)]
enum First {
    Query,
    Geometry,
    Funding,
    Association,
    Resources,
    Root,
    Effect,
    Receipt,
    Recipe,
    Joint,
    Append,
    Readback,
    Response,
    Reentry,
}

#[derive(Default)]
pub(super) struct FinalityOriginalV1 {
    entered: bool,
    query: Option<Result<Query, ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    association: Option<Result<Arc<RecoverRootAssociationV1>, ResourceReservationErrorV1>>,
    models: Option<Box<Models>>,
    root: Option<RootClient>,
    first: Option<First>,
    complete: bool,
    body: Option<Result<(), JournalError>>,
    response:
        Option<Result<Option<aos_sandbox_api::aos::sandbox::v1::Operation>, crate::ReconcilerError>>,
    fence: Option<Result<(), JournalError>>,
}

struct Models {
    resources: Option<Result<aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRecordsV1,
        aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceDataErrorV1>>,
    effect: Option<Result<EffectLedgerRecord, EffectHistoryDataError>>,
    receipt: Option<Result<[u8; CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1], JournalError>>,
    terminal: CreateStoppedMetadataTransitionOriginalV1,
    prepared: Option<Result<(), JournalError>>,
    joint: Option<Result<JournalTransaction, JournalError>>,
    append: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<(), JournalError>>,
}

pub(super) struct FirstLocalCompletedFieldsV1<'models> {
    pub(super) resources: aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRecordsV1,
    pub(super) projection_key: &'models [u8],
    pub(super) operation: aos_sandbox_model::OperationId,
    pub(super) query: Query,
    pub(super) source_terminal: [u8; 32],
}

impl OperatorCreateRecoveryOriginalV1 {
    // This borrows only the exact positively completed Root/joint4 originals.
    // It is not a constructor from protected rows or a new current authority.
    pub(super) fn first_local_completed_fields_v1(&self, controller: &Journal)
        -> Result<FirstLocalCompletedFieldsV1<'_>, OperatorCreateRecoveryClosedV1>
    {
        let operation = self.completed_metadata_operation_v1(controller)?;
        let association = self.finality.association.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        controller.require_completed_create_controller_instance_v1(&association.controller_identity)
            .map_err(|_| CLOSED)?;
        let models = self.finality.models.as_deref().ok_or(CLOSED)?;
        let resources = models.resources.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or(CLOSED)?;
        let transaction = models.joint.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        let mut projection = transaction.records().iter().filter(|record| record.namespace() == RecordNamespace::DesiredState);
        let projection_key = projection.next().ok_or(CLOSED)?.key();
        if projection.next().is_some() { return Err(CLOSED); }
        Ok(FirstLocalCompletedFieldsV1 { resources, projection_key, operation,
            query: association.query, source_terminal: association.source_terminal })
    }
}

impl Models {
    fn new() -> Self {
        Self {
            resources: None,
            effect: None,
            receipt: None,
            terminal: CreateStoppedMetadataTransitionOriginalV1::new(),
            prepared: None,
            joint: None,
            append: None,
            readback: None,
        }
    }
}

impl FinalityOriginalV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let models = self.models.as_deref();
        match self.first? {
            First::Query => cause(&self.query),
            First::Geometry => cause(&self.geometry),
            First::Funding => cause(&self.funding),
            First::Association => cause(&self.association),
            First::Resources => models.and_then(|models| cause(&models.resources)),
            First::Root => self
                .root
                .as_ref()
                .and_then(RootClient::failure)
                .or_else(|| cause(&self.body)),
            First::Effect => models.and_then(|models| cause(&models.effect)),
            First::Receipt => models.and_then(|models| cause(&models.receipt)),
            First::Recipe => models.and_then(|models| {
                models
                    .terminal
                    .failure()
                    .or_else(|| cause(&models.prepared))
            }),
            First::Joint => models.and_then(|models| cause(&models.joint)),
            First::Append => models.and_then(|models| cause(&models.append)),
            First::Readback => models.and_then(|models| cause(&models.readback)),
            First::Response => cause(&self.response),
            First::Reentry => Some(&CLOSED as &(dyn Error + 'static)),
        }
        .or(Some(&CLOSED))
    }
}

impl OperatorCreateRecoveryLoanV1<'_, '_> {
    pub(crate) fn prepare_root_finality_once_v1(
        &mut self,
        controller: &Journal,
        session: &Journal,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        root_geometry: Result<ResourceVector, ResourceReservationErrorV1>,
        root_peers: Result<ResourceVector, ResourceReservationErrorV1>,
    ) -> Result<(Arc<RecoverRootAssociationV1>, Query, ResourceVector), ResourceReservationErrorV1>
    {
        self.require_root_controller_v1(controller)?;
        if self.owner.finality.entered {
            self.owner.finality.first.get_or_insert(First::Reentry);
            self.owner.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.finality.entered = true;
        self.owner.finality.query = Some(self.root_finality_query_data_v1(session, inventory));
        if !matches!(self.owner.finality.query, Some(Ok(_))) {
            self.owner.finality.first = Some(First::Query);
            self.owner.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let base = self.reached_receiving_demand_v1();
        self.owner.finality.geometry = Some((|| {
            let parent = self
                .owner
                .target
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let models = controller
                .recovered_metadata_append_receiving_demand_v1(parent)
                .map_err(ResourceReservationErrorV1::Journal)?;
            let header = size_of::<Models>()
                .checked_mul(3)
                .and_then(|n| n.checked_add(3 * size_of::<RecoverRootAssociationV1>()))
                .and_then(|n| n.checked_add(4 * size_of::<Arc<RecoverRootAssociationV1>>()))
                .and_then(|n| n.checked_add(2 * size_of::<std::sync::atomic::AtomicUsize>()))
                .and_then(|n| {
                    n.checked_add(aos_sandbox_protocol::domain_ledger::public_operation::
                    metadata_complete_projection_receiving_bytes_v1()?)
                })
                .and_then(|n| u64::try_from(n).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok(base
                .checked_add(root_geometry?)?
                .checked_add(models)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, header))?)
        })());
        if !matches!(self.owner.finality.geometry, Some(Ok(_))) {
            self.owner.finality.first = Some(First::Geometry);
            self.owner.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let complete = *self
            .owner
            .finality
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.owner.finality.funding = Some(
            root_peers
                .and_then(|peers| complete.checked_add(peers).map_err(Into::into))
                .and_then(|complete| self.require_complete_v1(complete)),
        );
        if !matches!(self.owner.finality.funding, Some(Ok(()))) {
            self.owner.finality.first = Some(First::Funding);
            self.owner.latch_primary_failure_v1();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.owner.finality.models = Some(Box::new(Models::new()));
        self.owner.finality.association = Some((|| {
            let query = *self
                .owner
                .finality
                .query
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let (operation, target, project) = {
                let admission = self.owner.current_observation_data_v1(controller)?;
                (admission.operation, admission.target, admission.project)
            };
            let key = aos_sandbox_protocol::domain_ledger::provisioning_resources::provisioning_parent_key_v1(
                aos_sandbox_model::OperationId::from_bytes(target));
            self.owner.finality.models.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?.resources = Some((|| {
                use aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceDataErrorV1;
                let (_, records) = aos_sandbox_protocol::domain_ledger::provisioning_resources::decode_provisioning_resource_row_v1(
                    &key, controller.get(RecordNamespace::DesiredState, &key).ok_or(ProvisioningResourceDataErrorV1::NonCanonical)?)?
                    .ok_or(ProvisioningResourceDataErrorV1::NonCanonical)?;
                records.require_companions_v1(controller.historical_read_view_v1().materialized_state_v1())?;
                Ok(records)
            })());
            let resources = self.owner.finality.models.as_ref().and_then(|models| models.resources.as_ref())
                .and_then(|value| value.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?.fields_v1();
            if resources.parent.as_bytes() != &target || resources.project.as_bytes() != &project {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(Arc::new(RecoverRootAssociationV1 {
                query,
                controller_next: controller.snapshot_sequence(),
                operation,
                target,
                project,
                sandbox: *resources.sandbox.as_bytes(),
                source_terminal: self.owner.source.root_terminal_digest_v1()?,
                controller_identity: controller.create_stopped_controller_identity_v1()?,
            }))
        })());
        if !matches!(self.owner.finality.association, Some(Ok(_))) {
            self.owner.finality.first = Some(if self.owner.finality.models.as_ref()
                .is_some_and(|models| matches!(models.resources, Some(Err(_)))) {
                First::Resources
            } else { First::Association });
        }
        self.owner.latch_primary_failure_v1();
        let association = self
            .owner
            .finality
            .association
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .cloned()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((Arc::clone(&association), association.query, complete))
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Moves the whole Root original into this actual attempt before any CAS.
    ///
    /// # Errors
    /// Keeps the real failed socket/model/native work and the exact append
    /// result; no refused Root bytes or historical receiver can grant a write.
    #[doc(hidden)]
    pub fn complete_metadata_after_root_once_v1(
        &mut self,
        controller: &mut Journal,
        mut root: RootClient,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        if self.finality.root.is_some() {
            // The caller must park each actual Root owner exactly once. Losing
            // a second entered owner would discard its independent liabilities.
            std::process::abort();
        }
        self.latch_primary_failure_v1();
        root.park_in_native_attempt_v1();
        self.finality.root = Some(root);
        if self
            .finality
            .root
            .as_ref()
            .is_some_and(|root| root.failure().is_some())
        {
            self.finality.first.get_or_insert(First::Root);
        }
        self.latch_primary_failure_v1();
        if self.failure_v1().is_some() {
            return Err(CLOSED);
        }
        self.finality.body = Some(
            self.prepare_metadata_joint_once_v1(controller)
                .and_then(|()| {
                    // Move the exact retained transaction out only for the native
                    // call, then restore it on every outcome. The owner and Root
                    // association remain resident and cannot enter another CAS.
                    let transaction = self
                        .finality
                        .models
                        .as_mut()
                        .and_then(|models| models.joint.take())
                        .and_then(Result::ok)
                        .ok_or(JournalError::ProtectedBoundary)?;
                    let append = controller.commit_operator_recover_metadata_v1(self, &transaction);
                    let models = self
                        .finality
                        .models
                        .as_mut()
                        .ok_or(JournalError::ProtectedBoundary)?;
                    models.joint = Some(Ok(transaction));
                    models.append = Some(append);
                    if !matches!(models.append, Some(Ok(_))) {
                        self.finality.first.get_or_insert(First::Append);
                    }
                    if self.finality.first.is_some() {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    Ok(())
                }),
        );
        if matches!(self.finality.body, Some(Err(_))) {
            self.finality.first.get_or_insert(First::Root);
            self.latch_primary_failure_v1();
            return Err(CLOSED);
        }
        self.finality.models.as_mut().ok_or(CLOSED)?.readback =
            Some(self.require_metadata_completed_rows_v1(controller));
        if !matches!(
            self.finality
                .models
                .as_ref()
                .and_then(|models| models.readback.as_ref()),
            Some(Ok(()))
        ) {
            self.finality.first.get_or_insert(First::Readback);
        } else {
            self.finality.complete = true;
        }
        self.latch_primary_failure_v1();
        if self.finality.complete && self.failure_v1().is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    fn prepare_metadata_joint_once_v1(&mut self, controller: &Journal) -> Result<(), JournalError> {
        self.require_native_current_v1(controller)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.require_observation_current_v1(controller)?;
        let association = self
            .finality
            .association
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .cloned()
            .ok_or(JournalError::ProtectedBoundary)?;
        let root = self
            .finality
            .root
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let ack = root
            .require_metadata_ack_v1(&association, controller)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if ack.target != association.target || ack.source_terminal != association.source_terminal {
            self.finality.first.get_or_insert(First::Root);
            return Err(JournalError::ProtectedBoundary);
        }
        let horizon = crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1::
            from_original_data_v1(association.query.original, ack.cutoff)?
            .with_wall_expiry_data_v1(ack.wall_expiry);
        let clock = self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        clock.narrow_horizon_data_v1(horizon)?;
        clock.check_next_once_v1()?;
        let models = self
            .finality
            .models
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        let parent = aos_sandbox_model::OperationId::from_bytes(association.target);
        models.effect = Some(decode_effect(
            controller
                .get(RecordNamespace::Effect, &effect_key(parent, 0))
                .ok_or(JournalError::ProtectedBoundary)?,
        ));
        if !matches!(models.effect, Some(Ok(_))) {
            self.finality.first = Some(First::Effect);
            return Err(JournalError::ProtectedBoundary);
        }
        models.receipt = Some((|| {
            let effect = models
                .effect
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let EffectState::Applied { receipt, .. } = effect.state() else {
                return Err(JournalError::ProtectedBoundary);
            };
            receipt
                .as_bytes()
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)
        })());
        if !matches!(models.receipt, Some(Ok(_))) {
            self.finality.first = Some(First::Receipt);
            return Err(JournalError::ProtectedBoundary);
        }
        let receipt = models
            .receipt
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        clock.check_next_once_v1()?;
        models.prepared = Some(models.terminal.prepare_once_v1(
            controller,
            parent,
            aos_sandbox_model::ProjectId::from_bytes(association.project),
            aos_sandbox_model::SandboxId::from_bytes(association.sandbox),
            receipt,
            ack.sample,
        ));
        if !matches!(models.prepared, Some(Ok(()))) {
            self.finality.first = Some(First::Recipe);
            return Err(JournalError::ProtectedBoundary);
        }
        clock.check_next_once_v1()?;
        models.joint = Some((|| {
            let data = Admission::decode_v1(
                controller
                    .get(
                        RecordNamespace::OperatorRecovery,
                        &association.query.admission_key,
                    )
                    .ok_or(JournalError::ProtectedBoundary)?,
            )
            .map_err(|cause| JournalError::MetadataComplete(cause.into()))?;
            let operation = decode_operation(
                controller
                    .get(RecordNamespace::Operation, &data.operation)
                    .ok_or(JournalError::ProtectedBoundary)?,
            )
            .map_err(|cause| {
                JournalError::Q04ControllerLedger(Box::new(crate::ReconcilerError::from(cause)))
            })?;
            let transaction = metadata_complete_terminal_transaction_v1(
                models.terminal.transaction_v1()?,
                data,
                aos_sandbox_model::SandboxId::from_bytes(association.sandbox),
                operation,
                ack.sample,
            )?;
            if finality_controller_transaction_commitment_v1(&transaction)
                .map_err(|cause| JournalError::MetadataComplete(cause.into()))?
                != ack.controller_transaction
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(transaction)
        })());
        if !matches!(models.joint, Some(Ok(_))) {
            self.finality.first = Some(First::Joint);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn require_metadata_transition_v1(
        &self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.require_native_current_v1(controller)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.require_observation_current_v1(controller)?;
        let association = self
            .finality
            .association
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let ack = self
            .finality
            .root
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .require_metadata_ack_v1(association, controller)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if controller.snapshot_sequence() != association.controller_next
            || self.finality.first.is_some()
            || finality_controller_transaction_commitment_v1(transaction)
                .map_err(|cause| JournalError::MetadataComplete(cause.into()))?
                != ack.controller_transaction
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn final_metadata_crossing_v1(
        &mut self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.require_metadata_transition_v1(controller, transaction)?;
        let result = self
            .clock
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .check_next_once_v1()
            .and_then(|_| self.require_metadata_transition_v1(controller, transaction));
        self.latch_primary_failure_v1();
        result
    }

    fn require_metadata_completed_rows_v1(&self, controller: &Journal) -> Result<(), JournalError> {
        controller.ensure_healthy()?;
        let association = self
            .finality
            .association
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let transaction = self
            .finality
            .models
            .as_ref()
            .and_then(|models| models.joint.as_ref())
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        for row in transaction.records() {
            if controller.get(row.namespace(), row.key()) != row.value() {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        let raw = controller
            .get(
                RecordNamespace::OperatorRecovery,
                &association.query.admission_key,
            )
            .ok_or(JournalError::ProtectedBoundary)?;
        if finality_admission_commitment_v1(raw) != association.query.admission {
            return Err(JournalError::ProtectedBoundary);
        }
        let data = Admission::decode_v1(raw)
            .map_err(|cause| JournalError::MetadataComplete(cause.into()))?;
        require_metadata_complete_completed_operation_v1(
            data,
            controller
                .get(RecordNamespace::Operation, &association.operation)
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        Ok(())
    }

    /// Returns only the durably completed new public operation after all posts.
    ///
    /// # Errors
    /// Refuses partial CAS, native/Source/final-clock refusal or changed rows.
    #[doc(hidden)]
    pub fn completed_metadata_operation_v1(
        &self,
        controller: &Journal,
    ) -> Result<aos_sandbox_model::OperationId, OperatorCreateRecoveryClosedV1> {
        if !self.finality.complete
            || !matches!(self.after, Some(Ok(())))
            || self.require_source_disposed_v1().is_err()
            || !matches!(self.final_clock_comparison, Some(Ok(())))
            || self.failure_v1().is_some()
        {
            return Err(CLOSED);
        }
        self.require_metadata_completed_rows_v1(controller)
            .map_err(|_| CLOSED)?;
        let association = self
            .finality
            .association
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(CLOSED)?;
        Ok(aos_sandbox_model::OperationId::from_bytes(
            association.operation,
        ))
    }

    pub(crate) fn prepare_metadata_public_response_once_v1(
        &mut self,
        controller: &Journal,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        if !self.finality.complete
            || self.finality.response.is_some()
            || self.failure_v1().is_some()
        {
            return Err(CLOSED);
        }
        let operation = self
            .finality
            .association
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map(|association| aos_sandbox_model::OperationId::from_bytes(association.operation))
            .ok_or(CLOSED)?;
        self.clock
            .as_mut()
            .ok_or(CLOSED)?
            .check_next_once_v1()
            .map_err(|_| CLOSED)?;
        self.finality.response = Some(crate::reconciler::recovered_public_operation_resource_v1(
            controller, operation,
        ));
        if !matches!(self.finality.response, Some(Ok(Some(_)))) {
            self.finality.first.get_or_insert(First::Response);
        }
        self.latch_primary_failure_v1();
        if self.finality.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    pub(crate) fn take_completed_metadata_public_response_v1(
        &mut self,
        controller: &Journal,
    ) -> Result<aos_sandbox_api::aos::sandbox::v1::Operation, OperatorCreateRecoveryClosedV1> {
        self.completed_metadata_operation_v1(controller)?;
        self.finality
            .response
            .take()
            .and_then(Result::ok)
            .flatten()
            .ok_or(CLOSED)
    }

    pub(crate) fn fence_metadata_after_refusal_once_v1(&mut self, controller: &mut Journal) {
        if self.finality.fence.is_some()
            || !self
                .finality
                .models
                .as_ref()
                .is_some_and(|models| matches!(models.append, Some(Ok(_))))
        {
            return;
        }
        if let Some(Ok(association)) = &self.finality.association {
            // This is the captured SAME writer-instance identity, not an old
            // completion capability. The existing intrinsic poison works after
            // health/currentness refusal and permits no new native operation.
            self.finality.fence = Some(
                controller.fence_create_stopped_completion_v1(&association.controller_identity),
            );
        }
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

const CLOSED: OperatorCreateRecoveryClosedV1 = OperatorCreateRecoveryClosedV1;

struct RecoverFailureDisplayV1<'held>(&'held OperatorCreateRecoveryOriginalV1);

impl std::fmt::Display for RecoverFailureDisplayV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(cause) = self.0.failure_v1() else {
            return std::fmt::Display::fmt(&CLOSED, formatter);
        };
        if matches!(self.0.first, Some(FirstV1::Finality)) {
            if let Some(root) = self.0.finality.root.as_ref() {
                if root
                    .failure()
                    .is_some_and(|selected| std::ptr::eq(selected, cause))
                {
                    if let Some(view) = root.property_failure_view_v1() {
                        return std::fmt::Debug::fmt(&view, formatter);
                    }
                }
            }
        }
        std::fmt::Display::fmt(cause, formatter)
    }
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Formats only the selected retained cause, borrowing any actual Root archive.
    #[doc(hidden)]
    #[must_use]
    pub fn failure_view_v1(&self) -> Option<impl std::fmt::Display + '_> {
        self.failure_v1()?;
        Some(RecoverFailureDisplayV1(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_append_original_precedes_later_readback_refusal() {
        let mut original = FinalityOriginalV1::default();
        let mut models = Models::new();
        models.append = Some(Err(JournalError::Io(std::io::Error::other(
            "actual append",
        ))));
        original.models = Some(Box::new(models));
        original.first = Some(First::Append);
        let selected = original.failure().unwrap() as *const (dyn Error + 'static);

        original.models.as_mut().unwrap().readback = Some(Err(JournalError::ProtectedBoundary));

        assert!(std::ptr::eq(selected, original.failure().unwrap()));
        assert!(!original.complete);
    }
}
