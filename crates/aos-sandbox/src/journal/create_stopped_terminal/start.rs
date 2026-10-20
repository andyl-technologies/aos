//! Retains the finite Start and residual Stop three-row terminal CAS.
//!
//! The sole public Effect/Operation completion codec is reused. This branch
//! supplies only its closed observed facts from the actual retained source; the
//! caller alone owns native authority, admission, all posts and first causes.

use super::*;
use aos_sandbox_core::{CanonicalAssignmentManifestV1, ProjectId};
use aos_sandbox_protocol::domain_ledger::effect_history::EffectReceipt;

pub(crate) struct LifecycleTerminalMetadataOriginalV4 {
    projection: Option<Result<PublicProjectionRecordV1, PublicProjectionError>>,
    candidate: Option<aos_proto::aos::sandbox::v1::Sandbox>,
    candidate_check: Option<Result<(), PublicProjectionError>>,
    successor: Option<Result<PublicProjectionPlanV1, PublicProjectionError>>,
    completion: Option<Result<[JournalRecord; 2], crate::ReconcilerError>>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    before: Option<[[u8; 32]; 3]>,
    first: Option<FirstV1>,
}

#[derive(Clone, Copy)]
enum TerminalModelInputV4<'input> {
    Start { plan: &'input crate::OperationPlan, manifest: &'input CanonicalAssignmentManifestV1 },
    Stop {
        operation: OperationId,
        context: &'input aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1,
        fence: crate::lifecycle::LiveRuntimeFenceV1,
        residual: bool,
    },
}

impl LifecycleTerminalMetadataOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            projection: None,
            candidate: None,
            candidate_check: None,
            successor: None,
            completion: None,
            transaction: None,
            before: None,
            first: None,
        }
    }

    pub(crate) fn prepare_once_v2(
        &mut self,
        controller: &Journal,
        plan: &crate::OperationPlan,
        project: ProjectId,
        manifest: &CanonicalAssignmentManifestV1,
        receipt: &[u8],
        sample: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<(), JournalError> {
        self.prepare_model_once_v4(controller, project, receipt, sample,
            TerminalModelInputV4::Start { plan, manifest })
    }

    pub(crate) fn prepare_stop_residual_once_v4(
        &mut self,
        controller: &Journal,
        operation: OperationId,
        context: &aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1,
        fence: crate::lifecycle::LiveRuntimeFenceV1,
        receipt: &[u8],
        sample: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<(), JournalError> {
        self.prepare_model_once_v4(controller, context.project(), receipt, sample,
            TerminalModelInputV4::Stop { operation, context, fence, residual: true })
    }

    pub(crate) fn prepare_stop_success_once_v5(
        &mut self, controller: &Journal, operation: OperationId,
        context: &aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1,
        fence: crate::lifecycle::LiveRuntimeFenceV1, receipt: &[u8],
        sample: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<(), JournalError> {
        self.prepare_model_once_v4(controller, context.project(), receipt, sample,
            TerminalModelInputV4::Stop { operation, context, fence, residual: false })
    }

    fn prepare_model_once_v4(
        &mut self,
        controller: &Journal,
        project: ProjectId,
        receipt: &[u8],
        sample: aos_sandbox_core::RawPairedClockSample,
        input: TerminalModelInputV4<'_>,
    ) -> Result<(), JournalError> {
        if self.projection.is_some() || self.first.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (parent, sandbox, observation) = match input {
            TerminalModelInputV4::Start { plan, manifest } => (
                plan.operation_id(), manifest.manifest().sandbox(), TerminalObservationV2::StartRunning(manifest)),
            TerminalModelInputV4::Stop { operation, fence, .. } => (
                operation, fence.sandbox(), TerminalObservationV2::Stopped(fence)),
        };
        self.projection = Some(
            crate::controller_service::public_projection::PublicProjectionStoreV1::new(controller)
                .get(PublicProjectionKindV1::Sandbox, *sandbox.as_bytes())
                .and_then(|value| value.ok_or(PublicProjectionError::CorruptRecord)),
        );
        if !matches!(self.projection, Some(Ok(_))) {
            self.first = Some(FirstV1::Projection);
            return Err(JournalError::ProtectedBoundary);
        }
        self.candidate_check = Some(terminal_sandbox_candidate_v2(
            &mut self.candidate,
            self.projection
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?,
            parent,
            project,
            observation,
        ));
        if !matches!(self.candidate_check, Some(Ok(()))) {
            self.first = Some(FirstV1::Successor);
            return Err(JournalError::ProtectedBoundary);
        }
        self.successor = Some(PublicProjectionPlanV1::new(
            project,
            parent,
            PublicProjectionResourceV1::Sandbox(
                self.candidate
                    .as_ref()
                    .ok_or(JournalError::ProtectedBoundary)?
                    .clone(),
            ),
        ));
        if !matches!(self.successor, Some(Ok(_))) {
            self.first = Some(FirstV1::Successor);
            return Err(JournalError::ProtectedBoundary);
        }
        self.completion = Some((|| {
            let receipt = EffectReceipt::new(receipt.to_vec())?;
            match input {
                TerminalModelInputV4::Start { plan, .. } =>
                    crate::reconciler::completed_start_effect_operation_records_v2(
                        controller, plan, receipt, sample.wall_seconds()),
                TerminalModelInputV4::Stop { operation, context, residual, .. } => {
                    if residual {
                        crate::reconciler::completed_stop_residual_effect_operation_records_v4(
                            controller, operation, context, receipt, sample.wall_seconds())
                    } else {
                        crate::reconciler::completed_stop_success_effect_operation_records_v5(
                            controller, operation, context, receipt, sample.wall_seconds())
                    }
                }
            }
        })());
        if !matches!(self.completion, Some(Ok(_))) {
            self.first = Some(FirstV1::Effect);
            return Err(JournalError::ProtectedBoundary);
        }
        self.transaction = Some((|| {
            let rows = self
                .completion
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let successor = self
                .successor
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let key = projection_key(PublicProjectionKindV1::Sandbox, *sandbox.as_bytes());
            self.before = Some([
                Sha256::digest(
                    controller
                        .get(RecordNamespace::Effect, &effect_key(parent, 0))
                        .ok_or(JournalError::ProtectedBoundary)?,
                )
                .into(),
                Sha256::digest(
                    controller
                        .get(RecordNamespace::Operation, parent.as_bytes())
                        .ok_or(JournalError::ProtectedBoundary)?,
                )
                .into(),
                Sha256::digest(
                    controller
                        .get(RecordNamespace::DesiredState, &key)
                        .ok_or(JournalError::ProtectedBoundary)?,
                )
                .into(),
            ]);
            let digest: [u8; 32] = Sha256::new()
                .chain_update(match input {
                    TerminalModelInputV4::Start { .. } => b"aos.sandbox.start.terminal-controller.v2\0".as_slice(),
                    TerminalModelInputV4::Stop { residual: true, .. } => b"aos.sandbox.stop.residual-controller.v4\0".as_slice(),
                    TerminalModelInputV4::Stop { residual: false, .. } => b"aos.sandbox.stop.success-controller.v5\0".as_slice(),
                })
                .chain_update(parent.as_bytes())
                .chain_update(receipt)
                .finalize()
                .into();
            let id = digest[..16]
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            JournalTransaction::new(
                id,
                vec![
                    rows[0].clone(),
                    rows[1].clone(),
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        successor.desired_key().to_vec(),
                        successor.desired_value().to_vec(),
                    ),
                ],
            )
            .map_err(JournalError::from)
        })());
        if !matches!(self.transaction, Some(Ok(_))) {
            self.first = Some(FirstV1::Transaction);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn transaction_v2(&self) -> Result<&JournalTransaction, JournalError> {
        if self.first.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.transaction
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn require_before_v2(
        &self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if self.transaction_v2()? != transaction {
            return Err(JournalError::ProtectedBoundary);
        }
        let rows = transaction.records();
        let before = self
            .before
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if rows.len() != before.len() {
            return Err(JournalError::ProtectedBoundary);
        }
        for (row, expected) in rows.iter().zip(before) {
            let raw = controller
                .get(row.namespace(), row.key())
                .ok_or(JournalError::ProtectedBoundary)?;
            if <[u8; 32]>::from(Sha256::digest(raw)) != *expected {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV1::Projection => cause(&self.projection),
            FirstV1::Successor => cause(&self.candidate_check).or_else(|| cause(&self.successor)),
            FirstV1::Effect => cause(&self.completion),
            FirstV1::Transaction => cause(&self.transaction),
            _ => Some(&METADATA_CLOSED),
        }
    }
}

// Declared observed fields2/3: bytes16; fields4/5/6: uint64; and the
// nested observed-message length prefix. No carrier field becomes namespace.
pub(super) const START_OBSERVATION_WIRE_GROWTH_V2: usize = 2 * (1 + 1 + 16) + 3 * (1 + 10) + 10;

pub(crate) fn start_terminal_receiving_demand_v2(
    controller: &Journal,
    parent: OperationId,
) -> Result<ResourceVector, JournalError> {
    // The exact append is still unentered. Its native buffers/storage/traffic
    // are paid separately from the actual prepared three-row transaction at
    // require_terminal_append_once_v2, before the same Journal native engine.
    receiving::start_model_demand_v2(controller, parent)
}

// Both changed observed uint64 fields may grow from one to ten varint bytes;
// their nested observation length can gain one additional byte.
pub(super) const STOP_OBSERVATION_WIRE_GROWTH_V5: usize = 2 * (10 - 1) + 1;


