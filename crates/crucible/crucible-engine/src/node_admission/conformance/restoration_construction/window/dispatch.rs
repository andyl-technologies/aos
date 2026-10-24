//! Runs one already-admitted phase through its same actual runtime-owned node.
//!
//! This opaque argument does not extract a preparation, Source emitter or
//! controller. Core alone spends its phase before constructing it; the CNP
//! adapter lends its own controller and, only for Prepare, its actual Query.
//! Source returns opaque receipt evidence before Core advances the same target.

use super::*;
use crucible_node_transport::client::{CnpController, OriginalFreshRestoreQuery};

/// Carries one nonrenewing installed restoration phase to its actual node.
///
/// No public constructor, Clone, parser or conversion to execution/final-context
/// authority exists. Unknown nodes refuse this separate internal adapter path.
#[must_use = "dispatch only on the same admitted runtime-owned node"]
pub struct OriginalRestorationNodeDispatch<'a> {
    claim: OriginalRestorationTransactionClaim<'a>,
}

// A failed phase or unwind permanently closes the whole transaction. The
// actual node, Source, ticket and partial SDK owners remain in their original
// holder; this destructor performs only fixed Cell updates and no callbacks.
pub(super) struct RestorationDispatchAttempt<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    completed: bool,
}

impl<'a> RestorationDispatchAttempt<'a> {
    pub(super) fn begin(
        window: &'a CompleteOriginalRestorationWindow,
    ) -> Result<Self, RuntimeError> {
        window.origin()?;
        if window.stage.get() != WindowStage::TransactionAdmitted
            || window
                .whole_observation
                .authenticate_dispatch_data()
                .is_err()
            || window.phase_in_flight.replace(true)
        {
            window.stage.set(WindowStage::Failed);
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(Self {
            window,
            completed: false,
        })
    }

    pub(super) fn complete(mut self) -> Result<(), RuntimeError> {
        super::observation::authenticate_started_stage_data(
            &self.window.stage,
            WindowStage::TransactionAdmitted,
        )?;
        if !self.window.phase_in_flight.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Group success retains new actual owners. Receipt verification alone
        // cannot authorize the next phase without the complete owning walk.
        self.window.whole_observation.require_observation();
        self.completed = true;
        Ok(())
    }
}

impl Drop for RestorationDispatchAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.window.stage.set(WindowStage::Failed);
        }
        self.window.phase_in_flight.set(false);
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn begin_original_node_dispatch<'a>(
        &'a self,
        plan: &'a InstalledConformancePlan,
        activation: &'a ActivationRecord,
        selected: usize,
        phase: OriginalRestorationTransactionPhase,
    ) -> Result<OriginalRestorationNodeDispatch<'a>, RuntimeError> {
        Ok(OriginalRestorationNodeDispatch {
            claim: self.begin_original_phase_claim(plan, activation, selected, phase)?,
        })
    }

    fn original_node_row_data(
        &self,
        selected: usize,
    ) -> Result<&OriginalRestorationNodeConstructionData, RuntimeError> {
        self.node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)
    }
}

impl OriginalRestorationNodeDispatch<'_> {
    pub(crate) fn source_data(&self) -> &Rc<PacketCompleteSemanticSource> {
        self.claim.original_source_data()
    }

    pub(crate) fn ticket_data(&self) -> Result<&CompleteOriginalNativeTicket, RuntimeError> {
        self.claim.original_target_data().ticket_data()
    }

    pub(crate) fn needs_original_query_data(&self) -> bool {
        matches!(
            self.claim.phase(),
            OriginalRestorationTransactionPhase::Prepare
        )
    }

    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &ConformanceRuntime,
    ) -> Result<(), RuntimeError> {
        let target = self.claim.original_target_data();
        let window = self.claim.original_window_data();
        target.authenticate_original_target_data(
            self.claim.original_plan_data(),
            self.claim.original_source_data(),
            runtime,
            &window.archive,
            self.claim.original_activation_data(),
        )?;
        self.claim.authenticate_current()
    }

    pub(crate) fn execute_original_controller_data(
        self,
        controller: &mut CnpController,
        query: Option<&OriginalFreshRestoreQuery>,
        read_owner: *const (),
    ) -> Result<(), RuntimeError> {
        let window = self.claim.original_window_data();
        let target = self.claim.original_target_data();
        let source = self.claim.original_source_data();
        let plan = self.claim.original_plan_data();
        let activation = self.claim.original_activation_data();
        let node = window.original_node_row_data(target.selected_data())?;
        node.authenticate_original_owner_data(source, read_owner)?;
        let row = node.signer.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        self.claim.authenticate_current()?;
        match self.claim.phase() {
            OriginalRestorationTransactionPhase::Prepare => {
                let query = query.ok_or(RuntimeError::OwnerUnavailable)?;
                {
                    let mut output = target.mapping_output_data()?;
                    source.prepare_original_restore_transfer_mapping_into(
                        controller,
                        &self.claim,
                        row,
                        &mut output,
                    )?;
                }
                target.retain_original_mapping_data()?;
                let mut quote = Some(
                    source.quote_original_restore_transfer_upload_prospective_data(
                        controller,
                        query,
                        &self.claim,
                        row,
                        target.mapping_data()?,
                    )?,
                );
                let references = window
                    .cold
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .original_restoration_references_data(
                        target.selected_data(),
                        source,
                        target.ticket_data()?,
                    )?;
                target.retain_original_upload_quote_data(&mut quote, references)?;
                target.construct_original_normalization_data(node)?;
                let mut output =
                    target.response_output_data(&OriginalRestorationTransactionPhase::Prepare)?;
                let evidence = source.call_original_restore_transfer_prepare_into(
                    controller,
                    query,
                    &node.prepare_binding,
                    self.claim,
                    row,
                    &mut output,
                )?;
                window.complete_original_verified_phase(
                    plan,
                    activation,
                    target,
                    &OriginalRestorationTransactionPhase::Prepare,
                    &evidence,
                    None,
                )
            }
            OriginalRestorationTransactionPhase::Inputs => {
                if query.is_some() {
                    return Err(RuntimeError::ForeignAuthority);
                }
                let mut quote = target.input_quote_output_data()?;
                if quote.is_some() {
                    return Err(RuntimeError::OutstandingObligations);
                }
                *quote = Some(source.quote_original_restore_transfer_inputs_data(
                    controller,
                    &self.claim,
                    row,
                    target.upload_data()?,
                )?);
                let mut output = target.upload_output_data()?;
                let evidence = source.call_original_restore_transfer_inputs_into(
                    controller,
                    quote.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                    self.claim,
                    row,
                    &mut output,
                )?;
                window.complete_original_verified_phase(
                    plan,
                    activation,
                    target,
                    &OriginalRestorationTransactionPhase::Inputs,
                    &evidence,
                    output.as_ref(),
                )
            }
            OriginalRestorationTransactionPhase::Commit => {
                if query.is_some() {
                    return Err(RuntimeError::ForeignAuthority);
                }
                let upload = target.completed_upload_data()?;
                let upload = upload.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
                let mut output =
                    target.response_output_data(&OriginalRestorationTransactionPhase::Commit)?;
                let evidence = source.call_original_restore_transfer_commit_into(
                    controller,
                    upload,
                    self.claim,
                    row,
                    &mut output,
                )?;
                window.complete_original_verified_phase(
                    plan,
                    activation,
                    target,
                    &OriginalRestorationTransactionPhase::Commit,
                    &evidence,
                    Some(upload),
                )
            }
        }
    }
}

impl CompleteOriginalRestorationWindow {
    /// Dispatches the three genuine Prepare phases on their same inactive nodes.
    ///
    /// The window alone creates each once-spent claim. This performs no final
    /// lineage installation, Ready or Arm; every partial stays in its real node.
    ///
    /// # Errors
    /// Refuses changed/spent targets, unavailable same-node owners, currentness,
    /// any Source signing/transport/receipt failure or prepaid-axis excess.
    pub fn execute_original_prepare_phase(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &mut ConformanceRuntime,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        let attempt = RestorationDispatchAttempt::begin(self)?;
        for selected in 0..3 {
            let dispatch = self.begin_original_node_dispatch(
                plan,
                activation,
                selected,
                OriginalRestorationTransactionPhase::Prepare,
            )?;
            runtime.execute_original_restoration_transaction(dispatch)?;
        }
        attempt.complete()?;
        Ok(())
    }

    /// Dispatches the six-body uploads on the same Prepare-completed nodes.
    ///
    /// # Errors
    /// Refuses missing original receipts, spent/out-of-order phases, changed
    /// live membership, upload/ACK failure or growth beyond prepaid axes.
    pub fn execute_original_inputs_phase(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &mut ConformanceRuntime,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        let attempt = RestorationDispatchAttempt::begin(self)?;
        for selected in 0..3 {
            let dispatch = self.begin_original_node_dispatch(
                plan,
                activation,
                selected,
                OriginalRestorationTransactionPhase::Inputs,
            )?;
            runtime.execute_original_restoration_transaction(dispatch)?;
        }
        attempt.complete()?;
        Ok(())
    }

    /// Dispatches the three actual Commit phases without renewing the Query cut.
    ///
    /// Verified Commit transport remains distinct from the mandatory four-owner
    /// continuation/journal validation and final lineage-context installation.
    ///
    /// # Errors
    /// Refuses missing original uploads/ACKs, spent/out-of-order phases, changed
    /// live membership, Commit/proof failure or growth beyond prepaid axes.
    pub fn execute_original_commit_phase(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &mut ConformanceRuntime,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        let attempt = RestorationDispatchAttempt::begin(self)?;
        for selected in 0..3 {
            let dispatch = self.begin_original_node_dispatch(
                plan,
                activation,
                selected,
                OriginalRestorationTransactionPhase::Commit,
            )?;
            runtime.execute_original_restoration_transaction(dispatch)?;
        }
        attempt.complete()?;
        Ok(())
    }
}
