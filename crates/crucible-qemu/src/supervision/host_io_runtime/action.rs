//! Lends real request producers before wake and observes separate physical return.

use super::*;

impl QemuLiveHostIoRuntime {
    /// Cleans old identity-only debt before a fresh producing operation enters.
    pub(super) fn settle_previous_action(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let Some(source) = self.source_supervision.as_ref() else {
            return Ok(());
        };
        if source.action_is_pending() {
            let journal = source
                .settle_action_from_mapping(
                    self.region.as_ref().ok_or_else(region_missing)?,
                    self.vm_slot,
                )
                .map_err(|error| {
                    QemuAsyncDriverRuntimeError::operational_supervision(
                        "return previous action",
                        error,
                    )
                })?;
            let Some(journal) = journal else {
                return Err(QemuAsyncDriverRuntimeError::new(
                    "return previous action",
                    "actual native physical return remains pending",
                ));
            };
            if journal.first < 0 || journal.post < 0 {
                return Err(QemuAsyncDriverRuntimeError::new(
                    "return previous action",
                    format!(
                        "previous native action first/post {}/{} after known physical return",
                        journal.first, journal.post
                    ),
                ));
            }
        }
        let supervisor = self.host_operation_supervisor.as_ref().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "observe containing Source",
                "actual containing Source supervisor is unavailable",
            )
        })?;
        source
            .verify_live_control_source(supervisor)
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision(
                    "observe containing Source",
                    error,
                )
            })
    }

    /// Publishes the real operation loan before existing control-request effects.
    pub(super) fn lend_control_action(
        &mut self,
        deadline: &OperationPollBudget<'_>,
        capture: Option<u32>,
    ) -> Result<
        Option<crucible_protocol::boundary_action::ActionBinding>,
        QemuAsyncDriverRuntimeError,
    > {
        let Some(primary) = deadline.action_producers()? else {
            return Ok(None);
        };
        let source = self.source_supervision.as_ref().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "lend control action",
                "real standing Source owner is unavailable",
            )
        })?;
        let mapping = self.region.as_ref().ok_or_else(region_missing)?;
        let frontier = mapping
            .fault_command_write_index(self.vm_slot)
            .map_err(map_slot_error)?;
        let token = mapping
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .preview_action_token(frontier, capture)
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::new("preview control token", error.to_string())
            })?;
        source
            .begin_action(mapping, self.vm_slot, token, frontier, capture, primary)
            .map(Some)
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision("lend control action", error)
            })
    }

    /// Refreshes all actual lenders at one locked cut before native continuation.
    pub(super) fn refresh_control_action(&self) -> Result<(), QemuAsyncDriverRuntimeError> {
        if let Some(source) = &self.source_supervision {
            source.refresh_action().map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision(
                    "refresh control action",
                    error,
                )
            })?;
        }
        Ok(())
    }

    /// Observes physical close independently from both application ACK cuts.
    pub(super) fn finish_control_action(&self) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let Some(source) = &self.source_supervision else {
            return Ok(true);
        };
        let Some(journal) = source
            .settle_action_from_mapping(
                self.region.as_ref().ok_or_else(region_missing)?,
                self.vm_slot,
            )
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision("return control action", error)
            })?
        else {
            return Ok(false);
        };
        if journal.first < 0 || journal.post < 0 {
            return Err(QemuAsyncDriverRuntimeError::new(
                "return control action",
                format!(
                    "native action first/post {}/{} after known physical return",
                    journal.first, journal.post
                ),
            ));
        }
        Ok(true)
    }
}

/// Corroborates the actual published request against the retained action tuple.
///
/// This checks immutable facts only. It never returns a loan or retires debt.
pub(super) fn validate_control_action_request(
    request: super::control::PendingControlBoundary,
    loan: Option<crucible_protocol::boundary_action::ActionBinding>,
) -> Result<(), QemuAsyncDriverRuntimeError> {
    if loan.is_some_and(|loan| {
        request.generation != loan.token
            || request.fault_command_frontier != loan.frontier
            || request.fingerprint_capture_request != loan.capture
    }) {
        return Err(QemuAsyncDriverRuntimeError::new(
            "publish control action",
            "request changed after genuine loan publication",
        ));
    }
    Ok(())
}
