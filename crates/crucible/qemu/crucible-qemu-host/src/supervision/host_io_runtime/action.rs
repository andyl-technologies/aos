//! Lends real request producers before wake and observes separate physical return.

use super::*;

impl QemuLiveHostIoRuntime {
    /// Publishes the actual two-lender Park cohort before descriptor transport.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(super) fn retain_parent_park_request(
        &mut self,
        correlation: u64,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu_protocol::boundary_action::ActionBinding, QemuAsyncDriverRuntimeError>
    {
        if self.parent_park_action.is_some() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "retain parent Park action",
                "a prior Park request still owns its physical lifetime",
            ));
        }
        self.settle_previous_action()?;
        let source = self.source_supervision.as_ref().ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(
                "retain parent Park action",
                "actual standing Source publisher is unavailable",
            )
        })?;
        let binding = source
            .begin_parent_park_action(
                self.region.as_ref().ok_or_else(region_missing)?,
                self.vm_slot,
                correlation,
                actor,
                family,
            )
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision(
                    "retain parent Park action",
                    error,
                )
            })?;
        // The actual publisher owns born memberships even when begin refuses.
        // On success retain this selector before any later import or postcut.
        self.parent_park_action = Some(binding);
        self.observe_parent_park_request()
    }

    /// Recollects this same request without extending either original interval.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(super) fn observe_parent_park_request(
        &self,
    ) -> Result<crucible_qemu_protocol::boundary_action::ActionBinding, QemuAsyncDriverRuntimeError>
    {
        let binding = self.parent_park_action.ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new("observe parent Park action", "pair absent")
        })?;
        self.source_supervision
            .as_ref()
            .ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new(
                    "observe parent Park action",
                    "actual standing Source publisher is unavailable",
                )
            })?
            .check_parent_park_action(binding)
            .map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision(
                    "observe parent Park action",
                    error,
                )
            })?;
        Ok(binding)
    }

    /// Returns Host memberships only after the same QMP client proves local closure.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(super) fn return_parent_park_request(
        &mut self,
        closed: &crate::QmpParentParkClosedRequest,
    ) -> Result<bool, crucible_host_resources::host_supervision::HostSupervisionError> {
        use crucible_host_resources::host_supervision::HostSupervisionError;
        let binding = self
            .parent_park_action
            .ok_or(HostSupervisionError::Unavailable)?;
        let source = self
            .source_supervision
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        let mapping = self
            .region
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        let Some(settled) =
            source.settle_parent_park_from_mapping(mapping, self.vm_slot, closed)?
        else {
            return Ok(false);
        };
        if settled.binding != binding {
            return Err(HostSupervisionError::Unavailable);
        }
        // Actual Host unlink/publication/frontier return precedes semantic
        // reporting. Negative dispositions remain in Source and the receipt.
        self.parent_park_action = None;
        Ok(true)
    }

    /// Enrolls both actual park producers before a tokenized Pause effect.
    ///
    /// An earlier action must have a physical return, independently of its
    /// control acknowledgment. Born-negative membership stays Source-owned.
    pub(super) fn lend_paired_pause_action(
        &mut self,
        deadline: &OperationPollBudget<'_>,
    ) -> Result<
        Option<crucible_qemu_protocol::boundary_action::ActionBinding>,
        QemuAsyncDriverRuntimeError,
    > {
        if !deadline.is_paired_quiescence() {
            return Ok(None);
        }
        self.settle_previous_action()?;
        let binding = self.lend_control_action(deadline, None)?;
        if binding.is_none() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "lend paired Pause action",
                "actual two-producer Source publication is unavailable",
            ));
        }
        Ok(binding)
    }

    /// Cleans old identity-only debt before a fresh producing operation enters.
    pub(super) fn settle_previous_action(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if self.parent_park_action.is_some() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "return previous action",
                "the typed Park owner still retains this request lifetime",
            ));
        }
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
        Option<crucible_qemu_protocol::boundary_action::ActionBinding>,
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
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if self.parent_park_action.is_some() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "return control action",
                "a control return cannot consume the retained Park request",
            ));
        }
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
    loan: Option<crucible_qemu_protocol::boundary_action::ActionBinding>,
) -> Result<(), QemuAsyncDriverRuntimeError> {
    if loan.is_some_and(|loan| {
        loan.park_request.is_some()
            || request.generation != loan.token
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
