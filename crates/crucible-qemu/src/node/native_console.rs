//! Setup-owned console observation attached to the original scheduler RUN.
//!
//! The launch binds boot visibility after its genuine priming handoff. Each
//! concurrent RUN retains its original mapping before guest effects. Accepted
//! native byte custody stays in the same launch owner until observation drain.

use crucible::{BackendError, NodeCounter, NodeId, ObservableEvent, PreparedRunAdmission};

use super::QemuNode;
use crate::native_console_owner::ConsoleLaunchCustody;

pub(super) struct QemuNativeConsoleObservation {
    custody: ConsoleLaunchCustody,
    node: NodeId,
    ready_counter: Option<NodeCounter>,
}

impl QemuNativeConsoleObservation {
    pub(super) fn accepted_byte_tail(&self) -> Option<Vec<u8>> {
        self.custody.accepted_byte_tail()
    }

    pub(super) fn capture_origins(
        &self,
    ) -> Result<crate::native_console_owner::ConsoleOriginContinuation, super::QemuNodeChannelError>
    {
        let ready = self.ready_counter.ok_or_else(|| {
            super::QemuNodeChannelError::new(
                "capture child console origins",
                "ready visibility is absent",
            )
        })?;
        self.custody
            .checkpoint_origins(&self.node, ready)
            .map_err(|source| {
                super::QemuNodeChannelError::new(
                    "capture child console origins",
                    source.to_string(),
                )
            })
    }

    pub(super) fn from_restored(
        custody: ConsoleLaunchCustody,
        node: NodeId,
        ready_counter: NodeCounter,
    ) -> Self {
        Self {
            custody,
            node,
            ready_counter: Some(ready_counter),
        }
    }

    pub(super) fn checkpoint(&self) -> Result<Vec<u8>, super::QemuNodeError> {
        let ready = self.ready_counter.ok_or_else(|| {
            super::QemuNodeError::checkpoint("native console has no original ready visibility")
        })?;
        self.custody
            .checkpoint_origins(&self.node, ready)
            .and_then(|checkpoint| checkpoint.encode())
            .map_err(|source| super::QemuNodeError::checkpoint(source.to_string()))
    }

    pub(super) fn restore(&mut self, bytes: &[u8]) -> Result<(), super::QemuNodeError> {
        let saved = crate::native_console_owner::ConsoleOriginContinuation::decode(bytes)
            .map_err(|source| super::QemuNodeError::checkpoint(source.to_string()))?;
        self.ready_counter = Some(
            self.custody
                .restore_origins(&self.node, &saved)
                .map_err(|source| super::QemuNodeError::checkpoint(source.to_string()))?,
        );
        Ok(())
    }

    fn retain_run(&self, admission: &PreparedRunAdmission) -> Result<(), BackendError> {
        if admission.node() != &self.node || self.ready_counter.is_none() {
            return Err(BackendError::Rejected {
                message: String::from("native console has no matching original ready/RUN owner"),
            });
        }
        self.custody
            .retain_run_projection(admission)
            .map_err(|source| BackendError::Rejected {
                message: format!("retain original native console RUN projection: {source}"),
            })
    }

    pub(super) fn drain_observations(&self) -> Result<Vec<ObservableEvent>, BackendError> {
        let ready_counter = self.ready_counter.ok_or_else(|| BackendError::Rejected {
            message: String::from("native console has no original completed boot visibility"),
        })?;
        self.custody
            .drain_observations(&self.node, ready_counter)
            .map_err(|source| BackendError::Rejected {
                message: format!("project retained native console origins: {source}"),
            })
    }
}

impl QemuNode {
    #[cfg(test)]
    pub(crate) fn native_console_emission_for_test(
        &self,
        sequence: u64,
    ) -> Result<crucible_protocol::native_console::NativeConsoleAuthorization, BackendError> {
        let console = self
            .native_console
            .as_ref()
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("causal fixture has no actual console custody"),
            })?;
        console
            .custody
            .accepted_emission_for_test(sequence)
            .map_err(|error| BackendError::Rejected {
                message: error.to_string(),
            })?
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("causal endpoint has no successfully consumed emitting body"),
            })
    }

    #[cfg(test)]
    pub(crate) fn native_console_ready_counter_for_test(
        &self,
    ) -> Result<NodeCounter, BackendError> {
        self.native_console
            .as_ref()
            .and_then(|console| console.ready_counter)
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("causal fixture has no actual original console Ready owner"),
            })
    }

    pub(crate) fn with_native_console_custody(
        mut self,
        custody: Option<ConsoleLaunchCustody>,
        node: NodeId,
    ) -> Self {
        self.native_console = custody.map(|custody| QemuNativeConsoleObservation {
            custody,
            node,
            ready_counter: None,
        });
        self
    }

    /// Retains visibility only at the launch's original completed priming handoff.
    pub(crate) fn bind_native_console_ready_visibility(
        &mut self,
        completed_counter: NodeCounter,
    ) -> Result<(), BackendError> {
        if let Some(console) = &mut self.native_console {
            if console.ready_counter.is_some() {
                return Err(BackendError::Rejected {
                    message: String::from("native console ready visibility was already bound"),
                });
            }
            console.ready_counter = Some(completed_counter);
        }
        Ok(())
    }

    pub(crate) fn retain_native_console_run(
        &self,
        admission: &PreparedRunAdmission,
    ) -> Result<(), BackendError> {
        if let Some(console) = &self.native_console {
            console.retain_run(admission)?;
        }
        Ok(())
    }
}
