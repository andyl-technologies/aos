//! Worker-local observation before an actual console RUN can be continued.
//!
//! The probe is present only in libtest and preserves the worker's result.
//! QMP sampling and host allocation are deliberately outside performance runs.

use std::sync::{Arc, Mutex};

use crucible::{
    BackendError, BackendPhysicalStop, ConcurrentBackendRunOutcome, NativeConsoleByteOrigin,
    NodeCounter, NodeId, ObservableEventPayload, PreparedRunAdmission,
};

use crucible_protocol::native_console::{NativeConsoleAuthorization, NativeConsolePhase};

use super::QemuNodeSet;
use crate::QemuNode;

pub(crate) struct ConsoleSentinelProbe {
    node: NodeId,
    ready: NodeCounter,
    output: crate::spawn::ConsoleSentinelOutput,
    samples: Mutex<Vec<ConsoleSentinelSample>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ConsoleSentinelSample {
    pub(crate) byte: u8,
    pub(crate) accounted_ps: u64,
    pub(crate) origin: NativeConsoleByteOrigin,
    pub(crate) authorization: NativeConsoleAuthorization,
}

fn rejected(message: impl Into<String>) -> BackendError {
    BackendError::Rejected {
        message: message.into(),
    }
}

impl ConsoleSentinelProbe {
    pub(crate) fn new(
        node: NodeId,
        ready: NodeCounter,
        output: crate::spawn::ConsoleSentinelOutput,
    ) -> Arc<Self> {
        Arc::new(Self {
            node,
            ready,
            output,
            samples: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn observe(
        &self,
        node: &mut QemuNode,
        admission: &PreparedRunAdmission,
        completed: &ConcurrentBackendRunOutcome,
    ) -> Result<(), BackendError> {
        let BackendPhysicalStop::ConsoleOutput { sequence } = completed.step.physical_stop else {
            return Ok(());
        };
        if completed.node != self.node || admission.node() != &self.node {
            return Err(rejected(
                "sentinel probe lost its genuine node/RUN association",
            ));
        }
        let origin = completed
            .observations
            .iter()
            .filter_map(|event| match event.payload() {
                ObservableEventPayload::NativeConsoleByte { node, origin }
                    if node == &self.node =>
                {
                    Some(origin)
                }
                _ => None,
            })
            .last()
            .ok_or_else(|| rejected("real console stop has no accepted canonical origin"))?;
        if origin.node_sequence != sequence || origin.emitted_ps <= self.ready.ticks {
            return Err(rejected(
                "UART endpoint is not a post-Ready byte of this RUN",
            ));
        }

        let authorization = node.native_console_emission_for_test(sequence)?;
        if authorization.phase != NativeConsolePhase::Grant
            || authorization.logical_generation != origin.logical_generation
        {
            return Err(rejected(
                "accepted UART endpoint did not retain its genuine Grant body",
            ));
        }

        let before = node.current_icount()?;
        if before.retired != completed.step.reached.ticks {
            return Err(rejected(
                "stopped counter changed before fixed memory observation",
            ));
        }
        let byte = node
            .read_console_sentinel_for_test(&self.output)
            .map_err(|error| rejected(error.to_string()))?;
        let after = node.current_icount()?;
        if before != after {
            return Err(rejected(
                "stopped counter changed during fixed memory observation",
            ));
        }
        self.samples
            .lock()
            .map_err(|_| rejected("sentinel result custody was poisoned"))?
            .push(ConsoleSentinelSample {
                byte,
                accounted_ps: before.retired,
                origin: origin.clone(),
                authorization,
            });
        Ok(())
    }

    pub(crate) fn samples(&self) -> Result<Vec<ConsoleSentinelSample>, BackendError> {
        self.samples
            .lock()
            .map(|samples| samples.clone())
            .map_err(|_| rejected("sentinel result custody was poisoned"))
    }
}

impl QemuNodeSet {
    pub(crate) fn install_console_sentinel_probe_for_test(
        &mut self,
        probe: Arc<ConsoleSentinelProbe>,
    ) -> Result<(), BackendError> {
        if self.console_sentinel_probe.is_some() || !self.nodes.contains_key(&probe.node) {
            return Err(rejected(
                "sentinel probe requires one original installed node",
            ));
        }
        self.console_sentinel_probe = Some(probe);
        Ok(())
    }
}
