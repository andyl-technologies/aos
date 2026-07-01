//! Host-side bridge for plugin basic-block coverage observations.
//!
//! The QEMU plugin emits black-box TCG-exec coverage as protocol data. This
//! module binds that protocol payload to the engine-side coverage consumer and
//! keeps the coverage-on/off switch out of the execution-fingerprint stream.

use crucible::{
    BasicBlockCoverageConfig, BasicBlockCoverageConsumer, BasicBlockCoverageError,
    BasicBlockCoverageRegistrationPlan, ConsumedBasicBlockCoverage, Icount, NodeId,
    TcgExecBasicBlock,
};
use crucible_protocol::PluginBasicBlockCoverageObservation;
use thiserror::Error;

use crate::{
    QemuLaunchPluginConfig, QemuLaunchPluginSwitch, SingleVmFingerprintMismatch,
    SingleVmFingerprintStream, compare_single_vm_fingerprint_streams,
};

/// Host-side bridge from plugin coverage protocol observations to engine events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuBasicBlockCoverageBridge {
    consumer: BasicBlockCoverageConsumer,
}

impl QemuBasicBlockCoverageBridge {
    /// Builds a bridge from the engine coverage config for one node.
    ///
    /// # Errors
    ///
    /// Returns [`QemuCoverageError`] when coverage is disabled or configured with
    /// an invalid map size.
    pub fn new(node: NodeId, config: BasicBlockCoverageConfig) -> Result<Self, QemuCoverageError> {
        Self::from_registration_plan(node, config.registration_plan()?)
    }

    /// Builds a bridge from an already computed engine registration plan.
    ///
    /// # Errors
    ///
    /// Returns [`QemuCoverageError`] when coverage is disabled.
    pub fn from_registration_plan(
        node: NodeId,
        plan: BasicBlockCoverageRegistrationPlan,
    ) -> Result<Self, QemuCoverageError> {
        Ok(Self {
            consumer: plan.require_consumer(node)?,
        })
    }

    /// Returns the engine consumer token owned by this bridge.
    #[must_use]
    pub const fn consumer(&self) -> &BasicBlockCoverageConsumer {
        &self.consumer
    }

    /// Consumes one plugin protocol coverage observation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuCoverageError`] when the engine consumer rejects the block,
    /// the plugin map index cannot fit on this host, or the plugin and engine map
    /// folds disagree.
    pub fn consume_plugin_observation(
        &self,
        observation: PluginBasicBlockCoverageObservation,
    ) -> Result<ConsumedBasicBlockCoverage, QemuCoverageError> {
        let consumed = self
            .consumer
            .consume_tcg_exec_block(TcgExecBasicBlock::new(
                Icount {
                    retired: observation.current_icount(),
                },
                observation.guest_pc(),
                observation.block_len(),
            ))?;
        let plugin_map_index = usize::try_from(observation.map_index()).map_err(|_error| {
            QemuCoverageError::PluginMapIndexTooLarge {
                map_index: observation.map_index(),
            }
        })?;
        if plugin_map_index != consumed.map_index() {
            return Err(QemuCoverageError::PluginMapIndexMismatch {
                plugin_map_index,
                engine_map_index: consumed.map_index(),
            });
        }
        Ok(consumed)
    }
}

/// One single-VM fingerprint run paired with its plugin coverage switch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuCoverageFingerprintRun {
    plugin: QemuLaunchPluginConfig,
    stream: SingleVmFingerprintStream,
}

impl QemuCoverageFingerprintRun {
    /// Builds one coverage-mode fingerprint run descriptor.
    #[must_use]
    pub fn new(plugin: QemuLaunchPluginConfig, stream: SingleVmFingerprintStream) -> Self {
        Self { plugin, stream }
    }

    /// Returns the plugin launch config used by this run.
    #[must_use]
    pub const fn plugin(&self) -> &QemuLaunchPluginConfig {
        &self.plugin
    }

    /// Returns the canonical single-VM fingerprint stream for this run.
    #[must_use]
    pub const fn fingerprint_stream(&self) -> &SingleVmFingerprintStream {
        &self.stream
    }

    /// Returns the exact plugin argument used by this run.
    #[must_use]
    pub fn plugin_argument(&self) -> String {
        self.plugin.qemu_plugin_argument()
    }
}

/// Result of comparing coverage-off and coverage-on fingerprint runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuCoverageFingerprintReport {
    /// Shared final fingerprint bytes after proving both streams equal.
    pub matching_final_fingerprint: Vec<u8>,
    /// Plugin argument used by the coverage-off run.
    pub off_plugin_argument: String,
    /// Plugin argument used by the coverage-on run.
    pub on_plugin_argument: String,
}

/// Compares coverage-off and coverage-on runs through the single-VM fingerprint.
///
/// # Errors
///
/// Returns [`QemuCoverageError`] when the run descriptors do not represent the
/// same launch except for the coverage switch, or when the fingerprint streams
/// differ.
pub fn compare_coverage_opt_in_fingerprint_streams(
    off: &QemuCoverageFingerprintRun,
    on: &QemuCoverageFingerprintRun,
    run_horizon_icount: u64,
) -> Result<QemuCoverageFingerprintReport, QemuCoverageError> {
    validate_coverage_pair(off.plugin(), on.plugin())?;
    compare_single_vm_fingerprint_streams(
        off.fingerprint_stream(),
        on.fingerprint_stream(),
        run_horizon_icount,
    )
    .map_err(|source| QemuCoverageError::FingerprintMismatch { source })?;
    Ok(QemuCoverageFingerprintReport {
        matching_final_fingerprint: off.fingerprint_stream().final_fingerprint.clone(),
        off_plugin_argument: off.plugin_argument(),
        on_plugin_argument: on.plugin_argument(),
    })
}

fn validate_coverage_pair(
    off: &QemuLaunchPluginConfig,
    on: &QemuLaunchPluginConfig,
) -> Result<(), QemuCoverageError> {
    if off.coverage() != QemuLaunchPluginSwitch::Off {
        return Err(QemuCoverageError::InvalidCoveragePair {
            reason: "first run must have coverage=off",
        });
    }
    if on.coverage() != QemuLaunchPluginSwitch::On {
        return Err(QemuCoverageError::InvalidCoveragePair {
            reason: "second run must have coverage=on",
        });
    }
    if off.plugin_path() != on.plugin_path()
        || off.slot() != on.slot()
        || off.whitebox() != on.whitebox()
        || off.inherited_fds() != on.inherited_fds()
    {
        return Err(QemuCoverageError::InvalidCoveragePair {
            reason: "coverage comparison runs may differ only by the coverage switch",
        });
    }
    Ok(())
}

/// An error produced by QEMU basic-block coverage bridging.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuCoverageError {
    /// The engine coverage consumer rejected the observation.
    #[error("engine coverage consumer rejected plugin observation: {source}")]
    Engine {
        /// Engine coverage error.
        #[from]
        source: BasicBlockCoverageError,
    },
    /// The plugin map index cannot be represented on this host.
    #[error("plugin coverage map index {map_index} does not fit in usize")]
    PluginMapIndexTooLarge {
        /// Rejected plugin map index.
        map_index: u64,
    },
    /// The plugin and engine computed different map indexes.
    #[error(
        "plugin coverage map index {plugin_map_index} differs from engine index {engine_map_index}"
    )]
    PluginMapIndexMismatch {
        /// Map index reported by the plugin.
        plugin_map_index: usize,
        /// Map index computed by the engine.
        engine_map_index: usize,
    },
    /// Coverage-off and coverage-on run descriptors are not comparable.
    #[error("invalid coverage fingerprint comparison: {reason}")]
    InvalidCoveragePair {
        /// Rejection reason.
        reason: &'static str,
    },
    /// Coverage-off and coverage-on streams produced different fingerprints.
    #[error("coverage opt-in changed the execution fingerprint: {source}")]
    FingerprintMismatch {
        /// Single-VM fingerprint mismatch.
        source: SingleVmFingerprintMismatch,
    },
}
