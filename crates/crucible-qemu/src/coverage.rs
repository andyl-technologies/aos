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
}
