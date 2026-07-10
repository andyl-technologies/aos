//! Owned mapped shared-memory adapter for QEMU quantum channels.

use crucible::{
    BackendInput, ExecutionFingerprint, ExecutionHorizon, Icount, ObservableEvent,
    SchedulerSendAuthorizer,
};
use crucible_protocol::PluginBasicBlockCoverageObservation;
use crucible_shmem::{
    MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError,
    STATUS_DONE,
};
use thiserror::Error;

use crate::{
    QemuAsyncQuantumCompletion, QemuBasicBlockCoverageBridge, QemuCoverageError, QemuInboundFrame,
    QemuNodeChannelError, QemuNodeEmittedFrame, QemuNodeIdleState, QemuNodePendingQuantum,
    QemuPendingQuantum, QemuQuantumError, QemuQuantumOperation, QemuQuantumShmemConfig,
    QemuQuantumShmemHotPath, QemuQuantumShmemView, QemuShmemHotPathChannel,
    assert_qemu_quantum_hot_path_is_shmem_only,
};

/// An owned, mapped shared-memory hot-path channel for one QEMU node.
pub struct QemuMappedQuantumShmemHotPath {
    config: QemuQuantumShmemConfig,
    region: MappedSetupRegion,
    next_router_inbound_sequence: u64,
    coverage_bridge: Option<QemuBasicBlockCoverageBridge>,
    next_coverage_sequence: u64,
    last_coverage_icount: Option<u64>,
    seen_coverage_map_indices: Vec<bool>,
    send_authorizer: Box<dyn SchedulerSendAuthorizer>,
}

impl QemuMappedQuantumShmemHotPath {
    /// Returns whether the plugin published terminal `Done` for this VM slot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the retained mapping
    /// no longer validates or the configured slot is absent.
    pub fn plugin_teardown_done(&self) -> Result<bool, QemuMappedQuantumShmemHotPathError> {
        self.region
            .node_slot(self.config.vm_slot)
            .map(|slot| slot.snapshot().status == STATUS_DONE)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })
    }

    /// Binds one QEMU quantum channel to an owned mapped shared-memory region.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the config uses an
    /// invalid fixed icount shift, the mapped region header or directed-ring
    /// topology is invalid, or the selected ring capacities cannot back the
    /// hot-path adapter.
    pub fn new(
        config: QemuQuantumShmemConfig,
        mut region: MappedSetupRegion,
        send_authorizer: impl SchedulerSendAuthorizer + 'static,
    ) -> Result<Self, QemuMappedQuantumShmemHotPathError> {
        validate_config(&config)?;
        {
            let _view = mapped_view(&mut region, &config)?;
        }
        let coverage_bridge = match config.coverage.registration_plan() {
            Ok(plan) if plan.requests_tcg_exec_coverage() => {
                let bridge =
                    QemuBasicBlockCoverageBridge::from_registration_plan(config.node.clone(), plan)
                        .map_err(|source| QemuMappedQuantumShmemHotPathError::Coverage {
                            source,
                        })?;
                let ring = region.coverage_ring_mut(config.vm_slot).map_err(|source| {
                    QemuMappedQuantumShmemHotPathError::RegionAccess { source }
                })?;
                if ring.entries.len() != bridge.consumer().map_entries() {
                    return Err(QemuMappedQuantumShmemHotPathError::CoverageQueueCapacity {
                        map_entries: bridge.consumer().map_entries(),
                        queue_capacity: ring.entries.len(),
                    });
                }
                Some(bridge)
            }
            Ok(_disabled) => None,
            Err(source) => {
                return Err(QemuMappedQuantumShmemHotPathError::Coverage {
                    source: QemuCoverageError::Engine { source },
                });
            }
        };
        let next_coverage_sequence = if coverage_bridge.is_some() {
            region
                .coverage_ring_mut(config.vm_slot)
                .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?
                .header
                .read_index()
        } else {
            0
        };
        let seen_coverage_map_indices = coverage_bridge.as_ref().map_or_else(Vec::new, |bridge| {
            vec![false; bridge.consumer().map_entries()]
        });
        Ok(Self {
            config,
            region,
            next_router_inbound_sequence: 0,
            coverage_bridge,
            next_coverage_sequence,
            last_coverage_icount: None,
            seen_coverage_map_indices,
            send_authorizer: Box::new(send_authorizer),
        })
    }

    fn with_hot_path<T>(
        &mut self,
        operation: &'static str,
        run: impl FnOnce(&mut QemuQuantumShmemHotPath<'_>) -> Result<T, QemuNodeChannelError>,
    ) -> Result<T, QemuNodeChannelError> {
        let Self {
            config,
            region,
            send_authorizer,
            ..
        } = self;
        let view =
            mapped_view(region, config).map_err(|source| source.into_channel_error(operation))?;
        let mut hot_path =
            QemuQuantumShmemHotPath::new(config.clone(), view, send_authorizer.as_ref())
                .map_err(QemuNodeChannelError::from)?;
        run(&mut hot_path)
    }

    fn next_router_inbound_sequence(&self) -> Result<u32, QemuNodeChannelError> {
        u32::try_from(self.next_router_inbound_sequence)
            .map_err(|_| QemuQuantumError::InboundSequenceOverflow {
                next_sequence: self.next_router_inbound_sequence,
            })
            .map_err(QemuNodeChannelError::from)
    }

    fn commit_router_inbound_sequence(&mut self) -> Result<(), QemuNodeChannelError> {
        self.next_router_inbound_sequence = self
            .next_router_inbound_sequence
            .checked_add(1)
            .ok_or(QemuQuantumError::InboundSequenceOverflow {
                next_sequence: self.next_router_inbound_sequence,
            })
            .map_err(QemuNodeChannelError::from)?;
        Ok(())
    }

    fn drain_coverage_at_quantum_boundary(
        &mut self,
        boundary_icount: u64,
    ) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
        let Some(bridge) = self.coverage_bridge.as_ref() else {
            return Ok(Vec::new());
        };
        let ring = self
            .region
            .coverage_ring_mut(self.config.vm_slot)
            .map_err(|error| QemuNodeChannelError::new("drain coverage", error.to_string()))?;
        if ring.header.read_index() != self.next_coverage_sequence {
            return Err(QemuNodeChannelError::new(
                "drain coverage",
                format!(
                    "coverage read sequence changed: expected {}, observed {}",
                    self.next_coverage_sequence,
                    ring.header.read_index()
                ),
            ));
        }

        let mut events = Vec::new();
        while let Some(entry) = ring
            .header
            .dequeue_coverage(ring.entries)
            .map_err(|error| QemuNodeChannelError::new("drain coverage", error.to_string()))?
        {
            let entry = entry
                .validate()
                .map_err(|error| QemuNodeChannelError::new("drain coverage", error.to_string()))?;
            if entry.current_icount() > boundary_icount {
                return Err(QemuNodeChannelError::new(
                    "drain coverage",
                    format!(
                        "coverage icount {} exceeds completed quantum boundary {}",
                        entry.current_icount(),
                        boundary_icount
                    ),
                ));
            }
            if let Some(previous) = self.last_coverage_icount
                && entry.current_icount() < previous
            {
                return Err(QemuNodeChannelError::new(
                    "drain coverage",
                    format!(
                        "coverage icount regressed from {previous} to {}",
                        entry.current_icount()
                    ),
                ));
            }
            let observation = PluginBasicBlockCoverageObservation::new(
                entry.current_icount(),
                entry.vcpu_index(),
                entry.guest_pc(),
                entry.block_len(),
                entry.map_index(),
                true,
            )
            .map_err(|error| QemuNodeChannelError::new("drain coverage", error.to_string()))?;
            let map_index = usize::try_from(entry.map_index()).map_err(|_error| {
                QemuNodeChannelError::new(
                    "drain coverage",
                    format!(
                        "coverage map index {} does not fit usize",
                        entry.map_index()
                    ),
                )
            })?;
            let host_map_entries = self.seen_coverage_map_indices.len();
            let Some(was_seen) = self.seen_coverage_map_indices.get_mut(map_index) else {
                return Err(QemuNodeChannelError::new(
                    "drain coverage",
                    format!(
                        "coverage map index {map_index} is outside {} host entries",
                        host_map_entries
                    ),
                ));
            };
            if *was_seen {
                return Err(QemuNodeChannelError::new(
                    "drain coverage",
                    format!("coverage map index {map_index} was published more than once"),
                ));
            }
            let consumed = bridge
                .consume_plugin_observation(observation)
                .map_err(|error| QemuNodeChannelError::new("drain coverage", error.to_string()))?;
            events.push(consumed.into_event());
            *was_seen = true;
            self.last_coverage_icount = Some(entry.current_icount());
            self.next_coverage_sequence =
                self.next_coverage_sequence.checked_add(1).ok_or_else(|| {
                    QemuNodeChannelError::new("drain coverage", "coverage sequence overflowed")
                })?;
        }
        Ok(events)
    }
}

impl QemuShmemHotPathChannel for QemuMappedQuantumShmemHotPath {
    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
        self.with_hot_path("current_icount", |hot_path| {
            QemuShmemHotPathChannel::current_icount(hot_path)
        })
    }

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
        self.with_hot_path("start_quantum", |hot_path| {
            let pending = QemuQuantumShmemHotPath::start_quantum(hot_path, horizon)
                .map_err(QemuNodeChannelError::from)?;
            let start_operations = hot_path.operation_log().to_vec();
            assert_qemu_quantum_hot_path_is_shmem_only(&start_operations)
                .map_err(QemuNodeChannelError::from)?;
            Ok(QemuNodePendingQuantum::new(QemuMappedPendingQuantum {
                pending,
                start_operations,
            }))
        })
    }

    fn finish_quantum(
        &mut self,
        pending: QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        let pending = pending.downcast::<QemuMappedPendingQuantum>("finish_quantum")?;
        self.with_hot_path("finish_quantum", |hot_path| {
            let mut report = QemuQuantumShmemHotPath::finish_quantum(hot_path, pending.pending)
                .map_err(QemuNodeChannelError::from)?;
            let mut operations = pending.start_operations;
            operations.extend(report.operations);
            report.operations = operations;
            assert_qemu_quantum_hot_path_is_shmem_only(&report.operations)
                .map_err(QemuNodeChannelError::from)?;
            Ok(QemuAsyncQuantumCompletion::from(report))
        })
    }

    fn coverage_enabled(&self) -> bool {
        self.coverage_bridge.is_some()
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
        let boundary_icount = self.with_hot_path("coverage teardown boundary", |hot_path| {
            Ok(hot_path.node_snapshot().current_icount)
        })?;
        self.drain_coverage_at_quantum_boundary(boundary_icount)
    }

    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
        let sequence = self.next_router_inbound_sequence()?;
        let router_slot = self.config.router_slot;
        let payload = input.payload;
        self.with_hot_path("deliver_frame", move |hot_path| {
            let delivery_icount = Icount {
                retired: hot_path.node_snapshot().current_icount.saturating_add(1),
            };
            hot_path
                .enqueue_inbound_frame(QemuInboundFrame {
                    delivery_icount,
                    src_node: router_slot,
                    sequence,
                    payload,
                })
                .map_err(QemuNodeChannelError::from)
        })?;
        self.commit_router_inbound_sequence()
    }

    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
        self.with_hot_path("emit_frame", |hot_path| {
            QemuShmemHotPathChannel::emit_frame(hot_path)
        })
    }

    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
        self.with_hot_path("idle_state", |hot_path| {
            QemuShmemHotPathChannel::idle_state(hot_path)
        })
    }

    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
        self.with_hot_path("execution_fingerprint", |hot_path| {
            QemuShmemHotPathChannel::execution_fingerprint(hot_path)
        })
    }
}

#[derive(Debug)]
struct QemuMappedPendingQuantum {
    pending: QemuPendingQuantum,
    start_operations: Vec<QemuQuantumOperation>,
}

/// An error produced while binding a mapped QEMU quantum hot path.
#[derive(Debug, Error)]
pub enum QemuMappedQuantumShmemHotPathError {
    /// The mapped shared-memory region could not expose the requested node rings.
    #[error("mapped QEMU quantum shared-memory access failed")]
    RegionAccess {
        /// Underlying mapped-region access error.
        source: MappedSetupRegionAccessError,
    },
    /// The borrowed quantum adapter rejected the selected view.
    #[error("mapped QEMU quantum hot-path binding failed")]
    Quantum {
        /// Underlying quantum hot-path error.
        source: QemuQuantumError,
    },
    /// Coverage policy or consumer construction failed.
    #[error("mapped QEMU coverage bridge configuration failed")]
    Coverage {
        /// Underlying coverage bridge error.
        source: QemuCoverageError,
    },
    /// The ABI queue cardinality differed from the configured coverage map.
    #[error("coverage map has {map_entries} entries but mapped queue has {queue_capacity}")]
    CoverageQueueCapacity {
        /// Engine map cardinality.
        map_entries: usize,
        /// Mapped queue cardinality.
        queue_capacity: usize,
    },
}

impl QemuMappedQuantumShmemHotPathError {
    fn into_channel_error(self, operation: &'static str) -> QemuNodeChannelError {
        QemuNodeChannelError::new(operation, self.to_string())
    }
}

fn validate_config(
    config: &QemuQuantumShmemConfig,
) -> Result<(), QemuMappedQuantumShmemHotPathError> {
    if config.shift_bits >= 64 {
        return Err(QemuMappedQuantumShmemHotPathError::Quantum {
            source: QemuQuantumError::InvalidShift {
                shift_bits: config.shift_bits,
            },
        });
    }
    Ok(())
}

fn mapped_view<'a>(
    region: &'a mut MappedSetupRegion,
    config: &QemuQuantumShmemConfig,
) -> Result<QemuQuantumShmemView<'a>, QemuMappedQuantumShmemHotPathError> {
    let pair = region
        .node_directed_ring_pair_mut(
            config.vm_slot,
            config.router_slot,
            config.vm_slot,
            config.vm_slot,
            config.router_slot,
        )
        .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?;
    let MappedNodeRingPairMut {
        node_slot,
        first,
        second,
    } = pair;
    let MappedDirectedRingMut {
        header: inbound_ring,
        entries: inbound_entries,
        ..
    } = first;
    let MappedDirectedRingMut {
        header: outbound_ring,
        entries: outbound_entries,
        ..
    } = second;
    QemuQuantumShmemView::new(
        node_slot,
        inbound_ring,
        inbound_entries,
        outbound_ring,
        outbound_entries,
    )
    .map_err(|source| QemuMappedQuantumShmemHotPathError::Quantum { source })
}
