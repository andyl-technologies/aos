//! Owned mapped shared-memory adapter for QEMU quantum channels.

use crucible::{
    AppRandomDecision, BackendInput, ExecutionFingerprint, ExecutionHorizon, Icount,
    ObservableEvent, RngStreamId, SchedulerSendAuthorizer,
    observable_event_from_whitebox_marker_payload,
};
// crucible-lint: allow host-nondeterminism-state -- mapped callback records remain untrusted until scheduler validation.
use crucible::Decision;
use crucible_protocol::app_random_transport::{
    AppRandomDecisionTransportRecord, WHITEBOX_SHMEM_KIND_APP_RANDOM_DECISION,
    app_random_stream_name,
};
use crucible_protocol::guest_introspection::GuestIntrospectionRecord;
use crucible_protocol::{
    PluginBasicBlockCoverageObservation, WhiteboxDoorbellFrame, decode_whitebox_marker_payload,
};
use crucible_shmem::{
    FingerprintSample, GuestIntrospectionEntry, MappedDirectedRingMut, MappedNodeRingPairMut,
    MappedSetupRegion, SLOT_NET_ROUTER, STATUS_DONE,
};

use crate::{
    QemuAsyncQuantumCompletion, QemuBasicBlockCoverageBridge, QemuCoverageError, QemuInboundFrame,
    QemuNodeChannelError, QemuNodeEmittedFrame, QemuNodeIdleState, QemuNodePendingQuantum,
    QemuPendingQuantum, QemuQuantumError, QemuQuantumOperation, QemuQuantumShmemConfig,
    QemuQuantumShmemHotPath, QemuQuantumShmemView, QemuShmemHotPathChannel,
    assert_qemu_quantum_hot_path_is_shmem_only,
};

#[path = "mapped_quantum/error.rs"]
mod error;
#[path = "mapped_quantum/fault_commands.rs"]
mod fault_commands;
#[path = "mapped_quantum/preemption.rs"]
mod preemption;
pub use error::QemuMappedQuantumShmemHotPathError;

/// An owned, mapped shared-memory hot-path channel for one QEMU node.
pub struct QemuMappedQuantumShmemHotPath {
    config: QemuQuantumShmemConfig,
    region: MappedSetupRegion,
    next_router_inbound_sequence: u64,
    coverage_bridge: Option<QemuBasicBlockCoverageBridge>,
    next_coverage_sequence: u64,
    last_coverage_icount: Option<u64>,
    seen_coverage_map_indices: Vec<bool>,
    next_marker_sequence: u64,
    next_guest_introspection_request_sequence: u64,
    next_guest_introspection_response_sequence: u64,
    last_marker_icount: Option<u64>,
    pending_marker_events: Vec<ObservableEvent>,
    // crucible-lint: allow host-nondeterminism-state -- pending values cross only to the authoritative scheduler validator.
    pending_app_random_decisions: Vec<Decision>,
    send_authorizer: Box<dyn SchedulerSendAuthorizer>,
}

impl QemuMappedQuantumShmemHotPath {
    /// Arms the mapped slot for a quiesced VMState restore without waking QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the mapped hot path cannot be
    /// rebound or the restored counter is behind the slot's published counter.
    pub(crate) fn arm_vmstate_restore_ceiling(
        &mut self,
        restored_icount: u64,
    ) -> Result<(), QemuNodeChannelError> {
        self.with_hot_path("arm VMState restore ceiling", |hot_path| {
            hot_path
                .arm_vmstate_restore_ceiling(restored_icount)
                .map_err(QemuNodeChannelError::from)
        })
    }

    /// Arms an exact post-VMState logical-time reconstruction boundary.
    ///
    /// The caller must own a natively stopped QEMU process. This publishes the
    /// logical target, advances the request generation, and requests another
    /// plugin pause before QEMU is resumed for the reconstruction callback.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the slot is absent, another restore
    /// request is pending, or the pause wake cannot be published.
    pub(crate) fn arm_logical_time_restore_boundary(
        &mut self,
        target_icount: u64,
    ) -> Result<u32, QemuNodeChannelError> {
        let slot = self
            .region
            .node_slot(self.config.vm_slot)
            .map_err(|source| {
                QemuNodeChannelError::new("arm logical-time restore", source.to_string())
            })?;
        let generation = slot
            .arm_logical_time_restore(target_icount)
            .map_err(|source| {
                QemuNodeChannelError::new("arm logical-time restore", source.to_string())
            })?;
        self.region
            .header()
            .request_pause([slot])
            .map_err(|source| {
                QemuNodeChannelError::new("request logical-time restore pause", source.to_string())
            })?;
        Ok(generation)
    }

    /// Tests whether the plugin acknowledged one exact logical-time restore boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the mapped slot is absent or an
    /// acknowledgement publishes inconsistent logical/raw state.
    pub(crate) fn logical_time_restore_boundary_acknowledged(
        &mut self,
        generation: u32,
        calibration: crate::QemuLogicalTimeCalibration,
    ) -> Result<bool, QemuNodeChannelError> {
        let snapshot = self
            .region
            .node_slot(self.config.vm_slot)
            .map_err(|source| {
                QemuNodeChannelError::new("observe logical-time restore", source.to_string())
            })?
            .snapshot();
        if snapshot.logical_time_restore_ack != generation {
            return Ok(false);
        }
        if snapshot.logical_time_restore_request != generation
            || snapshot.logical_time_restore_target != calibration.logical_icount
            || snapshot.current_icount != calibration.logical_icount
            || snapshot.idle_wake_icount != calibration.logical_icount
            || snapshot.status != crucible_shmem::STATUS_IDLE
            || snapshot.device_io_active != 0
            || snapshot.logical_time_raw_icount != calibration.raw_icount
        {
            return Err(QemuNodeChannelError::new(
                "observe logical-time restore",
                format!("acknowledgement {generation} carried inconsistent boundary: {snapshot:?}"),
            ));
        }
        Ok(true)
    }

    /// Clears the exact post-restore plugin pause while QEMU remains stopped.
    pub(crate) fn clear_logical_time_restore_pause(&mut self) {
        self.region.header().clear_pause();
    }

    /// Publishes the shared shutdown flag and wakes this VM slot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the configured slot
    /// is absent or its non-private futex wake fails.
    pub fn request_plugin_shutdown(&self) -> Result<(), QemuMappedQuantumShmemHotPathError> {
        let slot = self
            .region
            .node_slot(self.config.vm_slot)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?;
        self.region
            .header()
            .request_shutdown([slot])
            .map(|_wake| ())
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionControl { source })
    }

    /// Returns this VM's most recent plugin-published fingerprint sample.
    ///
    /// Reads the per-node fingerprint sample slot the plugin publishes at each
    /// scheduler boundary when launched with `fingerprint=on`, returning a
    /// tear-free snapshot. Returns `None` when the plugin has published no
    /// sample yet — for example when fingerprint sampling was left disabled.
    /// The read borrows `&self` and mutates nothing, so it is safe to call
    /// after `finish_quantum` while the slot is quiescent.
    ///
    /// # Errors
    ///
    /// Returns [`QemuMappedQuantumShmemHotPathError`] when the retained mapping
    /// no longer validates or the configured VM slot has no fingerprint segment.
    pub fn fingerprint_sample(
        &self,
    ) -> Result<Option<FingerprintSample>, QemuMappedQuantumShmemHotPathError> {
        self.region
            .fingerprint_sample(self.config.vm_slot)
            .map(|slot| slot.snapshot())
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })
    }

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
        let next_marker_sequence = region
            .whitebox_marker_ring_mut(config.vm_slot)
            .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?
            .header
            .read_index();
        Ok(Self {
            config,
            region,
            next_router_inbound_sequence: 0,
            coverage_bridge,
            next_coverage_sequence,
            last_coverage_icount: None,
            seen_coverage_map_indices,
            next_marker_sequence,
            next_guest_introspection_request_sequence: 1,
            next_guest_introspection_response_sequence: 1,
            last_marker_icount: None,
            pending_marker_events: Vec::new(),
            pending_app_random_decisions: Vec::new(),
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

    fn drain_markers_at_quantum_boundary(
        &mut self,
        boundary_icount: u64,
    ) -> Result<(), QemuNodeChannelError> {
        let node = self.config.node.clone();
        let ring = self
            .region
            .whitebox_marker_ring_mut(self.config.vm_slot)
            .map_err(|error| {
                QemuNodeChannelError::new("drain white-box markers", error.to_string())
            })?;
        if ring.header.read_index() != self.next_marker_sequence {
            return Err(QemuNodeChannelError::new(
                "drain white-box markers",
                format!(
                    "marker read sequence changed: expected {}, observed {}",
                    self.next_marker_sequence,
                    ring.header.read_index()
                ),
            ));
        }

        while let Some(entry) =
            ring.header
                .dequeue_whitebox_marker(ring.entries)
                .map_err(|error| {
                    QemuNodeChannelError::new("drain white-box markers", error.to_string())
                })?
        {
            let entry = entry.validate().map_err(|error| {
                QemuNodeChannelError::new("drain white-box markers", error.to_string())
            })?;
            if entry.current_icount() > boundary_icount {
                return Err(QemuNodeChannelError::new(
                    "drain white-box markers",
                    format!(
                        "marker icount {} exceeds completed quantum boundary {}",
                        entry.current_icount(),
                        boundary_icount
                    ),
                ));
            }
            if let Some(previous) = self.last_marker_icount
                && entry.current_icount() < previous
            {
                return Err(QemuNodeChannelError::new(
                    "drain white-box markers",
                    format!(
                        "marker icount regressed from {previous} to {}",
                        entry.current_icount()
                    ),
                ));
            }
            if entry.kind() == WHITEBOX_SHMEM_KIND_APP_RANDOM_DECISION {
                let record =
                    AppRandomDecisionTransportRecord::decode(entry.payload()).map_err(|error| {
                        QemuNodeChannelError::new("drain app-random decisions", error.to_string())
                    })?;
                self.pending_app_random_decisions
                    // crucible-lint: allow host-nondeterminism-state -- decoding does not admit the plugin conjecture as authoritative state.
                    .push(Decision::AppRandom(AppRandomDecision {
                        node: node.clone(),
                        stream: RngStreamId::from_name(app_random_stream_name(
                            &node.name,
                            record.stream_tag(),
                        )),
                        request_id: u64::from(record.request_id()),
                        width: record.width_bytes().saturating_mul(8),
                        value: record.value(),
                    }));
            } else {
                let frame =
                    WhiteboxDoorbellFrame::new(entry.kind(), entry.payload()).map_err(|error| {
                        QemuNodeChannelError::new("drain white-box markers", error.to_string())
                    })?;
                let payload = decode_whitebox_marker_payload(&frame).map_err(|error| {
                    QemuNodeChannelError::new("drain white-box markers", error.to_string())
                })?;
                let event = observable_event_from_whitebox_marker_payload(
                    Icount {
                        retired: entry.current_icount(),
                    },
                    node.clone(),
                    &payload,
                )
                .ok_or_else(|| {
                    QemuNodeChannelError::new(
                        "drain white-box markers",
                        format!(
                            "marker kind {} is not observational and cannot enter the marker ring",
                            entry.kind()
                        ),
                    )
                })?;
                self.pending_marker_events.push(event);
            }
            self.last_marker_icount = Some(entry.current_icount());
            self.next_marker_sequence =
                self.next_marker_sequence.checked_add(1).ok_or_else(|| {
                    QemuNodeChannelError::new(
                        "drain white-box markers",
                        "marker sequence overflowed",
                    )
                })?;
        }
        Ok(())
    }
}

impl QemuShmemHotPathChannel for QemuMappedQuantumShmemHotPath {
    fn checkpoint_network_transport(
        &mut self,
    ) -> Result<crate::QemuNetworkTransportCheckpoint, QemuNodeChannelError> {
        let router_slot = SLOT_NET_ROUTER as u32;
        let pair = self
            .region
            .node_directed_ring_pair_mut(
                self.config.vm_slot,
                self.config.vm_slot,
                router_slot,
                router_slot,
                self.config.vm_slot,
            )
            .map_err(|error| {
                QemuNodeChannelError::new("checkpoint network transport", error.to_string())
            })?;
        let outbound = pair
            .first
            .header
            .snapshot(pair.first.entries)
            .map_err(|error| {
                QemuNodeChannelError::new("checkpoint network outbound ring", error.to_string())
            })?;
        let inbound = pair
            .second
            .header
            .snapshot(pair.second.entries)
            .map_err(|error| {
                QemuNodeChannelError::new("checkpoint network inbound ring", error.to_string())
            })?;
        Ok(crate::QemuNetworkTransportCheckpoint {
            inbound,
            outbound,
            next_router_inbound_sequence: self.next_router_inbound_sequence,
            next_host_outbound_sequence: 0,
            next_plugin_outbound_sequence: 0,
        })
    }

    fn restore_network_transport(
        &mut self,
        checkpoint: &crate::QemuNetworkTransportCheckpoint,
    ) -> Result<(), QemuNodeChannelError> {
        let router_slot = SLOT_NET_ROUTER as u32;
        let pair = self
            .region
            .node_directed_ring_pair_mut(
                self.config.vm_slot,
                self.config.vm_slot,
                router_slot,
                router_slot,
                self.config.vm_slot,
            )
            .map_err(|error| {
                QemuNodeChannelError::new("restore network transport", error.to_string())
            })?;
        let prior_outbound = pair
            .first
            .header
            .snapshot(pair.first.entries)
            .map_err(|error| {
                QemuNodeChannelError::new("snapshot prior network outbound ring", error.to_string())
            })?;
        pair.first
            .header
            .restore(pair.first.entries, &checkpoint.outbound)
            .map_err(|error| {
                QemuNodeChannelError::new("restore network outbound ring", error.to_string())
            })?;
        if let Err(error) = pair
            .second
            .header
            .restore(pair.second.entries, &checkpoint.inbound)
        {
            pair.first
                .header
                .restore(pair.first.entries, &prior_outbound)
                .map_err(|rollback| {
                    QemuNodeChannelError::new(
                        "roll back network outbound ring",
                        rollback.to_string(),
                    )
                })?;
            return Err(QemuNodeChannelError::new(
                "restore network inbound ring",
                error.to_string(),
            ));
        }
        self.next_router_inbound_sequence = checkpoint.next_router_inbound_sequence;
        Ok(())
    }

    fn send_guest_introspection(
        &mut self,
        record: GuestIntrospectionRecord,
    ) -> Result<(), QemuNodeChannelError> {
        record.validate_host_request().map_err(|error| {
            QemuNodeChannelError::new("validate guest introspection request", error.to_string())
        })?;
        let encoded = record.encode().map_err(|error| {
            QemuNodeChannelError::new("encode guest introspection request", error.to_string())
        })?;
        let following_sequence = self
            .next_guest_introspection_request_sequence
            .checked_add(1)
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "enqueue guest introspection request",
                    "request sequence overflow",
                )
            })?;
        let entry =
            GuestIntrospectionEntry::new(self.next_guest_introspection_request_sequence, &encoded)
                .map_err(|error| {
                    QemuNodeChannelError::new("encode guest introspection entry", error.to_string())
                })?;
        self.region
            .host_guest_introspection_rings_mut(self.config.vm_slot)
            .map_err(|error| {
                QemuNodeChannelError::new("map guest introspection request ring", error.to_string())
            })?
            .requests
            .enqueue(entry)
            .map_err(|error| {
                QemuNodeChannelError::new("enqueue guest introspection request", error.to_string())
            })?;
        self.next_guest_introspection_request_sequence = following_sequence;
        Ok(())
    }

    fn receive_guest_introspection(
        &mut self,
    ) -> Result<Option<GuestIntrospectionRecord>, QemuNodeChannelError> {
        let entry = self
            .region
            .host_guest_introspection_rings_mut(self.config.vm_slot)
            .map_err(|error| {
                QemuNodeChannelError::new(
                    "map guest introspection response ring",
                    error.to_string(),
                )
            })?
            .responses
            .dequeue()
            .map_err(|error| {
                QemuNodeChannelError::new("dequeue guest introspection response", error.to_string())
            })?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        if entry.sequence() != self.next_guest_introspection_response_sequence {
            return Err(QemuNodeChannelError::new(
                "dequeue guest introspection response",
                format!(
                    "response sequence mismatch: expected {}, actual {}",
                    self.next_guest_introspection_response_sequence,
                    entry.sequence()
                ),
            ));
        }
        let following_sequence = self
            .next_guest_introspection_response_sequence
            .checked_add(1)
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "dequeue guest introspection response",
                    "response sequence overflow",
                )
            })?;
        let record = GuestIntrospectionRecord::decode(entry.record().map_err(|error| {
            QemuNodeChannelError::new("decode guest introspection entry", error.to_string())
        })?)
        .map_err(|error| {
            QemuNodeChannelError::new("decode guest introspection response", error.to_string())
        })?;
        record.validate_guest_response().map_err(|error| {
            QemuNodeChannelError::new("validate guest introspection response", error.to_string())
        })?;
        self.next_guest_introspection_response_sequence = following_sequence;
        Ok(Some(record))
    }

    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
        self.with_hot_path("current_icount", |hot_path| {
            QemuShmemHotPathChannel::current_icount(hot_path)
        })
    }

    fn logical_time_calibration(
        &mut self,
    ) -> Result<crate::QemuLogicalTimeCalibration, QemuNodeChannelError> {
        self.with_hot_path("logical-time calibration", |hot_path| {
            QemuShmemHotPathChannel::logical_time_calibration(hot_path)
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

    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        let pending = pending.downcast_mut::<QemuMappedPendingQuantum>("finish_quantum")?;
        self.with_hot_path("finish_quantum", |hot_path| {
            let mut report = QemuQuantumShmemHotPath::poll_quantum(hot_path, &pending.pending)
                .map_err(QemuNodeChannelError::from)?;
            let mut operations = pending.start_operations.clone();
            operations.extend(report.operations);
            report.operations = operations;
            assert_qemu_quantum_hot_path_is_shmem_only(&report.operations)
                .map_err(QemuNodeChannelError::from)?;
            Ok(QemuAsyncQuantumCompletion::from(report))
        })
    }

    fn publish_preemption_command(
        &mut self,
        command: crucible_shmem::SchedulerPreemptionCommand,
    ) -> Result<(), QemuNodeChannelError> {
        QemuMappedQuantumShmemHotPath::publish_preemption_command(self, command)
            .map(|_| ())
            .map_err(|source| source.into_channel_error("publish_preemption_command"))
    }

    fn enqueue_fault_command(
        &mut self,
        header: crucible_shmem::FaultCommandHeaderV1,
        payload: &[u8],
    ) -> Result<(), QemuNodeChannelError> {
        QemuMappedQuantumShmemHotPath::enqueue_fault_command(self, header, payload)
            .map_err(|source| source.into_channel_error("enqueue_fault_command"))
    }

    fn dequeue_fault_result(
        &mut self,
    ) -> Result<Option<crucible_shmem::DequeuedFaultResult>, QemuNodeChannelError> {
        QemuMappedQuantumShmemHotPath::dequeue_fault_result(self)
            .map_err(|source| source.into_channel_error("dequeue_fault_result"))
    }

    fn dequeue_fault_event(
        &mut self,
    ) -> Result<Option<crucible_shmem::DequeuedFaultEvent>, QemuNodeChannelError> {
        QemuMappedQuantumShmemHotPath::dequeue_fault_event(self)
            .map_err(|source| source.into_channel_error("dequeue_fault_event"))
    }

    fn fault_event_pending(&mut self) -> Result<bool, QemuNodeChannelError> {
        QemuMappedQuantumShmemHotPath::fault_event_pending(self)
            .map_err(|source| source.into_channel_error("fault_event_pending"))
    }

    fn coverage_enabled(&self) -> bool {
        self.coverage_bridge.is_some()
    }

    fn drain_observable_events(&mut self) -> Result<Vec<ObservableEvent>, QemuNodeChannelError> {
        let boundary_icount = self.with_hot_path("observation boundary", |hot_path| {
            Ok(hot_path.node_snapshot().current_icount)
        })?;
        let mut events = self.drain_coverage_at_quantum_boundary(boundary_icount)?;
        self.drain_markers_at_quantum_boundary(boundary_icount)?;
        events.append(&mut self.pending_marker_events);
        events.sort_by_key(ObservableEvent::at);
        Ok(events)
    }

    // crucible-lint: allow host-nondeterminism-state -- callers must validate this untrusted causal batch before another quantum.
    fn drain_causal_decisions(&mut self) -> Result<Vec<Decision>, QemuNodeChannelError> {
        let boundary_icount = self.with_hot_path("causal boundary", |hot_path| {
            Ok(hot_path.node_snapshot().current_icount)
        })?;
        self.drain_markers_at_quantum_boundary(boundary_icount)?;
        Ok(std::mem::take(&mut self.pending_app_random_decisions))
    }

    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
        let delivery_icount = self.with_hot_path("delivery icount", |hot_path| {
            Ok(Icount {
                retired: hot_path.node_snapshot().current_icount.saturating_add(1),
            })
        })?;
        self.deliver_frame_at(input, delivery_icount)
    }

    fn deliver_frame_at(
        &mut self,
        // crucible-lint: allow host-nondeterminism-state -- the scheduler-selected timestamp is validated before this untrusted transport write.
        input: BackendInput,
        delivery_icount: Icount,
    ) -> Result<(), QemuNodeChannelError> {
        let sequence = self.next_router_inbound_sequence()?;
        let router_slot = self.config.router_slot;
        let payload = input.payload;
        self.with_hot_path("deliver_frame", move |hot_path| {
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
        let current_icount = self.with_hot_path("execution_fingerprint", |hot_path| {
            Ok(hot_path.node_snapshot().current_icount)
        })?;
        let sample = QemuMappedQuantumShmemHotPath::fingerprint_sample(self)
            .map_err(|source| {
                QemuNodeChannelError::new("execution_fingerprint", source.to_string())
            })?
            .ok_or_else(|| {
                QemuNodeChannelError::retryable(
                    "execution_fingerprint",
                    "the plugin has not published a black-box fingerprint sample",
                )
            })?;
        if sample.sample_icount < current_icount {
            return Err(QemuNodeChannelError::retryable(
                "execution_fingerprint",
                format!(
                    "black-box fingerprint sample at icount {} is behind current boundary {current_icount}",
                    sample.sample_icount
                ),
            ));
        }
        if sample.sample_icount != current_icount {
            return Err(QemuNodeChannelError::new(
                "execution_fingerprint",
                format!(
                    "black-box fingerprint sample at icount {} is ahead of current boundary {current_icount}",
                    sample.sample_icount
                ),
            ));
        }
        black_box_execution_fingerprint(&self.config.node, &sample)
    }

    fn fingerprint_sample(&mut self) -> Result<FingerprintSample, QemuNodeChannelError> {
        QemuMappedQuantumShmemHotPath::fingerprint_sample(self)
            .map_err(|source| QemuNodeChannelError::new("fingerprint_sample", source.to_string()))?
            .ok_or_else(|| {
                QemuNodeChannelError::retryable(
                    "fingerprint_sample",
                    "the plugin has not published a black-box fingerprint sample",
                )
            })
    }
}

const BLACK_BOX_EXECUTION_FINGERPRINT_DOMAIN: &str =
    "crucible.qemu.black-box-execution-fingerprint.v1";

pub(crate) fn black_box_execution_fingerprint(
    node: &crucible::NodeId,
    sample: &FingerprintSample,
) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
    sample
        .validate()
        .map_err(|source| QemuNodeChannelError::new("execution_fingerprint", source.to_string()))?;
    if sample.component_failures != 0 {
        return Err(QemuNodeChannelError::new(
            "execution_fingerprint",
            format!(
                "black-box fingerprint sample has component failure mask {:#x}",
                sample.component_failures
            ),
        ));
    }
    if sample.vcpu_count == 0 {
        return Err(QemuNodeChannelError::new(
            "execution_fingerprint",
            "black-box fingerprint sample contains no vCPU state",
        ));
    }

    let mut material = vec![
        format!("node={}", node.name),
        format!("sample_icount={}", sample.sample_icount),
        format!("vcpu_count={}", sample.vcpu_count),
        format!("rr_current_vcpu={}", sample.rr_current_vcpu),
        format!("rr_position_in_quantum={}", sample.rr_position_in_quantum),
        format!("rr_switch_quantum={}", sample.rr_switch_quantum),
    ];
    for (index, vcpu) in sample
        .vcpus
        .iter()
        .take(sample.vcpu_count as usize)
        .enumerate()
    {
        material.push(format!(
            "vcpu[{index}].register_digest={}",
            lowercase_hex(&vcpu.register_digest)
        ));
        material.push(format!(
            "vcpu[{index}].register_file_bytes={}",
            vcpu.register_file_bytes
        ));
        material.push(format!(
            "vcpu[{index}].retired_instruction_count={}",
            vcpu.retired_instruction_count
        ));
    }
    material.extend([
        format!("ram_bytes={}", sample.ram_bytes),
        format!("ram_digest={}", lowercase_hex(&sample.ram_digest)),
        format!("device_state_bytes={}", sample.device_state_bytes),
        format!(
            "device_state_digest={}",
            lowercase_hex(&sample.device_state_digest)
        ),
        format!(
            "device_state_schema_digest={}",
            lowercase_hex(&sample.device_state_schema_digest)
        ),
    ]);
    Ok(ExecutionFingerprint {
        hash: crucible::ContentHash::from_canonical_material(
            BLACK_BOX_EXECUTION_FINGERPRINT_DOMAIN,
            &material.join("\n"),
        ),
    })
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[derive(Debug)]
struct QemuMappedPendingQuantum {
    pending: QemuPendingQuantum,
    start_operations: Vec<QemuQuantumOperation>,
}

mod support;

use support::*;

#[cfg(test)]
mod fingerprint_tests {
    #![allow(clippy::unwrap_used)]

    use crucible_shmem::{FingerprintSample, FingerprintSampleVcpu};

    use super::*;

    fn sample() -> FingerprintSample {
        let mut sample = FingerprintSample {
            sample_icount: 41,
            vcpu_count: 1,
            rr_current_vcpu: 0,
            rr_position_in_quantum: 41,
            rr_switch_quantum: 4096,
            component_failures: 0,
            ram_bytes: 4096,
            ram_digest: [0x11; 32],
            device_state_bytes: 512,
            device_state_digest: [0x22; 32],
            device_state_schema_digest: [0x33; 32],
            ..FingerprintSample::default()
        };
        sample.vcpus[0] = FingerprintSampleVcpu {
            register_digest: [0x44; 32],
            register_file_bytes: 256,
            retired_instruction_count: 0,
        };
        sample
    }

    #[test]
    fn black_box_fingerprint_covers_live_register_ram_and_device_state() {
        let node = crucible::NodeId {
            name: String::from("vm-a"),
        };
        let baseline = black_box_execution_fingerprint(&node, &sample()).unwrap();

        let mut changed = sample();
        changed.vcpus[0].register_digest[0] ^= 1;
        assert_ne!(
            baseline,
            black_box_execution_fingerprint(&node, &changed).unwrap()
        );
        changed = sample();
        changed.ram_digest[0] ^= 1;
        assert_ne!(
            baseline,
            black_box_execution_fingerprint(&node, &changed).unwrap()
        );
        changed = sample();
        changed.device_state_digest[0] ^= 1;
        assert_ne!(
            baseline,
            black_box_execution_fingerprint(&node, &changed).unwrap()
        );
    }

    #[test]
    fn black_box_fingerprint_excludes_unused_vcpu_slots() {
        let node = crucible::NodeId {
            name: String::from("vm-a"),
        };
        let baseline = black_box_execution_fingerprint(&node, &sample()).unwrap();
        let mut changed = sample();
        changed.vcpus[1].register_digest = [0xff; 32];
        assert_eq!(
            baseline,
            black_box_execution_fingerprint(&node, &changed).unwrap()
        );
    }

    #[test]
    fn black_box_fingerprint_rejects_incomplete_samples() {
        let node = crucible::NodeId {
            name: String::from("vm-a"),
        };
        let mut failed = sample();
        failed.component_failures = 1;
        assert!(black_box_execution_fingerprint(&node, &failed).is_err());

        let mut empty = sample();
        empty.vcpu_count = 0;
        assert!(black_box_execution_fingerprint(&node, &empty).is_err());
    }
}
