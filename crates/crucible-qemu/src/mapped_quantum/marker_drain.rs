//! White-box marker validation and canonical evidence staging.

use super::*;

impl QemuMappedQuantumShmemHotPath {
    pub(super) fn drain_markers_at_quantum_boundary(
        &mut self,
        boundary: NodeSlotSnapshot,
    ) -> Result<(), QemuNodeChannelError> {
        let boundary_icount = boundary.current_icount;
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
                let record = BackendRngEvidenceTransportRecord::decode(entry.payload()).map_err(
                    |error| {
                        QemuNodeChannelError::new("drain app-random decisions", error.to_string())
                    },
                )?;
                self.pending_rng_evidence.push(BackendRngEvidence {
                    node: node.clone(),
                    stream: RngStreamId::from_name(app_random_stream_name(
                        &node.name,
                        record.stream_tag(),
                    )),
                    request_id: u64::from(record.request_id()),
                    width: record.width_bytes().saturating_mul(8),
                    value: record.value(),
                });
            } else if entry.kind() == WHITEBOX_SHMEM_KIND_SELECTABLE_REGISTERED {
                let registration =
                    SelectableRegister::decode(entry.payload()).map_err(|error| {
                        QemuNodeChannelError::new(
                            "mirror selectable registration",
                            error.to_string(),
                        )
                    })?;
                if let Some(plan) = self.selectable_catalog_plan.as_mut() {
                    plan.apply_registration(&registration).map_err(|error| {
                        QemuNodeChannelError::new(
                            "mirror selectable registration",
                            error.to_string(),
                        )
                    })?;
                }
            } else if entry.kind() == WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING {
                if boundary.status != STATUS_IDLE
                    || boundary.idle_wake_icount != boundary.current_icount
                {
                    return Err(QemuNodeChannelError::new(
                        "drain selectable pending requests",
                        format!(
                            "pending selectable requires an exact quiesced boundary, observed status {} current icount {} idle wake icount {}",
                            boundary.status, boundary.current_icount, boundary.idle_wake_icount,
                        ),
                    ));
                }
                let record =
                    SelectablePendingTransportRecord::decode(entry.payload()).map_err(|error| {
                        QemuNodeChannelError::new(
                            "drain selectable pending requests",
                            error.to_string(),
                        )
                    })?;
                let expected_boundary_icount = entry
                    .current_icount()
                    .checked_add(SELECTABLE_NATIVE_HANDOFF_INSTRUCTIONS)
                    .ok_or_else(|| {
                        QemuNodeChannelError::new(
                            "drain selectable pending requests",
                            format!(
                                "selectable trap icount {} cannot represent its stopped boundary",
                                entry.current_icount()
                            ),
                        )
                    })?;
                if boundary_icount != expected_boundary_icount {
                    return Err(QemuNodeChannelError::new(
                        "drain selectable pending requests",
                        format!(
                            "selectable trap icount {} requires stopped boundary {expected_boundary_icount}, observed {boundary_icount}",
                            entry.current_icount()
                        ),
                    ));
                }
                let pending = SelectablePlanPendingRequest::new(
                    record.request().clone(),
                    entry.current_icount(),
                    entry.vcpu_index(),
                    record.guest_virtual_address(),
                );
                if let Some(plan) = self.selectable_catalog_plan.as_mut() {
                    plan.apply_pending_request(pending.clone())
                        .map_err(|error| {
                            QemuNodeChannelError::new(
                                "mirror selectable request",
                                error.to_string(),
                            )
                        })?;
                }
                self.pending_selectable_requests.push(pending);
            } else if entry.kind() == WHITEBOX_SHMEM_KIND_SELECTABLE_COMPLETED {
                let reply = SelectionReply::decode(entry.payload()).map_err(|error| {
                    QemuNodeChannelError::new("mirror selectable completion", error.to_string())
                })?;
                if self.queued_selectable_reply.as_ref() != Some(&reply) {
                    return Err(QemuNodeChannelError::new(
                        "mirror selectable completion",
                        "plugin completion differs from the exact queued reply",
                    ));
                }
                if let Some(plan) = self.selectable_catalog_plan.as_mut() {
                    plan.apply_completed_reply(&reply).map_err(|error| {
                        QemuNodeChannelError::new("mirror selectable completion", error.to_string())
                    })?;
                }
                self.queued_selectable_reply = None;
            } else {
                let frame =
                    WhiteboxDoorbellFrame::new(entry.kind(), entry.payload()).map_err(|error| {
                        QemuNodeChannelError::new("drain white-box markers", error.to_string())
                    })?;
                let payload = decode_whitebox_marker_payload(&frame).map_err(|error| {
                    QemuNodeChannelError::new("drain white-box markers", error.to_string())
                })?;
                if payload
                    == WhiteboxMarkerPayload::Lifecycle(
                        WhiteboxLifecycleMarkerEvent::SetupComplete,
                    )
                    && let Some(plan) = self.selectable_catalog_plan.as_mut()
                    && plan.continuation().phase()
                        == crucible_protocol::selectable_catalog_plan::SelectablePlanPhase::Registering
                {
                    plan.apply_freeze().map_err(|error| {
                        QemuNodeChannelError::new("mirror selectable freeze", error.to_string())
                    })?;
                }
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
