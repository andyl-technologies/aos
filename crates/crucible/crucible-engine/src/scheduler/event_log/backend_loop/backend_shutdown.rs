//! Whole-world teardown and final causal evidence settlement.
//!
//! Failed or unresolved owners remain cleanup-only until actual backend
//! teardown succeeds; ordinary shutdown publishes only committed evidence.
//!
//! Settlement and teardown are separable: [`BackendQuantumLoop::drain_final_boundary`]
//! settles the committed boundary's evidence and leaves the world running, so
//! an owner can retain the world as a hot-fork template after proving that
//! nothing remained to settle. Shutdown performs the same settlement and then
//! tears the world down, so both paths publish identical entries.

use super::*;

/// Owner state that keeps the final boundary unsettled until teardown.
///
/// Ordinary shutdown discards this state through its cleanup-only path, so a
/// world holding any of it cannot be settled and kept running as a template.
/// Each variant names one condition and maps to a stable diagnostic token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalBoundaryRefusal {
    /// A failed settlement poisoned the physical continuation.
    PoisonedContinuation,
    /// A committed guest selectable stop awaits its authenticated host reply.
    HeldGuestSelectableStop,
    /// A committed campaign-marker stop awaits its atomic choice release.
    HeldCampaignMarkerStop,
    /// Physically completed peer RUNs remain private behind a network choice.
    HeldPeerEvidence,
    /// A fixed host input remains staged for the next RUN.
    PendingFixedInput,
    /// A device-group selection remains retained for publication.
    RetainedDeviceGroupSelection,
    /// A live World-network choice reservation remains unresolved.
    LiveNetworkPreselection,
}

impl FinalBoundaryRefusal {
    /// Returns the stable kebab-case token naming this refusal in diagnostics.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::PoisonedContinuation => "poisoned-continuation",
            Self::HeldGuestSelectableStop => "held-guest-selectable-stop",
            Self::HeldCampaignMarkerStop => "held-campaign-marker-stop",
            Self::HeldPeerEvidence => "held-peer-evidence",
            Self::PendingFixedInput => "pending-fixed-input",
            Self::RetainedDeviceGroupSelection => "retained-device-group-selection",
            Self::LiveNetworkPreselection => "live-network-preselection",
        }
    }
}

/// Settlement of the final committed boundary, before teardown.
struct FinalBoundarySettlement {
    network: Result<Vec<SchedulerEventLogEntry>, BackendError>,
    decisions: Result<(), SchedulerError>,
    observations: Result<Vec<SchedulerEventLogEntry>, BackendError>,
}

impl FinalBoundarySettlement {
    /// Returns the settled entries in publication order, or the first error.
    fn into_entries(self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let mut entries = self.network.map_err(SchedulerError::from)?;
        self.decisions?;
        entries.extend(self.observations.map_err(SchedulerError::from)?);
        Ok(entries)
    }
}

impl<L, B, I> BackendQuantumLoop<L, B, I>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    /// Settles the final committed boundary without tearing the world down.
    ///
    /// Returns `Ok(None)`, without touching any state, when the owner holds
    /// work that only teardown may discard: a held host continuation, a
    /// pending fixed input, a retained device-group selection, a preselection
    /// reservation, or a poisoned continuation. Otherwise returns the entries
    /// that [`QuantumLoop::shutdown`] would publish for this boundary, already
    /// appended to the log; a later shutdown publishes only what arrives after
    /// this call.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when uncommitted network output or
    /// observations remain beyond the committed frontier, causal decisions
    /// remain without a discovery handoff, or settlement cannot be appended.
    /// The world must then be shut down.
    pub fn drain_final_boundary(
        &mut self,
    ) -> Result<Option<Vec<SchedulerEventLogEntry>>, SchedulerError> {
        if self.final_boundary_refusal().is_some() {
            return Ok(None);
        }
        self.settle_final_boundary().into_entries().map(Some)
    }

    /// Names the first owner state that keeps the final boundary unsettled.
    ///
    /// Returns `None` exactly when [`Self::drain_final_boundary`] would settle
    /// the boundary, and reads state only. A held guest stop is a live
    /// controller capability that never enters a checkpoint or process
    /// protocol, so a world paused at an unanswered guest choice is refused.
    #[must_use]
    pub fn final_boundary_refusal(&self) -> Option<FinalBoundaryRefusal> {
        if self.continuation_poisoned {
            return Some(FinalBoundaryRefusal::PoisonedContinuation);
        }
        if let Some(held) = &self.held_host_continuation {
            return Some(match held.source_stop.as_ref().map(|stop| stop.kind) {
                Some(HeldHostStopKind::GuestSelectable) => {
                    FinalBoundaryRefusal::HeldGuestSelectableStop
                }
                Some(HeldHostStopKind::CampaignMarker) => {
                    FinalBoundaryRefusal::HeldCampaignMarkerStop
                }
                None => FinalBoundaryRefusal::HeldPeerEvidence,
            });
        }
        if self.pending_fixed_input.is_some() {
            return Some(FinalBoundaryRefusal::PendingFixedInput);
        }
        if self.device_group_selection.is_retained() {
            return Some(FinalBoundaryRefusal::RetainedDeviceGroupSelection);
        }
        if self.preselection.is_some() {
            return Some(FinalBoundaryRefusal::LiveNetworkPreselection);
        }
        None
    }

    fn requires_cleanup_only_shutdown(&self) -> bool {
        self.held_host_continuation.is_some()
            || self.pending_fixed_input.is_some()
            || self.device_group_selection.is_retained()
            || self.continuation_poisoned
    }

    pub(crate) fn shutdown_backend_owner(
        &mut self,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        if self.requires_cleanup_only_shutdown() {
            // Explicit whole-world teardown discards private physical evidence;
            // it never settles the source or admits a held peer receipt. Retain
            // ownership on failure so shutdown can be retried without any RUN.
            self.continuation_poisoned = true;
            self.backend.shutdown().map_err(SchedulerError::from)?;
            self.held_host_continuation = None;
            self.failed_input_resolution = None;
            self.pending_fixed_input = None;
            self.device_group_selection = Default::default();
            self.failed_cap_negotiation = None;
            self.failed_dispatch_resolution = None;
            self.preselection = None;
            self.pending_network_outputs.clear();
            self.frozen_network_output_times.clear();
            self.pending_observations.clear();
            return self.loop_impl.shutdown();
        }
        if self.preselection.is_some() {
            return self.shutdown_preselection();
        }
        let settlement = self.settle_final_boundary();
        let loop_result = self.loop_impl.shutdown();
        let backend_result = self.backend.shutdown().map_err(SchedulerError::from);
        let mut entries = settlement.into_entries()?;
        entries.extend(loop_result?);
        backend_result?;
        Ok(entries)
    }

    /// Drains the backend and appends everything committed at the frontier.
    ///
    /// Every drain runs even when an earlier one fails, so shutdown always
    /// reaches teardown with the backend emptied.
    fn settle_final_boundary(&mut self) -> FinalBoundarySettlement {
        let final_network_append = self.backend.drain_network_outputs().and_then(|outputs| {
            self.pending_network_outputs.extend(outputs);
            let first_uncommitted = self
                .pending_network_outputs
                .iter()
                .map(|output| {
                    pending_network_output_time(
                        &self.loop_impl,
                        &self.frozen_network_output_times,
                        output,
                    )
                        .map(|at| (at, output))
                        .map_err(|error| BackendError::Rejected {
                            message: error.to_string(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|(at, _output)| at.ticks > self.committed_frontier.ticks)
                .min_by_key(|(at, _output)| at.ticks);
            if let Some((at, output)) = first_uncommitted {
                return Err(BackendError::Rejected {
                    message: format!(
                        "{} live-backend network outputs remain uncommitted at shutdown; first future frame {} from `{}` has tick {} beyond committed frontier {}",
                        self.pending_network_outputs.len(),
                        output.sequence,
                        output.source.name,
                        at.ticks,
                        self.committed_frontier.ticks,
                    ),
                });
            }
            if self.pending_network_outputs.is_empty() {
                return Ok(Vec::new());
            }
            let outputs = std::mem::take(&mut self.pending_network_outputs);
            let _admission_path = crate::scheduler::network_admission_trace::enter_path("shutdown");
            self.loop_impl
                .append_backend_network_outputs(
                    outputs,
                    &self.frozen_network_output_times,
                )
                .map(|(_recorded, _discoveries, _configuration, append)| append.entries)
                .map_err(|error| BackendError::Rejected {
                    message: error.to_string(),
                })
        });
        let final_decisions = match self.backend.drain_rng_evidence() {
            Ok(decisions) if decisions.is_empty() => Ok(()),
            Ok(decisions) => Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "{} live-backend causal decisions remain without a quantum discovery handoff at shutdown",
                    decisions.len()
                ),
            }),
            Err(error) => Err(SchedulerError::from(error)),
        };
        let final_observations = self.backend.drain_observable_events().and_then(|events| {
            normalize_backend_observations(&self.loop_impl, events, self.committed_frontier)
                .map_err(|error| BackendError::Rejected {
                    message: error.to_string(),
                })
        });
        let final_append = final_observations.and_then(|events| {
            self.pending_observations.extend(events);
            self.pending_observations.sort_by_key(ObservableEvent::at);
            let committed = self
                .pending_observations
                .partition_point(|event| event.at().ticks <= self.committed_frontier.ticks);
            let observations = self
                .pending_observations
                .drain(..committed)
                .collect::<Vec<_>>();
            if let Some(first) = self.pending_observations.first() {
                let source = first
                    .backend_node()
                    .map(|node| node.name.as_str())
                    .unwrap_or("scheduler");
                Err(BackendError::Rejected {
                    message: format!(
                        "{} live-backend observations remain uncommitted at shutdown; first timestamp is {} (kind {}, source `{source}`, committed frontier {})",
                        self.pending_observations.len(),
                        first.at().ticks,
                        observation_kind(first.payload()),
                        self.committed_frontier.ticks,
                    ),
                })
            } else if observations.is_empty() {
                Ok(Vec::new())
            } else {
                self.loop_impl
                    .append_backend_observations_at_boundary(
                        observations,
                        self.committed_frontier,
                    )
                    .map(|append| append.entries)
                    .map_err(|error| BackendError::Rejected {
                        message: error.to_string(),
                    })
            }
        });
        FinalBoundarySettlement {
            network: final_network_append,
            decisions: final_decisions,
            observations: final_append,
        }
    }
}
