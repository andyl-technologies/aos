//! Exact selected network interval state and resolved-effect replay admission.

use super::*;
use crucible_engine::model::ResolvedEffectTrace;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CampaignMarkerReleaseRecord {
    pub(super) node: NodeId,
    pub(super) marker: String,
    pub(super) marker_icount: Icount,
    pub(super) physical_raw_icount: Icount,
    pub(super) physical_icount: Icount,
    pub(super) selected: ContentHash,
}

/// Checks that a restored plan equals the checkpointed selection or extends it.
///
/// An extension appends exactly one branch, anchored at the restored frontier,
/// to the plan the checkpoint authenticated.
pub(in crate::vm_lifecycle) fn validate_campaign_replay_restore(
    checkpoint_identity: Option<ContentHash>,
    replay: Option<&crucible_engine::NetworkFaultCampaignReplayPlan>,
    restore_frontier: Option<VirtualTime>,
) -> Result<(), SchedulerError> {
    let exact = checkpoint_identity
        == replay.map(crucible_engine::NetworkFaultCampaignReplayPlan::identity);
    let extension = replay.is_some_and(|plan| {
        let Some((last, prefix)) = plan.branches().split_last() else {
            return false;
        };
        let Some(frontier) = restore_frontier else {
            return false;
        };
        if last.at() != frontier {
            return false;
        }
        let prefix_identity = if prefix.is_empty() {
            None
        } else {
            crucible_engine::NetworkFaultCampaignReplayPlan::new(
                plan.target().clone(),
                prefix.to_vec(),
            )
            .ok()
            .map(|prior| prior.identity())
        };
        checkpoint_identity == prefix_identity
    });
    if !exact && !extension {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("restored network fault replay differs from the checkpoint"),
        });
    }
    Ok(())
}

impl ProductionFaultNetworkInterceptor {
    /// Installs the exact interval state selected at the parked world boundary.
    ///
    /// Campaign availability is an immutable branch interval, not a mutable
    /// signal-registry entry. The checkpoint authenticates its branch identity;
    /// frame admission and outage evidence derive the same state at virtual time.
    ///
    /// # Errors
    ///
    /// Returns an error when an exact restore supplies a different selection
    /// from the branch prefix authenticated by its network checkpoint.
    pub(in crate::vm_lifecycle) fn install_campaign_replay(
        &mut self,
        replay: Option<crucible_engine::NetworkFaultCampaignReplayPlan>,
        restore_frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        let selected_identity = replay
            .as_ref()
            .map(crucible_engine::NetworkFaultCampaignReplayPlan::identity);
        if restore_frontier.is_some() {
            validate_campaign_replay_restore(
                self.campaign_replay_identity,
                replay.as_ref(),
                restore_frontier,
            )?;
            for release in &self.campaign_marker_releases {
                let matches_selected = replay.as_ref().is_some_and(|plan| {
                    plan.branches().iter().any(|branch| {
                        branch.selected().id() == release.selected
                            && match branch.phase() {
                                crucible_engine::NetworkFaultPhase::First => {
                                    release.marker == "fault.transport.ready"
                                }
                                crucible_engine::NetworkFaultPhase::Followup => {
                                    release.marker == "fault.followup.ready"
                                }
                            }
                    })
                });
                if !matches_selected {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "restored network marker release differs from selected branch",
                        ),
                    });
                }
            }
        }
        let committed = self.campaign_log.records();
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?;
        self.resource_limits
            .reserve(
                "resolved_effect_records",
                runtime.recorded_effect_count(),
                committed,
            )
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("combined fault record count exceeds authored limits: {error}"),
            })?;
        runtime.set_external_effect_count(committed);
        drop(runtime);
        self.campaign_replay = replay;
        self.campaign_replay_identity = selected_identity;
        Ok(())
    }

    /// Rebinds the selected campaign plan of a world paused at `boundary`.
    ///
    /// A world launched for one attempt carries that attempt's whole plan,
    /// including branches it has not reached yet. Before the world becomes a
    /// source, its plan is replaced by the one an exact resume at `boundary`
    /// would install, so a checkpoint names only branches the world has
    /// already committed. The replacement must keep exactly the committed
    /// branches and may drop only branches still ahead of `boundary`; every
    /// recorded marker release must still name a kept branch. Returns the
    /// previous plan so a failed preparation can restore it.
    ///
    /// # Errors
    ///
    /// Returns an error, leaving the plan unchanged, when `replay` differs
    /// from the committed branches or a release names a dropped branch.
    pub(in crate::vm_lifecycle) fn rebind_campaign_replay(
        &mut self,
        replay: Option<crucible_engine::NetworkFaultCampaignReplayPlan>,
        boundary: &Configuration,
    ) -> Result<Option<crucible_engine::NetworkFaultCampaignReplayPlan>, SchedulerError> {
        let history = boundary.schedule.decision_history();
        let committed = self
            .campaign_replay
            .as_ref()
            .map_or(&[][..], crucible_engine::NetworkFaultCampaignReplayPlan::branches)
            .iter()
            .filter(|branch| {
                let index = branch.parent().schedule.len();
                index < boundary.schedule.len() && history.get(index) == Some(branch.decision())
            })
            .collect::<Vec<_>>();
        let kept = replay
            .as_ref()
            .map_or(&[][..], crucible_engine::NetworkFaultCampaignReplayPlan::branches);
        if !kept.iter().eq(committed.iter().copied()) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "rebound network fault replay differs from the branches committed at the boundary: kept=[{}] committed=[{}] boundary_decisions={}",
                    describe_branches(kept.iter()),
                    describe_branches(committed.iter().copied()),
                    boundary.schedule.len(),
                ),
            });
        }
        // A plan branch at or before the boundary whose decision is absent
        // was neither committed nor still ahead; the world left that plan.
        let abandoned = self.campaign_replay.as_ref().is_some_and(|plan| {
            plan.branches().iter().any(|branch| {
                let index = branch.parent().schedule.len();
                index < boundary.schedule.len() && history.get(index) != Some(branch.decision())
            })
        });
        let released_dropped = self.campaign_marker_releases.iter().any(|release| {
            !kept
                .iter()
                .any(|branch| branch.selected().id() == release.selected)
        });
        if abandoned || released_dropped {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "rebound network fault replay drops a branch the world already crossed",
                ),
            });
        }

        self.campaign_replay_identity = replay
            .as_ref()
            .map(crucible_engine::NetworkFaultCampaignReplayPlan::identity);
        Ok(std::mem::replace(&mut self.campaign_replay, replay))
    }

    /// Restores a plan returned by [`Self::rebind_campaign_replay`].
    pub(in crate::vm_lifecycle) fn restore_campaign_replay(
        &mut self,
        replay: Option<crucible_engine::NetworkFaultCampaignReplayPlan>,
    ) {
        self.campaign_replay_identity = replay
            .as_ref()
            .map(crucible_engine::NetworkFaultCampaignReplayPlan::identity);
        self.campaign_replay = replay;
    }

    /// Returns the identity of the selected campaign plan a checkpoint records.
    pub(in crate::vm_lifecycle) const fn campaign_replay_identity(&self) -> Option<ContentHash> {
        self.campaign_replay_identity
    }

    pub(in crate::vm_lifecycle) fn campaign_marker_release_committed(
        &self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> bool {
        self.campaign_marker_releases.iter().any(|record| {
            &record.node == node && record.marker == marker && record.selected == selected
        })
    }

    pub(in crate::vm_lifecycle) fn validate_campaign_marker_release(
        &self,
        node: &NodeId,
        marker: &str,
        marker_icount: Icount,
        physical_raw_icount: Icount,
        physical_icount: Icount,
        selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        let valid_selection = self.campaign_replay.as_ref().is_some_and(|plan| {
            plan.branches().iter().any(|branch| {
                branch.selected().id() == selected
                    && match branch.phase() {
                        crucible_engine::NetworkFaultPhase::First => {
                            marker == "fault.transport.ready"
                        }
                        crucible_engine::NetworkFaultPhase::Followup => {
                            marker == "fault.followup.ready"
                        }
                    }
            })
        });
        if !valid_selection
            || marker_icount.retired.checked_add(1) != Some(physical_raw_icount.retired)
            || physical_icount.retired < physical_raw_icount.retired
            || self
                .campaign_marker_releases
                .iter()
                .any(|record| record.node == *node && record.marker == marker)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network marker release lacks an exact selected park"),
            });
        }
        Ok(())
    }

    pub(in crate::vm_lifecycle) fn record_campaign_marker_release(
        &mut self,
        node: &NodeId,
        marker: &str,
        marker_icount: Icount,
        physical_raw_icount: Icount,
        physical_icount: Icount,
        selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        self.validate_campaign_marker_release(
            node,
            marker,
            marker_icount,
            physical_raw_icount,
            physical_icount,
            selected,
        )?;
        self.campaign_marker_releases
            .push(CampaignMarkerReleaseRecord {
                node: node.clone(),
                marker: marker.to_owned(),
                marker_icount,
                physical_raw_icount,
                physical_icount,
                selected,
            });
        Ok(())
    }

    /// Returns every committed campaign record, reading sealed segments.
    #[cfg(test)]
    pub(in crate::vm_lifecycle) fn campaign_effect_records(
        &self,
    ) -> Vec<crucible_engine::model::ResolvedEffectRecord> {
        let mut records = Vec::new();
        self.campaign_log
            .try_for_each_record(|record| {
                records.push(record.clone());
                Ok(())
            })
            .unwrap_or_else(|error| panic!("campaign effect log should read: {error}"));
        records
    }

    /// Returns the segmented log of committed campaign network effects.
    pub(in crate::vm_lifecycle) fn campaign_effect_log(&self) -> &CampaignRecordLog {
        &self.campaign_log
    }

    /// Installs exact campaign-owned effect evidence after owner partitioning.
    ///
    /// A restore consumes the records the checkpointed log already committed,
    /// reading both one segment at a time.
    pub(in crate::vm_lifecycle) fn install_campaign_effect_replay(
        &mut self,
        expected: Option<ResolvedEffectTrace>,
        restoring: bool,
    ) -> Result<(), SchedulerError> {
        let mut replay = expected
            .map(|trace| CampaignRecordReplay::new(trace, self.resource_limits))
            .transpose()?;
        if self.campaign_replay.is_none()
            && replay.as_ref().is_some_and(|replay| replay.total() != 0)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("campaign effect evidence has no selected network plan"),
            });
        }
        if restoring && let Some(replay) = replay.as_mut() {
            replay.skip_committed(&self.campaign_log)?;
        }
        self.campaign_effect_replay = replay;
        Ok(())
    }

    /// Requires every selected campaign effect to have been regenerated exactly.
    pub(in crate::vm_lifecycle) fn verify_campaign_effect_replay_exhausted(
        &self,
    ) -> Result<(), SchedulerError> {
        if self
            .campaign_effect_replay
            .as_ref()
            .is_some_and(|replay| !replay.exhausted())
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("campaign network effect replay was not exhausted"),
            });
        }
        Ok(())
    }

    /// Returns the authored limits used by this network adapter.
    #[cfg(test)]
    pub(in crate::vm_lifecycle) fn resource_limits(&self) -> FaultResourceLimits {
        self.resource_limits
    }

    pub(in crate::vm_lifecycle) fn active_outages(
        &self,
        now: u64,
    ) -> Result<Vec<(crucible_engine::model::ResolvedFaultTarget, u64)>, SchedulerError> {
        let mut outages = self.effect_state.boundary.active_outages(now);
        if let Some(replay) = &self.campaign_replay {
            outages.extend(
                replay
                    .active_outages(&self.topology, now)
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("resolve selected network outage evidence: {error}"),
                    })?,
            );
        }
        outages.sort();
        outages.dedup();
        Ok(outages)
    }
}


/// Names each branch's phase, anchor time, decision index and child.
fn describe_branches<'a>(
    branches: impl Iterator<Item = &'a crucible_engine::NetworkFaultCampaignBranch>,
) -> String {
    branches
        .map(|branch| {
            format!(
                "{:?}@{}:decision={}:child={}",
                branch.phase(),
                branch.at().ticks,
                branch.parent().schedule.len(),
                branch.selected().id().to_hex(),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}
