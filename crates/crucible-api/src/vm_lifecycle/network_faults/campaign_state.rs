//! Exact selected network interval state and resolved-effect replay admission.

use super::*;

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

pub(super) fn validate_campaign_replay_restore(
    checkpoint_identity: Option<ContentHash>,
    replay: Option<&crucible::NetworkFaultCampaignReplayPlan>,
    restore_frontier: Option<VirtualTime>,
) -> Result<(), SchedulerError> {
    let exact =
        checkpoint_identity == replay.map(crucible::NetworkFaultCampaignReplayPlan::identity);
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
            crucible::NetworkFaultCampaignReplayPlan::new(plan.target().clone(), prefix.to_vec())
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
        replay: Option<crucible::NetworkFaultCampaignReplayPlan>,
        restore_frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        let selected_identity = replay
            .as_ref()
            .map(crucible::NetworkFaultCampaignReplayPlan::identity);
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
                                crucible::NetworkFaultPhase::First => {
                                    release.marker == "fault.transport.ready"
                                }
                                crucible::NetworkFaultPhase::Followup => {
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
        let committed = u64::try_from(self.campaign_records.len()).map_err(|_| {
            SchedulerError::BoundaryViolation {
                message: String::from("campaign network effect record count exceeds u64"),
            }
        })?;
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
                        crucible::NetworkFaultPhase::First => marker == "fault.transport.ready",
                        crucible::NetworkFaultPhase::Followup => marker == "fault.followup.ready",
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

    /// Returns committed network actions using the production resolved-effect contract.
    pub(in crate::vm_lifecycle) fn campaign_effect_records(&self) -> &[ResolvedEffectRecord] {
        &self.campaign_records
    }

    /// Installs exact campaign-owned effect evidence after owner partitioning.
    pub(in crate::vm_lifecycle) fn install_campaign_effect_replay(
        &mut self,
        expected: Option<Vec<ResolvedEffectRecord>>,
        restoring: bool,
    ) -> Result<(), SchedulerError> {
        if self.campaign_replay.is_none()
            && expected.as_ref().is_some_and(|records| !records.is_empty())
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("campaign effect evidence has no selected network plan"),
            });
        }
        let consumed = if restoring {
            self.campaign_records.len()
        } else {
            0
        };
        if let Some(records) = &expected
            && (consumed > records.len() || records[..consumed] != self.campaign_records)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("restored network effect prefix differs from replay"),
            });
        }
        self.campaign_effect_replay = expected;
        self.campaign_effect_replay_cursor = consumed;
        Ok(())
    }

    /// Requires every selected campaign effect to have been regenerated exactly.
    pub(in crate::vm_lifecycle) fn verify_campaign_effect_replay_exhausted(
        &self,
    ) -> Result<(), SchedulerError> {
        if self
            .campaign_effect_replay
            .as_ref()
            .is_some_and(|expected| self.campaign_effect_replay_cursor != expected.len())
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("campaign network effect replay was not exhausted"),
            });
        }
        Ok(())
    }

    /// Returns the authored limits used by this network adapter.
    pub(in crate::vm_lifecycle) fn resource_limits(&self) -> FaultResourceLimits {
        self.resource_limits
    }

    pub(in crate::vm_lifecycle) fn active_outages(
        &self,
        now: u64,
    ) -> Result<Vec<(crucible::model::ResolvedFaultTarget, u64)>, SchedulerError> {
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
