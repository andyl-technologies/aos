//! Checkpoint-backed debugger coordinate and replay navigation.

use super::*;

impl TemporalGraph {
    pub(in crate::model) fn debug_restore_configuration(
        &self,
        target: &Configuration,
    ) -> Result<Configuration, EngineError> {
        if target.is_genesis() || self.cached_snapshot(target).is_some() {
            return Ok(target.clone());
        }
        if let Some(ancestor) = self.nearest_cached_ancestor(target)? {
            return Ok(ancestor);
        }
        Ok(Configuration::genesis(target.def.clone()))
    }

    pub(in crate::model) fn debug_resolve_coordinate(
        &self,
        current: &Configuration,
        coordinate: &DebugCoordinate,
        event_coordinates: &BTreeMap<u64, Configuration>,
    ) -> Result<Configuration, EngineError> {
        match coordinate {
            DebugCoordinate::Configuration(configuration) => Ok(configuration.clone()),
            DebugCoordinate::Checkpoint(checkpoint) => {
                self.recorded_configurations.get(checkpoint).cloned().ok_or(
                    EngineError::CheckpointNotRecorded {
                        checkpoint: *checkpoint,
                    },
                )
            }
            DebugCoordinate::EventSequence(sequence) => event_coordinates
                .get(sequence)
                .cloned()
                .ok_or(EngineError::DebugTimeTravelMissingEventCoordinate {
                    sequence: *sequence,
                }),
            DebugCoordinate::VirtualTime(time) => self
                .debug_latest_checkpoint_at_or_before_time(current, *time)
                .ok_or_else(|| EngineError::DebugTimeTravelCoordinateNotFound {
                    coordinate: coordinate.clone(),
                }),
            DebugCoordinate::NodeIcount { node, icount } => self
                .debug_latest_checkpoint_at_or_before_icount(current, node, *icount)
                .ok_or_else(|| EngineError::DebugTimeTravelCoordinateNotFound {
                    coordinate: coordinate.clone(),
                }),
        }
    }

    pub(in crate::model) fn debug_resolve_scoped_node_icount(
        &self,
        current: &Configuration,
        node: &NodeId,
        target: Icount,
    ) -> Option<Configuration> {
        self.debug_scoped_node_coordinate_candidates(current)
            .into_iter()
            .filter_map(|candidate| {
                let icount = candidate.node_icounts.get(node).copied()?;
                if icount == target {
                    Some((candidate, icount))
                } else {
                    None
                }
            })
            .max_by_key(|(candidate, icount)| {
                (
                    *icount,
                    candidate.virtual_time,
                    candidate.configuration.schedule.len(),
                    candidate.configuration.id(),
                )
            })
            .map(|(candidate, _)| candidate.configuration)
    }

    pub(in crate::model) fn debug_scoped_node_material(
        &mut self,
        current: &Configuration,
        target: &Configuration,
        node: NodeId,
        requested_icount: Icount,
    ) -> Result<DebugScopedNodeMaterial, EngineError> {
        debug_validate_same_scenario(current, target)?;
        self.record_checkpoint_closure(target)?;
        let restore = Configuration::genesis(target.def.clone());
        let restore_checkpoint = self
            .genesis_snapshot(&target.def)
            .ok_or(EngineError::MissingBakedGenesis {
                scenario: target.def.id,
            })?
            .checkpoint
            .clone();
        let (restore_icount, restore_blob) =
            debug_checkpoint_node_material(&restore_checkpoint, &node, restore.id())?;
        let replay_suffix = target
            .schedule
            .suffix_from(restore.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;
        let (node_icount, node_blob) = if replay_suffix.is_empty() {
            (restore_icount, restore_blob)
        } else {
            let replayed_icounts = replayed_node_icounts(
                &BTreeMap::from([(node.clone(), restore_icount)]),
                &replay_suffix,
            );
            let replayed_blobs = replayed_node_blobs(
                &BTreeMap::from([(node.clone(), restore_blob)]),
                &restore,
                &replay_suffix,
                target,
            );
            (
                replayed_icounts.get(&node).copied().ok_or_else(|| {
                    EngineError::DebugTimeTravelUnknownNode {
                        node: node.clone(),
                        configuration: target.id(),
                    }
                })?,
                replayed_blobs.get(&node).cloned().ok_or_else(|| {
                    EngineError::DebugTimeTravelUnknownNode {
                        node: node.clone(),
                        configuration: target.id(),
                    }
                })?,
            )
        };
        if node_icount != requested_icount {
            return Err(EngineError::DebugTimeTravelCoordinateNotFound {
                coordinate: DebugCoordinate::node_icount(node, requested_icount),
            });
        }
        let mut materialized_nodes = BTreeSet::new();
        materialized_nodes.insert(node.clone());

        Ok(DebugScopedNodeMaterial {
            target_configuration: target.id(),
            node_icount,
            node_blob,
            goto: DebugPerNodeGotoReport {
                current_configuration: current.id(),
                target_coordinate: DebugCoordinate::node_icount(node, requested_icount),
                target_configuration: target.id(),
                restore_configuration: restore.id(),
                restore_checkpoint: restore_checkpoint.id,
                replay_suffix_decisions: replay_suffix.len(),
                replay_oracle: None,
                materialized_nodes,
            },
        })
    }

    pub(in crate::model) fn debug_latest_checkpoint_at_or_before_time(
        &self,
        current: &Configuration,
        target: VirtualTime,
    ) -> Option<Configuration> {
        self.debug_checkpoint_coordinate_candidates(current)
            .into_iter()
            .filter(|candidate| candidate.virtual_time <= target)
            .max_by_key(|candidate| {
                (
                    candidate.virtual_time,
                    candidate.configuration.schedule.len(),
                    candidate.configuration.id(),
                )
            })
            .map(|candidate| candidate.configuration)
    }

    pub(in crate::model) fn debug_latest_checkpoint_at_or_before_icount(
        &self,
        current: &Configuration,
        node: &NodeId,
        target: Icount,
    ) -> Option<Configuration> {
        self.debug_checkpoint_coordinate_candidates(current)
            .into_iter()
            .filter_map(|candidate| {
                let icount = candidate.node_icounts.get(node).copied()?;
                if icount <= target {
                    Some((candidate, icount))
                } else {
                    None
                }
            })
            .max_by_key(|(candidate, icount)| {
                (
                    *icount,
                    candidate.virtual_time,
                    candidate.configuration.schedule.len(),
                    candidate.configuration.id(),
                )
            })
            .map(|(candidate, _)| candidate.configuration)
    }

    pub(in crate::model) fn debug_checkpoint_coordinate_candidates(
        &self,
        current: &Configuration,
    ) -> Vec<DebugCheckpointCoordinateCandidate> {
        self.debug_checkpoint_coordinate_candidates_where(current, |configuration| {
            debug_configuration_is_ancestor_or_self(configuration, current)
        })
    }

    pub(in crate::model) fn debug_scoped_node_coordinate_candidates(
        &self,
        current: &Configuration,
    ) -> Vec<DebugCheckpointCoordinateCandidate> {
        self.debug_checkpoint_coordinate_candidates_where(current, |configuration| {
            debug_configurations_are_linearly_related(configuration, current)
        })
    }

    pub(in crate::model) fn debug_checkpoint_coordinate_candidates_where<F>(
        &self,
        current: &Configuration,
        include: F,
    ) -> Vec<DebugCheckpointCoordinateCandidate>
    where
        F: Fn(&Configuration) -> bool,
    {
        let mut candidates = BTreeMap::<ContentHash, DebugCheckpointCoordinateCandidate>::new();
        for checkpoint in self
            .checkpoint_nodes
            .values()
            .chain(self.cached_snapshots.values())
        {
            if checkpoint.scenario_ref != current.def.id {
                continue;
            }
            let Some(configuration) = self.recorded_configurations.get(&checkpoint.configuration)
            else {
                continue;
            };
            if !include(configuration) {
                continue;
            }
            candidates
                .entry(checkpoint.configuration)
                .and_modify(|candidate| {
                    if candidate.node_icounts.is_empty() && !checkpoint.node_icounts.is_empty() {
                        candidate.node_icounts = checkpoint.node_icounts.clone();
                    }
                    if checkpoint.virtual_time > candidate.virtual_time {
                        candidate.virtual_time = checkpoint.virtual_time;
                    }
                })
                .or_insert_with(|| DebugCheckpointCoordinateCandidate {
                    configuration: configuration.clone(),
                    virtual_time: checkpoint.virtual_time,
                    node_icounts: checkpoint.node_icounts.clone(),
                });
        }
        candidates.into_values().collect()
    }

    pub(in crate::model) fn debug_goto_error(
        &self,
        current: &Configuration,
        target: &Configuration,
        restore: &Configuration,
        error: EngineError,
    ) -> EngineError {
        match error {
            EngineError::ReplayOracleMismatch {
                checkpoint,
                expected,
                actual,
            } => EngineError::DebugGotoReplayOracleMismatch {
                bisection: Box::new(self.debug_replay_oracle_bisection(current, target, restore)),
                checkpoint,
                expected,
                actual,
            },
            other => other,
        }
    }

    pub(in crate::model) fn debug_replay_oracle_bisection(
        &self,
        current: &Configuration,
        target: &Configuration,
        restore: &Configuration,
    ) -> DebugReplayOracleBisectionRequest {
        let mut low = 0_usize;
        let mut high = target.schedule.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let prefix = debug_configuration_prefix(target, mid).unwrap_or_else(|_| target.clone());
            match debug_cached_prefix_matches_replay_oracle(self, &prefix) {
                Ok(true) => low = mid.saturating_add(1),
                Ok(false) | Err(_) => high = mid,
            }
        }
        let restore_checkpoint = self
            .checkpoint_node(restore.id())
            .or_else(|| self.cached_snapshot(restore))
            .map(|checkpoint| checkpoint.id)
            .unwrap_or_else(|| restore.id());
        DebugReplayOracleBisectionRequest {
            current_configuration: current.id(),
            target_configuration: target.id(),
            restore_configuration: restore.id(),
            restore_checkpoint,
            last_matching_schedule_prefix_len: low.checked_sub(1),
            first_different_schedule_prefix_len: low,
        }
    }
}
