//! Checkpoint-edge and immediate-parent reduction helpers.

use super::*;

pub(in crate::model) fn checkpoint_edge(
    configuration: &Configuration,
    parent: Option<&Configuration>,
) -> Result<(Option<ContentHash>, Schedule), EngineError> {
    match (configuration.is_genesis(), parent) {
        (true, None) => Ok((None, Schedule::empty())),
        (true, Some(_)) => Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: configuration.id(),
            reason: "genesis-has-parent",
        }),
        (false, None) => Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: configuration.id(),
            reason: "descendant-missing-parent",
        }),
        (false, Some(parent)) => {
            if parent.def.id != configuration.def.id {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: configuration.id(),
                    reason: "parent-scenario-mismatch",
                });
            }
            let prefix = configuration
                .schedule
                .prefix(parent.schedule.len())
                .map_err(EngineError::SchedulePrefix)?;
            if prefix != parent.schedule {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: configuration.id(),
                    reason: "parent-not-schedule-prefix",
                });
            }
            let delta = configuration
                .schedule
                .suffix_from(parent.schedule.len())
                .map_err(EngineError::SchedulePrefix)?;
            if delta.is_empty() {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: configuration.id(),
                    reason: "empty-descendant-delta",
                });
            }
            Ok((Some(parent.id()), delta))
        }
    }
}

pub(in crate::model) fn immediate_parent_configuration(
    configuration: &Configuration,
) -> Result<Option<Configuration>, EngineError> {
    if configuration.is_genesis() {
        Ok(None)
    } else {
        let schedule = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
            .map_err(EngineError::SchedulePrefix)?;
        Ok(Some(Configuration {
            def: configuration.def.clone(),
            schedule,
        }))
    }
}
