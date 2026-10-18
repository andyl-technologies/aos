//! Admitted structural copies of recursive temporal actions.

use super::*;

impl Action {
    /// Encodes an action after admitting its exact canonical binary buffer.
    ///
    /// # Errors
    /// Refuses allocation failure, size overflow, or exhausted original authority.
    pub fn to_compact_binary_admitted(&self) -> Result<Vec<u8>, EngineError> {
        ScenarioBinaryWriter::encode_admitted(ACTION_BINARY_MAGIC, |writer| {
            write_action_binary(self, writer);
        })
    }

    /// Copies an action after admitting its concrete recursive fields.
    ///
    /// # Errors
    /// Refuses exhausted original metadata authority or allocation failure.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        Ok(match self {
            Self::ArmTimer { name, after } => Self::ArmTimer {
                name: TimerId {
                    name: copy_string(&name.name)?,
                },
                after: *after,
            },
            Self::CancelTimer { name } => Self::CancelTimer {
                name: TimerId {
                    name: copy_string(&name.name)?,
                },
            },
            Self::StartNode { node } => Self::StartNode {
                node: NodeId {
                    name: copy_string(&node.name)?,
                },
            },
            Self::StopNode { node } => Self::StopNode {
                node: NodeId {
                    name: copy_string(&node.name)?,
                },
            },
            Self::CreateSavepoint { label } => Self::CreateSavepoint {
                label: label.as_deref().map(copy_string).transpose()?,
            },
            Self::Fork { label } => Self::Fork {
                label: label.as_deref().map(copy_string).transpose()?,
            },
            Self::Pass => Self::Pass,
            Self::Fail { reason } => Self::Fail {
                reason: copy_string(reason)?,
            },
            Self::Log { level, message } => Self::Log {
                level: *level,
                message: copy_string(message)?,
            },
            Self::Group(actions) => {
                let mut copied = reserve_vec(actions.len())?;
                for action in actions {
                    copied.push(action.try_clone_admitted()?);
                }
                Self::Group(copied)
            }
        })
    }
}
