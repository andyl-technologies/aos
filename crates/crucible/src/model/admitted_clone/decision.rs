//! Concrete field reservations for structural runtime decision copies.
//!
//! Each dynamic field is admitted before its allocation. Already validated
//! selections retain their bytes and derived flags without a second decoding
//! pass or a new artifact-format limit on runtime state.

use super::*;

impl Decision {
    /// Copies a decision after admitting each concrete owned allocation.
    ///
    /// # Errors
    /// Refuses exhausted original authority or allocation failure.
    pub(crate) fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        Ok(match self {
            Self::DeliveryOrder(value) => {
                let mut order = reserve_vec(value.order.len())?;
                for event in &value.order {
                    order.push(EventKey {
                        virtual_time: event.virtual_time,
                        consumer: copy_scheduler_node(&event.consumer)?,
                        producer: copy_scheduler_node(&event.producer)?,
                        sequence: event.sequence,
                    });
                }
                Self::DeliveryOrder(DeliveryOrderDecision {
                    at: value.at,
                    order,
                })
            }
            Self::RngDraw(value) => Self::RngDraw(RngDecision {
                stream: RngStreamId {
                    domain: copy_string(&value.stream.domain)?,
                    name: copy_string(&value.stream.name)?,
                },
                value: value.value,
            }),
            Self::Override(value) => Self::Override(OverrideDecision {
                point: SchedulingPoint {
                    key: copy_string(&value.point.key)?,
                },
                choice: ChoiceTag {
                    name: copy_string(&value.choice.name)?,
                },
            }),
            Self::Preemption(value) => Self::Preemption(PreemptionDecision {
                node: NodeId {
                    name: copy_string(&value.node.name)?,
                },
                at: value.at,
                // Both variants contain only integer newtypes.
                kind: value.kind.clone(),
            }),
            Self::Selection(value) => Self::Selection(value.try_clone_admitted()?),
        })
    }
}

fn copy_scheduler_node(source: &SchedulerNodeId) -> Result<SchedulerNodeId, EngineError> {
    Ok(SchedulerNodeId {
        node: NodeId {
            name: copy_string(&source.node.name)?,
        },
        kind: source.kind,
    })
}

pub(in crate::model) fn reserve_vec<T>(length: usize) -> Result<Vec<T>, EngineError> {
    crate::owned_decode::charge_array::<T>(length)
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
    let mut values = Vec::new();
    values.try_reserve_exact(length).map_err(allocation_error)?;
    Ok(values)
}

pub(in crate::model) fn copy_vec<T: Copy>(source: &[T]) -> Result<Vec<T>, EngineError> {
    let mut values = reserve_vec(source.len())?;
    values.extend_from_slice(source);
    Ok(values)
}

pub(in crate::model) fn copy_string(source: &str) -> Result<String, EngineError> {
    crate::owned_decode::charge_array::<u8>(source.len())
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
    let mut value = String::new();
    value
        .try_reserve_exact(source.len())
        .map_err(allocation_error)?;
    value.push_str(source);
    Ok(value)
}

fn allocation_error(source: std::collections::TryReserveError) -> EngineError {
    EngineError::ArtifactDecodeAdmission {
        source: crate::owned_decode::DecodeAdmissionError::new(source),
    }
}
