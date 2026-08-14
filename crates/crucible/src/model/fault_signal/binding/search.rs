//! Bounded search policies for binding outcomes and mutations.

use super::*;
/// Bounded search behavior for one binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum BindingSearchPolicy {
    /// Always uses the model result.
    Fixed,
    /// Branches fired/not-fired at selected opportunities.
    BranchOutcome {
        /// Maximum retained branches.
        maximum_branches: PositiveU64,
    },
    /// Branches among finite transition candidates.
    BranchTransition {
        /// Canonical transition identities.
        candidates: Vec<FaultObjectId>,
    },
    /// Branches among finite typed parameter values.
    BranchParameter {
        /// Dynamic destination field.
        parameter: MappedEffectParameter,
        /// Canonical candidate values.
        candidates: Vec<SignalValue>,
    },
    /// Mutates a bounded normalized-trace interval.
    MutateTraceWindow {
        /// First included virtual nanosecond.
        start_nanos: u64,
        /// Exclusive end virtual nanosecond.
        end_nanos: u64,
        /// Finite concrete mutation schedules considered by search.
        candidates: Vec<TraceWindowMaterialization>,
        /// Maximum changed samples.
        maximum_mutations: PositiveU64,
    },
    /// Mutates finite transfer-function points.
    MutateMapping {
        /// Canonical point indices.
        point_indices: Vec<u32>,
        /// Finite concrete mutation schedules considered by search.
        candidates: Vec<MappingMaterialization>,
        /// Maximum changed points.
        maximum_mutations: PositiveU64,
    },
}

impl BindingSearchPolicy {
    /// Returns the largest finite candidate set admitted by this policy.
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        match self {
            Self::BranchTransition { candidates } => candidates.len(),
            Self::BranchParameter { candidates, .. } => candidates.len(),
            Self::MutateTraceWindow { candidates, .. } => candidates.len(),
            Self::MutateMapping { candidates, .. } => candidates.len(),
            Self::Fixed | Self::BranchOutcome { .. } => 0,
        }
    }

    /// Returns the maximum trace windows retained by this policy.
    #[must_use]
    pub const fn trace_mutation_windows(&self) -> u64 {
        if matches!(self, Self::MutateTraceWindow { .. }) {
            1
        } else {
            0
        }
    }

    /// Returns the maximum mapping points mutated by this policy.
    #[must_use]
    pub const fn mapping_mutation_points(&self) -> u64 {
        match self {
            Self::MutateMapping {
                maximum_mutations, ..
            } => maximum_mutations.get(),
            _ => 0,
        }
    }

    pub(super) fn validate(
        &mut self,
        mapping: &BindingMapping,
        signals: &[SignalId],
        program: &SignalProgram,
    ) -> Result<(), BindingError> {
        match self {
            Self::Fixed => Ok(()),
            Self::BranchOutcome { maximum_branches }
                if matches!(mapping, BindingMapping::Hazard)
                    && maximum_branches.get() <= HARD_SEARCH_CHOICES_PER_STATE =>
            {
                Ok(())
            }
            Self::BranchOutcome { .. } => Err(BindingError::InvalidSearchPolicy),
            Self::BranchTransition { candidates } => {
                if !matches!(mapping, BindingMapping::StateTransition { .. }) {
                    return Err(BindingError::InvalidSearchPolicy);
                }
                candidates.sort();
                validate_candidates(candidates)
            }
            Self::BranchParameter {
                parameter,
                candidates,
            } => {
                let mapped = match mapping {
                    BindingMapping::MapParameter { parameter }
                    | BindingMapping::PiecewiseParameter { parameter, .. } => parameter,
                    _ => return Err(BindingError::InvalidSearchPolicy),
                };
                if parameter != mapped
                    || candidates
                        .iter()
                        .any(|value| !parameter.accepts_value(value))
                {
                    return Err(BindingError::InvalidSearchPolicy);
                }
                candidates.sort();
                validate_candidates(candidates)
            }
            Self::MutateTraceWindow {
                start_nanos,
                end_nanos,
                candidates,
                maximum_mutations,
            } => {
                candidates.sort();
                if *start_nanos >= *end_nanos
                    || maximum_mutations.get() > HARD_SEARCH_CHOICES_PER_STATE
                    || validate_candidates(candidates).is_err()
                    || candidates.iter().any(|candidate| {
                        let trace_shape = signals
                            .contains(&candidate.trace_node)
                            .then(|| {
                                program.nodes().iter().find_map(|node| {
                                    (&node.id == &candidate.trace_node
                                        && matches!(
                                            node.kind,
                                            SignalNodeKind::Source(
                                                SignalSourceSpecification::Trace { .. }
                                            )
                                        ))
                                    .then_some(&node.output)
                                })
                            })
                            .flatten();
                        candidate.samples.is_empty()
                            || u64::try_from(candidate.samples.len())
                                .map_or(true, |count| count > maximum_mutations.get())
                            || candidate.samples.windows(2).any(|pair| {
                                (pair[0].coordinate, pair[0].event_sequence)
                                    >= (pair[1].coordinate, pair[1].event_sequence)
                            })
                            || candidate.samples.iter().any(|sample| {
                                sample.coordinate < *start_nanos
                                    || sample.coordinate >= *end_nanos
                                    || sample.value.value_type().as_ref()
                                        != trace_shape.map(|shape| &shape.value_type)
                            })
                    })
                {
                    Err(BindingError::InvalidSearchPolicy)
                } else {
                    Ok(())
                }
            }
            Self::MutateMapping {
                point_indices,
                candidates,
                maximum_mutations,
            } => {
                let (parameter, point_count) = match mapping {
                    BindingMapping::PiecewiseParameter {
                        parameter, points, ..
                    } => (parameter, points.len()),
                    _ => return Err(BindingError::InvalidSearchPolicy),
                };
                point_indices.sort_unstable();
                validate_candidates(point_indices)?;
                candidates.sort();
                if point_indices
                    .iter()
                    .any(|index| usize::try_from(*index).map_or(true, |index| index >= point_count))
                    || validate_candidates(candidates).is_err()
                    || candidates.iter().any(|candidate| {
                        candidate.points.is_empty()
                            || u64::try_from(candidate.points.len())
                                .map_or(true, |count| count > maximum_mutations.get())
                            || candidate
                                .points
                                .windows(2)
                                .any(|pair| pair[0].index >= pair[1].index)
                            || candidate.points.iter().any(|point| {
                                point_indices.binary_search(&point.index).is_err()
                                    || !parameter.accepts_value(&point.point.output)
                            })
                    })
                    || usize::try_from(maximum_mutations.get())
                        .map_or(true, |maximum| maximum > point_indices.len())
                {
                    return Err(BindingError::InvalidSearchPolicy);
                }
                Ok(())
            }
        }
    }
}

pub(super) fn validate_candidates<T: PartialEq>(values: &[T]) -> Result<(), BindingError> {
    if values.is_empty()
        || values.len() > HARD_SEARCH_CANDIDATE_LIMIT
        || values.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(BindingError::InvalidSearchPolicy);
    }
    Ok(())
}
