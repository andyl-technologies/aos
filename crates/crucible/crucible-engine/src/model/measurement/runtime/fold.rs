//! Forward folds that turn admitted samples into exact aggregates.
//!
//! A [`MetricFold`] consumes one metric's in-window samples in canonical
//! scheduler order and keeps only what its aggregation needs: a count, a
//! running total, an extreme, histogram bins, or the first and last values.
//! Its state is bounded by the metric declaration, never by how many samples
//! the window admits (RFC-0020 CMEAS-23).
//!
//! Arithmetic failures are recorded rather than returned when they occur. A
//! window decides which samples count only once it is resolved, so a fold
//! reports its first failure from [`MetricFold::finish`], exactly where
//! aggregating the complete sample list would have failed.

use super::*;

/// Exact running aggregate for one metric's admitted samples.
#[derive(Clone, Debug)]
pub(super) struct MetricFold {
    state: FoldState,
    samples: u64,
    failure: Option<MeasurementEvaluationError>,
}

#[derive(Clone, Debug)]
enum FoldState {
    Count,
    Sum(RunningSum),
    Extreme {
        selected: Option<MeasurementSampleValue>,
        desired: std::cmp::Ordering,
    },
    Mean(ReducedRational),
    Histogram {
        upper_bounds: Vec<i64>,
        bins: Vec<u64>,
    },
    First(Option<MeasurementSampleValue>),
    Last(Option<MeasurementSampleValue>),
    Delta {
        first: Option<MeasurementSampleValue>,
        last: Option<MeasurementSampleValue>,
    },
}

/// Running total typed by the metric's declared value type.
#[derive(Clone, Copy, Debug)]
enum RunningSum {
    Signed(i64),
    Unsigned(u64),
    Rational(ReducedRational),
    // Booleans, identifiers, and vectors have no sum; aggregating them fails
    // even over an empty window.
    Undefined,
}

impl MetricFold {
    /// Starts an empty fold for `metric`'s aggregation.
    pub(super) fn new(metric: &MetricDefinition) -> Self {
        let state = match &metric.aggregation {
            Aggregation::Count => FoldState::Count,
            Aggregation::Sum => FoldState::Sum(match metric.value_type {
                MetricValueType::SignedInteger => RunningSum::Signed(0),
                MetricValueType::UnsignedInteger => RunningSum::Unsigned(0),
                MetricValueType::ReducedRational => {
                    RunningSum::Rational(ReducedRational::from_unsigned(0))
                }
                MetricValueType::Boolean
                | MetricValueType::Enumerated { .. }
                | MetricValueType::IntegerVector { .. } => RunningSum::Undefined,
            }),
            Aggregation::Min => FoldState::Extreme {
                selected: None,
                desired: std::cmp::Ordering::Less,
            },
            Aggregation::Max => FoldState::Extreme {
                selected: None,
                desired: std::cmp::Ordering::Greater,
            },
            Aggregation::ExactMean => FoldState::Mean(ReducedRational::from_unsigned(0)),
            Aggregation::Histogram { upper_bounds } => FoldState::Histogram {
                upper_bounds: upper_bounds.clone(),
                bins: vec![0; upper_bounds.len().saturating_add(1)],
            },
            Aggregation::First => FoldState::First(None),
            Aggregation::Last => FoldState::Last(None),
            Aggregation::EventDelta => FoldState::Delta {
                first: None,
                last: None,
            },
        };
        Self {
            state,
            samples: 0,
            failure: None,
        }
    }

    /// Consumes the next admitted sample in canonical scheduler order.
    pub(super) fn observe(&mut self, value: &MeasurementSampleValue) {
        if self.failure.is_some() {
            return;
        }
        if let Err(error) = self.try_observe(value) {
            self.failure = Some(error);
        }
    }

    fn try_observe(
        &mut self,
        value: &MeasurementSampleValue,
    ) -> Result<(), MeasurementEvaluationError> {
        self.samples = self
            .samples
            .checked_add(1)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;
        match &mut self.state {
            FoldState::Count => {}
            FoldState::Sum(total) => *total = total.add(value)?,
            FoldState::Extreme { selected, desired } => match selected {
                None => *selected = Some(value.clone()),
                Some(current) => {
                    if compare_samples(value, current)? == *desired {
                        *current = value.clone();
                    }
                }
            },
            FoldState::Mean(total) => *total = total.checked_add(rational_value(value)?)?,
            FoldState::Histogram { upper_bounds, bins } => {
                let bin = histogram_bin(value, upper_bounds)?;
                bins[bin] = bins[bin]
                    .checked_add(1)
                    .ok_or(MeasurementEvaluationError::ArithmeticOverflow)?;
            }
            FoldState::First(first) => {
                first.get_or_insert_with(|| value.clone());
            }
            FoldState::Last(last) => *last = Some(value.clone()),
            FoldState::Delta { first, last } => {
                first.get_or_insert_with(|| value.clone());
                *last = Some(value.clone());
            }
        }
        Ok(())
    }

    /// Resolves the fold into its metric outcome for a resolved window.
    ///
    /// Only a completed window commits a measurement. A window that never
    /// opened, is still open, or timed out may lack every sample, so an
    /// aggregation undefined on empty input is reported absent rather than
    /// failing the whole evaluation.
    pub(super) fn finish(
        self,
        aggregation: &Aggregation,
        window: &MeasurementWindowOutcome,
    ) -> Result<MeasurementMetricOutcome, MeasurementEvaluationError> {
        let samples = self.samples;
        let aggregate = if samples == 0
            && !matches!(window, MeasurementWindowOutcome::Completed { .. })
            && aggregation_requires_samples(aggregation)
        {
            None
        } else {
            Some(self.aggregate()?)
        };
        Ok(MeasurementMetricOutcome { samples, aggregate })
    }

    /// Returns the exact aggregate of every consumed sample.
    pub(super) fn aggregate(self) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        match self.state {
            FoldState::Count => Ok(MeasurementAggregateValue::Unsigned(self.samples)),
            FoldState::Sum(total) => total.into_aggregate(),
            FoldState::Extreme { selected, desired } => {
                selected
                    .map(Into::into)
                    .ok_or(MeasurementEvaluationError::EmptySamples {
                        aggregation: if desired == std::cmp::Ordering::Less {
                            "min"
                        } else {
                            "max"
                        },
                    })
            }
            FoldState::Mean(total) => {
                if self.samples == 0 {
                    return Err(MeasurementEvaluationError::EmptySamples {
                        aggregation: "exact_mean",
                    });
                }
                total
                    .checked_divide_by(self.samples)
                    .map(MeasurementAggregateValue::Rational)
            }
            FoldState::Histogram { bins, .. } => Ok(MeasurementAggregateValue::Histogram(bins)),
            FoldState::First(first) => {
                first
                    .map(Into::into)
                    .ok_or(MeasurementEvaluationError::EmptySamples {
                        aggregation: "first",
                    })
            }
            FoldState::Last(last) => {
                last.map(Into::into)
                    .ok_or(MeasurementEvaluationError::EmptySamples {
                        aggregation: "last",
                    })
            }
            FoldState::Delta { first, last } => {
                let (Some(first), Some(last)) = (first, last) else {
                    return Err(MeasurementEvaluationError::EmptySamples {
                        aggregation: "event_delta",
                    });
                };
                sample_delta(&first, &last)
            }
        }
    }
}

impl RunningSum {
    fn add(self, value: &MeasurementSampleValue) -> Result<Self, MeasurementEvaluationError> {
        match (self, value) {
            (Self::Signed(total), MeasurementSampleValue::Signed(value)) => total
                .checked_add(*value)
                .map(Self::Signed)
                .ok_or(MeasurementEvaluationError::ArithmeticOverflow),
            (Self::Unsigned(total), MeasurementSampleValue::Unsigned(value)) => total
                .checked_add(*value)
                .map(Self::Unsigned)
                .ok_or(MeasurementEvaluationError::ArithmeticOverflow),
            (Self::Rational(total), MeasurementSampleValue::Rational(value)) => {
                total.checked_add(*value).map(Self::Rational)
            }
            _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
        }
    }

    fn into_aggregate(self) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
        match self {
            Self::Signed(total) => Ok(MeasurementAggregateValue::Signed(total)),
            Self::Unsigned(total) => Ok(MeasurementAggregateValue::Unsigned(total)),
            Self::Rational(total) => Ok(MeasurementAggregateValue::Rational(total)),
            Self::Undefined => Err(MeasurementEvaluationError::ArithmeticOverflow),
        }
    }
}

/// Reports whether an aggregation is undefined on an empty sample window.
pub(super) const fn aggregation_requires_samples(aggregation: &Aggregation) -> bool {
    match aggregation {
        Aggregation::Count | Aggregation::Sum | Aggregation::Histogram { .. } => false,
        Aggregation::Min
        | Aggregation::Max
        | Aggregation::ExactMean
        | Aggregation::First
        | Aggregation::Last
        | Aggregation::EventDelta => true,
    }
}

fn compare_samples(
    left: &MeasurementSampleValue,
    right: &MeasurementSampleValue,
) -> Result<std::cmp::Ordering, MeasurementEvaluationError> {
    match (left, right) {
        (MeasurementSampleValue::Signed(left), MeasurementSampleValue::Signed(right)) => {
            Ok(left.cmp(right))
        }
        (MeasurementSampleValue::Unsigned(left), MeasurementSampleValue::Unsigned(right)) => {
            Ok(left.cmp(right))
        }
        (MeasurementSampleValue::Rational(left), MeasurementSampleValue::Rational(right)) => {
            left.checked_cmp(*right)
        }
        (MeasurementSampleValue::Boolean(left), MeasurementSampleValue::Boolean(right)) => {
            Ok(left.cmp(right))
        }
        _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
    }
}

fn rational_value(
    value: &MeasurementSampleValue,
) -> Result<ReducedRational, MeasurementEvaluationError> {
    match value {
        MeasurementSampleValue::Signed(value) => Ok(ReducedRational::from_signed(*value)),
        MeasurementSampleValue::Unsigned(value) => Ok(ReducedRational::from_unsigned(*value)),
        MeasurementSampleValue::Rational(value) => Ok(*value),
        _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
    }
}

/// Selects the inclusive upper-bound bin, or the overflow bin past the last.
fn histogram_bin(
    value: &MeasurementSampleValue,
    upper_bounds: &[i64],
) -> Result<usize, MeasurementEvaluationError> {
    match value {
        MeasurementSampleValue::Signed(value) => {
            Ok(upper_bounds.partition_point(|bound| *bound < *value))
        }
        MeasurementSampleValue::Unsigned(value) => Ok(upper_bounds.partition_point(|bound| {
            bound.is_negative() || u64::try_from(*bound).is_ok_and(|bound| bound < *value)
        })),
        _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
    }
}

fn sample_delta(
    first: &MeasurementSampleValue,
    last: &MeasurementSampleValue,
) -> Result<MeasurementAggregateValue, MeasurementEvaluationError> {
    match (first, last) {
        (MeasurementSampleValue::Signed(first), MeasurementSampleValue::Signed(last)) => last
            .checked_sub(*first)
            .map(MeasurementAggregateValue::Signed)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow),
        (MeasurementSampleValue::Unsigned(first), MeasurementSampleValue::Unsigned(last)) => last
            .checked_sub(*first)
            .map(MeasurementAggregateValue::Unsigned)
            .ok_or(MeasurementEvaluationError::ArithmeticOverflow),
        (MeasurementSampleValue::Rational(first), MeasurementSampleValue::Rational(last)) => last
            .checked_sub(*first)
            .map(MeasurementAggregateValue::Rational),
        _ => Err(MeasurementEvaluationError::ArithmeticOverflow),
    }
}
