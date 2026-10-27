//! Single forward pass over a scheduler log for measurement evaluation.
//!
//! [`MeasurementReplay`] folds authenticated scheduler entries one at a time.
//! Each entry advances every window, and each sample the entry carries is
//! folded into its metric's aggregate at once if its window is open there.
//! The replay keeps window progress and one [`MetricFold`] per declared metric,
//! so its state is bounded by the declarations rather than by the log or the
//! samples it carries (RFC-0020 CMEAS-23). It never retains the log itself, so
//! a caller can stream entries from storage in order.
//!
//! [`ModelSampleProjector`] derives model-owned samples for one entry. It is a
//! separate producer, like the guest protocol adapter, so callers decide which
//! producers feed a replay.

use super::boundary::WindowProgress;
use super::fold::MetricFold;
use super::*;

/// Replay state for one declared measurement.
struct MeasurementFolds<'definition> {
    definition: &'definition MeasurementDefinition,
    window: WindowProgress<'definition>,
    // Whether the window is open at the entry being observed.
    inside: bool,
    // Samples admitted while the window is open, in declared metric order.
    folds: Vec<MetricFold>,
    // Samples at the terminal coordinate that arrived before any entry opened
    // the window. A begin boundary resolved only at the terminal coordinate
    // has exactly that coordinate, so these are the samples it admits.
    terminal_folds: Vec<MetricFold>,
    // Sequence of each metric's last sample, which rejects a second sample
    // for one metric on one entry.
    last_sample: Vec<Option<u64>>,
}

impl<'definition> MeasurementFolds<'definition> {
    fn new(
        definition: &'definition MeasurementDefinition,
        scenario_ready_at: Option<VirtualTime>,
    ) -> Self {
        let folds = definition
            .metrics
            .iter()
            .map(MetricFold::new)
            .collect::<Vec<_>>();
        Self {
            definition,
            window: WindowProgress::new(definition, scenario_ready_at),
            inside: false,
            terminal_folds: folds.clone(),
            folds,
            last_sample: vec![None; definition.metrics.len()],
        }
    }

    fn finish(
        self,
        terminal: &MeasurementTerminalState,
    ) -> Result<MeasurementOutcome, MeasurementEvaluationError> {
        let opened_by_entry = self.window.is_opened();
        let window = self.window.finish(terminal);
        let folds = if opened_by_entry || matches!(window, MeasurementWindowOutcome::NotStarted) {
            self.folds
        } else {
            self.terminal_folds
        };

        let mut metrics = BTreeMap::new();
        for (metric, fold) in self.definition.metrics.iter().zip(folds) {
            metrics.insert(
                metric.id.clone(),
                fold.finish(&metric.aggregation, &window)?,
            );
        }
        Ok(MeasurementOutcome { window, metrics })
    }
}

/// Incremental measurement evaluation over a dense scheduler log.
///
/// Feed every entry in sequence order with [`Self::observe`], then call
/// [`Self::finish`]. The result is identical to evaluating the complete log at
/// once, however the entries were batched.
///
/// # Examples
///
/// ```no_run
/// use crucible_engine::model::{
///     MeasurementDefinitions, MeasurementEvaluationError, MeasurementReplay,
///     MeasurementTerminalState, ModelSampleProjector,
/// };
/// use crucible_engine::SchedulerEventLogEntry;
///
/// fn evaluate(
///     definitions: &MeasurementDefinitions,
///     terminal: &MeasurementTerminalState,
///     entries: impl IntoIterator<Item = SchedulerEventLogEntry>,
/// ) -> Result<(), MeasurementEvaluationError> {
///     let projector = ModelSampleProjector::new(definitions);
///     let mut replay = MeasurementReplay::new(definitions, terminal)?;
///     for entry in entries {
///         let mut samples = Vec::new();
///         projector.project(&entry, &mut samples)?;
///         replay.observe(&entry, samples)?;
///     }
///     let _evaluation = replay.finish()?;
///     Ok(())
/// }
/// ```
pub struct MeasurementReplay<'definitions> {
    definitions: &'definitions MeasurementDefinitions,
    terminal: &'definitions MeasurementTerminalState,
    positions: BTreeMap<&'definitions MeasurementId, usize>,
    measurements: Vec<MeasurementFolds<'definitions>>,
    last_sequence: Option<u64>,
}

impl<'definitions> MeasurementReplay<'definitions> {
    /// Starts a replay against exact definitions and terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`MeasurementEvaluationError`] when the terminal state carries
    /// too many node counters or its scenario-ready coordinate follows its
    /// terminal coordinate.
    pub fn new(
        definitions: &'definitions MeasurementDefinitions,
        terminal: &'definitions MeasurementTerminalState,
    ) -> Result<Self, MeasurementEvaluationError> {
        if terminal.node_icounts.len() > MAX_MEASUREMENT_TERMINAL_NODES {
            return Err(MeasurementEvaluationError::LimitExceeded {
                limit: "measurement-terminal-nodes",
            });
        }

        let positions = definitions
            .definitions()
            .iter()
            .enumerate()
            .map(|(position, definition)| (&definition.id, position))
            .collect();
        let measurements = definitions
            .definitions()
            .iter()
            .map(|definition| MeasurementFolds::new(definition, terminal.scenario_ready_at))
            .collect();
        Ok(Self {
            definitions,
            terminal,
            positions,
            measurements,
            last_sequence: None,
        })
    }

    /// Folds one scheduler entry and the samples it carries.
    ///
    /// Every sample must name `entry`'s sequence. Samples from all producers
    /// for one entry must be supplied together, in any order.
    ///
    /// # Errors
    ///
    /// Returns [`MeasurementEvaluationError`] when the entry fails its content
    /// hash, does not follow the previous entry densely, lies beyond the
    /// terminal coordinate or icount, or when a sample names another sequence,
    /// an undeclared target, a mistyped value, or a duplicate.
    pub fn observe(
        &mut self,
        entry: &SchedulerEventLogEntry,
        samples: impl IntoIterator<Item = MeasurementRuntimeSample>,
    ) -> Result<(), MeasurementEvaluationError> {
        self.admit_entry(entry)?;

        for measurement in &mut self.measurements {
            measurement.inside = measurement.window.observe(entry);
        }
        for sample in samples {
            self.fold_sample(entry, sample)?;
        }
        Ok(())
    }

    /// Resolves terminal boundaries and builds the canonical evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`MeasurementEvaluationError`] when the scenario-ready
    /// coordinate follows the terminal coordinate, an aggregate fails exact
    /// arithmetic, or the evaluation exceeds its canonical byte bound.
    pub fn finish(self) -> Result<MeasurementEvaluation, MeasurementEvaluationError> {
        if self
            .terminal
            .scenario_ready_at
            .is_some_and(|ready| ready > self.terminal.at)
        {
            return Err(MeasurementEvaluationError::TerminalBeforeEvent {
                sequence: self.last_sequence.unwrap_or(0),
            });
        }

        let mut outcomes = BTreeMap::new();
        for measurement in self.measurements {
            let id = measurement.definition.id.clone();
            outcomes.insert(id, measurement.finish(self.terminal)?);
        }
        MeasurementEvaluation::new(self.definitions.content_hash(), outcomes)
    }

    fn admit_entry(
        &mut self,
        entry: &SchedulerEventLogEntry,
    ) -> Result<(), MeasurementEvaluationError> {
        if !entry.has_valid_content_hash() {
            return Err(MeasurementEvaluationError::InvalidEventHash {
                sequence: entry.sequence(),
            });
        }
        if let Some(previous) = self.last_sequence
            && previous.checked_add(1) != Some(entry.sequence())
        {
            return Err(MeasurementEvaluationError::NonDenseEventLog {
                previous,
                actual: entry.sequence(),
            });
        }
        self.last_sequence = Some(entry.sequence());

        if entry.at() > self.terminal.at {
            return Err(MeasurementEvaluationError::TerminalBeforeEvent {
                sequence: entry.sequence(),
            });
        }
        if let Some(node) = &entry.time().stamp.node
            && self
                .terminal
                .node_icounts
                .get(node)
                .zip(entry.time().stamp.retired)
                .is_some_and(|(terminal, observed)| terminal.retired < observed.retired)
        {
            return Err(MeasurementEvaluationError::TerminalIcountRegression {
                node: node.clone(),
            });
        }
        Ok(())
    }

    fn fold_sample(
        &mut self,
        entry: &SchedulerEventLogEntry,
        sample: MeasurementRuntimeSample,
    ) -> Result<(), MeasurementEvaluationError> {
        if sample.sequence != entry.sequence() {
            return Err(MeasurementEvaluationError::UnknownSampleSequence {
                sequence: sample.sequence,
            });
        }
        let (position, metric) = locate_sample_target(&self.positions, self.definitions, &sample)?;
        let at_terminal = entry.at() == self.terminal.at;

        let measurement = &mut self.measurements[position];
        if measurement.last_sample[metric] == Some(sample.sequence) {
            return Err(MeasurementEvaluationError::DuplicateSample {
                measurement: sample.measurement,
                metric: sample.metric,
                sequence: sample.sequence,
            });
        }
        measurement.last_sample[metric] = Some(sample.sequence);

        if measurement.inside {
            measurement.folds[metric].observe(&sample.value);
        } else if at_terminal && !measurement.window.is_opened() {
            measurement.terminal_folds[metric].observe(&sample.value);
        }
        Ok(())
    }
}

/// Resolves a sample's declared measurement and metric positions.
fn locate_sample_target(
    positions: &BTreeMap<&MeasurementId, usize>,
    definitions: &MeasurementDefinitions,
    sample: &MeasurementRuntimeSample,
) -> Result<(usize, usize), MeasurementEvaluationError> {
    let position = *positions.get(&sample.measurement).ok_or_else(|| {
        MeasurementEvaluationError::UnknownSampleTarget {
            kind: "measurement",
            id: sample.measurement.as_str().to_owned(),
        }
    })?;
    let metrics = &definitions.definitions()[position].metrics;
    let metric = metrics
        .iter()
        .position(|metric| metric.id == sample.metric)
        .ok_or_else(|| MeasurementEvaluationError::UnknownSampleTarget {
            kind: "metric",
            id: sample.metric.as_str().to_owned(),
        })?;
    if !sample_matches_type(&sample.value, &metrics[metric].value_type) {
        return Err(MeasurementEvaluationError::SampleTypeMismatch {
            measurement: sample.measurement.clone(),
            metric: sample.metric.clone(),
        });
    }
    Ok((position, metric))
}

/// Derives model-owned samples one scheduler entry at a time.
///
/// Virtual-time and scheduler-event metrics sample every entry; node icounts
/// sample entries stamped for the declared node; modeled event, network-drop,
/// and storage-completion metrics sample their exact typed event classes.
/// Guest metrics remain the responsibility of the guest protocol adapter.
pub struct ModelSampleProjector<'definitions> {
    metrics: Vec<(&'definitions MeasurementId, &'definitions MetricDefinition)>,
}

impl<'definitions> ModelSampleProjector<'definitions> {
    /// Collects every model-sourced metric the definitions declare.
    #[must_use]
    pub fn new(definitions: &'definitions MeasurementDefinitions) -> Self {
        let metrics = definitions
            .definitions()
            .iter()
            .flat_map(|definition| {
                definition
                    .metrics
                    .iter()
                    .filter(|metric| metric.source != MetricSource::Guest)
                    .map(move |metric| (&definition.id, metric))
            })
            .collect();
        Self { metrics }
    }

    /// Appends the model samples one entry carries.
    ///
    /// # Errors
    ///
    /// Returns [`MeasurementEvaluationError::InvalidModelSourceEvent`] when a
    /// sampled event lacks its required typed attribute or carries an invalid
    /// source authority.
    pub fn project(
        &self,
        entry: &SchedulerEventLogEntry,
        samples: &mut Vec<MeasurementRuntimeSample>,
    ) -> Result<(), MeasurementEvaluationError> {
        for (measurement, metric) in &self.metrics {
            if let Some(value) = model_sample_value(metric, entry)? {
                samples.push(MeasurementRuntimeSample::new(
                    entry.sequence(),
                    (*measurement).clone(),
                    metric.id.clone(),
                    value,
                ));
            }
        }
        Ok(())
    }
}
