//! Single forward pass over a scheduler log for measurement evaluation.
//!
//! [`MeasurementReplay`] folds authenticated scheduler entries one at a time.
//! Its state is bounded by the declared measurements and the samples they
//! admit: window progress per definition, the admitted samples, and the
//! scheduler coordinates of the entries carrying them. It never retains the
//! log itself, so a caller can stream entries from storage in order.
//!
//! [`ModelSampleProjector`] derives model-owned samples for one entry. It is a
//! separate producer, like the guest protocol adapter, so callers decide which
//! producers feed a replay.

use super::boundary::WindowProgress;
use super::*;

/// Scheduler coordinates of one entry that carries at least one sample.
#[derive(Clone, Copy)]
struct SampleEntry {
    at: VirtualTime,
    content_hash: ContentHash,
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
/// use crucible::model::{
///     MeasurementDefinitions, MeasurementEvaluationError, MeasurementReplay,
///     MeasurementTerminalState, ModelSampleProjector,
/// };
/// use crucible::SchedulerEventLogEntry;
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
    definitions_by_id: BTreeMap<&'definitions MeasurementId, &'definitions MeasurementDefinition>,
    windows: Vec<WindowProgress<'definitions>>,
    samples: SampleIndex,
    sample_count: usize,
    // Length of the samples' canonical JSON array, counted incrementally so
    // the bound matches encoding every admitted sample at once.
    sample_bytes: usize,
    sample_entries: BTreeMap<u64, SampleEntry>,
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

        let definitions_by_id = definitions
            .definitions()
            .iter()
            .map(|definition| (&definition.id, definition))
            .collect();
        let windows = definitions
            .definitions()
            .iter()
            .map(|definition| WindowProgress::new(definition, terminal.scenario_ready_at))
            .collect();
        Ok(Self {
            definitions,
            terminal,
            definitions_by_id,
            windows,
            samples: SampleIndex::new(),
            sample_count: 0,
            sample_bytes: "[]".len(),
            sample_entries: BTreeMap::new(),
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
    /// an undeclared target, a mistyped value, a duplicate, or exceeds the
    /// sample count or byte bound.
    pub fn observe(
        &mut self,
        entry: &SchedulerEventLogEntry,
        samples: impl IntoIterator<Item = MeasurementRuntimeSample>,
    ) -> Result<(), MeasurementEvaluationError> {
        self.admit_entry(entry)?;

        let mut carries_sample = false;
        for sample in samples {
            self.admit_sample(entry, sample)?;
            carries_sample = true;
        }
        if carries_sample {
            self.sample_entries.insert(
                entry.sequence(),
                SampleEntry {
                    at: entry.at(),
                    content_hash: entry.content_hash(),
                },
            );
        }

        for window in &mut self.windows {
            window.observe(entry);
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
    pub fn finish(mut self) -> Result<MeasurementEvaluation, MeasurementEvaluationError> {
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
        for (definition, window) in self.definitions.definitions().iter().zip(self.windows) {
            let window = window.finish(self.terminal);
            let mut metrics = BTreeMap::new();
            for metric in &definition.metrics {
                let offered = self
                    .samples
                    .remove(&(definition.id.clone(), metric.id.clone()))
                    .unwrap_or_default();
                let outcome =
                    metric_outcome(metric, &window, offered, &self.sample_entries)?;
                metrics.insert(metric.id.clone(), outcome);
            }
            outcomes.insert(
                definition.id.clone(),
                MeasurementOutcome { window, metrics },
            );
        }
        MeasurementEvaluation::new(self.definitions.content_hash(), outcomes)
    }

    fn admit_entry(&mut self, entry: &SchedulerEventLogEntry) -> Result<(), MeasurementEvaluationError> {
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

    fn admit_sample(
        &mut self,
        entry: &SchedulerEventLogEntry,
        sample: MeasurementRuntimeSample,
    ) -> Result<(), MeasurementEvaluationError> {
        if sample.sequence != entry.sequence() {
            return Err(MeasurementEvaluationError::UnknownSampleSequence {
                sequence: sample.sequence,
            });
        }
        validate_sample_target(&self.definitions_by_id, &sample)?;

        if self.sample_count == MAX_MEASUREMENT_RUNTIME_SAMPLES {
            return Err(MeasurementEvaluationError::LimitExceeded {
                limit: "measurement-runtime-samples",
            });
        }
        let separator = usize::from(self.sample_count > 0);
        let encoded = encoded_runtime_sample_len(&sample)?;
        self.sample_bytes = self
            .sample_bytes
            .checked_add(separator)
            .and_then(|length| length.checked_add(encoded))
            .filter(|length| *length <= MAX_MEASUREMENT_RUNTIME_SAMPLE_BYTES)
            .ok_or(MeasurementEvaluationError::LimitExceeded {
                limit: "measurement-runtime-sample-bytes",
            })?;

        let retained = self
            .samples
            .entry((sample.measurement.clone(), sample.metric.clone()))
            .or_default();
        if retained
            .last()
            .is_some_and(|previous| previous.sequence == sample.sequence)
        {
            return Err(MeasurementEvaluationError::DuplicateSample {
                measurement: sample.measurement,
                metric: sample.metric,
                sequence: sample.sequence,
            });
        }
        retained.push(sample);
        self.sample_count += 1;
        Ok(())
    }
}

/// Selects the samples a window admits and recomputes their aggregate.
fn metric_outcome(
    metric: &MetricDefinition,
    window: &MeasurementWindowOutcome,
    offered: Vec<MeasurementRuntimeSample>,
    sample_entries: &BTreeMap<u64, SampleEntry>,
) -> Result<MeasurementMetricOutcome, MeasurementEvaluationError> {
    let mut samples = Vec::new();
    let mut evidence = Vec::new();
    for sample in offered {
        let entry = sample_entries.get(&sample.sequence).ok_or(
            MeasurementEvaluationError::UnknownSampleSequence {
                sequence: sample.sequence,
            },
        )?;
        if window.includes(entry.at, sample.sequence) {
            evidence.push(entry.content_hash);
            samples.push(sample);
        }
    }

    let values = samples
        .iter()
        .map(|sample| sample.value.clone())
        .collect::<Vec<_>>();
    // Only a completed window commits a measurement. A window that never
    // opened, is still open, or timed out may lack every sample, so an
    // aggregation undefined on empty input is reported absent rather than
    // failing the whole evaluation.
    let aggregate = if values.is_empty()
        && !matches!(window, MeasurementWindowOutcome::Completed { .. })
        && aggregation_requires_samples(&metric.aggregation)
    {
        None
    } else {
        Some(aggregate_metric_samples(metric, &values)?)
    };
    Ok(MeasurementMetricOutcome {
        samples,
        aggregate,
        evidence,
    })
}

fn validate_sample_target(
    definitions_by_id: &BTreeMap<&MeasurementId, &MeasurementDefinition>,
    sample: &MeasurementRuntimeSample,
) -> Result<(), MeasurementEvaluationError> {
    let definition = definitions_by_id.get(&sample.measurement).ok_or_else(|| {
        MeasurementEvaluationError::UnknownSampleTarget {
            kind: "measurement",
            id: sample.measurement.as_str().to_owned(),
        }
    })?;
    let metric = definition
        .metrics
        .iter()
        .find(|metric| metric.id == sample.metric)
        .ok_or_else(|| MeasurementEvaluationError::UnknownSampleTarget {
            kind: "metric",
            id: sample.metric.as_str().to_owned(),
        })?;
    if !sample_matches_type(&sample.value, &metric.value_type) {
        return Err(MeasurementEvaluationError::SampleTypeMismatch {
            measurement: sample.measurement.clone(),
            metric: sample.metric.clone(),
        });
    }
    Ok(())
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
