//! Folded evaluation stays bounded by the declarations, not the log.

use super::*;

#[test]
fn model_source_amplification_folds_without_retaining_samples() -> Result<(), Box<dyn Error>> {
    let fixture = crate::happy_path_scenario()?;
    let server = node("server");
    let definitions = (0..4)
        .map(|measurement| {
            let metrics = (0..MAX_METRICS_PER_MEASUREMENT)
                .map(|metric| {
                    model_metric(
                        &format!("scheduler-{metric}"),
                        "events",
                        MetricSource::SchedulerEventCount,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(MeasurementDefinition {
                id: MeasurementId::parse(format!("bounded-{measurement}"))?,
                begin: BoundarySelector::ScenarioGenesis,
                end: BoundarySelector::SchedulerQuiescence,
                timeout: None,
                cohort: CohortPolicy::All(vec![server.clone()]),
                metrics,
            })
        })
        .collect::<Result<Vec<_>, MeasurementDefinitionError>>()?;
    let definitions = MeasurementDefinitions::new(
        fixture.scenario.world(),
        fixture.scenario.plan(),
        fixture.scenario.properties(),
        definitions,
    )?;
    let entries = (0_u64..977)
        .map(|sequence| {
            retained_model_event(
                sequence,
                sequence,
                &server,
                "tick",
                BTreeMap::from([
                    (
                        String::from("icount"),
                        EventAttributeValue::Icount(Icount { retired: sequence }),
                    ),
                    (
                        String::from("virtual_time"),
                        EventAttributeValue::VirtualTime(VirtualTime { ticks: sequence }),
                    ),
                ]),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let declared_metrics = definitions
        .definitions()
        .iter()
        .map(|definition| definition.metrics.len())
        .sum::<usize>();
    assert_eq!(declared_metrics * entries.len(), 4_001_792);

    // Four million samples stream through one replay; each is folded into its
    // metric's count as its entry is replayed and none is retained.
    let terminal = terminal(976);
    let projector = ModelSampleProjector::new(&definitions);
    let mut replay = MeasurementReplay::new(&definitions, &terminal)?;
    let mut samples = Vec::new();
    for entry in &entries {
        projector.project(entry, &mut samples)?;
        replay.observe(entry, samples.drain(..))?;
    }
    let evaluation = replay.finish()?;
    for outcome in evaluation.outcomes().values() {
        for metric in outcome.metrics().values() {
            assert_eq!(metric.samples(), 977);
            assert_eq!(
                metric.aggregate(),
                Some(&MeasurementAggregateValue::Unsigned(977))
            );
        }
    }
    Ok(())
}

#[test]
fn terminal_begin_admits_only_samples_at_the_terminal_coordinate() -> Result<(), Box<dyn Error>> {
    let definitions = MeasurementDefinitions::new(
        &world()?,
        &Plan::empty(),
        &Properties::empty(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("settled")?,
            begin: BoundarySelector::SchedulerQuiescence,
            end: BoundarySelector::SchedulerQuiescence,
            timeout: None,
            cohort: CohortPolicy::Any(vec![node("router-a")]),
            metrics: vec![metric(
                "count",
                MetricValueType::UnsignedInteger,
                Aggregation::Count,
            )?],
        }],
    )?;
    let entries = [10, 20, 20]
        .into_iter()
        .zip(0_u64..)
        .map(|(icount, sequence)| {
            SchedulerEventLogEntry::guest_marker_observation(
                sequence,
                Icount { retired: icount },
                node("router-a"),
                MarkerId::from_name("progress"),
            )
        })
        .collect::<Vec<_>>();
    let samples = entries
        .iter()
        .map(|entry| {
            Ok(MeasurementRuntimeSample::new(
                entry.sequence(),
                MeasurementId::parse("settled")?,
                MetricId::parse("count")?,
                MeasurementSampleValue::Unsigned(1),
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut terminal = terminal(20);
    terminal.scheduler_quiescent = true;

    // Quiescence is known only at the terminal coordinate, so the window opens
    // there and admits the two samples at tick 20 but not the one at tick 10.
    let evaluation = evaluate_measurements(&definitions, &entries, samples, &terminal)?;
    let outcome = &evaluation.outcomes()[&MeasurementId::parse("settled")?];
    assert!(matches!(
        outcome.window(),
        MeasurementWindowOutcome::Completed { begin, .. } if begin.sequence().is_none()
    ));
    let metric = &outcome.metrics()[&MetricId::parse("count")?];
    assert_eq!(metric.samples(), 2);
    assert_eq!(
        metric.aggregate(),
        Some(&MeasurementAggregateValue::Unsigned(2))
    );
    Ok(())
}
