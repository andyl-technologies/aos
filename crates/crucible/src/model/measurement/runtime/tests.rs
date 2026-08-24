//! Exact aggregation and boundary-replay regressions.

use super::*;

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn world() -> Result<World, EngineError> {
    World::from_nodes(
        ["router-a", "router-b"]
            .into_iter()
            .map(|name| WorldNode {
                id: node(name),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::from("measurement-runtime-test"),
                ready_point: ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
                white_box: WhiteBoxPolicy::Enabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            })
            .collect(),
    )
}

fn metric(
    id: &str,
    value_type: MetricValueType,
    aggregation: Aggregation,
) -> Result<MetricDefinition, MeasurementDefinitionError> {
    Ok(MetricDefinition {
        id: MetricId::parse(id)?,
        value_type,
        unit: UnitId::parse("samples")?,
        source: MetricSource::Guest,
        aggregation,
    })
}

fn terminal(at: u64) -> MeasurementTerminalState {
    MeasurementTerminalState {
        scenario_ready_at: Some(VirtualTime { ticks: 1 }),
        at: VirtualTime { ticks: at },
        node_icounts: BTreeMap::from([
            (node("router-a"), Icount { retired: at }),
            (node("router-b"), Icount { retired: at }),
        ]),
        scheduler_quiescent: false,
    }
}

#[test]
fn exact_mean_histogram_and_delta_are_recomputed() -> Result<(), Box<dyn Error>> {
    let mean = aggregate_metric_samples(
        &metric(
            "mean",
            MetricValueType::SignedInteger,
            Aggregation::ExactMean,
        )?,
        &[
            MeasurementSampleValue::Signed(-2),
            MeasurementSampleValue::Signed(5),
        ],
    )?;
    assert_eq!(
        mean,
        MeasurementAggregateValue::Rational(ReducedRational::new(false, 3, 2)?)
    );

    let histogram = aggregate_metric_samples(
        &metric(
            "histogram",
            MetricValueType::SignedInteger,
            Aggregation::Histogram {
                upper_bounds: vec![-1, 10],
            },
        )?,
        &[
            MeasurementSampleValue::Signed(-2),
            MeasurementSampleValue::Signed(-1),
            MeasurementSampleValue::Signed(0),
            MeasurementSampleValue::Signed(10),
            MeasurementSampleValue::Signed(11),
        ],
    )?;
    assert_eq!(
        histogram,
        MeasurementAggregateValue::Histogram(vec![2, 2, 1])
    );
    let wide_unsigned = aggregate_metric_samples(
        &metric(
            "wide-histogram",
            MetricValueType::UnsignedInteger,
            Aggregation::Histogram {
                upper_bounds: vec![0, 10],
            },
        )?,
        &[MeasurementSampleValue::Unsigned(u64::MAX)],
    )?;
    assert_eq!(
        wide_unsigned,
        MeasurementAggregateValue::Histogram(vec![0, 0, 1])
    );

    let delta = aggregate_metric_samples(
        &metric(
            "delta",
            MetricValueType::ReducedRational,
            Aggregation::EventDelta,
        )?,
        &[
            MeasurementSampleValue::Rational(ReducedRational::new(false, 1, 3)?),
            MeasurementSampleValue::Rational(ReducedRational::new(false, 5, 6)?),
        ],
    )?;
    assert_eq!(
        delta,
        MeasurementAggregateValue::Rational(ReducedRational::new(false, 1, 2)?)
    );
    Ok(())
}

#[test]
fn cohort_boundaries_retain_exact_events_and_bound_samples() -> Result<(), Box<dyn Error>> {
    let world = world()?;
    let measurement = MeasurementDefinition {
        id: MeasurementId::parse("recovery")?,
        begin: BoundarySelector::GuestMarker {
            marker: MarkerId::from_name("begin"),
            instance: None,
        },
        end: BoundarySelector::GuestMarker {
            marker: MarkerId::from_name("end"),
            instance: None,
        },
        timeout: Some(ModeledMeasurementTimeout::VirtualTime { nanos: 100 }),
        cohort: CohortPolicy::All(vec![node("router-a"), node("router-b")]),
        metrics: vec![metric(
            "samples",
            MetricValueType::UnsignedInteger,
            Aggregation::Sum,
        )?],
    };
    let definitions = MeasurementDefinitions::new(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        vec![measurement],
    )?;
    let entries = vec![
        SchedulerEventLogEntry::guest_marker_observation(
            0,
            Icount { retired: 10 },
            node("router-b"),
            MarkerId::from_name("begin"),
        ),
        SchedulerEventLogEntry::guest_marker_observation(
            1,
            Icount { retired: 20 },
            node("router-a"),
            MarkerId::from_name("begin"),
        ),
        SchedulerEventLogEntry::guest_marker_observation(
            2,
            Icount { retired: 30 },
            node("router-a"),
            MarkerId::from_name("end"),
        ),
        SchedulerEventLogEntry::guest_marker_observation(
            3,
            Icount { retired: 40 },
            node("router-b"),
            MarkerId::from_name("end"),
        ),
    ];
    let samples = vec![
        MeasurementRuntimeSample::new(
            0,
            MeasurementId::parse("recovery")?,
            MetricId::parse("samples")?,
            MeasurementSampleValue::Unsigned(99),
        ),
        MeasurementRuntimeSample::new(
            1,
            MeasurementId::parse("recovery")?,
            MetricId::parse("samples")?,
            MeasurementSampleValue::Unsigned(5),
        ),
        MeasurementRuntimeSample::new(
            3,
            MeasurementId::parse("recovery")?,
            MetricId::parse("samples")?,
            MeasurementSampleValue::Unsigned(7),
        ),
    ];

    let evaluation = evaluate_measurements(&definitions, &entries, samples.clone(), &terminal(40))?;
    assert_eq!(
        evaluation.content_hash(),
        ContentHash {
            bytes: [
                26, 107, 171, 63, 161, 143, 213, 139, 232, 199, 45, 255, 149, 19, 182, 123, 26,
                250, 143, 142, 125, 205, 176, 93, 115, 210, 157, 225, 221, 172, 42, 210,
            ],
        }
    );
    let outcome = &evaluation.outcomes()[&MeasurementId::parse("recovery")?];
    let MeasurementWindowOutcome::Completed { begin, end } = outcome.window() else {
        panic!("cohort window must complete");
    };
    assert_eq!(begin.sequence(), Some(1));
    assert_eq!(begin.events().len(), 2);
    assert_eq!(begin.cohort(), &[node("router-b"), node("router-a")]);
    assert_eq!(end.sequence(), Some(3));
    assert_eq!(end.events().len(), 2);
    let metric = &outcome.metrics()[&MetricId::parse("samples")?];
    assert_eq!(metric.samples().len(), 2);
    assert_eq!(metric.aggregate(), &MeasurementAggregateValue::Unsigned(12));
    assert_eq!(metric.evidence().len(), 2);
    let verified = verify_measurement_evaluation(
        &definitions,
        &entries,
        samples.clone(),
        &terminal(40),
        evaluation.canonical_bytes(),
    )?;
    assert_eq!(verified.content_hash(), evaluation.content_hash());
    let mut forged = evaluation.canonical_bytes().to_vec();
    forged.push(b' ');
    assert_eq!(
        verify_measurement_evaluation(&definitions, &entries, samples, &terminal(40), &forged,),
        Err(MeasurementEvaluationError::ReplayMismatch)
    );
    Ok(())
}

#[test]
fn semantic_marker_boundaries_require_the_exact_instance() -> Result<(), Box<dyn Error>> {
    let world = world()?;
    let expected_instance = MeasurementInstanceKey::parse("epoch-7")?;
    let measurement = MeasurementDefinition {
        id: MeasurementId::parse("recovery")?,
        begin: BoundarySelector::GuestMarker {
            marker: MarkerId::from_name("begin"),
            instance: Some(expected_instance.clone()),
        },
        end: BoundarySelector::GuestMarker {
            marker: MarkerId::from_name("end"),
            instance: Some(expected_instance),
        },
        timeout: None,
        cohort: CohortPolicy::All(vec![node("router-a")]),
        metrics: vec![metric(
            "samples",
            MetricValueType::UnsignedInteger,
            Aggregation::Count,
        )?],
    };
    let definitions = MeasurementDefinitions::new(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        vec![measurement],
    )?;
    let entries = vec![
        SchedulerEventLogEntry::guest_semantic_marker_observation(
            0,
            Icount { retired: 10 },
            node("router-a"),
            String::from("begin"),
            String::from("other-epoch"),
            Vec::new(),
        ),
        SchedulerEventLogEntry::guest_semantic_marker_observation(
            1,
            Icount { retired: 20 },
            node("router-a"),
            String::from("begin"),
            String::from("epoch-7"),
            Vec::new(),
        ),
        SchedulerEventLogEntry::guest_semantic_marker_observation(
            2,
            Icount { retired: 30 },
            node("router-a"),
            String::from("end"),
            String::from("other-epoch"),
            Vec::new(),
        ),
        SchedulerEventLogEntry::guest_semantic_marker_observation(
            3,
            Icount { retired: 40 },
            node("router-a"),
            String::from("end"),
            String::from("epoch-7"),
            Vec::new(),
        ),
    ];

    let evaluation = evaluate_measurements(&definitions, &entries, Vec::new(), &terminal(40))?;
    let outcome = &evaluation.outcomes()[&MeasurementId::parse("recovery")?];
    let MeasurementWindowOutcome::Completed { begin, end } = outcome.window() else {
        panic!("exact semantic-marker instance must complete the window");
    };
    assert_eq!(begin.sequence(), Some(1));
    assert_eq!(end.sequence(), Some(3));
    Ok(())
}

#[test]
fn end_boundary_wins_a_same_event_timeout() -> Result<(), Box<dyn Error>> {
    let world = world()?;
    let definitions = MeasurementDefinitions::new(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("deadline")?,
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::VirtualTime {
                at: VirtualTime { ticks: 10 },
            },
            timeout: Some(ModeledMeasurementTimeout::VirtualTime { nanos: 10 }),
            cohort: CohortPolicy::Any(vec![node("router-a"), node("router-b")]),
            metrics: vec![metric(
                "count",
                MetricValueType::UnsignedInteger,
                Aggregation::Count,
            )?],
        }],
    )?;
    let entries = vec![SchedulerEventLogEntry::guest_marker_observation(
        0,
        Icount { retired: 10 },
        node("router-a"),
        MarkerId::from_name("tick"),
    )];

    let evaluation = evaluate_measurements(&definitions, &entries, Vec::new(), &terminal(10))?;
    assert!(matches!(
        evaluation.outcomes()[&MeasurementId::parse("deadline")?].window(),
        MeasurementWindowOutcome::Completed { .. }
    ));
    assert_eq!(
        evaluation.outcomes()[&MeasurementId::parse("deadline")?].metrics()
            [&MetricId::parse("count")?]
            .aggregate(),
        &MeasurementAggregateValue::Unsigned(0)
    );
    Ok(())
}

#[test]
fn genesis_relative_timeout_opens_before_the_first_event() -> Result<(), Box<dyn Error>> {
    let world = world()?;
    let definitions = MeasurementDefinitions::new(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("timeout")?,
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::VirtualTime {
                at: VirtualTime { ticks: 20 },
            },
            timeout: Some(ModeledMeasurementTimeout::VirtualTime { nanos: 10 }),
            cohort: CohortPolicy::Any(vec![node("router-a")]),
            metrics: vec![metric(
                "count",
                MetricValueType::UnsignedInteger,
                Aggregation::Count,
            )?],
        }],
    )?;
    let entries = vec![SchedulerEventLogEntry::guest_marker_observation(
        0,
        Icount { retired: 10 },
        node("router-a"),
        MarkerId::from_name("tick"),
    )];

    let evaluation = evaluate_measurements(&definitions, &entries, Vec::new(), &terminal(10))?;
    assert!(matches!(
        evaluation.outcomes()[&MeasurementId::parse("timeout")?].window(),
        MeasurementWindowOutcome::TimedOut { .. }
    ));
    Ok(())
}

#[test]
fn synthetic_ready_coordinate_excludes_earlier_samples() -> Result<(), Box<dyn Error>> {
    let world = world()?;
    let definitions = MeasurementDefinitions::new(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("ready-window")?,
            begin: BoundarySelector::ScenarioReady,
            end: BoundarySelector::VirtualTime {
                at: VirtualTime { ticks: 25 },
            },
            timeout: None,
            cohort: CohortPolicy::Any(vec![node("router-a")]),
            metrics: vec![metric(
                "sum",
                MetricValueType::UnsignedInteger,
                Aggregation::Sum,
            )?],
        }],
    )?;
    let entries = vec![
        SchedulerEventLogEntry::guest_marker_observation(
            0,
            Icount { retired: 10 },
            node("router-a"),
            MarkerId::from_name("before-ready"),
        ),
        SchedulerEventLogEntry::guest_marker_observation(
            1,
            Icount { retired: 20 },
            node("router-a"),
            MarkerId::from_name("after-ready"),
        ),
        SchedulerEventLogEntry::guest_marker_observation(
            2,
            Icount { retired: 25 },
            node("router-a"),
            MarkerId::from_name("end"),
        ),
    ];
    let samples = vec![
        MeasurementRuntimeSample::new(
            0,
            MeasurementId::parse("ready-window")?,
            MetricId::parse("sum")?,
            MeasurementSampleValue::Unsigned(100),
        ),
        MeasurementRuntimeSample::new(
            1,
            MeasurementId::parse("ready-window")?,
            MetricId::parse("sum")?,
            MeasurementSampleValue::Unsigned(7),
        ),
    ];
    let mut terminal = terminal(25);
    terminal.scenario_ready_at = Some(VirtualTime { ticks: 15 });

    let evaluation = evaluate_measurements(&definitions, &entries, samples, &terminal)?;
    let outcome = &evaluation.outcomes()[&MeasurementId::parse("ready-window")?];
    assert!(matches!(
        outcome.window(),
        MeasurementWindowOutcome::Completed { .. }
    ));
    let metric = &outcome.metrics()[&MetricId::parse("sum")?];
    assert_eq!(metric.samples().len(), 1);
    assert_eq!(metric.aggregate(), &MeasurementAggregateValue::Unsigned(7));
    Ok(())
}

#[test]
fn duplicate_and_non_dense_inputs_fail_closed() -> Result<(), Box<dyn Error>> {
    let world = world()?;
    let definitions = MeasurementDefinitions::new(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("bounded")?,
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::VirtualTime {
                at: VirtualTime { ticks: 10 },
            },
            timeout: None,
            cohort: CohortPolicy::Any(vec![node("router-a")]),
            metrics: vec![metric(
                "value",
                MetricValueType::UnsignedInteger,
                Aggregation::Last,
            )?],
        }],
    )?;
    let entry = SchedulerEventLogEntry::guest_marker_observation(
        4,
        Icount { retired: 10 },
        node("router-a"),
        MarkerId::from_name("tick"),
    );
    let sample = MeasurementRuntimeSample::new(
        4,
        MeasurementId::parse("bounded")?,
        MetricId::parse("value")?,
        MeasurementSampleValue::Unsigned(1),
    );
    assert!(matches!(
        evaluate_measurements(
            &definitions,
            std::slice::from_ref(&entry),
            vec![sample.clone(), sample],
            &terminal(10)
        ),
        Err(MeasurementEvaluationError::DuplicateSample { .. })
    ));

    let gap = SchedulerEventLogEntry::guest_marker_observation(
        6,
        Icount { retired: 11 },
        node("router-a"),
        MarkerId::from_name("gap"),
    );
    assert!(matches!(
        evaluate_measurements(&definitions, &[entry, gap], Vec::new(), &terminal(11)),
        Err(MeasurementEvaluationError::NonDenseEventLog { .. })
    ));

    let late_entry = SchedulerEventLogEntry::guest_marker_observation(
        0,
        Icount { retired: 10 },
        node("router-a"),
        MarkerId::from_name("late"),
    );
    assert!(matches!(
        evaluate_measurements(&definitions, &[late_entry], Vec::new(), &terminal(9)),
        Err(MeasurementEvaluationError::TerminalBeforeEvent { .. })
    ));
    Ok(())
}

#[test]
fn model_sources_project_exact_replay_samples() -> Result<(), Box<dyn Error>> {
    let fixture = crate::happy_path_scenario()?;
    let server = node("server");
    let link = LinkId::for_endpoints(&node("client"), &server);
    let event = EventId::from_name("pass-on-quiescence");
    let definitions = MeasurementDefinitions::new(
        fixture.scenario.world(),
        fixture.scenario.plan(),
        fixture.scenario.properties(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("model-owned")?,
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::SchedulerQuiescence,
            timeout: None,
            cohort: CohortPolicy::All(vec![server.clone()]),
            metrics: vec![
                model_metric(
                    "virtual-time",
                    "virtual_nanoseconds",
                    MetricSource::VirtualTime,
                )?,
                model_metric(
                    "node-icount",
                    "instructions",
                    MetricSource::NodeIcount {
                        node: server.clone(),
                    },
                )?,
                model_metric(
                    "event-count",
                    "events",
                    MetricSource::ModeledEventCount {
                        event: event.clone(),
                    },
                )?,
                model_metric(
                    "network-drops",
                    "packets",
                    MetricSource::NetworkModeledDropCount {
                        link: Some(link.clone()),
                    },
                )?,
                model_metric(
                    "storage-completions",
                    "operations",
                    MetricSource::StorageCompletionCount {
                        node: server.clone(),
                    },
                )?,
                model_metric(
                    "scheduler-events",
                    "events",
                    MetricSource::SchedulerEventCount,
                )?,
            ],
        }],
    )?;

    let entries = vec![
        retained_model_event(
            0,
            10,
            &server,
            "tick",
            BTreeMap::from([
                (
                    String::from("icount"),
                    EventAttributeValue::Icount(Icount { retired: 10 }),
                ),
                (
                    String::from("virtual_time"),
                    EventAttributeValue::VirtualTime(VirtualTime { ticks: 10 }),
                ),
            ]),
        )?,
        retained_model_event(
            1,
            20,
            &server,
            "trigger_fired",
            BTreeMap::from([
                (
                    String::from("action"),
                    EventAttributeValue::String(String::from("pass")),
                ),
                (
                    String::from("at"),
                    EventAttributeValue::VirtualTime(VirtualTime { ticks: 20 }),
                ),
                (
                    String::from("condition"),
                    EventAttributeValue::String(String::from("quiescent")),
                ),
                (String::from("event"), EventAttributeValue::Event(event)),
            ]),
        )?,
        retained_model_event(
            2,
            30,
            &server,
            "message_dropped",
            BTreeMap::from([
                (
                    String::from("from"),
                    EventAttributeValue::Node(node("client")),
                ),
                (String::from("link"), EventAttributeValue::String(link.name)),
                (
                    String::from("reason"),
                    EventAttributeValue::String(String::from("modeled-loss")),
                ),
                (
                    String::from("to"),
                    EventAttributeValue::Node(server.clone()),
                ),
            ]),
        )?,
        retained_model_event(
            3,
            40,
            &server,
            "io_completion",
            BTreeMap::from([
                (
                    String::from("consumer"),
                    EventAttributeValue::Node(server.clone()),
                ),
                (
                    String::from("delivery_icount"),
                    EventAttributeValue::Icount(Icount { retired: 40 }),
                ),
                (
                    String::from("node"),
                    EventAttributeValue::Node(server.clone()),
                ),
                (
                    String::from("payload"),
                    EventAttributeValue::Bytes(vec![1, 2, 3]),
                ),
                (
                    String::from("producer"),
                    EventAttributeValue::Node(server.clone()),
                ),
                (String::from("sequence"), EventAttributeValue::U64(0)),
                (
                    String::from("virtual_time"),
                    EventAttributeValue::VirtualTime(VirtualTime { ticks: 40 }),
                ),
            ]),
        )?,
    ];

    let first = derive_model_measurement_samples(&definitions, &entries)?;
    let replayed = derive_model_measurement_samples(&definitions, &entries)?;
    assert_eq!(first, replayed);
    assert_eq!(first.len(), 15);
    assert_eq!(
        samples_for_metric(&first, "virtual-time"),
        vec![10, 20, 30, 40]
    );
    assert_eq!(
        samples_for_metric(&first, "node-icount"),
        vec![10, 20, 30, 40]
    );
    assert_eq!(samples_for_metric(&first, "event-count"), vec![1]);
    assert_eq!(samples_for_metric(&first, "network-drops"), vec![1]);
    assert_eq!(samples_for_metric(&first, "storage-completions"), vec![1]);
    assert_eq!(
        samples_for_metric(&first, "scheduler-events"),
        vec![1, 1, 1, 1]
    );
    Ok(())
}

#[test]
fn malformed_model_source_events_fail_closed() -> Result<(), Box<dyn Error>> {
    let fixture = crate::happy_path_scenario()?;
    let server = node("server");
    let definitions = MeasurementDefinitions::new(
        fixture.scenario.world(),
        fixture.scenario.plan(),
        fixture.scenario.properties(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("network")?,
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::SchedulerQuiescence,
            timeout: None,
            cohort: CohortPolicy::All(vec![server.clone()]),
            metrics: vec![model_metric(
                "drops",
                "packets",
                MetricSource::NetworkModeledDropCount { link: None },
            )?],
        }],
    )?;
    let malformed = retained_model_event(0, 1, &server, "message_dropped", BTreeMap::new())?;

    assert!(matches!(
        derive_model_measurement_samples(&definitions, &[malformed]),
        Err(MeasurementEvaluationError::InvalidModelSourceEvent {
            sequence: 0,
            kind: "message_dropped"
        })
    ));

    let forged_guest_drop = SchedulerEventLogEntry::from_retained_open_event(
        0,
        crate::EventLogTime::from_virtual_time(VirtualTime { ticks: 1 })
            .with_icount(server.clone(), Icount { retired: 1 }),
        EventSource::Guest { node: server },
        EventLevel::Info,
        SchedulerEventLogClass::Causal,
        crate::EventPayload::new(
            "message_dropped",
            BTreeMap::from([(
                String::from("link"),
                EventAttributeValue::String(
                    LinkId::for_endpoints(&node("client"), &node("server")).name,
                ),
            )]),
        ),
    )?;
    assert!(matches!(
        derive_model_measurement_samples(&definitions, &[forged_guest_drop]),
        Err(MeasurementEvaluationError::InvalidModelSourceEvent {
            sequence: 0,
            kind: "message_dropped"
        })
    ));
    Ok(())
}

#[test]
fn model_source_projection_rejects_visit_amplification_before_sampling()
-> Result<(), Box<dyn Error>> {
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

    assert_eq!(
        definitions
            .definitions()
            .iter()
            .map(|definition| definition.metrics.len())
            .sum::<usize>()
            * entries.len(),
        4_001_792
    );
    assert!(matches!(
        derive_model_measurement_samples(&definitions, &entries),
        Err(MeasurementEvaluationError::LimitExceeded {
            limit: "model-measurement-event-visits"
        })
    ));
    Ok(())
}

fn model_metric(
    id: &str,
    unit: &str,
    source: MetricSource,
) -> Result<MetricDefinition, MeasurementDefinitionError> {
    Ok(MetricDefinition {
        id: MetricId::parse(id)?,
        value_type: MetricValueType::UnsignedInteger,
        unit: UnitId::parse(unit)?,
        source,
        aggregation: Aggregation::Sum,
    })
}

fn retained_model_event(
    sequence: u64,
    ticks: u64,
    node: &NodeId,
    kind: &str,
    attributes: BTreeMap<String, EventAttributeValue>,
) -> Result<SchedulerEventLogEntry, crate::SchedulerError> {
    SchedulerEventLogEntry::from_retained_open_event(
        sequence,
        crate::EventLogTime::from_virtual_time(VirtualTime { ticks })
            .with_icount(node.clone(), Icount { retired: ticks }),
        EventSource::Engine,
        EventLevel::Info,
        SchedulerEventLogClass::Causal,
        crate::EventPayload::new(kind, attributes),
    )
}

fn samples_for_metric(samples: &[MeasurementRuntimeSample], metric: &str) -> Vec<u64> {
    samples
        .iter()
        .filter(|sample| sample.metric().as_str() == metric)
        .map(|sample| match sample.value() {
            MeasurementSampleValue::Unsigned(value) => *value,
            value => panic!("model projector emitted non-unsigned sample: {value:?}"),
        })
        .collect()
}
