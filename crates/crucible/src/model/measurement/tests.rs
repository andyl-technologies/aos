//! Measurement-definition canonicalization and scenario-integration regressions.

use super::*;

fn measurement_world() -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: String::from("router-a"),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("measurement-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

fn definition(id: &str, metric: &str) -> Result<MeasurementDefinition, MeasurementDefinitionError> {
    Ok(MeasurementDefinition {
        id: MeasurementId::parse(id)?,
        begin: BoundarySelector::ScenarioReady,
        end: BoundarySelector::VirtualTime {
            at: VirtualTime { ticks: 500 },
        },
        timeout: Some(ModeledMeasurementTimeout::VirtualTime { nanos: 1_000 }),
        cohort: CohortPolicy::All(vec![NodeId {
            name: String::from("router-a"),
        }]),
        metrics: vec![MetricDefinition {
            id: MetricId::parse(metric)?,
            value_type: MetricValueType::UnsignedInteger,
            unit: UnitId::parse("virtual_nanoseconds")?,
            source: MetricSource::VirtualTime,
            aggregation: Aggregation::EventDelta,
        }],
    })
}

#[test]
fn measurement_order_is_canonical_and_changes_scenario_identity() -> Result<(), Box<dyn Error>> {
    let world = measurement_world()?;
    let plan = Plan::empty();
    let properties = Properties::empty();
    let left = MeasurementDefinitions::new(
        &world,
        &plan,
        &properties,
        vec![
            definition("z-window", "z-metric")?,
            definition("a-window", "a-metric")?,
        ],
    )?;
    let right = MeasurementDefinitions::new(
        &world,
        &plan,
        &properties,
        vec![
            definition("a-window", "a-metric")?,
            definition("z-window", "z-metric")?,
        ],
    )?;
    assert_eq!(left, right);
    assert_eq!(left.definitions()[0].id.as_str(), "a-window");

    let empty = ScenarioDefForm::from_components(&world, &plan, &properties, Seed::default())?;
    let measured = ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        &left,
        Seed::default(),
        DEFAULT_APP_RANDOM_DRAW_CAP,
    )?;
    assert_ne!(empty.id(), measured.id());
    assert_eq!(measured.measurements(), &left);
    Ok(())
}

#[test]
fn measured_scenario_round_trips_binary_and_toml() -> Result<(), Box<dyn Error>> {
    let world = measurement_world()?;
    let plan = Plan::empty();
    let properties = Properties::empty();
    let measurements = MeasurementDefinitions::new(
        &world,
        &plan,
        &properties,
        vec![definition("recovery", "latency")?],
    )?;
    assert_eq!(
        measurements.canonical_bytes(),
        br#"[{"id":"recovery","begin":{"kind":"scenario_ready"},"end":{"kind":"virtual_time","at":{"ticks":500}},"timeout":{"kind":"virtual_time","nanos":1000},"cohort":{"kind":"all","value":[{"name":"router-a"}]},"metric":[{"id":"latency","value_type":{"kind":"unsigned_integer"},"unit":"virtual_nanoseconds","source":{"kind":"virtual_time"},"aggregation":{"kind":"event_delta"}}]}]"#,
    );
    let form = ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        &measurements,
        Seed::default(),
        DEFAULT_APP_RANDOM_DRAW_CAP,
    )?;

    let binary = form.to_compact_binary();
    assert!(binary.starts_with(SCENARIO_FORM_BINARY_MAGIC_V6));
    assert_eq!(ScenarioDefForm::from_compact_binary(&binary)?, form);

    let toml = form.to_canonical_toml()?;
    assert!(toml.contains("schema = \"crucible.scenario.v6\""));
    assert!(toml.contains("[[measurement]]"));
    assert!(toml.contains("[[measurement.metric]]"));
    assert_eq!(ScenarioDefForm::from_canonical_toml(&toml)?, form);
    assert!(
        ScenarioDefForm::from_canonical_toml(
            &toml.replace("crucible.scenario.v6", "crucible.scenario.v5")
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn v5_scenario_reads_as_empty_measurements_without_identity_drift() -> Result<(), Box<dyn Error>> {
    let world = measurement_world()?;
    let plan = Plan::empty();
    let properties = Properties::empty();
    let form = ScenarioDefForm::from_components(&world, &plan, &properties, Seed::default())?;
    let mut writer = ScenarioBinaryWriter::new(SCENARIO_FORM_BINARY_MAGIC_V5);
    writer.write_hash(form.id());
    write_world_binary(&form.world, &mut writer);
    write_plan_binary(&form.plan, &mut writer);
    write_properties_binary(&form.properties, &mut writer);
    writer.write_seed(form.seed);
    writer.write_u64(form.app_random_draw_cap);

    let scenario_v5 = writer.finish();
    let decoded = ScenarioDefForm::from_compact_binary(&scenario_v5)?;
    assert_eq!(decoded.id(), form.id());
    assert!(decoded.measurements().is_empty());
    let toml_v5 = form
        .to_canonical_toml()?
        .replace("crucible.scenario.v6", "crucible.scenario.v5");
    let decoded_toml = ScenarioDefForm::from_canonical_toml(&toml_v5)?;
    assert_eq!(decoded_toml.id(), form.id());
    assert!(decoded_toml.measurements().is_empty());

    let schedule = Schedule::empty();
    let mut artifact = ScenarioBinaryWriter::new(REPRODUCTION_ARTIFACT_BINARY_MAGIC_V5);
    artifact.write_binary_blob(&scenario_v5);
    artifact.write_binary_blob(&schedule.to_compact_binary());
    let artifact = ReproductionArtifact::from_compact_binary(&artifact.finish())?;
    assert_eq!(artifact.scenario_form(), &form);
    assert_eq!(artifact.schedule(), &schedule);
    Ok(())
}

#[test]
fn measurement_references_and_aggregation_fail_closed() -> Result<(), Box<dyn Error>> {
    let world = measurement_world()?;
    let plan = Plan::empty();
    let properties = Properties::empty();
    let mut unknown_event = definition("bad-event", "count")?;
    unknown_event.begin = BoundarySelector::PlanEvent {
        event: EventId::from_name("missing"),
    };
    assert!(matches!(
        MeasurementDefinitions::new(&world, &plan, &properties, vec![unknown_event]),
        Err(MeasurementDefinitionError::UnknownReference {
            kind: "plan event",
            ..
        })
    ));

    let mut invalid_aggregate = definition("bad-aggregate", "flag")?;
    invalid_aggregate.metrics[0].value_type = MetricValueType::Boolean;
    invalid_aggregate.metrics[0].source = MetricSource::Guest;
    invalid_aggregate.metrics[0].aggregation = Aggregation::ExactMean;
    assert!(matches!(
        MeasurementDefinitions::new(&world, &plan, &properties, vec![invalid_aggregate]),
        Err(MeasurementDefinitionError::IncompatibleAggregation { .. })
    ));

    let mut host_unit = definition("bad-unit", "duration")?;
    host_unit.metrics[0].unit = UnitId::parse("host_seconds")?;
    assert!(matches!(
        MeasurementDefinitions::new(&world, &plan, &properties, vec![host_unit]),
        Err(MeasurementDefinitionError::UnknownReference {
            kind: "metric unit",
            ..
        })
    ));

    let mut incompatible_source = definition("bad-source", "flag")?;
    incompatible_source.metrics[0].value_type = MetricValueType::Boolean;
    assert!(matches!(
        MeasurementDefinitions::new(&world, &plan, &properties, vec![incompatible_source]),
        Err(MeasurementDefinitionError::IncompatibleSource { .. })
    ));

    let mut wrong_unit = definition("wrong-unit", "duration")?;
    wrong_unit.metrics[0].unit = UnitId::parse("packets")?;
    assert!(matches!(
        MeasurementDefinitions::new(&world, &plan, &properties, vec![wrong_unit]),
        Err(MeasurementDefinitionError::IncompatibleSource { .. })
    ));
    Ok(())
}

#[test]
fn measurement_binary_rejects_noncanonical_json_before_identity_acceptance()
-> Result<(), Box<dyn Error>> {
    let world = measurement_world()?;
    let plan = Plan::empty();
    let properties = Properties::empty();
    let measurements = MeasurementDefinitions::new(
        &world,
        &plan,
        &properties,
        vec![definition("recovery", "latency")?],
    )?;
    let form = ScenarioDefForm::from_components_with_measurements(
        &world,
        &plan,
        &properties,
        &measurements,
        Seed::default(),
    )?;
    let mut noncanonical = measurements.canonical_bytes().to_vec();
    noncanonical.push(b' ');
    let mut writer = ScenarioBinaryWriter::new(SCENARIO_FORM_BINARY_MAGIC_V6);
    writer.write_hash(form.id());
    write_world_binary(&form.world, &mut writer);
    write_plan_binary(&form.plan, &mut writer);
    write_properties_binary(&form.properties, &mut writer);
    writer.write_binary_blob(&noncanonical);
    writer.write_seed(form.seed);
    writer.write_u64(form.app_random_draw_cap);

    assert!(matches!(
        ScenarioDefForm::from_compact_binary(&writer.finish()),
        Err(EngineError::ScenarioSerialization { reason })
            if reason == "measurement definitions are not canonically encoded"
    ));
    Ok(())
}
