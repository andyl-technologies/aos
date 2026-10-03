//! Checks exact scenario-TOML durations without nanosecond projection or aliases.

#![forbid(unsafe_code)]

use crucible::{
    Action, ContentHash, EngineError, EventGraph, EventId, Plan, Predicate, Properties,
    ScenarioDefForm, Seed, SimDuration, TimerId, World,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn scenario(
    duration_ticks: u64,
    after_ticks: u64,
) -> Result<ScenarioDefForm, Box<dyn std::error::Error>> {
    let world = World::from_nodes(Vec::new())?;
    let timer = TimerId {
        name: "finish".into(),
    };
    let graph = EventGraph::builder()
        .event("origin")
        .entrypoint()
        .action(Action::Group(Vec::new()))
        .event("arm")
        .when(Predicate::after(
            SimDuration {
                ticks: duration_ticks,
            },
            EventId::from_name("origin"),
        ))
        .action(Action::arm_timer(
            timer.clone(),
            SimDuration { ticks: after_ticks },
        ))
        .event("complete")
        .when(Predicate::timer(timer))
        .action(Action::Pass)
        .build()?;
    let plan = Plan::from_event_graph_for_world(&world, graph)?;
    Ok(ScenarioDefForm::from_components(
        &world,
        &plan,
        &Properties::empty(),
        Seed::from_u64(42),
    )?)
}

#[test]
fn exact_packaged_trigger_and_timer_durations_round_trip() -> TestResult {
    let original = scenario(1_250_003, 33)?;
    let encoded = original.to_canonical_toml()?;
    assert!(encoded.contains("duration_ticks = 1250003"));
    assert!(encoded.contains("after_ticks = 33"));
    assert!(!encoded.contains("duration_nanos"));
    assert!(!encoded.contains("after_nanos"));

    let decoded = ScenarioDefForm::from_canonical_toml(&encoded)?;
    assert_eq!(decoded, original);
    assert_eq!(decoded.id(), original.id());
    assert_eq!(decoded.to_compact_binary(), original.to_compact_binary());
    assert_eq!(decoded.to_canonical_toml()?, encoded);
    Ok(())
}

#[test]
fn durations_preserve_single_ticks_and_full_unsigned_range() -> TestResult {
    for ticks in [0, 1, 33, 1_000, 1_250_003, i64::MAX as u64, u64::MAX] {
        let original = scenario(ticks, ticks)?;
        let encoded = original.to_canonical_toml()?;
        if ticks > i64::MAX as u64 {
            assert!(encoded.contains(&format!("duration_ticks = \"u64:{ticks}\"")));
            assert!(encoded.contains(&format!("after_ticks = \"u64:{ticks}\"")));
        } else {
            assert!(encoded.contains(&format!("duration_ticks = {ticks}")));
            assert!(encoded.contains(&format!("after_ticks = {ticks}")));
        }
        let decoded = ScenarioDefForm::from_canonical_toml(&encoded)?;
        assert_eq!(decoded, original);
        assert_eq!(decoded.to_canonical_toml()?, encoded);
    }
    Ok(())
}

#[test]
fn whole_nanosecond_meaning_is_preserved_without_legacy_toml_acceptance() -> TestResult {
    let original = scenario(1_000, 2_000)?;
    let encoded = original.to_canonical_toml()?;
    let decoded = ScenarioDefForm::from_canonical_toml(&encoded)?;
    assert_eq!(decoded.id(), original.id());
    assert_eq!(decoded.to_compact_binary(), original.to_compact_binary());

    // The old field names encoded nanoseconds. Their serialized bytes change,
    // while the exact engine duration and content-addressed binary remain intact.
    let obsolete = encoded
        .replace("duration_ticks = 1000", "duration_nanos = 1")
        .replace("after_ticks = 2000", "after_nanos = 2");
    assert_ne!(
        ContentHash::from_bytes(encoded.as_bytes()),
        ContentHash::from_bytes(obsolete.as_bytes())
    );
    assert!(matches!(
        ScenarioDefForm::from_canonical_toml(&obsolete),
        Err(EngineError::ScenarioSerialization { .. })
    ));
    Ok(())
}

#[test]
fn duration_parser_rejects_old_aliases_nonintegers_and_unsigned_overflow() -> TestResult {
    let encoded = scenario(33, 33)?.to_canonical_toml()?;
    for field in ["duration_ticks", "after_ticks"] {
        let alias = field.replace("ticks", "nanos");
        let obsolete = encoded.replace(field, &alias);
        assert!(
            matches!(
                ScenarioDefForm::from_canonical_toml(&obsolete),
                Err(EngineError::ScenarioSerialization { .. })
            ),
            "{field} alias"
        );

        for value in [
            "-1",
            "1.5",
            "1e3",
            "\"33\"",
            "\"u64:1\"",
            "\"u64:018446744073709551615\"",
            "\"u64:18446744073709551616\"",
        ] {
            let malformed =
                encoded.replace(&format!("{field} = 33"), &format!("{field} = {value}"));
            assert_ne!(malformed, encoded);
            assert!(
                matches!(
                    ScenarioDefForm::from_canonical_toml(&malformed),
                    Err(EngineError::ScenarioSerialization { .. })
                ),
                "{field} value {value}"
            );
        }
    }
    Ok(())
}

#[test]
fn exact_duration_changes_still_require_matching_component_identity() -> TestResult {
    let encoded = scenario(33, 33)?.to_canonical_toml()?;
    for field in ["duration_ticks", "after_ticks"] {
        let changed = encoded.replace(&format!("{field} = 33"), &format!("{field} = 34"));
        assert!(ScenarioDefForm::from_canonical_toml(&changed).is_err());
    }
    for schema in ["crucible.scenario.v8", "crucible.scenario.v10"] {
        let noncurrent = encoded.replace("crucible.scenario.v9", schema);
        assert!(matches!(
            ScenarioDefForm::from_canonical_toml(&noncurrent),
            Err(EngineError::ScenarioSerialization { .. })
        ));
    }
    Ok(())
}
