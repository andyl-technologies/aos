//! Compaction and materialization of decoded continuation ancestries.

use std::error::Error;

use crucible_campaign::{
    CampaignHash, ConfigurationArtifact, ConfigurationId, ScenarioArtifact, ScenarioDefId,
    StopCondition,
};
use crucible_engine::{DeliveryOrderDecision, Schedule, VirtualTime};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

fn delivery_at(ticks: u64) -> Decision {
    Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks },
        order: Vec::new(),
    })
}

/// Builds the configuration holding deliveries `0..len` plus any `extra`.
fn configuration(len: u64, extra: &[Decision]) -> Result<Configuration, Box<dyn Error>> {
    let fixture = crucible_engine::happy_path_scenario()?;
    Ok(Configuration {
        def: fixture.scenario.scenario_def(),
        schedule: Schedule::from_decisions((0..len).map(delivery_at).chain(extra.iter().cloned())),
    })
}

/// Builds a distinct origin attempt; its identity plays no part in compaction.
fn attempt(index: u64) -> Result<Attempt, Box<dyn Error>> {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("origins", b"scenario"));
    let scenario_artifact = ScenarioArtifact::new(scenario, 1, b"scenario".to_vec())?.id()?;
    let configuration = ConfigurationArtifact::new(
        scenario,
        scenario_artifact,
        ConfigurationId::from_hash(CampaignHash::derive("origins", &index.to_be_bytes())),
        1,
        index.to_be_bytes().to_vec(),
    )?
    .id()?;
    Ok(Attempt::new(
        AttemptStart::Discover { configuration },
        BranchPath::new(Vec::new())?.id()?,
        StopCondition::ExecutionQuanta(index + 1),
    )?)
}

fn origin(index: u64, reached: Configuration) -> Result<CrucibleAttemptOrigin, Box<dyn Error>> {
    let replay = SignalFaultCampaignReplayPlan::empty(reached.clone());
    Ok(CrucibleAttemptOrigin::new_with_source_stop(
        attempt(index)?,
        reached,
        replay,
        StopOutcome::Reached(StopCondition::ExecutionQuanta(index + 1)),
    ))
}

#[test]
fn prefix_origins_are_kept_compact_and_materialize_exactly() -> TestResult {
    // Lengths cross the shared-storage chunk boundary.
    let decoded = [
        origin(0, configuration(3, &[])?)?,
        origin(1, configuration(64, &[])?)?,
        origin(2, configuration(130, &[])?)?,
    ];
    let terminal = origin(3, configuration(200, &[])?)?;
    let mut origins = CrucibleAttemptOrigins::from_terminal(terminal.clone());

    for origin in &decoded {
        assert!(origins.push_earlier(origin.clone()));
    }
    let materialized = origins.iter().collect::<Result<Vec<_>, _>>()?;

    assert_eq!(origins.len(), 4);
    assert!(
        origins
            .earlier
            .iter()
            .all(|link| matches!(link.boundary, OriginBoundary::TerminalPrefix(_)))
    );
    assert_eq!(materialized[..3], decoded);
    assert_eq!(materialized[3], terminal);
    assert_eq!(origins.last(), &terminal);
    Ok(())
}

#[test]
fn an_origin_outside_the_terminal_prefix_is_kept_decoded() -> TestResult {
    let terminal = origin(2, configuration(100, &[])?)?;
    let diverged = origin(0, configuration(10, &[delivery_at(u64::MAX)])?)?;
    let prefix = origin(1, configuration(50, &[])?)?;
    let mut origins = CrucibleAttemptOrigins::from_terminal(terminal.clone());

    assert!(!origins.push_earlier(diverged.clone()));
    assert!(origins.push_earlier(prefix.clone()));
    let materialized = origins.iter().collect::<Result<Vec<_>, _>>()?;

    assert!(matches!(
        origins.earlier[0].boundary,
        OriginBoundary::Decoded(_)
    ));
    assert_eq!(materialized, [diverged, prefix, terminal]);
    Ok(())
}

#[test]
fn explicit_origins_are_retained_as_given() -> TestResult {
    let first = origin(0, configuration(5, &[delivery_at(u64::MAX)])?)?;
    let second = origin(1, configuration(8, &[])?)?;
    let origins = CrucibleAttemptOrigins::new(first.clone(), vec![second.clone()]);
    let single = CrucibleAttemptOrigins::new(first.clone(), Vec::new());

    assert_eq!(origins.len(), 2);
    assert_eq!(origins.last(), &second);
    assert_eq!(
        origins.iter().collect::<Result<Vec<_>, _>>()?,
        [first.clone(), second]
    );
    assert_eq!(single.len(), 1);
    assert_eq!(single.iter().collect::<Result<Vec<_>, _>>()?, [first]);
    Ok(())
}
