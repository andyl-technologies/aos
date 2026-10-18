//! Origin-chain resolution and walking against an in-memory record source.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::error::Error;

use crucible_campaign::{CampaignHash, ConfigurationId, StopCondition};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

const PAYLOAD_BYTES: usize = 64 * 1024;
const ORIGIN_CHARGE: u64 = PAYLOAD_BYTES as u64 + SELECTED_ORIGIN_STRUCTURAL_BYTES;

/// Configuration artifacts keyed by identity, with a load counter.
struct MemoryOrigins {
    artifacts: BTreeMap<ConfigurationArtifactId, ConfigurationArtifact>,
    loads: Cell<usize>,
}

impl OriginRecordSource for MemoryOrigins {
    fn load_configuration_artifact(
        &self,
        id: ConfigurationArtifactId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        self.loads.set(self.loads.get() + 1);
        self.artifacts
            .get(&id)
            .cloned()
            .ok_or(CampaignRepositoryError::Integrity {
                reason: "test-configuration-artifact-is-missing",
            })
    }

    fn load_observation(&self, _id: ObservationId) -> Result<Observation, CampaignRepositoryError> {
        Err(CampaignRepositoryError::Integrity {
            reason: "test-source-has-no-observations",
        })
    }
}

/// One uncontrolled continuation chain: a discovery base and its descendants.
struct ChainFixture {
    source: MemoryOrigins,
    lineage: CampaignLineage,
    path: BranchPathId,
    base: Attempt,
    descendants: Vec<Attempt>,
}

impl ChainFixture {
    fn new(origins: usize) -> Result<Self, Box<dyn Error>> {
        let scenario = ScenarioDefId::from_hash(CampaignHash::derive("origin-chain", b"scenario"));
        let scenario_artifact = ScenarioArtifact::new(scenario, 1, b"scenario".to_vec())?.id()?;
        let genesis = configuration_artifact(scenario, scenario_artifact, 0)?;
        let genesis_id = genesis.id()?;
        let lineage = CampaignLineage::new(
            scenario,
            scenario_artifact,
            genesis.configuration(),
            genesis_id,
            "crucible-origin-chain-test",
            "qemu-origin-chain-test",
            BTreeMap::from([(String::from("control"), 1)]),
            1,
            1,
        )?;
        let path = BranchPath::new(Vec::new())?.id()?;

        let mut artifacts = BTreeMap::from([(genesis_id, genesis)]);
        let base = Attempt::new(
            AttemptStart::Discover {
                configuration: genesis_id,
            },
            path,
            StopCondition::ExecutionQuanta(1),
        )?;
        let mut descendants = Vec::with_capacity(origins);
        let mut origin = base.id()?;
        for index in 1..=origins {
            let reached = configuration_artifact(scenario, scenario_artifact, index)?;
            let reached_id = reached.id()?;
            artifacts.insert(reached_id, reached);
            let descendant = Attempt::new(
                AttemptStart::AfterAttempt {
                    origin,
                    reached: reached_id,
                },
                path,
                StopCondition::ExecutionQuanta(u64::try_from(index)? + 1),
            )?;
            origin = descendant.id()?;
            descendants.push(descendant);
        }

        Ok(Self {
            source: MemoryOrigins {
                artifacts,
                loads: Cell::new(0),
            },
            lineage,
            path,
            base,
            descendants,
        })
    }

    fn resolve(&self, limit: u64) -> Result<AttemptOriginChain, CampaignRepositoryError> {
        let mut budget = OriginResidentBudget::new(limit);
        resolve_origin_chain(
            &self.source,
            &self.lineage,
            self.path,
            self.base.clone(),
            self.descendants.clone(),
            &mut budget,
        )
    }

    fn reached(&self, descendant: usize) -> Result<ConfigurationArtifactId, Box<dyn Error>> {
        match self.descendants.get(descendant).map(Attempt::start) {
            Some(AttemptStart::AfterAttempt { reached, .. }) => Ok(reached),
            _ => Err("fixture descendant is not a continuation".into()),
        }
    }
}

fn configuration_artifact(
    scenario: ScenarioDefId,
    scenario_artifact: ScenarioArtifactId,
    index: usize,
) -> Result<ConfigurationArtifact, Box<dyn Error>> {
    let configuration = ConfigurationId::from_hash(CampaignHash::derive(
        "origin-chain-configuration",
        &index.to_be_bytes(),
    ));
    let fill = u8::try_from(index % 256)?;
    Ok(ConfigurationArtifact::new(
        scenario,
        scenario_artifact,
        configuration,
        1,
        vec![fill; PAYLOAD_BYTES],
    )?)
}

#[test]
fn deep_chain_is_charged_its_peak_origin_instead_of_its_sum() -> TestResult {
    let fixture = ChainFixture::new(64)?;

    // The terminal origin stays resident and one intermediate is transient;
    // the 64-origin sum would need thirty-two times this ceiling.
    let chain = fixture.resolve(2 * ORIGIN_CHARGE)?;

    assert_eq!(chain.len(), 64);
    assert_eq!(fixture.source.loads.get(), 64);
    assert_eq!(
        chain.peak_intermediate_encoded_bytes(),
        PAYLOAD_BYTES as u64
    );
    assert_eq!(Some(chain.last().attempt()), fixture.descendants.get(62));
    Ok(())
}

#[test]
fn walking_a_chain_reloads_each_intermediate_once_oldest_first() -> TestResult {
    let fixture = ChainFixture::new(8)?;
    let chain = fixture.resolve(2 * ORIGIN_CHARGE)?;
    fixture.source.loads.set(0);

    let mut visited = Vec::new();
    chain.try_for_each_from(&fixture.source, |origin| {
        visited.push((origin.attempt().clone(), origin.reached().id()?));
        Ok::<(), CampaignRepositoryError>(())
    })?;

    let expected = std::iter::once(&fixture.base)
        .chain(&fixture.descendants[..7])
        .cloned()
        .zip((0..8).map(|index| fixture.reached(index)))
        .map(|(attempt, reached)| reached.map(|reached| (attempt, reached)))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(visited, expected);
    // The resident terminal origin is lent without a reload.
    assert_eq!(fixture.source.loads.get(), 7);
    Ok(())
}

#[test]
fn origin_above_the_remaining_ceiling_is_refused() -> TestResult {
    let fixture = ChainFixture::new(2)?;

    let result = fixture.resolve(2 * ORIGIN_CHARGE - 1);

    assert!(matches!(
        result,
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "attempt-origin-artifacts-exceed-resource-limit"
        })
    ));
    Ok(())
}

#[test]
fn origin_from_another_scenario_artifact_is_rejected() -> TestResult {
    let mut fixture = ChainFixture::new(3)?;
    let reached = fixture.reached(1)?;
    let foreign_scenario =
        ScenarioArtifact::new(fixture.lineage.scenario(), 1, b"other".to_vec())?.id()?;
    let foreign = configuration_artifact(fixture.lineage.scenario(), foreign_scenario, 2)?;
    // The fake keys by the original identity so only the lineage check can fail.
    fixture.source.artifacts.insert(reached, foreign);

    let result = fixture.resolve(2 * ORIGIN_CHARGE);

    assert!(matches!(
        result,
        Err(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-chain-lineage-mismatch"
        })
    ));
    Ok(())
}

#[test]
fn broken_origin_link_is_rejected() -> TestResult {
    let mut fixture = ChainFixture::new(3)?;
    fixture.descendants.swap(0, 1);

    let result = fixture.resolve(2 * ORIGIN_CHARGE);

    assert!(matches!(
        result,
        Err(CampaignRepositoryError::Integrity {
            reason: "attempt-origin-chain-link-mismatch"
        })
    ));
    Ok(())
}

#[test]
fn walk_surfaces_an_intermediate_that_disappeared_after_resolution() -> TestResult {
    let mut fixture = ChainFixture::new(3)?;
    let chain = fixture.resolve(2 * ORIGIN_CHARGE)?;
    let reached = fixture.reached(0)?;
    fixture.source.artifacts.remove(&reached);

    let mut visited = 0_usize;
    let result = chain.try_for_each_from(&fixture.source, |_origin| {
        visited += 1;
        Ok::<(), CampaignRepositoryError>(())
    });

    assert_eq!(visited, 0);
    assert!(matches!(
        result,
        Err(CampaignRepositoryError::Integrity {
            reason: "test-configuration-artifact-is-missing"
        })
    ));
    Ok(())
}
