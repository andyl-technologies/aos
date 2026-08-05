//! Live-QEMU terminal failure classification and reproduction capture.

use super::*;

pub(super) fn qemu_search_terminal_failure(
    scenario: &crucible::ScenarioDefForm,
    snapshot: &crucible_session::EngineSnapshot,
) -> Result<Option<crucible::SearchDiscoveredFailure>, CliError> {
    let crucible_session::EngineState::Stopped { outcome } = &snapshot.state else {
        return Ok(None);
    };
    let failure_material = match outcome {
        crucible_session::Outcome::Failed { violations } => {
            let mut canonical_violations = violations.clone();
            canonical_violations.sort();
            canonical_violations.dedup();
            format!(
                "kind=property\nviolations={}",
                canonical_violations.join("\n")
            )
        }
        crucible_session::Outcome::Crashed { detail } => {
            return Err(backend_error(format!(
                "live QEMU search backend crashed: {detail}"
            )));
        }
        crucible_session::Outcome::Timeout => String::from("kind=timeout"),
        crucible_session::Outcome::Passed | crucible_session::Outcome::Stopped => return Ok(None),
    };
    let configuration = snapshot.configuration.clone();
    let fingerprint = crucible::ContentHash::from_canonical_material(
        "crucible.live-qemu-search-failure.v1",
        &format!(
            "configuration={}\n{}",
            configuration.id().to_hex(),
            failure_material
        ),
    );
    let reproduction_artifact = crucible::FindingReproductionArtifact::capture(
        crucible::FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        scenario,
        &configuration,
    )
    .map_err(|error| {
        backend_error(format!(
            "capture live QEMU search failure reproduction: {error}"
        ))
    })?;
    Ok(Some(crucible::SearchDiscoveredFailure {
        configuration: configuration.id(),
        fingerprint,
        reproduction_artifact,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with_outcome(
        scenario: &crucible::ScenarioDefForm,
        outcome: crucible_session::Outcome,
    ) -> crucible_session::EngineSnapshot {
        crucible_session::EngineSnapshot {
            state: crucible_session::EngineState::Stopped { outcome },
            configuration: crucible::Configuration::genesis(scenario.scenario_def()),
            terminal_savepoint: None,
            frontier: crucible::VirtualTime { ticks: 0 },
            event_log_len: 0,
            quanta: 0,
        }
    }

    #[test]
    fn live_qemu_search_failure_captures_canonical_reproduction_artifact()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario = crucible::happy_path_scenario()?.scenario;
        let first = snapshot_with_outcome(
            &scenario,
            crucible_session::Outcome::Failed {
                violations: vec![
                    String::from("second invariant"),
                    String::from("first invariant"),
                    String::from("second invariant"),
                ],
            },
        );
        let reordered = snapshot_with_outcome(
            &scenario,
            crucible_session::Outcome::Failed {
                violations: vec![
                    String::from("first invariant"),
                    String::from("second invariant"),
                ],
            },
        );

        let first_failure = qemu_search_terminal_failure(&scenario, &first)?
            .ok_or_else(|| std::io::Error::other("failed outcome produced no search finding"))?;
        let reordered_failure = qemu_search_terminal_failure(&scenario, &reordered)?
            .ok_or_else(|| std::io::Error::other("failed outcome produced no search finding"))?;

        assert_eq!(first_failure.fingerprint, reordered_failure.fingerprint);
        assert_eq!(first_failure.configuration, first.configuration.id());
        assert_eq!(
            first_failure.reproduction_artifact.discovery_path,
            crucible::FindingDiscoveryPath::StateSpaceSearch
        );
        assert_eq!(
            first_failure.reproduction_artifact.configuration,
            first_failure.configuration
        );
        assert_eq!(
            first_failure.reproduction_artifact.finding_fingerprint,
            first_failure.fingerprint
        );
        Ok(())
    }

    #[test]
    fn live_qemu_search_failure_distinguishes_non_failure_and_backend_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario = crucible::happy_path_scenario()?.scenario;
        let passed = snapshot_with_outcome(&scenario, crucible_session::Outcome::Passed);
        assert!(qemu_search_terminal_failure(&scenario, &passed)?.is_none());

        let timeout = snapshot_with_outcome(&scenario, crucible_session::Outcome::Timeout);
        let timeout_finding = qemu_search_terminal_failure(&scenario, &timeout)?
            .ok_or_else(|| std::io::Error::other("timeout produced no search finding"))?;
        assert_eq!(
            timeout_finding.reproduction_artifact.discovery_path,
            crucible::FindingDiscoveryPath::StateSpaceSearch
        );

        let crashed = snapshot_with_outcome(
            &scenario,
            crucible_session::Outcome::Crashed {
                detail: String::from("qemu exited"),
            },
        );
        let Err(error) = qemu_search_terminal_failure(&scenario, &crashed) else {
            return Err(
                std::io::Error::other("backend crash was reported as a modeled finding").into(),
            );
        };
        assert!(
            error
                .to_string()
                .contains("live QEMU search backend crashed")
        );
        Ok(())
    }
}
