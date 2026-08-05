//! Checks that structured guest-assertion semantics stay host-side.

use std::error::Error;
use std::fs;

use super::{PLUGIN_PACKAGE, display_repo_path, visit_rust_sources, workspace_crates_dir};

#[test]
fn guest_assertion_evaluation_stays_in_the_host() -> Result<(), Box<dyn Error>> {
    let crates = workspace_crates_dir()?;
    let host_evaluator =
        fs::read_to_string(crates.join("crucible/src/trigger/guest_assertion_observation.rs"))?;
    for marker in [
        "observe_guest_marker_assertion_state",
        "HostAssertionOutcomeKind::Violated",
        "GuestAssertionKind::Unreachable",
    ] {
        assert!(
            host_evaluator.contains(marker),
            "host guest-assertion evaluator must contain `{marker}`"
        );
    }

    let plugin = crates.join(PLUGIN_PACKAGE).join("src");
    let mut failures = Vec::new();
    visit_rust_sources(&plugin, &mut |path, source| {
        for forbidden in ["HostAssertionOutcome", "GuestMarkerAssertionState"] {
            if source.contains(forbidden) {
                failures.push(format!(
                    "{}: GPL-side observation code contains host assertion semantic `{forbidden}`",
                    display_repo_path(path)
                ));
            }
        }
    })?;
    assert!(
        failures.is_empty(),
        "guest assertion semantics crossed into the QEMU plugin:\n{}",
        failures.join("\n")
    );
    Ok(())
}
