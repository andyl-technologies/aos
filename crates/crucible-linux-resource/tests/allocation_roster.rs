//! Runs global allocation controls in their own plain-main process.
//!
//! The ordinary Rust test harness allocates concurrently on its main thread.
//! The child owns only the control thread and the fixture's explicitly joined
//! worker; the production observer still refuses every contended capture.

#![cfg(feature = "test-support")]
// crucible-lint: allow panic-shortcut -- Any helper failure or missing completion marker must fail the regression.
#![allow(clippy::unwrap_used)]

#[test]
fn fixed_global_roster_and_original_before_free_controls() {
    let output =
        std::process::Command::new(env!("CARGO_BIN_EXE_crucible-allocation-roster-controls"))
            .output()
            .unwrap();

    assert!(
        output.status.success(),
        "allocation controls failed: status={}; stdout={}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        output.stdout,
        b"PASS fixed global roster and original before-free controls: 8\n"
    );
}
