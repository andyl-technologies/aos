//! Executes allocation observer controls without a concurrent test harness.
//!
//! This executable is available only with the test-support feature. It preserves
//! the global observer's fail-closed outcomes and runs the same physical-close,
//! worker-join and unwind assertions as the integration test.

#[path = "../../tests/support/allocation_roster_controls.rs"]
mod controls;

fn main() {
    controls::run_all_controls();
    println!("PASS fixed global roster and original before-free controls: 8");
}
