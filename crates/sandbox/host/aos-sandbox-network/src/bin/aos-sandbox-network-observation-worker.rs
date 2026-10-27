//! Runs the one Source-first, signed-D Network observation programme.
//!
//! PID1 supplies native child custody before any startup or argv processing.
//! The protected parent prepays all bootstrap, read and native handback work.

fn main() {
    aos_sandbox_network::run_inherited_network_observation_worker_entry_v2()
}
