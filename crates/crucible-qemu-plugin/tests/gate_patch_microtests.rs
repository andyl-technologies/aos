//! Checks the aggregate `gate:patch-microtests` wiring.
//!
//! The carried-QEMU-patch roster, the per-patch evidence table, and the
//! source-shape assertions live in the `support/gate_patch_microtests/`
//! modules; this file holds only the two test entry points so it stays within
//! the RFC-0010 file-shape limits as the roster grows with each carried patch.

#![forbid(unsafe_code)]

use std::error::Error;

#[path = "support/gate_patch_microtests/aggregate.rs"]
mod aggregate;
#[path = "support/gate_patch_microtests/common.rs"]
mod common;
#[path = "support/gate_patch_microtests/evidence.rs"]
mod evidence;
#[path = "support/gate_patch_microtests/surfaces.rs"]
mod surfaces;

#[test]
fn gate_patch_microtests_covers_carried_qemu_patch_series() -> Result<(), Box<dyn Error>> {
    aggregate::assert_aggregate_and_default()?;
    surfaces::assert_plugin_and_series_surfaces()?;
    Ok(())
}

#[test]
fn per_patch_microtests_publish_required_evidence() -> Result<(), Box<dyn Error>> {
    evidence::assert_per_patch_evidence()
}
