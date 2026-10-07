//! Withholds the next scheduler grant at an authenticated live idle boundary.
//!
//! The original completed-quantum clamp leaves this diskless node RUNNING in
//! its native all-vCPU idle wait. Host delay is an adversary outside virtual
//! time, never an input to the canonical clock. The external gate separately
//! requires a matched, admitted native waiter receipt spanning these markers.

use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use crucible_qemu::{QemuLogicalTimeCalibration, QemuNode};

pub(super) fn hold(
    node: &mut QemuNode,
    original: QemuLogicalTimeCalibration,
) -> Result<(), Box<dyn Error>> {
    let pid = node.process_id();
    marker("before", pid, original);
    std::thread::sleep(Duration::from_millis(200));
    let held = node.logical_time_calibration()?;
    marker("after", pid, held);

    if held.raw_icount != original.raw_icount
        || held.logical_icount != original.logical_icount
        || held.offset() != original.offset()
    {
        return Err("idle clock moved without an authorized scheduler grant".into());
    }
    Ok(())
}

fn marker(phase: &str, pid: u32, calibration: QemuLogicalTimeCalibration) {
    // A closed diagnostic sink cannot replace the original flight result.
    let _ = writeln!(
        io::stderr().lock(),
        "CRUCIBLE-TIME-HOLD-V1 phase={phase} pid={pid} raw={} ps={}",
        calibration.raw_icount,
        calibration.logical_icount,
    );
}
