//! Observes ready markers before deferring campaign VMStop boundaries.
//!
//! Refusals retain the event's existing name allocation and numeric provider
//! status. The callback creates no Source, operation or cleanup authority.
// SPDX-License-Identifier: GPL-2.0-only

use std::os::raw::c_char;

use super::{LiveWhiteboxError, QemuForceVcpuTbExitFn, SelectableVmstopHandoff};

const CAMPAIGN_BOUNDARY_MARKERS: [&str; 2] = ["fault.transport.ready", "fault.followup.ready"];

pub(super) fn observe(
    name: String,
    observed_raw_icount: u64,
    ready_marker: extern "C" fn(*const c_char, usize, u64) -> i32,
    campaign: Option<(&SelectableVmstopHandoff, QemuForceVcpuTbExitFn)>,
) -> Result<(), LiveWhiteboxError> {
    let status = ready_marker(name.as_ptr().cast(), name.len(), observed_raw_icount);
    if status < 0 {
        return Err(LiveWhiteboxError::ReadyMarkerRefused { name, status });
    }

    if let Some((handoff, force_vcpu_tb_exit)) = campaign
        && CAMPAIGN_BOUNDARY_MARKERS.contains(&name.as_str())
    {
        match handoff.defer_campaign_marker(force_vcpu_tb_exit) {
            Ok(true) => {}
            Ok(false) => return Err(LiveWhiteboxError::CampaignMarkerCollision { name }),
            Err(status) => {
                return Err(LiveWhiteboxError::CampaignMarkerExitRefused { name, status });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
