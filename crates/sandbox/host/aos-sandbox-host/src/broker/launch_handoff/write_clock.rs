//! Samples the resident Launch clock immediately before native effect writes.
//!
//! This closed borrower keeps the request, signed WALL/BOOTTIME clock contract.
//! A weak back-reference avoids a cycle through the Launch's resident workers;
//! the actual broker remains the native clock owner through every owed post.

use std::sync::{Arc, Mutex, Weak};

use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

use super::HostLaunchOriginalV2;
use crate::{HostError, Result};

pub(crate) struct HostLaunchWriteClockV2 {
    original: Weak<Mutex<HostLaunchOriginalV2>>,
    request: ([u8; 16], [u8; 32], [u8; 32]),
    cutoff: u64,
}

impl Clone for HostLaunchWriteClockV2 {
    fn clone(&self) -> Self {
        Self {
            original: Weak::clone(&self.original),
            request: self.request,
            cutoff: self.cutoff,
        }
    }
}

impl HostLaunchWriteClockV2 {
    pub(in crate::broker) fn borrow_v2(
        original: &Arc<Mutex<HostLaunchOriginalV2>>,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<Self> {
        let held = original.lock().map_err(|_| closed("Launch clock owner is poisoned"))?;
        held.require_same_request(request)?;
        if held.clock.as_ref().is_none_or(|clock| !clock.has_effect_comparison_v3())
            || held.worker.is_none() || held.worker_deadline.is_none() {
            return Err(closed("Launch clock or prepaid native worker is absent"));
        }
        Ok(Self {
            original: Arc::downgrade(original),
            request: held.request,
            cutoff: held.deadline,
        })
    }

    #[cfg(test)]
    pub(crate) fn absent_for_test() -> Self {
        Self {
            original: Weak::new(),
            request: ([0; 16], [0; 32], [0; 32]),
            cutoff: 0,
        }
    }

    fn sample_before_sdk_write_v3(&self) -> Result<RawPairedClockSample> {
        let original = self.original.upgrade()
            .ok_or(closed("Launch clock owner is no longer resident"))?;
        let mut held = original.lock().map_err(|_| closed("Launch clock owner is poisoned"))?;
        if held.request != self.request || held.deadline != self.cutoff {
            return Err(closed("Launch SDK write differs from original request or cutoff"));
        }
        let sampled = held.clock.as_mut().ok_or(closed("Launch native clock is absent"))?
            .sample_sdk_write_v3()?;
        require_original_cutoff_v2(sampled, self.cutoff)
    }

    pub(crate) fn sdk_gate_v3(&self) -> Arc<dyn aos_systemd_client::HostLaunchEffectWriteGateV3> {
        Arc::new(self.clone())
    }

    pub(crate) fn sdk_gate_receiving_bytes_v3() -> Option<usize> {
        (2 * std::mem::size_of::<Self>())
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(aos_systemd_client::HostSystemdConnectionOriginalV2::effect_write_gate_receiving_bytes_v3()?)
    }

    pub(crate) fn sample_before_write_v2(&self) -> Result<RawPairedClockSample> {
        let original = self.original.upgrade()
            .ok_or(closed("Launch clock owner is no longer resident"))?;
        let mut held = original.lock().map_err(|_| closed("Launch clock owner is poisoned"))?;
        if held.request != self.request || held.deadline != self.cutoff {
            return Err(closed("Launch write differs from its original request or cutoff"));
        }
        let sampled = held.clock.as_mut().ok_or(closed("Launch native clock is absent"))?
            .sample_launch_write_v2()?;
        require_original_cutoff_v2(sampled, self.cutoff)
    }
}

impl std::fmt::Debug for HostLaunchWriteClockV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HostLaunchWriteClockV2")
            .field("cutoff", &self.cutoff).finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Host Launch native write refused; original paired-clock cause remains resident")]
struct HostLaunchWriteClockRefusalV3;

impl aos_systemd_client::HostLaunchEffectWriteGateV3 for HostLaunchWriteClockV2 {
    fn check_before_native_write_v3(&self) -> std::io::Result<()> {
        self.sample_before_sdk_write_v3().map(|_| ())
            .map_err(|_| std::io::Error::other(HostLaunchWriteClockRefusalV3))
    }
}

fn require_original_cutoff_v2(sampled: RawPairedClockSample, cutoff: u64) -> Result<RawPairedClockSample> {
    if sampled.boottime_nanoseconds() >= cutoff {
        return Err(closed("original signed Launch cutoff expired before freezer write"));
    }
    Ok(sampled)
}

fn closed(message: &'static str) -> HostError {
    HostError::Fence(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::argument_handoff::ArgumentClockV2;

    #[test]
    fn absent_resident_launch_refuses_sdk_write_without_an_ordinary_clock() {
        let clock = HostLaunchWriteClockV2::absent_for_test();
        let gate = clock.sdk_gate_v3();

        let error = gate.check_before_native_write_v3().unwrap_err();

        assert!(error.get_ref().unwrap().is::<HostLaunchWriteClockRefusalV3>());
        assert!(gate.check_before_native_write_v3().is_err());
        assert!(clock.original.upgrade().is_none());
    }

    #[test]
    fn fresh_native_boottime_refuses_expired_cutoff_despite_future_local_instant() {
        let boot = aos_sandbox_linux::boot::KernelBootId::current().unwrap().into_bytes();
        let mut clock = ArgumentClockV2::capture_launch_v2(boot);
        let original_cutoff = clock.sample().unwrap().boottime_nanoseconds();
        let future_local = std::time::Instant::now() + std::time::Duration::from_secs(60);

        let sampled = clock.sample_launch_write_v2().unwrap();
        let refused = require_original_cutoff_v2(sampled, original_cutoff);

        assert!(std::time::Instant::now() < future_local);
        assert!(matches!(refused, Err(HostError::Fence(
            "original signed Launch cutoff expired before freezer write"
        ))));
        assert!(clock.failure().is_none());
    }
}
