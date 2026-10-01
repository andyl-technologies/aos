//! Immutable accepted producer time window rechecked before new dispatch.
//!
//! Waiting for capacity cannot renew an independently signed acceptance. This
//! window belongs only to new admission and provider effects; exact historical
//! acknowledgement and physical guard readback have their own authority.

use anyhow::{ensure, Result};

pub(crate) struct AcceptedProducerWindow {
    issued_at: u64,
    valid_until: u64,
    uncertainty: u64,
}

impl AcceptedProducerWindow {
    pub(crate) fn new(issued_at: u64, valid_until: u64, uncertainty: u64) -> Result<Self> {
        ensure!(
            issued_at < valid_until && (1..30).contains(&uncertainty),
            "accepted producer window is invalid"
        );
        Ok(Self {
            issued_at,
            valid_until,
            uncertainty,
        })
    }

    pub(crate) fn latest_now(&self, now: u64) -> Result<u64> {
        let latest = now
            .checked_add(self.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("accepted producer clock overflow"))?;
        ensure!(
            self.issued_at <= now && latest < self.valid_until,
            "accepted producer window expired or clock regressed"
        );
        Ok(latest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_wait_cannot_renew_original_signed_window() {
        let window = AcceptedProducerWindow::new(100, 130, 2).unwrap();
        assert_eq!(window.latest_now(100).unwrap(), 102);
        assert_eq!(window.latest_now(127).unwrap(), 129);
        assert!(window.latest_now(128).is_err());
        assert!(window.latest_now(129).is_err());
        assert!(window.latest_now(99).is_err());
        assert!(window.latest_now(u64::MAX).is_err());
    }

    #[test]
    fn malformed_bounds_fail_before_dispatch() {
        assert!(AcceptedProducerWindow::new(130, 130, 1).is_err());
        assert!(AcceptedProducerWindow::new(131, 130, 1).is_err());
        assert!(AcceptedProducerWindow::new(100, 130, 0).is_err());
        assert!(AcceptedProducerWindow::new(100, 130, 30).is_err());
    }
}
