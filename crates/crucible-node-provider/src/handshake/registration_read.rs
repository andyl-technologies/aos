//! Reads the original registrar gate without exposing registration or wire data.

use super::ConnectionAuthority;
use crate::ProviderError;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

pub(crate) struct RegistrationRead {
    gate: Arc<Mutex<()>>,
    current: Arc<AtomicU64>,
    original: u64,
}

impl RegistrationRead {
    pub(crate) fn ensure_current(&self) -> Result<(), ProviderError> {
        // A contended gate is uncertainty, rather than permission to wait past
        // the caller's final native-dispatch boundary.
        let _gate = self
            .gate
            .try_lock()
            .map_err(|_| ProviderError::Correlation("original registrar read gate unavailable"))?;
        if self.current.load(Ordering::Acquire) != self.original {
            return Err(ProviderError::Correlation(
                "original registrar read revoked",
            ));
        }
        Ok(())
    }

    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.gate, &other.gate)
            && Arc::ptr_eq(&self.current, &other.current)
            && self.original == other.original
    }
}

impl ConnectionAuthority {
    pub(crate) fn original_registration_read(&self) -> Result<RegistrationRead, ProviderError> {
        self.ensure_live()?;
        Ok(RegistrationRead {
            gate: Arc::clone(&self.registration_gate),
            current: Arc::clone(&self.shared_epoch),
            original: self.epoch,
        })
    }
}

#[cfg(test)]
#[path = "registration_read_tests.rs"]
mod tests;
