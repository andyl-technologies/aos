//! QEMU virtual-time ownership request capability.

use std::ffi::c_void;

use thiserror::Error;

use super::{PluginTimeControlOwnership, QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL};

/// QEMU's plugin API entry point for acquiring virtual-time ownership.
pub type QemuRequestTimeControlFn = extern "C" fn() -> *const c_void;

impl PluginTimeControlOwnership {
    /// Acquires QEMU virtual-time control through the plugin API.
    ///
    /// # Errors
    ///
    /// Returns [`PluginTimeControlRequestError::CapabilityUnavailable`] when
    /// the request symbol is absent, or
    /// [`PluginTimeControlRequestError::OwnershipRejected`] when another plugin
    /// already owns virtual time.
    pub fn request(
        request_time_control: Option<QemuRequestTimeControlFn>,
    ) -> Result<Self, PluginTimeControlRequestError> {
        let Some(request_time_control) = request_time_control else {
            return Err(PluginTimeControlRequestError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL,
            });
        };
        if request_time_control().is_null() {
            return Err(PluginTimeControlRequestError::OwnershipRejected);
        }
        Ok(Self { _private: () })
    }
}

/// An error produced while acquiring QEMU virtual-time ownership.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginTimeControlRequestError {
    /// QEMU did not export the time-control request capability.
    #[error("QEMU time-control request capability {symbol} is unavailable")]
    CapabilityUnavailable {
        /// Missing QEMU symbol.
        symbol: &'static str,
    },
    /// QEMU reported that another plugin already owns virtual time.
    #[error("QEMU rejected plugin virtual-time ownership")]
    OwnershipRejected,
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_TIME_CONTROL_TOKEN: u8 = 1;

    #[test]
    fn time_control_request_requires_export_and_nonnull_ownership_token() {
        assert!(PluginTimeControlOwnership::request(Some(test_request_time_control)).is_ok());
        assert!(matches!(
            PluginTimeControlOwnership::request(None),
            Err(PluginTimeControlRequestError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL,
            })
        ));
        assert!(matches!(
            PluginTimeControlOwnership::request(Some(test_reject_time_control)),
            Err(PluginTimeControlRequestError::OwnershipRejected)
        ));
    }

    extern "C" fn test_request_time_control() -> *const c_void {
        (&TEST_TIME_CONTROL_TOKEN as *const u8).cast()
    }

    extern "C" fn test_reject_time_control() -> *const c_void {
        std::ptr::null()
    }
}
