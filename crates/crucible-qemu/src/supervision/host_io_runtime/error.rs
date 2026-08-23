//! Host-I/O runtime construction and slot-access errors.

use crucible_shmem::{MappedSetupRegionAccessError, SetupRegionMapError};
use thiserror::Error;

use crate::QemuAsyncDriverRuntimeError;

/// Maps a node-slot access failure to a runtime await error.
pub(super) fn map_slot_error(source: MappedSetupRegionAccessError) -> QemuAsyncDriverRuntimeError {
    QemuAsyncDriverRuntimeError::new("poll advance completion", source.to_string())
}

/// Error building a [`super::QemuLiveHostIoRuntime`].
#[derive(Debug, Error)]
pub enum QemuLiveHostIoRuntimeError {
    /// The shared-memory region could not be mapped.
    #[error("map shared-memory region failed: {source}")]
    MapRegion {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// The plugin wake eventfd could not be cloned.
    #[error("clone plugin wake eventfd failed: {source}")]
    CloneWakeFd {
        /// Underlying descriptor clone error.
        source: std::io::Error,
    },
    /// The configured poll interval was zero.
    #[error("host-I/O runtime poll interval must be nonzero")]
    ZeroPollInterval,
    /// More than one console stream was attached to one node runtime.
    #[error("QEMU host-I/O runtime already has a console stream")]
    DuplicateConsole,
}
