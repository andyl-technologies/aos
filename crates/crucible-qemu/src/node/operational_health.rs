//! Polls owned source failures without changing pending guest or cleanup state.

pub(crate) mod native_actor;

use super::QemuNodeProcessControl;
use crate::QemuAsyncDriverHealthError;

pub(super) fn check_child_sources(
    child: &QemuNodeProcessControl,
) -> Result<(), QemuAsyncDriverHealthError> {
    #[cfg(target_os = "linux")]
    if let QemuNodeProcessControl::Direct(child) = child {
        child
            .check_ram_source()
            .map_err(QemuAsyncDriverHealthError::ram_source)?;
    }
    Ok(())
}
