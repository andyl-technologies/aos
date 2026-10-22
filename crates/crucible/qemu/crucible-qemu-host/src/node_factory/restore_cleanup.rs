//! Preserves borrowed restore cleanup history while its issued owner stays held.

use super::QemuNodeFactoryError;

pub(super) fn reap_failed_restore_child(
    owner: &mut crate::node::IssuedLaunchOwner,
    primary: QemuNodeFactoryError,
) -> QemuNodeFactoryError {
    match owner.retry_cleanup() {
        Ok(()) => primary,
        Err(cleanup) => QemuNodeFactoryError::FailedRestoreCleanup {
            primary: Box::new(primary),
            cleanup,
        },
    }
}
