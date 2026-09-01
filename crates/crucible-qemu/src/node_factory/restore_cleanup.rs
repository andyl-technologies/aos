//! Fail-closed cleanup for rejected warm QEMU realizations.

use super::{QemuNode, QemuNodeChild, QemuNodeFactoryError};

pub(super) fn reap_failed_restore_child(
    child: &mut QemuNodeChild,
    primary: QemuNodeFactoryError,
) -> QemuNodeFactoryError {
    match child.force_kill_and_reap_failed_realization() {
        Ok(()) => primary,
        Err(cleanup) => QemuNodeFactoryError::FailedRestoreCleanup {
            primary: Box::new(primary),
            cleanup,
        },
    }
}

pub(super) fn reap_failed_restored_node(
    node: &mut QemuNode,
    primary: QemuNodeFactoryError,
) -> QemuNodeFactoryError {
    match node.reap_failed_realization() {
        Ok(()) => primary,
        Err(cleanup) => QemuNodeFactoryError::FailedRestoreCleanup {
            primary: Box::new(primary),
            cleanup,
        },
    }
}
