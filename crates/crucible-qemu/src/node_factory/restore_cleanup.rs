//! Fail-closed cleanup for rejected warm QEMU realizations.

use super::{QemuNode, QemuNodeChild, QemuNodeFactoryError, QemuWarmRestoreLaunchError};

pub(super) fn reap_failed_warm_restore_child(
    mut child: QemuNodeChild,
    primary: QemuWarmRestoreLaunchError,
) -> QemuWarmRestoreLaunchError {
    match child.force_kill_and_reap_failed_realization() {
        Ok(()) => primary,
        Err(cleanup) => QemuWarmRestoreLaunchError::FailedCleanup {
            primary: Box::new(primary),
            cleanup,
            unreaped_child: Some(Box::new(child)),
        },
    }
}

pub(super) fn reap_failed_restore_child(
    mut child: QemuNodeChild,
    primary: QemuNodeFactoryError,
) -> QemuNodeFactoryError {
    match child.force_kill_and_reap_failed_realization() {
        Ok(()) => primary,
        Err(cleanup) => QemuNodeFactoryError::FailedRestoreCleanup {
            primary: Box::new(primary),
            cleanup,
            unreaped_child: Some(Box::new(child)),
        },
    }
}

pub(super) fn reap_failed_restored_node(
    mut node: QemuNode,
    primary: QemuNodeFactoryError,
) -> QemuNodeFactoryError {
    match node.reap_failed_realization() {
        Ok(()) => primary,
        Err(cleanup) => QemuNodeFactoryError::FailedRestoreCleanup {
            primary: Box::new(primary),
            cleanup,
            unreaped_child: Some(Box::new(node.into_direct_child_for_quarantine())),
        },
    }
}
