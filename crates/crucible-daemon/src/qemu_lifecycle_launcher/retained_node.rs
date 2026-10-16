//! Retains the actual node, lease and directory through pairing or observation.

use super::*;

pub(super) struct RetainedNodeLaunch {
    node: Option<QemuNode>,
    lease: Option<RetainedNodeLease>,
    _run_directory: std::path::PathBuf,
    channels_closed: bool,
}

enum RetainedNodeLease {
    Paired(Box<dyn ProductionVmNodeLease>),
    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    Observed(QemuLifecycleGenerationLease),
}

impl RetainedNodeLaunch {
    pub(super) fn new(launch: ProductionVmNodeLaunch) -> Self {
        let (node, lease, run_directory) = launch.into_retained_parts();
        Self {
            node: Some(node),
            lease: Some(RetainedNodeLease::Paired(lease)),
            _run_directory: run_directory,
            channels_closed: false,
        }
    }

    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    pub(super) fn observed(
        node: QemuNode,
        lease: QemuLifecycleGenerationLease,
        run_directory: std::path::PathBuf,
    ) -> Self {
        Self {
            node: Some(node),
            lease: Some(RetainedNodeLease::Observed(lease)),
            _run_directory: run_directory,
            channels_closed: false,
        }
    }

    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    pub(super) fn node_mut(&mut self) -> Result<&mut QemuNode, LifecycleApiError> {
        self.node
            .as_mut()
            .ok_or_else(|| launcher_message("observed native node channels already closed"))
    }

    pub(super) fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        if let Some(node) = self.node.as_mut() {
            node.force_quarantine_and_reap().map_err(|error| {
                launcher_message(format!("reap retained QEMU node pairing: {error}"))
            })?;
            // An unwind leaves closure unknown and retains this exact lease.
            drop(self.node.take());
            self.channels_closed = true;
        }
        if !self.channels_closed {
            return Err(
                (launcher_message("retained QEMU node channel return is uncertain")).into(),
            );
        }
        if let Some(lease) = self.lease.as_mut() {
            match lease {
                RetainedNodeLease::Paired(lease) => lease.finish()?,
                #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
                RetainedNodeLease::Observed(lease) => lease.finish()?,
            }
        }
        self.lease = None;
        Ok(())
    }
}
