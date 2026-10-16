//! Keeps a refused node/lease pairing in the same containing Source launcher.

use super::*;

pub(super) struct RetainedFailedLaunch {
    node: Option<QemuNode>,
    lease: Option<Box<dyn ProductionVmNodeLease>>,
    _run_directory: std::path::PathBuf,
    channels_closed: bool,
}

impl RetainedFailedLaunch {
    pub(super) fn new(launch: ProductionVmNodeLaunch) -> Self {
        let (node, lease, run_directory) = launch.into_retained_parts();
        Self {
            node: Some(node),
            lease: Some(lease),
            _run_directory: run_directory,
            channels_closed: false,
        }
    }

    pub(super) fn finish(&mut self) -> Result<(), LifecycleApiError> {
        if let Some(node) = self.node.as_mut() {
            node.force_quarantine_and_reap().map_err(|error| {
                launcher_message(format!("reap refused QEMU node pairing: {error}"))
            })?;
            // A destructor unwind leaves channels_closed false and the exact
            // lease retained; a later retry cannot certify physical return.
            drop(self.node.take());
            self.channels_closed = true;
        }
        if !self.channels_closed {
            return Err(launcher_message(
                "refused QEMU pairing channel return is uncertain",
            ));
        }
        if let Some(lease) = self.lease.as_mut() {
            lease.finish()?;
        }
        self.lease = None;
        Ok(())
    }
}
