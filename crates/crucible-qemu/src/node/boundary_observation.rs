//! Effect-free observation acquisition under the original quantum deadline.
//!
//! Mapped observation drains acquire a coherent slot before touching a ring.
//! Publication contention may therefore repeat that acquisition, while any
//! failure after consumption remains an immediate error. The live runtime
//! retains the original advance budget; this path never starts or renews one.

use super::*;

impl QemuNode {
    /// Acquires an observation before effects under the retained RUN budget.
    ///
    /// # Errors
    ///
    /// Returns the original nonbusy channel error, unavailable wait-owner error,
    /// child-exit failure or typed timeout with original owned-child cleanup.
    pub(super) fn read_boundary_observation<T>(
        &mut self,
        operation: &'static str,
        mut read: impl FnMut(&mut dyn QemuShmemHotPathChannel) -> Result<T, QemuNodeChannelError>,
    ) -> Result<T, QemuNodeError> {
        // Match the driver's original renewal slice for an unbounded RUN.
        // Unlike that RUN, observations never renew an expired slice.
        let timeout = if self.async_policy.unbounded_advance_completion {
            self.async_policy
                .advance_completion_timeout
                .min(Duration::from_secs(1))
        } else {
            self.async_policy.advance_completion_timeout
        };
        loop {
            match read(self.channels.shmem_hot_path.as_mut()) {
                Ok(value) => return Ok(value),
                Err(source) if source.is_publication_unavailable() => {}
                Err(source) => {
                    return Err(QemuNodeError::from_channel(
                        QemuNodeChannelPlane::ShmemHotPath,
                        source,
                    ));
                }
            }

            // A completed RUN stays owned. This wait observes only publisher
            // availability and does not drain, wake, or execute the guest.
            let outcome = self
                .host_io_runtime
                .await_node_publication(timeout)
                .map_err(|source| {
                    QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
                })?;
            if let Some(exit) = self.child.try_wait_natural_exit().map_err(|source| {
                QemuNodeError::from_channel(
                    QemuNodeChannelPlane::ShmemHotPath,
                    QemuNodeChannelError::new(operation, source.to_string()),
                )
            })? {
                let status = self.crash_detector.unexpected_child_exit(exit);
                let shutdown = self.shutdown_child()?;
                return Err(QemuNodeError::Crashed {
                    status: Box::new(status),
                    shutdown: Box::new(shutdown),
                });
            }
            if outcome == crate::QemuAsyncWaitOutcome::TimedOut {
                let status = self
                    .crash_detector
                    .bounded_await_timeout(operation, timeout);
                let shutdown = self.shutdown_child()?;
                return Err(QemuNodeError::Crashed {
                    status: Box::new(status),
                    shutdown: Box::new(shutdown),
                });
            }
        }
    }

    /// Reads a marker calibration under the original completion budget.
    ///
    /// # Errors
    ///
    /// Returns the original calibration error or bounded publication failure.
    pub(crate) fn boundary_logical_time_calibration(
        &mut self,
    ) -> Result<QemuLogicalTimeCalibration, QemuNodeError> {
        self.read_boundary_observation("campaign marker calibration", |channel| {
            channel.logical_time_calibration()
        })
    }
}
