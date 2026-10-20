//! Effect-free observation acquisition under the original quantum deadline.
//!
//! Mapped observation drains acquire a coherent slot before touching a ring.
//! Publication contention may therefore repeat that acquisition, while any
//! failure after consumption remains an immediate error. The live runtime
//! retains the original advance budget; this path never starts or renews one.
//!
//! The node's coherent single-slot reads (instruction count, idle state,
//! time calibration, and timer witness) use the same acquisition. A
//! completed RUN does not stop QEMU from publishing: it settles the host's
//! clamp advance right after acknowledging it, so one read can race that
//! write.

use super::*;

#[cfg(test)]
thread_local! {
    /// Receives the operation name each time a read on this thread finds the
    /// slot publication busy and is about to wait for it.
    pub(super) static BUSY_OBSERVATION_FOR_TEST:
        std::cell::RefCell<Option<std::sync::mpsc::Sender<&'static str>>> =
        const { std::cell::RefCell::new(None) };
}

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
                Err(source) if source.is_publication_unavailable() => {
                    #[cfg(test)]
                    BUSY_OBSERVATION_FOR_TEST.with_borrow(|hook| {
                        if let Some(hook) = hook {
                            let _delivered = hook.send(operation);
                        }
                    });
                }
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

    /// Reads the current retired-instruction count through shared memory.
    ///
    /// A completed RUN does not stop QEMU from publishing, so a single
    /// coherent read can race its next write. Contention is retried under the
    /// retained RUN budget, without draining, waking, or running the guest.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory hot path cannot be
    /// read, or when no coherent publication appears within the retained
    /// budget; the child is then shut down as a crashed node.
    pub fn current_icount(&mut self) -> Result<Icount, QemuNodeError> {
        self.read_boundary_observation("current_icount", |channel| channel.current_icount())
    }

    /// Reads the current idle state through shared memory.
    ///
    /// Publication contention is retried like [`Self::current_icount`].
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory idle state cannot be
    /// read within the retained RUN budget.
    pub fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeError> {
        self.read_boundary_observation("idle_state", |channel| channel.idle_state())
    }

    /// Reads the coherent logical/raw time calibration published by the plugin.
    ///
    /// Publication contention is retried like [`Self::current_icount`].
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory state cannot be read
    /// within the retained RUN budget or its raw instruction count is ahead of
    /// logical time.
    pub fn logical_time_calibration(
        &mut self,
    ) -> Result<QemuLogicalTimeCalibration, QemuNodeError> {
        self.read_boundary_observation("logical-time calibration", |channel| {
            channel.logical_time_calibration()
        })
    }

    /// Reads the calibration once, for diagnostics that must not wait.
    ///
    /// Publication contention returns an error instead of waiting, so a
    /// best-effort report can never spend the retained RUN budget or shut the
    /// child down.
    pub(crate) fn try_logical_time_calibration(
        &mut self,
    ) -> Result<QemuLogicalTimeCalibration, QemuNodeError> {
        self.channels
            .shmem_hot_path
            .logical_time_calibration()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })
    }

    /// Reads the most recent actual virtual-timer callback witness.
    ///
    /// Publication contention is retried like [`Self::current_icount`].
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the shared-memory state cannot be read
    /// within the retained RUN budget.
    pub fn virtual_timer_fire_witness(
        &mut self,
    ) -> Result<Option<QemuVirtualTimerFireWitness>, QemuNodeError> {
        self.read_boundary_observation("virtual-timer fire witness", |channel| {
            channel.virtual_timer_fire_witness()
        })
    }
}
