//! Fresh identity reads after same-boundary fault-command publication.

use super::*;
use crate::QemuAsyncDriverRuntimeError;
use crate::supervision::host_io_runtime::operational_wait::OperationPollBudget;
use crucible_linux_resource::host_supervision::HostOperationClass;

impl QemuNode {
    fn capture_fault_fingerprint(
        &mut self,
        deadline: &OperationPollBudget<'_>,
    ) -> Result<(), QemuNodeError> {
        let result = match deadline {
            OperationPollBudget::Supervised(original) => self
                .host_io_runtime
                .publish_current_execution_fingerprint_under_original(original),
            OperationPollBudget::Borrowed(original) => self
                .host_io_runtime
                .publish_current_execution_fingerprint_under_original(original),
            OperationPollBudget::Fixture(_) => {
                #[cfg(any(test, feature = "test-support"))]
                {
                    let remaining = deadline
                        .remaining("publish fresh fault fingerprint")
                        .map_err(fingerprint_runtime_error)?
                        .ok_or_else(|| {
                            fingerprint_runtime_error(QemuAsyncDriverRuntimeError::new(
                                "publish fresh fault fingerprint",
                                "fixture operation has expired",
                            ))
                        })?;
                    self.host_io_runtime
                        .publish_fresh_execution_fingerprint_for_test(remaining)
                }
                #[cfg(not(any(test, feature = "test-support")))]
                {
                    Err(QemuAsyncDriverRuntimeError::new(
                        "publish fresh fault fingerprint",
                        "fresh fault capture requires original supervision",
                    ))
                }
            }
        };
        result.map_err(fingerprint_runtime_error)
    }

    pub(super) fn read_fresh_fault_fingerprint(
        &mut self,
        deadline: &OperationPollBudget<'_>,
    ) -> Result<ExecutionFingerprint, QemuNodeError> {
        self.capture_fault_fingerprint(deadline)?;
        // A fresh ACK followed by an invalid sample is a refusal, not a reason
        // to issue a second coalescing request or return the previous sample.
        let fingerprint = self
            .channels
            .shmem_hot_path
            .execution_fingerprint()
            .map_err(fingerprint_channel_error)?;
        deadline
            .complete("read fresh fault fingerprint")
            .map_err(fingerprint_runtime_error)?;
        self.fault_fingerprint_invalidated = false;
        Ok(fingerprint)
    }

    pub(super) fn read_fresh_fault_fingerprint_sample(
        &mut self,
    ) -> Result<QemuFingerprintSample, QemuNodeError> {
        let deadline = OperationPollBudget::begin(
            self.host_operation_supervisor(),
            HostOperationClass::FingerprintUpdate,
            self.async_policy.advance_completion_timeout,
            "read fresh fault fingerprint sample",
        )
        .map_err(fingerprint_runtime_error)?;
        self.capture_fault_fingerprint(&deadline)?;

        let sample = self
            .channels
            .shmem_hot_path
            .fingerprint_sample()
            .map_err(fingerprint_channel_error)?;
        let current = self.current_icount()?;
        if sample.sample_icount != current.retired {
            return Err(fingerprint_channel_error(QemuNodeChannelError::new(
                "read fresh fault fingerprint sample",
                format!(
                    "sample icount {} differs from current boundary {}",
                    sample.sample_icount, current.retired,
                ),
            )));
        }
        crate::mapped_quantum::validate_black_box_fingerprint_sample(&sample)
            .map_err(fingerprint_channel_error)?;
        deadline
            .complete("read fresh fault fingerprint sample")
            .map_err(fingerprint_runtime_error)?;
        self.fault_fingerprint_invalidated = false;
        Ok(sample)
    }
}

fn fingerprint_runtime_error(source: QemuAsyncDriverRuntimeError) -> QemuNodeError {
    QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
}

fn fingerprint_channel_error(source: QemuNodeChannelError) -> QemuNodeError {
    QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
}
