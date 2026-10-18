//! Retains RAM cleanup custody and attaches operational node supervision.

use super::*;

impl QemuNode {
    pub(super) fn finish_host_ram_cleanup(&mut self) -> Result<(), QemuNodeError> {
        #[cfg(target_os = "linux")]
        if let Some(ram) = &mut self.hot_fork_ram_continuation {
            ram.finish()?;
        }
        #[cfg(target_os = "linux")]
        if let QemuNodeProcessControl::Direct(child) = &mut self.child {
            finish_ram_source_cleanup(&mut child.ram_source, "join retained RAM source")?;
        }
        self.host_io_runtime
            .retire_host_ram_after_cleanup()
            .map_err(|error| QemuNodeError::Channel {
                plane: QemuNodeChannelPlane::PluginIpcControl,
                operation: "retire host RAM resources",
                message: error.to_string(),
            })
    }

    /// Attaches one operational owner before a reconstructed node is released.
    ///
    /// Both QMP and host I/O retain the same owner; no guest or modeled state is
    /// changed. Native paging admission remains a separate readiness obligation.
    ///
    /// # Errors
    /// Returns a channel error if either existing live transport cannot retain
    /// the independently admitted operational supervision owner.
    pub fn attach_host_operation_supervisor(
        &mut self,
        supervisor: crucible_host_resources::host_supervision::HostOperationSupervisor,
    ) -> Result<(), QemuNodeChannelError> {
        self.channels
            .qmp_machine_control
            .set_host_operation_supervisor(supervisor.clone())?;
        self.host_io_runtime
            .set_host_operation_supervisor(supervisor)
            .map_err(|source| {
                QemuNodeChannelError::new("attach host operation supervisor", source.to_string())
            })
    }
}

/// Keeps failed cleanup custody in its original slot before returning the cause.
///
/// # Errors
/// Returns the typed source refusal after restoring the same service slot.
#[cfg(target_os = "linux")]
pub(super) fn finish_ram_source_cleanup(
    retained: &mut Option<Box<crate::ram_source::QemuRamSourceService>>,
    operation: &'static str,
) -> Result<(), QemuNodeError> {
    if let Some(service) = retained.take()
        && let Err(error) = service.stop()
    {
        *retained = Some(error.service);

        return Err(QemuNodeError::from_ram_source_cleanup(
            operation,
            error.source,
        ));
    }

    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::qmp::checkpoint_paged_source_support::ImmutableBacking;
    use crate::ram_source::{QemuRamBacking, QemuRamSourceError, QemuRamSourceService};
    use crucible_engine::{BackendError, SchedulerError, SchedulerOperationalFailureClass};
    use crucible_host_resources::host_services::{HostServiceAllocator, HostServiceError};
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor, HostSupervisionError,
    };
    use crucible_qemu_protocol::ram_page::{RamPageBinding, RamPageRequest};
    use std::error::Error;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    // Real socket/worker cleanup, without a QEMU process or native RAM authority.
    struct SourceFixture {
        retained: Option<Box<QemuRamSourceService>>,
        peer: UnixStream,
        backing: Arc<ImmutableBacking>,
        binding: RamPageBinding,
        services: HostServiceAllocator,
        supervisor: HostOperationSupervisor,
    }

    impl SourceFixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let backing = Arc::new(ImmutableBacking::new(2)?);
            let binding = RamPageBinding {
                session: [1; 16],
                owner_incarnation: [2; 16],
                source_generation: 1,
                root_digest: *backing.root_record().digest().as_bytes(),
            };

            let supervisor = HostOperationSupervisor::new(
                HostOperationBudgets::default(),
                Some(Duration::from_secs(5)),
            )?;
            let services = HostServiceAllocator::new(1, 4, 8 * 1024 * 1024)?;

            let (server, peer) = UnixStream::pair()?;
            let service = QemuRamSourceService::start(
                server,
                backing.clone(),
                binding,
                supervisor.clone(),
                services.clone(),
            )?;

            Ok(Self {
                retained: Some(Box::new(service)),
                peer,
                backing,
                binding,
                services,
                supervisor,
            })
        }

        fn refuse_an_authenticated_page(&mut self) -> Result<(), Box<dyn Error>> {
            self.backing.corrupt_reads.store(true, Ordering::Release);
            self.peer.write_all(
                &RamPageRequest {
                    binding: self.binding,
                    sequence: 1,
                    region_ordinal: 0,
                    page_index: 0,
                }
                .encode()?,
            )?;

            let observation = self.supervisor.begin(HostOperationClass::Preparation)?;
            loop {
                match self.retained.as_ref().unwrap().check_health() {
                    Err(QemuRamSourceError::WorkerFailed(_)) => break,
                    Err(source) => return Err(source.into()),
                    Ok(()) => {
                        std::thread::sleep(observation.wait_slice()?.min(Duration::from_millis(1)))
                    }
                }
            }

            observation.complete()?;
            Ok(())
        }

        fn task_is_retained(&self) -> bool {
            matches!(
                self.services.reserve_resources(1, 0, 0),
                Err(HostServiceError::CapacityExhausted)
            )
        }
    }

    #[test]
    fn shared_cleanup_helper_keeps_same_cause_and_service_for_both_boundary_labels()
    -> Result<(), Box<dyn Error>> {
        for operation in ["join retained RAM source", "join hot-fork RAM source"] {
            let mut fixture = SourceFixture::new()?;
            fixture.refuse_an_authenticated_page()?;
            let error = finish_ram_source_cleanup(&mut fixture.retained, operation).unwrap_err();
            let observed = fixture
                .retained
                .as_ref()
                .unwrap()
                .check_health()
                .unwrap_err();
            let QemuRamSourceError::WorkerFailed(worker) = observed else {
                panic!("the retained service must expose its original worker failure");
            };
            assert!(matches!(worker.as_ref(), QemuRamSourceError::Proof(_)));
            let QemuNodeError::RamSourceCleanup {
                operation: found,
                source,
            } = &error
            else {
                panic!("cleanup must preserve the typed source failure");
            };
            assert_eq!(*found, operation);
            {
                let original = crate::QemuAsyncDriverHealthError::ram_source(
                    QemuRamSourceError::WorkerFailed(worker.clone()),
                );
                assert_eq!(source, &original);
            }
            assert!(fixture.task_is_retained());

            // The worker was joined, but its first failure and original lease
            // remain observable. A second cleanup closes the retained service;
            // the scheduler observer still keeps that same failure allocation.
            finish_ram_source_cleanup(&mut fixture.retained, operation)?;
            assert!(fixture.retained.is_none());
            let scheduler = SchedulerError::from(BackendError::from(error));
            assert_eq!(
                scheduler.operational_failure_class(),
                Some(SchedulerOperationalFailureClass::Terminal)
            );
            drop(worker);
            assert!(fixture.task_is_retained());
            drop(scheduler);
            assert!(fixture.services.reserve_resources(1, 0, 0).is_ok());
        }
        Ok(())
    }

    #[test]
    fn healthy_source_cleanup_removes_the_service_and_is_idempotent() -> Result<(), Box<dyn Error>>
    {
        let mut fixture = SourceFixture::new()?;
        assert!(fixture.task_is_retained());

        finish_ram_source_cleanup(&mut fixture.retained, "join retained RAM source")?;
        finish_ram_source_cleanup(&mut fixture.retained, "join retained RAM source")?;

        assert!(fixture.retained.is_none());
        assert!(fixture.services.reserve_resources(1, 0, 0).is_ok());
        Ok(())
    }

    #[test]
    fn cleanup_admission_refusal_retains_service_and_credit_until_retry()
    -> Result<(), Box<dyn Error>> {
        let mut fixture = SourceFixture::new()?;
        let mut guards = Vec::new();
        loop {
            match fixture.supervisor.begin(HostOperationClass::Cleanup) {
                Ok(guard) => guards.push(guard),
                Err(HostSupervisionError::CapacityExhausted) => break,
                Err(source) => return Err(source.into()),
            }
        }
        let error = finish_ram_source_cleanup(&mut fixture.retained, "join retained RAM source")
            .unwrap_err();

        assert!(
            matches!(error, QemuNodeError::RamSourceCleanup { ref source, .. }
            if matches!(source.source_failure(), QemuRamSourceError::Supervision(HostSupervisionError::CapacityExhausted)))
        );
        assert!(fixture.retained.is_some());
        assert!(fixture.task_is_retained());

        drop(guards);
        finish_ram_source_cleanup(&mut fixture.retained, "join retained RAM source")?;
        assert!(fixture.retained.is_none());
        assert!(fixture.services.reserve_resources(1, 0, 0).is_ok());
        Ok(())
    }
}
