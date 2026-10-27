//! Shares the exact observation exchange and independent helper cleanup.
//!
//! Native owners differ by lifetime, while the existing semantic and native
//! reducer remains one body. A stable response still requires real leader
//! death and whole-cgroup empty proof before positive completion.

mod parent_v2;
pub(crate) use parent_v2::{NetworkParentObservationInputV2, NetworkParentObservationOriginalV2};

use super::*;
use aos_sandbox_linux::cgroup::CgroupPopulationMonitor;
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;

pub(super) trait ObservationNativeV4 {
    fn begin(&mut self) -> Result<(), NetworkObservationWorkerError>;
    fn ready(&mut self) -> Result<(), NetworkObservationWorkerError>;
    fn population(&mut self) -> Result<(), NetworkObservationWorkerError>;
    fn exchange(&mut self) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError>;
    fn natural_exit(&mut self) -> Result<(), NetworkObservationWorkerError>;
    fn cleanup(&mut self) -> Result<(), NetworkObservationWorkerError>;
    fn fail_stop(&mut self);
    fn opening_failed(&mut self) {}
}

pub(super) fn observe_recipe_v4(
    native: &mut impl ObservationNativeV4,
) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
    let opening = native
        .begin()
        .and_then(|()| native.ready())
        .and_then(|()| native.population());
    if let Err(primary) = opening {
        native.opening_failed();
        return Err(primary);
    }
    match native.exchange() {
        Ok(observation) => match native.natural_exit() {
            Ok(()) => Ok(observation),
            Err(primary) => {
                if native.cleanup().is_err() {
                    native.fail_stop();
                }
                Err(primary)
            }
        },
        Err(primary) => {
            if native.cleanup().is_err() {
                native.fail_stop();
            }
            Err(primary)
        }
    }
}

pub(super) fn observe_local_v4(
    executor: &mut SystemdNetworkObservationExecutor,
    request: &ObservationRequestV1,
    target: &NamespaceFd,
) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
    let mut native = LocalObservationV4 {
        population: None,
        cgroup: None,
        ready_payload: None,
        ready: None,
        socket: None,
        executor,
        request,
        target,
    };
    observe_recipe_v4(&mut native)
}

struct LocalObservationV4<'held> {
    // Keep the old locals' reverse native disposal order on immediate return.
    population: Option<CgroupPopulationMonitor>,
    cgroup: Option<RetainedCgroupAnchor>,
    ready_payload: Option<ObservationReadyV1>,
    ready: Option<ReceivedDescriptorRecord>,
    socket: Option<DescriptorSubjectSocket>,
    executor: &'held mut SystemdNetworkObservationExecutor,
    request: &'held ObservationRequestV1,
    target: &'held NamespaceFd,
}

impl ObservationNativeV4 for LocalObservationV4<'_> {
    fn begin(&mut self) -> Result<(), NetworkObservationWorkerError> {
        if self.executor.fixed_service {
            return protocol("fixed service observer requires its retained receiving original");
        }
        if self.executor.fail_stopped {
            return protocol("Network observation executor is fail-stopped");
        }
        self.executor.host_namespace.validate_current_network()?;
        self.socket = Some(DescriptorSubjectSocket::connect(
            &self.executor.socket_path,
        )?);
        let socket = self
            .socket
            .as_ref()
            .ok_or(NetworkObservationWorkerError::Protocol(
                "observation socket is absent",
            ))?;
        validate_systemd_manager_peer(socket.peer(), &self.executor.systemd_manager_cgroup)?;
        Ok(())
    }

    fn ready(&mut self) -> Result<(), NetworkObservationWorkerError> {
        let socket = self
            .socket
            .as_mut()
            .ok_or(NetworkObservationWorkerError::Protocol(
                "observation socket is absent",
            ))?;
        self.ready = Some(receive_record_before(
            socket,
            READY_HEADER_BYTES + MAXIMUM_CGROUP_BYTES,
            0,
            deadline_after(TRANSFER_TIMEOUT)?,
        )?);
        let ready = self
            .ready
            .as_ref()
            .ok_or(NetworkObservationWorkerError::Protocol(
                "observation READY is absent",
            ))?;
        self.ready_payload = Some(ObservationReadyV1::decode(ready.payload())?);
        let payload =
            self.ready_payload
                .as_ref()
                .ok_or(NetworkObservationWorkerError::Protocol(
                    "observation READY body is absent",
                ))?;
        self.cgroup = Some(validate_observer_subject(
            payload.cgroup(),
            ready.subject(),
            &self.executor.worker_parent_cgroup,
        )?);
        Ok(())
    }

    fn population(&mut self) -> Result<(), NetworkObservationWorkerError> {
        let cgroup = self
            .cgroup
            .as_ref()
            .ok_or(NetworkObservationWorkerError::Protocol(
                "observation cgroup is absent",
            ))?;
        self.population = Some(cgroup.population_monitor()?);
        Ok(())
    }

    fn exchange(&mut self) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        let (Some(socket), Some(ready), Some(cgroup)) = (
            self.socket.as_mut(),
            self.ready.as_ref(),
            self.cgroup.as_ref(),
        ) else {
            return protocol("observation native prefix is incomplete");
        };
        exchange_observation(
            socket,
            self.request,
            self.executor.host_namespace.as_fd(),
            self.target.as_fd(),
            ready.subject(),
            cgroup,
        )
    }

    fn natural_exit(&mut self) -> Result<(), NetworkObservationWorkerError> {
        let (Some(ready), Some(population)) = (self.ready.as_ref(), self.population.as_ref())
        else {
            return protocol("observation quiescence prefix is incomplete");
        };
        Ok(wait_for_quiescence(
            ready.subject(),
            population,
            NATURAL_EXIT_TIMEOUT,
        )?)
    }

    fn cleanup(&mut self) -> Result<(), NetworkObservationWorkerError> {
        let (Some(ready), Some(cgroup), Some(population)) = (
            self.ready.as_ref(),
            self.cgroup.as_ref(),
            self.population.as_ref(),
        ) else {
            return protocol("observation cleanup prefix is incomplete");
        };
        Ok(quiesce_worker(ready.subject(), cgroup, population)?)
    }

    fn fail_stop(&mut self) {
        self.executor.fail_stopped = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailedObservation {
        opening_fails: bool,
        trace: Vec<&'static str>,
    }

    impl ObservationNativeV4 for FailedObservation {
        fn begin(&mut self) -> Result<(), NetworkObservationWorkerError> {
            self.trace.push("begin");
            Ok(())
        }
        fn ready(&mut self) -> Result<(), NetworkObservationWorkerError> {
            self.trace.push("ready");
            Ok(())
        }
        fn population(&mut self) -> Result<(), NetworkObservationWorkerError> {
            self.trace.push("population");
            if self.opening_fails {
                protocol("monitor original")
            } else {
                Ok(())
            }
        }
        fn exchange(
            &mut self,
        ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
            self.trace.push("exchange");
            protocol("primary exchange")
        }
        fn natural_exit(&mut self) -> Result<(), NetworkObservationWorkerError> {
            panic!("exchange failed")
        }
        fn cleanup(&mut self) -> Result<(), NetworkObservationWorkerError> {
            self.trace.push("cleanup");
            protocol("later cleanup")
        }
        fn fail_stop(&mut self) {
            self.trace.push("fail-stop");
        }
        fn opening_failed(&mut self) {
            self.trace.push("opening-failed");
        }
    }

    #[test]
    fn shared_observation_retains_primary_order_while_cleanup_is_independently_owed() {
        let mut native = FailedObservation {
            opening_fails: false,
            trace: Vec::new(),
        };
        assert!(matches!(
            observe_recipe_v4(&mut native),
            Err(NetworkObservationWorkerError::Protocol("primary exchange"))
        ));
        assert_eq!(
            native.trace,
            [
                "begin",
                "ready",
                "population",
                "exchange",
                "cleanup",
                "fail-stop"
            ]
        );
    }

    #[test]
    fn failed_monitor_enters_only_the_prearmed_opening_cleanup_hook() {
        let mut native = FailedObservation {
            opening_fails: true,
            trace: Vec::new(),
        };
        assert!(matches!(
            observe_recipe_v4(&mut native),
            Err(NetworkObservationWorkerError::Protocol("monitor original"))
        ));
        assert_eq!(
            native.trace,
            ["begin", "ready", "population", "opening-failed"]
        );
    }
}
