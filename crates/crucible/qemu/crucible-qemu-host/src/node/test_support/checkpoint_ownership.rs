//! Real local checkpoint custody with conditional remote wire observations.
//!
//! The existing ARM sender transfers an actual eventfd alias. The existing QMP
//! client validates a begin reply derived from that received request. The peers
//! issue no native Source, Stop owner, page proof, or VM qualification.

use crate::qmp::{QmpClient, QmpTimeoutStream};
use crate::ram_control::{RamControlClient, RamControlRegistrar, RamControlRegistration};
use crate::{
    CheckpointArmLoan, CheckpointOriginalError, CheckpointOriginalLoan,
    QemuAsyncDriverRuntimeError, QemuNodeChannelError,
};
use crucible_host_resources::host_services::HostServiceAllocator;
use crucible_host_resources::host_supervision::{
    HostOperationBudget, HostOperationBudgets, HostOperationClass, HostOperationGuard,
    HostOperationSupervisor,
};
use crucible_host_resources::ram_policy::{
    HostRamMode, HostRamPolicy, HostRamTarget, HostResourceVector,
};
use crucible_qemu_protocol::ram_control::*;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::error::Error;
use std::io::Write;
use std::io::{self, IoSliceMut, Read};
use std::mem::MaybeUninit;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Default)]
struct Observations {
    arm: Option<([u8; 32], u64)>,
    original_id: Option<u64>,
    arms: usize,
    begins: usize,
    alias_closed: bool,
    aliases: Vec<OwnedFd>,
}

struct Registrar {
    client: Mutex<RamControlClient>,
    observations: Arc<Mutex<Observations>>,
}

impl RamControlRegistrar for Registrar {
    fn checkpoint_arm(
        &self,
        loan: CheckpointArmLoan<'_>,
    ) -> Result<crate::ram_control::CheckpointArmReceipt, CheckpointOriginalError> {
        self.observations.lock().unwrap().original_id =
            Some(loan.original().guard().status().unwrap().operation_id);
        self.client.lock().unwrap().checkpoint_arm(loan)
    }

    fn register(
        &self,
        _: HostRamTarget,
        _: HostRamPolicy,
        _: HostResourceVector,
        _: HostOperationSupervisor,
        _: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }
}

pub(crate) struct Ownership {
    pub(crate) supervisor: HostOperationSupervisor,
    pub(crate) registration: RamControlRegistration,
    cancellation: OwnedFd,
    qmp: Mutex<QmpClient<Wire>>,
    observations: Arc<Mutex<Observations>>,
    stop: Arc<AtomicBool>,
    wake: UnixStream,
    peer: Option<JoinHandle<io::Result<()>>>,
}

impl std::fmt::Debug for Ownership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointOwnership")
            .finish_non_exhaustive()
    }
}

// Sleeping component processes ignore modeled Quit messages. Give real cleanup
// a short finite class allowance while retaining every containment phase.
pub(crate) fn fixture_budgets() -> HostOperationBudgets {
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::Cleanup as usize] =
        HostOperationBudget::finite(Duration::from_secs(1));
    budgets
}

impl Ownership {
    #[cfg(test)]
    pub(crate) fn new(fail_stop: bool) -> Result<Arc<Self>, Box<dyn Error>> {
        let supervisor =
            HostOperationSupervisor::new(fixture_budgets(), Some(Duration::from_secs(30)))?;
        Self::with_supervisor(supervisor, fail_stop)
    }

    pub(crate) fn with_supervisor(
        supervisor: HostOperationSupervisor,
        fail_stop: bool,
    ) -> Result<Arc<Self>, Box<dyn Error>> {
        let account = HostServiceAllocator::new(2, 8, 1024 * 1024)?;
        let cancellation = rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )?;
        let target = HostRamTarget {
            daemon_epoch: [1; 32],
            owner_id: [2; 32],
            node_id: [3; 32],
            owner_generation: 1,
            arena_generation: 1,
            retained_template: false,
        };
        let observations = Arc::new(Mutex::new(Observations::default()));
        let qmp = QmpClient::connect(Wire::new(observations.clone(), fail_stop))?;
        let stop = Arc::new(AtomicBool::new(false));
        let (host, remote) = UnixStream::pair()?;
        let wake = remote.try_clone()?;
        remote.set_read_timeout(Some(Duration::from_millis(100)))?;
        let remote_observations = observations.clone();
        let remote_stop = stop.clone();
        let peer = std::thread::spawn(move || serve_ram(remote, remote_observations, remote_stop));
        let client =
            match RamControlClient::connect_supervised(host, [4; 32], target, supervisor.clone()) {
                Ok(client) => client,
                Err(error) => {
                    stop.store(true, Ordering::Release);
                    let _ = wake.shutdown(Shutdown::Both);
                    let _ = peer.join();
                    return Err(error.into());
                }
            };
        let registration = RamControlRegistration {
            target,
            initial_policy: HostRamPolicy {
                mode: HostRamMode::ResidentRequired,
                resident_target_bytes: 4096,
                eviction_preference: 0,
                writeback_bytes_per_second: 4096,
                maximum_paging_io_in_flight: 1,
                prefetch_on_increase: false,
                latency: HostOperationBudgets::default(),
            },
            resources: HostResourceVector::default(),
            spill_quota_bytes: 0,
            host_services: account,
            registrar: Arc::new(Registrar {
                client: Mutex::new(client),
                observations: observations.clone(),
            }),
        };
        Ok(Arc::new(Self {
            supervisor,
            registration,
            cancellation,
            qmp: Mutex::new(qmp),
            observations,
            stop,
            wake,
            peer: Some(peer),
        }))
    }

    pub(crate) fn cancellation(&self) -> io::Result<OwnedFd> {
        self.cancellation.try_clone()
    }

    pub(crate) fn bind(
        &self,
        original: CheckpointOriginalLoan,
    ) -> Result<(), QemuNodeChannelError> {
        self.qmp
            .lock()
            .unwrap()
            .bind_checkpoint_original(original)
            .map_err(|e| channel("bind checkpoint original", e))
    }

    pub(crate) fn begin(
        &self,
        receipt: crate::ram_control::CheckpointArmReceipt,
    ) -> Result<(), QemuNodeChannelError> {
        self.qmp
            .lock()
            .unwrap()
            .begin_checkpoint_receiving(receipt)
            .map_err(|e| channel("begin checkpoint receiving", e))
    }

    pub(crate) fn stop(&self) -> Result<(), QemuNodeChannelError> {
        self.qmp
            .lock()
            .unwrap()
            .stop()
            .map(|_| ())
            .map_err(|e| channel("stop_for_checkpoint", e))
    }

    pub(crate) fn resume(&self) -> Result<(), QemuNodeChannelError> {
        self.qmp
            .lock()
            .unwrap()
            .cont()
            .map(|_| ())
            .map_err(|e| channel("resume_after_checkpoint", e))
    }

    pub(crate) fn check(
        &self,
        original: &HostOperationGuard,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let operation = "scripted checkpoint original";
        if !original.shares_outer_cap(&self.supervisor)
            || self.observations.lock().unwrap().original_id
                != Some(
                    original
                        .status()
                        .map_err(|e| {
                            QemuAsyncDriverRuntimeError::operational_supervision(operation, e)
                        })?
                        .operation_id,
                )
        {
            return Err(QemuAsyncDriverRuntimeError::new(
                operation,
                "different original owner",
            ));
        }
        original
            .check_original_quiescence_cancellation()
            .and_then(|()| original.wait_slice().map(|_| ()))
            .map_err(|e| QemuAsyncDriverRuntimeError::operational_supervision(operation, e))
    }

    #[cfg(test)]
    pub(crate) fn cancel_from_peer(&self) -> io::Result<()> {
        let observations = self.observations.lock().unwrap();
        assert_eq!(observations.aliases.len(), 1);
        rustix::io::write(&observations.aliases[0], &1_u64.to_ne_bytes())?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn original_id(&self) -> Option<u64> {
        self.observations.lock().unwrap().original_id
    }

    #[cfg(test)]
    pub(crate) fn peer_lifetime(&self) -> impl Fn() -> bool + use<> {
        let observations = self.observations.clone();
        move || observations.lock().unwrap().alias_closed
    }

    #[cfg(test)]
    pub(crate) fn counts(&self) -> (usize, usize) {
        let observations = self.observations.lock().unwrap();
        (observations.arms, observations.begins)
    }
}

impl Drop for Ownership {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.wake.shutdown(Shutdown::Both);
        if let Some(peer) = self.peer.take() {
            let result = peer.join();
            if !std::thread::panicking() {
                assert!(
                    matches!(result, Ok(Ok(()))),
                    "checkpoint wire peer failed: {result:?}"
                );
            }
        }
    }
}

fn channel(operation: &'static str, error: impl std::fmt::Display) -> QemuNodeChannelError {
    QemuNodeChannelError::new(operation, error.to_string())
}

struct Aliases {
    observations: Arc<Mutex<Observations>>,
}

impl Drop for Aliases {
    fn drop(&mut self) {
        let mut observed = self.observations.lock().unwrap();
        observed.aliases.clear();
        observed.alias_closed = true;
    }
}

fn serve_ram(
    stream: UnixStream,
    observations: Arc<Mutex<Observations>>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    match serve_ram_loop(stream, observations, &stop) {
        Err(error)
            if stop.load(Ordering::Acquire)
                && matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                ) =>
        {
            Ok(())
        }
        result => result,
    }
}

// Hello is a conditional wire observation. No inventory, physical measurement,
// actor, placement, or successful operation is supplied by this peer.
fn hello_reply(frame: RamControlFrame) -> io::Result<RamControlFrame> {
    let state = RamControlReply {
        performance: None,
        placement_receipt: None,
        operation_failure: None,
        fault_actor: None,
        kernel_probe: None,
        activity: None,
        disposition: RamControlDisposition::Accepted,
        logical_ram_bytes: 0,
        inventory: None,
        inventory_region: None,
        limitation_reasons: 0,
        measurements_available: false,
        resident_observation: None,
        requested_policy_revision: 1,
        applied_policy_revision: 1,
        reservation_revision: 1,
        observation_sequence: 1,
        effective_resident_target_bytes: 0,
        effective_floor_bytes: 0,
        private_resident_bytes: 0,
        shared_resident_bytes_observed: 0,
        preserved_backing_bytes: 0,
        private_dirty_bytes: 0,
        writeback_pending_bytes: 0,
        convergence: RamControlConvergence::Stable,
    };
    Ok(RamControlFrame {
        message: RamControlMessage::Reply {
            request_digest: ram_control_request_digest(&frame).map_err(io::Error::other)?,
            state,
        },
        ..frame
    })
}

fn serve_ram_loop(
    mut stream: UnixStream,
    observations: Arc<Mutex<Observations>>,
    stop: &AtomicBool,
) -> io::Result<()> {
    let hello = read_ram_control(&mut stream)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("missing Hello"))?;
    assert!(matches!(
        hello.message,
        RamControlMessage::Request(RamControlRequest::Hello)
    ));
    write_ram_control(&mut stream, &hello_reply(hello)?).map_err(io::Error::other)?;
    let _aliases = Aliases {
        observations: observations.clone(),
    };
    while !stop.load(Ordering::Acquire) {
        let mut first = [0];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received = match recvmsg(
            &stream,
            &mut [IoSliceMut::new(&mut first)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        ) {
            Ok(received) if received.bytes == 0 => return Ok(()),
            Ok(received) => received,
            Err(error) if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::INTR => {
                continue;
            }
            Err(_) if stop.load(Ordering::Acquire) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        assert_eq!(received.bytes, 1);
        let descriptors: Vec<_> = ancillary
            .drain()
            .flat_map(|message| match message {
                RecvAncillaryMessage::ScmRights(fds) => fds.collect::<Vec<_>>(),
                _ => panic!("unexpected ARM ancillary record"),
            })
            .collect();
        assert_eq!(descriptors.len(), 1);
        observations.lock().unwrap().aliases.extend(descriptors);
        let mut length = [0; 4];
        length[0] = first[0];
        stream.read_exact(&mut length[1..])?;
        let length = u32::from_be_bytes(length) as usize;
        assert!(length <= RAM_CONTROL_CHECKPOINT_MAX_BYTES);
        let mut body = [0; RAM_CONTROL_CHECKPOINT_MAX_BYTES];
        stream.read_exact(&mut body[..length])?;
        let arm = decode_ram_control(&body[..length]).map_err(io::Error::other)?;
        assert!(matches!(
            arm.message,
            RamControlMessage::Request(RamControlRequest::CheckpointArm { .. })
        ));
        let digest = ram_control_request_digest(&arm).map_err(io::Error::other)?;
        {
            let mut observed = observations.lock().unwrap();
            assert_eq!(observed.arms, 0, "ARM alias must be transferred only once");
            observed.arms += 1;
            observed.arm = Some((digest, arm.sequence));
        }
        let receipt = RamControlFrame {
            message: RamControlMessage::CheckpointArmReply {
                request_digest: digest,
                receipt: RamControlCheckpointArmReceipt {
                    disposition: RamControlDisposition::Accepted,
                    request_generation: arm.sequence,
                    first_status: 0,
                    post_status: 0,
                },
            },
            ..arm
        };
        write_ram_control(&mut stream, &receipt).map_err(io::Error::other)?;
    }
    Ok(())
}

/// Duplex JSON observations consumed by the real QMP parser and original loan.
struct Wire {
    input: VecDeque<u8>,
    output: Vec<u8>,
    observations: Arc<Mutex<Observations>>,
    fail_stop: bool,
    running: bool,
}

impl Wire {
    fn new(observations: Arc<Mutex<Observations>>, fail_stop: bool) -> Self {
        Self {
            input: b"{\"QMP\":{\"version\":{},\"capabilities\":[]}}\n"
                .to_vec()
                .into(),
            output: Vec::new(),
            observations,
            fail_stop,
            running: true,
        }
    }

    fn reply(&mut self, request: Value) -> io::Result<()> {
        let response = match request["execute"].as_str() {
            Some("qmp_capabilities") => json!({ "return": {} }),
            Some("crucible-checkpoint-begin") => {
                let mut observed = self.observations.lock().unwrap();
                let (digest, generation) = observed
                    .arm
                    .ok_or_else(|| io::Error::other("begin before ARM"))?;
                let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
                assert_eq!(request["arguments"]["arm-request-digest"], digest);
                assert_eq!(request["arguments"]["request-generation"], generation);
                observed.begins += 1;
                json!({ "return": {
                    "arm-request-digest": request["arguments"]["arm-request-digest"],
                    "request-generation": request["arguments"]["request-generation"],
                    "connection-epoch": 11,
                } })
            }
            Some("stop") if self.fail_stop => {
                json!({"error": {"class": "GenericError", "desc": "injected QMP stop failure"}})
            }
            Some("stop") => {
                self.running = false;
                json!({ "return": {} })
            }
            Some("cont") => {
                self.running = true;
                json!({ "return": {} })
            }
            Some("query-status") => {
                json!({ "return": { "running": self.running, "singlestep": false, "status": if self.running { "running" } else { "paused" } } })
            }
            _ => return Err(io::Error::other("unexpected checkpoint QMP command")),
        };
        self.input.extend(serde_json::to_vec(&response)?);
        self.input.push_back(b'\n');
        Ok(())
    }
}

impl Read for Wire {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = buffer.len().min(self.input.len());
        for byte in &mut buffer[..length] {
            *byte = self.input.pop_front().unwrap();
        }
        Ok(length)
    }
}

impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        while let Some(end) = self.output.iter().position(|byte| *byte == b'\n') {
            let line: Vec<_> = self.output.drain(..=end).collect();
            self.reply(serde_json::from_slice(&line)?)?;
        }
        Ok(())
    }
}

impl QmpTimeoutStream for Wire {
    fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
    fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}
