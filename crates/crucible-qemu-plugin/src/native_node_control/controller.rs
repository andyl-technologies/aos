//! Retained native command snapshots and stop facts beneath GPL-side custody.

use std::{
    collections::BTreeMap,
    ffi::c_void,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use crucible_node_contract::{Id, Phase, Position, U64};
use crucible_protocol::node_control::{
    BoundaryPolicy, CommandJournal, CommandJournalDisposition, ExecutionCommand, ExecutionKind,
    NativeCommandError, OwnerScope,
};

use super::abi::{
    NATIVE_NODE_CONTROL_VERSION, NativeNodeCommand, NativeNodeReceipt, RegisterNodeControl,
};

struct State {
    journal: CommandJournal,
    current: Option<NativeNodeCommand>,
    receipts: BTreeMap<u64, NativeNodeReceipt>,
    quarantined: bool,
    cpu_park: Option<crucible_protocol::node_control::NativeCpuParkFacts>,
    timer_objects: BTreeMap<u64, Vec<u8>>,
    timer_object_bytes: usize,
    writer_objects: BTreeMap<u64, Vec<u8>>,
    writer_object_bytes: usize,
    writer_generation: Option<u64>,
    source_fault: Option<crucible_protocol::node_control::SourceFaultFacts>,
}

/// Retains separately admitted native requests for process-lifetime callbacks.
///
/// The authenticated process-channel adapter must verify preparation, durable
/// activation and original complete input custody before calling `retain`.
/// This correlation mechanism does not qualify complete native queue closure.
pub(crate) struct NativeNodeControl {
    initialization: Option<super::initialization_custody::InitializationCustody>,
    initialization_registered: AtomicBool,
    state: Mutex<State>,
    protocol_worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    worker_gate: OnceLock<Arc<crate::runtime::worker_quiescence::LiveWorkerQuiescence>>,
    protocol_notify: Option<super::abi::NotifyNodeControl>,
    prepared_scope_hash: [u8; 32],
    cpu_query: Option<super::abi::QueryCpuPark>,
    timer_query: Option<super::abi::QueryTimers>,
    writer_query: Option<super::writer_abi::QueryWriters>,
    source_fault_query: Option<super::source_fault_abi::QuerySourceFault>,
    #[cfg(unix)]
    channel: Option<crucible_protocol::node_control::NativeChannel>,
}

impl NativeNodeControl {
    pub(crate) fn new(
        scope: OwnerScope,
        boundary: Position,
        maximum_commands: usize,
    ) -> Result<Self, NativeCommandError> {
        let prepared_scope_hash = scope.identity_digest()?;
        Ok(Self {
            initialization: None,
            initialization_registered: AtomicBool::new(false),
            prepared_scope_hash,
            cpu_query: None,
            timer_query: None,
            writer_query: None,
            source_fault_query: None,
            state: Mutex::new(State {
                journal: CommandJournal::new(scope, boundary, maximum_commands)?,
                current: None,
                receipts: BTreeMap::new(),
                quarantined: false,
                cpu_park: None,
                timer_objects: BTreeMap::new(),
                timer_object_bytes: 0,
                writer_objects: BTreeMap::new(),
                writer_object_bytes: 0,
                writer_generation: None,
                source_fault: None,
            }),
            protocol_worker: Mutex::new(None),
            worker_gate: OnceLock::new(),
            protocol_notify: None,
            #[cfg(unix)]
            channel: None,
        })
    }

    /// Attaches the separately prepared private nonblocking endpoint.
    ///
    /// Only the supervisor-owned descriptor custody chain can supply this socket.
    /// A newly decoded command still must match the pinned full owner scope.
    #[cfg(unix)]
    pub(crate) fn with_prepared_channel(
        mut self,
        channel: crucible_protocol::node_control::NativeChannel,
    ) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Retains the native wake function before binding the actual runtime workers.
    pub(crate) fn with_protocol_notify(mut self, notify: super::abi::NotifyNodeControl) -> Self {
        self.protocol_notify = Some(notify);
        self
    }

    /// Processes at most one original native transport request per callback.
    #[cfg(unix)]
    pub(crate) fn poll_channel(&self) -> Result<(), NativeCommandError> {
        use crucible_protocol::node_control::NativeFrame;
        let Some(channel) = &self.channel else {
            return Ok(());
        };
        let received = channel
            .receive()
            .map_err(|_| NativeCommandError::Conflict)?;
        match received {
            None => Ok(()),
            Some(
                frame @ (NativeFrame::QueryInitialization(_)
                | NativeFrame::Initialize(_)
                | NativeFrame::AcknowledgeInitialization(_)),
            ) => self.poll_initialization_frame(frame),
            Some(NativeFrame::Command(command)) => {
                let sequence = command.sequence;
                let disposition = self.retain(*command)?;
                if matches!(
                    disposition,
                    CommandJournalDisposition::Stopped | CommandJournalDisposition::Acknowledged
                ) {
                    self.send_original_facts(sequence)?;
                }
                Ok(())
            }
            Some(NativeFrame::Acknowledge(ack)) => {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| NativeCommandError::Conflict)?;
                let original = state
                    .journal
                    .original(ack.sequence)
                    .ok_or(NativeCommandError::Conflict)?;
                if original.identity_digest()? != ack.command_digest {
                    return Err(NativeCommandError::Conflict);
                }
                drop(state);
                self.acknowledge(ack.sequence, &ack.authorization_digest)?;
                if let Some(channel) = &self.channel {
                    // A full socket preserves original journal custody. The
                    // host retries this exact ACK to recover the same reply.
                    let _sent = channel
                        .send(&NativeFrame::Acknowledged(ack))
                        .map_err(|_| NativeCommandError::Conflict)?;
                }
                Ok(())
            }
            Some(NativeFrame::QueryTimers(query)) => self.send_timer_chunk(&query),
            Some(NativeFrame::QueryWriters(query)) => self.send_writer_chunk(&query),
            Some(NativeFrame::QueryCpuPark(scope)) => {
                if scope != self.prepared_scope_hash {
                    return Err(NativeCommandError::Conflict);
                }
                self.send_cpu_park()
            }
            Some(
                NativeFrame::Stopped(_)
                | NativeFrame::Prepare(_)
                | NativeFrame::Acknowledged(_)
                | NativeFrame::CpuPark(_)
                | NativeFrame::TimerChunk(_)
                | NativeFrame::WriterChunk(_)
                | NativeFrame::SourceFault(_)
                | NativeFrame::PrepareInitialization(_)
                | NativeFrame::InitializationCut(_)
                | NativeFrame::InitializationStopped(_)
                | NativeFrame::InitializationAcknowledged(_),
            ) => Err(NativeCommandError::Conflict),
        }
    }

    #[cfg(unix)]
    fn send_original_facts(&self, sequence: U64) -> Result<(), NativeCommandError> {
        let Some(channel) = &self.channel else {
            return Ok(());
        };
        let receipt = self.receipt(sequence).ok_or(NativeCommandError::Conflict)?;
        let facts = portable_facts(receipt)?;
        // A full socket leaves the immutable facts under native journal custody.
        // The host retries its original command to recover exactly these facts.
        channel
            .send(&crucible_protocol::node_control::NativeFrame::Stopped(
                facts,
            ))
            .map_err(|_| NativeCommandError::Conflict)?;
        Ok(())
    }

    /// Starts and retains the sole native protocol-reader worker.
    #[cfg(unix)]
    pub(crate) fn start_prepared_protocol_worker(
        &'static self,
        workers: Arc<crate::runtime::worker_quiescence::LiveWorkerQuiescence>,
    ) -> Result<(), std::io::Error> {
        let notify = self
            .protocol_notify
            .ok_or_else(|| std::io::Error::other("native protocol wake was not prepared"))?;
        self.start_protocol_worker(notify, workers)
    }

    #[cfg(unix)]
    pub(crate) fn start_protocol_worker(
        &'static self,
        notify: super::abi::NotifyNodeControl,
        workers: Arc<crate::runtime::worker_quiescence::LiveWorkerQuiescence>,
    ) -> Result<(), std::io::Error> {
        let mut worker = self
            .protocol_worker
            .lock()
            .map_err(|_| std::io::Error::other("native protocol worker custody poisoned"))?;
        if worker.is_some() || self.channel.is_none() {
            return Err(std::io::Error::other(
                "native protocol worker already started or has no prepared socket",
            ));
        }
        if workers.worker_mask() & crate::runtime::worker_quiescence::WORKER_NATIVE_CONTROL == 0 {
            return Err(std::io::Error::other(
                "native reader is absent from the actual worker roster",
            ));
        }
        self.worker_gate
            .set(Arc::clone(&workers))
            .map_err(|_| std::io::Error::other("native reader worker gate is already bound"))?;
        let (started, startup) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::Builder::new()
            .name("crucible-native-node-control".into())
            .spawn(move || self.run_protocol_worker(notify, workers, started))?;
        *worker = Some(handle);
        drop(worker);
        // Native registration already owns these callbacks. A startup timeout
        // retains the handle and original socket for the fatal install policy.
        startup
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| {
                std::io::Error::other("native reader did not reach its registered safe point")
            })?;
        Ok(())
    }

    pub(crate) fn has_protocol_worker(&self) -> bool {
        self.protocol_worker
            .lock()
            .ok()
            .is_some_and(|worker| worker.as_ref().is_some_and(|handle| !handle.is_finished()))
    }

    /// Returns independently retained native resources after reader startup.
    #[cfg(unix)]
    pub(crate) fn prepared_resources(&self) -> Option<(i32, [u8; 32])> {
        use std::os::fd::AsRawFd;

        if !self.has_protocol_worker() {
            return None;
        }
        let workers = self.worker_gate.get()?;
        if workers.worker_mask() & crate::runtime::worker_quiescence::WORKER_NATIVE_CONTROL == 0 {
            return None;
        }
        let channel = self.channel.as_ref()?;
        Some((
            channel.prepared_descriptor().as_raw_fd(),
            self.prepared_scope_hash,
        ))
    }

    #[cfg(unix)]
    fn run_protocol_worker(
        &'static self,
        notify: super::abi::NotifyNodeControl,
        workers: Arc<crate::runtime::worker_quiescence::LiveWorkerQuiescence>,
        started: std::sync::mpsc::SyncSender<()>,
    ) {
        use std::os::fd::AsRawFd;
        let Some(channel) = &self.channel else {
            return;
        };
        let mut idle = workers.idle(crate::runtime::worker_quiescence::WORKER_NATIVE_CONTROL);
        if started.send(()).is_err() {
            return;
        }
        loop {
            let mut readiness = libc::pollfd {
                fd: channel.prepared_descriptor().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let faulted = self
                .state
                .lock()
                .ok()
                .is_some_and(|state| state.source_fault.is_some());
            if faulted {
                // Preserve every unread original frame after proof invalidation.
                // Polling the socket here would spin on an unconsumed command.
                readiness.events = 0;
            }
            let timeout = if self.source_fault_query.is_some() {
                25
            } else {
                -1
            };
            // SAFETY: The descriptor and writable pollfd remain live under
            // process-lifetime ownership. Polling changes no modeled clocks.
            let result = unsafe { libc::poll(&mut readiness, 1, timeout) };
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            if result < 0
                || readiness.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
            {
                if let Ok(mut state) = self.state.lock() {
                    state.quarantined = true;
                    state.current = None;
                }
                let _ = notify();
                return;
            }
            // The socket is nonblocking. Acquire admission before receive so
            // a held cut contains either the untouched socket bytes or the
            // whole bounded journal operation, never an unaccounted local frame.
            let operation = idle.enter_before_nonblocking_receive();
            match self.observe_source_fault() {
                Ok(true) => {
                    if self.send_source_fault().is_err() {
                        return;
                    }
                    drop(operation);
                    idle = workers.idle(crate::runtime::worker_quiescence::WORKER_NATIVE_CONTROL);
                    continue;
                }
                Ok(false) => {}
                Err(_) => {
                    if let Ok(mut state) = self.state.lock() {
                        state.quarantined = true;
                        state.current = None;
                    }
                    let _ = notify();
                    return;
                }
            }
            if result == 0 {
                drop(operation);
                idle = workers.idle(crate::runtime::worker_quiescence::WORKER_NATIVE_CONTROL);
                continue;
            }
            if self.poll_channel().is_err() {
                if let Ok(mut state) = self.state.lock() {
                    state.quarantined = true;
                    state.current = None;
                }
                let _ = notify();
                return;
            }
            // Publish the original retained command before waking RR's durable
            // predicate scan. This wake neither injects work nor advances time.
            if notify() != 0 {
                if let Ok(mut state) = self.state.lock() {
                    state.quarantined = true;
                    state.current = None;
                }
                return;
            }
            drop(operation);
            idle = workers.idle(crate::runtime::worker_quiescence::WORKER_NATIVE_CONTROL);
        }
    }

    /// Registers an independently negotiated process-lifetime callback owner.
    ///
    /// The caller retains this owner until QEMU terminates; the static reference
    /// prevents a dropped transport handle from invalidating native callbacks.
    pub(crate) fn register(
        &'static self,
        register: RegisterNodeControl,
    ) -> Result<(), NativeCommandError> {
        self.register_initialization()?;
        let result = register(
            NATIVE_NODE_CONTROL_VERSION,
            Some(get_command),
            Some(publish_stop),
            (self as *const Self).cast_mut().cast(),
        );
        if result == 0 {
            Ok(())
        } else {
            if self.initialization_registered.load(Ordering::Acquire) {
                // The source already owns initializer callbacks into this library.
                // Returning an install refusal could unload still-referenced code.
                std::process::abort();
            }
            Err(NativeCommandError::Conflict)
        }
    }

    pub(crate) fn retain(
        &self,
        command: ExecutionCommand,
    ) -> Result<CommandJournalDisposition, NativeCommandError> {
        if self
            .initialization
            .as_ref()
            .is_some_and(|initialization| !initialization.permits_execution_transport())
        {
            return Err(NativeCommandError::Conflict);
        }
        let snapshot = snapshot(&command)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        if state.quarantined {
            return Err(NativeCommandError::Conflict);
        }
        let disposition = state.journal.retain(command)?;
        if disposition == CommandJournalDisposition::New {
            state.current = Some(snapshot);
        }
        Ok(disposition)
    }

    pub(crate) fn command(&self) -> Option<NativeNodeCommand> {
        if self
            .initialization
            .as_ref()
            .is_some_and(|initialization| !initialization.permits_execution_transport())
        {
            return None;
        }
        let state = self.state.lock().ok()?;
        if state.quarantined {
            None
        } else {
            state.current
        }
    }

    pub(crate) fn receipt(&self, sequence: U64) -> Option<NativeNodeReceipt> {
        self.state
            .lock()
            .ok()?
            .receipts
            .get(&sequence.get())
            .copied()
    }

    pub(crate) fn record_stop(&self, receipt: NativeNodeReceipt) -> Result<(), NativeCommandError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        let result = record_stop(&mut state, receipt);
        if result.is_err() {
            state.quarantined = true;
            state.current = None;
        }
        result
    }

    /// Settles original correlated custody after the authenticated host commit.
    pub(crate) fn acknowledge(
        &self,
        sequence: U64,
        original_authorization: &[u8; 32],
    ) -> Result<(), NativeCommandError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        if state.quarantined {
            return Err(NativeCommandError::Conflict);
        }
        state.journal.acknowledge(sequence, original_authorization)
    }
}

fn snapshot(command: &ExecutionCommand) -> Result<NativeNodeCommand, NativeCommandError> {
    let start = command.kind.start();
    let limit = command.kind.limit();
    let (kind, policy) = match command.kind {
        ExecutionKind::ExactRun {
            boundary_policy, ..
        } => (
            1,
            match boundary_policy {
                BoundaryPolicy::HorizonPark => 0,
                BoundaryPolicy::InputBlockedPark => 1,
            },
        ),
        ExecutionKind::BoundarySettle { .. } => (2, 0),
    };
    let binding_hash = digest_bytes(&command.scope.owner_binding.digest)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.qemu-native-owner-incarnation.v1\0");
    for identity in [
        &command.scope.session,
        &command.scope.incarnation,
        &command.scope.owner,
    ] {
        hash_identifier(&mut hasher, identity);
    }
    hasher.update(&command.scope.owner_generation.get().to_be_bytes());
    let owner_incarnation_hash = *hasher.finalize().as_bytes();
    Ok(NativeNodeCommand {
        version: NATIVE_NODE_CONTROL_VERSION,
        size: std::mem::size_of::<NativeNodeCommand>() as u32,
        kind,
        policy,
        sequence: command.sequence.get(),
        start_ps: start.time_ps.get(),
        start_microstep: start.microstep.get(),
        start_phase: start.phase as u64,
        limit_ps: limit.time_ps.get(),
        limit_microstep: limit.microstep.get(),
        limit_phase: limit.phase as u64,
        binding_hash,
        owner_incarnation_hash,
        grant_hash: command.identity_digest()?,
    })
}

fn hash_identifier(hasher: &mut blake3::Hasher, identity: &Id) {
    hasher.update(&(identity.as_str().len() as u16).to_be_bytes());
    hasher.update(identity.as_str().as_bytes());
}

fn digest_bytes(digest: &str) -> Result<[u8; 32], NativeCommandError> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(digest, &mut bytes)
        .map_err(|_| NativeCommandError::Invalid("invalid native binding digest"))?;
    Ok(bytes)
}

fn record_stop(state: &mut State, receipt: NativeNodeReceipt) -> Result<(), NativeCommandError> {
    if state.quarantined
        || receipt.version != NATIVE_NODE_CONTROL_VERSION
        || receipt.size != std::mem::size_of::<NativeNodeReceipt>() as u32
        || !matches!(receipt.reason, 1..=4)
    {
        return Err(NativeCommandError::Conflict);
    }
    if let Some(original) = state.receipts.get(&receipt.command_sequence) {
        return if original == &receipt {
            Ok(())
        } else {
            Err(NativeCommandError::Conflict)
        };
    }
    let command = state
        .journal
        .original(U64::new(receipt.command_sequence))
        .ok_or(NativeCommandError::Conflict)?;
    let snapshot = snapshot(command)?;
    if state.current != Some(snapshot) || snapshot.grant_hash != receipt.grant_hash {
        return Err(NativeCommandError::Conflict);
    }
    let phase = match receipt.reached_phase {
        0 => Phase::BoundaryControl,
        1 => Phase::Publication,
        2 => Phase::Delivery,
        3 => Phase::Reaction,
        _ => return Err(NativeCommandError::Invalid("native stop has unknown phase")),
    };
    let reached = Position {
        time_ps: U64::new(receipt.current_ps),
        microstep: U64::new(receipt.reached_microstep),
        phase,
    };
    if receipt.reason == 1 && reached != command.kind.limit() {
        return Err(NativeCommandError::Conflict);
    }
    // Only original stopped facts are retained. Incomplete pending_classes never
    // become a complete source inventory or a positive producer-bound receipt.
    state
        .journal
        .record_native_stop(U64::new(receipt.command_sequence), reached)?;
    state.receipts.insert(receipt.command_sequence, receipt);
    state.current = None;
    Ok(())
}

#[cfg(unix)]
fn portable_facts(
    receipt: NativeNodeReceipt,
) -> Result<crucible_protocol::node_control::NativeStopFacts, NativeCommandError> {
    use crucible_protocol::node_control::{NativeStopFacts, NativeStopKind};
    let kind = match receipt.reason {
        1 => NativeStopKind::HorizonPark,
        2 => NativeStopKind::NativeBoundary,
        3 => NativeStopKind::Unsupported,
        4 => NativeStopKind::Invalid,
        _ => return Err(NativeCommandError::Conflict),
    };
    let phase = match receipt.reached_phase {
        0 => Phase::BoundaryControl,
        1 => Phase::Publication,
        2 => Phase::Delivery,
        3 => Phase::Reaction,
        _ => return Err(NativeCommandError::Conflict),
    };
    Ok(NativeStopFacts {
        sequence: U64::new(receipt.command_sequence),
        command_digest: receipt.grant_hash,
        kind,
        reached: Position {
            time_ps: U64::new(receipt.current_ps),
            microstep: U64::new(receipt.reached_microstep),
            phase,
        },
        retired_count: U64::new(receipt.raw_icount),
        pending_classes: receipt.pending_classes,
        next_native_deadline_ps: (receipt.next_native_deadline_ps != u64::MAX)
            .then_some(U64::new(receipt.next_native_deadline_ps)),
        next_service_deadline_ps: (receipt.next_service_deadline_ps != u64::MAX)
            .then_some(U64::new(receipt.next_service_deadline_ps)),
        pending_service_credit_ps: U64::new(receipt.pending_service_credit_ps),
    })
}

extern "C" fn get_command(out: *mut NativeNodeCommand, userdata: *mut c_void) -> bool {
    if out.is_null() || userdata.is_null() {
        return false;
    }
    // SAFETY: Registration requires a static owner; QEMU passes its original
    // userdata and a writable, suitably aligned ABI-sized output object.
    let owner = unsafe { &*userdata.cast::<NativeNodeControl>() };
    if owner.writer_query.is_some()
        && !owner
            .state
            .lock()
            .ok()
            .is_some_and(|state| state.writer_objects.contains_key(&0))
    {
        if (owner.observe_initial_cpu_park().is_err()
            || owner.observe_writers(U64::new(0)).is_err())
            && let Ok(mut state) = owner.state.lock()
        {
            state.quarantined = true;
            state.current = None;
        }
        return false;
    }
    let Some(command) = owner.command() else {
        if (owner.observe_initial_cpu_park().is_err()
            || owner.observe_writers(U64::new(0)).is_err()
            || owner.observe_timers(U64::new(0)).is_err())
            && let Ok(mut state) = owner.state.lock()
        {
            state.quarantined = true;
            state.current = None;
        }
        return false;
    };
    // SAFETY: The checked QEMU callback contract provides exclusive output storage.
    unsafe {
        out.write(command);
    }
    true
}

extern "C" fn publish_stop(receipt: *const NativeNodeReceipt, userdata: *mut c_void) {
    if receipt.is_null() || userdata.is_null() {
        return;
    }
    // SAFETY: QEMU supplies an ABI-sized immutable receipt during this callback;
    // userdata remains the original registered process-lifetime owner.
    let owner = unsafe { &*userdata.cast::<NativeNodeControl>() };
    let receipt = unsafe { receipt.read() };
    // Invalid native evidence withholds all future modeled execution. The host
    // must reconcile or contain the original request rather than replay it.
    if owner.record_stop(receipt).is_ok() {
        if owner
            .observe_timers(U64::new(receipt.command_sequence))
            .is_err()
            || owner
                .observe_writers(U64::new(receipt.command_sequence))
                .is_err()
        {
            if let Ok(mut state) = owner.state.lock() {
                state.quarantined = true;
                state.current = None;
            }
            return;
        }
        #[cfg(unix)]
        let _ = owner.send_original_facts(U64::new(receipt.command_sequence));
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[path = "cpu_park.rs"]
mod cpu_park;

#[path = "timers.rs"]
mod timers;

#[path = "source_fault.rs"]
mod source_fault;
#[path = "writers.rs"]
mod writers;

#[path = "initialization_callbacks.rs"]
mod initialization_callbacks;
