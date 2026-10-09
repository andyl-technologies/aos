//! Owning selected-native driver with exact command history and sticky uncertainty.

use std::{
    fs,
    io::{Read, Write},
    net::Shutdown,
    os::unix::{
        fs::DirBuilderExt,
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crucible_node_contract::{Id, U64, canonical};

use crate::{ProviderError, reference_device::DeviceOutput};

use super::{
    LineageStage, NativeLineageOrigin, NativeLineageReceipt,
    custody::LineageCustodyQueue,
    journal::{Journal, NativeCommandRecord},
    kernel::KernelScope,
    physical_observation::PhysicalActivation,
    protocol::{DIALECT, MAX_FRAME_BYTES, Request, Response},
    transport::{DeadlineIo, ExchangeBudget, connect},
};

const MAX_WINDOWS: usize = 64;
static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Distinguishes actual native command custody from kernel containment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineageDeviceStatus {
    /// The actual child is parked and accepts the next original stage.
    Parked,
    /// Original ordered inputs are staged without executing their checksum loop.
    Staged,
    /// The original native output is retained before acknowledged closure.
    Active,
    /// The actual original native closure awaits host publication acknowledgment.
    ClosedPending,
    /// Effect paths are fenced; original command and response custody remains.
    Quarantined,
    /// The original child was reaped and the complete private group disappeared.
    Reclaimed,
}

/// Retains one actual original stage, native output, closure and ACK status.
#[derive(Clone)]
pub struct NativeLineageWindow {
    stage: LineageStage,
    output: Option<DeviceOutput>,
    closed: Option<NativeLineageReceipt>,
    pub(super) closed_command: Option<usize>,
    measured_host_ns: Option<U64>,
    acknowledged: bool,
}

impl NativeLineageWindow {
    /// Returns the actual original staged event inventory.
    pub fn stage(&self) -> &LineageStage {
        &self.stage
    }

    /// Returns native output retained before any public publication release.
    pub fn output(&self) -> Option<&DeviceOutput> {
        self.output.as_ref()
    }

    /// Returns the actual validated original native closure, if received.
    pub fn closure(&self) -> Option<&NativeLineageReceipt> {
        self.closed.as_ref()
    }

    /// Returns separately observed physical duration of the original activation.
    pub fn measured_host_ns(&self) -> Option<U64> {
        self.measured_host_ns
    }

    /// Reports actual native ACK receipt, without erasing original closure custody.
    pub fn acknowledged(&self) -> bool {
        self.acknowledged
    }
}

pub(super) struct Session {
    child: Option<Child>,
    pub(super) pid: u32,
    pub(super) owner: Id,
    pub(super) incarnation: Id,
    pub(super) generation: U64,
    kernel: Option<KernelScope>,
    stream: Option<UnixStream>,
    directory: PathBuf,
    pub(super) journal: Journal,
    pub(super) windows: Vec<NativeLineageWindow>,
    pub(super) reclaimed: bool,
}

impl Session {
    pub(super) fn poll_reclamation(&mut self) -> Result<bool, ProviderError> {
        if self.reclaimed {
            return Ok(true);
        }
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let child = self
            .child
            .as_mut()
            .ok_or(ProviderError::Correlation("lineage original child absent"))?;
        if self.kernel.is_none() {
            self.kernel = Some(KernelScope::capture(child)?);
        }
        self.reclaimed = self
            .kernel
            .as_mut()
            .ok_or(ProviderError::Correlation("lineage kernel custody absent"))?
            .poll(child)?;
        if self.reclaimed {
            let _ = fs::remove_file(self.directory.join("control.sock"));
            let _ = fs::remove_dir(&self.directory);
        }
        Ok(self.reclaimed)
    }
}

/// Owns a source-selected native lineage child and its complete finite history.
///
/// Spawn verifies actual OS peer identity and the distinct native dialect. It
/// does not qualify an arbitrary executable or grant common-runtime authority.
/// The enclosing installed adapter must authenticate every original stage and
/// authorize each publication ACK. Drop transfers complete native custody to
/// the pre-reserved persistent queue, including rejected or partial responses.
pub struct NativeLineageDevice {
    session: Option<Box<Session>>,
    queue: LineageCustodyQueue,
    reservation: U64,
    owner: Id,
    incarnation: Id,
    generation: U64,
    timeout: Duration,
    status: LineageDeviceStatus,
    current: Option<usize>,
}

impl NativeLineageDevice {
    /// Reserves custody before spawning and authenticates actual native readiness.
    ///
    /// # Errors
    /// Refuses invalid launch geometry, exhausted custody or journal credit,
    /// failed spawn, timed-out readiness, a foreign peer or a changed dialect.
    /// Post-spawn failures retain the original child and complete raw journal.
    pub fn spawn(
        executable: &Path,
        socket_parent: &Path,
        owner: Id,
        incarnation: Id,
        generation: U64,
        timeout: Duration,
        queue: LineageCustodyQueue,
    ) -> Result<Self, ProviderError> {
        if !executable.is_absolute() || generation.get() == 0 || timeout.is_zero() {
            return Err(ProviderError::Correlation("invalid native lineage launch"));
        }
        ExchangeBudget::after(timeout)?;
        let journal = Journal::new()?;
        let mut windows = Vec::new();
        windows
            .try_reserve_exact(MAX_WINDOWS)
            .map_err(|_| ProviderError::ResourceExhausted("lineage window reservation"))?;
        let reservation = queue.reserve()?;
        let sequence =
            match DIRECTORY_SEQUENCE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            }) {
                Ok(sequence) => sequence,
                Err(_) => {
                    queue.release_unspawned(reservation);
                    return Err(ProviderError::ResourceExhausted(
                        "lineage directory sequence",
                    ));
                }
            };
        let directory = socket_parent.join(format!(
            "crucible-lineage-{}-{sequence}",
            std::process::id()
        ));
        // Allocate the complete fallback capsule before the first native spawn.
        // Transfer on Drop moves this allocation and performs no allocation.
        let mut session = Box::new(Session {
            child: None,
            pid: 0,
            owner: owner.clone(),
            incarnation: incarnation.clone(),
            generation,
            kernel: None,
            stream: None,
            directory: directory.clone(),
            journal,
            windows,
            reclaimed: false,
        });
        let initialize = Request::Initialize {
            dialect: DIALECT.into(),
            owner: owner.clone(),
            incarnation: incarnation.clone(),
            generation,
        };
        let ready_index = match session.journal.reserve(&initialize) {
            Ok(index) => index,
            Err(error) => {
                queue.release_unspawned(reservation);
                return Err(error);
            }
        };
        let launch = (|| {
            fs::DirBuilder::new().mode(0o700).create(&directory)?;
            let listener = UnixListener::bind(directory.join("control.sock"))?;
            listener.set_nonblocking(true)?;
            let child = Command::new(executable)
                .arg(directory.join("control.sock"))
                .current_dir(&directory)
                .env_clear()
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            Ok::<_, ProviderError>((listener, child))
        })();
        let (listener, child) = match launch {
            Ok(launched) => launched,
            Err(error) => {
                let _ = fs::remove_file(directory.join("control.sock"));
                let _ = fs::remove_dir(&directory);
                queue.release_unspawned(reservation);
                return Err(error);
            }
        };
        let pid = child.id();
        session.pid = pid;
        session.child = Some(child);
        let mut device = Self {
            session: Some(session),
            queue,
            reservation,
            owner,
            incarnation,
            generation,
            timeout,
            status: LineageDeviceStatus::Parked,
            current: None,
        };
        // Capture the leader while it remains waitable, before any exit inspection.
        let session = device.session_mut()?;
        let child = session
            .child
            .as_ref()
            .ok_or(ProviderError::Correlation("lineage original child absent"))?;
        session.kernel = Some(KernelScope::capture(child)?);
        session.stream = Some(connect(&listener, child, timeout)?);
        let ready = device.exchange_reserved(ready_index)?;
        if !matches!(ready, Response::Ready { dialect, owner: actual_owner, incarnation: actual_incarnation, generation: actual_generation, child_pid } if dialect == DIALECT && actual_owner == device.owner && actual_incarnation == device.incarnation && actual_generation == generation && child_pid.get() == u64::from(pid))
        {
            return device.reject("native lineage readiness changed original scope");
        }
        device.session_mut()?.journal.accept(ready_index);
        Ok(device)
    }

    /// Borrows actual original native identity and the accepted initialization frame.
    ///
    /// The result retains historical provenance after quarantine or reaping. It
    /// supplies no current readiness, installed source qualification or effect
    /// permission. The raw frame was checked against actual peer credentials.
    ///
    /// # Errors
    /// Refuses absent original session/kernel identity or initialization whose
    /// response was not accepted in this owning driver's actual scope.
    pub fn origin(&self) -> Result<NativeLineageOrigin<'_>, ProviderError> {
        let session = self.session.as_ref().ok_or(ProviderError::Correlation(
            "original native lineage session absent",
        ))?;
        let kernel = session.kernel.as_ref().ok_or(ProviderError::Correlation(
            "original native lineage kernel identity absent",
        ))?;
        let initialization = session
            .journal
            .commands
            .first()
            .filter(|command| command.knowledge() == super::NativeCommandKnowledge::Accepted)
            .ok_or(ProviderError::Correlation(
                "original native lineage initialization is unaccepted",
            ))?;
        Ok(NativeLineageOrigin {
            pid: session.pid,
            start_ticks: kernel.original_start_ticks(),
            owner: &session.owner,
            incarnation: &session.incarnation,
            generation: session.generation,
            initialization,
        })
    }

    /// Returns the current effect and native output custody state.
    pub fn status(&self) -> LineageDeviceStatus {
        self.status
    }

    /// Returns the original pre-spawn supervision reservation.
    pub fn reservation(&self) -> U64 {
        self.reservation
    }

    /// Returns exact retained original commands, including uncertain response bytes.
    pub fn commands(&self) -> &[NativeCommandRecord] {
        self.session
            .as_ref()
            .map_or(&[], |session| session.journal.commands.as_slice())
    }

    /// Returns all original windows, including acknowledged predecessor closures.
    pub fn windows(&self) -> &[NativeLineageWindow] {
        self.session
            .as_ref()
            .map_or(&[], |session| session.windows.as_slice())
    }

    /// Stages one authentic original ordered input inventory without executing it.
    ///
    /// # Errors
    /// Refuses changed ownership, original identity reuse, skipped quantum,
    /// exhausted pre-effect credit or a mismatched actual native stage receipt.
    /// Transport uncertainty fences all later effects while retaining originals.
    pub fn stage(&mut self, original: LineageStage) -> Result<(), ProviderError> {
        self.connected()?;
        original.validate()?;
        if original.grant.owner_id != self.owner
            || original.grant.incarnation_id != self.incarnation
            || original.grant.generation != self.generation
        {
            return Err(ProviderError::Conflict("lineage stage changed owner"));
        }
        if let Some(current) = self.current {
            return if self.windows()[current].stage == original {
                Ok(())
            } else {
                Err(ProviderError::Conflict(
                    "lineage stage replaced original input",
                ))
            };
        }
        let count = self.windows().len();
        if count >= MAX_WINDOWS
            || original.grant.quantum.get() != count as u64
            || self
                .windows()
                .iter()
                .any(|window| window.stage.grant.window_id == original.grant.window_id)
        {
            return Err(ProviderError::Conflict(
                "lineage original window reused or exhausted",
            ));
        }
        let expected = original.identity()?;
        let request = Request::Stage {
            dialect: DIALECT.into(),
            original: Box::new(original.clone()),
        };
        let index = self.session_mut()?.journal.reserve(&request)?;
        // Reserve raw response credit before changing local stage custody. The
        // complete original inventory is then retained before native bytes.
        self.session_mut()?.windows.push(NativeLineageWindow {
            stage: original.clone(),
            output: None,
            closed: None,
            closed_command: None,
            measured_host_ns: None,
            acknowledged: false,
        });
        self.current = Some(count);
        let response = self.exchange_reserved(index)?;
        if !matches!(response, Response::Staged { original } if original == expected) {
            return self.reject("native lineage staged receipt changed original");
        }
        self.session_mut()?.journal.accept(index);
        self.status = LineageDeviceStatus::Staged;
        Ok(())
    }

    /// Executes the actual ordered entry loop once and retains its original output.
    ///
    /// # Errors
    /// Refuses absent or uncertain staging, exhausted native journal credit,
    /// transport loss or an output referring to another original window.
    pub fn activate(&mut self) -> Result<DeviceOutput, ProviderError> {
        self.connected()?;
        let current = self.current.ok_or(ProviderError::Conflict(
            "lineage activation omits original stage",
        ))?;
        if let Some(output) = &self.windows()[current].output {
            return Ok(output.clone());
        }
        if self.status != LineageDeviceStatus::Staged {
            return Err(ProviderError::Conflict(
                "lineage original stage is not accepted",
            ));
        }
        let window = self.windows()[current].stage.grant.window_id.clone();
        let budget = Duration::from_nanos(self.windows()[current].stage.grant.host_budget_ns.get());
        let measurement = PhysicalActivation::begin();
        let result = self.exchange_budget(
            &Request::Activate {
                window: window.clone(),
            },
            budget,
        );
        let observed = match measurement.finish(budget) {
            Ok(observed) => observed,
            Err(_) => return self.reject("lineage physical duration extent"),
        };
        let measured = observed.nanoseconds;
        self.session_mut()?.windows[current].measured_host_ns = Some(measured);
        let (response, index) = result?;
        let output = match response {
            Response::Completed {
                window: actual,
                output,
            } if actual == window
                && output.bytes_processed.get()
                    == self.windows()[current].stage.input.len() as u64 =>
            {
                output
            }
            _ => return self.reject("native lineage output changed original stage"),
        };
        let session = self.session_mut()?;
        session.windows[current].output = Some(output.clone());
        session.windows[current].measured_host_ns = Some(measured);
        if observed.exceeded_budget {
            // Preserve the actual output before reporting physical uncertainty.
            // An over-budget receipt cannot authorize a successful public window.
            return self.reject("lineage original activation budget exhausted");
        }
        session.journal.accept(index);
        self.status = LineageDeviceStatus::Active;
        Ok(output)
    }

    /// Obtains actual native park and checks its complete original consumption chain.
    ///
    /// # Errors
    /// Refuses unactivated or uncertain windows, exhausted journal credit,
    /// changed entry order, predecessor closure, checksum or native park response.
    pub fn close(&mut self) -> Result<NativeLineageReceipt, ProviderError> {
        self.connected()?;
        let current = self.current.ok_or(ProviderError::Conflict(
            "lineage close omits original stage",
        ))?;
        if let Some(closed) = &self.windows()[current].closed {
            return Ok(closed.clone());
        }
        if self.status != LineageDeviceStatus::Active {
            return Err(ProviderError::Conflict("lineage close precedes activation"));
        }
        let window = self.windows()[current].stage.grant.window_id.clone();
        let (response, index) = self.exchange(&Request::Close { window })?;
        let Response::Closed { original } = response else {
            return self.reject("native lineage close response changed kind");
        };
        let checked = original.validate_against(
            &self.windows()[current].stage,
            current
                .checked_sub(1)
                .and_then(|previous| self.windows()[previous].closed.as_ref()),
        );
        if checked.is_err() || self.windows()[current].output.as_ref() != Some(&original.output) {
            return self.reject("native lineage closure changed actual consumption");
        }
        let session = self.session_mut()?;
        session.windows[current].closed = Some((*original).clone());
        session.windows[current].closed_command = Some(index);
        session.journal.accept(index);
        self.status = LineageDeviceStatus::ClosedPending;
        Ok(*original)
    }

    /// Authenticates a closure against this driver's actual retained native history.
    ///
    /// # Errors
    /// Refuses changed, foreign or unobserved receipts. This authenticates only
    /// original native custody, not common-world publication permission.
    pub fn validate_closure(&self, receipt: &NativeLineageReceipt) -> Result<(), ProviderError> {
        if self
            .windows()
            .iter()
            .any(|window| window.closed.as_ref() == Some(receipt))
        {
            Ok(())
        } else {
            Err(ProviderError::Correlation(
                "lineage receipt lacks original native custody",
            ))
        }
    }

    /// ACKs only an actual closed original window after host-authorized publication.
    ///
    /// # Errors
    /// Refuses foreign receipts, premature ACK, uncertain state, exhausted credit
    /// or a mismatched native acknowledgment. Original history remains retained.
    pub fn acknowledge_publication(
        &mut self,
        receipt: &NativeLineageReceipt,
    ) -> Result<(), ProviderError> {
        self.connected()?;
        self.validate_closure(receipt)?;
        if self
            .windows()
            .iter()
            .any(|window| window.closed.as_ref() == Some(receipt) && window.acknowledged)
        {
            return Ok(());
        }
        let current = self
            .current
            .ok_or(ProviderError::Conflict("lineage ACK omits current window"))?;
        if self.status != LineageDeviceStatus::ClosedPending
            || self.windows()[current].closed.as_ref() != Some(receipt)
        {
            return Err(ProviderError::Conflict(
                "lineage ACK changed retained original",
            ));
        }
        let window = receipt.grant.window_id.clone();
        let (response, index) = self.exchange(&Request::Acknowledge {
            window: window.clone(),
        })?;
        if !matches!(response, Response::Acknowledged { window: actual } if actual == window) {
            return self.reject("native lineage ACK changed original window");
        }
        let session = self.session_mut()?;
        session.windows[current].acknowledged = true;
        session.journal.accept(index);
        self.current = None;
        self.status = LineageDeviceStatus::Parked;
        Ok(())
    }

    /// Fences native effects and polls actual original child and group reclamation.
    ///
    /// # Errors
    /// Retains original custody on kernel identity, census or termination failure.
    /// A true result never authorizes modeled output release or scope reuse.
    pub fn poll_quarantine(&mut self) -> Result<bool, ProviderError> {
        self.status = LineageDeviceStatus::Quarantined;
        let reclaimed = self.session_mut()?.poll_reclamation()?;
        if reclaimed {
            self.status = LineageDeviceStatus::Reclaimed;
        }
        Ok(reclaimed)
    }

    fn connected(&self) -> Result<(), ProviderError> {
        if matches!(
            self.status,
            LineageDeviceStatus::Quarantined | LineageDeviceStatus::Reclaimed
        ) {
            Err(ProviderError::Conflict(
                "lineage original incarnation is contained",
            ))
        } else {
            Ok(())
        }
    }

    fn session_mut(&mut self) -> Result<&mut Session, ProviderError> {
        self.session
            .as_deref_mut()
            .ok_or(ProviderError::Correlation(
                "lineage native custody transferred",
            ))
    }

    fn reject<T>(&mut self, reason: &'static str) -> Result<T, ProviderError> {
        self.status = LineageDeviceStatus::Quarantined;
        if let Some(stream) = self.session_mut()?.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        Err(ProviderError::Correlation(reason))
    }

    fn exchange(&mut self, request: &Request) -> Result<(Response, usize), ProviderError> {
        self.exchange_budget(request, self.timeout)
    }

    fn exchange_budget(
        &mut self,
        request: &Request,
        budget: Duration,
    ) -> Result<(Response, usize), ProviderError> {
        let budget = ExchangeBudget::after(budget)?;
        let index = self.session_mut()?.journal.reserve(request)?;
        self.exchange_with_budget(index, budget)
            .map(|response| (response, index))
    }

    fn exchange_reserved(&mut self, index: usize) -> Result<Response, ProviderError> {
        self.exchange_with_budget(index, ExchangeBudget::after(self.timeout)?)
    }

    fn exchange_with_budget(
        &mut self,
        index: usize,
        budget: ExchangeBudget,
    ) -> Result<Response, ProviderError> {
        let session = self.session_mut()?;
        let record = &mut session.journal.commands[index];
        let result = (|| {
            let stream = session
                .stream
                .as_mut()
                .ok_or(ProviderError::Correlation("lineage stream absent"))?;
            let mut io = DeadlineIo::new(stream, budget);
            let length = u32::try_from(record.request.len())
                .map_err(|_| ProviderError::Frame("lineage request extent"))?;
            io.write_all(&length.to_be_bytes())?;
            io.write_all(&record.request)?;
            read_response_with_budget(&mut io, &mut record.response_wire, budget)
        })();
        session.journal.charge_response(index);
        match result {
            Ok(response) => Ok(response),
            Err(error) => {
                self.status = LineageDeviceStatus::Quarantined;
                if let Some(stream) = self.session_mut()?.stream.take() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
                Err(error)
            }
        }
    }
}

impl Drop for NativeLineageDevice {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            self.queue.retain(self.reservation, session);
        }
    }
}

fn read_response_with_budget(
    io: &mut impl Read,
    wire: &mut Vec<u8>,
    budget: ExchangeBudget,
) -> Result<Response, ProviderError> {
    // Retain the complete actual response before reporting an expired original
    // exchange as unknown. Buffered final bytes and parsing cannot renew it.
    let response = read_response(io, wire)?;
    budget.require_current()?;
    Ok(response)
}

fn read_response(io: &mut impl Read, wire: &mut Vec<u8>) -> Result<Response, ProviderError> {
    read_retained(io, wire, 4)?;
    let length = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ProviderError::Frame("lineage response extent"));
    }
    read_retained(io, wire, length + 4)?;
    let value = canonical::parse_json_with_depth(&wire[4..], MAX_FRAME_BYTES, 64)?;
    serde_json::from_value(value).map_err(|_| ProviderError::Frame("lineage response schema"))
}

fn read_retained(io: &mut impl Read, wire: &mut Vec<u8>, end: usize) -> Result<(), ProviderError> {
    while wire.len() < end {
        let start = wire.len();
        wire.resize(end, 0);
        let result = io.read(&mut wire[start..]);
        match result {
            Ok(0) => {
                wire.truncate(start);
                return Err(ProviderError::Correlation(
                    "lineage native response truncated",
                ));
            }
            Ok(count) => wire.truncate(start + count),
            Err(error) => {
                wire.truncate(start);
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error.into());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
