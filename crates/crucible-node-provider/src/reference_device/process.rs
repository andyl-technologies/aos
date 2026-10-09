//! Native child ownership, total request deadlines and retained device receipts.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::{
    fs::DirBuilderExt,
    net::{UnixListener, UnixStream},
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crucible_node_contract::{Id, U64};

use crate::{
    ProviderError,
    transport::{FrameReader, write_frame},
};

use super::protocol::{
    DEVICE_FRAME_BYTES, DeviceGrant, DeviceOutput, DeviceReceipt, MAX_INPUT_BYTES, Request,
    Response,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
const MAX_RETAINED_WINDOWS: usize = 65_536;

/// Distinguishes native preparation, output custody and contained resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceStatus {
    /// The child is waiting for an immutable input batch.
    Parked,
    /// Input is staged, with no checksum transition executed yet.
    Staged,
    /// Activated batch work completed, but window closure is unacknowledged.
    Active,
    /// The child acknowledged park and outputs await publication acknowledgment.
    ClosedPending,
    /// The stream is disconnected and physical child reclamation is pending.
    Quarantined,
    /// The disconnected child has been reaped.
    Reaped,
}

pub(super) struct Window {
    pub(super) grant: DeviceGrant,
    pub(super) input: Vec<u8>,
    pub(super) output: Option<DeviceOutput>,
    pub(super) measured: Duration,
    pub(super) receipt: Option<DeviceReceipt>,
}

/// Owns one actual controlled device and its unpublished output obligations.
///
/// The executable must be the admitted source-built reference device. This
/// driver does not authenticate an arbitrary executable or accept world grants
/// on its own: the enclosing provider supplies that authorization. Completed
/// windows remain fenced against identity reuse for this finite incarnation.
pub struct ReferenceDevice {
    child: Option<Child>,
    pid: u32,
    supervision_id: U64,
    stream: Option<UnixStream>,
    directory: PathBuf,
    owner: Id,
    incarnation: Id,
    generation: U64,
    control_timeout: Duration,
    status: DeviceStatus,
    next_quantum: U64,
    used_windows: BTreeSet<Id>,
    window: Option<Window>,
    last_acknowledged: Option<DeviceGrant>,
}

impl ReferenceDevice {
    /// Spawns the admitted binary and establishes its private stopped command loop.
    ///
    /// `socket_parent` must be an existing operational directory. The driver
    /// creates a mode-0700 child directory and verifies the connected device's
    /// process ID and realization identity before returning ownership.
    ///
    /// # Errors
    /// Rejects relative executables, zero generation/deadline, unavailable
    /// resources, process failure, timed-out connection or mismatched readiness.
    pub fn spawn(
        executable: &Path,
        socket_parent: &Path,
        owner: Id,
        incarnation: Id,
        generation: U64,
        control_timeout: Duration,
    ) -> Result<Self, ProviderError> {
        if !executable.is_absolute() || generation.get() == 0 || control_timeout.is_zero() {
            return Err(ProviderError::Correlation(
                "invalid reference-device launch",
            ));
        }
        let supervision_id =
            super::supervision::reserve(owner.clone(), incarnation.clone(), generation)?;
        let sequence =
            match NEXT_DIRECTORY.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            }) {
                Ok(sequence) => sequence,
                Err(_) => {
                    super::supervision::release_reservation(supervision_id);
                    return Err(ProviderError::ResourceExhausted(
                        "device directory sequence",
                    ));
                }
            };
        let directory =
            socket_parent.join(format!("crucible-device-{}-{sequence}", std::process::id()));
        if let Err(error) = fs::DirBuilder::new().mode(0o700).create(&directory) {
            super::supervision::release_reservation(supervision_id);
            return Err(error.into());
        }
        let socket_path = directory.join("control.sock");
        let launch = (|| {
            let listener = UnixListener::bind(&socket_path)?;
            listener.set_nonblocking(true)?;
            let child = Command::new(executable)
                .arg(&socket_path)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            Ok::<_, ProviderError>((listener, child))
        })();
        let (listener, mut child) = match launch {
            Ok(launched) => launched,
            Err(error) => {
                let _ = fs::remove_file(&socket_path);
                let _ = fs::remove_dir(&directory);
                super::supervision::release_reservation(supervision_id);
                return Err(error);
            }
        };
        let connection = connect_child(&listener, &mut child, control_timeout);
        let stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                super::supervision::retain(supervision_id, child, directory, None);
                return Err(error);
            }
        };
        let pid = child.id();
        let mut device = Self {
            child: Some(child),
            pid,
            supervision_id,
            stream: Some(stream),
            directory,
            owner: owner.clone(),
            incarnation: incarnation.clone(),
            generation,
            control_timeout,
            status: DeviceStatus::Parked,
            next_quantum: U64::new(0),
            used_windows: BTreeSet::new(),
            window: None,
            last_acknowledged: None,
        };
        let ready = device.request(
            &Request::Initialize {
                owner: owner.clone(),
                incarnation: incarnation.clone(),
                generation,
            },
            control_timeout,
        )?;
        if !matches!(ready, Response::Ready { owner: actual_owner, incarnation: actual_incarnation, generation: actual_generation, child_pid }
            if actual_owner == owner && actual_incarnation == incarnation && actual_generation == generation && child_pid.get() == u64::from(device.pid))
        {
            let _ = device.quarantine();
            return Err(ProviderError::Correlation(
                "reference-device readiness mismatch",
            ));
        }
        Ok(device)
    }

    /// Returns the native lifecycle and output-custody state.
    pub const fn status(&self) -> DeviceStatus {
        self.status
    }

    /// Returns the operating system process ID for diagnostics and custody checks.
    pub fn child_pid(&self) -> u32 {
        self.pid
    }

    /// Returns the native execution owner authenticated during child readiness.
    pub fn owner_id(&self) -> &Id {
        &self.owner
    }

    /// Returns the child incarnation authenticated on the private control stream.
    pub fn incarnation_id(&self) -> &Id {
        &self.incarnation
    }

    /// Returns the realized native owner generation.
    pub const fn generation(&self) -> U64 {
        self.generation
    }

    /// Stages a complete authorized input batch without applying device effects.
    ///
    /// # Errors
    /// Refuses a stale owner, changed duplicate, occupied window, reused identity,
    /// nonconsecutive quantum, excessive input, retention exhaustion or failed ACK.
    pub fn stage(&mut self, grant: DeviceGrant, input: &[u8]) -> Result<(), ProviderError> {
        grant.validate()?;
        self.ensure_connected()?;
        if let Some(current) = &self.window {
            if current.grant == grant && current.input == input {
                return Ok(());
            }
            return Err(ProviderError::Conflict(
                "reference device already holds a different input cut",
            ));
        }
        if input.len() > MAX_INPUT_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "reference device input allowance",
            ));
        }
        if self.used_windows.len() >= MAX_RETAINED_WINDOWS {
            return Err(ProviderError::ResourceExhausted(
                "reference device window tombstones",
            ));
        }
        if grant.owner_id != self.owner
            || grant.incarnation_id != self.incarnation
            || grant.generation != self.generation
            || grant.quantum != self.next_quantum
            || self.used_windows.contains(&grant.window_id)
        {
            return Err(ProviderError::Conflict(
                "reference device grant scope or window mismatch",
            ));
        }
        // Retain original material before the first potentially uncertain send.
        self.window = Some(Window {
            grant: grant.clone(),
            input: input.to_vec(),
            output: None,
            measured: Duration::ZERO,
            receipt: None,
        });
        let response = self.request(
            &Request::Stage {
                grant: grant.clone(),
                input: input.to_vec(),
            },
            self.control_timeout,
        )?;
        if !matches!(response, Response::Staged { grant: actual } if actual == grant) {
            return self.reject_response("reference device staging acknowledgment mismatch");
        }
        self.used_windows.insert(grant.window_id);
        self.status = DeviceStatus::Staged;
        Ok(())
    }

    /// Activates exactly the retained batch under its total elapsed host budget.
    ///
    /// Repeating the original activation does not rerun checksum transitions.
    /// Output remains private until an authenticated close response is retained.
    ///
    /// # Errors
    /// Refuses changed identity, unstaged input, closed/quarantined execution,
    /// budget expiry, uncertain child execution or mismatched completion evidence.
    pub fn activate(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.ensure_connected()?;
        let current = self.matching_window(grant)?;
        if self.status == DeviceStatus::Active {
            return Ok(());
        }
        if self.status != DeviceStatus::Staged || current.output.is_some() {
            return Err(ProviderError::Correlation(
                "reference device window cannot activate",
            ));
        }
        let started = operational_now();
        let response = self.request(
            &Request::Activate {
                window: grant.window_id.clone(),
            },
            Duration::from_nanos(grant.host_budget_ns.get()),
        )?;
        let measured = operational_now().duration_since(started);
        let output = match response {
            Response::Completed { window, output }
                if window == grant.window_id
                    && output.bytes_processed.get()
                        == self.matching_window(grant)?.input.len() as u64 =>
            {
                output
            }
            _ => return self.reject_response("reference device completion mismatch"),
        };
        if measured > Duration::from_nanos(grant.host_budget_ns.get()) {
            return self.reject_response("reference device exceeded operational budget");
        }
        let current = self.window.as_mut().ok_or(ProviderError::Correlation(
            "reference device window disappeared",
        ))?;
        current.output = Some(output);
        current.measured = measured;
        self.status = DeviceStatus::Active;
        Ok(())
    }

    /// Obtains actual application-park acknowledgment and retains the full output.
    ///
    /// The receipt's publication coordinate is the original fixed boundary;
    /// this operation does not authorize the coordinator to publish it yet.
    ///
    /// # Errors
    /// Refuses mismatched identity, unactivated windows, uncertain closure or a
    /// child response that disagrees with the retained output or park state.
    pub fn close(&mut self, grant: &DeviceGrant) -> Result<DeviceReceipt, ProviderError> {
        self.ensure_connected()?;
        let current = self.matching_window(grant)?;
        if let Some(receipt) = &current.receipt {
            return Ok(receipt.clone());
        }
        if self.status != DeviceStatus::Active {
            return Err(ProviderError::Correlation(
                "reference device window is not active",
            ));
        }
        let response = self.request(
            &Request::Close {
                window: grant.window_id.clone(),
            },
            self.control_timeout,
        )?;
        let current = self.matching_window(grant)?;
        let output = match response {
            Response::Closed {
                grant: actual,
                output,
                application_parked: true,
            } if actual == *grant && current.output.as_ref() == Some(&output) => output,
            _ => return self.reject_response("reference device close receipt mismatch"),
        };
        let measured_host_ns = u64::try_from(current.measured.as_nanos())
            .map_err(|_| ProviderError::ResourceExhausted("device duration representation"))?;
        let receipt = DeviceReceipt {
            grant: grant.clone(),
            output,
            measured_host_ns: U64::new(measured_host_ns),
            application_parked: true,
        };
        self.window
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "reference device window disappeared",
            ))?
            .receipt = Some(receipt.clone());
        self.status = DeviceStatus::ClosedPending;
        Ok(receipt)
    }

    /// Authenticates a receipt against this driver's retained native evidence.
    ///
    /// # Errors
    /// Refuses a fabricated, changed, retired or quarantined receipt. Equality
    /// of serialized fields alone cannot authorize world publication.
    pub fn validate_receipt(&self, receipt: &DeviceReceipt) -> Result<(), ProviderError> {
        self.ensure_connected()?;
        let current = self.matching_window(&receipt.grant)?;
        if self.status != DeviceStatus::ClosedPending || current.receipt.as_ref() != Some(receipt) {
            return Err(ProviderError::Correlation(
                "device receipt lacks retained native custody",
            ));
        }
        Ok(())
    }

    /// Releases original output custody after the host acknowledges publication.
    ///
    /// The enclosing provider must first validate world boundary settlement.
    /// Repeating the most recent identical acknowledgment is idempotent.
    ///
    /// # Errors
    /// Refuses premature release, changed identity, sequence overflow or uncertain
    /// acknowledgment. Failure retains the original window and output obligations.
    pub fn acknowledge_publication(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.ensure_connected()?;
        if self.last_acknowledged.as_ref() == Some(grant) {
            return Ok(());
        }
        self.matching_window(grant)?;
        if self.status != DeviceStatus::ClosedPending {
            return Err(ProviderError::Correlation(
                "device publication precedes acknowledged close",
            ));
        }
        let next_quantum = self.next_quantum.checked_add(U64::new(1))?;
        let response = self.request(
            &Request::Acknowledge {
                window: grant.window_id.clone(),
            },
            self.control_timeout,
        )?;
        if !matches!(response, Response::Acknowledged { window } if window == grant.window_id) {
            return self.reject_response("reference device publication acknowledgment mismatch");
        }
        self.window = None;
        self.last_acknowledged = Some(grant.clone());
        self.next_quantum = next_quantum;
        self.status = DeviceStatus::Parked;
        Ok(())
    }

    /// Disconnects effect paths, requests process death and polls for actual reaping.
    ///
    /// Unpublished data remains retained even after physical reclamation.
    /// A false result means ownership remains quarantined and must be polled again.
    ///
    /// # Errors
    /// Returns an error when termination or process-status inspection fails;
    /// disconnection and the quarantined state still remain in force.
    pub fn quarantine(&mut self) -> Result<bool, ProviderError> {
        if self.status == DeviceStatus::Reaped {
            return Ok(true);
        }
        self.status = DeviceStatus::Quarantined;
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if self.child_mut()?.try_wait()?.is_some() {
            self.status = DeviceStatus::Reaped;
            return Ok(true);
        }
        self.child_mut()?.kill()?;
        let deadline = deadline(self.control_timeout)?;
        loop {
            if self.child_mut()?.try_wait()?.is_some() {
                self.status = DeviceStatus::Reaped;
                return Ok(true);
            }
            if operational_now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Identifies this incarnation's reserved native-supervision capsule.
    pub const fn supervision_id(&self) -> U64 {
        self.supervision_id
    }

    /// Discharges retained input/output after host-authorized attempt containment.
    ///
    /// # Errors
    /// Refuses discharge until actual child reaping has been acknowledged. The
    /// host must first resolve all pending publication and external obligations.
    pub fn acknowledge_containment(&mut self) -> Result<(), ProviderError> {
        if self.status != DeviceStatus::Reaped {
            return Err(ProviderError::Correlation(
                "device containment not physically complete",
            ));
        }
        self.window = None;
        Ok(())
    }

    fn child_mut(&mut self) -> Result<&mut Child, ProviderError> {
        self.child.as_mut().ok_or(ProviderError::Correlation(
            "device child transferred to supervisor",
        ))
    }

    fn ensure_connected(&self) -> Result<(), ProviderError> {
        if matches!(
            self.status,
            DeviceStatus::Quarantined | DeviceStatus::Reaped
        ) {
            return Err(ProviderError::Correlation("reference device is contained"));
        }
        Ok(())
    }

    fn matching_window(&self, grant: &DeviceGrant) -> Result<&Window, ProviderError> {
        let current = self
            .window
            .as_ref()
            .ok_or(ProviderError::Correlation("no retained device window"))?;
        if &current.grant != grant {
            return Err(ProviderError::Conflict(
                "device operation changed original grant",
            ));
        }
        Ok(current)
    }

    fn reject_response<T>(&mut self, reason: &'static str) -> Result<T, ProviderError> {
        let _ = self.quarantine();
        Err(ProviderError::Correlation(reason))
    }

    fn request(&mut self, request: &Request, timeout: Duration) -> Result<Response, ProviderError> {
        let result = (|| {
            let stream = self.stream.as_mut().ok_or(ProviderError::Correlation(
                "reference device stream disconnected",
            ))?;
            let mut io = DeadlineIo {
                stream,
                deadline: deadline(timeout)?,
            };
            let value = serde_json::to_value(request)
                .map_err(|_| ProviderError::Frame("device request encoding failed"))?;
            write_frame(&mut io, &value, DEVICE_FRAME_BYTES)?;
            let response = FrameReader::new(&mut io, DEVICE_FRAME_BYTES)?
                .read()?
                .ok_or(ProviderError::Correlation(
                    "reference device disconnected without acknowledgment",
                ))?;
            serde_json::from_value(response)
                .map_err(|_| ProviderError::Frame("invalid reference device response"))
        })();
        if result.is_err() {
            let _ = self.quarantine();
        }
        result
    }
}

impl Drop for ReferenceDevice {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        // The slot was reserved before spawn; transfer cannot fail on capacity.
        if let Some(child) = self.child.take() {
            super::supervision::retain(
                self.supervision_id,
                child,
                std::mem::take(&mut self.directory),
                self.window.take(),
            );
        }
    }
}

fn connect_child(
    listener: &UnixListener,
    child: &mut Child,
    timeout: Duration,
) -> Result<UnixStream, ProviderError> {
    let deadline = deadline(timeout)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let credentials =
                    rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
                let peer_pid =
                    u32::try_from(credentials.pid.as_raw_nonzero().get()).map_err(|_| {
                        ProviderError::Correlation("reference device peer PID outside native range")
                    })?;
                if peer_pid != child.id() {
                    return Err(ProviderError::Correlation(
                        "reference device OS peer identity mismatch",
                    ));
                }
                return Ok(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        if child.try_wait()?.is_some() {
            return Err(ProviderError::Correlation(
                "reference child exited before connection",
            ));
        }
        if operational_now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "reference child connection timed out",
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn deadline(duration: Duration) -> Result<Instant, ProviderError> {
    operational_now()
        .checked_add(duration)
        .ok_or(ProviderError::ResourceExhausted(
            "device deadline representation",
        ))
}

struct DeadlineIo<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl DeadlineIo<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(operational_now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "reference device total request budget exhausted",
                )
            })
    }
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// crucible-lint: allow clippy-disallowed-method -- Quantized host budgets use operational time, never modeled publication time
// crucible-lint: allow rust-allow -- Quantized host budgets use operational time, never modeled publication time
#[allow(
    clippy::disallowed_methods,
    reason = "Quantized host budgets use operational time, never modeled publication time"
)]
fn operational_now() -> Instant {
    Instant::now()
}
