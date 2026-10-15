//! Retains original startup inputs, wire progress and linear process custody.
//!
//! All inputs enter the same installed holder before Core observes them. All
//! wire banks, reservations and closed Commands precede the first Child. Error
//! and unwind preserve original owners; this path accepts no arbitrary Command.

use super::*;
use crucible::node_adapters::cnp::{
    CnpSemanticLaunchGuard, CnpSemanticLaunchReservation, CnpSemanticProcessSlot,
    PacketCompleteAckPeerBootMaterial, PacketCompleteNativeStartupWire,
};
use crucible_node_contract::ContentRef;
use std::{
    ffi::OsStr,
    io::{self, Write},
    os::{
        fd::OwnedFd,
        unix::{ffi::OsStrExt, net::UnixStream, process::CommandExt},
    },
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const STARTUP_ARGUMENT: &str = "--original-native-startup14";
const PATH_MAXIMUM: usize = 4096;
const MAXIMUM_WRITE_WATCHDOG: Duration = Duration::from_secs(60);

/// Contains actual previously owned inputs for one original native launch.
///
/// The installed holder takes these originals before Core observes them. The
/// process slot reserves cleanup custody; the real installed baseline action
/// remains independently required before any additional allocation or Child.
pub struct PacketCompleteNativeLaunchInputs {
    /// Names the absolute, independently measured original executable.
    pub executable_path: PathBuf,
    /// Retains its exact installed content identity.
    pub executable: ContentRef,
    /// Retains the same installed private directory for this Source.
    pub directory: PathBuf,
    /// Names this directory's original control.sock path.
    pub socket: PathBuf,
    /// Retains the pre-reserved original cleanup slot until reservation.
    pub slot: Option<Box<dyn CnpSemanticProcessSlot>>,
    /// Retains the preowned child-side bootstrap endpoint before Command takes it.
    pub bootstrap_reader: Option<UnixStream>,
    /// Retains the same parent-side endpoint through every partial wire write.
    pub bootstrap_writer: Option<UnixStream>,
    /// Bounds operational writing only; host time never enters model state.
    pub write_watchdog: Duration,
}

pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) struct NativeLaunchOwners
{
    installed: bool,
    admitted: Cell<Option<[usize; 3]>>,
    peers: [NativeLaunchPeer; 3],
}

struct NativeLaunchPeer {
    inputs: Option<PacketCompleteNativeLaunchInputs>,
    wire: Option<PacketCompleteNativeStartupWire>,
    reservation: Option<CnpSemanticLaunchReservation>,
    guard: Option<CnpSemanticLaunchGuard>,
    command: Option<Command>,
    attempted: bool,
    written: bool,
}

impl NativeLaunchOwners {
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn new()
    -> Self {
        Self {
            installed: false,
            admitted: Cell::new(None),
            peers: std::array::from_fn(|_| NativeLaunchPeer {
                inputs: None,
                wire: None,
                reservation: None,
                guard: None,
                command: None,
                attempted: false,
                written: false,
            }),
        }
    }
}

impl PacketCompleteReportStartupHolder {
    /// Retains every original launch input before asking Core to admit startup.
    ///
    /// The separate report startup action completes first. Incoming owners stay
    /// untouched on an occupied/busy refusal. Once moved,
    /// the same holder stays populated even when validation refuses afterward.
    ///
    /// # Errors
    /// Refuses foreign/repeated holders or missing/occupied original slots.
    pub fn retain_original_native_launch_inputs_into(
        original: &Rc<RefCell<Self>>,
        incoming: &mut [Option<PacketCompleteNativeLaunchInputs>; 3],
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        // Report publication's separate one-shot observation has already ended;
        // its earlier owner row must not omit newly installed native inputs.
        if !held.completed.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let mut owners = held
            .native_launches
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if held.native_attempted.get()
            || owners.installed
            || incoming.iter().any(Option::is_none)
            || owners.peers.iter().any(|peer| peer.inputs.is_some())
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        owners.installed = true;
        for (peer, incoming) in owners.peers.iter_mut().zip(incoming) {
            peer.inputs = incoming.take();
        }
        for (member, peer) in owners.peers.iter().enumerate() {
            held.authenticate_native_launch_input_data(
                member,
                peer.inputs.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            )?;
        }
        Ok(())
    }

    fn authenticate_native_launch_input_data(
        &self,
        member: usize,
        inputs: &PacketCompleteNativeLaunchInputs,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        for path in [&inputs.executable_path, &inputs.socket] {
            let bytes = path.as_os_str().as_bytes();
            if !path.is_absolute()
                || bytes.is_empty()
                || bytes.len() > PATH_MAXIMUM
                || bytes.contains(&0)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        if inputs.executable_path != self.authority.graph_policy.measurements()[member].peer.path
            || inputs.directory != self.authority.directories[member]
            || inputs.socket.parent() != Some(inputs.directory.as_path())
            || inputs.socket.file_name() != Some(OsStr::new("control.sock"))
            || inputs.write_watchdog.is_zero()
            || inputs.write_watchdog > MAXIMUM_WRITE_WATCHDOG
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut artifacts = self.authority.roster.sources[member]
            .installation()
            .provider
            .implementation
            .artifacts
            .iter()
            .filter(|artifact| artifact.role.as_str() == "executable");
        if artifacts
            .next()
            .is_none_or(|artifact| artifact.content != inputs.executable)
            || artifacts.next().is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn native_launch_requested_storage_data(&self) -> Result<[usize; 3], RuntimeError> {
        self.authenticate_native_origin_data()?;
        let owners = self
            .native_launches
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.installed {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let maximum = usize::try_from(self.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let mut rows = [0; 3];
        for (member, peer) in owners.peers.iter().enumerate() {
            let inputs = peer.inputs.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            self.authenticate_native_launch_input_data(member, inputs)?;
            if peer.attempted
                || peer.reservation.is_some()
                || peer.guard.is_some()
                || peer.command.is_some()
                || peer.wire.is_some()
                || inputs.bootstrap_reader.is_none()
                || inputs.bootstrap_writer.is_none()
            {
                return Err(RuntimeError::UnsupportedFacet);
            }
            let reservation =
                CnpSemanticLaunchReservation::quote_unlaunched_retained_storage_precredit_data(
                    &inputs.directory,
                    &inputs.executable,
                    inputs
                        .slot
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?
                        .as_ref(),
                    maximum,
                )?;
            let (retained, transient, scratch) = CnpSemanticLaunchReservation::quote_original_native_startup_acquisition_storage_data(&inputs.executable, maximum)?;
            let currentness = self
                .authority
                .graph_policy
                .original_native_launch_currentness_storage_data(member)?;
            let command = closed_command_requested_storage_data(inputs)?;
            rows[member] = reservation
                .checked_add(retained)
                .and_then(|bytes| bytes.checked_add(transient))
                .and_then(|bytes| bytes.checked_add(scratch))
                .and_then(|bytes| bytes.checked_add(currentness))
                .and_then(|bytes| bytes.checked_add(command))
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(rows)
    }

    pub(super) fn retain_native_launch_admitted_data(
        &self,
        rows: [usize; 3],
    ) -> Result<(), RuntimeError> {
        let owners = self
            .native_launches
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if owners.admitted.get().is_some() || rows.contains(&0) {
            return Err(RuntimeError::DuplicateOperation);
        }
        owners.admitted.set(Some(rows));
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn charge_native_launch_storage_precredit_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        let owners = self
            .native_launches
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for peer in &owners.peers {
            let Some(inputs) = &peer.inputs else {
                continue;
            };
            for path in [&inputs.directory, &inputs.executable_path, &inputs.socket] {
                counter
                    .charge(path)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            counter
                .charge(&inputs.executable)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            if let Some(slot) = &inputs.slot {
                counter
                    .add(std::mem::size_of_val(slot.as_ref()))
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                counter
                    .add(
                        slot.retained_requested_storage_precredit_data(counter.remaining())?
                            .ok_or(RuntimeError::UnsupportedFacet)?,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            if let Some(wire) = &peer.wire {
                counter
                    .add(wire.retained_requested_storage_precredit_data(counter.remaining())?)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            if let Some(reservation) = &peer.reservation {
                counter
                    .add(
                        reservation
                            .unlaunched_retained_requested_storage_precredit_data(
                                counter.remaining(),
                            )?
                            .complete_requested_bytes_precredit_data()?,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            if peer.command.is_some() {
                counter
                    .add(closed_command_requested_storage_data(inputs)?)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            // Unknown live custody is never replaced by zero. A later HOST
            // SDK construction action needs its own genuine producer/owner join.
            if peer.guard.is_some() {
                return Err(RuntimeError::UnsupportedFacet);
            }
        }
        Ok(())
    }

    /// Finalizes startup, then prepares and launches the three actual originals.
    ///
    /// Every wire, process reservation and closed Command precedes the first
    /// Child. The same reservation receives the Child before authentication;
    /// failed guard transfer restores that reservation in its fixed slot.
    /// Error and unwind keep all original owners and partial write cursors.
    /// This is not HOST SDK construction or completed once-Admit; the separate
    /// prospective HOST connection producer remains unavailable.
    ///
    /// # Errors
    /// Refuses missing inputs/admission, a changed owner/capacity, unsupported
    /// acquisition, process failure or interrupted original wire publication.
    pub fn launch_original_native_startup(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        Self::finalize_original_native_startup(original)?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        let mut owners = held
            .native_launches
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let bounds = owners
            .admitted
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let mut materials: [Option<PacketCompleteAckPeerBootMaterial<'_>>; 3] = [None, None, None];
        for (member, peer) in owners.peers.iter_mut().enumerate() {
            let inputs = peer.inputs.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
            let source = &held.authority.roster.sources[member];
            materials[member] = Some(
                source
                    .begin_original_canonical_ack_private_boot()
                    .map_err(|_| RuntimeError::ForeignAuthority)?,
            );
            materials[member]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .prepare_original_native_startup_wire_into(
                    &held.authority.original_launches[member],
                    &held.authority.private_launches[member],
                    &mut peer.wire,
                )
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            materials[member]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .reserve_original_native_startup_launch_into(
                    &inputs.directory,
                    &inputs.executable,
                    &mut inputs.slot,
                    &mut peer.reservation,
                )
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            let observed = peer
                .reservation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .unlaunched_retained_requested_storage_precredit_data(bounds[member])?
                .complete_requested_bytes_precredit_data()?;
            if observed
                .checked_add(closed_command_requested_storage_data(inputs)?)
                .is_none_or(|bytes| bytes > bounds[member])
            {
                return Err(RuntimeError::ResourceLimit);
            }
            peer.command = Some(Command::new(&inputs.executable_path));
            let command = peer
                .command
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            command
                .env_clear()
                .arg(&inputs.socket)
                .arg(STARTUP_ARGUMENT)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0);
            let reader = inputs
                .bootstrap_reader
                .take()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            command.stdin(Stdio::from(OwnedFd::from(reader)));
        }
        for (member, peer) in owners.peers.iter_mut().enumerate() {
            if peer.attempted {
                return Err(RuntimeError::DuplicateOperation);
            }
            peer.attempted = true;
            let NativeLaunchPeer {
                reservation,
                command,
                guard,
                wire,
                inputs,
                written,
                ..
            } = peer;
            held.authority
                .graph_policy
                .authenticate_original_native_launch_currentness(member, bounds[member])?;
            reservation
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .launch(command.as_mut().ok_or(RuntimeError::OwnerUnavailable)?)
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            let original_reservation = reservation.take().ok_or(RuntimeError::OwnerUnavailable)?;
            match original_reservation.into_guard() {
                Ok(original_guard) => *guard = Some(original_guard),
                Err(failure) => {
                    *reservation = Some(failure.original);
                    return Err(RuntimeError::OwnerUnavailable);
                }
            }
            let inputs = inputs.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
            let deadline = Instant::now()
                .checked_add(inputs.write_watchdog)
                .ok_or(RuntimeError::ResourceLimit)?;
            let mut writer = NativeDeadlineWriter {
                stream: inputs
                    .bootstrap_writer
                    .as_mut()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                deadline,
            };
            wire.as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .write_original(
                    materials[member]
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    &mut writer,
                )
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            *written = true;
        }
        held.authenticate_native_origin_data()
    }
}

// Pinned AOS Rust's Unix Command creates two program CStrings, one socket and
// one flag CString. Its argv table grows two -> four pointers. env_clear yields
// one null envp pointer at spawn. Count old+new argv tables conservatively;
// this is a source-derived constructor request, not a getter-length inference.
fn closed_command_requested_storage_data(
    inputs: &PacketCompleteNativeLaunchInputs,
) -> Result<usize, RuntimeError> {
    if !cfg!(all(target_os = "linux", target_pointer_width = "64")) {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let program = inputs
        .executable_path
        .as_os_str()
        .as_bytes()
        .len()
        .checked_add(1)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(RuntimeError::ResourceLimit)?;
    let socket = inputs
        .socket
        .as_os_str()
        .as_bytes()
        .len()
        .checked_add(1)
        .ok_or(RuntimeError::ResourceLimit)?;
    let flag = STARTUP_ARGUMENT
        .len()
        .checked_add(1)
        .ok_or(RuntimeError::ResourceLimit)?;
    let pointers = std::mem::size_of::<*const std::ffi::c_char>()
        .checked_mul(7)
        .ok_or(RuntimeError::ResourceLimit)?;
    program
        .checked_add(socket)
        .and_then(|bytes| bytes.checked_add(flag))
        .and_then(|bytes| bytes.checked_add(pointers))
        .ok_or(RuntimeError::ResourceLimit)
}

pub(super) struct NativeDeadlineWriter<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl Write for NativeDeadlineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
