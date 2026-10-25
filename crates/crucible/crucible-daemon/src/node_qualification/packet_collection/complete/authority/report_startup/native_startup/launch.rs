//! Retains original startup inputs, wire progress and linear process custody.
//!
//! All inputs enter the same installed holder before Core observes them. All
//! wire banks, reservations and closed Commands precede the first Child. Error
//! and unwind preserve original owners; this path accepts no arbitrary Command.

use super::*;
use crate::supervision::ProcessDeadline;
use crucible_engine::node_adapters::cnp::{
    CnpSemanticLaunchGuard, CnpSemanticLaunchReservation, CnpSemanticProcessSlot,
    PacketCompleteAckPeerBootMaterial, PacketCompleteNativeRestoredSuffixStartupWire,
    PacketCompleteNativeStartupWire,
};
use crucible_node_format::ContentRef;
use std::{
    ffi::OsStr,
    io::{self, Write},
    os::{
        fd::OwnedFd,
        unix::{ffi::OsStrExt, net::UnixStream, process::CommandExt},
    },
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

const STARTUP_ARGUMENT: &str = "--original-native-startup14";
// Same compiled argument extent preserves the old closed Command quote.
const INVOCATION_ARGUMENT: &str = "--original-native-startup15";
const RESTORED_SUFFIX_ARGUMENT: &str = "--original-native-startup16";
const _: () = assert!(STARTUP_ARGUMENT.len() == INVOCATION_ARGUMENT.len());
const _: () = assert!(STARTUP_ARGUMENT.len() == RESTORED_SUFFIX_ARGUMENT.len());
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
    suffix_wire: Option<PacketCompleteNativeRestoredSuffixStartupWire>,
    reservation: Option<CnpSemanticLaunchReservation>,
    guard: Option<CnpSemanticLaunchGuard>,
    command: Option<Command>,
    command_stdin_owned: bool,
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
                suffix_wire: None,
                reservation: None,
                guard: None,
                command: None,
                command_stdin_owned: false,
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
        held.stage_original_native_launch_inputs_data(incoming)
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn stage_original_native_launch_inputs_data(
        &self,
        incoming: &mut [Option<PacketCompleteNativeLaunchInputs>; 3],
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        let mut owners = self
            .native_launches
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if self.native_attempted.get()
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
            self.authenticate_native_launch_input_data(
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
                || peer.suffix_wire.is_some()
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
        self.charge_original_launch_storage_data(counter, false)
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn charge_original_live_launch_storage_precredit_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        self.charge_original_launch_storage_data(counter, true)
    }

    fn charge_original_launch_storage_data(
        &self,
        counter: &mut Counter,
        live_scene: bool,
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
            Self::charge_original_native_launch_input_storage_data(inputs, counter)?;
            if peer.wire.is_some() && peer.suffix_wire.is_some() {
                return Err(RuntimeError::ForeignAuthority);
            }
            if let Some(wire) = &peer.wire {
                counter
                    .add(wire.retained_requested_storage_precredit_data(counter.remaining())?)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            if let Some(wire) = &peer.suffix_wire {
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
            // The selected live scene requires the genuine typed guard row.
            // Other callers still refuse live or partial custody as unknown.
            if let Some(guard) = &peer.guard {
                if !live_scene {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                // These guards have not entered the opaque SDK continuation.
                // Attached/partial protocol custody moves into that retained
                // owner and is counted there with its actual known witnesses.
                counter
                    .add(
                        guard.original_initial_lifecycle_retained_storage_precredit_data(
                            None,
                            None,
                            counter.remaining(),
                        )?,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
        }
        Ok(())
    }

    /// Charges actual retained launch paths, full content identity and concrete slot backing.
    ///
    /// # Errors
    /// Refuses unknown slot ownership or exhausted requested byte credit.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn charge_original_native_launch_input_storage_data(
        inputs: &PacketCompleteNativeLaunchInputs,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
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
        Ok(())
    }

    /// Finalizes startup, then prepares and launches the three actual originals.
    ///
    /// Every wire, process reservation and closed Command precedes the first
    /// Child. The same reservation receives the Child before authentication;
    /// failed guard transfer restores that reservation in its fixed slot.
    /// Error and unwind keep all original owners and partial write cursors.
    /// The distinct installed HOST SDK action constructs its original owners
    /// after native finalization and before boot-material or Child loans.
    /// Initial protocol methods and completed once-Admit remain separate.
    ///
    /// # Errors
    /// Refuses missing inputs/admission, a changed owner/capacity, unsupported
    /// acquisition, process failure or interrupted original wire publication.
    pub fn launch_original_native_startup(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        Self::launch_original_native_startup_with_member(original, None)
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn launch_original_native_startup_with_initial_lifecycle(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        Self::launch_original_native_startup_with_member(
            original,
            Some(Self::complete_retained_host_initial_lifecycle_member),
        )
    }

    fn launch_original_native_startup_with_member(
        original: &Rc<RefCell<Self>>,
        initial: Option<fn(&Rc<RefCell<Self>>, usize) -> Result<(), RuntimeError>>,
    ) -> Result<(), RuntimeError> {
        #[cfg(test)]
        eprintln!("native control: native startup finalization begin");
        Self::finalize_original_native_startup(original)?;
        #[cfg(test)]
        eprintln!("native control: native startup finalization end; host SDK construction begin");
        Self::prepare_original_native_host_sdk(original)?;
        #[cfg(test)]
        eprintln!("native control: host SDK construction end");
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
        // This same-holder declaration routes only to a constructor that
        // independently requires the consumed Core suffix member. It grants
        // no native action and cannot make an old member use the new family.
        let restored_suffix = held.restored_suffix_startup_selected_data()?;
        let mut materials: [Option<PacketCompleteAckPeerBootMaterial<'_>>; 3] = [None, None, None];
        for (member, peer) in owners.peers.iter_mut().enumerate() {
            #[cfg(test)]
            eprintln!("native control: native member {member} bootstrap construction begin");
            let inputs = peer.inputs.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
            let source = &held.authority.roster.sources[member];
            materials[member] = Some(
                source
                    .begin_original_canonical_ack_private_boot()
                    .map_err(|_| RuntimeError::ForeignAuthority)?,
            );
            let material = materials[member]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let invocation = material
                .requires_original_native_invocation_wire_data()
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            if restored_suffix {
                material.prepare_original_restored_suffix_wire_into(
                    &held.authority.original_launches[member],
                    &held.authority.private_launches[member],
                    &mut peer.suffix_wire,
                )
            } else if invocation {
                material.prepare_original_native_invocation_wire_into(
                    &held.authority.original_launches[member],
                    &held.authority.private_launches[member],
                    &mut peer.wire,
                )
            } else {
                material.prepare_original_native_startup_wire_into(
                    &held.authority.original_launches[member],
                    &held.authority.private_launches[member],
                    &mut peer.wire,
                )
            }
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
            #[cfg(test)]
            eprintln!("native control: native member {member} wire prepared; reservation begin");
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
            #[cfg(test)]
            eprintln!("native control: native member {member} reservation prepared");
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
                .arg(if restored_suffix {
                    RESTORED_SUFFIX_ARGUMENT
                } else if invocation {
                    INVOCATION_ARGUMENT
                } else {
                    STARTUP_ARGUMENT
                })
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0);
            let reader = inputs
                .bootstrap_reader
                .take()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            command.stdin(Stdio::from(OwnedFd::from(reader)));
            // Command retains the original stdin fd after spawn as well. This
            // assignment immediately follows its nonfallible ownership move.
            peer.command_stdin_owned = true;
        }
        drop(owners);
        for member in 0..3 {
            #[cfg(test)]
            eprintln!("native control: native member {member} launch begin");
            {
                let mut owners = held
                    .native_launches
                    .try_borrow_mut()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let peer = owners
                    .peers
                    .get_mut(member)
                    .ok_or(RuntimeError::ForeignAuthority)?;
                if peer.attempted {
                    return Err(RuntimeError::DuplicateOperation);
                }
                peer.attempted = true;
                let NativeLaunchPeer {
                    reservation,
                    command,
                    guard,
                    wire,
                    suffix_wire,
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
                    .map_err(|error| {
                        #[cfg(test)]
                        eprintln!(
                            "native control: native member {member} launch refused: {error:?}"
                        );
                        let _ = error;
                        RuntimeError::OwnerUnavailable
                    })?;
                let original_reservation =
                    reservation.take().ok_or(RuntimeError::OwnerUnavailable)?;
                match original_reservation.into_guard() {
                    Ok(original_guard) => *guard = Some(original_guard),
                    Err(failure) => {
                        #[cfg(test)]
                        eprintln!(
                            "native control: native member {member} guard transfer refused: {:?}",
                            failure.error
                        );
                        *reservation = Some(failure.original);
                        return Err(RuntimeError::OwnerUnavailable);
                    }
                }
                let inputs = inputs.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
                let deadline = ProcessDeadline::after(inputs.write_watchdog)
                    .ok_or(RuntimeError::ResourceLimit)?;
                let mut writer = NativeDeadlineWriter {
                    stream: inputs
                        .bootstrap_writer
                        .as_mut()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    deadline,
                };
                let material = materials[member]
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                match (wire.as_mut(), suffix_wire.as_mut()) {
                    (Some(wire), None) if !restored_suffix => {
                        wire.write_original(material, &mut writer)
                    }
                    (None, Some(wire)) if restored_suffix => {
                        wire.write_original(material, &mut writer)
                    }
                    _ => return Err(RuntimeError::ForeignAuthority),
                }
                .map_err(|error| {
                    #[cfg(test)]
                    eprintln!(
                        "native control: native member {member} wire publication refused: {error:?}"
                    );
                    let _ = error;
                    RuntimeError::OwnerUnavailable
                })?;
                *written = true;
                #[cfg(test)]
                eprintln!("native control: native member {member} wire published");
            }
            // No native launch-bank loan crosses the initial lifecycle. The
            // next child has not started its birth deadline while this member
            // completes Hello and preparation under its own admitted window.
            drop(materials[member].take());
            if let Some(complete) = initial {
                complete(original, member)?;
                #[cfg(test)]
                eprintln!("native control: native member {member} initial lifecycle completed");
            }
        }
        held.authenticate_native_origin_data()
    }
}

impl PacketCompleteReportStartupHolder {
    /// Retains and connects an existing original control stream after wire delivery.
    ///
    /// Socket acquisition is a separately admitted caller input. This consumer
    /// creates no socket and extracts no controller. The same retained launch
    /// guard, SDK attempt and known supervisor authenticate Hello; uncertainty
    /// keeps the original stream in either this holder or the partial SDK root.
    ///
    /// # Errors
    /// Refuses an incomplete or foreign launch, occupied stream, repeated SDK
    /// connection, unavailable known supervisor or failed original Hello.
    pub fn connect_original_native_host_stream_into(
        original: &Rc<RefCell<Self>>,
        member: usize,
        incoming: &mut Option<UnixStream>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if !held.host_sdk_completed.get() || held.host_sdk_in_flight.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let owners = held
            .native_launches
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let peer = owners
            .peers
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !peer.written {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let guard = peer.guard.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let mut streams = held
            .host_sdk_streams
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let stream = streams
            .get_mut(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if stream.is_some() || incoming.is_none() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let mut outputs = held
            .host_sdk_outputs
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let output = outputs
            .get_mut(member)
            .and_then(Option::as_mut)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempted = held
            .host_sdk_connect_attempted
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if attempted.replace(true) {
            return Err(RuntimeError::DuplicateOperation);
        }
        *stream = incoming.take();
        held.connect_original_host_sdk_peer_data(member, output, guard, stream)
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
    deadline: ProcessDeadline,
}

impl Write for NativeDeadlineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.deadline.remaining();
        if remaining.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl NativeLaunchOwners {
    /// Lends the same written original guard and its retained control path.
    ///
    /// # Errors
    /// Refuses an invalid peer, incomplete launch or absent original owners.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_guard_and_socket_data(
        &self,
        selected: usize,
    ) -> Result<(&CnpSemanticLaunchGuard, &std::path::Path), RuntimeError> {
        let peer = self
            .peers
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !peer.attempted || !peer.written {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok((
            peer.guard.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            peer.inputs
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .socket
                .as_path(),
        ))
    }
}

impl NativeLaunchOwners {
    /// Lends the retained control path after its original guard moves into preparation.
    ///
    /// # Errors
    /// Refuses an invalid peer, incomplete launch or absent original inputs.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_socket_data(
        &self,
        selected: usize,
    ) -> Result<&std::path::Path, RuntimeError> {
        let peer = self
            .peers
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !peer.attempted || !peer.written {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(peer
            .inputs
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .socket
            .as_path())
    }

    /// Lends the actual guard output slot to the closed Source lifecycle consumer.
    ///
    /// # Errors
    /// Refuses an invalid peer, incomplete launch or already transferred guard.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_guard_slot_for_initial_lifecycle(
        &mut self,
        selected: usize,
    ) -> Result<&mut Option<CnpSemanticLaunchGuard>, RuntimeError> {
        let peer = self
            .peers
            .get_mut(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !peer.attempted || !peer.written || peer.guard.is_none() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(&mut peer.guard)
    }
}

impl PacketCompleteReportStartupHolder {
    /// Retires the same original native guards into their reserved supervision slots.
    ///
    /// # Errors
    /// Refuses a conflicting native bank loan; untransferred owners stay retained.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn retire_original_scene_native_guards(
        &self,
    ) -> Result<(), RuntimeError> {
        let mut owners = self
            .native_launches
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for peer in &mut owners.peers {
            if let Some(guard) = &mut peer.guard {
                guard.retire_original();
            }
            // Failed launch reservations still own any partial Child; their
            // guard Drop transfers it to the same supervisor. Unstarted peers
            // release their unused expected slot even with a retained Command.
            drop(peer.reservation.take());
            if !peer.attempted
                && peer.reservation.is_none()
                && peer.guard.is_none()
                && peer.command.is_none()
            {
                if let Some(inputs) = &mut peer.inputs {
                    // This concrete slot has never received native custody.
                    // Releasing only that unused reservation clears expected;
                    // all bootstrap, source and partial-action owners remain.
                    drop(inputs.slot.take());
                }
            }
        }
        Ok(())
    }
}

impl NativeLaunchOwners {
    /// Counts actual bootstrap, closed Command and selected native custody descriptors.
    ///
    /// # Errors
    /// Refuses unknown slot, reservation or guard backing or checked count overflow.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn retained_descriptor_views_precredit_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let mut total = 0usize;
        for peer in &self.peers {
            if let Some(inputs) = &peer.inputs {
                total = total
                    .checked_add(usize::from(inputs.bootstrap_reader.is_some()))
                    .and_then(|sum| sum.checked_add(usize::from(inputs.bootstrap_writer.is_some())))
                    .ok_or(RuntimeError::ResourceLimit)?;
                if let Some(slot) = &inputs.slot {
                    total = total
                        .checked_add(
                            slot.retained_descriptor_views_precredit_data()?
                                .ok_or(RuntimeError::UnsupportedFacet)?,
                        )
                        .ok_or(RuntimeError::ResourceLimit)?;
                }
            }
            if peer.command_stdin_owned {
                if peer.command.is_none() {
                    return Err(RuntimeError::ForeignAuthority);
                }
                total = total.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
            }
            if let Some(reservation) = &peer.reservation {
                total = total
                    .checked_add(reservation.retained_descriptor_views_precredit_data()?)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            if let Some(guard) = &peer.guard {
                total = total
                    .checked_add(guard.retained_descriptor_views_precredit_data()?)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        Ok(total)
    }
}

// The holder's real Rc observer counts its enlarged inline peer slots. These
// separate defining views prepay the new selected write and raw-bank observer
// before any Source factory, wire allocation or original Child path.
pub(super) fn restored_suffix_wire_counter_scratch_data() -> usize {
    use crucible_engine::node_contract::OperationFailure;
    use std::mem::size_of;

    size_of::<Option<PacketCompleteNativeRestoredSuffixStartupWire>>()
        + size_of::<&PacketCompleteNativeRestoredSuffixStartupWire>()
        + size_of::<Option<&PacketCompleteNativeRestoredSuffixStartupWire>>()
        + size_of::<&mut PacketCompleteNativeRestoredSuffixStartupWire>()
        + size_of::<Option<&mut PacketCompleteNativeRestoredSuffixStartupWire>>()
        + size_of::<&mut Option<PacketCompleteNativeRestoredSuffixStartupWire>>()
        + size_of::<(
            Option<&mut PacketCompleteNativeStartupWire>,
            Option<&mut PacketCompleteNativeRestoredSuffixStartupWire>,
        )>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<(), OperationFailure>>()
        + size_of::<Result<bool, OperationFailure>>()
        + size_of::<Result<bool, RuntimeError>>()
        + size_of::<&PacketCompleteAckPeerBootMaterial<'static>>()
        + size_of::<Result<&PacketCompleteAckPeerBootMaterial<'static>, RuntimeError>>()
        + size_of::<bool>()
}

#[cfg(test)]
mod reservation_retirement_tests {
    // Invalid static fixture DATA must fail before the retirement assertions.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_engine::node_adapters::cnp::CnpSemanticProcessCustody;
    use crucible_node_format::{U64, canonical};
    use std::{io::Read, os::fd::AsRawFd};

    struct Slot {
        dropped: Rc<Cell<usize>>,
        retained: Rc<Cell<usize>>,
    }

    impl CnpSemanticProcessSlot for Slot {
        fn identity(&self) -> U64 {
            U64::new(1)
        }

        fn retain(&mut self, _original: CnpSemanticProcessCustody) {
            self.retained.set(self.retained.get() + 1);
        }
    }

    impl Drop for Slot {
        fn drop(&mut self) {
            self.dropped.set(self.dropped.get() + 1);
        }
    }

    #[test]
    fn retiring_prepared_commands_releases_unstarted_reservations_once() {
        let (_scene, original) =
            crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
        let dropped = Rc::new(Cell::new(0));
        let retained = Rc::new(Cell::new(0));
        let executable =
            canonical::content_ref(b"never launched", "application/octet-stream").unwrap();
        let held = original.borrow();
        {
            let mut owners = held.native_launches.borrow_mut();
            for peer in &mut owners.peers {
                peer.reservation = Some(CnpSemanticLaunchReservation::reserve(
                    PathBuf::from("unstarted-retirement-control"),
                    executable.clone(),
                    Box::new(Slot {
                        dropped: Rc::clone(&dropped),
                        retained: Rc::clone(&retained),
                    }),
                ));
                peer.command = Some(Command::new("unstarted-retirement-must-not-execute"));
                assert!(!peer.attempted);
                assert!(peer.guard.is_none());
            }
        }
        assert_eq!(dropped.get(), 0);

        held.retire_original_scene_native_guards().unwrap();
        assert_eq!(dropped.get(), 3);
        assert_eq!(retained.get(), 0);
        {
            let owners = held.native_launches.borrow();
            assert!(owners.peers.iter().all(|peer| {
                peer.reservation.is_none() && peer.command.is_some() && !peer.attempted
            }));
        }
        held.retire_original_scene_native_guards().unwrap();
        assert_eq!(dropped.get(), 3);
        assert_eq!(retained.get(), 0);
    }

    #[test]
    fn native_writer_expiry_rejects_before_touching_the_original_socket() {
        let (mut stream, mut receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let original_descriptor = stream.as_raw_fd();
        let original_deadline = ProcessDeadline::after(Duration::ZERO).unwrap();
        let mut writer = NativeDeadlineWriter {
            stream: &mut stream,
            deadline: original_deadline,
        };

        let error = writer.write(b"expired").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(writer.deadline == original_deadline);
        assert_eq!(writer.stream.as_raw_fd(), original_descriptor);
        let mut received = [0; 1];
        assert_eq!(
            receiver.read(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn native_writer_reuses_the_same_cut_across_separate_writes() {
        let (mut stream, mut receiver) = UnixStream::pair().unwrap();
        let original_descriptor = stream.as_raw_fd();
        let original_deadline = ProcessDeadline::after(MAXIMUM_WRITE_WATCHDOG).unwrap();
        let mut writer = NativeDeadlineWriter {
            stream: &mut stream,
            deadline: original_deadline,
        };

        writer.write_all(b"first").unwrap();
        assert!(writer.deadline == original_deadline);
        writer.write_all(b"second").unwrap();

        assert!(writer.deadline == original_deadline);
        assert_eq!(writer.stream.as_raw_fd(), original_descriptor);
        let mut received = [0; 11];
        receiver.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"firstsecond");
    }
}
