//! External hardware-counter control for the whole-demand execution epoch.
//!
//! The evaluator does not issue platform-specific performance-counter ioctls.
//! A default-off benchmark wrapper instead passes inherited command and
//! acknowledgement pipe descriptors through environment variables. The
//! handshake prevents the evaluator from racing counter enable or disable.
//! Legacy wrappers exchange one-byte `B`/`E` commands and `A` acknowledgements;
//! their counts remain non-authoritative. Setting
//! `AOS_NIX_DEMAND_EPOCH_PROTOCOL=2` selects fixed-width packets carrying a
//! process-local session id, monotone window id, and exact outer-leaf kind.
//! Version 2 also returns instruction/cycle counts and a null-window
//! calibration. Any mismatch or missing count fails closed.
//!
//! ```text
//! request/ack:  opcode:u8, version:u8, kind:u8, reserved:u8,
//!               session:u64-le, window:u64-le
//! count reply:  the same 20-byte header followed by
//!               instructions:u64-le, cycles:u64-le
//!
//! N -> C(counts)                  null-window calibration, window 0
//! B -> A                          begin identified target window
//! E -> C(counts)                  end identified target window
//! ```

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};

/// Serializes access to either inherited pipe protocol within this process.
///
/// Preventing concurrent local users avoids acknowledgement theft. Legacy
/// exchanges still lack provenance; identified exchanges additionally prove
/// their process-local session and window identities.
static WINDOW_CONTROLLER_CLAIMED: AtomicBool = AtomicBool::new(false);
static NEXT_SESSION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

const IDENTIFIED_PROTOCOL_ENV: &str = "AOS_NIX_DEMAND_EPOCH_PROTOCOL";
const IDENTIFIED_PROTOCOL_VERSION: u8 = 2;
const IDENTIFIED_REQUEST_BYTES: usize = 20;
const IDENTIFIED_COUNT_RESPONSE_BYTES: usize = 36;

/// Exact outer leaf attributed to one identified counter window.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DemandWindowKind {
    /// Formal-set auto-call at requested attribute-path segment four.
    AutoCall4 = 1,
    /// Terminal force at requested attribute-path segment five.
    FinalForce5 = 2,
}

impl DemandWindowKind {
    /// Returns the stable report label for this window kind.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::AutoCall4 => "auto_call_4",
            Self::FinalForce5 => "final_force_5",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::AutoCall4 => 0,
            Self::FinalForce5 => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct HardwareCounts {
    instructions: u64,
    cycles: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct WindowTotals {
    windows: u64,
    raw: HardwareCounts,
    adjusted: HardwareCounts,
}

/// Read-only, provenance-checked totals returned by the external PMU owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DemandCounterEvidence {
    session_id: u64,
    null_overhead: HardwareCounts,
    totals: [WindowTotals; 2],
    authoritative: bool,
}

impl DemandCounterEvidence {
    /// Returns an explicit zeroed non-authoritative evidence value.
    pub(super) const fn unavailable() -> Self {
        Self {
            session_id: 0,
            null_overhead: HardwareCounts {
                instructions: 0,
                cycles: 0,
            },
            totals: [
                WindowTotals {
                    windows: 0,
                    raw: HardwareCounts {
                        instructions: 0,
                        cycles: 0,
                    },
                    adjusted: HardwareCounts {
                        instructions: 0,
                        cycles: 0,
                    },
                },
                WindowTotals {
                    windows: 0,
                    raw: HardwareCounts {
                        instructions: 0,
                        cycles: 0,
                    },
                    adjusted: HardwareCounts {
                        instructions: 0,
                        cycles: 0,
                    },
                },
            ],
            authoritative: false,
        }
    }

    /// Returns the process-local identity transmitted with every window.
    pub(super) const fn session_id(self) -> u64 {
        self.session_id
    }

    /// Returns whether identity, balance, calibration, and all counter replies reconcile.
    pub(super) const fn authoritative(self) -> bool {
        self.authoritative
    }

    /// Returns the null-window instruction overhead subtracted from each window.
    pub(super) const fn null_instructions(self) -> u64 {
        self.null_overhead.instructions
    }

    /// Returns the null-window cycle overhead subtracted from each window.
    pub(super) const fn null_cycles(self) -> u64 {
        self.null_overhead.cycles
    }

    /// Returns the number of measured windows of one exact leaf kind.
    pub(super) const fn windows(self, kind: DemandWindowKind) -> u64 {
        self.totals[kind.index()].windows
    }

    /// Returns calibrated retired instructions for one exact leaf kind.
    pub(super) const fn instructions(self, kind: DemandWindowKind) -> u64 {
        self.totals[kind.index()].adjusted.instructions
    }

    /// Returns calibrated cycles for one exact leaf kind.
    pub(super) const fn cycles(self, kind: DemandWindowKind) -> u64 {
        self.totals[kind.index()].adjusted.cycles
    }

    /// Returns uncalibrated retired instructions for one exact leaf kind.
    pub(super) const fn raw_instructions(self, kind: DemandWindowKind) -> u64 {
        self.totals[kind.index()].raw.instructions
    }

    /// Returns uncalibrated cycles for one exact leaf kind.
    pub(super) const fn raw_cycles(self, kind: DemandWindowKind) -> u64 {
        self.totals[kind.index()].raw.cycles
    }

    /// Returns calibrated retired instructions across every identified window.
    pub(super) fn total_instructions(self) -> Option<u64> {
        self.totals.iter().try_fold(0u64, |sum, totals| {
            sum.checked_add(totals.adjusted.instructions)
        })
    }

    /// Returns calibrated cycles across every identified window.
    pub(super) fn total_cycles(self) -> Option<u64> {
        self.totals
            .iter()
            .try_fold(0u64, |sum, totals| sum.checked_add(totals.adjusted.cycles))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowProtocol {
    Legacy,
    Identified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowIdentity {
    session: u64,
    window: u64,
    kind: DemandWindowKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExchangeState {
    Closed,
    Open,
    Indeterminate,
}

/// An open whole-demand epoch owned by the API call that established it.
#[derive(Debug)]
pub(super) struct DemandEpoch {
    control: File,
    acknowledgement: File,
    state: ExchangeState,
    owns_process_claim: bool,
}

/// Persistent inherited-pipe controller for noncontiguous demand windows.
///
/// The controller opens each inherited descriptor once. Every admitted window
/// then uses the selected legacy or identified handshake, allowing the
/// external PMU owner to accumulate counters without reopening descriptors.
#[derive(Debug)]
pub(super) struct DemandWindowController {
    control: File,
    acknowledgement: File,
    state: ExchangeState,
    protocol: WindowProtocol,
    session_id: u64,
    next_window_id: u64,
    active_window: Option<WindowIdentity>,
    null_overhead: Option<HardwareCounts>,
    totals: [WindowTotals; 2],
    owns_process_claim: bool,
    begin_commands: u64,
    end_commands: u64,
    failures: u64,
}

impl DemandWindowController {
    /// Connects to inherited control pipes without enabling counters.
    pub(super) fn connect() -> Option<Self> {
        if !claim_process_protocol() {
            return None;
        }
        let Some(control) = open_inherited_fd("AOS_NIX_DEMAND_EPOCH_CONTROL_FD", true) else {
            WINDOW_CONTROLLER_CLAIMED.store(false, Ordering::Release);
            return None;
        };
        let Some(acknowledgement) = open_inherited_fd("AOS_NIX_DEMAND_EPOCH_ACK_FD", false) else {
            WINDOW_CONTROLLER_CLAIMED.store(false, Ordering::Release);
            return None;
        };
        let protocol =
            if std::env::var_os(IDENTIFIED_PROTOCOL_ENV).is_some_and(|value| value == "2") {
                WindowProtocol::Identified
            } else {
                WindowProtocol::Legacy
            };
        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let mut controller = Self {
            control,
            acknowledgement,
            state: ExchangeState::Closed,
            protocol,
            session_id,
            next_window_id: 0,
            active_window: None,
            null_overhead: None,
            totals: [WindowTotals::default(); 2],
            owns_process_claim: true,
            begin_commands: 0,
            end_commands: 0,
            failures: 0,
        };
        if protocol == WindowProtocol::Identified {
            controller.calibrate_null_window();
        }
        Some(controller)
    }

    /// Enables the externally owned counters for one target leaf.
    pub(super) fn begin_window(&mut self, kind: DemandWindowKind) -> bool {
        if self.state != ExchangeState::Closed {
            self.failures = self.failures.saturating_add(1);
            return false;
        }
        // Once the byte write is attempted, failure cannot distinguish an
        // unsent command from a sent command whose acknowledgement was lost.
        self.state = ExchangeState::Indeterminate;
        match self.protocol {
            WindowProtocol::Legacy => {
                if !exchange(&mut self.control, &mut self.acknowledgement, b'B') {
                    self.failures = self.failures.saturating_add(1);
                    return false;
                }
            }
            WindowProtocol::Identified => {
                let Some(window) = self.next_window_id.checked_add(1) else {
                    self.failures = self.failures.saturating_add(1);
                    return false;
                };
                let identity = WindowIdentity {
                    session: self.session_id,
                    window,
                    kind,
                };
                if identified_begin(&mut self.control, &mut self.acknowledgement, identity).is_err()
                {
                    self.failures = self.failures.saturating_add(1);
                    return false;
                }
                self.next_window_id = window;
                self.active_window = Some(identity);
            }
        }
        self.state = ExchangeState::Open;
        self.begin_commands = self.begin_commands.saturating_add(1);
        true
    }

    /// Disables the externally owned counters after one target leaf.
    pub(super) fn end_window(&mut self) -> bool {
        if self.state != ExchangeState::Open {
            self.failures = self.failures.saturating_add(1);
            return false;
        }
        // Mark the transition before sending. A failed exchange is never
        // replayed because the `E` byte may already have reached the peer.
        self.state = ExchangeState::Indeterminate;
        let counts = match self.protocol {
            WindowProtocol::Legacy => {
                if !exchange(&mut self.control, &mut self.acknowledgement, b'E') {
                    self.failures = self.failures.saturating_add(1);
                    return false;
                }
                None
            }
            WindowProtocol::Identified => {
                let Some(identity) = self.active_window else {
                    self.failures = self.failures.saturating_add(1);
                    return false;
                };
                match identified_counts(
                    &mut self.control,
                    &mut self.acknowledgement,
                    b'E',
                    identity,
                ) {
                    Ok(counts) => Some((identity, counts)),
                    Err(()) => {
                        self.failures = self.failures.saturating_add(1);
                        return false;
                    }
                }
            }
        };
        if let Some((identity, counts)) = counts
            && !self.record_counts(identity.kind, counts)
        {
            self.failures = self.failures.saturating_add(1);
            return false;
        }
        self.state = ExchangeState::Closed;
        self.active_window = None;
        self.end_commands = self.end_commands.saturating_add(1);
        true
    }

    fn calibrate_null_window(&mut self) {
        let identity = WindowIdentity {
            session: self.session_id,
            window: 0,
            kind: DemandWindowKind::AutoCall4,
        };
        match identified_counts(&mut self.control, &mut self.acknowledgement, b'N', identity) {
            Ok(counts) => self.null_overhead = Some(counts),
            Err(()) => {
                self.state = ExchangeState::Indeterminate;
                self.failures = self.failures.saturating_add(1);
            }
        }
    }

    fn record_counts(&mut self, kind: DemandWindowKind, counts: HardwareCounts) -> bool {
        let Some(overhead) = self.null_overhead else {
            return false;
        };
        let Some(adjusted_instructions) = counts.instructions.checked_sub(overhead.instructions)
        else {
            return false;
        };
        let Some(adjusted_cycles) = counts.cycles.checked_sub(overhead.cycles) else {
            return false;
        };
        let totals = &mut self.totals[kind.index()];
        let Some(windows) = totals.windows.checked_add(1) else {
            return false;
        };
        let Some(raw_instructions) = totals.raw.instructions.checked_add(counts.instructions)
        else {
            return false;
        };
        let Some(raw_cycles) = totals.raw.cycles.checked_add(counts.cycles) else {
            return false;
        };
        let Some(instructions) = totals
            .adjusted
            .instructions
            .checked_add(adjusted_instructions)
        else {
            return false;
        };
        let Some(cycles) = totals.adjusted.cycles.checked_add(adjusted_cycles) else {
            return false;
        };
        totals.windows = windows;
        totals.raw = HardwareCounts {
            instructions: raw_instructions,
            cycles: raw_cycles,
        };
        totals.adjusted = HardwareCounts {
            instructions,
            cycles,
        };
        true
    }

    /// Returns acknowledged begin commands.
    pub(super) const fn begin_commands(&self) -> u64 {
        self.begin_commands
    }

    /// Returns acknowledged end commands.
    pub(super) const fn end_commands(&self) -> u64 {
        self.end_commands
    }

    /// Returns protocol or balance failures.
    pub(super) const fn failures(&self) -> u64 {
        self.failures
    }

    /// Returns whether no target window remains open.
    pub(super) const fn balanced(&self) -> bool {
        matches!(self.state, ExchangeState::Closed)
            && self.begin_commands == self.end_commands
            && self.active_window.is_none()
            && self.failures == 0
    }

    /// Returns whether the selected protocol identifies exact evaluator windows.
    pub(super) const fn provenance_available(&self) -> bool {
        matches!(self.protocol, WindowProtocol::Identified)
    }

    /// Returns calibrated counters only when every authority condition holds.
    pub(super) fn counter_evidence(&self) -> DemandCounterEvidence {
        let authoritative = self.provenance_available()
            && self.null_overhead.is_some()
            && self.balanced()
            && self
                .totals
                .iter()
                .try_fold(0u64, |sum, totals| sum.checked_add(totals.windows))
                == Some(self.end_commands);
        DemandCounterEvidence {
            session_id: self.session_id,
            null_overhead: self.null_overhead.unwrap_or_default(),
            totals: self.totals,
            authoritative,
        }
    }
}

impl Drop for DemandWindowController {
    fn drop(&mut self) {
        if self.state == ExchangeState::Open {
            self.state = ExchangeState::Indeterminate;
            let completed = match self.protocol {
                WindowProtocol::Legacy => {
                    exchange(&mut self.control, &mut self.acknowledgement, b'E')
                }
                WindowProtocol::Identified => self.active_window.is_some_and(|identity| {
                    identified_counts(&mut self.control, &mut self.acknowledgement, b'E', identity)
                        .is_ok_and(|counts| self.record_counts(identity.kind, counts))
                }),
            };
            if completed {
                self.active_window = None;
                self.end_commands = self.end_commands.saturating_add(1);
                self.state = ExchangeState::Closed;
            } else {
                self.failures = self.failures.saturating_add(1);
            }
        }
        if self.owns_process_claim {
            WINDOW_CONTROLLER_CLAIMED.store(false, Ordering::Release);
            self.owns_process_claim = false;
        }
    }
}

impl DemandEpoch {
    /// Begins an epoch when the external wrapper supplied both pipe descriptors.
    pub(super) fn begin() -> Option<Self> {
        if !claim_process_protocol() {
            return None;
        }
        let Some(control) = open_inherited_fd("AOS_NIX_DEMAND_EPOCH_CONTROL_FD", true) else {
            WINDOW_CONTROLLER_CLAIMED.store(false, Ordering::Release);
            return None;
        };
        let Some(acknowledgement) = open_inherited_fd("AOS_NIX_DEMAND_EPOCH_ACK_FD", false) else {
            WINDOW_CONTROLLER_CLAIMED.store(false, Ordering::Release);
            return None;
        };
        let mut epoch = Self {
            control,
            acknowledgement,
            state: ExchangeState::Indeterminate,
            owns_process_claim: true,
        };
        if epoch.exchange(b'B') {
            epoch.state = ExchangeState::Open;
            Some(epoch)
        } else {
            None
        }
    }

    /// Ends the epoch after the external wrapper has disabled its counters.
    pub(super) fn end(mut self) {
        if self.state == ExchangeState::Open {
            self.state = ExchangeState::Indeterminate;
            if self.exchange(b'E') {
                self.state = ExchangeState::Closed;
            }
        }
    }

    /// Sends one boundary command and waits for the counter-side acknowledgement.
    fn exchange(&mut self, command: u8) -> bool {
        exchange(&mut self.control, &mut self.acknowledgement, command)
    }
}

impl Drop for DemandEpoch {
    fn drop(&mut self) {
        if self.state == ExchangeState::Open {
            self.state = ExchangeState::Indeterminate;
            if self.exchange(b'E') {
                self.state = ExchangeState::Closed;
            }
        }
        if self.owns_process_claim {
            WINDOW_CONTROLLER_CLAIMED.store(false, Ordering::Release);
            self.owns_process_claim = false;
        }
    }
}

fn claim_process_protocol() -> bool {
    if WINDOW_CONTROLLER_CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        true
    } else {
        eprintln!(
            "aos_nix_demand_epoch_probe_error \
             \"one-byte PMU protocol already has a process-local owner\""
        );
        false
    }
}

fn identified_begin(
    control: &mut File,
    acknowledgement: &mut File,
    identity: WindowIdentity,
) -> Result<(), ()> {
    write_identified_request(control, b'B', identity)?;
    let mut response = [0u8; IDENTIFIED_REQUEST_BYTES];
    acknowledgement.read_exact(&mut response).map_err(|error| {
        eprintln!("aos_nix_demand_epoch_probe_error {error:?}");
    })?;
    validate_identified_response(&response[..IDENTIFIED_REQUEST_BYTES], b'A', identity)
}

fn identified_counts(
    control: &mut File,
    acknowledgement: &mut File,
    command: u8,
    identity: WindowIdentity,
) -> Result<HardwareCounts, ()> {
    write_identified_request(control, command, identity)?;
    let mut response = [0u8; IDENTIFIED_COUNT_RESPONSE_BYTES];
    acknowledgement.read_exact(&mut response).map_err(|error| {
        eprintln!("aos_nix_demand_epoch_probe_error {error:?}");
    })?;
    validate_identified_response(&response[..IDENTIFIED_REQUEST_BYTES], b'C', identity)?;
    let instructions = u64::from_le_bytes(response[20..28].try_into().map_err(|_| ())?);
    let cycles = u64::from_le_bytes(response[28..36].try_into().map_err(|_| ())?);
    Ok(HardwareCounts {
        instructions,
        cycles,
    })
}

fn write_identified_request(
    control: &mut File,
    command: u8,
    identity: WindowIdentity,
) -> Result<(), ()> {
    let packet = identified_packet(command, identity);
    control
        .write_all(&packet)
        .and_then(|()| control.flush())
        .map_err(|error| {
            eprintln!("aos_nix_demand_epoch_probe_error {error:?}");
        })
}

fn identified_packet(command: u8, identity: WindowIdentity) -> [u8; IDENTIFIED_REQUEST_BYTES] {
    let mut packet = [0u8; IDENTIFIED_REQUEST_BYTES];
    packet[0] = command;
    packet[1] = IDENTIFIED_PROTOCOL_VERSION;
    packet[2] = identity.kind as u8;
    packet[4..12].copy_from_slice(&identity.session.to_le_bytes());
    packet[12..20].copy_from_slice(&identity.window.to_le_bytes());
    packet
}

fn validate_identified_response(
    response: &[u8],
    expected_command: u8,
    expected: WindowIdentity,
) -> Result<(), ()> {
    let expected_packet = identified_packet(expected_command, expected);
    if response == expected_packet {
        Ok(())
    } else {
        eprintln!(
            "aos_nix_demand_epoch_probe_error \
             \"identified PMU response did not match session/window/kind\""
        );
        Err(())
    }
}

fn exchange(control: &mut File, acknowledgement: &mut File, command: u8) -> bool {
    let result = control
        .write_all(&[command])
        .and_then(|()| control.flush())
        .and_then(|()| {
            let mut received = [0u8; 1];
            acknowledgement.read_exact(&mut received)?;
            if received == [b'A'] {
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "unexpected demand-epoch acknowledgement",
                ))
            }
        });
    if let Err(error) = result {
        eprintln!("aos_nix_demand_epoch_probe_error {error:?}");
        return false;
    }
    true
}

/// Opens one inherited descriptor through procfs without platform-specific code.
fn open_inherited_fd(name: &str, write: bool) -> Option<File> {
    let raw_fd = std::env::var_os(name)?;
    let Some(raw_fd) = raw_fd.to_str() else {
        eprintln!("aos_nix_demand_epoch_probe_error {name:?}=\"fd is not UTF-8\"");
        return None;
    };
    let Ok(fd) = raw_fd.parse::<u32>() else {
        eprintln!("aos_nix_demand_epoch_probe_error {name:?}=\"fd is not an integer\"");
        return None;
    };
    let path = format!("/proc/self/fd/{fd}");
    match OpenOptions::new().read(!write).write(write).open(path) {
        Ok(file) => Some(file),
        Err(error) => {
            eprintln!("aos_nix_demand_epoch_probe_error {error:?}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn failed_end_ack_is_never_retried_by_drop() {
        let (control_client, mut control_peer) = UnixStream::pair().expect("control socket pair");
        let (ack_client, ack_peer) = UnixStream::pair().expect("ack socket pair");
        drop(ack_peer);
        let mut controller = DemandWindowController {
            control: File::from(OwnedFd::from(control_client)),
            acknowledgement: File::from(OwnedFd::from(ack_client)),
            state: ExchangeState::Open,
            protocol: WindowProtocol::Legacy,
            session_id: 1,
            next_window_id: 0,
            active_window: None,
            null_overhead: None,
            totals: [WindowTotals::default(); 2],
            owns_process_claim: false,
            begin_commands: 1,
            end_commands: 0,
            failures: 0,
        };

        assert!(!controller.end_window());
        assert_eq!(controller.state, ExchangeState::Indeterminate);
        drop(controller);

        let mut commands = Vec::new();
        control_peer
            .read_to_end(&mut commands)
            .expect("read commands");
        assert_eq!(commands, vec![b'E']);
    }

    #[test]
    fn acknowledged_window_is_balanced() {
        let (control_client, mut control_peer) = UnixStream::pair().expect("control socket pair");
        let (ack_client, mut ack_peer) = UnixStream::pair().expect("ack socket pair");
        let peer = std::thread::spawn(move || {
            let mut commands = [0u8; 2];
            for command in &mut commands {
                control_peer
                    .read_exact(std::slice::from_mut(command))
                    .expect("read command");
                ack_peer.write_all(b"A").expect("write acknowledgement");
            }
            commands
        });
        let mut controller = DemandWindowController {
            control: File::from(OwnedFd::from(control_client)),
            acknowledgement: File::from(OwnedFd::from(ack_client)),
            state: ExchangeState::Closed,
            protocol: WindowProtocol::Legacy,
            session_id: 1,
            next_window_id: 0,
            active_window: None,
            null_overhead: None,
            totals: [WindowTotals::default(); 2],
            owns_process_claim: false,
            begin_commands: 0,
            end_commands: 0,
            failures: 0,
        };

        assert!(controller.begin_window(DemandWindowKind::AutoCall4));
        assert!(controller.end_window());
        assert!(controller.balanced());
        assert!(!controller.counter_evidence().authoritative());
        assert_eq!(peer.join().expect("peer thread"), [b'B', b'E']);
    }

    #[test]
    fn identified_windows_return_calibrated_split_counters() {
        let (control_client, mut control_peer) = UnixStream::pair().expect("control socket pair");
        let (ack_client, mut ack_peer) = UnixStream::pair().expect("ack socket pair");
        let peer = std::thread::spawn(move || {
            let mut request = [0u8; IDENTIFIED_REQUEST_BYTES];

            control_peer.read_exact(&mut request).expect("read null");
            let null_identity = WindowIdentity {
                session: 41,
                window: 0,
                kind: DemandWindowKind::AutoCall4,
            };
            assert_eq!(request, identified_packet(b'N', null_identity));
            let mut null_response = Vec::from(identified_packet(b'C', null_identity));
            null_response.extend_from_slice(&10u64.to_le_bytes());
            null_response.extend_from_slice(&20u64.to_le_bytes());
            ack_peer
                .write_all(&null_response)
                .expect("write null counts");

            control_peer
                .read_exact(&mut request)
                .expect("read auto begin");
            let auto_identity = WindowIdentity {
                session: 41,
                window: 1,
                kind: DemandWindowKind::AutoCall4,
            };
            assert_eq!(request, identified_packet(b'B', auto_identity));
            ack_peer
                .write_all(&identified_packet(b'A', auto_identity))
                .expect("write auto begin ack");
            control_peer
                .read_exact(&mut request)
                .expect("read auto end");
            assert_eq!(request, identified_packet(b'E', auto_identity));
            let mut auto_response = Vec::from(identified_packet(b'C', auto_identity));
            auto_response.extend_from_slice(&110u64.to_le_bytes());
            auto_response.extend_from_slice(&220u64.to_le_bytes());
            ack_peer
                .write_all(&auto_response)
                .expect("write auto counts");

            control_peer
                .read_exact(&mut request)
                .expect("read final begin");
            let final_identity = WindowIdentity {
                session: 41,
                window: 2,
                kind: DemandWindowKind::FinalForce5,
            };
            assert_eq!(request, identified_packet(b'B', final_identity));
            ack_peer
                .write_all(&identified_packet(b'A', final_identity))
                .expect("write final begin ack");
            control_peer
                .read_exact(&mut request)
                .expect("read final end");
            assert_eq!(request, identified_packet(b'E', final_identity));
            let mut final_response = Vec::from(identified_packet(b'C', final_identity));
            final_response.extend_from_slice(&310u64.to_le_bytes());
            final_response.extend_from_slice(&420u64.to_le_bytes());
            ack_peer
                .write_all(&final_response)
                .expect("write final counts");
        });
        let mut controller = DemandWindowController {
            control: File::from(OwnedFd::from(control_client)),
            acknowledgement: File::from(OwnedFd::from(ack_client)),
            state: ExchangeState::Closed,
            protocol: WindowProtocol::Identified,
            session_id: 41,
            next_window_id: 0,
            active_window: None,
            null_overhead: None,
            totals: [WindowTotals::default(); 2],
            owns_process_claim: false,
            begin_commands: 0,
            end_commands: 0,
            failures: 0,
        };

        controller.calibrate_null_window();
        assert!(controller.begin_window(DemandWindowKind::AutoCall4));
        assert!(controller.end_window());
        assert!(controller.begin_window(DemandWindowKind::FinalForce5));
        assert!(controller.end_window());
        let evidence = controller.counter_evidence();
        assert!(evidence.authoritative());
        assert_eq!(evidence.session_id(), 41);
        assert_eq!(evidence.null_instructions(), 10);
        assert_eq!(evidence.null_cycles(), 20);
        assert_eq!(evidence.windows(DemandWindowKind::AutoCall4), 1);
        assert_eq!(evidence.instructions(DemandWindowKind::AutoCall4), 100);
        assert_eq!(evidence.cycles(DemandWindowKind::AutoCall4), 200);
        assert_eq!(evidence.windows(DemandWindowKind::FinalForce5), 1);
        assert_eq!(evidence.instructions(DemandWindowKind::FinalForce5), 300);
        assert_eq!(evidence.cycles(DemandWindowKind::FinalForce5), 400);
        assert_eq!(evidence.total_instructions(), Some(400));
        assert_eq!(evidence.total_cycles(), Some(600));
        peer.join().expect("peer thread");
    }

    #[test]
    fn mismatched_identified_window_fails_closed() {
        let (control_client, mut control_peer) = UnixStream::pair().expect("control socket pair");
        let (ack_client, mut ack_peer) = UnixStream::pair().expect("ack socket pair");
        let peer = std::thread::spawn(move || {
            let mut request = [0u8; IDENTIFIED_REQUEST_BYTES];
            control_peer.read_exact(&mut request).expect("read begin");
            let wrong = WindowIdentity {
                session: 99,
                window: 2,
                kind: DemandWindowKind::AutoCall4,
            };
            ack_peer
                .write_all(&identified_packet(b'A', wrong))
                .expect("write mismatched ack");
        });
        let mut controller = DemandWindowController {
            control: File::from(OwnedFd::from(control_client)),
            acknowledgement: File::from(OwnedFd::from(ack_client)),
            state: ExchangeState::Closed,
            protocol: WindowProtocol::Identified,
            session_id: 99,
            next_window_id: 0,
            active_window: None,
            null_overhead: Some(HardwareCounts {
                instructions: 1,
                cycles: 1,
            }),
            totals: [WindowTotals::default(); 2],
            owns_process_claim: false,
            begin_commands: 0,
            end_commands: 0,
            failures: 0,
        };

        assert!(!controller.begin_window(DemandWindowKind::AutoCall4));
        assert!(!controller.counter_evidence().authoritative());
        peer.join().expect("peer thread");
    }

    #[test]
    fn identified_count_below_null_overhead_is_refused() {
        let (control_client, _) = UnixStream::pair().expect("control socket pair");
        let (ack_client, _) = UnixStream::pair().expect("ack socket pair");
        let mut controller = DemandWindowController {
            control: File::from(OwnedFd::from(control_client)),
            acknowledgement: File::from(OwnedFd::from(ack_client)),
            state: ExchangeState::Closed,
            protocol: WindowProtocol::Identified,
            session_id: 1,
            next_window_id: 0,
            active_window: None,
            null_overhead: Some(HardwareCounts {
                instructions: 10,
                cycles: 20,
            }),
            totals: [WindowTotals::default(); 2],
            owns_process_claim: false,
            begin_commands: 0,
            end_commands: 0,
            failures: 0,
        };

        assert!(!controller.record_counts(
            DemandWindowKind::FinalForce5,
            HardwareCounts {
                instructions: 9,
                cycles: 21,
            },
        ));
        assert_eq!(
            controller
                .counter_evidence()
                .windows(DemandWindowKind::FinalForce5),
            0,
        );
    }
}
