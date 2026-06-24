//! Optional white-box doorbell trap callback core.
//!
//! White-box mode is opt-in. When disabled, this module's registration plan
//! installs no trap and leaves black-box operation untouched. When enabled, the
//! safe callback body reads the guest payload only through a guest-memory API
//! adapter at the trap's current icount, records an observational marker, and
//! routes any host-to-guest reply through an explicit delivery-icount gate.

use thiserror::Error;

use crucible_shmem::MAX_FRAME_DATA;

use crate::{PluginDeviceCallbackKind, PluginSwitch};

/// QEMU capability label for registering the reserved white-box doorbell trap.
pub const QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL: &str = "qemu_plugin_register_doorbell_trap";
/// QEMU capability label for reading guest memory at the trap icount.
pub const QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL: &str = "qemu_plugin_guest_memory_read";
/// QEMU capability label for writing white-box replies into guest memory.
pub const QEMU_PLUGIN_GUEST_MEMORY_WRITE_SYMBOL: &str = "qemu_plugin_guest_memory_write";

/// Registration-time-fixed white-box doorbell state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginWhiteboxDoorbell {
    mode: PluginSwitch,
    trap: WhiteboxDoorbellTrap,
    max_payload_len: usize,
}

impl PluginWhiteboxDoorbell {
    /// Builds doorbell state from the parsed `whitebox` switch and trap config.
    #[must_use]
    pub const fn new(
        mode: PluginSwitch,
        trap: WhiteboxDoorbellTrap,
        max_payload_len: usize,
    ) -> Self {
        Self {
            mode,
            trap,
            max_payload_len,
        }
    }

    /// Returns the launch-time white-box switch.
    #[must_use]
    pub const fn mode(&self) -> PluginSwitch {
        self.mode
    }

    /// Returns the reserved trap selected at registration.
    #[must_use]
    pub const fn trap(&self) -> WhiteboxDoorbellTrap {
        self.trap
    }

    /// Returns the bounded maximum payload length read at one trap.
    #[must_use]
    pub const fn max_payload_len(&self) -> usize {
        self.max_payload_len
    }

    /// Builds the callback registration plan for the current switch state.
    ///
    /// Off-mode returns [`WhiteboxDoorbellRegistrationPlan::Disabled`] without
    /// requiring any white-box QEMU capability, which is the black-box default.
    /// On-mode requires both the trap registration surface and the guest-memory
    /// read surface before it can install the callback.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellError::InvalidMaxPayloadLen`] when the payload
    /// bound is zero or larger than the shared-memory frame bound. Returns
    /// [`WhiteboxDoorbellError::CapabilityUnavailable`] when white-box mode is
    /// enabled but a required QEMU capability is absent.
    pub fn registration_plan(
        &self,
        capabilities: WhiteboxDoorbellCapabilities,
    ) -> Result<WhiteboxDoorbellRegistrationPlan, WhiteboxDoorbellError> {
        if !self.mode.is_on() {
            return Ok(WhiteboxDoorbellRegistrationPlan::Disabled);
        }

        self.validate_max_payload_len()?;

        if !capabilities.register_doorbell_trap() {
            return Err(WhiteboxDoorbellError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL,
            });
        }
        if !capabilities.guest_memory_read() {
            return Err(WhiteboxDoorbellError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL,
            });
        }

        Ok(WhiteboxDoorbellRegistrationPlan::Install {
            trap: self.trap,
            callback_kind: PluginDeviceCallbackKind::WhiteboxDoorbell,
            max_payload_len: self.max_payload_len,
        })
    }

    /// Services one synchronous doorbell trap.
    ///
    /// The returned marker is stamped with `event.current_icount()`, and the
    /// guest bytes are obtained through [`GuestMemoryReader::read_guest_memory`]
    /// before the marker is recorded.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellError`] when white-box mode is disabled, the
    /// payload range is too large, the guest-memory API fails or returns a
    /// different byte count, or the marker sink rejects the observational entry.
    pub fn service_trap<R, S>(
        &self,
        reader: &mut R,
        sink: &mut S,
        event: WhiteboxDoorbellTrapEvent,
    ) -> Result<WhiteboxMarker, WhiteboxDoorbellError>
    where
        R: GuestMemoryReader + ?Sized,
        S: WhiteboxMarkerSink + ?Sized,
    {
        if !self.mode.is_on() {
            return Err(WhiteboxDoorbellError::TrapWhileDisabled);
        }
        self.validate_payload_range(event.payload_range())?;

        let payload = reader
            .read_guest_memory(
                event.vcpu_index(),
                event.current_icount(),
                event.payload_range(),
            )
            .map_err(|source| WhiteboxDoorbellError::GuestMemoryRead {
                range: event.payload_range(),
                source,
            })?;
        if payload.len() != event.payload_range().len() {
            return Err(WhiteboxDoorbellError::GuestMemoryReadLengthMismatch {
                requested_len: event.payload_range().len(),
                actual_len: payload.len(),
            });
        }

        let marker = WhiteboxMarker {
            marker_icount: event.current_icount(),
            vcpu_index: event.vcpu_index(),
            payload_range: event.payload_range(),
            payload,
        };
        sink.record_whitebox_marker(&marker).map_err(|source| {
            WhiteboxDoorbellError::MarkerSink {
                marker_icount: marker.marker_icount(),
                source,
            }
        })?;
        Ok(marker)
    }

    /// Requires the QEMU guest-memory write capability for host-to-guest inputs.
    ///
    /// The returned proof token is required by [`PluginWhiteboxDoorbell::inject_guest_input`],
    /// preventing reply writes from bypassing registration-time capability checks.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellError::InputWhileDisabled`] when white-box mode
    /// is off, [`WhiteboxDoorbellError::InvalidMaxPayloadLen`] for an invalid
    /// enabled payload bound, or
    /// [`WhiteboxDoorbellError::CapabilityUnavailable`] when the QEMU
    /// guest-memory write export is absent.
    pub fn require_guest_input_capability(
        &self,
        capabilities: WhiteboxDoorbellCapabilities,
    ) -> Result<WhiteboxGuestInputCapability, WhiteboxDoorbellError> {
        if !self.mode.is_on() {
            return Err(WhiteboxDoorbellError::InputWhileDisabled);
        }
        self.validate_max_payload_len()?;
        if !capabilities.guest_memory_write() {
            return Err(WhiteboxDoorbellError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_GUEST_MEMORY_WRITE_SYMBOL,
            });
        }
        Ok(WhiteboxGuestInputCapability { _private: () })
    }

    /// Delivers one host-to-guest white-box input at its exact delivery icount.
    ///
    /// This method is the safe core for marker acknowledgments, control writes,
    /// and later app-random replies. It does not write early: if the current
    /// icount is before the input's delivery icount, it returns `NotReady`.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellError`] when white-box mode is disabled, the
    /// input is late, its target range and payload length disagree, or the
    /// guest-input writer fails loudly.
    pub fn inject_guest_input<W>(
        &self,
        _capability: &WhiteboxGuestInputCapability,
        writer: &mut W,
        current_icount: u64,
        input: &WhiteboxGuestInput,
    ) -> Result<WhiteboxGuestInputOutcome, WhiteboxDoorbellError>
    where
        W: WhiteboxGuestInputWriter + ?Sized,
    {
        if !self.mode.is_on() {
            return Err(WhiteboxDoorbellError::InputWhileDisabled);
        }
        if input.payload_range().len() != input.payload().len() {
            return Err(WhiteboxDoorbellError::InputPayloadLengthMismatch {
                range_len: input.payload_range().len(),
                payload_len: input.payload().len(),
            });
        }
        self.validate_payload_range(input.payload_range())?;
        if current_icount < input.delivery_icount() {
            return Ok(WhiteboxGuestInputOutcome::NotReady {
                delivery_icount: input.delivery_icount(),
            });
        }
        if current_icount > input.delivery_icount() {
            return Err(WhiteboxDoorbellError::InputDeliveryAlreadyPassed {
                delivery_icount: input.delivery_icount(),
                current_icount,
            });
        }

        writer
            .write_whitebox_input(
                input.delivery_icount(),
                input.payload_range(),
                input.payload(),
            )
            .map_err(|source| WhiteboxDoorbellError::GuestInputWrite {
                delivery_icount: input.delivery_icount(),
                source,
            })?;
        Ok(WhiteboxGuestInputOutcome::Delivered(
            WhiteboxGuestInputInjection {
                delivery_icount: input.delivery_icount(),
                payload_range: input.payload_range(),
                payload_len: input.payload().len(),
            },
        ))
    }

    fn validate_max_payload_len(&self) -> Result<(), WhiteboxDoorbellError> {
        if self.max_payload_len == 0 || self.max_payload_len > MAX_FRAME_DATA {
            Err(WhiteboxDoorbellError::InvalidMaxPayloadLen {
                max_payload_len: self.max_payload_len,
                max_frame_data: MAX_FRAME_DATA,
            })
        } else {
            Ok(())
        }
    }

    fn validate_payload_range(&self, range: GuestMemoryRange) -> Result<(), WhiteboxDoorbellError> {
        self.validate_max_payload_len()?;
        if range.len() > self.max_payload_len {
            Err(WhiteboxDoorbellError::PayloadTooLarge {
                len: range.len(),
                max_payload_len: self.max_payload_len,
            })
        } else {
            Ok(())
        }
    }
}

/// Handles one safe white-box doorbell callback body.
///
/// # Errors
///
/// Returns [`WhiteboxDoorbellError`] when the trap is not enabled, guest-memory
/// reading fails, or marker recording fails.
pub fn handle_whitebox_doorbell_callback<R, S>(
    doorbell: &PluginWhiteboxDoorbell,
    reader: &mut R,
    sink: &mut S,
    event: WhiteboxDoorbellTrapEvent,
) -> Result<WhiteboxMarker, WhiteboxDoorbellError>
where
    R: GuestMemoryReader + ?Sized,
    S: WhiteboxMarkerSink + ?Sized,
{
    doorbell.service_trap(reader, sink, event)
}

/// Handles one safe white-box host-to-guest input callback body.
///
/// # Errors
///
/// Returns [`WhiteboxDoorbellError`] when delivery would violate the explicit
/// delivery-icount contract or when the guest write fails.
pub fn handle_whitebox_guest_input_callback<W>(
    doorbell: &PluginWhiteboxDoorbell,
    capability: &WhiteboxGuestInputCapability,
    writer: &mut W,
    current_icount: u64,
    input: &WhiteboxGuestInput,
) -> Result<WhiteboxGuestInputOutcome, WhiteboxDoorbellError>
where
    W: WhiteboxGuestInputWriter + ?Sized,
{
    doorbell.inject_guest_input(capability, writer, current_icount, input)
}

/// QEMU capabilities needed by the optional white-box channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WhiteboxDoorbellCapabilities {
    register_doorbell_trap: bool,
    guest_memory_read: bool,
    guest_memory_write: bool,
}

impl WhiteboxDoorbellCapabilities {
    /// Returns an empty capability set.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            register_doorbell_trap: false,
            guest_memory_read: false,
            guest_memory_write: false,
        }
    }

    /// Returns capabilities sufficient for guest-to-host marker delivery.
    #[must_use]
    pub const fn guest_to_host() -> Self {
        Self {
            register_doorbell_trap: true,
            guest_memory_read: true,
            guest_memory_write: false,
        }
    }

    /// Returns capabilities sufficient for bidirectional white-box traffic.
    #[must_use]
    pub const fn bidirectional() -> Self {
        Self {
            register_doorbell_trap: true,
            guest_memory_read: true,
            guest_memory_write: true,
        }
    }

    /// Returns whether the reserved trap can be registered.
    #[must_use]
    pub const fn register_doorbell_trap(self) -> bool {
        self.register_doorbell_trap
    }

    /// Returns whether guest memory can be read through the QEMU plugin API.
    #[must_use]
    pub const fn guest_memory_read(self) -> bool {
        self.guest_memory_read
    }

    /// Returns whether guest memory can be written for white-box replies.
    #[must_use]
    pub const fn guest_memory_write(self) -> bool {
        self.guest_memory_write
    }
}

/// A registration decision for the optional doorbell trap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxDoorbellRegistrationPlan {
    /// White-box mode is off and no doorbell trap is installed.
    Disabled,
    /// White-box mode is on and the reserved trap must be installed.
    Install {
        /// Reserved instruction or port-I/O trap to install.
        trap: WhiteboxDoorbellTrap,
        /// Plugin callback family used for the trap.
        callback_kind: PluginDeviceCallbackKind,
        /// Maximum payload bytes read at one trap.
        max_payload_len: usize,
    },
}

impl WhiteboxDoorbellRegistrationPlan {
    /// Returns whether this plan installs a QEMU doorbell trap.
    #[must_use]
    pub const fn installs_trap(self) -> bool {
        matches!(self, Self::Install { .. })
    }

    /// Returns whether black-box operation remains functional without a trap.
    #[must_use]
    pub const fn black_box_remains_functional(self) -> bool {
        matches!(self, Self::Disabled)
    }
}

/// The reserved trap surface used by the white-box doorbell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxDoorbellTrap {
    /// x86_64 reserved port-I/O write.
    X86PortIo {
        /// Reserved port number chosen by the scenario.
        port: u16,
    },
    /// aarch64 reserved trap instruction.
    Aarch64ReservedInstruction {
        /// Reserved immediate encoded in the trap instruction.
        immediate: u16,
    },
}

/// The address space used for a guest-memory payload range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestMemoryAddressSpace {
    /// Guest physical address or a pinned identity-mapped shared page.
    Physical,
    /// Guest virtual address translated by QEMU at the trap.
    Virtual,
}

/// An opaque range in guest memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMemoryRange {
    address_space: GuestMemoryAddressSpace,
    guest_address: u64,
    len: usize,
}

impl GuestMemoryRange {
    /// Builds a guest-memory range.
    #[must_use]
    pub const fn new(
        address_space: GuestMemoryAddressSpace,
        guest_address: u64,
        len: usize,
    ) -> Self {
        Self {
            address_space,
            guest_address,
            len,
        }
    }

    /// Returns whether the address is physical or virtual.
    #[must_use]
    pub const fn address_space(self) -> GuestMemoryAddressSpace {
        self.address_space
    }

    /// Returns the guest address, opaque to Rust and meaningful only to QEMU.
    #[must_use]
    pub const fn guest_address(self) -> u64 {
        self.guest_address
    }

    /// Returns the number of bytes in the range.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns whether the range is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// One synchronous reserved-instruction or port-I/O doorbell event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhiteboxDoorbellTrapEvent {
    vcpu_index: u32,
    current_icount: u64,
    payload_range: GuestMemoryRange,
}

impl WhiteboxDoorbellTrapEvent {
    /// Builds a doorbell trap event from QEMU callback metadata.
    #[must_use]
    pub const fn new(
        vcpu_index: u32,
        current_icount: u64,
        payload_range: GuestMemoryRange,
    ) -> Self {
        Self {
            vcpu_index,
            current_icount,
            payload_range,
        }
    }

    /// Returns the vCPU that retired the doorbell instruction.
    #[must_use]
    pub const fn vcpu_index(self) -> u32 {
        self.vcpu_index
    }

    /// Returns the exact current icount stamped onto the marker.
    #[must_use]
    pub const fn current_icount(self) -> u64 {
        self.current_icount
    }

    /// Returns the guest-memory payload range to read at this trap.
    #[must_use]
    pub const fn payload_range(self) -> GuestMemoryRange {
        self.payload_range
    }
}

/// An icount-stamped white-box marker read from guest memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxMarker {
    marker_icount: u64,
    vcpu_index: u32,
    payload_range: GuestMemoryRange,
    payload: Vec<u8>,
}

impl WhiteboxMarker {
    /// Returns the exact doorbell icount stamped on the marker.
    #[must_use]
    pub const fn marker_icount(&self) -> u64 {
        self.marker_icount
    }

    /// Returns the vCPU that retired the doorbell instruction.
    #[must_use]
    pub const fn vcpu_index(&self) -> u32 {
        self.vcpu_index
    }

    /// Returns the guest-memory range used for the payload read.
    #[must_use]
    pub const fn payload_range(&self) -> GuestMemoryRange {
        self.payload_range
    }

    /// Returns the raw doorbell bytes read through QEMU's guest-memory API.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A backend for reading guest memory at the doorbell trap.
pub trait GuestMemoryReader {
    /// Reads one guest-memory range through QEMU's plugin memory API.
    ///
    /// # Errors
    ///
    /// Returns [`GuestMemoryReadError`] when QEMU cannot snapshot the requested
    /// guest bytes at the trap icount.
    fn read_guest_memory(
        &mut self,
        vcpu_index: u32,
        current_icount: u64,
        range: GuestMemoryRange,
    ) -> Result<Vec<u8>, GuestMemoryReadError>;
}

/// A loud guest-memory read failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("guest-memory read failed: {message}")]
pub struct GuestMemoryReadError {
    message: String,
}

impl GuestMemoryReadError {
    /// Builds a guest-memory read error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the backend diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// A sink for observational white-box marker entries.
pub trait WhiteboxMarkerSink {
    /// Records one marker as observational output.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxMarkerSinkError`] when the event-log path cannot accept
    /// the marker and must fail loudly.
    fn record_whitebox_marker(
        &mut self,
        marker: &WhiteboxMarker,
    ) -> Result<(), WhiteboxMarkerSinkError>;
}

/// A loud marker-sink failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("white-box marker sink failed: {message}")]
pub struct WhiteboxMarkerSinkError {
    message: String,
}

impl WhiteboxMarkerSinkError {
    /// Builds a marker-sink error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the backend diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// One explicit host-to-guest white-box input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxGuestInput {
    delivery_icount: u64,
    payload_range: GuestMemoryRange,
    payload: Vec<u8>,
}

impl WhiteboxGuestInput {
    /// Builds a host-to-guest white-box input.
    #[must_use]
    pub fn new(delivery_icount: u64, payload_range: GuestMemoryRange, payload: Vec<u8>) -> Self {
        Self {
            delivery_icount,
            payload_range,
            payload,
        }
    }

    /// Returns the exact icount at which the input may become visible.
    #[must_use]
    pub const fn delivery_icount(&self) -> u64 {
        self.delivery_icount
    }

    /// Returns the guest-memory range written at delivery.
    #[must_use]
    pub const fn payload_range(&self) -> GuestMemoryRange {
        self.payload_range
    }

    /// Returns the payload written into guest memory.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Proof that QEMU's guest-memory write API was available for white-box input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhiteboxGuestInputCapability {
    _private: (),
}

/// A backend for writing white-box input into guest memory.
pub trait WhiteboxGuestInputWriter {
    /// Writes one white-box input through QEMU's guest-memory API.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxGuestInputWriteError`] when QEMU cannot make the input
    /// visible at the requested delivery icount.
    fn write_whitebox_input(
        &mut self,
        delivery_icount: u64,
        range: GuestMemoryRange,
        payload: &[u8],
    ) -> Result<(), WhiteboxGuestInputWriteError>;
}

/// A loud white-box guest-input write failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("white-box guest input write failed: {message}")]
pub struct WhiteboxGuestInputWriteError {
    message: String,
}

impl WhiteboxGuestInputWriteError {
    /// Builds a guest-input write error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the backend diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Result of attempting one white-box guest input delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WhiteboxGuestInputOutcome {
    /// The input is still in the future and must not be visible yet.
    NotReady {
        /// The pending explicit delivery icount.
        delivery_icount: u64,
    },
    /// The input was delivered at its exact icount.
    Delivered(WhiteboxGuestInputInjection),
}

/// Metadata for one delivered white-box guest input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhiteboxGuestInputInjection {
    delivery_icount: u64,
    payload_range: GuestMemoryRange,
    payload_len: usize,
}

impl WhiteboxGuestInputInjection {
    /// Returns the exact icount at which the input was written.
    #[must_use]
    pub const fn delivery_icount(self) -> u64 {
        self.delivery_icount
    }

    /// Returns the guest-memory range written.
    #[must_use]
    pub const fn payload_range(self) -> GuestMemoryRange {
        self.payload_range
    }

    /// Returns the number of payload bytes written.
    #[must_use]
    pub const fn payload_len(self) -> usize {
        self.payload_len
    }
}

/// An error produced by white-box doorbell handling.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WhiteboxDoorbellError {
    /// A required QEMU white-box capability is unavailable.
    #[error("required white-box capability {symbol} is unavailable")]
    CapabilityUnavailable {
        /// The missing capability label.
        symbol: &'static str,
    },
    /// The configured maximum payload length is unusable.
    #[error("white-box max payload length {max_payload_len} must be in 1..={max_frame_data}")]
    InvalidMaxPayloadLen {
        /// Configured maximum payload length.
        max_payload_len: usize,
        /// Shared-memory frame payload ceiling.
        max_frame_data: usize,
    },
    /// A trap fired even though white-box mode is disabled.
    #[error("white-box doorbell trap fired while white-box mode is disabled")]
    TrapWhileDisabled,
    /// A doorbell payload exceeds the configured bounded atomic-read size.
    #[error("white-box payload length {len} exceeds configured maximum {max_payload_len}")]
    PayloadTooLarge {
        /// Guest-requested payload length.
        len: usize,
        /// Configured maximum payload length.
        max_payload_len: usize,
    },
    /// Reading guest memory through QEMU failed.
    #[error("white-box guest-memory read failed for {range:?}: {source}")]
    GuestMemoryRead {
        /// The guest-memory range requested from QEMU.
        range: GuestMemoryRange,
        /// The backend read failure.
        source: GuestMemoryReadError,
    },
    /// The guest-memory API returned a byte count different from the request.
    #[error(
        "white-box guest-memory read returned {actual_len} bytes for requested length {requested_len}"
    )]
    GuestMemoryReadLengthMismatch {
        /// The requested byte count.
        requested_len: usize,
        /// The returned byte count.
        actual_len: usize,
    },
    /// Recording the observational marker failed.
    #[error("white-box marker at icount {marker_icount} could not be recorded: {source}")]
    MarkerSink {
        /// The marker icount.
        marker_icount: u64,
        /// The sink failure.
        source: WhiteboxMarkerSinkError,
    },
    /// A host-to-guest white-box input was attempted while disabled.
    #[error("white-box guest input attempted while white-box mode is disabled")]
    InputWhileDisabled,
    /// The host-to-guest input range and payload length disagree.
    #[error("white-box guest input range length {range_len} does not match payload {payload_len}")]
    InputPayloadLengthMismatch {
        /// Guest-memory range length.
        range_len: usize,
        /// Payload byte count.
        payload_len: usize,
    },
    /// A host-to-guest input delivery icount was already passed.
    #[error(
        "white-box guest input delivery icount {delivery_icount} already passed at current icount {current_icount}"
    )]
    InputDeliveryAlreadyPassed {
        /// The missed delivery icount.
        delivery_icount: u64,
        /// The current plugin icount.
        current_icount: u64,
    },
    /// Writing host-to-guest input through QEMU failed.
    #[error("white-box guest input at icount {delivery_icount} write failed: {source}")]
    GuestInputWrite {
        /// The delivery icount being written.
        delivery_icount: u64,
        /// The backend write failure.
        source: WhiteboxGuestInputWriteError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitebox_registration_off_mode_installs_no_trap_and_preserves_black_box() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::Off,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );

        let plan = match doorbell.registration_plan(WhiteboxDoorbellCapabilities::none()) {
            Ok(plan) => plan,
            Err(error) => panic!("off-mode should not require capabilities: {error}"),
        };

        assert_eq!(plan, WhiteboxDoorbellRegistrationPlan::Disabled);
        assert!(!plan.installs_trap());
        assert!(plan.black_box_remains_functional());
    }

    #[test]
    fn whitebox_registration_off_mode_bypasses_whitebox_payload_validation() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::Off,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            0,
        );

        assert_eq!(
            doorbell.registration_plan(WhiteboxDoorbellCapabilities::none()),
            Ok(WhiteboxDoorbellRegistrationPlan::Disabled)
        );
    }

    #[test]
    fn whitebox_registration_on_mode_requires_trap_and_memory_read_capabilities() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );

        assert_eq!(
            doorbell.registration_plan(WhiteboxDoorbellCapabilities::none()),
            Err(WhiteboxDoorbellError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL,
            })
        );
        assert_eq!(
            doorbell.registration_plan(WhiteboxDoorbellCapabilities {
                register_doorbell_trap: true,
                guest_memory_read: false,
                guest_memory_write: false,
            }),
            Err(WhiteboxDoorbellError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL,
            })
        );

        let plan = match doorbell.registration_plan(WhiteboxDoorbellCapabilities::guest_to_host()) {
            Ok(plan) => plan,
            Err(error) => panic!("on-mode capabilities should produce install plan: {error}"),
        };
        assert_eq!(
            plan,
            WhiteboxDoorbellRegistrationPlan::Install {
                trap: WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
                callback_kind: PluginDeviceCallbackKind::WhiteboxDoorbell,
                max_payload_len: 128,
            }
        );
        assert!(plan.installs_trap());
        assert!(!plan.black_box_remains_functional());
    }

    #[test]
    fn whitebox_doorbell_reads_guest_memory_via_api_and_stamps_current_icount() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 4);
        let event = WhiteboxDoorbellTrapEvent::new(2, 777, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(b"mark".to_vec());
        let mut sink = RecordingMarkerSink::default();

        let marker =
            match handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event) {
                Ok(marker) => marker,
                Err(error) => panic!("doorbell should be serviced: {error}"),
            };

        assert_eq!(reader.calls, vec![(2, 777, range)]);
        assert_eq!(marker.marker_icount(), 777);
        assert_eq!(marker.vcpu_index(), 2);
        assert_eq!(marker.payload_range(), range);
        assert_eq!(marker.payload(), b"mark");
        assert_eq!(sink.markers, vec![marker]);
    }

    #[test]
    fn whitebox_doorbell_rejects_oversized_payload_before_guest_memory_read() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            3,
        );
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 4);
        let event = WhiteboxDoorbellTrapEvent::new(0, 10, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(b"mark".to_vec());
        let mut sink = RecordingMarkerSink::default();

        assert_eq!(
            handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
            Err(WhiteboxDoorbellError::PayloadTooLarge {
                len: 4,
                max_payload_len: 3,
            })
        );
        assert!(reader.calls.is_empty());
        assert!(sink.markers.is_empty());
    }

    #[test]
    fn whitebox_doorbell_read_failure_records_no_marker() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::Aarch64ReservedInstruction { immediate: 0x4c1 },
            128,
        );
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x2000, 4);
        let event = WhiteboxDoorbellTrapEvent::new(1, 44, range);
        let mut reader = RecordingGuestMemoryReader::failing("translation failed");
        let mut sink = RecordingMarkerSink::default();

        assert_eq!(
            handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
            Err(WhiteboxDoorbellError::GuestMemoryRead {
                range,
                source: GuestMemoryReadError::new("translation failed"),
            })
        );
        assert_eq!(reader.calls, vec![(1, 44, range)]);
        assert!(sink.markers.is_empty());
    }

    #[test]
    fn whitebox_doorbell_trap_while_disabled_is_loud() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::Off,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 4);
        let event = WhiteboxDoorbellTrapEvent::new(0, 10, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(b"mark".to_vec());
        let mut sink = RecordingMarkerSink::default();

        assert_eq!(
            handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
            Err(WhiteboxDoorbellError::TrapWhileDisabled)
        );
        assert!(reader.calls.is_empty());
        assert!(sink.markers.is_empty());
    }

    #[test]
    fn whitebox_guest_input_is_not_visible_before_delivery_icount() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let capability = guest_input_capability(&doorbell);
        let input = input_at(50, b"ack");
        let mut writer = RecordingGuestInputWriter::default();

        assert_eq!(
            handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 49, &input),
            Ok(WhiteboxGuestInputOutcome::NotReady {
                delivery_icount: 50,
            })
        );
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn whitebox_guest_input_writes_at_exact_delivery_icount_only() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let capability = guest_input_capability(&doorbell);
        let input = input_at(50, b"ack");
        let mut writer = RecordingGuestInputWriter::default();

        let outcome = match handle_whitebox_guest_input_callback(
            &doorbell,
            &capability,
            &mut writer,
            50,
            &input,
        ) {
            Ok(outcome) => outcome,
            Err(error) => panic!("input should deliver exactly at icount: {error}"),
        };

        assert_eq!(
            outcome,
            WhiteboxGuestInputOutcome::Delivered(WhiteboxGuestInputInjection {
                delivery_icount: 50,
                payload_range: input.payload_range(),
                payload_len: 3,
            })
        );
        assert_eq!(
            writer.writes,
            vec![(50, input.payload_range(), b"ack".to_vec())]
        );
    }

    #[test]
    fn whitebox_guest_input_rejects_oversized_payload_before_guest_memory_write() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            3,
        );
        let capability = guest_input_capability(&doorbell);
        let input = input_at(50, b"toolong");
        let mut writer = RecordingGuestInputWriter::default();

        assert_eq!(
            handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 50, &input),
            Err(WhiteboxDoorbellError::PayloadTooLarge {
                len: 7,
                max_payload_len: 3,
            })
        );
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn whitebox_guest_input_rejects_late_delivery() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let capability = guest_input_capability(&doorbell);
        let input = input_at(50, b"ack");
        let mut writer = RecordingGuestInputWriter::default();

        assert_eq!(
            handle_whitebox_guest_input_callback(&doorbell, &capability, &mut writer, 51, &input),
            Err(WhiteboxDoorbellError::InputDeliveryAlreadyPassed {
                delivery_icount: 50,
                current_icount: 51,
            })
        );
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn whitebox_guest_input_while_disabled_is_loud() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::Off,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );

        assert_eq!(
            doorbell.require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional()),
            Err(WhiteboxDoorbellError::InputWhileDisabled)
        );
    }

    #[test]
    fn whitebox_guest_input_requires_qemu_guest_memory_write_capability() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );

        assert_eq!(
            doorbell.require_guest_input_capability(WhiteboxDoorbellCapabilities::guest_to_host()),
            Err(WhiteboxDoorbellError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_GUEST_MEMORY_WRITE_SYMBOL,
            })
        );
        assert!(
            doorbell
                .require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional())
                .is_ok()
        );
    }

    fn input_at(delivery_icount: u64, payload: &[u8]) -> WhiteboxGuestInput {
        WhiteboxGuestInput::new(
            delivery_icount,
            GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x3000, payload.len()),
            payload.to_vec(),
        )
    }

    fn guest_input_capability(doorbell: &PluginWhiteboxDoorbell) -> WhiteboxGuestInputCapability {
        match doorbell.require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional())
        {
            Ok(capability) => capability,
            Err(error) => panic!("bidirectional capability should be available: {error}"),
        }
    }

    struct RecordingGuestMemoryReader {
        calls: Vec<(u32, u64, GuestMemoryRange)>,
        result: Result<Vec<u8>, GuestMemoryReadError>,
    }

    impl RecordingGuestMemoryReader {
        fn with_payload(payload: Vec<u8>) -> Self {
            Self {
                calls: Vec::new(),
                result: Ok(payload),
            }
        }

        fn failing(message: impl Into<String>) -> Self {
            Self {
                calls: Vec::new(),
                result: Err(GuestMemoryReadError::new(message)),
            }
        }
    }

    impl GuestMemoryReader for RecordingGuestMemoryReader {
        fn read_guest_memory(
            &mut self,
            vcpu_index: u32,
            current_icount: u64,
            range: GuestMemoryRange,
        ) -> Result<Vec<u8>, GuestMemoryReadError> {
            self.calls.push((vcpu_index, current_icount, range));
            self.result.clone()
        }
    }

    #[derive(Default)]
    struct RecordingMarkerSink {
        markers: Vec<WhiteboxMarker>,
    }

    impl WhiteboxMarkerSink for RecordingMarkerSink {
        fn record_whitebox_marker(
            &mut self,
            marker: &WhiteboxMarker,
        ) -> Result<(), WhiteboxMarkerSinkError> {
            self.markers.push(marker.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingGuestInputWriter {
        writes: Vec<(u64, GuestMemoryRange, Vec<u8>)>,
    }

    impl WhiteboxGuestInputWriter for RecordingGuestInputWriter {
        fn write_whitebox_input(
            &mut self,
            delivery_icount: u64,
            range: GuestMemoryRange,
            payload: &[u8],
        ) -> Result<(), WhiteboxGuestInputWriteError> {
            self.writes.push((delivery_icount, range, payload.to_vec()));
            Ok(())
        }
    }
}
