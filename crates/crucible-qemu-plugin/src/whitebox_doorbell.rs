//! Optional white-box doorbell trap callback core.
//!
//! White-box mode is opt-in. When disabled, this module's registration plan
//! installs no trap and leaves black-box operation untouched. When enabled, the
//! safe callback body reads the guest payload only through a guest-memory API
//! adapter at the trap's current icount, records an observational marker, and
//! routes any host-to-guest reply through an explicit delivery-icount gate.

pub use crucible_protocol::{
    GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS, GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS,
    WHITEBOX_DOORBELL_AARCH64_ABI, WHITEBOX_DOORBELL_AARCH64_HLT_BYTES,
    WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE, WHITEBOX_DOORBELL_ABIS,
    WHITEBOX_DOORBELL_FRAME_HEADER_LEN, WHITEBOX_DOORBELL_FRAME_MAGIC,
    WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE, WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
    WHITEBOX_DOORBELL_KIND_ASSERTION, WHITEBOX_DOORBELL_KIND_COVERAGE,
    WHITEBOX_DOORBELL_KIND_EVENT, WHITEBOX_DOORBELL_KIND_LIFECYCLE,
    WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST, WHITEBOX_DOORBELL_LIFECYCLE_SETUP_COMPLETE,
    WHITEBOX_DOORBELL_LIFECYCLE_TEST_DONE, WHITEBOX_DOORBELL_MARKER_KIND_COUNT,
    WHITEBOX_DOORBELL_PROTOCOL_VERSION, WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES,
    WHITEBOX_DOORBELL_X86_64_ABI, WHITEBOX_DOORBELL_X86_64_OUT_DX_EAX_BYTES,
    WHITEBOX_DOORBELL_X86_64_RESERVED_PORT, WhiteboxAssertionMarkerBody,
    WhiteboxAssertionMarkerFlavor, WhiteboxCoverageMarkerBody, WhiteboxDoorbellAbi,
    WhiteboxDoorbellArchitecture, WhiteboxDoorbellFrame, WhiteboxDoorbellFrameDecodeError,
    WhiteboxDoorbellFrameEncodeError, WhiteboxDoorbellFrameGoldenVector,
    WhiteboxDoorbellInstruction, WhiteboxDoorbellMarkerKind, WhiteboxDoorbellTrapAbi,
    WhiteboxEventMarkerBody, WhiteboxLifecycleMarkerEvent, WhiteboxMarkerDetail,
    WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError, WhiteboxMarkerPayloadEncodeError,
    WhiteboxMarkerPayloadGoldenVector, WhiteboxRandomRequestBody, decode_whitebox_marker_payload,
    encode_aarch64_hlt_instruction, encode_whitebox_doorbell_frame, encode_whitebox_marker_frame,
    encode_whitebox_marker_payload_body, encode_x86_64_out_dx_eax_instruction,
    whitebox_doorbell_abi_for_architecture,
};
use crucible_shmem::MAX_FRAME_DATA;
use thiserror::Error;

use crate::{PluginDeviceCallbackKind, PluginSwitch};

/// QEMU plugin API label for translation-block instrumentation.
pub const QEMU_PLUGIN_DOORBELL_TRANSLATION_SYMBOL: &str = "qemu_plugin_register_vcpu_tb_trans_cb";
/// QEMU plugin API label for installing memory callbacks on translated instructions.
pub const QEMU_PLUGIN_DOORBELL_MEM_CB_SYMBOL: &str = "qemu_plugin_register_vcpu_mem_cb";
/// QEMU plugin API label for resolving a memory callback's hardware address.
pub const QEMU_PLUGIN_GET_HWADDR_SYMBOL: &str = "qemu_plugin_get_hwaddr";
/// QEMU plugin API label for checking whether a memory callback targets I/O space.
pub const QEMU_PLUGIN_IO_ADDRESS_QUERY_SYMBOL: &str = "qemu_plugin_hwaddr_is_io";
/// QEMU plugin API label for extracting a hardware-address physical address.
pub const QEMU_PLUGIN_HWADDR_PHYS_ADDR_SYMBOL: &str = "qemu_plugin_hwaddr_phys_addr";
/// QEMU plugin API label for reading a register during a callback.
pub const QEMU_PLUGIN_READ_REGISTER_SYMBOL: &str = "qemu_plugin_read_register";
/// QEMU capability label for registering the reserved white-box doorbell trap.
pub const QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL: &str = QEMU_PLUGIN_DOORBELL_MEM_CB_SYMBOL;
/// QEMU capability label for reading guest memory at the trap icount.
pub const QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL: &str = "qemu_plugin_read_memory_vaddr";
/// QEMU capability label for writing white-box replies into guest memory.
pub const QEMU_PLUGIN_GUEST_MEMORY_WRITE_SYMBOL: &str = "qemu_plugin_guest_memory_write";
/// Maximum random-request reply width in bytes.
pub const WHITEBOX_APP_RANDOM_MAX_WIDTH_BYTES: u8 =
    WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES;

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
    const fn new(mode: PluginSwitch, trap: WhiteboxDoorbellTrap, max_payload_len: usize) -> Self {
        Self {
            mode,
            trap,
            max_payload_len,
        }
    }

    /// Builds doorbell state from a single-source architecture ABI entry.
    #[must_use]
    pub const fn from_abi(
        mode: PluginSwitch,
        abi: WhiteboxDoorbellAbi,
        max_payload_len: usize,
    ) -> Self {
        Self::new(
            mode,
            WhiteboxDoorbellTrap::from_abi(abi.trap()),
            max_payload_len,
        )
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
    /// On-mode requires a setup-time non-collision validation for the configured
    /// trap, the upstream memory-callback trap surface, and the guest-memory read
    /// surface before it can install the callback.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellError::InvalidMaxPayloadLen`] when the payload
    /// bound is zero or larger than the shared-memory frame bound. Returns a
    /// setup validation error when the reserved trap was not checked, collided
    /// with the guest's real device or instruction surface, or was checked for a
    /// different trap. Returns
    /// [`WhiteboxDoorbellError::CapabilityUnavailable`] when white-box mode is
    /// enabled but a required QEMU capability is absent.
    pub fn registration_plan(
        &self,
        capabilities: WhiteboxDoorbellCapabilities,
        setup_validation: WhiteboxDoorbellSetupValidation,
    ) -> Result<WhiteboxDoorbellRegistrationPlan, WhiteboxDoorbellError> {
        if !self.mode.is_on() {
            return Ok(WhiteboxDoorbellRegistrationPlan::Disabled);
        }

        self.validate_max_payload_len()?;
        self.validate_setup_collision(setup_validation)?;

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
    /// guest bytes are obtained through [`GuestMemoryReader::read_guest_memory`],
    /// decoded as a [`WhiteboxDoorbellFrame`], and recorded as the decoded
    /// marker kind plus body bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellError`] when white-box mode is disabled, the
    /// payload range is too large, the guest-memory API fails or returns a
    /// different byte count, the frame is malformed, or the marker sink rejects
    /// the observational entry.
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
        let frame = WhiteboxDoorbellFrame::decode(&payload).map_err(|source| {
            WhiteboxDoorbellError::DoorbellFrameDecode {
                marker_icount: event.current_icount(),
                source,
            }
        })?;
        let decoded_payload = decode_whitebox_marker_payload(&frame).map_err(|source| {
            WhiteboxDoorbellError::DoorbellMarkerDecode {
                marker_icount: event.current_icount(),
                source,
            }
        })?;
        if !decoded_payload.is_observational() {
            return Err(WhiteboxDoorbellError::NonObservationalMarkerKind {
                marker_icount: event.current_icount(),
                kind: decoded_payload.kind(),
            });
        }

        let marker = WhiteboxMarker {
            marker_icount: event.current_icount(),
            vcpu_index: event.vcpu_index(),
            payload_range: event.payload_range(),
            kind: frame.kind(),
            payload: frame.payload().to_vec(),
            decoded_payload,
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

    fn validate_setup_collision(
        &self,
        setup_validation: WhiteboxDoorbellSetupValidation,
    ) -> Result<(), WhiteboxDoorbellError> {
        if setup_validation.trap() != self.trap {
            return Err(WhiteboxDoorbellError::SetupValidationTrapMismatch {
                configured: self.trap,
                validated: setup_validation.trap(),
            });
        }

        match setup_validation.outcome() {
            WhiteboxDoorbellSetupOutcome::Unchecked => {
                Err(WhiteboxDoorbellError::SetupCollisionUnchecked { trap: self.trap })
            }
            WhiteboxDoorbellSetupOutcome::CollisionFree => Ok(()),
            WhiteboxDoorbellSetupOutcome::Collision { collision } => {
                Err(WhiteboxDoorbellError::SetupCollision {
                    trap: self.trap,
                    collision,
                })
            }
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

/// Handles one app-controlled randomness doorbell callback body.
///
/// The request is read through the same trap-icount guest-memory API as ordinary
/// white-box markers, decoded as a closed `random_request` frame, served through
/// the provided decision source, and written back through the host-to-guest
/// injection gate at the trap icount.
///
/// Malformed frames are returned as [`AppRandomDoorbellOutcome::Dropped`] so the
/// caller can record a decode diagnostic without drawing from the decision
/// source or writing into guest memory.
///
/// # Errors
///
/// Returns [`AppRandomDoorbellError`] when the white-box capability path fails,
/// the decision source cannot record the draw, or the reply cannot be delivered
/// at the trap icount.
pub fn handle_whitebox_app_random_callback<R, D, W>(
    doorbell: &PluginWhiteboxDoorbell,
    capability: &WhiteboxGuestInputCapability,
    reader: &mut R,
    decision_source: &mut D,
    writer: &mut W,
    node_name: &str,
    event: WhiteboxDoorbellTrapEvent,
) -> Result<AppRandomDoorbellOutcome, AppRandomDoorbellError>
where
    R: GuestMemoryReader + ?Sized,
    D: AppRandomDecisionSource + ?Sized,
    W: WhiteboxGuestInputWriter + ?Sized,
{
    let payload =
        read_doorbell_payload(doorbell, reader, event).map_err(AppRandomDoorbellError::Doorbell)?;
    let frame = match WhiteboxDoorbellFrame::decode(&payload) {
        Ok(frame) => frame,
        Err(error) => {
            return Ok(AppRandomDoorbellOutcome::Dropped {
                diagnostic: AppRandomDecodeDiagnostic::from(error),
            });
        }
    };
    let request = match AppRandomDoorbellRequest::from_frame(node_name, event, frame) {
        Ok(request) => request,
        Err(diagnostic) => return Ok(AppRandomDoorbellOutcome::Dropped { diagnostic }),
    };

    let decision = decision_source
        .serve_app_random(&request)
        .map_err(|source| AppRandomDoorbellError::DecisionSource {
            node_name: request.node_name().to_owned(),
            stream_tag: request.stream_tag().to_owned(),
            width_bits: request.width_bits(),
            source,
        })?;
    validate_decision_record(&request, &decision)?;

    let reply = WhiteboxGuestInput::new(
        request.trap_icount(),
        request.reply_range(),
        app_random_reply_payload(decision.value(), request.width_bytes()),
    );
    let outcome = doorbell
        .inject_guest_input(capability, writer, request.trap_icount(), &reply)
        .map_err(AppRandomDoorbellError::Doorbell)?;
    match outcome {
        WhiteboxGuestInputOutcome::Delivered(injection) => {
            Ok(AppRandomDoorbellOutcome::Served(AppRandomDoorbellService {
                request,
                decision,
                injection,
            }))
        }
        WhiteboxGuestInputOutcome::NotReady { delivery_icount } => {
            Err(AppRandomDoorbellError::ReplyNotDelivered { delivery_icount })
        }
    }
}

fn read_doorbell_payload<R>(
    doorbell: &PluginWhiteboxDoorbell,
    reader: &mut R,
    event: WhiteboxDoorbellTrapEvent,
) -> Result<Vec<u8>, WhiteboxDoorbellError>
where
    R: GuestMemoryReader + ?Sized,
{
    if !doorbell.mode.is_on() {
        return Err(WhiteboxDoorbellError::TrapWhileDisabled);
    }
    doorbell.validate_payload_range(event.payload_range())?;
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
    Ok(payload)
}

/// One decoded app-controlled randomness request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRandomDoorbellRequest {
    node_name: String,
    guest_request_id: u32,
    trap_icount: u64,
    width_bytes: u8,
    stream_tag: String,
    reply_range: GuestMemoryRange,
}

impl AppRandomDoorbellRequest {
    fn from_frame(
        node_name: &str,
        event: WhiteboxDoorbellTrapEvent,
        frame: WhiteboxDoorbellFrame,
    ) -> Result<Self, AppRandomDecodeDiagnostic> {
        if frame.kind() != WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST {
            return Err(AppRandomDecodeDiagnostic::new(
                AppRandomDecodeDiagnosticKind::UnexpectedKind {
                    expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                    actual: frame.kind(),
                },
            ));
        }

        let payload_len = frame.payload().len();
        let payload = match decode_whitebox_marker_payload(&frame) {
            Ok(WhiteboxMarkerPayload::RandomRequest(payload)) => payload,
            Ok(payload) => {
                return Err(AppRandomDecodeDiagnostic::new(
                    AppRandomDecodeDiagnosticKind::UnexpectedKind {
                        expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                        actual: payload.kind().wire_value(),
                    },
                ));
            }
            Err(error) => {
                return Err(AppRandomDecodeDiagnostic::from_marker_payload_error(
                    error,
                    payload_len,
                ));
            }
        };

        let guest_request_id = payload.request_id;
        let width_bytes = payload.width_bytes;
        let stream_tag = payload.stream_tag;

        Ok(Self {
            node_name: node_name.to_owned(),
            guest_request_id,
            trap_icount: event.current_icount(),
            width_bytes,
            stream_tag,
            reply_range: GuestMemoryRange::new(
                event.payload_range().address_space(),
                event.payload_range().guest_address(),
                usize::from(width_bytes),
            ),
        })
    }

    /// Returns the canonical node name whose guest requested the draw.
    #[must_use]
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    /// Returns the guest-supplied request identifier.
    #[must_use]
    pub const fn guest_request_id(&self) -> u32 {
        self.guest_request_id
    }

    /// Returns the doorbell trap icount used as the reply delivery icount.
    #[must_use]
    pub const fn trap_icount(&self) -> u64 {
        self.trap_icount
    }

    /// Returns the requested reply width in bytes.
    #[must_use]
    pub const fn width_bytes(&self) -> u8 {
        self.width_bytes
    }

    /// Returns the requested decision width in bits.
    #[must_use]
    pub const fn width_bits(&self) -> u8 {
        self.width_bytes * 8
    }

    /// Returns the guest-provided decision stream tag.
    #[must_use]
    pub fn stream_tag(&self) -> &str {
        &self.stream_tag
    }

    /// Returns the guest-memory range used for the host-to-guest reply.
    #[must_use]
    pub const fn reply_range(&self) -> GuestMemoryRange {
        self.reply_range
    }
}

/// Decision metadata returned after recording `Decision::AppRandom`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRandomDecisionRecord {
    node_name: String,
    stream_tag: String,
    request_id: u64,
    width_bits: u8,
    value: u64,
}

impl AppRandomDecisionRecord {
    /// Builds a decision record matching the engine's `Decision::AppRandom` data.
    #[must_use]
    pub fn new(
        node_name: impl Into<String>,
        stream_tag: impl Into<String>,
        request_id: u64,
        width_bits: u8,
        value: u64,
    ) -> Self {
        Self {
            node_name: node_name.into(),
            stream_tag: stream_tag.into(),
            request_id,
            width_bits,
            value,
        }
    }

    /// Returns the node recorded in the decision.
    #[must_use]
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    /// Returns the stream recorded in the decision.
    #[must_use]
    pub fn stream_tag(&self) -> &str {
        &self.stream_tag
    }

    /// Returns the per-stream request id recorded in the decision.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Returns the recorded draw width in bits.
    #[must_use]
    pub const fn width_bits(&self) -> u8 {
        self.width_bits
    }

    /// Returns the deterministic value served to the guest.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }
}

/// Source that records and serves app-controlled randomness decisions.
pub trait AppRandomDecisionSource {
    /// Draws from the seeded decision source and records `Decision::AppRandom`.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomDecisionError`] when the engine-side recorder cannot
    /// serve the request.
    fn serve_app_random(
        &mut self,
        request: &AppRandomDoorbellRequest,
    ) -> Result<AppRandomDecisionRecord, AppRandomDecisionError>;
}

/// A failure from the engine-side app-random decision source.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("app-random decision source failed: {message}")]
pub struct AppRandomDecisionError {
    message: String,
}

impl AppRandomDecisionError {
    /// Builds an app-random decision source failure.
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

/// Result of handling one app-random doorbell request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppRandomDoorbellOutcome {
    /// A valid request was recorded and replied to at the trap icount.
    Served(AppRandomDoorbellService),
    /// A malformed or non-random-request frame was diagnosed and dropped.
    Dropped {
        /// The decode diagnostic to record as observational output.
        diagnostic: AppRandomDecodeDiagnostic,
    },
}

/// Metadata for one served app-random request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRandomDoorbellService {
    request: AppRandomDoorbellRequest,
    decision: AppRandomDecisionRecord,
    injection: WhiteboxGuestInputInjection,
}

impl AppRandomDoorbellService {
    /// Returns the decoded guest request.
    #[must_use]
    pub const fn request(&self) -> &AppRandomDoorbellRequest {
        &self.request
    }

    /// Returns the recorded `Decision::AppRandom` metadata.
    #[must_use]
    pub const fn decision(&self) -> &AppRandomDecisionRecord {
        &self.decision
    }

    /// Returns the exact host-to-guest injection metadata.
    #[must_use]
    pub const fn injection(&self) -> WhiteboxGuestInputInjection {
        self.injection
    }
}

/// Decode diagnostic for malformed app-random doorbell frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRandomDecodeDiagnostic {
    kind: AppRandomDecodeDiagnosticKind,
}

impl AppRandomDecodeDiagnostic {
    /// Builds a decode diagnostic.
    #[must_use]
    pub const fn new(kind: AppRandomDecodeDiagnosticKind) -> Self {
        Self { kind }
    }

    /// Returns the diagnostic kind.
    #[must_use]
    pub const fn kind(&self) -> &AppRandomDecodeDiagnosticKind {
        &self.kind
    }

    fn from_marker_payload_error(
        error: WhiteboxMarkerPayloadDecodeError,
        payload_len: usize,
    ) -> Self {
        let kind = match error {
            WhiteboxMarkerPayloadDecodeError::PayloadTooShort {
                kind: WhiteboxDoorbellMarkerKind::RandomRequest,
                ..
            } => AppRandomDecodeDiagnosticKind::TruncatedRandomRequest {
                len: payload_len,
                minimum_len: 7,
            },
            WhiteboxMarkerPayloadDecodeError::InvalidRandomWidth {
                width_bytes,
                max_width_bytes,
            } => AppRandomDecodeDiagnosticKind::InvalidRandomWidth {
                width_bytes,
                max_width_bytes,
            },
            WhiteboxMarkerPayloadDecodeError::LengthPrefixExceedsPayload {
                kind: WhiteboxDoorbellMarkerKind::RandomRequest,
                field: "stream_tag",
                declared_len,
                remaining_len,
            } => AppRandomDecodeDiagnosticKind::StreamTagLengthMismatch {
                declared_len,
                actual_len: remaining_len,
            },
            WhiteboxMarkerPayloadDecodeError::TrailingBytes {
                kind: WhiteboxDoorbellMarkerKind::RandomRequest,
                trailing_len,
            } => {
                let actual_len = payload_len.saturating_sub(7);
                AppRandomDecodeDiagnosticKind::StreamTagLengthMismatch {
                    declared_len: actual_len.saturating_sub(trailing_len),
                    actual_len,
                }
            }
            WhiteboxMarkerPayloadDecodeError::InvalidUtf8 {
                kind: WhiteboxDoorbellMarkerKind::RandomRequest,
                field: "stream_tag",
            } => AppRandomDecodeDiagnosticKind::InvalidUtf8StreamTag,
            WhiteboxMarkerPayloadDecodeError::UnknownKind { kind } => {
                AppRandomDecodeDiagnosticKind::UnexpectedKind {
                    expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                    actual: kind,
                }
            }
            WhiteboxMarkerPayloadDecodeError::PayloadTooShort { kind, .. }
            | WhiteboxMarkerPayloadDecodeError::LengthPrefixExceedsPayload { kind, .. }
            | WhiteboxMarkerPayloadDecodeError::TrailingBytes { kind, .. }
            | WhiteboxMarkerPayloadDecodeError::InvalidUtf8 { kind, .. }
            | WhiteboxMarkerPayloadDecodeError::InvalidBool { kind, .. } => {
                AppRandomDecodeDiagnosticKind::UnexpectedKind {
                    expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                    actual: kind.wire_value(),
                }
            }
            WhiteboxMarkerPayloadDecodeError::InvalidAssertionFlavor { .. } => {
                AppRandomDecodeDiagnosticKind::UnexpectedKind {
                    expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                    actual: WHITEBOX_DOORBELL_KIND_ASSERTION,
                }
            }
            WhiteboxMarkerPayloadDecodeError::InvalidLifecycleEvent { .. } => {
                AppRandomDecodeDiagnosticKind::UnexpectedKind {
                    expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                    actual: WHITEBOX_DOORBELL_KIND_LIFECYCLE,
                }
            }
        };
        Self::new(kind)
    }
}

impl From<WhiteboxDoorbellFrameDecodeError> for AppRandomDecodeDiagnostic {
    fn from(error: WhiteboxDoorbellFrameDecodeError) -> Self {
        let kind = match error {
            WhiteboxDoorbellFrameDecodeError::TruncatedFrame { len, minimum_len } => {
                AppRandomDecodeDiagnosticKind::TruncatedFrame { len, minimum_len }
            }
            WhiteboxDoorbellFrameDecodeError::BadMagic { expected, actual } => {
                AppRandomDecodeDiagnosticKind::BadMagic { expected, actual }
            }
            WhiteboxDoorbellFrameDecodeError::UnsupportedVersion { expected, actual } => {
                AppRandomDecodeDiagnosticKind::UnsupportedVersion { expected, actual }
            }
            WhiteboxDoorbellFrameDecodeError::PayloadLengthMismatch {
                declared_len,
                actual_len,
            } => AppRandomDecodeDiagnosticKind::PayloadLengthMismatch {
                declared_len,
                actual_len,
            },
        };
        Self::new(kind)
    }
}

/// Kind of app-random doorbell decode diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppRandomDecodeDiagnosticKind {
    /// The frame was shorter than the fixed header.
    TruncatedFrame {
        /// Observed byte length.
        len: usize,
        /// Minimum valid byte length.
        minimum_len: usize,
    },
    /// The fixed channel magic was not recognized.
    BadMagic {
        /// Expected fixed magic.
        expected: u32,
        /// Observed magic.
        actual: u32,
    },
    /// The protocol version was not recognized.
    UnsupportedVersion {
        /// Expected protocol version.
        expected: u16,
        /// Observed protocol version.
        actual: u16,
    },
    /// The header payload length did not match the received payload bytes.
    PayloadLengthMismatch {
        /// Header-declared payload length.
        declared_len: usize,
        /// Actual payload length after the header.
        actual_len: usize,
    },
    /// The frame kind was not the random-request kind.
    UnexpectedKind {
        /// Expected random-request kind.
        expected: u16,
        /// Observed kind.
        actual: u16,
    },
    /// The random-request body was shorter than its fixed fields.
    TruncatedRandomRequest {
        /// Observed body length.
        len: usize,
        /// Minimum valid body length.
        minimum_len: usize,
    },
    /// The random-request width was outside `1..=8` bytes.
    InvalidRandomWidth {
        /// Observed byte width.
        width_bytes: u8,
        /// Maximum byte width.
        max_width_bytes: u8,
    },
    /// The stream-tag length prefix did not match the remaining bytes.
    StreamTagLengthMismatch {
        /// Declared tag length.
        declared_len: usize,
        /// Remaining body bytes after the tag-length field.
        actual_len: usize,
    },
    /// The stream tag was not UTF-8.
    InvalidUtf8StreamTag,
}

/// An error while serving an app-random doorbell request.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AppRandomDoorbellError {
    /// The underlying white-box doorbell path failed.
    #[error("white-box doorbell path failed while serving app-random: {0}")]
    Doorbell(WhiteboxDoorbellError),
    /// The decision source failed to draw or record `Decision::AppRandom`.
    #[error(
        "app-random decision source failed for node {node_name} stream {stream_tag} width {width_bits}: {source}"
    )]
    DecisionSource {
        /// Node whose guest requested the draw.
        node_name: String,
        /// Requested stream tag.
        stream_tag: String,
        /// Requested decision width in bits.
        width_bits: u8,
        /// Engine-side decision source error.
        source: AppRandomDecisionError,
    },
    /// The decision source returned metadata for the wrong node.
    #[error("app-random decision node {actual} does not match request node {expected}")]
    DecisionNodeMismatch {
        /// Requested node name.
        expected: String,
        /// Recorded node name.
        actual: String,
    },
    /// The decision source returned metadata for the wrong stream.
    #[error("app-random decision stream {actual} does not match request stream {expected}")]
    DecisionStreamMismatch {
        /// Requested stream tag.
        expected: String,
        /// Recorded stream tag.
        actual: String,
    },
    /// The decision source returned a value with an invalid width.
    #[error("app-random decision width {actual_bits} does not match request width {expected_bits}")]
    DecisionWidthMismatch {
        /// Requested width in bits.
        expected_bits: u8,
        /// Recorded width in bits.
        actual_bits: u8,
    },
    /// The decision source returned metadata for the wrong request id.
    #[error("app-random decision request id {actual} does not match request id {expected}")]
    DecisionRequestIdMismatch {
        /// Guest-requested id.
        expected: u64,
        /// Recorded request id.
        actual: u64,
    },
    /// The decision source returned a value with high bits set outside the width.
    #[error("app-random decision value {value:#x} exceeds {width_bits} bits")]
    DecisionValueOutOfRange {
        /// Requested width in bits.
        width_bits: u8,
        /// Recorded value.
        value: u64,
    },
    /// The host-to-guest delivery gate did not deliver at the trap icount.
    #[error("app-random reply was not delivered at icount {delivery_icount}")]
    ReplyNotDelivered {
        /// Required reply delivery icount.
        delivery_icount: u64,
    },
}

fn validate_decision_record(
    request: &AppRandomDoorbellRequest,
    decision: &AppRandomDecisionRecord,
) -> Result<(), AppRandomDoorbellError> {
    if decision.node_name() != request.node_name() {
        return Err(AppRandomDoorbellError::DecisionNodeMismatch {
            expected: request.node_name().to_owned(),
            actual: decision.node_name().to_owned(),
        });
    }
    if decision.stream_tag() != request.stream_tag() {
        return Err(AppRandomDoorbellError::DecisionStreamMismatch {
            expected: request.stream_tag().to_owned(),
            actual: decision.stream_tag().to_owned(),
        });
    }
    if decision.width_bits() != request.width_bits() {
        return Err(AppRandomDoorbellError::DecisionWidthMismatch {
            expected_bits: request.width_bits(),
            actual_bits: decision.width_bits(),
        });
    }
    if decision.request_id() != u64::from(request.guest_request_id()) {
        return Err(AppRandomDoorbellError::DecisionRequestIdMismatch {
            expected: u64::from(request.guest_request_id()),
            actual: decision.request_id(),
        });
    }
    if !value_fits_width(decision.value(), decision.width_bits()) {
        return Err(AppRandomDoorbellError::DecisionValueOutOfRange {
            width_bits: decision.width_bits(),
            value: decision.value(),
        });
    }
    Ok(())
}

fn value_fits_width(value: u64, width_bits: u8) -> bool {
    if width_bits == 64 {
        true
    } else {
        value <= ((1_u64 << width_bits) - 1)
    }
}

fn app_random_reply_payload(value: u64, width_bytes: u8) -> Vec<u8> {
    let bytes = value.to_le_bytes();
    bytes[..usize::from(width_bytes)].to_vec()
}

/// QEMU capabilities needed by the optional white-box channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WhiteboxDoorbellCapabilities {
    /// Whether upstream plugin memory callbacks can observe the reserved trap.
    register_doorbell_trap: bool,
    /// Whether upstream plugin memory reads can copy the payload at trap icount.
    guest_memory_read: bool,
    /// Whether a host-to-guest reply write surface is available.
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

    /// Returns whether the reserved trap can be observed through memory callbacks.
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

/// Guest-owned trap resources observed during white-box setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhiteboxDoorbellSetupResources<'a> {
    x86_mapped_ports: &'a [u16],
    aarch64_reserved_immediates_in_use: &'a [u16],
}

impl<'a> WhiteboxDoorbellSetupResources<'a> {
    /// Builds setup resources from the guest's observed device and instruction surface.
    #[must_use]
    pub const fn from_observed_resources(
        x86_mapped_ports: &'a [u16],
        aarch64_reserved_immediates_in_use: &'a [u16],
    ) -> Self {
        Self {
            x86_mapped_ports,
            aarch64_reserved_immediates_in_use,
        }
    }

    /// Returns observed x86_64 ports that are already mapped to real guest devices.
    #[must_use]
    pub const fn x86_mapped_ports(self) -> &'a [u16] {
        self.x86_mapped_ports
    }

    /// Returns observed aarch64 reserved immediates that are unavailable for Crucible.
    #[must_use]
    pub const fn aarch64_reserved_immediates_in_use(self) -> &'a [u16] {
        self.aarch64_reserved_immediates_in_use
    }
}

/// Setup-time non-collision validation for one reserved doorbell trap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhiteboxDoorbellSetupValidation {
    trap: WhiteboxDoorbellTrap,
    outcome: WhiteboxDoorbellSetupOutcome,
}

impl WhiteboxDoorbellSetupValidation {
    /// Builds an unchecked validation result for a configured trap.
    #[must_use]
    pub const fn unchecked(trap: WhiteboxDoorbellTrap) -> Self {
        Self {
            trap,
            outcome: WhiteboxDoorbellSetupOutcome::Unchecked,
        }
    }

    /// Validates a configured trap against setup-observed guest resources.
    #[must_use]
    pub fn validate(
        trap: WhiteboxDoorbellTrap,
        resources: WhiteboxDoorbellSetupResources<'_>,
    ) -> Self {
        let outcome = match trap {
            WhiteboxDoorbellTrap::X86PortIo { port } => {
                if resources.x86_mapped_ports().contains(&port) {
                    WhiteboxDoorbellSetupOutcome::Collision {
                        collision: WhiteboxDoorbellCollision::X86PortMapped { port },
                    }
                } else {
                    WhiteboxDoorbellSetupOutcome::CollisionFree
                }
            }
            WhiteboxDoorbellTrap::Aarch64Hlt { immediate } => {
                if resources
                    .aarch64_reserved_immediates_in_use()
                    .contains(&immediate)
                {
                    WhiteboxDoorbellSetupOutcome::Collision {
                        collision: WhiteboxDoorbellCollision::Aarch64ReservedImmediateInUse {
                            immediate,
                        },
                    }
                } else {
                    WhiteboxDoorbellSetupOutcome::CollisionFree
                }
            }
        };
        Self { trap, outcome }
    }

    /// Returns the trap that was validated during setup.
    #[must_use]
    pub const fn trap(self) -> WhiteboxDoorbellTrap {
        self.trap
    }

    /// Returns the setup validation outcome.
    #[must_use]
    pub const fn outcome(self) -> WhiteboxDoorbellSetupOutcome {
        self.outcome
    }
}

/// Result of checking a reserved doorbell trap against guest-owned resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxDoorbellSetupOutcome {
    /// No setup-time collision check has been performed.
    Unchecked,
    /// The trap was checked and no collision was found.
    CollisionFree,
    /// The trap collides with a guest-owned resource or instruction use.
    Collision {
        /// The detected collision.
        collision: WhiteboxDoorbellCollision,
    },
}

/// A guest-owned resource that collides with the reserved doorbell trap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxDoorbellCollision {
    /// The x86_64 port is mapped to a real guest device.
    X86PortMapped {
        /// Colliding port number.
        port: u16,
    },
    /// The aarch64 `hlt #imm16` immediate is used by guest code or platform ABI.
    Aarch64ReservedImmediateInUse {
        /// Colliding immediate value.
        immediate: u16,
    },
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
    /// aarch64 reserved `hlt #imm16` trap instruction.
    Aarch64Hlt {
        /// Reserved immediate encoded in the trap instruction.
        immediate: u16,
    },
}

impl WhiteboxDoorbellTrap {
    /// Converts the shared instruction ABI trap into the plugin registration trap.
    #[must_use]
    pub const fn from_abi(trap: WhiteboxDoorbellTrapAbi) -> Self {
        match trap {
            WhiteboxDoorbellTrapAbi::X86PortIo { port } => Self::X86PortIo { port },
            WhiteboxDoorbellTrapAbi::Aarch64Hlt { immediate } => Self::Aarch64Hlt { immediate },
        }
    }
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
    payload_source: WhiteboxDoorbellPayloadSource,
}

impl WhiteboxDoorbellTrapEvent {
    /// Builds a doorbell trap event whose payload lives in a configured shared page.
    #[must_use]
    pub const fn from_shared_page(
        vcpu_index: u32,
        current_icount: u64,
        payload_range: GuestMemoryRange,
    ) -> Self {
        Self {
            vcpu_index,
            current_icount,
            payload_source: WhiteboxDoorbellPayloadSource::SharedPage {
                range: payload_range,
            },
        }
    }

    /// Builds a doorbell trap event whose payload pointer and length came from registers.
    #[must_use]
    pub const fn from_register_pointer_length(
        vcpu_index: u32,
        current_icount: u64,
        payload_range: GuestMemoryRange,
    ) -> Self {
        Self {
            vcpu_index,
            current_icount,
            payload_source: WhiteboxDoorbellPayloadSource::RegisterPointerLength {
                range: payload_range,
            },
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

    /// Returns how the callback obtained the guest-memory payload range.
    #[must_use]
    pub const fn payload_source(self) -> WhiteboxDoorbellPayloadSource {
        self.payload_source
    }

    /// Returns the guest-memory payload range to read at this trap.
    #[must_use]
    pub const fn payload_range(self) -> GuestMemoryRange {
        self.payload_source.range()
    }
}

/// The allowed guest-memory source for a white-box doorbell payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxDoorbellPayloadSource {
    /// Payload bytes were written by the guest into a configured shared page.
    SharedPage {
        /// Guest-memory range read at the doorbell trap.
        range: GuestMemoryRange,
    },
    /// Payload bytes are addressed by a pointer and length captured from registers.
    RegisterPointerLength {
        /// Guest-memory range read at the doorbell trap.
        range: GuestMemoryRange,
    },
}

impl WhiteboxDoorbellPayloadSource {
    /// Returns the guest-memory range read at the doorbell trap.
    #[must_use]
    pub const fn range(self) -> GuestMemoryRange {
        match self {
            Self::SharedPage { range } | Self::RegisterPointerLength { range } => range,
        }
    }
}

/// An icount-stamped white-box marker read from guest memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxMarker {
    marker_icount: u64,
    vcpu_index: u32,
    payload_range: GuestMemoryRange,
    kind: u16,
    payload: Vec<u8>,
    decoded_payload: WhiteboxMarkerPayload,
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

    /// Returns the decoded doorbell marker kind.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        self.kind
    }

    /// Returns the decoded kind-specific doorbell body bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the decoded closed marker payload.
    #[must_use]
    pub fn decoded_payload(&self) -> &WhiteboxMarkerPayload {
        &self.decoded_payload
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
    /// Setup did not validate that the reserved trap is collision-free.
    #[error("white-box doorbell trap {trap:?} was not checked for setup collisions")]
    SetupCollisionUnchecked {
        /// The unchecked trap.
        trap: WhiteboxDoorbellTrap,
    },
    /// Setup found that the reserved trap collides with guest-owned state.
    #[error("white-box doorbell trap {trap:?} collides at setup: {collision:?}")]
    SetupCollision {
        /// The configured trap.
        trap: WhiteboxDoorbellTrap,
        /// The detected collision.
        collision: WhiteboxDoorbellCollision,
    },
    /// Setup validated a different trap than the configured doorbell trap.
    #[error(
        "white-box doorbell setup validated {validated:?}, but configured trap is {configured:?}"
    )]
    SetupValidationTrapMismatch {
        /// The configured trap.
        configured: WhiteboxDoorbellTrap,
        /// The trap that setup validated.
        validated: WhiteboxDoorbellTrap,
    },
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
    /// The guest bytes did not decode as a white-box doorbell frame.
    #[error("white-box marker at icount {marker_icount} carried a malformed frame: {source}")]
    DoorbellFrameDecode {
        /// The marker icount.
        marker_icount: u64,
        /// The frame decode failure.
        source: WhiteboxDoorbellFrameDecodeError,
    },
    /// The decoded frame body did not match the closed marker vocabulary.
    #[error("white-box marker at icount {marker_icount} carried a malformed marker body: {source}")]
    DoorbellMarkerDecode {
        /// The marker icount.
        marker_icount: u64,
        /// The marker body decode failure.
        source: WhiteboxMarkerPayloadDecodeError,
    },
    /// The observational marker path received an in-band marker kind.
    #[error("white-box marker at icount {marker_icount} carried non-observational kind {kind:?}")]
    NonObservationalMarkerKind {
        /// The marker icount.
        marker_icount: u64,
        /// The non-observational marker kind.
        kind: WhiteboxDoorbellMarkerKind,
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

    fn collision_free_setup(trap: WhiteboxDoorbellTrap) -> WhiteboxDoorbellSetupValidation {
        WhiteboxDoorbellSetupValidation::validate(
            trap,
            WhiteboxDoorbellSetupResources::from_observed_resources(&[], &[]),
        )
    }

    #[test]
    fn whitebox_registration_off_mode_installs_no_trap_and_preserves_black_box() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::Off,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );

        let plan = match doorbell.registration_plan(
            WhiteboxDoorbellCapabilities::none(),
            WhiteboxDoorbellSetupValidation::unchecked(doorbell.trap()),
        ) {
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
            doorbell.registration_plan(
                WhiteboxDoorbellCapabilities::none(),
                WhiteboxDoorbellSetupValidation::unchecked(doorbell.trap()),
            ),
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
        let setup_validation = collision_free_setup(doorbell.trap());

        assert_eq!(
            doorbell.registration_plan(WhiteboxDoorbellCapabilities::none(), setup_validation),
            Err(WhiteboxDoorbellError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL,
            })
        );
        assert_eq!(
            doorbell.registration_plan(
                WhiteboxDoorbellCapabilities {
                    register_doorbell_trap: true,
                    guest_memory_read: false,
                    guest_memory_write: false,
                },
                setup_validation,
            ),
            Err(WhiteboxDoorbellError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL,
            })
        );

        let plan = match doorbell.registration_plan(
            WhiteboxDoorbellCapabilities::guest_to_host(),
            setup_validation,
        ) {
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
    fn whitebox_registration_on_mode_requires_setup_collision_validation() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );

        assert_eq!(
            doorbell.registration_plan(
                WhiteboxDoorbellCapabilities::guest_to_host(),
                WhiteboxDoorbellSetupValidation::unchecked(doorbell.trap()),
            ),
            Err(WhiteboxDoorbellError::SetupCollisionUnchecked {
                trap: doorbell.trap(),
            })
        );
        assert_eq!(
            doorbell.registration_plan(
                WhiteboxDoorbellCapabilities::guest_to_host(),
                WhiteboxDoorbellSetupValidation::validate(
                    doorbell.trap(),
                    WhiteboxDoorbellSetupResources::from_observed_resources(&[0xe7], &[]),
                ),
            ),
            Err(WhiteboxDoorbellError::SetupCollision {
                trap: doorbell.trap(),
                collision: WhiteboxDoorbellCollision::X86PortMapped { port: 0xe7 },
            })
        );
        assert_eq!(
            doorbell.registration_plan(
                WhiteboxDoorbellCapabilities::guest_to_host(),
                collision_free_setup(WhiteboxDoorbellTrap::Aarch64Hlt { immediate: 0x4c1 }),
            ),
            Err(WhiteboxDoorbellError::SetupValidationTrapMismatch {
                configured: doorbell.trap(),
                validated: WhiteboxDoorbellTrap::Aarch64Hlt { immediate: 0x4c1 },
            })
        );

        let aarch64 = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::Aarch64Hlt { immediate: 0x4c1 },
            128,
        );
        assert_eq!(
            aarch64.registration_plan(
                WhiteboxDoorbellCapabilities::guest_to_host(),
                WhiteboxDoorbellSetupValidation::validate(
                    aarch64.trap(),
                    WhiteboxDoorbellSetupResources::from_observed_resources(&[], &[0x4c1]),
                ),
            ),
            Err(WhiteboxDoorbellError::SetupCollision {
                trap: aarch64.trap(),
                collision: WhiteboxDoorbellCollision::Aarch64ReservedImmediateInUse {
                    immediate: 0x4c1,
                },
            })
        );
    }

    #[test]
    fn whitebox_doorbell_abi_vectors_cover_x86_64_and_aarch64() {
        assert_eq!(WHITEBOX_DOORBELL_ABIS.len(), 2);
        assert_eq!(
            WHITEBOX_DOORBELL_ABIS
                .iter()
                .map(|abi| abi.vector_name())
                .collect::<Vec<_>>(),
            vec!["x86_64-out-dx-eax-port-e7", "aarch64-hlt-imm-04c1"]
        );
        assert_eq!(
            WHITEBOX_DOORBELL_ABIS
                .iter()
                .map(|abi| abi.version())
                .collect::<Vec<_>>(),
            vec![
                WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
                WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
            ]
        );
        assert_eq!(
            whitebox_doorbell_abi_for_architecture(WhiteboxDoorbellArchitecture::X86_64),
            WHITEBOX_DOORBELL_X86_64_ABI
        );
        assert_eq!(
            whitebox_doorbell_abi_for_architecture(WhiteboxDoorbellArchitecture::Aarch64),
            WHITEBOX_DOORBELL_AARCH64_ABI
        );
    }

    #[test]
    fn whitebox_doorbell_x86_64_golden_vector_freezes_out_dx_eax() {
        let abi = WHITEBOX_DOORBELL_X86_64_ABI;

        assert_eq!(abi.architecture().as_str(), "x86_64");
        assert_eq!(abi.instruction(), WhiteboxDoorbellInstruction::X86OutDxEax);
        assert_eq!(abi.instruction().as_str(), "out-dx-eax");
        assert_eq!(
            abi.trap(),
            WhiteboxDoorbellTrapAbi::X86PortIo {
                port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
            }
        );
        assert_eq!(
            WhiteboxDoorbellTrap::from_abi(abi.trap()),
            WhiteboxDoorbellTrap::X86PortIo {
                port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
            }
        );
        assert_eq!(abi.payload_pointer_register(), "rax");
        assert_eq!(abi.payload_length_register(), "rcx");
        assert_eq!(abi.assembly(), "out dx, eax");
        assert_eq!(
            encode_x86_64_out_dx_eax_instruction(),
            WHITEBOX_DOORBELL_X86_64_OUT_DX_EAX_BYTES
        );
        assert_eq!(abi.instruction_bytes(), &[0xef]);
    }

    #[test]
    fn whitebox_doorbell_aarch64_golden_vector_freezes_hlt_immediate() {
        let abi = WHITEBOX_DOORBELL_AARCH64_ABI;

        assert_eq!(abi.architecture().as_str(), "aarch64");
        assert_eq!(abi.instruction(), WhiteboxDoorbellInstruction::Aarch64Hlt);
        assert_eq!(abi.instruction().as_str(), "hlt-imm16");
        assert_eq!(
            abi.trap(),
            WhiteboxDoorbellTrapAbi::Aarch64Hlt {
                immediate: WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE,
            }
        );
        assert_eq!(
            WhiteboxDoorbellTrap::from_abi(abi.trap()),
            WhiteboxDoorbellTrap::Aarch64Hlt {
                immediate: WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE,
            }
        );
        assert_eq!(abi.payload_pointer_register(), "x0");
        assert_eq!(abi.payload_length_register(), "x1");
        assert_eq!(abi.assembly(), "hlt #0x04c1");
        assert_eq!(
            encode_aarch64_hlt_instruction(WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE),
            WHITEBOX_DOORBELL_AARCH64_HLT_BYTES
        );
        assert_eq!(abi.instruction_bytes(), &[0x20, 0x98, 0x40, 0xd4]);
    }

    #[test]
    fn whitebox_doorbell_registration_uses_single_source_abi_trap() {
        for abi in WHITEBOX_DOORBELL_ABIS {
            let doorbell = PluginWhiteboxDoorbell::from_abi(PluginSwitch::On, *abi, 128);
            let setup_validation = collision_free_setup(doorbell.trap());
            let plan = match doorbell.registration_plan(
                WhiteboxDoorbellCapabilities::guest_to_host(),
                setup_validation,
            ) {
                Ok(plan) => plan,
                Err(error) => panic!("ABI-derived doorbell should validate: {error}"),
            };

            assert_eq!(doorbell.trap(), WhiteboxDoorbellTrap::from_abi(abi.trap()));
            assert_eq!(
                plan,
                WhiteboxDoorbellRegistrationPlan::Install {
                    trap: WhiteboxDoorbellTrap::from_abi(abi.trap()),
                    callback_kind: PluginDeviceCallbackKind::WhiteboxDoorbell,
                    max_payload_len: 128,
                }
            );
        }
    }

    #[test]
    fn whitebox_doorbell_reads_guest_memory_via_api_and_stamps_current_icount() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let frame = coverage_marker_frame("mark");
        let expected_body = coverage_marker_body("mark");
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, frame.len());
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 777, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(frame);
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
        assert_eq!(marker.kind(), 4);
        assert_eq!(marker.payload(), expected_body);
        assert_eq!(
            marker.decoded_payload(),
            &WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
                point: String::from("mark"),
            })
        );
        assert_eq!(sink.markers, vec![marker]);
    }

    #[test]
    fn whitebox_doorbell_records_decoded_marker_into_engine_event_log_sink() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            256,
        );
        let payload = WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
            flavor: WhiteboxAssertionMarkerFlavor::Reachable,
            condition: true,
            must_hit: true,
            id: String::from("guest.ready"),
            message: String::from("guest reported ready"),
            location: String::from("guest.rs:7"),
            details: vec![WhiteboxMarkerDetail::new("phase", "setup")],
        });
        let frame = encode_whitebox_marker_frame(&payload)
            .unwrap_or_else(|error| panic!("test marker frame should encode: {error}"));
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, frame.len());
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 888, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(frame);
        let mut sink = EngineEventLogMarkerSink::new("db-0");

        let marker =
            match handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event) {
                Ok(marker) => marker,
                Err(error) => panic!("doorbell should append marker to engine event log: {error}"),
            };

        assert_eq!(marker.marker_icount(), 888);
        assert_eq!(marker.decoded_payload(), &payload);
        assert_eq!(sink.entries.len(), 1);
        let entry = &sink.entries[0];
        assert_eq!(entry.class(), crucible::EventClass::Observational);
        assert_eq!(
            entry.time().icount,
            crucible::EventLogIcountStamp {
                node: Some(crucible_node("db-0")),
                icount: crucible::Icount { retired: 888 },
            }
        );
        assert_eq!(
            entry.source(),
            &crucible::EventSource::Guest {
                node: crucible_node("db-0"),
            }
        );
        assert_eq!(entry.event_payload().kind(), "guest_marker");
        assert_eq!(
            entry.event_payload().string("assertion"),
            Some("guest.ready")
        );
        assert!(crucible::event_log_causal_projection(&sink.entries).is_empty());
    }

    #[test]
    fn whitebox_doorbell_rejects_malformed_frame_without_marker() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 4);
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 777, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(b"mark".to_vec());
        let mut sink = RecordingMarkerSink::default();

        assert_eq!(
            handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
            Err(WhiteboxDoorbellError::DoorbellFrameDecode {
                marker_icount: 777,
                source: WhiteboxDoorbellFrameDecodeError::TruncatedFrame {
                    len: 4,
                    minimum_len: WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
                },
            })
        );
        assert_eq!(reader.calls, vec![(2, 777, range)]);
        assert!(sink.markers.is_empty());
    }

    #[test]
    fn whitebox_doorbell_rejects_random_request_on_observational_marker_path() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let frame = random_request_frame(1, 4, "rng");
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, frame.len());
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(2, 777, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(frame);
        let mut sink = RecordingMarkerSink::default();

        assert_eq!(
            handle_whitebox_doorbell_callback(&doorbell, &mut reader, &mut sink, event),
            Err(WhiteboxDoorbellError::NonObservationalMarkerKind {
                marker_icount: 777,
                kind: WhiteboxDoorbellMarkerKind::RandomRequest,
            })
        );
        assert_eq!(reader.calls, vec![(2, 777, range)]);
        assert!(sink.markers.is_empty());
    }

    #[test]
    fn whitebox_doorbell_payload_source_is_shared_page_or_register_pointer_length() {
        let shared_range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 8);
        let register_range = GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x2000, 16);

        let shared = WhiteboxDoorbellTrapEvent::from_shared_page(0, 12, shared_range);
        let register =
            WhiteboxDoorbellTrapEvent::from_register_pointer_length(1, 34, register_range);

        assert_eq!(
            shared.payload_source(),
            WhiteboxDoorbellPayloadSource::SharedPage {
                range: shared_range,
            }
        );
        assert_eq!(shared.payload_range(), shared_range);
        assert_eq!(
            register.payload_source(),
            WhiteboxDoorbellPayloadSource::RegisterPointerLength {
                range: register_range,
            }
        );
        assert_eq!(register.payload_range(), register_range);
    }

    #[test]
    fn whitebox_doorbell_rejects_oversized_payload_before_guest_memory_read() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            3,
        );
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1000, 4);
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
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
            WhiteboxDoorbellTrap::Aarch64Hlt { immediate: 0x4c1 },
            128,
        );
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x2000, 4);
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(1, 44, range);
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
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
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

    #[test]
    fn whitebox_app_random_serves_random_request_records_decision_and_replies_at_trap_icount() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let capability = guest_input_capability(&doorbell);
        let payload = random_request_frame(7, 2, "workload");
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(1, 99, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(payload);
        let record = AppRandomDecisionRecord::new("node-a", "workload", 7, 16, 0xbeef);
        let mut decisions = RecordingAppRandomSource::with_record(record.clone());
        let mut writer = RecordingGuestInputWriter::default();

        let outcome = match handle_whitebox_app_random_callback(
            &doorbell,
            &capability,
            &mut reader,
            &mut decisions,
            &mut writer,
            "node-a",
            event,
        ) {
            Ok(outcome) => outcome,
            Err(error) => panic!("app-random request should be served: {error}"),
        };

        let service = match outcome {
            AppRandomDoorbellOutcome::Served(service) => service,
            AppRandomDoorbellOutcome::Dropped { diagnostic } => {
                panic!("valid app-random request should not drop: {diagnostic:?}")
            }
        };
        assert_eq!(reader.calls, vec![(1, 99, range)]);
        assert_eq!(decisions.requests.len(), 1);
        assert_eq!(decisions.requests[0].node_name(), "node-a");
        assert_eq!(decisions.requests[0].guest_request_id(), 7);
        assert_eq!(decisions.requests[0].trap_icount(), 99);
        assert_eq!(decisions.requests[0].width_bytes(), 2);
        assert_eq!(decisions.requests[0].width_bits(), 16);
        assert_eq!(decisions.requests[0].stream_tag(), "workload");
        assert_eq!(service.request(), &decisions.requests[0]);
        assert_eq!(service.decision(), &record);
        assert_eq!(service.injection().delivery_icount(), 99);
        assert_eq!(service.injection().payload_len(), 2);
        assert_eq!(
            writer.writes,
            vec![(
                99,
                GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, 2),
                vec![0xef, 0xbe],
            )]
        );
    }

    #[test]
    fn whitebox_app_random_drops_malformed_request_without_decision_or_reply() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let capability = guest_input_capability(&doorbell);
        let payload = random_request_frame(1, 9, "wide");
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(payload);
        let mut decisions = RecordingAppRandomSource::with_record(AppRandomDecisionRecord::new(
            "node-a", "wide", 0, 72, 0,
        ));
        let mut writer = RecordingGuestInputWriter::default();

        let outcome = match handle_whitebox_app_random_callback(
            &doorbell,
            &capability,
            &mut reader,
            &mut decisions,
            &mut writer,
            "node-a",
            event,
        ) {
            Ok(outcome) => outcome,
            Err(error) => panic!("malformed app-random request should drop, not fail: {error}"),
        };

        assert_eq!(
            outcome,
            AppRandomDoorbellOutcome::Dropped {
                diagnostic: AppRandomDecodeDiagnostic::new(
                    AppRandomDecodeDiagnosticKind::InvalidRandomWidth {
                        width_bytes: 9,
                        max_width_bytes: WHITEBOX_APP_RANDOM_MAX_WIDTH_BYTES,
                    },
                ),
            }
        );
        assert_eq!(reader.calls, vec![(0, 10, range)]);
        assert!(decisions.requests.is_empty());
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn whitebox_app_random_decoder_rejects_bad_magic_version_kind_and_utf8() {
        assert_eq!(
            WhiteboxDoorbellFrame::decode(&[1, 2, 3]),
            Err(WhiteboxDoorbellFrameDecodeError::TruncatedFrame {
                len: 3,
                minimum_len: WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
            })
        );

        let bad_magic = doorbell_frame_with_header(0, WHITEBOX_DOORBELL_PROTOCOL_VERSION, 5, &[]);
        assert_eq!(
            WhiteboxDoorbellFrame::decode(&bad_magic),
            Err(WhiteboxDoorbellFrameDecodeError::BadMagic {
                expected: WHITEBOX_DOORBELL_FRAME_MAGIC,
                actual: 0,
            })
        );

        let bad_version = doorbell_frame_with_header(WHITEBOX_DOORBELL_FRAME_MAGIC, 1, 5, &[]);
        assert_eq!(
            WhiteboxDoorbellFrame::decode(&bad_version),
            Err(WhiteboxDoorbellFrameDecodeError::UnsupportedVersion {
                expected: WHITEBOX_DOORBELL_PROTOCOL_VERSION,
                actual: 1,
            })
        );

        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(
            0,
            10,
            GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, 32),
        );
        let wrong_kind = match WhiteboxDoorbellFrame::decode(&doorbell_frame(4, &[])) {
            Ok(frame) => frame,
            Err(error) => panic!("wrong-kind frame header should decode: {error:?}"),
        };
        assert_eq!(
            AppRandomDoorbellRequest::from_frame("node-a", event, wrong_kind),
            Err(AppRandomDecodeDiagnostic::new(
                AppRandomDecodeDiagnosticKind::UnexpectedKind {
                    expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                    actual: 4,
                },
            ))
        );

        let mut invalid_utf8_body = Vec::new();
        invalid_utf8_body.extend_from_slice(&1_u32.to_le_bytes());
        invalid_utf8_body.push(1);
        invalid_utf8_body.extend_from_slice(&1_u16.to_le_bytes());
        invalid_utf8_body.push(0xff);
        let invalid_utf8 =
            match WhiteboxDoorbellFrame::decode(&doorbell_frame(5, &invalid_utf8_body)) {
                Ok(frame) => frame,
                Err(error) => panic!("invalid-utf8 frame header should decode: {error:?}"),
            };
        assert_eq!(
            AppRandomDoorbellRequest::from_frame("node-a", event, invalid_utf8),
            Err(AppRandomDecodeDiagnostic::new(
                AppRandomDecodeDiagnosticKind::InvalidUtf8StreamTag,
            ))
        );
    }

    #[test]
    fn whitebox_app_random_rejects_unmasked_decision_value_without_reply() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let capability = guest_input_capability(&doorbell);
        let payload = random_request_frame(3, 1, "byte");
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(payload);
        let mut decisions = RecordingAppRandomSource::with_record(AppRandomDecisionRecord::new(
            "node-a", "byte", 3, 8, 0x1ff,
        ));
        let mut writer = RecordingGuestInputWriter::default();

        assert_eq!(
            handle_whitebox_app_random_callback(
                &doorbell,
                &capability,
                &mut reader,
                &mut decisions,
                &mut writer,
                "node-a",
                event,
            ),
            Err(AppRandomDoorbellError::DecisionValueOutOfRange {
                width_bits: 8,
                value: 0x1ff,
            })
        );
        assert_eq!(decisions.requests.len(), 1);
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn whitebox_app_random_rejects_request_id_mismatch_without_reply() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::On,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let capability = guest_input_capability(&doorbell);
        let payload = random_request_frame(11, 1, "byte");
        let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, payload.len());
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(0, 10, range);
        let mut reader = RecordingGuestMemoryReader::with_payload(payload);
        let mut decisions = RecordingAppRandomSource::with_record(AppRandomDecisionRecord::new(
            "node-a", "byte", 12, 8, 0xff,
        ));
        let mut writer = RecordingGuestInputWriter::default();

        assert_eq!(
            handle_whitebox_app_random_callback(
                &doorbell,
                &capability,
                &mut reader,
                &mut decisions,
                &mut writer,
                "node-a",
                event,
            ),
            Err(AppRandomDoorbellError::DecisionRequestIdMismatch {
                expected: 11,
                actual: 12,
            })
        );
        assert_eq!(decisions.requests.len(), 1);
        assert!(writer.writes.is_empty());
    }

    #[test]
    fn whitebox_app_random_zero_requests_leave_no_decisions_or_replies() {
        let doorbell = PluginWhiteboxDoorbell::new(
            PluginSwitch::Off,
            WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
            128,
        );
        let plan = match doorbell.registration_plan(
            WhiteboxDoorbellCapabilities::none(),
            WhiteboxDoorbellSetupValidation::validate(
                doorbell.trap(),
                WhiteboxDoorbellSetupResources::from_observed_resources(&[0xe7], &[]),
            ),
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("zero-request black-box plan should validate: {error}"),
        };
        let decisions = RecordingAppRandomSource::with_record(AppRandomDecisionRecord::new(
            "node-a", "unused", 0, 8, 7,
        ));
        let writer = RecordingGuestInputWriter::default();

        assert!(plan.black_box_remains_functional());
        assert!(decisions.requests.is_empty());
        assert!(writer.writes.is_empty());
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

    fn random_request_frame(guest_request_id: u32, width_bytes: u8, stream_tag: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&guest_request_id.to_le_bytes());
        body.push(width_bytes);
        body.extend_from_slice(&(stream_tag.len() as u16).to_le_bytes());
        body.extend_from_slice(stream_tag.as_bytes());
        doorbell_frame(WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST, &body)
    }

    fn doorbell_frame(kind: u16, body: &[u8]) -> Vec<u8> {
        match encode_whitebox_doorbell_frame(kind, body) {
            Ok(frame) => frame,
            Err(error) => panic!("test doorbell frame should encode: {error}"),
        }
    }

    fn coverage_marker_body(point: &str) -> Vec<u8> {
        let payload = WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
            point: String::from(point),
        });
        match crucible_protocol::encode_whitebox_marker_payload_body(&payload) {
            Ok(body) => body,
            Err(error) => panic!("test coverage marker body should encode: {error}"),
        }
    }

    fn coverage_marker_frame(point: &str) -> Vec<u8> {
        let payload = WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
            point: String::from(point),
        });
        match encode_whitebox_marker_frame(&payload) {
            Ok(frame) => frame,
            Err(error) => panic!("test coverage marker frame should encode: {error}"),
        }
    }

    fn doorbell_frame_with_header(magic: u32, version: u16, kind: u16, body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&magic.to_le_bytes());
        frame.extend_from_slice(&version.to_le_bytes());
        frame.extend_from_slice(&kind.to_le_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(body);
        frame
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

    struct EngineEventLogMarkerSink {
        node: crucible::NodeId,
        event_log: crucible::EventLog,
        entries: Vec<crucible::SchedulerEventLogEntry>,
    }

    impl EngineEventLogMarkerSink {
        fn new(node_name: &str) -> Self {
            Self {
                node: crucible_node(node_name),
                event_log: crucible::EventLog::new(),
                entries: Vec::new(),
            }
        }
    }

    impl WhiteboxMarkerSink for EngineEventLogMarkerSink {
        fn record_whitebox_marker(
            &mut self,
            marker: &WhiteboxMarker,
        ) -> Result<(), WhiteboxMarkerSinkError> {
            let event = crucible::observable_event_from_whitebox_marker_payload(
                crucible::Icount {
                    retired: marker.marker_icount(),
                },
                self.node.clone(),
                marker.decoded_payload(),
            )
            .ok_or_else(|| {
                WhiteboxMarkerSinkError::new("non-observational marker reached event-log sink")
            })?;
            let sequence = self
                .event_log
                .next_sequence(0)
                .map_err(|error| WhiteboxMarkerSinkError::new(format!("{error:?}")))?;
            let entry =
                crucible::test_support::condition_observation_entry_for_test(sequence, &event);
            let append = self
                .event_log
                .append_entries(vec![entry])
                .map_err(|error| WhiteboxMarkerSinkError::new(format!("{error:?}")))?;
            self.entries.extend(append.entries);
            Ok(())
        }
    }

    fn crucible_node(name: &str) -> crucible::NodeId {
        crucible::NodeId {
            name: name.to_owned(),
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

    struct RecordingAppRandomSource {
        requests: Vec<AppRandomDoorbellRequest>,
        result: Result<AppRandomDecisionRecord, AppRandomDecisionError>,
    }

    impl RecordingAppRandomSource {
        fn with_record(record: AppRandomDecisionRecord) -> Self {
            Self {
                requests: Vec::new(),
                result: Ok(record),
            }
        }
    }

    impl AppRandomDecisionSource for RecordingAppRandomSource {
        fn serve_app_random(
            &mut self,
            request: &AppRandomDoorbellRequest,
        ) -> Result<AppRandomDecisionRecord, AppRandomDecisionError> {
            self.requests.push(request.clone());
            self.result.clone()
        }
    }
}
