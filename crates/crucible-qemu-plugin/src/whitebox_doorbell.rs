//! Optional white-box doorbell trap callback core.
//!
//! White-box mode is opt-in. When disabled, this module's registration plan
//! installs no trap and leaves black-box operation untouched. When enabled, the
//! safe callback body reads the guest payload only through a guest-memory API
//! adapter at the trap's current icount, records an observational marker, and
//! routes any host-to-guest reply through an explicit delivery-icount gate.

pub use crucible_protocol::{
    GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS, GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS,
    WHITEBOX_DOORBELL_AARCH64_ABI, WHITEBOX_DOORBELL_AARCH64_HINT_BYTES,
    WHITEBOX_DOORBELL_AARCH64_RESERVED_HINT, WHITEBOX_DOORBELL_ABIS,
    WHITEBOX_DOORBELL_FRAME_HEADER_LEN, WHITEBOX_DOORBELL_FRAME_MAGIC,
    WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE, WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
    WHITEBOX_DOORBELL_KIND_ASSERTION, WHITEBOX_DOORBELL_KIND_COVERAGE,
    WHITEBOX_DOORBELL_KIND_EVENT, WHITEBOX_DOORBELL_KIND_LIFECYCLE,
    WHITEBOX_DOORBELL_KIND_MEASUREMENT_BEGIN, WHITEBOX_DOORBELL_KIND_MEASUREMENT_END,
    WHITEBOX_DOORBELL_KIND_METRIC_SAMPLE, WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
    WHITEBOX_DOORBELL_KIND_SEMANTIC_MARKER, WHITEBOX_DOORBELL_LIFECYCLE_SETUP_COMPLETE,
    WHITEBOX_DOORBELL_LIFECYCLE_TEST_DONE, WHITEBOX_DOORBELL_MARKER_KIND_COUNT,
    WHITEBOX_DOORBELL_PROTOCOL_VERSION, WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES,
    WHITEBOX_DOORBELL_X86_64_ABI, WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES,
    WHITEBOX_DOORBELL_X86_64_RESERVED_PORT, WHITEBOX_MARKER_BODY_MAX_BYTES,
    WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES, WHITEBOX_MEASUREMENT_VALUE_KIND_COUNT,
    WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS, WHITEBOX_SEMANTIC_MARKER_MAX_DETAILS,
    WhiteboxAssertionMarkerBody, WhiteboxAssertionMarkerFlavor, WhiteboxCoverageMarkerBody,
    WhiteboxDoorbellAbi, WhiteboxDoorbellArchitecture, WhiteboxDoorbellFrame,
    WhiteboxDoorbellFrameDecodeError, WhiteboxDoorbellFrameEncodeError,
    WhiteboxDoorbellFrameGoldenVector, WhiteboxDoorbellInstruction, WhiteboxDoorbellMarkerKind,
    WhiteboxDoorbellTrapAbi, WhiteboxEventMarkerBody, WhiteboxLifecycleMarkerEvent,
    WhiteboxMarkerDetail, WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError,
    WhiteboxMarkerPayloadEncodeError, WhiteboxMarkerPayloadGoldenVector,
    WhiteboxMeasurementBoundaryBody, WhiteboxMeasurementValue, WhiteboxMeasurementValueKind,
    WhiteboxMetricSampleBody, WhiteboxRandomRequestBody, WhiteboxReducedRational,
    WhiteboxSemanticMarkerBody, WhiteboxSemanticMarkerDetail, decode_whitebox_marker_payload,
    encode_aarch64_hint_instruction, encode_whitebox_doorbell_frame, encode_whitebox_marker_frame,
    encode_whitebox_marker_payload_body, encode_x86_64_out_imm8_al_instruction,
    whitebox_doorbell_abi_for_architecture,
};
use crucible_shmem::MAX_FRAME_DATA;
use thiserror::Error;

use crate::{PluginDeviceCallbackKind, PluginSwitch};

mod selectable;
pub use selectable::{
    CatalogedSelectableService, SELECTABLE_CATALOG_HARD_MAX_DECLARATIONS,
    SELECTABLE_CATALOG_HARD_MAX_REQUESTS, SelectableCallbackCoordinate, SelectableCatalog,
    SelectableCatalogError, SelectableCatalogExpectation, SelectableCatalogFreeze,
    SelectableCatalogLimits, SelectableCatalogPhase, SelectableDecisionAuthority,
    SelectableDoorbellError, SelectableDoorbellOutcome, SelectableDoorbellService,
    SelectableDoorbellServiceError, SelectableExpectedDeclaration, SelectableExpectedPresence,
    SelectablePendingRequest, SelectableRegistrationService, SelectableReplyService,
    handle_whitebox_selectable_callback,
};

/// QEMU plugin API label for translation-block instrumentation.
pub const QEMU_PLUGIN_DOORBELL_TRANSLATION_SYMBOL: &str = "qemu_plugin_register_vcpu_tb_trans_cb";
/// QEMU plugin API label for installing callbacks on translated instructions.
pub const QEMU_PLUGIN_DOORBELL_EXEC_CB_SYMBOL: &str = "qemu_plugin_register_vcpu_insn_exec_cb";
/// QEMU plugin API label for reading a register during a callback.
pub const QEMU_PLUGIN_READ_REGISTER_SYMBOL: &str = "qemu_plugin_read_register";
/// QEMU capability label for registering the reserved white-box doorbell trap.
pub const QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL: &str = QEMU_PLUGIN_DOORBELL_EXEC_CB_SYMBOL;
/// QEMU capability label for reading guest memory at the trap icount.
pub const QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL: &str = "qemu_plugin_read_memory_vaddr";
/// QEMU capability label for writing white-box replies into guest memory.
pub const QEMU_PLUGIN_GUEST_MEMORY_WRITE_SYMBOL: &str = "qemu_plugin_crucible_write_memory_vaddr";
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

        let payload = read_doorbell_payload(self, reader, event)?;
        let frame = match WhiteboxDoorbellFrame::decode_bounded(&payload, self.max_payload_len()) {
            Ok(frame) => frame,
            Err(source) => {
                record_decode_diagnostic(
                    sink,
                    WhiteboxDoorbellDecodeDiagnostic::frame_decode(event, source.clone()),
                )?;
                return Err(WhiteboxDoorbellError::DoorbellFrameDecode {
                    marker_icount: event.current_icount(),
                    source,
                });
            }
        };
        let decoded_payload = match decode_whitebox_marker_payload(&frame) {
            Ok(decoded_payload) => decoded_payload,
            Err(source) => {
                record_decode_diagnostic(
                    sink,
                    WhiteboxDoorbellDecodeDiagnostic::marker_decode(event, source.clone()),
                )?;
                return Err(WhiteboxDoorbellError::DoorbellMarkerDecode {
                    marker_icount: event.current_icount(),
                    source,
                });
            }
        };
        if !decoded_payload.is_observational() {
            record_decode_diagnostic(
                sink,
                WhiteboxDoorbellDecodeDiagnostic::non_observational_kind(
                    event,
                    decoded_payload.kind(),
                ),
            )?;
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

fn record_decode_diagnostic<S>(
    sink: &mut S,
    diagnostic: WhiteboxDoorbellDecodeDiagnostic,
) -> Result<(), WhiteboxDoorbellError>
where
    S: WhiteboxMarkerSink + ?Sized,
{
    sink.record_whitebox_decode_diagnostic(&diagnostic)
        .map_err(|source| WhiteboxDoorbellError::MarkerSink {
            marker_icount: diagnostic.marker_icount(),
            source,
        })
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
    let frame = match WhiteboxDoorbellFrame::decode_bounded(&payload, doorbell.max_payload_len()) {
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
    #[cfg(test)]
    pub(crate) fn test_request(
        node_name: &str,
        guest_request_id: u32,
        width_bytes: u8,
        stream_tag: &str,
    ) -> Self {
        Self {
            node_name: node_name.to_owned(),
            guest_request_id,
            trap_icount: 1,
            width_bytes,
            stream_tag: stream_tag.to_owned(),
            reply_range: GuestMemoryRange::new(
                GuestMemoryAddressSpace::Virtual,
                0x1000,
                usize::from(width_bytes),
            ),
        }
    }

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
            WhiteboxMarkerPayloadDecodeError::BodyTooLarge { len, max_len } => {
                AppRandomDecodeDiagnosticKind::PayloadLengthExceedsBound {
                    declared_len: len,
                    max_payload_len: max_len,
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
            WhiteboxMarkerPayloadDecodeError::InvalidMeasurementIdentifier { kind, .. } => {
                AppRandomDecodeDiagnosticKind::UnexpectedKind {
                    expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                    actual: kind.wire_value(),
                }
            }
            WhiteboxMarkerPayloadDecodeError::InvalidMeasurementValueKind { .. }
            | WhiteboxMarkerPayloadDecodeError::InvalidReducedRational { .. }
            | WhiteboxMarkerPayloadDecodeError::MeasurementVectorTooLong { .. } => {
                AppRandomDecodeDiagnosticKind::UnexpectedKind {
                    expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                    actual: WHITEBOX_DOORBELL_KIND_METRIC_SAMPLE,
                }
            }
            WhiteboxMarkerPayloadDecodeError::TooManyTypedDetails { .. }
            | WhiteboxMarkerPayloadDecodeError::NonCanonicalDetailOrder { .. } => {
                AppRandomDecodeDiagnosticKind::UnexpectedKind {
                    expected: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
                    actual: WHITEBOX_DOORBELL_KIND_SEMANTIC_MARKER,
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
            WhiteboxDoorbellFrameDecodeError::PayloadLengthExceedsBound {
                declared_len,
                max_payload_len,
            } => AppRandomDecodeDiagnosticKind::PayloadLengthExceedsBound {
                declared_len,
                max_payload_len,
            },
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
    /// The header payload length exceeded the bounded trap-time allocation budget.
    PayloadLengthExceedsBound {
        /// Header-declared payload length.
        declared_len: usize,
        /// Configured maximum payload length.
        max_payload_len: usize,
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
    aarch64_reserved_immediates_in_use: &'a [u8],
}

impl<'a> WhiteboxDoorbellSetupResources<'a> {
    /// Builds setup resources from the guest's observed device and instruction surface.
    #[must_use]
    pub const fn from_observed_resources(
        x86_mapped_ports: &'a [u16],
        aarch64_reserved_immediates_in_use: &'a [u8],
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
    pub const fn aarch64_reserved_immediates_in_use(self) -> &'a [u8] {
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
            WhiteboxDoorbellTrap::Aarch64Hint { immediate } => {
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
    /// The aarch64 `hint #imm7` immediate is used by guest code or platform ABI.
    Aarch64ReservedImmediateInUse {
        /// Colliding immediate value.
        immediate: u8,
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
    /// aarch64 reserved inert `hint #imm7` instruction.
    Aarch64Hint {
        /// Reserved immediate encoded in the inert instruction.
        immediate: u8,
    },
}

impl WhiteboxDoorbellTrap {
    /// Converts the shared instruction ABI trap into the plugin registration trap.
    #[must_use]
    pub const fn from_abi(trap: WhiteboxDoorbellTrapAbi) -> Self {
        match trap {
            WhiteboxDoorbellTrapAbi::X86PortIo { port } => Self::X86PortIo { port },
            WhiteboxDoorbellTrapAbi::Aarch64Hint { immediate } => Self::Aarch64Hint { immediate },
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

/// Phase 0 S5 check that retired the guest virtual-memory payload-read spike.
pub const WHITEBOX_GUEST_MEMORY_VADDR_SPIKE_CHECK: &str = "checks.crucible.phase0.s5VirtualMemory";

/// Fail-closed payload-read addressing when S5 evidence has not been supplied.
pub const WHITEBOX_GUEST_MEMORY_ADDRESSING_UNRESOLVED: WhiteboxGuestMemoryAddressingResolution =
    WhiteboxGuestMemoryAddressingResolution::unresolved(WHITEBOX_GUEST_MEMORY_VADDR_SPIKE_CHECK);

const fn static_str_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Default addressing mode for a white-box payload range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhiteboxPayloadAddressingMode {
    /// Use the guest virtual pointer and length captured at the trap.
    VirtualPointerLength,
    /// Use the conservative physical or identity-mapped shared page fallback.
    PhysicalSharedPage,
}

/// Evidence that selects the default white-box payload address form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhiteboxGuestMemoryAddressingResolution {
    /// Gate whose result produced this resolution.
    pub check: &'static str,
    /// Whether QEMU exports the plugin virtual-memory read function.
    pub qemu_plugin_read_memory_vaddr_available: bool,
    /// Whether the virtual-address read spike passed overall.
    pub virtual_address_read_result: bool,
    /// Whether resident static-storage payload reads passed.
    pub resident_read: bool,
    /// Whether page-spanning payload reads passed.
    pub page_spanning_read: bool,
    /// Whether normally paged anonymous-mmap payload reads passed.
    pub paged_mmap_read: bool,
    /// Whether marker icounts matched across repeated read-enabled runs.
    pub marker_icounts_reproducible: bool,
    /// Whether the plugin read the expected payload bytes.
    pub read_bytes_match_expected: bool,
    /// Whether payload hashes matched across repeated read-enabled runs.
    pub read_hashes_reproducible: bool,
    /// Whether read-enabled and read-disabled final fingerprints matched.
    pub side_effect_free_fingerprint_match: bool,
    /// Whether the conservative physical/pinned fallback was adopted.
    pub physical_pinned_fallback_adopted: bool,
}

impl WhiteboxGuestMemoryAddressingResolution {
    /// Builds an unresolved resolution that keeps the conservative physical fallback.
    #[must_use]
    pub const fn unresolved(check: &'static str) -> Self {
        Self {
            check,
            qemu_plugin_read_memory_vaddr_available: false,
            virtual_address_read_result: false,
            resident_read: false,
            page_spanning_read: false,
            paged_mmap_read: false,
            marker_icounts_reproducible: false,
            read_bytes_match_expected: false,
            read_hashes_reproducible: false,
            side_effect_free_fingerprint_match: false,
            physical_pinned_fallback_adopted: true,
        }
    }

    /// Returns whether the virtual pointer+length payload form is sound.
    #[must_use]
    pub const fn virtual_pointer_length_is_sound(self) -> bool {
        static_str_eq(self.check, WHITEBOX_GUEST_MEMORY_VADDR_SPIKE_CHECK)
            && self.qemu_plugin_read_memory_vaddr_available
            && self.virtual_address_read_result
            && self.resident_read
            && self.page_spanning_read
            && self.paged_mmap_read
            && self.marker_icounts_reproducible
            && self.read_bytes_match_expected
            && self.read_hashes_reproducible
            && self.side_effect_free_fingerprint_match
            && !self.physical_pinned_fallback_adopted
    }

    /// Returns the default payload addressing mode selected by the spike result.
    #[must_use]
    pub const fn default_payload_addressing_mode(self) -> WhiteboxPayloadAddressingMode {
        if self.virtual_pointer_length_is_sound() {
            WhiteboxPayloadAddressingMode::VirtualPointerLength
        } else {
            WhiteboxPayloadAddressingMode::PhysicalSharedPage
        }
    }

    /// Builds the default payload source, retaining the physical fallback.
    #[must_use]
    pub const fn default_payload_source(
        self,
        virtual_guest_address: u64,
        physical_shared_page_address: u64,
        len: usize,
    ) -> WhiteboxDoorbellPayloadSource {
        match self.default_payload_addressing_mode() {
            WhiteboxPayloadAddressingMode::VirtualPointerLength => {
                WhiteboxDoorbellPayloadSource::RegisterPointerLength {
                    range: GuestMemoryRange::new(
                        GuestMemoryAddressSpace::Virtual,
                        virtual_guest_address,
                        len,
                    ),
                }
            }
            WhiteboxPayloadAddressingMode::PhysicalSharedPage => {
                WhiteboxDoorbellPayloadSource::SharedPage {
                    range: GuestMemoryRange::new(
                        GuestMemoryAddressSpace::Physical,
                        physical_shared_page_address,
                        len,
                    ),
                }
            }
        }
    }
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

    /// Builds a doorbell trap event from the S5 virtual-memory read resolution.
    #[must_use]
    pub const fn from_default_payload_addressing(
        vcpu_index: u32,
        current_icount: u64,
        addressing: WhiteboxGuestMemoryAddressingResolution,
        virtual_guest_address: u64,
        physical_shared_page_address: u64,
        payload_len: usize,
    ) -> Self {
        Self {
            vcpu_index,
            current_icount,
            payload_source: addressing.default_payload_source(
                virtual_guest_address,
                physical_shared_page_address,
                payload_len,
            ),
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

/// A defensive decode diagnostic for a dropped white-box doorbell payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxDoorbellDecodeDiagnostic {
    marker_icount: u64,
    vcpu_index: u32,
    payload_range: GuestMemoryRange,
    kind: WhiteboxDoorbellDecodeDiagnosticKind,
}

impl WhiteboxDoorbellDecodeDiagnostic {
    fn frame_decode(
        event: WhiteboxDoorbellTrapEvent,
        source: WhiteboxDoorbellFrameDecodeError,
    ) -> Self {
        Self::new(
            event,
            WhiteboxDoorbellDecodeDiagnosticKind::FrameDecode { source },
        )
    }

    fn marker_decode(
        event: WhiteboxDoorbellTrapEvent,
        source: WhiteboxMarkerPayloadDecodeError,
    ) -> Self {
        Self::new(
            event,
            WhiteboxDoorbellDecodeDiagnosticKind::MarkerDecode { source },
        )
    }

    fn non_observational_kind(
        event: WhiteboxDoorbellTrapEvent,
        kind: WhiteboxDoorbellMarkerKind,
    ) -> Self {
        Self::new(
            event,
            WhiteboxDoorbellDecodeDiagnosticKind::NonObservationalKind { kind },
        )
    }

    fn new(event: WhiteboxDoorbellTrapEvent, kind: WhiteboxDoorbellDecodeDiagnosticKind) -> Self {
        Self {
            marker_icount: event.current_icount(),
            vcpu_index: event.vcpu_index(),
            payload_range: event.payload_range(),
            kind,
        }
    }

    /// Returns the exact doorbell icount stamped on the diagnostic.
    #[must_use]
    pub const fn marker_icount(&self) -> u64 {
        self.marker_icount
    }

    /// Returns the vCPU that retired the malformed doorbell instruction.
    #[must_use]
    pub const fn vcpu_index(&self) -> u32 {
        self.vcpu_index
    }

    /// Returns the guest-memory range used for the malformed payload read.
    #[must_use]
    pub const fn payload_range(&self) -> GuestMemoryRange {
        self.payload_range
    }

    /// Returns the typed decode diagnostic kind.
    #[must_use]
    pub const fn kind(&self) -> &WhiteboxDoorbellDecodeDiagnosticKind {
        &self.kind
    }
}

/// The defensive decode diagnostic kind for a dropped white-box doorbell payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WhiteboxDoorbellDecodeDiagnosticKind {
    /// The fixed doorbell frame header or length was invalid.
    FrameDecode {
        /// The typed frame decode error.
        source: WhiteboxDoorbellFrameDecodeError,
    },
    /// The frame kind or kind-specific marker body was invalid.
    MarkerDecode {
        /// The typed marker payload decode error.
        source: WhiteboxMarkerPayloadDecodeError,
    },
    /// The marker path received a non-observational in-band kind.
    NonObservationalKind {
        /// The non-observational marker kind.
        kind: WhiteboxDoorbellMarkerKind,
    },
}

impl WhiteboxDoorbellDecodeDiagnosticKind {
    /// Returns a stable marker label for event-log diagnostic records.
    #[must_use]
    pub const fn semantic_label(&self) -> &'static str {
        match self {
            Self::FrameDecode { .. } => "frame_decode",
            Self::MarkerDecode { .. } => "marker_decode",
            Self::NonObservationalKind { .. } => "non_observational_kind",
        }
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

    /// Records one malformed doorbell decode diagnostic as observational output.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxMarkerSinkError`] when the event-log path cannot accept
    /// the diagnostic and must fail loudly.
    fn record_whitebox_decode_diagnostic(
        &mut self,
        diagnostic: &WhiteboxDoorbellDecodeDiagnostic,
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
mod tests;
