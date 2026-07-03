//! `crucible-guest` owns the optional in-guest white-box emitter.
//!
//! Spec index: RFC-0010 files 16.
//!
//! This L2 crate is the thin library wrapped by the `crucible-guest` static
//! command-line emitter. It builds marker payloads from the shared
//! `crucible-protocol` vocabulary, encodes the same architecture-independent
//! doorbell frame consumed by the QEMU plugin, and rings the per-architecture
//! trap instruction selected by the single-source ABI table.
//!
//! Module map: the crate root owns CLI argument parsing, guest command
//! constructors, frame encoding, the transport trait used by tests and the CLI,
//! and the Linux guest instruction transport. `crucible-protocol` remains the
//! owner of the wire format and instruction ABI.
//!
//! Unsafe boundary discipline: inline assembly is private to
//! [`InstructionDoorbellTransport`]. Public callers pass typed [`GuestCommand`]
//! values to a safe [`DoorbellTransport`] implementation; the transport receives
//! a mutable frame buffer so reply-bearing app-random requests can be written
//! back at the same guest-memory range the plugin reads; public callers use safe doorbell and marker accessors while the private transport code owns the
//! guest/register and shared-region invariants.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub use crucible_protocol::{
    WHITEBOX_DOORBELL_AARCH64_ABI, WHITEBOX_DOORBELL_AARCH64_HLT_BYTES,
    WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE, WHITEBOX_DOORBELL_ABIS,
    WHITEBOX_DOORBELL_ASSERTION_FLAVOR_COUNT, WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
    WHITEBOX_DOORBELL_FRAME_MAGIC, WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE,
    WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION, WHITEBOX_DOORBELL_KIND_ASSERTION,
    WHITEBOX_DOORBELL_KIND_COVERAGE, WHITEBOX_DOORBELL_KIND_EVENT,
    WHITEBOX_DOORBELL_KIND_LIFECYCLE, WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
    WHITEBOX_DOORBELL_LIFECYCLE_EVENT_COUNT, WHITEBOX_DOORBELL_LIFECYCLE_SETUP_COMPLETE,
    WHITEBOX_DOORBELL_LIFECYCLE_TEST_DONE, WHITEBOX_DOORBELL_MARKER_KIND_COUNT,
    WHITEBOX_DOORBELL_PROTOCOL_VERSION, WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES,
    WHITEBOX_DOORBELL_X86_64_ABI, WHITEBOX_DOORBELL_X86_64_OUT_DX_EAX_BYTES,
    WHITEBOX_DOORBELL_X86_64_RESERVED_PORT, WhiteboxAssertionMarkerBody,
    WhiteboxAssertionMarkerFlavor, WhiteboxCoverageMarkerBody, WhiteboxDoorbellAbi,
    WhiteboxDoorbellArchitecture, WhiteboxDoorbellFrame, WhiteboxDoorbellFrameDecodeError,
    WhiteboxDoorbellFrameEncodeError, WhiteboxDoorbellInstruction, WhiteboxDoorbellMarkerKind,
    WhiteboxDoorbellTrapAbi, WhiteboxEventMarkerBody, WhiteboxLifecycleMarkerEvent,
    WhiteboxMarkerDetail, WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError,
    WhiteboxMarkerPayloadEncodeError, WhiteboxRandomRequestBody, decode_whitebox_marker_payload,
    encode_aarch64_hlt_instruction, encode_whitebox_doorbell_frame, encode_whitebox_marker_frame,
    encode_whitebox_marker_payload_body, encode_x86_64_out_dx_eax_instruction,
    whitebox_doorbell_abi_for_architecture,
};

use thiserror::Error;

/// Rust target flags required for the AOS static `crucible-guest` package.
pub const CRUCIBLE_GUEST_STATIC_RUSTFLAGS: &[&str] = &["-C", "target-feature=+crt-static"];

/// Guest architectures supported by the white-box emitter instruction ABI.
pub const CRUCIBLE_GUEST_SUPPORTED_ARCHITECTURES: &[WhiteboxDoorbellArchitecture] = &[
    WhiteboxDoorbellArchitecture::X86_64,
    WhiteboxDoorbellArchitecture::Aarch64,
];

/// Default stream tag used by `crucible-guest get-random` when no tag is supplied.
pub const CRUCIBLE_GUEST_DEFAULT_RANDOM_STREAM_TAG: &str = "crucible-guest";

/// Request identifier used by one-shot CLI `get-random` invocations.
pub const CRUCIBLE_GUEST_DEFAULT_RANDOM_REQUEST_ID: u32 = 0;

/// Usage text for the `crucible-guest` command-line emitter.
#[must_use]
pub const fn usage() -> &'static str {
    "usage: crucible-guest <verb> [args]\n\nverbs:\n  always <id> <message> <0|1>\n  sometimes <id> <message> <0|1>\n  reachable <id> <message>\n  unreachable <id> <message>\n  setup-complete\n  test-done\n  event <name> [k=v ...]\n  coverage <point>\n  get-random <width> [tag]"
}

/// Error returned while parsing, encoding, or emitting a guest marker command.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GuestEmitterError {
    /// The command-line arguments did not match the emitter vocabulary.
    #[error("{message}")]
    Usage {
        /// Human-readable usage diagnostic.
        message: String,
    },
    /// The current target cannot execute the requested doorbell instruction.
    #[error(
        "white-box doorbell is unsupported on target architecture {target_arch} and operating system {target_os}"
    )]
    UnsupportedTarget {
        /// Rust target architecture observed at compile time.
        target_arch: &'static str,
        /// Rust target operating system observed at compile time.
        target_os: &'static str,
    },
    /// Marker payload encoding failed before the doorbell was rung.
    #[error("white-box marker encode failed: {source}")]
    MarkerEncode {
        /// Underlying shared marker encoder error.
        #[from]
        source: WhiteboxMarkerPayloadEncodeError,
    },
    /// A doorbell transport implementation failed to emit the frame.
    #[error("doorbell transport failed: {message}")]
    Transport {
        /// Transport-specific diagnostic.
        message: String,
    },
    /// Linux rejected the x86_64 port-I/O permission request.
    #[error("failed to enable x86_64 I/O permission for port {port:#x}: {message}")]
    IoPermission {
        /// Reserved port number used by the shared doorbell ABI.
        port: u16,
        /// Operating-system diagnostic returned by `ioperm`.
        message: String,
    },
    /// A reply-bearing command did not receive enough bytes back from the host.
    #[error("random reply length {actual_len} is shorter than requested {expected_len}")]
    ShortRandomReply {
        /// Number of bytes requested by the guest command.
        expected_len: usize,
        /// Number of bytes available after the transport returned.
        actual_len: usize,
    },
}

/// A typed one-shot command emitted by the guest white-box agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestCommand {
    payload: WhiteboxMarkerPayload,
    reply_width: Option<u8>,
}

impl GuestCommand {
    /// Builds an `always` assertion marker.
    #[must_use]
    pub fn always(id: impl Into<String>, message: impl Into<String>, condition: bool) -> Self {
        Self::assertion(
            WhiteboxAssertionMarkerFlavor::Always,
            id,
            message,
            condition,
            "crucible-guest:always",
        )
    }

    /// Builds a `sometimes` assertion marker.
    #[must_use]
    pub fn sometimes(id: impl Into<String>, message: impl Into<String>, condition: bool) -> Self {
        Self::assertion(
            WhiteboxAssertionMarkerFlavor::Sometimes,
            id,
            message,
            condition,
            "crucible-guest:sometimes",
        )
    }

    /// Builds a reachable-point marker.
    #[must_use]
    pub fn reachable(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::assertion(
            WhiteboxAssertionMarkerFlavor::Reachable,
            id,
            message,
            true,
            "crucible-guest:reachable",
        )
    }

    /// Builds an unreachable-dual marker.
    #[must_use]
    pub fn unreachable(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::assertion(
            WhiteboxAssertionMarkerFlavor::Unreachable,
            id,
            message,
            true,
            "crucible-guest:unreachable",
        )
    }

    /// Builds a setup-complete lifecycle marker.
    #[must_use]
    pub const fn setup_complete() -> Self {
        Self {
            payload: WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::SetupComplete),
            reply_width: None,
        }
    }

    /// Builds a test-done lifecycle marker.
    #[must_use]
    pub const fn test_done() -> Self {
        Self {
            payload: WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::TestDone),
            reply_width: None,
        }
    }

    /// Builds a diagnostic event marker.
    #[must_use]
    pub fn event(name: impl Into<String>, details: Vec<WhiteboxMarkerDetail>) -> Self {
        Self {
            payload: WhiteboxMarkerPayload::Event(WhiteboxEventMarkerBody {
                name: name.into(),
                details,
            }),
            reply_width: None,
        }
    }

    /// Builds a semantic coverage marker.
    #[must_use]
    pub fn coverage(point: impl Into<String>) -> Self {
        Self {
            payload: WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
                point: point.into(),
            }),
            reply_width: None,
        }
    }

    /// Builds an app-controlled random request marker.
    ///
    /// # Errors
    ///
    /// Returns [`GuestEmitterError::Usage`] when `width_bytes` is outside the
    /// shared random-request width range.
    pub fn get_random(
        width_bytes: u8,
        stream_tag: impl Into<String>,
    ) -> Result<Self, GuestEmitterError> {
        validate_random_width(width_bytes)?;
        Ok(Self {
            payload: WhiteboxMarkerPayload::RandomRequest(WhiteboxRandomRequestBody {
                request_id: CRUCIBLE_GUEST_DEFAULT_RANDOM_REQUEST_ID,
                width_bytes,
                stream_tag: stream_tag.into(),
            }),
            reply_width: Some(width_bytes),
        })
    }

    /// Returns the shared marker payload encoded by this command.
    #[must_use]
    pub const fn payload(&self) -> &WhiteboxMarkerPayload {
        &self.payload
    }

    /// Returns the reply width for reply-bearing commands.
    #[must_use]
    pub const fn reply_width(&self) -> Option<u8> {
        self.reply_width
    }

    /// Encodes this command into the shared doorbell frame ABI.
    ///
    /// # Errors
    ///
    /// Returns [`GuestEmitterError::MarkerEncode`] when the shared marker codec
    /// rejects the payload.
    pub fn encode_frame(&self) -> Result<Vec<u8>, GuestEmitterError> {
        encode_whitebox_marker_frame(&self.payload).map_err(GuestEmitterError::from)
    }

    fn assertion(
        flavor: WhiteboxAssertionMarkerFlavor,
        id: impl Into<String>,
        message: impl Into<String>,
        condition: bool,
        location: &'static str,
    ) -> Self {
        Self {
            payload: WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
                flavor,
                condition,
                must_hit: true,
                id: id.into(),
                message: message.into(),
                location: location.to_owned(),
                details: Vec::new(),
            }),
            reply_width: None,
        }
    }
}

/// A safe abstraction over the per-architecture doorbell instruction.
pub trait DoorbellTransport {
    /// Rings the doorbell with a mutable encoded frame buffer.
    ///
    /// The buffer is mutable because `random_request` uses the same guest-memory
    /// range for the host-to-guest reply. Observational marker transports should
    /// leave it unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`GuestEmitterError`] when the transport cannot issue the trap or
    /// cannot deliver the reply.
    fn ring(&mut self, frame: &mut [u8]) -> Result<(), GuestEmitterError>;
}

/// Result returned after a command has rung the doorbell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestCommandOutcome {
    /// An observational marker was emitted.
    Marker {
        /// Complete frame bytes passed to the transport.
        frame: Vec<u8>,
    },
    /// An app-random request was emitted and a reply was read.
    Random {
        /// Complete request frame bytes passed to the transport.
        request_frame: Vec<u8>,
        /// Reply bytes written by the host at the requested width.
        reply: Vec<u8>,
    },
}

/// Emits one guest command through a doorbell transport.
///
/// # Errors
///
/// Returns [`GuestEmitterError`] when command encoding fails, the transport
/// fails, or a reply-bearing command does not receive the requested number of
/// bytes.
pub fn emit_command<T>(
    command: &GuestCommand,
    transport: &mut T,
) -> Result<GuestCommandOutcome, GuestEmitterError>
where
    T: DoorbellTransport + ?Sized,
{
    let mut frame = command.encode_frame()?;
    let request_frame = frame.clone();
    transport.ring(&mut frame)?;
    if let Some(width) = command.reply_width() {
        let width = usize::from(width);
        if frame.len() < width {
            return Err(GuestEmitterError::ShortRandomReply {
                expected_len: width,
                actual_len: frame.len(),
            });
        }
        Ok(GuestCommandOutcome::Random {
            request_frame,
            reply: frame[..width].to_vec(),
        })
    } else {
        Ok(GuestCommandOutcome::Marker {
            frame: request_frame,
        })
    }
}

/// Parses CLI arguments into a typed guest command.
///
/// The iterator must contain only the arguments after the binary name.
///
/// # Errors
///
/// Returns [`GuestEmitterError::Usage`] when the verb, arity, boolean field,
/// key/value detail, or random width is invalid.
pub fn parse_cli_args<I, S>(args: I) -> Result<GuestCommand, GuestEmitterError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let words = args
        .into_iter()
        .map(|arg| arg.as_ref().to_owned())
        .collect::<Vec<_>>();
    let Some((verb, rest)) = words.split_first() else {
        return Err(usage_error("missing verb"));
    };
    match verb.as_str() {
        "always" => parse_condition_assertion(rest, GuestCommand::always, "always"),
        "sometimes" => parse_condition_assertion(rest, GuestCommand::sometimes, "sometimes"),
        "reachable" => parse_reachability(rest, GuestCommand::reachable, "reachable"),
        "unreachable" => parse_reachability(rest, GuestCommand::unreachable, "unreachable"),
        "setup-complete" => parse_zero_arity(rest, GuestCommand::setup_complete, "setup-complete"),
        "test-done" => parse_zero_arity(rest, GuestCommand::test_done, "test-done"),
        "event" => parse_event(rest),
        "coverage" => parse_coverage(rest),
        "get-random" => parse_get_random(rest),
        _ => Err(usage_error(format!("unknown verb `{verb}`"))),
    }
}

/// Doorbell transport that executes the native Linux guest trap instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstructionDoorbellTransport {
    abi: WhiteboxDoorbellAbi,
}

impl InstructionDoorbellTransport {
    /// Builds a transport from a shared ABI entry.
    #[must_use]
    pub const fn new(abi: WhiteboxDoorbellAbi) -> Self {
        Self { abi }
    }

    /// Builds a transport for the current Linux guest target.
    ///
    /// # Errors
    ///
    /// Returns [`GuestEmitterError::UnsupportedTarget`] when the crate is
    /// compiled for a non-Linux host or for an architecture without a doorbell
    /// ABI.
    pub fn native() -> Result<Self, GuestEmitterError> {
        native_doorbell_abi().map(Self::new)
    }

    /// Returns the shared ABI entry this transport executes.
    #[must_use]
    pub const fn abi(self) -> WhiteboxDoorbellAbi {
        self.abi
    }
}

impl DoorbellTransport for InstructionDoorbellTransport {
    fn ring(&mut self, frame: &mut [u8]) -> Result<(), GuestEmitterError> {
        ring_doorbell(self.abi.trap(), frame)
    }
}

fn parse_condition_assertion(
    rest: &[String],
    constructor: fn(String, String, bool) -> GuestCommand,
    verb: &'static str,
) -> Result<GuestCommand, GuestEmitterError> {
    if rest.len() != 3 {
        return Err(usage_error(format!("{verb} requires <id> <message> <0|1>")));
    }
    let condition = parse_condition(&rest[2])?;
    Ok(constructor(rest[0].clone(), rest[1].clone(), condition))
}

fn parse_reachability(
    rest: &[String],
    constructor: fn(String, String) -> GuestCommand,
    verb: &'static str,
) -> Result<GuestCommand, GuestEmitterError> {
    if rest.len() != 2 {
        return Err(usage_error(format!("{verb} requires <id> <message>")));
    }
    Ok(constructor(rest[0].clone(), rest[1].clone()))
}

fn parse_zero_arity(
    rest: &[String],
    constructor: fn() -> GuestCommand,
    verb: &'static str,
) -> Result<GuestCommand, GuestEmitterError> {
    if rest.is_empty() {
        Ok(constructor())
    } else {
        Err(usage_error(format!("{verb} takes no arguments")))
    }
}

fn parse_event(rest: &[String]) -> Result<GuestCommand, GuestEmitterError> {
    let Some((name, details)) = rest.split_first() else {
        return Err(usage_error("event requires <name> [k=v ...]"));
    };
    Ok(GuestCommand::event(name.clone(), parse_details(details)?))
}

fn parse_coverage(rest: &[String]) -> Result<GuestCommand, GuestEmitterError> {
    if rest.len() != 1 {
        return Err(usage_error("coverage requires <point>"));
    }
    Ok(GuestCommand::coverage(rest[0].clone()))
}

fn parse_get_random(rest: &[String]) -> Result<GuestCommand, GuestEmitterError> {
    if !(1..=2).contains(&rest.len()) {
        return Err(usage_error("get-random requires <width> [tag]"));
    }
    let width = rest[0].parse::<u8>().map_err(|_error| {
        usage_error(format!(
            "get-random width `{}` is not an integer in 1..={}",
            rest[0], WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES
        ))
    })?;
    let tag = rest
        .get(1)
        .cloned()
        .unwrap_or_else(|| CRUCIBLE_GUEST_DEFAULT_RANDOM_STREAM_TAG.to_owned());
    GuestCommand::get_random(width, tag)
}

fn parse_condition(value: &str) -> Result<bool, GuestEmitterError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(usage_error(format!(
            "condition `{value}` must be exactly 0 or 1"
        ))),
    }
}

fn parse_details(words: &[String]) -> Result<Vec<WhiteboxMarkerDetail>, GuestEmitterError> {
    let mut details = Vec::with_capacity(words.len());
    for word in words {
        let Some((key, value)) = word.split_once('=') else {
            return Err(usage_error(format!(
                "event detail `{word}` must use key=value syntax"
            )));
        };
        if key.is_empty() {
            return Err(usage_error("event detail key must not be empty"));
        }
        details.push(WhiteboxMarkerDetail::new(key, value));
    }
    Ok(details)
}

fn validate_random_width(width_bytes: u8) -> Result<(), GuestEmitterError> {
    if (1..=WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES).contains(&width_bytes) {
        Ok(())
    } else {
        Err(usage_error(format!(
            "get-random width {width_bytes} is outside 1..={}",
            WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES
        )))
    }
}

fn usage_error(message: impl Into<String>) -> GuestEmitterError {
    GuestEmitterError::Usage {
        message: format!("{}; {}", message.into(), usage()),
    }
}

fn native_doorbell_abi() -> Result<WhiteboxDoorbellAbi, GuestEmitterError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok(whitebox_doorbell_abi_for_architecture(
            WhiteboxDoorbellArchitecture::X86_64,
        ))
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        Ok(whitebox_doorbell_abi_for_architecture(
            WhiteboxDoorbellArchitecture::Aarch64,
        ))
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64")
    )))]
    {
        Err(unsupported_target())
    }
}

fn ring_doorbell(trap: WhiteboxDoorbellTrapAbi, frame: &mut [u8]) -> Result<(), GuestEmitterError> {
    match trap {
        WhiteboxDoorbellTrapAbi::X86PortIo { port } => ring_x86_64(port, frame),
        WhiteboxDoorbellTrapAbi::Aarch64Hlt { immediate } => ring_aarch64(immediate, frame),
    }
}

fn ring_x86_64(port: u16, frame: &mut [u8]) -> Result<(), GuestEmitterError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        enable_x86_64_port_io(port)?;
        let pointer = frame.as_mut_ptr() as usize;
        let len = frame.len();
        // SAFETY: the inline assembly is the private implementation of the
        // RFC-0010 Linux x86_64 doorbell ABI. `pointer` and `len` describe the
        // live mutable frame slice for the duration of the instruction, and the
        // reserved port comes from the shared ABI table.
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("rax") pointer,
                in("rcx") len,
                in("dx") port,
                options(nostack)
            );
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (port, frame);
        Err(unsupported_target())
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn enable_x86_64_port_io(port: u16) -> Result<(), GuestEmitterError> {
    // SAFETY: `ioperm` is called with the single reserved doorbell port from the
    // shared ABI table and a one-port range. It changes the current process I/O
    // permission bitmap before the immediately following `out dx,eax`.
    let result = unsafe { libc::ioperm(u64::from(port), 1, 1) };
    if result == 0 {
        Ok(())
    } else {
        Err(GuestEmitterError::IoPermission {
            port,
            message: std::io::Error::last_os_error().to_string(),
        })
    }
}

fn ring_aarch64(immediate: u16, frame: &mut [u8]) -> Result<(), GuestEmitterError> {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        if immediate != WHITEBOX_DOORBELL_AARCH64_RESERVED_IMMEDIATE {
            return Err(GuestEmitterError::Transport {
                message: format!(
                    "aarch64 doorbell immediate {immediate:#x} does not match shared ABI"
                ),
            });
        }
        let pointer = frame.as_mut_ptr() as usize;
        let len = frame.len();
        // SAFETY: the inline assembly is the private implementation of the
        // RFC-0010 Linux aarch64 doorbell ABI. `pointer` and `len` describe the
        // live mutable frame slice in x0/x1 for the duration of the instruction,
        // and the reserved immediate is checked against the shared ABI table.
        unsafe {
            core::arch::asm!(
                "hlt #0x04c1",
                in("x0") pointer,
                in("x1") len,
                options(nostack)
            );
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let _ = (immediate, frame);
        Err(unsupported_target())
    }
}

fn unsupported_target() -> GuestEmitterError {
    GuestEmitterError::UnsupportedTarget {
        target_arch: std::env::consts::ARCH,
        target_os: std::env::consts::OS,
    }
}
