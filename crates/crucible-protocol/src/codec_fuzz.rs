//! Structure-aware control-codec fuzz target.
//!
//! The target is a normal Rust function so the ABI-conformance gate can execute
//! it hermetically without an external fuzzing runtime. External fuzzers can also
//! feed arbitrary bytes through [`run_control_codec_fuzz_target`].

use crate::{
    ControlTag, FrameDecodeError, HostMsg, PluginMsg, control_decode_host_msg,
    control_decode_plugin_msg, control_frame_tag,
};

const OVERSIZE_LENGTH: [u8; 4] = [0, 0, 0, 65];
const HELLO_SHORT_PAYLOAD: [u8; 5] = [0, 0, 0, 1, 0xF0];
const HELLO_LONG_PAYLOAD: [u8; 14] = [0, 0, 0, 10, 0xF0, 0, 0, 0, 1, 0, 0, 0, 1, 0];
const SETUP_ACK_TRUNCATED: [u8; 5] = [0, 0, 0, 2, 0x02];
const SETUP_ACK_LONG_PAYLOAD: [u8; 7] = [0, 0, 0, 3, 0x02, 0, 0];
const QUIT_TRAILING_BYTES: [u8; 6] = [0, 0, 0, 1, 0x12, 0];
const ZERO_LENGTH_TRAILING: [u8; 5] = [0, 0, 0, 0, 0x12];
const WRONG_DIRECTION_HOST: [u8; 21] = [
    0, 0, 0, 17, 0xF1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
];
const WRONG_DIRECTION_PLUGIN: [u8; 13] = [0, 0, 0, 9, 0xF0, 0, 0, 0, 1, 0, 0, 0, 1];
const MAX_SIZED_QUIT_LONG_PAYLOAD: [u8; 68] = [
    0, 0, 0, 64, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
];

/// One seeded regression input for the control-codec fuzz target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlCodecFuzzCase {
    /// Stable corpus name.
    pub name: &'static str,
    /// Raw frame bytes supplied to the fuzz target.
    pub frame: &'static [u8],
}

/// Result of running one frame through every pure control decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlCodecFuzzOutcome {
    /// Plugin-direction decode result.
    pub plugin: Result<PluginMsg, FrameDecodeError>,
    /// Host-direction decode result.
    pub host: Result<HostMsg, FrameDecodeError>,
    /// Direction-agnostic tag decode result.
    pub tag: Result<ControlTag, FrameDecodeError>,
}

/// Seeded regression corpus for malformed and adversarial control frames.
pub const CODEC_FUZZ_REGRESSION_CORPUS: [ControlCodecFuzzCase; 15] = [
    ControlCodecFuzzCase {
        name: "empty",
        frame: &[],
    },
    ControlCodecFuzzCase {
        name: "truncated-length-one-byte",
        frame: &[0],
    },
    ControlCodecFuzzCase {
        name: "truncated-length-three-bytes",
        frame: &[0, 0, 0],
    },
    ControlCodecFuzzCase {
        name: "oversize-length",
        frame: &OVERSIZE_LENGTH,
    },
    ControlCodecFuzzCase {
        name: "missing-tag",
        frame: &[0, 0, 0, 0],
    },
    ControlCodecFuzzCase {
        name: "unknown-tag",
        frame: &[0, 0, 0, 1, 0x99],
    },
    ControlCodecFuzzCase {
        name: "zero-length-trailing-byte",
        frame: &ZERO_LENGTH_TRAILING,
    },
    ControlCodecFuzzCase {
        name: "hello-short-payload",
        frame: &HELLO_SHORT_PAYLOAD,
    },
    ControlCodecFuzzCase {
        name: "hello-long-payload",
        frame: &HELLO_LONG_PAYLOAD,
    },
    ControlCodecFuzzCase {
        name: "setup-ack-truncated-payload",
        frame: &SETUP_ACK_TRUNCATED,
    },
    ControlCodecFuzzCase {
        name: "setup-ack-long-payload",
        frame: &SETUP_ACK_LONG_PAYLOAD,
    },
    ControlCodecFuzzCase {
        name: "quit-trailing-bytes",
        frame: &QUIT_TRAILING_BYTES,
    },
    ControlCodecFuzzCase {
        name: "max-sized-quit-long-payload",
        frame: &MAX_SIZED_QUIT_LONG_PAYLOAD,
    },
    ControlCodecFuzzCase {
        name: "well-formed-host-frame-in-plugin-decoder",
        frame: &WRONG_DIRECTION_HOST,
    },
    ControlCodecFuzzCase {
        name: "well-formed-plugin-frame-in-host-decoder",
        frame: &WRONG_DIRECTION_PLUGIN,
    },
];

/// Runs one arbitrary byte frame through the pure control-codec fuzz target.
///
/// The function performs no I/O and allocates only through the decoders'
/// ordinary owned error/message paths.
#[must_use]
pub fn run_control_codec_fuzz_target(frame: &[u8]) -> ControlCodecFuzzOutcome {
    ControlCodecFuzzOutcome {
        plugin: control_decode_plugin_msg(frame),
        host: control_decode_host_msg(frame),
        tag: control_frame_tag(frame),
    }
}
