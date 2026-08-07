//! Structure-aware block and 9p wire fuzz target.
//!
//! The target is a normal Rust function so `gate:abi-conformance` can execute
//! it hermetically without an external fuzzing runtime. It covers the pure block
//! request/response wire codec and a fail-closed 9p wire handler for the raw
//! message envelopes forwarded by the plugin callbacks.

use crate::{
    BlockRequest, BlockResponse, BlockWireError, NinePWireError, NinePWireHandlerOutcome,
    NinePWireMessage, handle_ninep_wire_fuzz_message,
};

/// Negotiated 9p `msize` used by the pure wire fuzz target.
pub const NINEP_FUZZ_MSIZE: u32 = 15;

const BLOCK_REQUEST_UNKNOWN_OP: [u8; 20] = [
    9, 3, 0, 0, // type/version/reserved
    1, 0, 0, 0, // request_id
    0, 0, 0, 0, 0, 0, 0, 0, // offset
    0, 0, 0, 0, // count
];
const BLOCK_REQUEST_BAD_VERSION: [u8; 20] = [
    0, 99, 0, 0, // type/version/reserved
    1, 0, 0, 0, // request_id
    0, 0, 0, 0, 0, 0, 0, 0, // offset
    1, 0, 0, 0, // count
];
const BLOCK_REQUEST_NONZERO_RESERVED: [u8; 20] = [
    0, 3, 1, 0, // type/version/reserved
    1, 0, 0, 0, // request_id
    0, 0, 0, 0, 0, 0, 0, 0, // offset
    1, 0, 0, 0, // count
];
const BLOCK_REQUEST_WRITE_COUNT_EXCEEDS: [u8; 22] = [
    1, 3, 0, 0, // type/version/reserved
    1, 0, 0, 0, // request_id
    0, 0, 0, 0, 0, 0, 0, 0, // offset
    4, 0, 0, 0, // count
    b'a', b'b',
];
const BLOCK_REQUEST_READ_TRAILING_PAYLOAD: [u8; 21] = [
    0, 3, 0, 0, // type/version/reserved
    1, 0, 0, 0, // request_id
    0, 0, 0, 0, 0, 0, 0, 0, // offset
    1, 0, 0, 0, // count
    b'x',
];
const BLOCK_REQUEST_DISCARD_TRAILING_PAYLOAD: [u8; 21] = [
    4, 3, 0, 0, // type/version/reserved
    1, 0, 0, 0, // request_id
    0, 0, 0, 0, 0, 0, 0, 0, // offset
    1, 0, 0, 0, // count
    b'x',
];
const BLOCK_RESPONSE_UNKNOWN_STATUS: [u8; 12] = [
    2, 3, 0, 0, // status/version/reserved
    1, 0, 0, 0, // request_id
    0, 0, 0, 0, // count
];
const BLOCK_RESPONSE_COUNT_EXCEEDS: [u8; 12] = [
    0, 3, 0, 0, // status/version/reserved
    1, 0, 0, 0, // request_id
    4, 0, 0, 0, // count
];
const BLOCK_RESPONSE_TRAILING_PAYLOAD: [u8; 13] = [
    0, 3, 0, 0, // status/version/reserved
    1, 0, 0, 0, // request_id
    0, 0, 0, 0, // count
    b'!',
];
const NINEP_SIZE_TOO_SMALL: [u8; 7] = [6, 0, 0, 0, 100, 1, 0];
const NINEP_DECLARED_EXCEEDS_FRAME: [u8; 7] = [10, 0, 0, 0, 100, 1, 0];
const NINEP_TRAILING_BYTES: [u8; 8] = [7, 0, 0, 0, 100, 1, 0, 0];
const NINEP_UNKNOWN_TYPE: [u8; 7] = [7, 0, 0, 0, 0xff, 1, 0];
const NINEP_MSIZE_EXCEEDS: [u8; 16] = [
    16, 0, 0, 0, 100, 1, 0, b'9', b'P', b'2', b'0', b'0', b'0', b'.', b'L', 0,
];

/// One seeded regression input for the block/9p wire fuzz target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoWireFuzzCase {
    /// Stable corpus name.
    pub name: &'static str,
    /// Wire channel primarily exercised by this frame.
    pub channel: IoWireFuzzChannel,
    /// Raw frame bytes supplied to the fuzz target.
    pub frame: &'static [u8],
}

/// A wire channel covered by the qemu-plugin wire fuzz target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoWireFuzzChannel {
    /// Block request payloads sent from a VM slot to `SLOT_BLK_IO`.
    BlockRequest,
    /// Block response payloads sent from `SLOT_BLK_IO` to a VM slot.
    BlockResponse,
    /// Raw 9p message envelopes forwarded through `SLOT_9P_IO`.
    NineP,
}

/// Result of running one frame through every pure I/O wire decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoWireFuzzOutcome {
    /// Block-request decode result.
    pub block_request: Result<(u32, BlockRequest), BlockWireError>,
    /// Block-response decode result.
    pub block_response: Result<BlockResponse, BlockWireError>,
    /// 9p envelope decode result.
    pub ninep_message: Result<NinePWireMessage, NinePWireError>,
    /// 9p handler result that always carries a deterministic 9p error response.
    pub ninep_handler: NinePWireHandlerOutcome,
}

/// Seeded regression corpus for malformed and adversarial block/9p wire frames.
pub const IO_WIRE_FUZZ_REGRESSION_CORPUS: [IoWireFuzzCase; 15] = [
    IoWireFuzzCase {
        name: "empty",
        channel: IoWireFuzzChannel::BlockRequest,
        frame: &[],
    },
    IoWireFuzzCase {
        name: "block-request-unknown-operation",
        channel: IoWireFuzzChannel::BlockRequest,
        frame: &BLOCK_REQUEST_UNKNOWN_OP,
    },
    IoWireFuzzCase {
        name: "block-request-bad-version",
        channel: IoWireFuzzChannel::BlockRequest,
        frame: &BLOCK_REQUEST_BAD_VERSION,
    },
    IoWireFuzzCase {
        name: "block-request-nonzero-reserved",
        channel: IoWireFuzzChannel::BlockRequest,
        frame: &BLOCK_REQUEST_NONZERO_RESERVED,
    },
    IoWireFuzzCase {
        name: "block-request-write-count-exceeds-payload",
        channel: IoWireFuzzChannel::BlockRequest,
        frame: &BLOCK_REQUEST_WRITE_COUNT_EXCEEDS,
    },
    IoWireFuzzCase {
        name: "block-request-read-trailing-payload",
        channel: IoWireFuzzChannel::BlockRequest,
        frame: &BLOCK_REQUEST_READ_TRAILING_PAYLOAD,
    },
    IoWireFuzzCase {
        name: "block-request-discard-trailing-payload",
        channel: IoWireFuzzChannel::BlockRequest,
        frame: &BLOCK_REQUEST_DISCARD_TRAILING_PAYLOAD,
    },
    IoWireFuzzCase {
        name: "block-response-unknown-status",
        channel: IoWireFuzzChannel::BlockResponse,
        frame: &BLOCK_RESPONSE_UNKNOWN_STATUS,
    },
    IoWireFuzzCase {
        name: "block-response-count-exceeds-payload",
        channel: IoWireFuzzChannel::BlockResponse,
        frame: &BLOCK_RESPONSE_COUNT_EXCEEDS,
    },
    IoWireFuzzCase {
        name: "block-response-trailing-payload",
        channel: IoWireFuzzChannel::BlockResponse,
        frame: &BLOCK_RESPONSE_TRAILING_PAYLOAD,
    },
    IoWireFuzzCase {
        name: "9p-declared-size-too-small",
        channel: IoWireFuzzChannel::NineP,
        frame: &NINEP_SIZE_TOO_SMALL,
    },
    IoWireFuzzCase {
        name: "9p-declared-size-exceeds-frame",
        channel: IoWireFuzzChannel::NineP,
        frame: &NINEP_DECLARED_EXCEEDS_FRAME,
    },
    IoWireFuzzCase {
        name: "9p-trailing-bytes",
        channel: IoWireFuzzChannel::NineP,
        frame: &NINEP_TRAILING_BYTES,
    },
    IoWireFuzzCase {
        name: "9p-unknown-type-envelope",
        channel: IoWireFuzzChannel::NineP,
        frame: &NINEP_UNKNOWN_TYPE,
    },
    IoWireFuzzCase {
        name: "9p-msize-exceeds",
        channel: IoWireFuzzChannel::NineP,
        frame: &NINEP_MSIZE_EXCEEDS,
    },
];

/// Runs one arbitrary byte frame through the pure block/9p wire fuzz target.
#[must_use]
pub fn run_io_wire_fuzz_target(frame: &[u8]) -> IoWireFuzzOutcome {
    run_io_wire_fuzz_target_with_msize(frame, NINEP_FUZZ_MSIZE)
}

/// Runs one arbitrary byte frame through the pure block/9p wire fuzz target.
#[must_use]
pub fn run_io_wire_fuzz_target_with_msize(frame: &[u8], ninep_msize: u32) -> IoWireFuzzOutcome {
    IoWireFuzzOutcome {
        block_request: BlockRequest::decode(frame),
        block_response: BlockResponse::decode(frame),
        ninep_message: NinePWireMessage::decode_with_msize(frame, ninep_msize),
        ninep_handler: handle_ninep_wire_fuzz_message(frame, ninep_msize),
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::{
        BlockResponseStatus, IO_WIRE_FUZZ_REGRESSION_CORPUS, IoWireFuzzChannel, IoWireFuzzOutcome,
    };

    use super::*;

    #[test]
    fn io_wire_regression_corpus_exercises_block_and_9p_wire_cases() {
        assert_io_wire_fuzz_corpus();
    }

    #[test]
    fn io_wire_fuzz_target_never_panics_on_regression_corpus() {
        for case in IO_WIRE_FUZZ_REGRESSION_CORPUS {
            let outcome = assert_clean_reject_or_deterministic_decode(case.frame);
            match case.channel {
                IoWireFuzzChannel::BlockRequest => assert!(outcome.block_request.is_err()),
                IoWireFuzzChannel::BlockResponse => assert!(outcome.block_response.is_err()),
                IoWireFuzzChannel::NineP if case.name == "9p-unknown-type-envelope" => {
                    assert!(outcome.ninep_message.is_ok());
                    assert_eq!(outcome.ninep_handler.errno(), 38);
                    assert_well_formed_9p_error_response(&outcome);
                }
                IoWireFuzzChannel::NineP if case.name == "9p-msize-exceeds" => {
                    assert_eq!(
                        outcome.ninep_message,
                        Err(NinePWireError::DeclaredSizeExceedsMsize {
                            size: 16,
                            msize: NINEP_FUZZ_MSIZE,
                        })
                    );
                    assert_eq!(outcome.ninep_handler.errno(), 22);
                    assert_well_formed_9p_error_response(&outcome);
                }
                IoWireFuzzChannel::NineP => {
                    assert!(outcome.ninep_message.is_err());
                    assert_well_formed_9p_error_response(&outcome);
                }
            }
        }
    }

    #[test]
    fn block_request_wire_messages_round_trip() {
        assert_decode_encode_roundtrip();
    }

    #[test]
    fn block_response_wire_messages_round_trip() {
        for response in generated_block_responses() {
            let encoded = match response.encode() {
                Ok(encoded) => encoded,
                Err(error) => panic!("block response should encode: {error}"),
            };
            assert_eq!(BlockResponse::decode(&encoded), Ok(response.clone()));
            assert_eq!(
                assert_clean_reject_or_deterministic_decode(&encoded).block_response,
                Ok(response),
            );
        }
    }

    #[test]
    fn ninep_wire_messages_round_trip_and_msize_is_enforced() {
        for message in generated_ninep_messages() {
            let encoded = match message.encode() {
                Ok(encoded) => encoded,
                Err(error) => panic!("9p message should encode: {error}"),
            };
            assert_eq!(NinePWireMessage::decode(&encoded), Ok(message.clone()));
            assert_eq!(
                assert_clean_reject_or_deterministic_decode(&encoded).ninep_message,
                Ok(message),
            );
        }

        let encoded = match NinePWireMessage::new(100, 1, b"9P2000.L".to_vec()).encode() {
            Ok(encoded) => encoded,
            Err(error) => panic!("9p message should encode: {error}"),
        };
        assert_eq!(
            NinePWireMessage::decode_with_msize(&encoded, 8),
            Err(NinePWireError::DeclaredSizeExceedsMsize { size: 15, msize: 8 })
        );
        assert_eq!(
            assert_clean_reject_or_deterministic_decode(&encoded)
                .ninep_handler
                .errno(),
            5,
        );
    }

    #[test]
    fn structure_aware_malformed_wire_frames_never_panic() {
        for operation in [0, 1, 2, 3, 4, u8::MAX] {
            for payload_len in [0, 1, 2, 4, 8] {
                let frame = structured_block_request(operation, 3, 0, 7, 4096, 3, payload_len);
                let outcome = assert_clean_reject_or_deterministic_decode(&frame);
                if operation > 4 {
                    assert!(outcome.block_request.is_err());
                }
            }
        }

        for status in [0, 1, 2, u8::MAX] {
            for payload_len in [0, 1, 2, 4, 8] {
                let frame = structured_block_response(status, 3, 0, 7, 3, payload_len);
                let outcome = assert_clean_reject_or_deterministic_decode(&frame);
                if status > 1 {
                    assert!(outcome.block_response.is_err());
                }
            }
        }

        for message_type in [0, 100, 101, 116, 117, 126, 127, u8::MAX] {
            let frame = structured_ninep_frame(message_type, 9, 4);
            let outcome = assert_clean_reject_or_deterministic_decode(&frame);
            assert!(outcome.ninep_message.is_ok());
            assert_well_formed_9p_error_response(&outcome);
        }
    }

    #[test]
    fn generated_truncations_and_trailing_bytes_stay_typed() {
        for frame in well_formed_block_request_frames() {
            for len in 0..frame.len() {
                let truncated = &frame[..len];
                let outcome = assert_clean_reject_or_deterministic_decode(truncated);
                assert!(outcome.block_request.is_err());
            }

            let mut trailing = frame.clone();
            trailing.push(0xa5);
            let outcome = assert_clean_reject_or_deterministic_decode(&trailing);
            assert!(outcome.block_request.is_err());
        }

        for frame in well_formed_block_response_frames() {
            for len in 0..frame.len() {
                let truncated = &frame[..len];
                let outcome = assert_clean_reject_or_deterministic_decode(truncated);
                assert!(outcome.block_response.is_err());
            }

            let mut trailing = frame.clone();
            trailing.push(0xa5);
            let outcome = assert_clean_reject_or_deterministic_decode(&trailing);
            assert!(outcome.block_response.is_err());
        }

        for frame in well_formed_ninep_frames() {
            for len in 0..frame.len() {
                let truncated = &frame[..len];
                let outcome = assert_clean_reject_or_deterministic_decode(truncated);
                assert!(outcome.ninep_message.is_err());
                assert_well_formed_9p_error_response(&outcome);
            }

            let mut trailing = frame.clone();
            trailing.push(0xa5);
            let outcome = assert_clean_reject_or_deterministic_decode(&trailing);
            assert!(matches!(
                outcome.ninep_message,
                Err(NinePWireError::DeclaredSizeHasTrailingBytes { .. })
            ));
            assert_well_formed_9p_error_response(&outcome);
        }
    }

    #[test]
    fn wire_fuzz_target_reports_deterministic_decode_results() {
        let frame = structured_ninep_frame(100, 1, 8);
        let first = assert_clean_reject_or_deterministic_decode(&frame);
        let second = assert_clean_reject_or_deterministic_decode(&frame);
        assert_eq!(first, second);
    }

    fn assert_io_wire_fuzz_corpus() {
        let regression_corpus = IO_WIRE_FUZZ_REGRESSION_CORPUS;
        assert!(regression_corpus.len() >= 15);
        assert!(corpus_contains("block-request-unknown-operation"));
        assert!(corpus_contains("block-request-write-count-exceeds-payload"));
        assert!(corpus_contains("block-request-discard-trailing-payload"));
        assert!(corpus_contains("block-response-unknown-status"));
        assert!(corpus_contains("block-response-trailing-payload"));
        assert!(corpus_contains("9p-declared-size-too-small"));
        assert!(corpus_contains("9p-declared-size-exceeds-frame"));
        assert!(corpus_contains("9p-trailing-bytes"));
        assert!(corpus_contains("9p-msize-exceeds"));
    }

    fn assert_decode_encode_roundtrip() {
        for (request_id, request) in generated_block_requests() {
            let encoded = match request.encode(request_id) {
                Ok(encoded) => encoded,
                Err(error) => panic!("block request should encode: {error}"),
            };
            assert_eq!(
                BlockRequest::decode(&encoded),
                Ok((request_id, request.clone()))
            );
            assert_eq!(
                assert_clean_reject_or_deterministic_decode(&encoded).block_request,
                Ok((request_id, request)),
            );
        }
    }

    fn assert_well_formed_9p_error_response(outcome: &IoWireFuzzOutcome) {
        assert_eq!(outcome.ninep_handler.response().message_type(), 7);
        assert_eq!(outcome.ninep_handler.response().payload().len(), 4);
        let encoded = match outcome.ninep_handler.response().encode() {
            Ok(encoded) => encoded,
            Err(error) => panic!("9p fuzz error response should encode: {error}"),
        };
        assert_eq!(
            NinePWireMessage::decode_with_msize(&encoded, u32::MAX),
            Ok(outcome.ninep_handler.response().clone())
        );
    }

    fn assert_clean_reject_or_deterministic_decode(frame: &[u8]) -> IoWireFuzzOutcome {
        match catch_unwind(AssertUnwindSafe(|| run_io_wire_fuzz_target(frame))) {
            Ok(outcome) => outcome,
            Err(_) => panic!("I/O wire fuzz target panicked for frame {frame:?}"),
        }
    }

    fn corpus_contains(name: &str) -> bool {
        IO_WIRE_FUZZ_REGRESSION_CORPUS
            .iter()
            .any(|case| case.name == name)
    }

    fn generated_block_requests() -> Vec<(u32, BlockRequest)> {
        let write = match BlockRequest::write(4096, b"data".to_vec()) {
            Ok(request) => request,
            Err(error) => panic!("write request should build: {error}"),
        };
        vec![
            (0, BlockRequest::read(0, 0)),
            (1, BlockRequest::read(4096, 512)),
            (2, write),
            (3, BlockRequest::flush()),
            (4, BlockRequest::get_length()),
            (5, BlockRequest::discard(8192, 4096)),
        ]
    }

    fn generated_block_responses() -> Vec<BlockResponse> {
        vec![
            BlockResponse::new(BlockResponseStatus::Ok, 0, Vec::new()),
            BlockResponse::new(BlockResponseStatus::Ok, 1, b"abcd".to_vec()),
            BlockResponse::new(BlockResponseStatus::Ok, 2, 4096_u64.to_le_bytes().to_vec()),
            BlockResponse::new(BlockResponseStatus::Error, 3, vec![8]),
        ]
    }

    fn generated_ninep_messages() -> Vec<NinePWireMessage> {
        vec![
            NinePWireMessage::new(100, 1, b"9P2000.L".to_vec()),
            NinePWireMessage::new(104, 2, vec![0, 0, 0, 0]),
            NinePWireMessage::new(116, 3, b"read".to_vec()),
            NinePWireMessage::new(255, u16::MAX, Vec::new()),
        ]
    }

    fn well_formed_block_request_frames() -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for (request_id, request) in generated_block_requests() {
            match request.encode(request_id) {
                Ok(encoded) => frames.push(encoded),
                Err(error) => panic!("block request should encode: {error}"),
            }
        }
        frames
    }

    fn well_formed_block_response_frames() -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for response in generated_block_responses() {
            match response.encode() {
                Ok(encoded) => frames.push(encoded),
                Err(error) => panic!("block response should encode: {error}"),
            }
        }
        frames
    }

    fn well_formed_ninep_frames() -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for message in generated_ninep_messages() {
            match message.encode() {
                Ok(encoded) => frames.push(encoded),
                Err(error) => panic!("9p message should encode: {error}"),
            }
        }
        frames
    }

    fn structured_block_request(
        operation: u8,
        version: u8,
        reserved: u16,
        request_id: u32,
        offset: u64,
        count: u32,
        payload_len: usize,
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(20 + payload_len);
        frame.push(operation);
        frame.push(version);
        frame.extend_from_slice(&reserved.to_le_bytes());
        frame.extend_from_slice(&request_id.to_le_bytes());
        frame.extend_from_slice(&offset.to_le_bytes());
        frame.extend_from_slice(&count.to_le_bytes());
        for index in 0..payload_len {
            frame.push((index & 0xff) as u8);
        }
        frame
    }

    fn structured_block_response(
        status: u8,
        version: u8,
        reserved: u16,
        request_id: u32,
        count: u32,
        payload_len: usize,
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(12 + payload_len);
        frame.push(status);
        frame.push(version);
        frame.extend_from_slice(&reserved.to_le_bytes());
        frame.extend_from_slice(&request_id.to_le_bytes());
        frame.extend_from_slice(&count.to_le_bytes());
        for index in 0..payload_len {
            frame.push((0xa0 | (index & 0x0f)) as u8);
        }
        frame
    }

    fn structured_ninep_frame(message_type: u8, tag: u16, payload_len: usize) -> Vec<u8> {
        let len = 7 + payload_len;
        let mut frame = Vec::with_capacity(len);
        frame.extend_from_slice(&(len as u32).to_le_bytes());
        frame.push(message_type);
        frame.extend_from_slice(&tag.to_le_bytes());
        for index in 0..payload_len {
            frame.push((index & 0xff) as u8);
        }
        frame
    }
}
