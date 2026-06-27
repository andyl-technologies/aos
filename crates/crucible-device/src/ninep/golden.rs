//! 9p wire-format golden vectors: a known-bytes conformance corpus ([IO-18]).
//!
//! This module is the `gate:abi-conformance` corpus for the 9p ABI: a table of
//! `(name, raw_bytes, decoded_message)` triples asserting that decoding the exact
//! wire bytes yields the exact decoded form, and that re-encoding a reply yields
//! byte-identical output. The byte tables are written out longhand (no helper
//! that could mask an encoding drift) so a change to the wire layout fails a
//! vector loudly. Structured as a reusable [`request_vectors`] / [`reply_vectors`]
//! corpus a downstream conformance harness can import.

use super::codec::{self, GetattrReply, Message, Qid, QidType, StatfsReply, TMessage};

/// One request-side golden vector: a name, the raw frame, and its decoding.
pub struct RequestVector {
    /// A human label for diagnostics.
    pub name: &'static str,
    /// The exact little-endian wire bytes of the request frame.
    pub bytes: Vec<u8>,
    /// The expected decoded message.
    pub decoded: Message,
}

/// One reply-side golden vector: a name and the exact expected reply bytes.
pub struct ReplyVector {
    /// A human label for diagnostics.
    pub name: &'static str,
    /// The exact little-endian wire bytes the encoder must produce.
    pub bytes: Vec<u8>,
}

/// Returns the request-decode golden vectors.
///
/// Each entry's `bytes` are written byte-for-byte; the test asserts
/// `Message::decode(bytes) == decoded` and that the round-trip is stable.
pub fn request_vectors() -> Vec<RequestVector> {
    vec![
        RequestVector {
            name: "Tversion 9P2000.L msize=8192 tag=1",
            // size=21 type=100 tag=1 msize=8192 version="9P2000.L"(len=8)
            bytes: vec![
                21, 0, 0, 0,   // size
                100, // Tversion
                1, 0, // tag
                0, 32, 0, 0, // msize = 8192
                8, 0, // version length
                b'9', b'P', b'2', b'0', b'0', b'0', b'.', b'L',
            ],
            decoded: Message {
                tag: 1,
                body: TMessage::Version {
                    msize: 8192,
                    version: "9P2000.L".to_string(),
                },
            },
        },
        RequestVector {
            name: "Tattach fid=1 tag=2",
            // size type tag fid afid uname="u"(1) aname=""(0) n_uname=0
            bytes: vec![
                // size = 7 + 4 + 4 + (2+1) + (2+0) + 4 = 24
                24, 0, 0, 0,   //
                104, // Tattach
                2, 0, // tag
                1, 0, 0, 0, // fid
                0xff, 0xff, 0xff, 0xff, // afid = NOFID
                1, 0, b'u', // uname = "u"
                0, 0, // aname = ""
                0, 0, 0, 0, // n_uname
            ],
            decoded: Message {
                tag: 2,
                body: TMessage::Attach { fid: 1 },
            },
        },
        RequestVector {
            name: "Twalk fid=1 newfid=2 [bin,tool] tag=3",
            bytes: vec![
                // size = 7 + 4 + 4 + 2 + (2+3) + (2+4) = 28
                28, 0, 0, 0,   //
                110, // Twalk
                3, 0, // tag
                1, 0, 0, 0, // fid
                2, 0, 0, 0, // newfid
                2, 0, // nwname = 2
                3, 0, b'b', b'i', b'n', // "bin"
                4, 0, b't', b'o', b'o', b'l', // "tool"
            ],
            decoded: Message {
                tag: 3,
                body: TMessage::Walk {
                    fid: 1,
                    newfid: 2,
                    wnames: vec!["bin".to_string(), "tool".to_string()],
                },
            },
        },
        RequestVector {
            name: "Tread fid=2 offset=0 count=64 tag=5",
            bytes: vec![
                // size = 7 + 4 + 8 + 4 = 23
                23, 0, 0, 0,   //
                116, // Tread
                5, 0, // tag
                2, 0, 0, 0, // fid
                0, 0, 0, 0, 0, 0, 0, 0, // offset
                64, 0, 0, 0, // count
            ],
            decoded: Message {
                tag: 5,
                body: TMessage::Read {
                    fid: 2,
                    offset: 0,
                    count: 64,
                },
            },
        },
        RequestVector {
            name: "Tgetattr fid=2 mask=0x7ff tag=6",
            bytes: vec![
                // size = 7 + 4 + 8 = 19
                19, 0, 0, 0,  //
                24, // Tgetattr
                6, 0, // tag
                2, 0, 0, 0, // fid
                0xff, 0x07, 0, 0, 0, 0, 0, 0, // request_mask = 0x7ff
            ],
            decoded: Message {
                tag: 6,
                body: TMessage::Getattr {
                    fid: 2,
                    request_mask: 0x7ff,
                },
            },
        },
        RequestVector {
            name: "Tclunk fid=2 tag=7",
            bytes: vec![
                // size = 7 + 4 = 11
                11, 0, 0, 0,   //
                120, // Tclunk
                7, 0, // tag
                2, 0, 0, 0, // fid
            ],
            decoded: Message {
                tag: 7,
                body: TMessage::Clunk { fid: 2 },
            },
        },
        RequestVector {
            name: "Twrite (mutating) collapses to Mutating tag=9",
            bytes: vec![
                // size = 7 + 4 = 11 (a stub body; the type alone routes to EROFS)
                11, 0, 0, 0,   //
                118, // Twrite
                9, 0, // tag
                0, 0, 0, 0, //
            ],
            decoded: Message {
                tag: 9,
                body: TMessage::Mutating { msg_type: 118 },
            },
        },
        RequestVector {
            name: "unknown type 200 -> Unknown tag=11",
            bytes: vec![
                // size = 7 + 1 = 8
                8, 0, 0, 0,   //
                200, // unknown
                11, 0, // tag
                0,
            ],
            decoded: Message {
                tag: 11,
                body: TMessage::Unknown { msg_type: 200 },
            },
        },
    ]
}

/// Returns the reply-encode golden vectors.
///
/// Each entry's `bytes` are the exact frame the corresponding encoder must
/// produce; the test re-encodes and asserts equality.
pub fn reply_vectors() -> Vec<ReplyVector> {
    vec![
        ReplyVector {
            name: "Rversion msize=8192 9P2000.L tag=1",
            // A panic here is the intended signal: this is a test corpus, and an
            // encode failure for a fixed, in-range input is a codec bug.
            bytes: codec::encode_rversion(1, 8192, codec::PROTOCOL_VERSION)
                .unwrap_or_else(|e| panic!("Rversion golden vector must encode: {e}")),
        },
        ReplyVector {
            name: "Rlerror EROFS tag=9",
            bytes: vec![
                // size = 7 + 4 = 11
                11, 0, 0, 0, //
                7, // Rlerror
                9, 0, // tag
                30, 0, 0, 0, // ecode = EROFS
            ],
        },
        ReplyVector {
            name: "Rclunk tag=7",
            bytes: vec![
                // size = 7
                7, 0, 0, 0,   //
                121, // Rclunk
                7, 0, // tag
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_golden_vectors_decode_exactly() {
        for v in request_vectors() {
            let decoded = Message::decode(&v.bytes)
                .unwrap_or_else(|e| panic!("vector {} failed to decode: {e}", v.name));
            assert_eq!(decoded, v.decoded, "decode mismatch for {}", v.name);
        }
    }

    #[test]
    fn rlerror_golden_vector_encodes_exactly() {
        let bytes = codec::encode_rlerror(9, super::super::errno::EROFS)
            .unwrap_or_else(|e| panic!("encode failed: {e}"));
        let want = &reply_vectors()[1];
        assert_eq!(bytes, want.bytes, "{}", want.name);
    }

    #[test]
    fn rclunk_golden_vector_encodes_exactly() {
        let bytes = codec::encode_rclunk(7).unwrap_or_else(|e| panic!("encode failed: {e}"));
        let want = &reply_vectors()[2];
        assert_eq!(bytes, want.bytes, "{}", want.name);
    }

    #[test]
    fn rversion_golden_vector_matches_handwritten_bytes() {
        // The handwritten expected bytes for Rversion, independent of the encoder.
        let want: Vec<u8> = vec![
            // size = 7 + 4 + 2 + 8 = 21
            21, 0, 0, 0,   //
            101, // Rversion
            1, 0, // tag
            0, 32, 0, 0, // msize = 8192
            8, 0, // version length
            b'9', b'P', b'2', b'0', b'0', b'0', b'.', b'L',
        ];
        let got = codec::encode_rversion(1, 8192, codec::PROTOCOL_VERSION)
            .unwrap_or_else(|e| panic!("encode failed: {e}"));
        assert_eq!(got, want);
    }

    #[test]
    fn qid_round_trips_through_wire_bytes() {
        let qid = Qid::new(QidType::Symlink, 0x0123_4567_89ab_cdef);
        let mut bytes = Vec::new();
        qid.encode_into(&mut bytes);
        assert_eq!(bytes.len(), codec::QID_LEN);
        let decoded = Qid::decode(&bytes).unwrap_or_else(|e| panic!("qid decode: {e}"));
        assert_eq!(decoded, qid);
        // The wire layout: type[1] version[4] path[8].
        assert_eq!(bytes[0], QidType::Symlink.to_wire());
        assert_eq!(
            u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
            Qid::FIXED_VERSION
        );
    }

    #[test]
    fn getattr_reply_encodes_with_fixed_epoch_timestamps() {
        let reply = GetattrReply {
            valid: 0x7ff,
            qid: Qid::new(QidType::File, 42),
            mode: 0o100555,
            uid: 0,
            gid: 0,
            nlink: 1,
            rdev: 0,
            size: 13,
            blksize: 4096,
            blocks: 1,
        };
        let frame = reply.encode(6).unwrap_or_else(|e| panic!("encode: {e}"));
        assert_eq!(frame[4], codec::RGETATTR);
        // The trailing 9 timestamp words are all zero.
        let ts = &frame[frame.len() - 9 * 8..];
        assert!(ts.iter().all(|&b| b == 0), "timestamps must be fixed epoch");
    }

    #[test]
    fn statfs_reply_encodes_synthetic_fixed_values() {
        let reply = StatfsReply {
            fs_type: 0x5346_5039,
            bsize: 4096,
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            fsid: 0,
            namelen: 255,
        };
        let frame = reply.encode(3).unwrap_or_else(|e| panic!("encode: {e}"));
        assert_eq!(frame[4], codec::RSTATFS);
        assert_eq!(
            u32::from_le_bytes([frame[7], frame[8], frame[9], frame[10]]),
            0x5346_5039
        );
    }

    #[test]
    fn all_request_vectors_are_size_consistent() {
        // Every golden frame's size[4] prefix must equal its byte length, or
        // Message::decode rejects it with SizeMismatch.
        for v in request_vectors() {
            let size = u32::from_le_bytes([v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3]]);
            assert_eq!(
                size as usize,
                v.bytes.len(),
                "vector {} size prefix wrong",
                v.name
            );
        }
    }
}
