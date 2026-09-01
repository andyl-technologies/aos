//! The versioned block wire ABI: `BlockRequest` and `BlockResponse` codecs.
//!
//! This module owns the on-wire format the block sub-node speaks across the
//! `SLOT_BLK_IO` shmem rings ([IO-8], [IO-9]). Both messages are a fixed field
//! order with all multi-byte integers in **little-endian**; reserved bytes are
//! zero on emit and rejected when nonzero on receive. Decoding is fully
//! bounds-checked: an
//! arbitrary byte sequence never panics, never reads out of bounds, and yields a
//! [`BlockCodecError`] when malformed — the fuzz-safe boundary the spec demands.
//!
//! ```text
//! BlockRequest  (VM slot -> SLOT_BLK_IO), little-endian, header = 28 bytes
//!   off 0   u8   op          -- 0=read, 1=write, 2=flush, 3=get_length
//!   off 1   u8   version     -- block wire ABI version (= 4)
//!   off 2   u16  _reserved   -- zero on emit, rejected when nonzero
//!   off 4   u64  epoch       -- transport generation
//!   off 12  u32 request_id   -- correlation ID within the epoch
//!   off 16  u64 offset       -- byte offset (read/write; 0 otherwise)
//!   off 24  u32 count        -- byte count (read/write; 0 otherwise)
//!   off 28  [count bytes]    -- payload, write only (else absent)
//!
//! BlockResponse (SLOT_BLK_IO -> VM slot), little-endian, header = 20 bytes
//!   off 0   u8   status      -- terminal or transport-control status
//!   off 1   u8   version     -- block wire ABI version (= 4)
//!   off 2   u16  _reserved   -- zero on emit, rejected when nonzero
//!   off 4   u64  epoch       -- echoes the request epoch
//!   off 12  u32 request_id   -- echoes the request ID
//!   off 16  u32 count        -- response data length
//!   off 20  [count bytes]    -- success data, or one typed-error byte on error
//! ```
//!
//! The encoded bytes are carried as the opaque
//! [`crate::request::Request::payload`] / [`crate::request::Response::payload`]
//! and ride the `FrameEntry.data` field of a `SLOT_BLK_IO` ring frame
//! ([`crucible_shmem::MAX_FRAME_DATA`] = 4608 bytes, which fits a 4 KiB read
//! response plus this 12-byte header). [`crate::subnode::IoCore`] supplies the
//! shmem lifecycle bridge that drains VM-to-block frames, computes responses,
//! publishes block-to-VM frames, and issues the corresponding wake.

/// The block wire ABI version encoded in every request and response.
///
/// A decoder rejects any message whose version byte differs from this constant
/// ([IO-8]); bumping it is a breaking ABI change gated by `gate:abi-conformance`.
pub const BLOCK_ABI_VERSION: u8 = 4;

/// The fixed size in bytes of an encoded [`BlockRequest`] header.
pub const REQUEST_HEADER_LEN: usize = 28;

/// The fixed size in bytes of an encoded [`BlockResponse`] header.
pub const RESPONSE_HEADER_LEN: usize = 20;

#[path = "codec/request.rs"]
mod request;
#[path = "codec/response.rs"]
mod response;
#[path = "codec/support.rs"]
mod support;
#[path = "codec/types.rs"]
mod types;

pub use request::BlockRequest;
pub use response::BlockResponse;
pub use support::BlockCodecError;
use support::*;
pub use types::*;
