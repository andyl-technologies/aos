//! Defines the registered closed protobuf vocabulary for publisher-local-v1.
//!
//! ```text
//! One SOCK_SEQPACKET record = one PublisherPacket protobuf, <= 65536 bytes.
//! SCM_RIGHTS descriptors are ordered separately by the operation matrix.
//! ```

/// The registered operation discriminants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Operation {
    /// The Unspecified registry entry.
    Unspecified = 0,
    /// The Probe registry entry.
    Probe = 1,
    /// The Publish registry entry.
    Publish = 2,
    /// The Adopt registry entry.
    Adopt = 3,
    /// The InspectBody registry entry.
    InspectBody = 4,
    /// The Retire registry entry.
    Retire = 5,
    /// The Restore registry entry.
    Restore = 6,
    /// The FinishRetirement registry entry.
    FinishRetirement = 7,
    /// The Drain registry entry.
    Drain = 8,
    /// The Inventory registry entry.
    Inventory = 9,
    /// The Resume registry entry.
    Resume = 10,
}

/// The registered bodykind discriminants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum BodyKind {
    /// The Unspecified registry entry.
    Unspecified = 0,
    /// The Sealed registry entry.
    Sealed = 1,
    /// The Chunk registry entry.
    Chunk = 2,
    /// The Pack registry entry.
    Pack = 3,
}

/// The registered resultcode discriminants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum ResultCode {
    /// The Ok registry entry.
    Ok = 0,
    /// The Invalid registry entry.
    Invalid = 1,
    /// The Denied registry entry.
    Denied = 2,
    /// The NotFound registry entry.
    NotFound = 3,
    /// The Conflict registry entry.
    Conflict = 4,
    /// The Unsupported registry entry.
    Unsupported = 5,
    /// The ResourceExhausted registry entry.
    ResourceExhausted = 6,
    /// The Unavailable registry entry.
    Unavailable = 7,
}

/// The registered publisher bodykey message.
#[derive(Clone, PartialEq, prost::Message)]
pub struct BodyKey {
    /// The registered `kind` field (tag 1).
    #[prost(enumeration = "BodyKind", tag = "1")]
    pub kind: i32,
    /// The registered `descriptor` field (tag 2).
    #[prost(bytes = "vec", tag = "2")]
    pub descriptor: Vec<u8>,
    /// The registered `codec` field (tag 3).
    #[prost(uint32, tag = "3")]
    pub codec: u32,
    /// The registered `pack_id` field (tag 4).
    #[prost(bytes = "vec", tag = "4")]
    pub pack_id: Vec<u8>,
}

/// The registered publisher claim message.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Claim {
    /// The registered `descriptor` field (tag 1).
    #[prost(bytes = "vec", tag = "1")]
    pub descriptor: Vec<u8>,
    /// The registered `chunk_profile` field (tag 2).
    #[prost(string, tag = "2")]
    pub chunk_profile: String,
    /// The registered `plaintext_size` field (tag 3).
    #[prost(uint64, tag = "3")]
    pub plaintext_size: u64,
    /// The registered `manifest_offset` field (tag 4).
    #[prost(uint64, tag = "4")]
    pub manifest_offset: u64,
    /// The registered `manifest_length` field (tag 5).
    #[prost(uint64, tag = "5")]
    pub manifest_length: u64,
    /// The registered `retention_id` field (tag 6).
    #[prost(bytes = "vec", tag = "6")]
    pub retention_id: Vec<u8>,
}

/// The registered publisher packet message.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Packet {
    /// The registered `version` field (tag 1).
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// The registered `request_id` field (tag 2).
    #[prost(uint64, tag = "2")]
    pub request_id: u64,
    /// The registered `operation` field (tag 3).
    #[prost(enumeration = "Operation", tag = "3")]
    pub operation: i32,
    /// The registered `domain` field (tag 4).
    #[prost(string, tag = "4")]
    pub domain: String,
    /// The registered `cache_incarnation` field (tag 5).
    #[prost(bytes = "vec", tag = "5")]
    pub cache_incarnation: Vec<u8>,
    /// The registered `wait_budget_ms` field (tag 6).
    #[prost(uint64, tag = "6")]
    pub wait_budget_ms: u64,
    /// The registered `claim` field (tag 7).
    #[prost(message, optional, tag = "7")]
    pub claim: Option<Claim>,
    /// The registered `body` field (tag 8).
    #[prost(message, optional, tag = "8")]
    pub body: Option<BodyKey>,
    /// The registered `body_incarnation` field (tag 9).
    #[prost(bytes = "vec", tag = "9")]
    pub body_incarnation: Vec<u8>,
    /// The registered `response` field (tag 10).
    #[prost(bool, tag = "10")]
    pub response: bool,
    /// The registered `result` field (tag 11).
    #[prost(enumeration = "ResultCode", tag = "11")]
    pub result: i32,
    /// The registered `verity_algorithm` field (tag 12).
    #[prost(uint32, tag = "12")]
    pub verity_algorithm: u32,
    /// The registered `verity_digest` field (tag 13).
    #[prost(bytes = "vec", tag = "13")]
    pub verity_digest: Vec<u8>,
    /// The registered `inventory_cursor` field (tag 14).
    #[prost(bytes = "vec", tag = "14")]
    pub inventory_cursor: Vec<u8>,
    /// The registered `inventory` field (tag 15).
    #[prost(message, repeated, tag = "15")]
    pub inventory: Vec<BodyKey>,
}
