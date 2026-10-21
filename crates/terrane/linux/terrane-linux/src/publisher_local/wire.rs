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
    /// Retains pending inode custody without returning backing access.
    InspectPending = 11,
    /// Observes retained quarantine custody without content or lifecycle authority.
    InspectQuarantine = 12,
    /// Moves an exact retained canonical sealed inode into non-serving quarantine.
    Quarantine = 13,
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
    /// The sealed, chunk or pack key shape.
    #[prost(enumeration = "BodyKind", tag = "1")]
    pub kind: i32,
    /// The canonical chunk or manifest descriptor; absent for pack keys.
    #[prost(bytes = "vec", tag = "2")]
    pub descriptor: Vec<u8>,
    /// The registered chunk codec byte (0, 1 or 2); absent for other keys.
    #[prost(uint32, tag = "3")]
    pub codec: u32,
    /// The existing 16-byte pack identity; absent for other key shapes.
    #[prost(bytes = "vec", tag = "4")]
    pub pack_id: Vec<u8>,
}

/// The registered publisher claim message.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Claim {
    /// The canonical inline-chunk or manifest descriptor.
    #[prost(bytes = "vec", tag = "1")]
    pub descriptor: Vec<u8>,
    /// The configured registered chunk-profile label.
    #[prost(string, tag = "2")]
    pub chunk_profile: String,
    /// The exact assembled plaintext size, independent of manifest encoded size.
    #[prost(uint64, tag = "3")]
    pub plaintext_size: u64,
    /// The manifest range start in the optional read-only metadata-pack file.
    #[prost(uint64, tag = "4")]
    pub manifest_offset: u64,
    /// The nonzero manifest range length; zero for inline claims.
    #[prost(uint64, tag = "5")]
    pub manifest_length: u64,
    /// The 16-byte cache-owned pin identifier; this is not a retention proof.
    #[prost(bytes = "vec", tag = "6")]
    pub retention_id: Vec<u8>,
}

/// The registered publisher packet message.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Packet {
    /// The transport version, exactly one.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// The nonzero connection-scoped request identity, unique while active.
    #[prost(uint64, tag = "2")]
    pub request_id: u64,
    /// The registered fixed native command, never a filesystem callback.
    #[prost(enumeration = "Operation", tag = "3")]
    pub operation: i32,
    /// The configured disclosure-domain label selecting trusted physical roots.
    #[prost(string, tag = "4")]
    pub domain: String,
    /// The 16-byte cache-owner incarnation governed by the drain barrier.
    #[prost(bytes = "vec", tag = "5")]
    pub cache_incarnation: Vec<u8>,
    /// The request wait budget (1..=300000); zero on responses.
    #[prost(uint64, tag = "6")]
    pub wait_budget_ms: u64,
    /// The publication or sealed-adoption witness; absent from responses.
    #[prost(message, optional, tag = "7")]
    pub claim: Option<Claim>,
    /// The operation-specific checked content key; absent from responses.
    #[prost(message, optional, tag = "8")]
    pub body: Option<BodyKey>,
    /// The 32-byte publisher-issued retained-inode token, when required.
    #[prost(bytes = "vec", tag = "9")]
    pub body_incarnation: Vec<u8>,
    /// Whether the packet is a publisher response rather than a serve request.
    #[prost(bool, tag = "10")]
    pub response: bool,
    /// The response outcome; requests omit this field.
    #[prost(enumeration = "ResultCode", tag = "11")]
    pub result: i32,
    /// The successful sealed/probe binding algorithm (1 or 2), when required.
    #[prost(uint32, tag = "12")]
    pub verity_algorithm: u32,
    /// The measured kernel digest, 32 or 64 bytes for algorithms 1 or 2.
    #[prost(bytes = "vec", tag = "13")]
    pub verity_digest: Vec<u8>,
    /// The opaque connection/domain/incarnation cursor, at most 64 bytes.
    #[prost(bytes = "vec", tag = "14")]
    pub inventory_cursor: Vec<u8>,
    /// The inventory response page, at most 64 unverified key names.
    #[prost(message, repeated, tag = "15")]
    pub inventory: Vec<BodyKey>,
}
