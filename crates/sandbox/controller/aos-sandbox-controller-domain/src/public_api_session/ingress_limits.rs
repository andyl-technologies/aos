//! Fixed Controller ingress limits shared by assembly and resource admission.
//!
//! These ceilings describe concurrent work and decoder representations. They
//! neither identify a caller nor issue a service or operation reservation.

/// Bounds authenticated public connections, including incomplete handshakes.
pub const MAXIMUM_PUBLIC_CONNECTIONS: usize = 32;

/// Bounds public TLS handshakes within the public connection capacity.
pub const MAXIMUM_PUBLIC_HANDSHAKES: usize = 8;

/// Bounds diagnostic connections, including clients that send no request.
pub const MAXIMUM_DIAGNOSTIC_CONNECTIONS: usize = 8;

/// Bounds public RPCs through the lifetime of their response bodies.
pub const MAXIMUM_PUBLIC_RPC_REQUESTS: usize = 4;

/// Preserves a separate diagnostic slot when public requests are saturated.
pub const MAXIMUM_DIAGNOSTIC_RPC_REQUESTS: usize = 1;

/// Bounds both on-wire request bodies and decompressed RPC messages.
pub const MAXIMUM_RPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Configures typed collection admission, separately from payload contents.
///
/// Binary decoding charges Buffa element footprints. JSON decoding charges a
/// conservative typed growth/floor/link budget under the same configured limit.
/// Encoded contents, parser scratch and normalized buffers need separate provision.
pub const MAXIMUM_RPC_ELEMENT_MEMORY_BYTES: usize = 32 * 1024 * 1024;
