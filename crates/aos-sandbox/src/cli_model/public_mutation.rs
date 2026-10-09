//! Exact public mutation request envelopes.
//!
//! The controller compiler needs both a closed RPC method and the exact
//! protobuf bytes received on its authenticated HTTP/2 stream. This envelope
//! preserves those bytes without decoding and re-encoding them first:
//!
//! ```text
//! +----------------+----------------+----------------+-------------------+
//! | magic (8 bytes)| method (u16 BE)| length (u32 BE)| protobuf body ... |
//! +----------------+----------------+----------------+-------------------+
//! ```

pub use aos_sandbox_protocol::public_api::mutation::{
    PublicMutationRequestError, PublicMutationRequestV1,
};
