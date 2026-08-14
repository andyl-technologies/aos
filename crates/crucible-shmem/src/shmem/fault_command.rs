//! Closed byte-level fault command, result, and capability protocol.
//!
//! These values cross the Apache host/GPL QEMU process boundary only as
//! explicitly encoded little-endian bytes. They are not native Rust or C wire
//! layouts. Every decoder rejects unknown tags, nonzero reserved fields,
//! unsupported versions, invalid bounds, and unauthenticated payload bytes.

use crate::RingHeader;
use core::fmt::Write as _;
use core::sync::atomic::Ordering;
use thiserror::Error;

#[path = "fault_command/c_header.rs"]
mod c_header;
#[path = "fault_command/c_header_transport.rs"]
mod c_header_transport;
#[path = "fault_command/capability.rs"]
mod capability;
#[path = "fault_command/codec.rs"]
mod codec;
#[path = "fault_command/envelope.rs"]
mod envelope;
#[path = "fault_command/errors.rs"]
mod errors;
#[path = "fault_command/layout.rs"]
mod layout;
#[path = "fault_command/transport.rs"]
mod transport;
#[path = "fault_command/vocabulary.rs"]
mod vocabulary;

pub(crate) use c_header::emit_fault_command_c_header;
use c_header_transport::emit_fault_transport_c_header;
pub use capability::*;
use codec::*;
pub use envelope::*;
pub use errors::*;
pub use layout::*;
pub use transport::*;
pub use vocabulary::*;

#[cfg(test)]
#[path = "fault_command_test.rs"]
mod tests;
