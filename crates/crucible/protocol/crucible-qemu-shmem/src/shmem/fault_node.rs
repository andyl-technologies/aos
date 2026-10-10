//! Closed typed-field codec for non-impulse QEMU node fault commands.
//!
//! The command kind in [`FaultCommandHeaderV1`](crate::FaultCommandHeaderV1)
//! selects a closed schema. This module carries that schema's operation,
//! target, and named fields as canonical little-endian bytes. Fields are
//! strictly ordered and uniquely tagged, so the GPL-side implementation can
//! reject unknown, duplicate, missing, or incorrectly typed values before it
//! changes QEMU state.

use core::fmt::Write as _;
use thiserror::Error;

use crate::{FaultCommandKind, HARD_FAULT_PAYLOAD_BYTES};

/// Eight-byte magic for a version-1 typed node-fault payload.
pub const NODE_FAULT_PAYLOAD_MAGIC_V1: [u8; 8] = *b"CRUCNOD1";
/// Semantic version of the typed node-fault payload.
pub const NODE_FAULT_PAYLOAD_VERSION_V1: u16 = 1;
/// Fixed bytes before the first typed field.
pub const NODE_FAULT_PAYLOAD_HEADER_V1_BYTES: usize = 128;
/// Fixed bytes in one typed-field header.
pub const NODE_FAULT_FIELD_HEADER_V1_BYTES: usize = 8;
/// Maximum number of typed fields in one command.
pub const NODE_FAULT_MAX_FIELDS_V1: usize = 128;
/// Maximum hashes in one canonical identity set.
pub const NODE_FAULT_MAX_HASH_SET_V1: usize = 4_096;
/// Eight-byte prefix for a closed policy encoded as canonical JSON.
pub const NODE_FAULT_POLICY_JSON_MAGIC_V1: [u8; 8] = *b"CRUCJSN1";
/// Eight-byte magic for typed node command evidence.
pub const NODE_FAULT_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUCNEV1";
/// Fixed byte length of typed node command evidence.
pub const NODE_FAULT_EVIDENCE_V1_BYTES: usize = 228;

#[path = "fault_node/field.rs"]
mod field;

pub use field::*;

#[path = "fault_node/payload_codec.rs"]
mod payload_codec;
#[path = "fault_node/payload_validation.rs"]
mod payload_validation;

pub use payload_codec::NodeFaultPayloadV1;

#[path = "fault_node/evidence.rs"]
mod evidence;

pub use evidence::NodeFaultEvidenceV1;

#[path = "fault_node/support.rs"]
mod support;

pub use support::NodeFaultPayloadError;
pub(crate) use support::emit_fault_node_c_header;

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
// crucible-lint: allow rust-allow -- the test case table keeps the wire payload and expected projection together.
#[allow(clippy::expect_used, clippy::type_complexity)]
#[path = "fault_node_test.rs"]
mod tests;
