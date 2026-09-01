//! Canonical translation records and QEMU memory-mutation evidence.
//!
//! Translation digests are SHA-256 over the domain
//! `crucible.memory-translation.v1\0`, the little-endian vCPU index and record
//! count, then fixed-width records in ascending virtual-address order. Memory
//! evidence carries the same records plus stable RAM-region identities and
//! bounded inline before/after bytes.

use core::fmt::Write as _;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    HARD_FAULT_PAYLOAD_BYTES, MemoryMutationAddressSpace, MemoryMutationPayloadError,
    MemoryMutationTransformKind,
};

#[path = "fault_memory_evidence/mapping.rs"]
mod mapping;
#[path = "fault_memory_evidence/translation.rs"]
mod translation;

pub use mapping::*;
pub use translation::*;

#[path = "fault_memory_evidence/evidence.rs"]
mod evidence;

pub use evidence::*;

#[path = "fault_memory_evidence/support.rs"]
mod support;

pub use support::MemoryMutationEvidenceError;
pub(crate) use support::emit_memory_evidence_c_header;
use support::*;

#[cfg(test)]
#[path = "fault_memory_evidence_test.rs"]
mod tests;
