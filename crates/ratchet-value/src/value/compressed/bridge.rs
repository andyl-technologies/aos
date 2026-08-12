//! Errors at the active-value/Candidate-C conversion boundary.
//!
//! Encoding and decoding heap values is evaluator-context owned: the caller
//! must prove typed membership in its reservation before translating between
//! a native pointer and a compressed index. This module keeps that boundary's
//! shared error vocabulary next to the sealed word codec.

use thiserror::Error;

use super::{CandidateCScalarError, CompressedValueError};
use crate::value::{ValueError, ValueTag};

/// An active [`crate::value::Value`] could not cross the Candidate-C bridge.
#[derive(Debug, Error)]
pub enum CandidateCValueError {
    /// The active value failed its checked scalar or pointer accessor.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// A boxed integer or float could not be stored or decoded.
    #[error(transparent)]
    Scalar(#[from] CandidateCScalarError),
    /// The one-word codec rejected a kind, flag, or payload.
    #[error(transparent)]
    Codec(#[from] CompressedValueError),
    /// The evaluator heap does not have a Candidate-C reservation backend.
    #[error("Candidate-C value conversion requires a reservation-backed heap")]
    ReservationUnavailable,
    /// An indexed word belongs to another live reservation domain.
    #[error("Candidate-C value arena domain {actual} does not match expected domain {expected}")]
    ArenaDomainMismatch {
        /// The receiving heap's reservation domain.
        expected: u32,
        /// The word's encoded reservation domain.
        actual: u32,
    },
    /// A native heap value did not name a typed object published by this heap.
    #[error("Candidate-C {tag:?} pointer 0x{address:x} is not published in this heap")]
    HeapPointerNotPublished {
        /// The semantic tag carried by the active value.
        tag: ValueTag,
        /// The rejected native address.
        address: usize,
    },
    /// A compressed heap index did not name the expected typed object.
    #[error("Candidate-C {tag:?} index {index} is not published in this heap")]
    HeapIndexNotPublished {
        /// The semantic tag carried by the compressed word.
        tag: ValueTag,
        /// The rejected reservation offset.
        index: u32,
    },
    /// The active value cannot preserve the compressed thunk shortcut bit.
    #[error("Candidate-C forced-thunk words cannot cross the active 16-byte Value bridge")]
    ForcedThunkUnsupported,
}
