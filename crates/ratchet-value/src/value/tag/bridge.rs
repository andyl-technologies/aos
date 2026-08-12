//! Errors at the active-value/Candidate-B conversion boundary.
//!
//! The word codec validates representation shape. Evaluator-owned conversion
//! additionally proves typed heap membership and owns boxed scalar cells.

use thiserror::Error;

use super::{TaggedValueKind, TaggedValueWordError};
use crate::value::ValueError;
use crate::value::ValueTag;
use crate::value::compressed::CandidateCScalarError;

/// An active [`crate::value::Value`] could not cross the Candidate-B bridge.
#[derive(Debug, Error)]
pub enum CandidateBValueError {
    /// The active value failed its checked scalar or pointer accessor.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// A boxed integer or float could not be stored or decoded.
    #[error(transparent)]
    Scalar(#[from] CandidateCScalarError),
    /// The one-word codec rejected a tag or address.
    #[error(transparent)]
    Codec(#[from] TaggedValueWordError),
    /// A decoder received the wrong representation class.
    #[error("expected a tagged {expected}, found {actual:?}")]
    KindMismatch {
        /// The requested semantic value class.
        expected: &'static str,
        /// The observed representation class.
        actual: TaggedValueKind,
    },
    /// A native heap value did not name a typed object published by this heap.
    #[error("Candidate-B {tag:?} pointer 0x{address:x} is not published in this heap")]
    HeapPointerNotPublished {
        /// The semantic tag carried by the active value.
        tag: ValueTag,
        /// The rejected native address.
        address: usize,
    },
    /// A tagged heap address did not name any typed object in this heap.
    #[error("Candidate-B heap address 0x{address:x} is not published in this heap")]
    HeapAddressNotPublished {
        /// The rejected native address.
        address: usize,
    },
    /// The active value cannot preserve the tagged thunk shortcut bit.
    #[error("Candidate-B forced-thunk words cannot cross the active 16-byte Value bridge")]
    ForcedThunkUnsupported,
}
