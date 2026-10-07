//! Owns canonical owner-bound index format data and executable recipe inputs.
//!
//! These codecs describe immutable data. They do not verify index contents,
//! resolve current occurrences, or grant authority to use an index.
//!
//! ```text
//! index-roots = {"value": {"uid": "0123...64 lowercase hex digits"}, "inherit": false}
//! recipe = {1: "index", 2: [owner32], 3: {"profile": "terrane-index/v1", "attribute": "uid"}}
//! key = canonical-CBOR(attribute-value) || object-digest32
//! ```

pub mod carrier;
pub mod evaluation;

/// Constructs owner-local index bindings before forming detached recipes.
pub mod completion;

/// Queries immutable index rows and local occurrence routes with measured work.
pub mod lookup;

/// Maintains ordinary immutable index data through explicit measured operations.
pub mod maintenance;

mod key;
mod recipe;
mod roots;

pub use key::{IndexKey, MAX_INDEX_KEY_BYTES};
pub use recipe::{INDEX_EVALUATION_PROFILE, IndexEvaluationRecipe};
pub use roots::{IndexBinding, IndexRoots};

use crate::cbor;
use core::fmt;

/// A rejected canonical index format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An encoded value is malformed, noncanonical, or has trailing bytes.
    Cbor(cbor::Error),
    /// A field or owner binding has the wrong shape or vocabulary.
    Schema,
    /// An attribute name is not registered.
    UnknownAttribute,
    /// Encoded input exceeds its size bound.
    Limit,
}

impl From<cbor::Error> for Error {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => error.fmt(formatter),
            Self::Schema => formatter.write_str("invalid index format schema"),
            Self::UnknownAttribute => formatter.write_str("unregistered index attribute"),
            Self::Limit => formatter.write_str("index format limit exceeded"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod carrier_tests;

#[cfg(test)]
mod evaluation_tests;
