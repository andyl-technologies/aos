//! Owns canonical per-object attributes and deterministic plaintext producers.
//!
//! Records use the `terrane-attr-v1` identity domain. The initial producing
//! functions use version `1`; ELF values encode class as 32 or 64, machine and
//! type as unsigned ELF header values, an optional text interpreter, and needed
//! libraries in dynamic-table order. Interpreter and library strings are UTF-8
//! without embedded NULs and at most 64 KiB each. ELF32/ELF64 and either byte
//! order are supported; extended program counts are explicitly unsupported.
//! Shebang values carry a text interpreter
//! and an optional text argument. Missing optional strings encode as null.
//!
//! ```text
//! AttrRecord = {1: object_digest, 2: attribute_name, 3: typed_value,
//!               4: "function/version", 5: producing_commit_digest, ?6: bstr64}
//! class.shebang = {1: "/bin/bash", 2: null}
//! ```
//!
//! Producer commit references are external to the producing tree: an advisory
//! side-table index can name a record after that commit has its final identity.
//! Neither the tree nor its commit needs to include the resulting record ID.
//! Deployment-supplied `zstd-dictionary` records carry standalone chunk digests;
//! their choices can be authenticated but cannot be recomputed from plaintext.

mod classify;
mod elf;
mod hashes;
mod provenance;
mod record;

pub use classify::{MAGIC_PREFIX_LIMIT, Magic, classify_magic, parse_shebang};
pub use elf::{
    ElfDynamic, ElfHeader, ElfProgram, parse_elf_dynamic, parse_elf_header, parse_elf_programs,
};
pub use hashes::{HashValues, PlaintextHashes};
pub use provenance::{VerifiedAttributeEvidence, verify_producer, verify_record_producer};
pub use record::{AttrRecord, AttributeName, AttributeValue, ElfValue, Function, ShebangValue};

use crate::{cbor, identity::IdentityError};
use core::fmt;

/// A canonical-format, producer, or plaintext validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Deterministic CBOR decoding failed.
    Cbor(cbor::Error),
    /// The attribute name is outside the closed registry.
    UnknownAttribute,
    /// The registered attribute has another value type or invalid content.
    InvalidValue,
    /// The function identifier is malformed or does not match its attribute.
    InvalidFunction,
    /// The function version is retained but has no implemented producer.
    UnsupportedFunction,
    /// The supplied plaintext length differs from its declaration.
    LengthMismatch,
    /// The recognized executable format is malformed or unsupported.
    MalformedExecutable,
    /// A format offset, count, or resource bound is invalid.
    Limit,
    /// The inline and side-table values disagree.
    InlineDisagreement,
    /// Signed producer or tree evidence is absent or inconsistent.
    InvalidProvenance,
    /// The witness or producer has not completed disclosure and root-scope checks.
    UnverifiedContext,
    /// An attribute identity or profile is invalid.
    Identity(IdentityError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => write!(f, "invalid attribute CBOR: {error}"),
            Self::Identity(error) => write!(f, "invalid attribute identity: {error}"),
            Self::InvalidProvenance => f.write_str("invalid derived attribute producer evidence"),
            Self::UnverifiedContext => {
                f.write_str("derived attribute history context is not completely verified")
            }
            Self::UnknownAttribute => f.write_str("unregistered derived attribute"),
            Self::InvalidValue => f.write_str("invalid derived attribute value"),
            Self::InvalidFunction => f.write_str("invalid producing function"),
            Self::UnsupportedFunction => f.write_str("unsupported producing function version"),
            Self::LengthMismatch => f.write_str("plaintext length mismatch"),
            Self::MalformedExecutable => f.write_str("malformed executable format"),
            Self::Limit => f.write_str("derived attribute format bound exceeded"),
            Self::InlineDisagreement => f.write_str("inline derived attribute disagrees"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<cbor::Error> for Error {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

impl From<IdentityError> for Error {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "Failed test setup and assertions intentionally panic."
)]
mod tests;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "Failed signed fixture setup intentionally panics."
)]
mod provenance_tests;
