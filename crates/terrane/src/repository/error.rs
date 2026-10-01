//! Typed SDK failures preserve the originating format, I/O, and store diagnostics.

use std::fmt;

/// Describes a repository or realization failure without stringly typed outcomes.
#[derive(Debug)]
pub enum Error {
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// A backend operation failed.
    Store(crate::store::StoreFailure),
    /// The shared publication coordinator rejected an operation.
    Advance(crate::ref_advance::AdvanceError),
    /// A canonical tree encoding or namespace was invalid.
    Tree(terrane_core::tree_format::Error),
    /// A registered plaintext attribute producer failed.
    Derived(terrane_core::derived::Error),
    /// An immutable identity was invalid.
    Identity(terrane_core::identity::IdentityError),
    /// An object manifest was invalid.
    Manifest(terrane_core::manifest::Error),
    /// A chunk could not be encoded or verified.
    Codec(crate::codec::FrameError),
    /// A commit or ref record was malformed.
    Record(terrane_core::refs::RecordError),
    /// Registered bucket capability metadata was malformed.
    Bucket(terrane_core::bucket::RecordError),
    /// A reference or subtree was absent.
    Absent,
    /// Authorization or verified provenance failed closed.
    Denied,
    /// A root contains unresolved conflicts or unsupported entry kinds.
    Unrealizable,
    /// A path or symlink would escape the exposure root.
    PathEscape,
    /// The requested compiled surface is unavailable.
    UnavailableSurface(String),
    /// A later milestone owns the requested operation.
    UnavailableOperation(&'static str),
    /// Required metadata failed schema validation.
    Schema,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => fmt::Display::fmt(error, f),
            Self::Store(error) => fmt::Display::fmt(error, f),
            Self::Advance(error) => fmt::Display::fmt(error, f),
            Self::Tree(error) => fmt::Display::fmt(error, f),
            Self::Derived(error) => fmt::Display::fmt(error, f),
            Self::Identity(error) => fmt::Display::fmt(error, f),
            Self::Manifest(error) => fmt::Display::fmt(error, f),
            Self::Codec(error) => fmt::Display::fmt(error, f),
            Self::Record(error) => fmt::Display::fmt(error, f),
            Self::Bucket(error) => fmt::Display::fmt(error, f),
            Self::Absent => f.write_str("repository target absent"),
            Self::Denied => f.write_str("repository access denied"),
            Self::Unrealizable => f.write_str("tree contains entries that cannot be realized"),
            Self::PathEscape => f.write_str("path escapes the exposure root"),
            Self::UnavailableSurface(name) => write!(f, "surface {name:?} unavailable"),
            Self::UnavailableOperation(name) => {
                write!(f, "operation {name:?} unavailable in this milestone")
            }
            Self::Schema => f.write_str("view fails the surface schema"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Advance(error) => Some(error),
            Self::Tree(error) => Some(error),
            Self::Derived(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Record(error) => Some(error),
            Self::Bucket(error) => Some(error),
            _ => None,
        }
    }
}

macro_rules! conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for Error {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    };
}

conversion!(std::io::Error, Io);
conversion!(crate::store::StoreFailure, Store);
conversion!(terrane_core::tree_format::Error, Tree);
conversion!(terrane_core::identity::IdentityError, Identity);
conversion!(terrane_core::manifest::Error, Manifest);
conversion!(crate::codec::FrameError, Codec);
conversion!(terrane_core::refs::RecordError, Record);

conversion!(crate::ref_advance::AdvanceError, Advance);

conversion!(terrane_core::derived::Error, Derived);
