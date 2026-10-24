//! Retains authored marker diagnostics and concrete shared-entry validation causes.
//!
//! Entry failures stay inline. Constructing or cloning their diagnostic never
//! allocates a formatted message; Display renders the original coordinates.

use crucible_qemu_shmem::WhiteboxMarkerEntryError;
use std::borrow::Cow;
use std::error::Error;
use std::fmt;

/// Reports a marker-sink refusal with its original diagnostic or typed cause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxMarkerSinkError {
    detail: Detail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Detail {
    Message(Cow<'static, str>),
    EntryValidation(WhiteboxMarkerEntryError),
}

impl WhiteboxMarkerSinkError {
    /// Builds a marker-sink error retaining the supplied owned diagnostic.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            detail: Detail::Message(Cow::Owned(message.into())),
        }
    }

    /// Builds a marker-sink error borrowing a fixed diagnostic without allocation.
    #[must_use]
    pub const fn from_static(message: &'static str) -> Self {
        Self {
            detail: Detail::Message(Cow::Borrowed(message)),
        }
    }

    /// Retains a shared-entry validation cause without formatting or allocation.
    #[must_use]
    pub const fn from_entry_validation(source: WhiteboxMarkerEntryError) -> Self {
        Self {
            detail: Detail::EntryValidation(source),
        }
    }

    /// Returns the authored diagnostic, or an empty string for a typed cause.
    ///
    /// Display renders a typed cause directly, retaining its exact coordinates.
    #[must_use]
    pub fn message(&self) -> &str {
        match &self.detail {
            Detail::Message(message) => message,
            Detail::EntryValidation(_) => "",
        }
    }

    /// Borrows the original shared-entry validation cause, when present.
    #[must_use]
    pub const fn entry_validation_source(&self) -> Option<&WhiteboxMarkerEntryError> {
        match &self.detail {
            Detail::EntryValidation(source) => Some(source),
            Detail::Message(_) => None,
        }
    }
}

impl fmt::Display for WhiteboxMarkerSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("white-box marker sink failed: ")?;
        match &self.detail {
            Detail::Message(message) => formatter.write_str(message),
            Detail::EntryValidation(source) => fmt::Display::fmt(source, formatter),
        }
    }
}

impl Error for WhiteboxMarkerSinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.entry_validation_source().map(|source| source as _)
    }
}
