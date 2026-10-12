//! Owns ordinary recorded interpretations selected by immutable view and root.
//!
//! The caller independently justifies each association and preservation-name
//! registration. Copying this configuration authenticates nothing, recovers no
//! history and grants no authority. Native installation must separately retain
//! its deliberate legacy-versus-explicit mode; an absent mapping is no fallback.

use super::RecordedContext;
use crate::{identity::Digest, properties::Error as PropertyError};
use alloc::{collections::BTreeMap, collections::btree_map::Entry, string::String};
use core::fmt;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;

/// Owns one caller-justified view/root selection and its fixed interpretation.
///
/// The revision and later names come only from a validated [`RecordedContext`].
/// Names are copied and sorted by unsigned UTF-8 bytes without changing their
/// set. This ordinary data does not establish that the root belongs to the view
/// or that the caller's preservation registrations are authentic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedAssociation {
    view: Digest,
    original_root: Digest,
    context: RecordedContext,
}

impl RecordedAssociation {
    /// Copies a validated interpretation and the caller's immutable selection.
    ///
    /// The original root precedes any fold preprocessing. The caller must
    /// independently justify both the view/root association and later names.
    /// Sorting owned names leaves the caller's borrowed input order unchanged.
    pub fn new(view: Digest, original_root: Digest, context: RecordedContext) -> Self {
        Self {
            view,
            original_root,
            context,
        }
    }

    /// Returns the caller-selected immutable view identity.
    pub const fn view(&self) -> Digest {
        self.view
    }

    /// Returns the caller-associated original root before fold preprocessing.
    pub const fn original_root(&self) -> Digest {
        self.original_root
    }

    /// Returns the fixed validated property revision without inferring a default.
    pub const fn revision(&self) -> u64 {
        self.context.revision()
    }

    /// Borrows the exact preservation set in unsigned UTF-8 byte order.
    ///
    /// The names remain ordinary caller configuration, including compiled names
    /// that are inert under the selected revision. No names are deduplicated.
    pub fn later_registered(&self) -> &[String] {
        self.context.later_registered()
    }

    /// Returns the independently selected current revision retained at installation.
    pub const fn current_revision(&self) -> u64 {
        self.context.current_revision()
    }

    /// Borrows the complete validated independently installed interpretation.
    pub const fn context(&self) -> &RecordedContext {
        &self.context
    }

    /// Supplies the exact retained context without reconstructing caller trust.
    ///
    /// # Errors
    /// Preserves the existing adapter result type; borrowing a validated context
    /// introduces no validation error or publication authority.
    ///
    /// # Panics
    /// Propagates a panic from the caller-supplied action.
    pub fn with_context<T>(
        &self,
        action: impl FnOnce(&RecordedContext) -> T,
    ) -> Result<T, PropertyError> {
        Ok(action(&self.context))
    }
}

/// Reports a conflicting or unavailable explicit immutable selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// One view was supplied with conflicting root, revision or preservation set.
    ConflictingView {
        /// Immutable view whose independently supplied configurations conflict.
        view: Digest,
    },
    /// No explicit association was supplied for the requested immutable view.
    MissingView {
        /// Immutable view lacking a mapping, without a current or legacy fallback.
        view: Digest,
    },
    /// The requested original root differs from the view's configured root.
    OriginalRootMismatch {
        /// Immutable view selected by the caller.
        view: Digest,
        /// Original root retained in the supplied table.
        expected: Digest,
        /// Original root requested by the caller.
        actual: Digest,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConflictingView { .. } => "conflicting recorded view association",
            Self::MissingView { .. } => "missing recorded view association",
            Self::OriginalRootMismatch { .. } => "recorded view original root mismatch",
        })
    }
}

impl core::error::Error for Error {}

/// Owns immutable caller-supplied interpretations keyed exclusively by view.
///
/// Distinct views may select different interpretations of the same physical root.
/// Identical duplicate entries coalesce after copied-name canonicalization;
/// conflicting duplicates reject. Neither an empty table nor an absent view
/// selects a current revision or a legacy mode. Construction and selection do
/// not authenticate the associations, registrations or represented histories.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordedAssociations {
    entries: BTreeMap<Digest, RecordedAssociation>,
}

impl RecordedAssociations {
    /// Retains supplied associations while refusing conflicting view duplicates.
    ///
    /// Identical root, revision and preservation sets for one view coalesce even
    /// when the original borrowed name orders differ. An empty input stays empty.
    ///
    /// # Errors
    /// Returns [`Error::ConflictingView`] if one view has different roots,
    /// revisions or preservation sets. No conflicting entry replaces another.
    pub fn new(entries: impl IntoIterator<Item = RecordedAssociation>) -> Result<Self, Error> {
        let mut retained = BTreeMap::new();
        for association in entries {
            match retained.entry(association.view) {
                Entry::Vacant(entry) => {
                    entry.insert(association);
                }
                Entry::Occupied(entry) if entry.get() == &association => {}
                Entry::Occupied(_) => {
                    return Err(Error::ConflictingView {
                        view: association.view,
                    });
                }
            }
        }
        Ok(Self { entries: retained })
    }

    /// Borrows validated ordinary entries in canonical immutable view order.
    ///
    /// Iteration preserves the full independently installed current context;
    /// it authenticates no caller, history or publication authority.
    pub fn iter(&self) -> impl Iterator<Item = &RecordedAssociation> {
        self.entries.values()
    }

    /// Returns the number of distinct immutable views with explicit mappings.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether the configuration supplies no explicit view mappings.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Selects exactly the supplied immutable view and original root.
    ///
    /// No root-global lookup, current default, legacy fallback or historical
    /// association recovery occurs. A match returns ordinary configuration and
    /// does not verify that the represented view actually has that root.
    ///
    /// # Errors
    /// Returns [`Error::MissingView`] for an absent view, including an empty
    /// table, or [`Error::OriginalRootMismatch`] for a different original root.
    pub fn select(
        &self,
        view: Digest,
        original_root: Digest,
    ) -> Result<&RecordedAssociation, Error> {
        let association = self.entries.get(&view).ok_or(Error::MissingView { view })?;
        if association.original_root != original_root {
            return Err(Error::OriginalRootMismatch {
                view,
                expected: association.original_root,
                actual: original_root,
            });
        }
        Ok(association)
    }
}
