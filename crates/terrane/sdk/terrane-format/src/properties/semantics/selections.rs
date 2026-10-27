//! Retains an explicit installed mode and exact immutable-view overrides.
//!
//! These inputs describe property interpretation only. Their caller independently
//! justifies each signed view/original-root association and later registration.
//! They authenticate no history, provide no current authority, and establish no
//! attribute, index relationship or coverage result.

use super::associations::{Error, RecordedAssociation, RecordedAssociations};
use crate::identity::Digest;
use alloc::collections::{BTreeMap, btree_map::Entry};

/// Describes one independently selected view's original property interpretation.
///
/// Legacy remains an explicit mode rather than a synthetic Recorded revision.
/// Recorded retains its exact validated revision and inert preservation set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ViewPropertySelection {
    /// Retains deliberately selected Legacy interpretation for one exact view.
    Legacy {
        /// Immutable signed view selected by the caller.
        view: Digest,
        /// Original signed namespace root before any fold filtering.
        original_root: Digest,
    },
    /// Retains the exact ordinary Recorded view/root association.
    Recorded(RecordedAssociation),
}

impl ViewPropertySelection {
    /// Returns the independently supplied immutable view identity.
    pub const fn view(&self) -> Digest {
        match self {
            Self::Legacy { view, .. } => *view,
            Self::Recorded(association) => association.view(),
        }
    }

    /// Returns the independently supplied original signed namespace root.
    pub const fn original_root(&self) -> Digest {
        match self {
            Self::Legacy { original_root, .. } => *original_root,
            Self::Recorded(association) => association.original_root(),
        }
    }

    /// Borrows the Recorded association, or reports the explicit Legacy mode.
    pub const fn association(&self) -> Option<&RecordedAssociation> {
        match self {
            Self::Legacy { .. } => None,
            Self::Recorded(association) => Some(association),
        }
    }
}

/// Keeps the independently installed base distinct from exact view overrides.
#[derive(Clone, Debug, Eq, PartialEq)]
enum InstalledBase {
    Legacy,
    Recorded(RecordedAssociations),
}

/// Owns immutable ordinary property selections for a mixed history.
///
/// A deliberate Legacy base may select a new Recorded view without relabeling
/// its Legacy ancestors. A strict Recorded base never treats absence as Legacy;
/// only an independently supplied exact override can select an absent view.
/// Overrides cannot change an existing explicit base association. Shared roots
/// do not unify different views, and copying these inputs grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewPropertySelections {
    base: InstalledBase,
    overrides: BTreeMap<Digest, ViewPropertySelection>,
}

impl ViewPropertySelections {
    /// Retains deliberate Legacy installation and exact independently supplied overrides.
    ///
    /// Every view without an override uses the deliberately installed Legacy
    /// mode. This behavior does not infer Legacy from a missing stored context.
    ///
    /// # Errors
    /// Returns [`Error::ConflictingView`] for duplicate views with different
    /// roots, modes, revisions or preservation sets. Equal duplicates coalesce.
    pub fn legacy(
        overrides: impl IntoIterator<Item = ViewPropertySelection>,
    ) -> Result<Self, Error> {
        Self::new(InstalledBase::Legacy, overrides)
    }

    /// Retains strict Recorded installation and exact independently supplied overrides.
    ///
    /// An absent base entry may have an explicit Legacy or Recorded override.
    /// An existing base entry accepts only an identical Recorded override;
    /// a root mismatch is not an absent entry. Missing selections refuse.
    ///
    /// # Errors
    /// Returns [`Error::ConflictingView`] for conflicting duplicate overrides
    /// or a differing mode, revision or preservation set at an existing view.
    /// Returns [`Error::OriginalRootMismatch`] for an override whose root
    /// differs from the existing base association.
    pub fn recorded(
        base: RecordedAssociations,
        overrides: impl IntoIterator<Item = ViewPropertySelection>,
    ) -> Result<Self, Error> {
        Self::new(InstalledBase::Recorded(base), overrides)
    }

    fn new(
        base: InstalledBase,
        overrides: impl IntoIterator<Item = ViewPropertySelection>,
    ) -> Result<Self, Error> {
        let mut retained = BTreeMap::new();
        for selection in overrides {
            let view = selection.view();
            if let InstalledBase::Recorded(associations) = &base {
                match associations.select(view, selection.original_root()) {
                    Ok(existing) if selection.association() == Some(existing) => {}
                    Ok(_) => return Err(Error::ConflictingView { view }),
                    Err(Error::MissingView { .. }) => {}
                    Err(error) => return Err(error),
                }
            }

            match retained.entry(view) {
                Entry::Vacant(entry) => {
                    entry.insert(selection);
                }
                Entry::Occupied(entry) if entry.get() == &selection => {}
                Entry::Occupied(_) => return Err(Error::ConflictingView { view }),
            }
        }

        Ok(Self {
            base,
            overrides: retained,
        })
    }

    /// Selects the exact view and original root without authenticating either.
    ///
    /// `None` reports deliberately installed or explicitly selected Legacy.
    /// It never represents an absent entry in a strict Recorded base. A matching
    /// Recorded result retains the exact revision and inert preservation names.
    ///
    /// # Errors
    /// Returns [`Error::OriginalRootMismatch`] when an explicit selection binds
    /// another original root, or [`Error::MissingView`] when neither a strict
    /// base nor an exact override selects this view. No root-global lookup or
    /// fallback from a failed Recorded selection occurs.
    pub fn select(
        &self,
        view: Digest,
        original_root: Digest,
    ) -> Result<Option<&RecordedAssociation>, Error> {
        if let Some(selection) = self.overrides.get(&view) {
            if selection.original_root() != original_root {
                return Err(Error::OriginalRootMismatch {
                    view,
                    expected: selection.original_root(),
                    actual: original_root,
                });
            }

            return Ok(selection.association());
        }

        match &self.base {
            InstalledBase::Legacy => Ok(None),
            InstalledBase::Recorded(associations) => {
                associations.select(view, original_root).map(Some)
            }
        }
    }
}
