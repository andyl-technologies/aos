//! Retains independent per-view namespace attribute configuration.
//!
//! Entries combine an ordinary recorded property association with an explicitly
//! supplied attribute revision. Neither construction nor lookup authenticates a
//! view, completes a relationship, or grants current repository authority.

use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt;

use terrane_format::identity::Digest;
use terrane_format::properties::semantics::associations::{
    self, RecordedAssociation, RecordedAssociations,
};

/// Retains one independently configured historical namespace profile.
///
/// The property association identifies the exact immutable view and original
/// signed root. The attribute revision is independent configuration; tree,
/// chunk, selector and identity behavior still come from the actual verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedNamespaceProfile {
    association: RecordedAssociation,
    attribute_revision: u64,
}

impl RecordedNamespaceProfile {
    /// Retains a property association and an explicit registered attribute revision.
    ///
    /// # Errors
    /// Returns [`NamespaceProfileError::UnsupportedAttributeRevision`] unless the
    /// attribute revision is 1 or 2. Construction does not verify a historical
    /// view or promise completion for every property/attribute combination.
    pub fn new(
        association: RecordedAssociation,
        attribute_revision: u64,
    ) -> Result<Self, NamespaceProfileError> {
        if !matches!(attribute_revision, 1 | 2) {
            return Err(NamespaceProfileError::UnsupportedAttributeRevision {
                revision: attribute_revision,
            });
        }

        Ok(Self {
            association,
            attribute_revision,
        })
    }

    /// Borrows the ordinary exact view/root property association.
    pub fn association(&self) -> &RecordedAssociation {
        &self.association
    }

    /// Returns the independently supplied namespace attribute revision.
    pub const fn attribute_revision(&self) -> u64 {
        self.attribute_revision
    }
}

/// Reports unsupported, conflicting or unavailable ordinary namespace inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespaceProfileError {
    /// The attribute revision is not registered by this implementation.
    UnsupportedAttributeRevision {
        /// Independently supplied revision that cannot be installed.
        revision: u64,
    },
    /// One view has incompatible property or attribute configurations.
    ConflictingView {
        /// Immutable view whose supplied profiles disagree.
        view: Digest,
    },
    /// The ordinary property association is missing or has a different root.
    Association(associations::Error),
}

impl fmt::Display for NamespaceProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAttributeRevision { .. } => {
                formatter.write_str("unsupported recorded namespace attribute revision")
            }
            Self::ConflictingView { .. } => {
                formatter.write_str("conflicting recorded namespace profile")
            }
            Self::Association(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for NamespaceProfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Association(error) => Some(error),
            _ => None,
        }
    }
}

/// Owns immutable per-view property and namespace attribute configurations.
///
/// Equal duplicates coalesce; conflicting profiles reject. Empty tables and
/// missing views refuse selection instead of choosing a legacy interpretation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordedNamespaceProfiles {
    entries: BTreeMap<Digest, RecordedNamespaceProfile>,
    associations: RecordedAssociations,
}

impl RecordedNamespaceProfiles {
    /// Retains explicitly supplied profiles without replacing conflicting views.
    ///
    /// # Errors
    /// Returns [`NamespaceProfileError::ConflictingView`] when one view has a
    /// different root, property fence, preservation set or attribute revision.
    /// Preserves any association validation error with its original cause.
    pub fn new(
        profiles: impl IntoIterator<Item = RecordedNamespaceProfile>,
    ) -> Result<Self, NamespaceProfileError> {
        let mut entries = BTreeMap::new();
        for profile in profiles {
            let view = profile.association.view();
            match entries.entry(view) {
                Entry::Vacant(entry) => {
                    entry.insert(profile);
                }
                Entry::Occupied(entry) if entry.get() == &profile => {}
                Entry::Occupied(_) => {
                    return Err(NamespaceProfileError::ConflictingView { view });
                }
            }
        }

        let associations =
            RecordedAssociations::new(entries.values().map(|profile| profile.association.clone()))
                .map_err(NamespaceProfileError::Association)?;

        Ok(Self {
            entries,
            associations,
        })
    }

    /// Selects only the configured immutable view and its exact original root.
    ///
    /// # Errors
    /// Returns [`NamespaceProfileError::Association`] for a missing view or a
    /// different original root. No global revision or root-only fallback applies.
    pub fn select(
        &self,
        view: Digest,
        original_root: Digest,
    ) -> Result<&RecordedNamespaceProfile, NamespaceProfileError> {
        self.associations
            .select(view, original_root)
            .map_err(NamespaceProfileError::Association)?;

        self.entries
            .get(&view)
            .ok_or(NamespaceProfileError::Association(
                associations::Error::MissingView { view },
            ))
    }

    /// Borrows validated input rows in canonical view order for fresh installation.
    ///
    /// The constructor consumes these as ordinary data into the single owning
    /// Guard view table; this profile object is not retained as another authority.
    #[cfg(feature = "std")]
    pub(in crate::guard) fn iter(&self) -> impl Iterator<Item = &RecordedNamespaceProfile> {
        self.entries.values()
    }
}
