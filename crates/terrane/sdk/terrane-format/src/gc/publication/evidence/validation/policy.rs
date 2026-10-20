//! Checks seeded profiles, semantic revisions and canonical property fences.

use super::*;
use crate::cbor::Decoder;
use crate::chunking::{
    CDC_1M_MAX, CDC_1M_MIN, CDC_1M_NORMALIZATION, CDC_1M_TARGET, CDC_1M_WINDOW, ChunkProfile,
};
use crate::properties::validate_property;
use crate::tree_format::{MAX_NODE_ITEMS_BYTES, Property};

// Historical revisions bind immutable vocabulary, not the moving compiled list.
const REVISION_ONE_PROPERTIES: &[&str] = &[
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
];

fn revision_properties(revision: u64) -> Result<Vec<&'static str>, EvidenceError> {
    let mut properties = REVISION_ONE_PROPERTIES.to_vec();
    match revision {
        1 => {}
        2 => {
            properties.push("index-roots");
            properties.sort_unstable();
        }
        3 => {
            properties.extend(["index-gaps", "index-roots"]);
            properties.sort_unstable();
        }
        _ => return Err(EvidenceError::UnsupportedRevision),
    }
    Ok(properties)
}

impl ConfiguredRegistryInputs {
    /// Identifies the registered semantics of an exact behavioral name list.
    ///
    /// This identifies ordinary configuration data; it does not select a Guard
    /// or establish current authority. Revision 1 retains its original 33 names,
    /// revision 2 adds only the owner-local `index-roots` binding, and revision 3
    /// adds only the auxiliary-root `index-gaps` binding.
    ///
    /// # Errors
    /// Rejects names that are unsorted, duplicated, malformed, or do not match
    /// a complete registered vocabulary.
    pub fn property_revision_for(properties: &[String]) -> Result<u64, EvidenceError> {
        names(properties)?;
        for revision in [1, 2, 3] {
            if properties
                .iter()
                .map(String::as_str)
                .eq(revision_properties(revision)?)
            {
                return Ok(revision);
            }
        }
        Err(EvidenceError::Contradiction)
    }
}

impl SeededChunkProfile {
    /// Recomputes the pure FastCDC profile from its six represented inputs.
    ///
    /// This derives masks and gear values, never backend or Guard authority.
    ///
    /// # Errors
    /// Rejects platform-unrepresentable sizes and invalid FastCDC parameters.
    pub fn to_chunk_profile(&self) -> Result<ChunkProfile, EvidenceError> {
        let minimum = usize::try_from(self.minimum).map_err(|_| EvidenceError::Schema)?;
        let target = usize::try_from(self.target).map_err(|_| EvidenceError::Schema)?;
        let maximum = usize::try_from(self.maximum).map_err(|_| EvidenceError::Schema)?;

        Ok(ChunkProfile::new(
            minimum,
            target,
            maximum,
            self.window,
            self.normalization,
            self.seed,
        )?)
    }
}

impl Validate for SeededChunkProfile {
    fn validate(&self) -> Result<(), EvidenceError> {
        self.to_chunk_profile()?;
        Ok(())
    }
}

impl Validate for TrustedGuardConfig {
    fn validate(&self) -> Result<(), EvidenceError> {
        nonempty(&self.store_name)?;
        domain(&self.storage_domain)?;
        acl(&self.initial_acl)?;
        self.chunk_profile.validate()?;

        if self.minimum_chunk_size != self.chunk_profile.minimum {
            return Err(EvidenceError::Contradiction);
        }
        if self.chunk_profile_name != "cdc-1m" {
            return Err(EvidenceError::Schema);
        }
        let profile = &self.chunk_profile;
        if profile.minimum != CDC_1M_MIN as u64
            || profile.target != CDC_1M_TARGET as u64
            || profile.maximum != CDC_1M_MAX as u64
            || profile.window != CDC_1M_WINDOW
            || profile.normalization != CDC_1M_NORMALIZATION
        {
            return Err(EvidenceError::Contradiction);
        }

        // The exact profile-record seed is an input, not a zero-seed assertion.
        // Encoding hints, optional locality and policy labels retain exact text;
        // actual current authority and ownership remain private-factory checks.
        Ok(())
    }
}

fn names(names: &[String]) -> Result<(), EvidenceError> {
    for name in names {
        if name.is_empty() || name.len() > 255 {
            return Err(EvidenceError::Schema);
        }
    }
    if names
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(EvidenceError::Schema);
    }

    Ok(())
}

impl Validate for ConfiguredRegistryInputs {
    fn validate(&self) -> Result<(), EvidenceError> {
        // D-105 retains registered scalar revisions independently as ordinary
        // data. The executable carrier separately requires exact 3/2/1.
        if !matches!(self.property_revision, 1..=3)
            || !matches!(self.attribute_revision, 1 | 2)
            || [
                self.selector_revision,
                self.tree_revision,
                self.chunk_revision,
            ]
            .iter()
            .any(|revision| *revision != 1)
            || self.identity_profile != "terrane-v1"
        {
            return Err(EvidenceError::UnsupportedRevision);
        }
        names(&self.behavioral_properties)?;
        names(&self.later_properties)?;

        let registered = revision_properties(self.property_revision)?;
        if !self
            .behavioral_properties
            .iter()
            .map(String::as_str)
            .eq(registered)
        {
            return Err(EvidenceError::Contradiction);
        }
        if self
            .later_properties
            .iter()
            .any(|name| self.behavioral_properties.binary_search(name).is_ok())
        {
            return Err(EvidenceError::Contradiction);
        }

        // A nonempty later set remains inert decoded data. Genuine current
        // configuration separately requires the currently supported empty set.
        Ok(())
    }
}

/// Checks ordinary registry shape without granting unsupported semantics.
///
/// # Errors
/// Rejects malformed, overlapping or noncanonical name sets, and vocabularies
/// differing from a registered property revision, and unregistered property
/// revisions. Unsupported non-property semantic uints remain ordinary data.
pub(super) fn registry_structure(
    registries: &ConfiguredRegistryInputs,
) -> Result<(), EvidenceError> {
    names(&registries.behavioral_properties)?;
    names(&registries.later_properties)?;
    if registries
        .later_properties
        .iter()
        .any(|name| registries.behavioral_properties.binary_search(name).is_ok())
    {
        return Err(EvidenceError::Contradiction);
    }

    // PROP-30 rejects unregistered property revisions as record data. Exact
    // known vocabulary is independent of execution support: revision3 retains
    // its exact 35-name fence, separately from the selected attribute pairing.
    let registered = match registries.property_revision {
        1 | 2 => revision_properties(registries.property_revision)?,
        3 => {
            let mut properties = REVISION_ONE_PROPERTIES.to_vec();
            properties.extend(["index-gaps", "index-roots"]);
            properties.sort_unstable();
            properties
        }
        _ => return Err(EvidenceError::UnsupportedRevision),
    };
    if !registries
        .behavioral_properties
        .iter()
        .map(String::as_str)
        .eq(registered)
    {
        return Err(EvidenceError::Contradiction);
    }

    Ok(())
}

impl Validate for GuardSnapshot {
    fn validate(&self) -> Result<(), EvidenceError> {
        self.registration.validate()?;
        issuers(&self.issuers)?;
        disclosures(&self.disclosures)?;

        self.configuration.validate()?;
        self.registries.validate()?;
        if self.registration.physical_domain() != self.configuration.storage_domain {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }
}

/// Checks exact canonical property-map bytes and an optional behavior fence.
///
/// # Errors
/// Rejects malformed property maps, wrong registered values, and names outside
/// the represented behavioral and inert-name fence when one is supplied.
pub(super) fn property_map(
    bytes: &[u8],
    registries: Option<&ConfiguredRegistryInputs>,
) -> Result<(), EvidenceError> {
    property_map_with_fence(bytes, registries, true)
}

/// Checks canonical map structure and exact membership in a per-view fence.
///
/// # Errors
/// Rejects malformed property maps and names outside the represented fence.
/// This does not grant behavior for unsupported semantic profiles.
pub(super) fn property_map_structure(
    bytes: &[u8],
    registries: &ConfiguredRegistryInputs,
) -> Result<(), EvidenceError> {
    property_map_with_fence(bytes, Some(registries), false)
}

fn property_map_with_fence(
    bytes: &[u8],
    registries: Option<&ConfiguredRegistryInputs>,
    interpret_behavior: bool,
) -> Result<(), EvidenceError> {
    if bytes.len() > MAX_NODE_ITEMS_BYTES {
        return Err(EvidenceError::Cbor(crate::cbor::Error::Limit));
    }
    let mut decoder = Decoder::new(bytes);
    let count = decoder.map(MAX_NODE_ITEMS_BYTES)?;
    let mut previous = None;
    for _ in 0..count {
        let key_start = decoder.position();
        let name = decoder.text(255)?;
        let encoded_key = decoder.slice(key_start, decoder.position())?;
        if name.is_empty() || previous.is_some_and(|prior: &[u8]| prior >= encoded_key) {
            return Err(EvidenceError::Schema);
        }
        previous = Some(encoded_key);

        let value_start = decoder.position();
        crate::tree_format::property_value(&mut decoder)?;
        let value = decoder.slice(value_start, decoder.position())?;
        if let Some(registries) = registries {
            let behavioral = registries
                .behavioral_properties
                .iter()
                .any(|property| property == name);
            if !behavioral
                && !registries
                    .later_properties
                    .iter()
                    .any(|later| later == name)
            {
                return Err(EvidenceError::Schema);
            }
            if behavioral && interpret_behavior {
                match (registries.property_revision, name) {
                    (2 | 3, "index-roots") => {
                        crate::indexing::IndexRoots::decode_binding(value)
                            .map_err(|_| EvidenceError::Schema)?;
                    }
                    (3, "index-gaps") => return Err(EvidenceError::Schema),
                    _ => {
                        validate_property(&Property { name, value })?;
                    }
                }
            }
        } else if REVISION_ONE_PROPERTIES.contains(&name) {
            // Nested records have no revision field. Their original behavioral
            // checks stay fixed; later names await the enclosing explicit fence.
            validate_property(&Property { name, value })?;
        }
    }
    decoder.finish()?;
    Ok(())
}

#[cfg(test)]
#[path = "policy/active_tests.rs"]
mod active_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_property_names_remain_inert_under_their_recorded_revision() -> Result<(), EvidenceError>
    {
        let mut registry = ConfiguredRegistryInputs {
            property_revision: 1,
            behavioral_properties: REVISION_ONE_PROPERTIES
                .iter()
                .map(|name| (*name).into())
                .collect(),
            attribute_revision: 1,
            selector_revision: 1,
            tree_revision: 1,
            chunk_revision: 1,
            identity_profile: "terrane-v1".into(),
            later_properties: alloc::vec!["index-roots".into()],
        };
        registry.validate()?;
        // This canonical opaque value is invalid as a behavioral owner binding.
        // Its meaning remains inert under the independently recorded old fence.
        let map = b"\xa1\x6bindex-roots\x00";
        property_map(map, Some(&registry))?;

        registry.later_properties.clear();
        assert_eq!(
            property_map(map, Some(&registry)),
            Err(EvidenceError::Schema)
        );

        registry.property_revision = 2;
        registry.behavioral_properties.push("index-roots".into());
        registry.behavioral_properties.sort();
        registry.validate()?;
        assert!(property_map(map, Some(&registry)).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod private_registry_tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Fixture failures intentionally panic in tests."
    )]
    use super::*;

    fn registry(revision: u64, attribute_revision: u64) -> ConfiguredRegistryInputs {
        let mut behavioral_properties: Vec<String> = REVISION_ONE_PROPERTIES
            .iter()
            .map(|name| (*name).into())
            .collect();
        if revision >= 2 {
            behavioral_properties.push("index-roots".into());
        }
        if revision >= 3 {
            behavioral_properties.push("index-gaps".into());
        }
        behavioral_properties.sort();

        ConfiguredRegistryInputs {
            property_revision: revision,
            behavioral_properties,
            attribute_revision,
            selector_revision: 1,
            tree_revision: 1,
            chunk_revision: 1,
            identity_profile: "terrane-v1".into(),
            later_properties: Vec::new(),
        }
    }

    #[test]
    fn property_and_attribute_revisions_bind_structural_index_names_exactly() {
        for revision in 1..=3 {
            for attribute_revision in [1, 2] {
                let model = registry(revision, attribute_revision);
                assert_eq!(model.behavioral_properties.len(), 32 + revision as usize);
                assert_eq!(model.validate(), Ok(()));
                assert_eq!(
                    ConfiguredRegistryInputs::property_revision_for(&model.behavioral_properties),
                    Ok(revision)
                );

                for mismatched in 1..=3 {
                    if mismatched != revision {
                        let mut wrong = model.clone();
                        wrong.property_revision = mismatched;
                        assert_eq!(wrong.validate(), Err(EvidenceError::Contradiction));
                    }
                }
                for unknown in [0, 4, u64::MAX] {
                    let mut wrong = model.clone();
                    wrong.property_revision = unknown;
                    assert_eq!(wrong.validate(), Err(EvidenceError::UnsupportedRevision));
                }
                for unknown in [0, 3, u64::MAX] {
                    let mut wrong = model.clone();
                    wrong.attribute_revision = unknown;
                    assert_eq!(wrong.validate(), Err(EvidenceError::UnsupportedRevision));
                }
                for field in 0..3 {
                    let mut wrong = model.clone();
                    match field {
                        0 => wrong.selector_revision = 2,
                        1 => wrong.tree_revision = 2,
                        _ => wrong.chunk_revision = 2,
                    }
                    assert_eq!(wrong.validate(), Err(EvidenceError::UnsupportedRevision));
                }
            }
        }
    }

    #[test]
    fn legacy_semantic_contexts_preserve_inert_index_carriers() {
        // Independent canonical maps deliberately carry invalid active values.
        let roots = b"\xa1\x6bindex-roots\x00";
        let gaps = b"\xa1\x6aindex-gaps\x00";
        for attribute_revision in [1, 2] {
            for revision in [1, 2] {
                let mut model = registry(revision, attribute_revision);
                model.later_properties.push("index-gaps".into());
                if revision == 1 {
                    model.later_properties.push("index-roots".into());
                    assert_eq!(property_map(roots, Some(&model)), Ok(()));
                } else {
                    assert!(property_map(roots, Some(&model)).is_err());
                }
                assert_eq!(model.validate(), Ok(()));
                assert_eq!(property_map(gaps, Some(&model)), Ok(()));
                model.later_properties.clear();
                assert_eq!(property_map(gaps, Some(&model)), Err(EvidenceError::Schema));
            }
            let current = registry(3, attribute_revision);
            assert_eq!(
                property_map(gaps, Some(&current)),
                Err(EvidenceError::Schema)
            );
        }

        use crate::indexing::carrier::{SemanticContext, validate_namespace_attributes};
        use crate::tree_format::{Attribute, Entry, EntryKind};

        // Presence and digest width cannot activate a historical pointer.
        let mut pointer = alloc::vec![0x58, 0x20];
        pointer.extend_from_slice(&[7; 32]);
        for value in [&pointer[..], &b"\x00"[..]] {
            let entry = Entry {
                kind: EntryKind::Directory { mode: 0o755 },
                attrs: alloc::vec![Attribute {
                    name: "index.occurrences",
                    value
                }],
                attrs_present: true,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            };
            assert_eq!(validate_namespace_attributes(1, &entry), Ok(()));
            assert!(validate_namespace_attributes(2, &entry).is_err());
            for unknown in [0, 3, u64::MAX] {
                assert!(validate_namespace_attributes(unknown, &entry).is_err());
            }
        }
        assert!(SemanticContext::new(3, 2, 1).is_ok());
        for (property, attribute, tree) in [
            (1, 1, 1),
            (2, 2, 1),
            (3, 1, 1),
            (4, 2, 1),
            (3, 3, 1),
            (3, 2, 2),
        ] {
            assert!(SemanticContext::new(property, attribute, tree).is_err());
        }

        // Unfenced nested records defer both new names to the enclosing fence.
        assert_eq!(property_map(roots, None), Ok(()));
        assert_eq!(property_map(gaps, None), Ok(()));
        assert!(property_map(b"\xa1\x66domain\x00", None).is_err());
    }
}
