//! Resolves properties under explicitly selected recorded registry revisions.
//!
//! The caller supplies the recorded revision and any trusted later registrations.
//! Selecting a revision describes ordinary data; it does not confer authority or
//! establish that a decoded publication is admissible. Later names remain in the
//! caller's raw maps and never enter effective policy.

use super::{Defaults, Domain, EffectiveProperties, Error, PropertyName, RootLayer, Value};
use super::{registry, validate_domain_policy, validate_property, value};
use crate::cbor;
use crate::tree_format::{MAX_GRAFT_DEPTH, Property};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Owns caller-supplied immutable view/root interpretation associations.
pub mod associations;

/// Owns mixed Legacy and Recorded inputs without authenticating their selection.
pub mod selections;

// This explicit list freezes revision 1 even when the compiled registry grows.
const ORIGINAL_NAMES: &[&str] = &[
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

/// Owns one explicitly selected recorded revision and trusted preservation set.
///
/// Equality includes the independently selected current revision. Later names
/// are copied and sorted without adding them to behavioral policy. The caller
/// separately binds this interpretation to the immutable signed view and its
/// original namespace root before any fold preprocessing.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecordedContext {
    revision: u64,
    current_revision: u64,
    later_registered: Vec<String>,
}

#[derive(Clone, Copy)]
// Generic syntax validation retains the existing preserved-map contract;
// namespace roles additionally enforce active structural placement rules.
pub(super) enum Placement {
    /// Syntax-only validation, including registered auxiliary bindings.
    Data,
    /// Properties owned by a namespace root.
    NamespaceRoot,
    /// Properties supplied by one graft occurrence.
    GraftOverride,
}

impl RecordedContext {
    /// Validates exact registered revisions and a disjoint preservation vocabulary.
    ///
    /// The current revision is an explicit supported configuration input; it is
    /// never inferred from the newest compiled registry or a stored lineage.
    /// The supplied later-name list is the caller's explicit registration input.
    /// Known names must be registered by the selected current revision. Unknown
    /// extension names are deliberately installed as preserve-only registrations;
    /// this pure constructor cannot authenticate the operator supplying them.
    /// Neither revision nor copied names establish publication authority.
    ///
    /// # Errors
    /// Rejects unknown revisions, a recorded revision newer than the selected
    /// current revision, known later names introduced after the current revision,
    /// duplicate later names or behavioral-name overlap. Empty
    /// names, names longer than 255 bytes and sets over 65,536 bytes exceed limits.
    pub fn new(
        revision: u64,
        current_revision: u64,
        later_registered: &[&str],
    ) -> Result<Self, Error> {
        if !matches!(revision, 1..=3)
            || !matches!(current_revision, 1..=3)
            || revision > current_revision
        {
            return Err(Error::InvalidValue);
        }
        let mut bytes = 0usize;
        for (position, name) in later_registered.iter().enumerate() {
            if name.is_empty() || name.len() > 255 {
                return Err(Error::Limit);
            }
            bytes = bytes.checked_add(name.len()).ok_or(Error::Limit)?;
            if bytes > 65536 {
                return Err(Error::Limit);
            }
            if supports(revision, name)
                || later_registered[..position].contains(name)
                || introduced_revision(name).is_some_and(|introduced| introduced > current_revision)
            {
                return Err(Error::InvalidValue);
            }
        }
        // Validate every name and the whole bound before copying caller data.
        let mut later: Vec<_> = later_registered
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        later.sort_unstable();
        Ok(Self {
            revision,
            current_revision,
            later_registered: later,
        })
    }

    /// Returns the exact recorded property revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the independently selected current property revision.
    pub const fn current_revision(&self) -> u64 {
        self.current_revision
    }

    /// Iterates the exact behavioral vocabulary in unsigned UTF-8 order.
    ///
    /// Revisions 1, 2 and 3 have exactly 33, 34 and 35 names. Auxiliary-only
    /// `index-gaps` is recognized at revision 3 but never becomes namespace policy.
    pub fn behavioral_names(&self) -> impl Iterator<Item = &'static str> {
        let mut names = ORIGINAL_NAMES.to_vec();
        if self.revision >= 2 {
            names.push("index-roots");
        }
        if self.revision >= 3 {
            names.push("index-gaps");
        }
        names.sort_unstable();
        names.into_iter()
    }

    /// Borrows the exact sorted preservation set without assigning behavior.
    pub fn later_registered(&self) -> &[String] {
        &self.later_registered
    }

    /// Reports whether the recorded revision interprets a registered name.
    ///
    /// Auxiliary `index-gaps` is recognized at revision 3 but remains forbidden
    /// in namespace policy. The exhaustive legacy list freezes revision 1's
    /// vocabulary independently of future additions to the compiled registry.
    pub const fn supports(&self, name: PropertyName) -> bool {
        match name {
            PropertyName::IndexRoots => self.revision >= 2,
            PropertyName::IndexGaps => self.revision >= 3,
            PropertyName::Store
            | PropertyName::Chunk
            | PropertyName::Compression
            | PropertyName::Encryption
            | PropertyName::Retain
            | PropertyName::Domain
            | PropertyName::Dedup
            | PropertyName::Redundancy
            | PropertyName::Degraded
            | PropertyName::Durability
            | PropertyName::Replicate
            | PropertyName::Home
            | PropertyName::Warm
            | PropertyName::Quota
            | PropertyName::CompactionThreshold
            | PropertyName::WholePackThreshold
            | PropertyName::GapMergeBytes
            | PropertyName::SpanMaxBytes
            | PropertyName::Trust
            | PropertyName::Baseline
            | PropertyName::Merge
            | PropertyName::Writers
            | PropertyName::ReflogRetain
            | PropertyName::Prefetch
            | PropertyName::Reassembly
            | PropertyName::Passthrough
            | PropertyName::Wipe
            | PropertyName::OnRelease
            | PropertyName::Acl
            | PropertyName::Hashes
            | PropertyName::Classify
            | PropertyName::Index
            | PropertyName::StrictAttrs => true,
        }
    }

    /// Validates a namespace root map under the recorded revision.
    ///
    /// Later registrations receive only canonical value and size validation.
    /// Their bytes and placement remain uninterpreted by this revision.
    ///
    /// # Errors
    /// Rejects unknown names, duplicates, malformed or oversized values, invalid
    /// active bindings, and active auxiliary-only `index-gaps` placement.
    pub fn validate_map(&self, properties: &[Property<'_>]) -> Result<(), Error> {
        self.validate(properties, Placement::NamespaceRoot)
    }

    /// Validates graft overrides under the recorded revision.
    ///
    /// # Errors
    /// Rejects invalid maps and active owner-only `index-roots` or auxiliary-only
    /// `index-gaps`. Trusted later names retain no active placement restrictions.
    pub fn validate_graft_overrides(&self, properties: &[Property<'_>]) -> Result<(), Error> {
        self.validate(properties, Placement::GraftOverride)
    }

    /// Checks root and graft maps before replacements erase their roles.
    ///
    /// # Errors
    /// Rejects malformed maps and active owner-only or auxiliary placements.
    pub(super) fn validate_layer(
        &self,
        properties: &[Property<'_>],
        overrides: &[Property<'_>],
    ) -> Result<(), Error> {
        self.validate_map(properties)?;
        self.validate_graft_overrides(overrides)
    }

    /// Validates bounded raw values under the supplied contextual placement.
    ///
    /// # Errors
    /// Rejects malformed or unknown values, duplicate names and active role violations.
    pub(super) fn validate(
        &self,
        properties: &[Property<'_>],
        placement: Placement,
    ) -> Result<(), Error> {
        let mut bytes = 0usize;
        for (position, property) in properties.iter().enumerate() {
            if property.name.is_empty() || property.name.len() > 255 {
                return Err(Error::Limit);
            }
            bytes = bytes
                .checked_add(property.name.len())
                .and_then(|size| size.checked_add(property.value.len()))
                .ok_or(Error::Limit)?;
            if bytes > 65536 {
                return Err(Error::Limit);
            }
            if properties[..position]
                .iter()
                .any(|other| other.name == property.name)
            {
                return Err(Error::InvalidValue);
            }

            match PropertyName::parse(property.name) {
                Ok(name) if self.supports(name) => {
                    if matches!(
                        (placement, name),
                        (
                            Placement::NamespaceRoot | Placement::GraftOverride,
                            PropertyName::IndexGaps
                        ) | (Placement::GraftOverride, PropertyName::IndexRoots)
                    ) {
                        return Err(Error::InvalidValue);
                    }
                    validate_property(property)?;
                }
                _ if self
                    .later_registered
                    .iter()
                    .any(|name| name == property.name) =>
                {
                    let mut decoder = cbor::Decoder::new(property.value);
                    value::skip_value(&mut decoder, 65536)?;
                    decoder.finish()?;
                }
                _ => return Err(Error::UnknownProperty),
            }
        }
        Ok(())
    }

    /// Resolves an ancestor-first path using only the recorded behavioral names.
    ///
    /// Later names remain unchanged in the supplied maps. Revision 1 supplies
    /// 33 defaults; revisions 2 and 3 supply 34 namespace defaults, never an
    /// implicit gap reference. No cache, I/O, or authorization is performed.
    ///
    /// # Errors
    /// Rejects invalid maps or defaults, unsupported placement, more than 64
    /// graft edges, and domain policy violations.
    pub fn resolve<'p>(
        &self,
        path: &[RootLayer<'p>],
        defaults: Defaults<'p>,
    ) -> Result<EffectiveProperties<'p>, Error> {
        if path.len().saturating_sub(1) > MAX_GRAFT_DEPTH {
            return Err(Error::Limit);
        }
        let mut values = registry::defaults(defaults)?;
        values.retain(|(name, _)| self.supports(*name));
        let mut wipe_set = false;
        for (position, layer) in path.iter().enumerate() {
            self.validate_map(layer.properties)?;
            self.validate_graft_overrides(layer.overrides)?;
            // A graft-local override replaces the whole binding, including its
            // inherit flag. A local non-inheriting override must not uncover the
            // referenced root's own value in descendant roots.
            for property in layer
                .properties
                .iter()
                .filter(|property| {
                    !layer
                        .overrides
                        .iter()
                        .any(|other| other.name == property.name)
                })
                .chain(layer.overrides.iter())
            {
                if !PropertyName::parse(property.name).is_ok_and(|name| self.supports(name)) {
                    continue;
                }
                let (name, value) = validate_property(property)?;
                let (_, inherit) = registry::binding(property.value)?;
                if !inherit && position + 1 != path.len() {
                    continue;
                }
                if name == PropertyName::Wipe {
                    wipe_set = true;
                }
                if let Some(existing) = values.iter_mut().find(|(key, _)| *key == name) {
                    existing.1 = value;
                }
            }
        }
        let active_index_roots = path
            .last()
            .and_then(|layer| {
                layer
                    .properties
                    .iter()
                    .find(|property| property.name == "index-roots")
            })
            .filter(|_| self.revision >= 2)
            .map(|property| {
                crate::indexing::IndexRoots::decode_binding(property.value)
                    .map_err(|_| Error::InvalidValue)
            })
            .transpose()?;
        let mut effective = EffectiveProperties {
            values,
            active_index_roots,
        };
        if !wipe_set {
            let wipe = if matches!(effective.domain()?, Domain::Private(_)) {
                "zero"
            } else {
                "none"
            };
            if let Some((_, value)) = effective
                .values
                .iter_mut()
                .find(|(name, _)| *name == PropertyName::Wipe)
            {
                *value = Value::Text(wipe);
            }
        }
        validate_domain_policy(&effective)?;
        Ok(effective)
    }
}

// Known later names need a current configuration that registers their revision.
// Uncompiled extension names instead come from the explicit installation input.
fn introduced_revision(name: &str) -> Option<u64> {
    match name {
        "index-roots" => Some(2),
        "index-gaps" => Some(3),
        _ => None,
    }
}

fn supports(revision: u64, name: &str) -> bool {
    ORIGINAL_NAMES.contains(&name)
        || (revision >= 2 && name == "index-roots")
        || (revision >= 3 && name == "index-gaps")
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[allow(clippy::expect_used, reason = "invalid property fixtures must panic")]
#[path = "semantics/tests_private.rs"]
mod private_tests;
