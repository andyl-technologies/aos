//! Binds exact authenticated side records to canonical view and domain witnesses.
//!
//! Side values remain outside the tree. Their signatures prove production;
//! acceptance still requires verified ancestor history carrying an inline value.
//!
//! ```text
//! selected evidence = [[view-location, name, domain, full-view-path,
//!                       [record, object, name, function, version, value,
//!                        producer, producer-location, [domain, full-path]]], ...]
//! ```

use super::{EntryLocation, Rejected, VerifiedHistory};
use crate::{
    cbor,
    derived::VerifiedAttributeEvidence,
    identity::Digest,
    properties::{self, Defaults, RootLayer, Value},
    tree_format::{ContentRef, Entry, EntryKind},
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

pub(super) type SideAttributeKey = (EntryLocation, String, String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BoundSideAttribute {
    evidence: VerifiedAttributeEvidence,
    producer_domain: String,
    producer_path: Vec<u8>,
    view_path: Vec<u8>,
}

/// Supplies canonical paths and trusted defaults for a side record's witnesses.
///
/// Store/home defaults come from protected repository configuration. Signed
/// original contexts derive implicit private ownership from each canonical view;
/// legacy commits retain their explicit trusted original defaults route.
/// The history checks both full paths, effective domains and object identities.
#[derive(Clone, Copy, Debug)]
pub struct SideAttributeBinding<'a> {
    /// Verified immutable view that consumes this selected record.
    pub view: Digest,
    /// Full view-relative path of the consuming file.
    pub path: &'a [u8],
    /// Full path in the checked producing witness commit.
    pub producer_path: &'a [u8],
    /// Policy defaults for the producing witness's repository/root.
    pub producer_defaults: Defaults<'a>,
    /// Policy defaults for the consuming view's repository/root.
    pub view_defaults: Defaults<'a>,
}

fn object(entry: &Entry<'_>) -> Result<Digest, Rejected> {
    match entry.kind {
        EntryKind::File {
            content: ContentRef::Inline(digest) | ContentRef::Manifest(digest),
            ..
        } => Ok(digest),
        _ => Err(Rejected),
    }
}

fn effective_domain(
    history: &VerifiedHistory,
    view: Digest,
    path: &[u8],
    defaults: Defaults<'_>,
) -> Result<(EntryLocation, String), Rejected> {
    let record = history.commit(&view).ok_or(Rejected)?.commit();
    let canonical_owner = record
        .profile_pair
        .commit_context
        .is_some()
        .then(|| super::root_context::canonical_private_domain(record.tree))
        .transpose()?;
    let defaults = Defaults {
        private_domain: canonical_owner
            .as_deref()
            .unwrap_or(defaults.private_domain),
        ..defaults
    };
    let (location, properties) = history.locate_policies(view, path)?;
    let layers: Vec<_> = properties
        .iter()
        .map(|properties| RootLayer {
            properties,
            overrides: &[],
        })
        .collect();
    let effective = history
        .view_selection(view)?
        .resolve(&layers, defaults)
        .map_err(|_| Rejected)?;
    let Some(Value::Text(domain)) = effective.get(properties::PropertyName::Domain) else {
        return Err(Rejected);
    };
    effective.domain().map_err(|_| Rejected)?;
    Ok((location, (*domain).to_string()))
}

impl VerifiedHistory {
    /// Selects an authenticated side record for a canonical file in one view.
    ///
    /// The typed evidence originates in `derived::verify_record_producer`.
    /// This operation rechecks its witness against this history and binds both
    /// effective domains and exact paths. It creates no inline attributes,
    /// introducing commits, or ancestor-carried acceptance evidence (PROV-9/16).
    /// Only one exact record can be selected per view location/name/domain.
    /// Incomplete evidence remains unavailable; rejection does not establish
    /// record invalidity or authorize durable quarantine.
    ///
    /// # Errors
    /// Returns [`Rejected`] for unavailable, unfinished or unrelated witnesses,
    /// policy/domain violations, missing producer commits, contradictory inline
    /// origins/values or a conflicting selected record.
    pub fn insert_side_attribute(
        &mut self,
        evidence: VerifiedAttributeEvidence,
        binding: SideAttributeBinding<'_>,
    ) -> Result<(), Rejected> {
        // Evidence may come from another completed history. This history must
        // independently admit every carrying, producer and destination context.
        self.require_verified_context(*evidence.producer())?;
        self.require_verified_context(evidence.location().commit)?;
        self.require_verified_context(binding.view)?;

        let (producer_location, producer_domain) = effective_domain(
            self,
            evidence.location().commit,
            binding.producer_path,
            binding.producer_defaults,
        )?;
        if producer_location != *evidence.location()
            || object(&self.entry(&producer_location)?)? != *evidence.object()
        {
            return Err(Rejected);
        }
        let (location, domain) =
            effective_domain(self, binding.view, binding.path, binding.view_defaults)?;
        let target = self.entry(&location)?;
        if object(&target)? != *evidence.object()
            || !properties::Domain::parse(&domain)
                .map_err(|_| Rejected)?
                .permits_reference(
                    properties::Domain::parse(&producer_domain).map_err(|_| Rejected)?,
                )
        {
            return Err(Rejected);
        }
        let name = evidence.name().as_str();
        if let Some(inline) = target.attrs.iter().find(|attribute| attribute.name == name)
            && (inline.value != evidence.value()
                || self.attribute_producer(&location, name)? != *evidence.producer())
        {
            return Err(Rejected);
        }
        drop(target);

        let key = (location, name.to_string(), domain);
        let bound = BoundSideAttribute {
            evidence,
            producer_domain,
            producer_path: binding.producer_path.to_vec(),
            view_path: binding.path.to_vec(),
        };
        if self
            .side_attributes
            .get(&key)
            .is_some_and(|previous| *previous != bound)
        {
            return Err(Rejected);
        }
        self.side_attributes.insert(key, bound);
        Ok(())
    }

    pub(super) fn attribute_context(
        &self,
        location: &EntryLocation,
        name: &str,
        domain: &str,
        require_acceptance: bool,
    ) -> Result<(Digest, Vec<Digest>, Option<&BoundSideAttribute>), Rejected> {
        let side =
            self.side_attributes
                .get(&(location.clone(), name.to_string(), domain.to_string()));
        let producer = if let Some(side) = side {
            *side.evidence.producer()
        } else {
            self.attribute_producer(location, name)?
        };
        // A side record alone cannot invent ancestor-carried values. Existing
        // inline history remains the only source of attribute acceptance.
        let acceptance = if self
            .entry(location)?
            .attrs
            .iter()
            .any(|attribute| attribute.name == name)
        {
            if self.attribute_producer(location, name)? != producer {
                return Err(Rejected);
            }
            if require_acceptance {
                self.attribute_acceptance_commits(location, name, producer)?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        Ok((producer, acceptance, side))
    }

    pub(super) fn side_context(&self, view: Digest, domain: &str) -> Vec<u8> {
        let selected: Vec<_> = self
            .side_attributes
            .iter()
            .filter(|((location, _, selected_domain), _)| {
                location.commit == view && selected_domain == domain
            })
            .collect();
        if selected.is_empty() {
            return Vec::new();
        }
        let mut bytes = Vec::new();
        cbor::write_array(&mut bytes, selected.len());
        for ((location, name, domain), bound) in selected {
            cbor::write_array(&mut bytes, 5);
            encode_location(&mut bytes, location);
            cbor::write_text(&mut bytes, name);
            cbor::write_text(&mut bytes, domain);
            cbor::write_bytes(&mut bytes, &bound.view_path);
            bound.encode_context(&mut bytes);
        }
        bytes
    }
}

fn encode_location(output: &mut Vec<u8>, location: &EntryLocation) {
    cbor::write_array(output, 3);
    cbor::write_bytes(output, &location.commit);
    cbor::write_bytes(output, &location.root);
    cbor::write_bytes(output, &location.path);
}

impl BoundSideAttribute {
    pub(super) fn encode_context(&self, output: &mut Vec<u8>) {
        cbor::write_array(output, 9);
        cbor::write_bytes(output, self.evidence.record().digest());
        cbor::write_bytes(output, self.evidence.object());
        cbor::write_text(output, self.evidence.name().as_str());
        cbor::write_text(output, &self.evidence.function().name);
        cbor::write_text(output, &self.evidence.function().version);
        cbor::write_bytes(output, self.evidence.value());
        cbor::write_bytes(output, self.evidence.producer());
        encode_location(output, self.evidence.location());
        cbor::write_array(output, 2);
        cbor::write_text(output, &self.producer_domain);
        cbor::write_bytes(output, &self.producer_path);
    }
}
