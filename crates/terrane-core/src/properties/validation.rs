//! Checks modified entries and recomputes completeness from supplied metadata.
//!
//! This module never reads content. Derived records are provided by the
//! repository after identity, provenance, and function-version verification.

use super::{Domain, EffectiveProperties, Error, PropertyName, Value};
use crate::cbor::Decoder;
use crate::identity::Digest;
use crate::tree_format::{Attribute, ContentRef, Entry, EntryKind};

/// A previously verified attribute from the derived-data store.
#[derive(Clone, Copy, Debug)]
pub struct DerivedAttribute<'a> {
    /// Object identity named by the record.
    pub object: Digest,
    /// Registered attribute and canonical value.
    pub attribute: Attribute<'a>,
}

/// A changed entry and the disclosure metadata needed for its references.
#[derive(Clone, Copy, Debug)]
pub struct EntryChange<'a> {
    /// Entry being introduced by this commit.
    pub entry: &'a Entry<'a>,
    /// Effective policy of the nearest root along the current graft path.
    pub properties: &'a EffectiveProperties<'a>,
    /// Domains of every referenced chunk, manifest, index target, or tree root.
    pub reference_domains: &'a [Domain<'a>],
    /// Effective target-root policy for a tree entry, including graft overrides.
    pub graft_properties: Option<&'a EffectiveProperties<'a>>,
}

/// Reports whether an attribute belongs to a registered namespace and name.
pub fn registered_attribute(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    if let Some(tag) = name.strip_prefix("tag.") {
        return !tag.is_empty();
    }
    if [
        "uid",
        "gid",
        "zstd-dictionary",
        "hash.sha256",
        "hash.sha512",
        "hash.git-blob-sha1",
        "hash.git-blob-sha256",
        "class.magic",
        "class.elf",
        "class.shebang",
        "provenance.reintroduced-from",
    ]
    .contains(&name)
    {
        return true;
    }
    let Some((namespace, suffix)) = name.split_once('.') else {
        return false;
    };
    match namespace {
        "nar" => [
            "hash_sha256",
            "size",
            "references",
            "deriver",
            "signatures",
            "ca",
            "file_hash",
            "file_size",
            "compression",
        ]
        .contains(&suffix),
        "nix-cache-info" => ["store_dir", "priority", "want_mass_query"].contains(&suffix),
        "reapi" => ["size_bytes", "output_digests"].contains(&suffix),
        "gha" => ["key", "version", "scope", "size", "created_at"].contains(&suffix),
        "oci" => ["media_type", "subject", "annotations"].contains(&suffix),
        _ => false,
    }
}

fn object(entry: &Entry<'_>) -> Option<Digest> {
    match entry.kind {
        EntryKind::File {
            content: ContentRef::Inline(identity) | ContentRef::Manifest(identity),
            ..
        } => Some(identity),
        _ => None,
    }
}

fn attr<'a>(
    entry: &Entry<'a>,
    name: &str,
    derived: &[DerivedAttribute<'a>],
) -> Result<Option<&'a [u8]>, Error> {
    let inline = entry
        .attrs
        .iter()
        .find(|attribute| attribute.name == name)
        .map(|attribute| attribute.value);
    let identity = object(entry);
    let mut record = None;
    for candidate in derived
        .iter()
        .filter(|candidate| Some(candidate.object) == identity && candidate.attribute.name == name)
    {
        if record.is_some_and(|previous| previous != candidate.attribute.value) {
            return Err(Error::InvalidValue);
        }
        record = Some(candidate.attribute.value);
    }
    if inline.is_some() && record.is_some() && inline != record {
        return Err(Error::InvalidValue);
    }
    Ok(inline.or(record))
}

fn hash_attribute(name: &str) -> Result<(&'static str, usize), Error> {
    match name {
        "sha256" => Ok(("hash.sha256", 32)),
        "sha512" => Ok(("hash.sha512", 64)),
        "git-blob-sha1" => Ok(("hash.git-blob-sha1", 20)),
        "git-blob-sha256" => Ok(("hash.git-blob-sha256", 32)),
        _ => Err(Error::InvalidValue),
    }
}

fn satisfies(
    entry: &Entry<'_>,
    property: PropertyName,
    value: &Value<'_>,
    derived: &[DerivedAttribute<'_>],
) -> Result<bool, Error> {
    if property == PropertyName::StrictAttrs {
        let Value::Boolean(strict) = value else {
            return Err(Error::InvalidValue);
        };
        return Ok(!strict
            || entry
                .attrs
                .iter()
                .all(|attribute| registered_attribute(attribute.name)));
    }
    if object(entry).is_none() {
        return Ok(true);
    }
    let Value::Names(names) = value else {
        return Err(Error::InvalidValue);
    };
    match property {
        PropertyName::Hashes => {
            for name in names {
                let (attribute, length) = hash_attribute(name)?;
                let Some(bytes) = attr(entry, attribute, derived)? else {
                    return Ok(false);
                };
                let mut decoder = Decoder::new(bytes);
                if decoder.bytes(length)?.len() != length {
                    return Err(Error::InvalidValue);
                }
                decoder.finish()?;
            }
        }
        PropertyName::Classify => {
            if !names.is_empty() {
                // All registered classifier names are outcomes of class.magic.
                // elf and shebang additionally have structured detail records.
                let Some(bytes) = attr(entry, "class.magic", derived)? else {
                    return Ok(false);
                };
                let mut decoder = Decoder::new(bytes);
                let magic = decoder.text(65536)?;
                if ![
                    "elf", "shebang", "ar", "zstd", "gzip", "tar", "text", "other",
                ]
                .contains(&magic)
                {
                    return Err(Error::InvalidValue);
                }
                decoder.finish()?;
                for name in names {
                    if *name == magic && matches!(*name, "elf" | "shebang") {
                        let required = if *name == "elf" {
                            "class.elf"
                        } else {
                            "class.shebang"
                        };
                        if attr(entry, required, derived)?.is_none() {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        _ => return Err(Error::InvalidValue),
    }
    Ok(true)
}

/// Validates only entries added or modified by a commit.
///
/// Unchanged entries are deliberately absent from this input, so adding a
/// requirement leaves existing gaps for a backfill rather than rejecting the
/// property change. Supplied side-table records avoid content reads.
///
/// # Errors
/// Rejects missing required attributes, invalid attribute values, cross-domain
/// references, inconsistent inline records, or missing reference metadata.
pub fn validate_commit(
    changes: &[EntryChange<'_>],
    derived: &[DerivedAttribute<'_>],
) -> Result<(), Error> {
    for change in changes {
        let mut context = SliceContext {
            domains: change.reference_domains.iter(),
            graft: change.graft_properties,
        };
        validate_changed_entry(change.entry, change.properties, derived, &mut context, 0)?;
        if context.domains.next().is_some() {
            return Err(Error::InvalidValue);
        }
    }
    Ok(())
}

/// Supplies verified disclosure metadata without reading content.
///
/// Implementations look up immutable records already loaded by the repository.
/// Graft policies must be resolved for the candidate entry's overrides and the
/// supplied parent policy, rather than cached by target hash alone.
pub trait CommitContext {
    /// Returns the domain of a referenced object or tree root.
    ///
    /// # Errors
    /// Returns [`Error::IncompleteContext`] when metadata is unavailable.
    fn reference_domain(&mut self, identity: Digest) -> Result<Domain<'_>, Error>;

    /// Returns the target root's effective policy at this graft point.
    ///
    /// # Errors
    /// Returns [`Error::IncompleteContext`] when root or ancestor metadata is unavailable.
    fn graft_policy(
        &self,
        entry: &Entry<'_>,
        parent: &EffectiveProperties<'_>,
    ) -> Result<&EffectiveProperties<'_>, Error>;

    /// Reports verified admin authority on the ancestor for ACL widening.
    ///
    /// The default denies widening. A repository overrides this only after
    /// checking the committing principal's effective ancestor grants.
    fn ancestor_admin(&self, _parent: &EffectiveProperties<'_>) -> bool {
        false
    }

    /// Returns names registered by a trusted later-version property schema.
    ///
    /// Unsupported registered bindings are preserved without affecting policy.
    fn later_registered_properties(&self) -> &[&str] {
        &[]
    }
}

struct SliceContext<'a> {
    domains: core::slice::Iter<'a, Domain<'a>>,
    graft: Option<&'a EffectiveProperties<'a>>,
}

impl CommitContext for SliceContext<'_> {
    fn reference_domain(&mut self, _identity: Digest) -> Result<Domain<'_>, Error> {
        self.domains.next().copied().ok_or(Error::IncompleteContext)
    }

    fn graft_policy(
        &self,
        _entry: &Entry<'_>,
        _parent: &EffectiveProperties<'_>,
    ) -> Result<&EffectiveProperties<'_>, Error> {
        self.graft.ok_or(Error::IncompleteContext)
    }
}

/// Validates changed entries, including every conflict candidate and base.
///
/// The context resolves metadata separately for each reference identity and
/// each graft candidate. Unchanged entries are excluded from `changes`.
///
/// # Errors
/// Rejects missing attributes, unsafe disclosure, invalid policies, malformed
/// nested conflicts, or incomplete reference and graft metadata.
pub fn validate_commit_with_context(
    changes: &[(&Entry<'_>, &EffectiveProperties<'_>)],
    derived: &[DerivedAttribute<'_>],
    context: &mut impl CommitContext,
) -> Result<(), Error> {
    for (entry, properties) in changes {
        validate_changed_entry(entry, properties, derived, context, 0)?;
    }
    Ok(())
}

fn validate_changed_entry(
    entry: &Entry<'_>,
    properties: &EffectiveProperties<'_>,
    derived: &[DerivedAttribute<'_>],
    context: &mut impl CommitContext,
    depth: usize,
) -> Result<(), Error> {
    if depth > 1 {
        return Err(Error::InvalidValue);
    }
    validate_entry(entry, properties, derived)?;
    let domain = properties.domain()?;
    match &entry.kind {
        EntryKind::File {
            content: ContentRef::Inline(identity) | ContentRef::Manifest(identity),
            ..
        } => {
            if !domain.permits_reference(context.reference_domain(*identity)?) {
                return Err(Error::Domain);
            }
        }
        EntryKind::Tree { root, props } => {
            if let Some(props) = props {
                super::validate_preserved_map(props, context.later_registered_properties())?;
            }
            if !domain.permits_reference(context.reference_domain(*root)?) {
                return Err(Error::Domain);
            }
            let target = context.graft_policy(entry, properties)?;
            super::validate_boundary_transition(
                properties,
                target,
                context.ancestor_admin(properties),
            )?;
        }
        EntryKind::Index { targets } => {
            for identity in targets {
                if !domain.permits_reference(context.reference_domain(*identity)?) {
                    return Err(Error::Domain);
                }
            }
        }
        EntryKind::Conflict { candidates, base } => {
            if depth != 0 || candidates.len() < 2 {
                return Err(Error::InvalidValue);
            }
            for candidate in candidates {
                validate_changed_entry(candidate, properties, derived, context, depth + 1)?;
            }
            if let Some(Some(base)) = base {
                validate_changed_entry(base, properties, derived, context, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_entry(
    entry: &Entry<'_>,
    properties: &EffectiveProperties<'_>,
    derived: &[DerivedAttribute<'_>],
) -> Result<(), Error> {
    if entry.attrs.len() > 256 {
        return Err(Error::Limit);
    }
    if properties.get(PropertyName::StrictAttrs) == Some(&Value::Boolean(true)) {
        for attribute in &entry.attrs {
            if !registered_attribute(attribute.name) {
                return Err(Error::UnknownAttribute);
            }
        }
    }
    for property in [PropertyName::Hashes, PropertyName::Classify] {
        let value = properties.get(property).ok_or(Error::InvalidValue)?;
        if !satisfies(entry, property, value, derived)? {
            return Err(Error::MissingAttribute);
        }
    }
    Ok(())
}

/// A tree-derived count for one requirement property.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Completeness {
    /// Number of applicable entries satisfying every named requirement.
    pub complete: u64,
    /// Number of applicable entries missing at least one requirement.
    pub incomplete: u64,
}

impl Completeness {
    /// Reports whether status should request a backfill job.
    pub const fn backfill_required(self) -> bool {
        self.incomplete != 0
    }
}

/// Recomputes requirement completeness from entries and verified side records.
///
/// Every entry is paired with policy resolved along its actual graft path.
/// No counter cache is kept, and changing any ancestor requirement therefore
/// changes the next result. `indexes` lists verified materialized attributes
/// for the root when reporting the index requirement.
///
/// # Errors
/// Rejects invalid policies, inconsistent derived records, invalid attribute
/// values, unsupported requirement names, or an overflowing entry count.
pub fn completeness(
    entries: &[(&Entry<'_>, &EffectiveProperties<'_>)],
    property: PropertyName,
    derived: &[DerivedAttribute<'_>],
    indexes: &[&str],
) -> Result<Completeness, Error> {
    let mut report = Completeness::default();
    for (entry, policy) in entries {
        if object(entry).is_none() && property != PropertyName::StrictAttrs {
            continue;
        }
        let value = policy.get(property).ok_or(Error::InvalidValue)?;
        let complete = if property == PropertyName::Index {
            let Value::Names(names) = value else {
                return Err(Error::InvalidValue);
            };
            names.iter().all(|name| indexes.contains(name))
        } else {
            satisfies(entry, property, value, derived)?
        };
        let count = if complete {
            &mut report.complete
        } else {
            &mut report.incomplete
        };
        *count = count.checked_add(1).ok_or(Error::Limit)?;
    }
    Ok(report)
}
