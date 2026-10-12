//! Builds independent canonical tree and cache witnesses for common replay.
//!
//! The terminal occurrence helper frames this leaf shape directly:
//! ```text
//! {1: 0, 2: [[key-bytes, 0, {1: 7, 14: [object-digest32]}]]}
//! ```

use crate::algebra::OperationDomains;
use crate::derivation::cache::{AdvisoryCache, CacheRecord, CacheUnavailable};
use crate::derivation::evaluation::EvaluationInputs;
use crate::identity::{Digest, IdentityKind, TERRANE_V1};
use crate::indexing::carrier::SemanticContext;
use crate::tree_builder::Tree;
use crate::tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Defines the immutable chunk geometry used by the pure namespace fixtures.
pub(super) const MINIMUM: u64 = 1024;

/// Encodes the explicit private domain carried by the pure namespace fixtures.
pub(super) const DOMAIN: &[u8] = b"\x70private:verified";

/// Creates an entry without attributes, extended attributes or provenance.
pub(super) fn entry(kind: EntryKind<'_>) -> Entry<'_> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

/// Pairs an owned key with the supplied entry for a canonical tree fixture.
pub(super) fn item<'a>(key: &[u8], entry: Entry<'a>) -> LeafItem<'a> {
    LeafItem {
        key: key.to_vec(),
        entry,
    }
}

/// Builds a namespace with the fixture's explicit domain and chunk geometry.
///
/// # Panics
/// Panics if the supplied entries do not form a valid canonical namespace.
pub(super) fn namespace(items: Vec<LeafItem<'_>>) -> Tree<'_> {
    Tree::build(
        items,
        Some(alloc::vec![Property {
            name: "domain",
            value: DOMAIN
        }]),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap()
}

/// Creates a symlink leaf item with the supplied key and fixed target bytes.
pub(super) fn symlink(key: &[u8], target: &'static [u8]) -> LeafItem<'static> {
    item(key, entry(EntryKind::Symlink { target }))
}

/// Creates a tree reference without graft-local property overrides.
pub(super) fn graft(root: Digest) -> Entry<'static> {
    entry(EntryKind::Tree { root, props: None })
}

/// Borrows the namespace graph with the registered index semantic revisions.
///
/// # Panics
/// Panics if the registered property 3, attribute 2 and tree 1 context is rejected.
pub(super) fn inputs<'t, 'a>(trees: &'t BTreeMap<Digest, Tree<'a>>) -> EvaluationInputs<'t, 'a> {
    EvaluationInputs {
        trees,
        minimum: MINIMUM,
        context: SemanticContext::new(3, 2, 1).unwrap(),
        domains: None,
        provenance: &[],
        fold: None,
        overlay: None,
    }
}

/// Copies every physical Node of one tree into an identity-indexed byte map.
pub(super) fn nodes(tree: &Tree<'_>) -> BTreeMap<Digest, Vec<u8>> {
    tree.nodes()
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect()
}

/// Hashes fixture bytes in the supplied Terrane v1 identity domain.
///
/// # Panics
/// Panics if the registered profile cannot calculate or expose that digest.
pub(super) fn digest(kind: IdentityKind, bytes: &[u8]) -> Digest {
    TERRANE_V1
        .calculate(kind, bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap()
}

/// Binds each supplied root to independently resolved fixture ownership.
///
/// # Panics
/// Panics if property resolution or a root's ownership binding is rejected.
pub(super) fn domains(roots: &[Digest], domain: &'static str) -> OperationDomains {
    let effective = crate::properties::resolve(
        &[],
        crate::properties::Defaults {
            store: "memo-fixture-store",
            private_domain: domain,
            home: "memo-fixture-home",
        },
    )
    .unwrap();
    let mut domains = OperationDomains::new();
    for root in roots {
        domains.bind_resolved(*root, &effective).unwrap();
    }
    domains
}

/// Borrows canonical fixture roots through the ordinary algebra resolver.
pub(super) struct Forest<'t, 'a>(/** Canonical roots. */ pub(super) &'t BTreeMap<Digest, Tree<'a>>);

impl<'a> crate::algebra::Roots<'a> for Forest<'_, 'a> {
    fn resolve(&self, identity: &Digest) -> Option<&Tree<'a>> {
        self.0.get(identity)
    }
}

/// Refuses every advisory lookup and replacement for cache-availability tests.
pub(super) struct Unavailable;

impl AdvisoryCache for Unavailable {
    /// Refuses the advisory lookup without supplying a record.
    ///
    /// # Errors
    /// Always returns `CacheUnavailable`.
    fn lookup(&mut self, _: Digest) -> Result<Option<CacheRecord>, CacheUnavailable> {
        Err(CacheUnavailable)
    }

    /// Refuses advisory replacement without retaining the supplied record.
    ///
    /// # Errors
    /// Always returns `CacheUnavailable`.
    fn replace(&mut self, _: Digest, _: CacheRecord) -> Result<(), CacheUnavailable> {
        Err(CacheUnavailable)
    }
}

/// Encodes an independent generic recipe rather than using an executable codec.
pub(super) fn retained(operation: &str, root: Digest, argument: Option<(&str, &str)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    crate::cbor::write_map(&mut bytes, 2 + usize::from(argument.is_some()));
    crate::cbor::write_uint(&mut bytes, 1);
    crate::cbor::write_text(&mut bytes, operation);
    crate::cbor::write_uint(&mut bytes, 2);
    crate::cbor::write_array(&mut bytes, 1);
    crate::cbor::write_bytes(&mut bytes, &root);
    if let Some((key, value)) = argument {
        crate::cbor::write_uint(&mut bytes, 3);
        crate::cbor::write_map(&mut bytes, 1);
        crate::cbor::write_text(&mut bytes, key);
        crate::cbor::write_text(&mut bytes, value);
    }
    bytes
}

/// Assembles a single terminal route directly from the CDDL Node/entry fields.
pub(super) fn terminal_route_wire(key: &[u8], object: Digest) -> Vec<u8> {
    let mut bytes = alloc::vec![0xa2, 1, 0, 2, 0x81, 0x83];
    crate::cbor::write_bytes(&mut bytes, key);
    bytes.extend_from_slice(&[0, 0xa2, 1, 7, 14, 0x81]);
    crate::cbor::write_bytes(&mut bytes, &object);
    bytes
}
