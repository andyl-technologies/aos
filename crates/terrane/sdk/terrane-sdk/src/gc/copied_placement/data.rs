//! Checks declared DATA dependencies without certifying foreign historical authority.
//!
//! The caller supplies bodies fetched through actual current eligible placement.
//! This layer checks canonical identities and dependency availability only. It
//! retains all encountered history and side metadata, makes no proof-edge pruning
//! decision, and cannot construct a publication or native-effect capability.

use crate::pack::IndexEntry;
use crate::store::{StoreErrorKind, StoreFailure};
use std::collections::{BTreeMap, BTreeSet};
use terrane_format::chunking::ChunkProfile;
use terrane_format::derived::{AttrRecord, AttributeName, AttributeValue};
use terrane_format::gc::{ExpandedContext, ExpandedObject, ParentCutoff};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::indexing::IndexRoots;
use terrane_format::manifest::Manifest;
use terrane_format::refs::{Commit, EntryOrigin, EntrySource};
use terrane_format::tree_format::{self, ContentRef, Entry, EntryKind, NodeItems, TreeUse};

/// Contains canonical metadata actually returned by the current serving path.
pub(super) type Bodies = BTreeMap<(u8, Digest), Vec<u8>>;

/// Contains actual eligible chunk rows without reading chunk bodies.
pub(super) type Chunks = BTreeMap<Digest, IndexEntry>;

/// Records completed physical expansions without authenticated proof contexts.
pub(super) struct Traversal {
    /// Complete actual commit expansions, without parent-age pruning.
    pub(super) commits: Vec<ExpandedContext>,
    /// Complete typed expansions and actual structural node contexts.
    pub(super) objects: Vec<ExpandedObject>,
    /// Exact current eligible identities conservatively retained physically.
    pub(super) hashes: Vec<Digest>,
}

#[derive(Default)]
struct Dependencies {
    commits: BTreeSet<Digest>,
    objects: BTreeSet<Digest>,
}

// Commit::decode has already checked the entire registered recipe schema.
// Physical retention follows its explicit operands, without evaluating generic
// arguments or treating an audit/configuration digest as a public object edge.
fn recipe_roots(encoded: &[u8]) -> Result<Vec<Digest>, StoreFailure> {
    let mut decoder = terrane_format::cbor::Decoder::new(encoded);
    let fields = decoder.map(3).map_err(|_| corrupt())?;
    if !(2..=3).contains(&fields) || decoder.uint().map_err(|_| corrupt())? != 1 {
        return Err(corrupt());
    }
    decoder.text(32).map_err(|_| corrupt())?;
    if decoder.uint().map_err(|_| corrupt())? != 2 {
        return Err(corrupt());
    }
    let count = decoder.array(encoded.len()).map_err(|_| corrupt())?;
    let mut roots = Vec::with_capacity(count);
    for _ in 0..count {
        roots.push(
            decoder
                .bytes(32)
                .map_err(|_| corrupt())?
                .try_into()
                .map_err(|_| corrupt())?,
        );
    }
    if fields == 3 {
        if decoder.uint().map_err(|_| corrupt())? != 3 {
            return Err(corrupt());
        }
        decoder.skip_value(encoded.len()).map_err(|_| corrupt())?;
    }
    decoder.finish().map_err(|_| corrupt())?;
    Ok(roots)
}

fn corrupt() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(
        crate::store::CorruptSubject::RefName("copied-placement".into()),
    ))
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}

fn key(kind: IdentityKind, hash: Digest) -> (u8, Digest) {
    (kind as u8, hash)
}

fn require(bodies: &Bodies, kind: IdentityKind, hash: Digest) -> Result<&[u8], StoreFailure> {
    bodies
        .get(&key(kind, hash))
        .map(Vec::as_slice)
        .ok_or_else(unavailable)
}

fn chunk(chunks: &Chunks, hash: Digest, length: Option<u64>) -> Result<(), StoreFailure> {
    let row = chunks.get(&hash).ok_or_else(unavailable)?;
    if length.is_some_and(|length| length != u64::from(row.plaintext_len())) {
        return Err(corrupt());
    }
    Ok(())
}

fn content(
    bodies: &Bodies,
    chunks: &Chunks,
    profile: &ChunkProfile,
    reference: ContentRef,
    size: u64,
    dependencies: &mut Dependencies,
) -> Result<(), StoreFailure> {
    match reference {
        ContentRef::Inline(hash) => {
            dependencies.objects.insert(hash);
            chunk(chunks, hash, Some(size))
        }
        ContentRef::Manifest(hash) => {
            dependencies.objects.insert(hash);
            let bytes = require(bodies, IdentityKind::Manifest, hash)?;
            let manifest = Manifest::decode(bytes, profile).map_err(|_| corrupt())?;
            if manifest.size != size {
                return Err(corrupt());
            }
            for declaration in manifest.chunks {
                dependencies.objects.insert(declaration.digest);
                chunk(chunks, declaration.digest, Some(declaration.length))?;
            }
            Ok(())
        }
    }
}

// A source claim is retained only when its DATA is already available through
// the destination's eligible public catalog. Missing audit sources cause a
// refusal, never a private source probe or a fabricated disclosure boundary.
fn source(
    bodies: &Bodies,
    source: &EntrySource,
    dependencies: &mut Dependencies,
) -> Result<(), StoreFailure> {
    let commit = Commit::decode(require(bodies, IdentityKind::Commit, source.commit)?)
        .map_err(|_| corrupt())?;
    if commit.tree != source.root {
        return Err(corrupt());
    }
    require(bodies, IdentityKind::Node, source.root)?;
    dependencies.commits.insert(source.commit);
    Ok(())
}

fn origin(
    bodies: &Bodies,
    origin: &EntryOrigin,
    dependencies: &mut Dependencies,
) -> Result<(), StoreFailure> {
    match origin {
        EntryOrigin::Current => Ok(()),
        EntryOrigin::Source(previous) => source(bodies, previous, dependencies),
    }
}

fn entry(
    bodies: &Bodies,
    chunks: &Chunks,
    profile: &ChunkProfile,
    first: &Entry<'_>,
    pending: &mut Vec<(Digest, bool, bool)>,
    dependencies: &mut Dependencies,
) -> Result<(), StoreFailure> {
    let mut entries = vec![first];
    while let Some(entry) = entries.pop() {
        if let Some(producer) = entry.provenance {
            require(bodies, IdentityKind::Commit, producer)?;
            dependencies.commits.insert(producer);
        }
        for attribute in &entry.attrs {
            if matches!(&entry.kind, EntryKind::Index { .. })
                && attribute.name == terrane_format::indexing::carrier::OCCURRENCES_ATTRIBUTE
            {
                let mut decoder = terrane_format::cbor::Decoder::new(attribute.value);
                let root = decoder
                    .bytes(32)
                    .map_err(|_| corrupt())?
                    .try_into()
                    .map_err(|_| corrupt())?;
                decoder.finish().map_err(|_| corrupt())?;
                pending.push((root, true, true));
            }
            if attribute.name == "zstd-dictionary" {
                let value = AttributeValue::decode(AttributeName::ZstdDictionary, attribute.value)
                    .map_err(|_| corrupt())?;
                let AttributeValue::ZstdDictionary(hash) = value else {
                    return Err(corrupt());
                };
                chunk(chunks, hash, None)?;
                dependencies.objects.insert(hash);
            }
        }
        match &entry.kind {
            EntryKind::File {
                content: reference,
                size,
                ..
            } => content(bodies, chunks, profile, *reference, *size, dependencies)?,
            EntryKind::Tree { root, .. } => pending.push((*root, true, false)),
            EntryKind::Conflict { candidates, base } => {
                entries.extend(candidates);
                if let Some(Some(base)) = base {
                    entries.push(base);
                }
            }
            EntryKind::Index { targets } => {
                // Index target bytes do not select an identity domain or grant
                // proof authority. Preserve every already eligible occurrence.
                for target in targets {
                    dependencies.objects.insert(*target);
                    if !chunks.contains_key(target)
                        && !bodies.keys().any(|(_, hash)| hash == target)
                    {
                        return Err(unavailable());
                    }
                }
            }
            EntryKind::Directory { .. } | EntryKind::Symlink { .. } | EntryKind::Whiteout => {}
        }
    }
    Ok(())
}

fn tree(
    bodies: &Bodies,
    chunks: &Chunks,
    profile: &ChunkProfile,
    root: (Digest, bool),
    minimum: u64,
    visits: &mut BTreeSet<ExpandedObject>,
    dependencies: &mut Dependencies,
) -> Result<(), StoreFailure> {
    let (root, index) = root;
    let mut forests = vec![(root, true, index)];
    let mut seen = BTreeSet::new();
    while let Some((root, _, index)) = forests.pop() {
        if !seen.insert((root, index)) {
            continue;
        }
        let mut pending = vec![(root, true)];
        let mut leaves = Vec::new();
        while let Some((hash, is_root)) = pending.pop() {
            dependencies.objects.insert(hash);
            visits.insert(ExpandedObject {
                kind: 2,
                hash,
                flags: (u8::from(is_root) * 2) | (u8::from(index) * 4),
                proof_context: None,
            });
            let bytes = require(bodies, IdentityKind::Node, hash)?;
            let usage = if index {
                TreeUse::Index
            } else {
                TreeUse::Ordinary
            };
            let node = tree_format::decode_node_for(bytes, is_root, minimum, usage)
                .map_err(|_| corrupt())?;
            if let Some(properties) = &node.props {
                for property in properties {
                    if property.name == "index-roots" {
                        let bindings =
                            IndexRoots::decode_binding(property.value).map_err(|_| corrupt())?;
                        forests.extend(
                            bindings
                                .as_bindings()
                                .iter()
                                .map(|binding| (binding.node, true, true)),
                        );
                    }
                    if index && property.name == "index-gaps" {
                        let gap = terrane_format::indexing::carrier::GapBinding::decode_binding(
                            property.value,
                        )
                        .map_err(|_| corrupt())?;
                        forests.push((gap.node(), true, true));
                    }
                }
            }
            match &node.items {
                NodeItems::Internal(children) => {
                    for reference in children {
                        let child_bytes = require(bodies, IdentityKind::Node, reference.child)?;
                        let child =
                            tree_format::decode_node_for(child_bytes, false, minimum, usage)
                                .map_err(|_| corrupt())?;
                        tree_format::verify_child_ref_for(
                            node.level,
                            reference,
                            &child,
                            child_bytes,
                            minimum,
                            usage,
                        )
                        .map_err(|_| corrupt())?;
                    }
                    pending.extend(children.iter().rev().map(|child| (child.child, false)));
                }
                NodeItems::Leaf(items) => {
                    for item in items {
                        entry(
                            bodies,
                            chunks,
                            profile,
                            &item.entry,
                            &mut forests,
                            dependencies,
                        )?;
                    }
                    leaves.extend(items.iter().cloned());
                }
            }
        }
        tree_format::validate_tree_entries(
            &leaves,
            if index {
                TreeUse::Index
            } else {
                TreeUse::Ordinary
            },
        )
        .map_err(|_| corrupt())?;
    }
    Ok(())
}

/// Checks complete declared roots and side-record dependencies in eligible DATA.
///
/// Every retained Commit is traversed, including parents and introducing
/// provenance. No timestamp, foreign signature or missing trust input discards
/// a dependency. Chunk placement is checked against actual eligible index rows
/// and declared lengths without reading chunk bodies, as required by GC-9.
///
/// # Errors
/// Refuses missing typed dependencies, noncanonical metadata, invalid tree or
/// manifest structure, identity disagreements and unavailable eligible roots.
pub(super) fn check(
    bodies: &Bodies,
    chunks: &Chunks,
    roots: impl IntoIterator<Item = Digest>,
    profile: &ChunkProfile,
    minimum: u64,
) -> Result<Traversal, StoreFailure> {
    let mut objects = BTreeSet::new();
    let mut commits = Vec::new();
    objects.extend(chunks.keys().map(|hash| ExpandedObject {
        kind: 0,
        hash: *hash,
        flags: 0,
        proof_context: None,
    }));
    let mut dependencies = Dependencies::default();
    for root in roots {
        require(bodies, IdentityKind::Commit, root)?;
        dependencies.commits.insert(root);
    }
    let mut processed = BTreeSet::new();
    loop {
        let before = (dependencies.commits.len(), dependencies.objects.len());
        for ((kind, hash), bytes) in bodies {
            let kind = match *kind {
                kind if kind == IdentityKind::Commit as u8 => IdentityKind::Commit,
                kind if kind == IdentityKind::Node as u8 => IdentityKind::Node,
                kind if kind == IdentityKind::Manifest as u8 => IdentityKind::Manifest,
                kind if kind == IdentityKind::Attribute as u8 => IdentityKind::Attribute,
                kind if kind == IdentityKind::Memo as u8 => IdentityKind::Memo,
                kind if kind == IdentityKind::Index as u8 => IdentityKind::Index,
                kind if kind == IdentityKind::Bundle as u8 => IdentityKind::Bundle,
                kind if kind == IdentityKind::Policy as u8 => IdentityKind::Policy,
                kind if kind == IdentityKind::Filter as u8 => IdentityKind::Filter,
                _ => return Err(corrupt()),
            };
            let identity = TERRANE_V1.from_digest(kind, hash).map_err(|_| corrupt())?;
            TERRANE_V1.verify(&identity, bytes).map_err(|_| corrupt())?;
            let physical_kind = match kind {
                IdentityKind::Manifest => Some(1),
                IdentityKind::Bundle => Some(4),
                IdentityKind::Filter => Some(5),
                IdentityKind::Index => Some(6),
                IdentityKind::Attribute => Some(7),
                IdentityKind::Policy => Some(8),
                IdentityKind::Memo => Some(9),
                // Nodes carry their actual structural contexts; commits belong in
                // the separate unbounded expansion map rather than witness rows.
                IdentityKind::Node | IdentityKind::Commit => None,
                _ => return Err(corrupt()),
            };
            if let Some(kind) = physical_kind {
                objects.insert(ExpandedObject {
                    kind,
                    hash: *hash,
                    flags: 0,
                    proof_context: None,
                });
            }
            match kind {
                IdentityKind::Commit => {
                    let commit = Commit::decode(bytes).map_err(|_| corrupt())?;
                    if !dependencies.commits.contains(hash)
                        || !processed.insert((kind as u8, *hash))
                    {
                        continue;
                    }
                    dependencies.objects.insert(*hash);
                    commits.push(ExpandedContext {
                        commit: *hash,
                        parent_cutoff: ParentCutoff::Unbounded,
                        proof_context: None,
                    });
                    for parent in &commit.parents {
                        require(bodies, IdentityKind::Commit, *parent)?;
                        dependencies.commits.insert(*parent);
                    }
                    if let Some(receipts) = &commit.profile_pair.entry_receipts {
                        for receipt in receipts {
                            require(bodies, IdentityKind::Node, receipt.root)?;
                            origin(bodies, &receipt.origin, &mut dependencies)?;
                            if let Some(attributes) = &receipt.attributes {
                                for (_, introduction) in attributes {
                                    origin(bodies, introduction, &mut dependencies)?;
                                }
                            }
                            if let Some(previous) = &receipt.reintroduced_from {
                                source(bodies, previous, &mut dependencies)?;
                            }
                            // Disclosure signatures remain inline schema-checked
                            // claims. They grant no permission or pruning here.
                        }
                    }
                    if let Some(encoded) = &commit.profile_pair.recipe {
                        for root in recipe_roots(encoded)? {
                            tree(
                                bodies,
                                chunks,
                                profile,
                                (root, false),
                                minimum,
                                &mut objects,
                                &mut dependencies,
                            )?;
                        }
                    }
                    tree(
                        bodies,
                        chunks,
                        profile,
                        (commit.tree, false),
                        minimum,
                        &mut objects,
                        &mut dependencies,
                    )?;
                }
                IdentityKind::Manifest => {
                    // Canonical validation applies to all available metadata. Its
                    // content edges are expanded only at an actual file use.
                    Manifest::decode(bytes, profile).map_err(|_| corrupt())?;
                }
                IdentityKind::Attribute => {
                    let record = AttrRecord::decode(bytes).map_err(|_| corrupt())?;
                    // Sharing a reachable file digest does not select this
                    // side record or consume its private audit producer. Keep
                    // its canonical bytes and physical row regardless. Expand
                    // producer dependencies only for an actual declared use of
                    // this record identity; file dictionaries and signed entry
                    // attribute origins have their own explicit edges above.
                    if !dependencies.objects.contains(hash)
                        || !processed.insert((kind as u8, *hash))
                    {
                        continue;
                    }
                    require(bodies, IdentityKind::Commit, record.producer)?;
                    dependencies.commits.insert(record.producer);
                    if !chunks.contains_key(&record.object)
                        && !bodies.contains_key(&key(IdentityKind::Manifest, record.object))
                    {
                        return Err(unavailable());
                    }
                    if let AttributeValue::ZstdDictionary(dictionary) = record.value {
                        chunk(chunks, dictionary, None)?;
                        dependencies.objects.insert(dictionary);
                    }
                }
                IdentityKind::Memo => {
                    let memo =
                        terrane_format::derivation::Memo::decode(bytes).map_err(|_| corrupt())?;
                    if !dependencies.objects.contains(hash)
                        || !processed.insert((kind as u8, *hash))
                    {
                        continue;
                    }
                    // Memo does not encode a tree-use context. An actually
                    // consumed hint must match a root already expanded under
                    // its genuine ordinary/index use; it cannot reinterpret
                    // an index result as an ordinary tree or create authority.
                    if !objects.iter().any(|visit| {
                        visit.kind == 2 && visit.hash == memo.result_root() && visit.flags & 2 != 0
                    }) {
                        return Err(unavailable());
                    }
                }
                IdentityKind::Bundle => {
                    terrane_format::pack_format::decode_bundle(bytes).map_err(|_| corrupt())?;
                }
                IdentityKind::Node
                | IdentityKind::Index
                | IdentityKind::Policy
                | IdentityKind::Filter => {}
                _ => return Err(corrupt()),
            }
        }
        if before == (dependencies.commits.len(), dependencies.objects.len()) {
            break;
        }
    }
    commits.sort_by_key(|context| context.commit);
    let hashes: BTreeSet<_> = bodies
        .keys()
        .map(|(_, hash)| *hash)
        .chain(chunks.keys().copied())
        .collect();
    Ok(Traversal {
        commits,
        objects: objects.into_iter().collect(),
        hashes: hashes.into_iter().collect(),
    })
}
