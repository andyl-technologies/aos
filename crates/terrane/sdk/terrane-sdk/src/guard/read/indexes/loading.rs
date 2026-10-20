//! Loads and verifies immutable discovery inputs without authorizing their rows.

use super::{IndexLookupError, IndexLookupMethod, IndexLookupWork, count};
use crate::guard::read::AuthorizedSnapshot;
use crate::indexing;
use crate::store::ContentStore;
use terrane_format::gc::publication::evidence::ConfiguredRegistryInputs;
use terrane_format::identity::Digest;
use terrane_format::indexing::{IndexKey, lookup};
use terrane_format::tree_format::{ContentRef, EntryKind};

/// Owns an actual file observation after all borrowed source trees are dropped.
pub(super) struct Row {
    /// Actual composed absolute path exported from the immutable local route.
    pub(super) path: Vec<u8>,
    /// Actual namespace root reached by this occurrence, not a route back-reference.
    pub(super) source_root: Digest,
    /// Exact tagged content identity from the independently verified source entry.
    pub(super) content: ContentRef,
    /// Canonical source file declaration.
    pub(super) size: u64,
    /// Exact canonical inline bytes, or independently verified absence.
    pub(super) value: Option<Vec<u8>>,
}

impl Row {
    /// Returns the object target of the actual tagged content reference.
    pub(super) fn object(&self) -> Digest {
        match self.content {
            ContentRef::Inline(object) | ContentRef::Manifest(object) => object,
        }
    }
}

/// Separates ordinary discovery rows from eventual live authorization.
pub(super) struct Discovery {
    /// Actual matching occurrences, which have not passed current checks.
    pub(super) present: Vec<Row>,
    /// Actual missing-value occurrences, independently of the equality range.
    pub(super) missing: Vec<Row>,
    /// Real immutable stage counters; current checks populate their own field.
    pub(super) work: IndexLookupWork,
    /// Discovery method actually executed.
    pub(super) method: IndexLookupMethod,
}

/// Acquires complete immutable inputs and executes indexed discovery or explicit fallback.
///
/// # Errors
/// Preserves exact loader/relationship failures; only MissingBinding selects fallback.
pub(super) async fn discover<S: ContentStore>(
    store: &S,
    snapshot: &AuthorizedSnapshot,
    attribute: &str,
    value: &[u8],
    profile: &ConfiguredRegistryInputs,
    minimum: u64,
    fallback: bool,
) -> Result<Discovery, IndexLookupError> {
    let revisions = indexing::SemanticRevisions {
        property: profile.property_revision,
        attribute: profile.attribute_revision,
        tree: profile.tree_revision,
    };
    let loaded =
        match indexing::load(store, snapshot.evidence.root, attribute, revisions, minimum).await {
            Ok(loaded) => loaded,
            Err(indexing::Error::MissingBinding(_)) if fallback => {
                return walk(store, snapshot, attribute, value, revisions, minimum).await;
            }
            Err(error) => return Err(error.into()),
        };
    let sources = loaded.sources()?;
    let prepared = loaded.prepare(&sources.trees)?;
    let candidates = prepared.candidates(value)?;
    let gaps = prepared.all_missing()?;
    let mut work = IndexLookupWork {
        loading: loaded.loading(),
        reconstruction: sources.work,
        preparation: Some(prepared.preparation().clone()),
        candidates: candidates.work,
        present_routes: Vec::new(),
        gaps: gaps.work,
        missing_routes: Vec::new(),
        walked_files: 0,
        current: Default::default(),
    };
    let mut present = Vec::new();
    for candidate in candidates.rows {
        let occurrences = candidate.occurrences()?;
        work.present_routes.push(occurrences.work);
        for occurrence in occurrences.rows {
            present.push(export(occurrence)?);
        }
    }
    let mut missing = Vec::new();
    for gap in gaps.rows {
        let occurrences = gap.occurrences()?;
        work.missing_routes.push(occurrences.work);
        for occurrence in occurrences.rows {
            missing.push(export(occurrence)?);
        }
    }
    Ok(Discovery {
        present,
        missing,
        work,
        method: IndexLookupMethod::Index,
    })
}

fn export(occurrence: lookup::Occurrence<'_, '_>) -> Result<Row, IndexLookupError> {
    let mut path = b"/".to_vec();
    for hop in &occurrence.hops {
        append(&mut path, &hop.key)?;
    }
    append(&mut path, &occurrence.key)?;
    Ok(Row {
        path,
        source_root: occurrence.source_root,
        content: occurrence.content,
        size: occurrence.size,
        value: occurrence.value.map(<[u8]>::to_vec),
    })
}

/// Appends an actual local key while respecting the existing public path bound.
///
/// # Errors
/// Refuses an invalid composed request path instead of changing its limit.
pub(super) fn append(path: &mut Vec<u8>, key: &[u8]) -> Result<(), IndexLookupError> {
    if path != b"/" {
        path.push(b'/');
    }
    path.extend_from_slice(key);
    // Ordinary policy_path uses this same registered full request-key validator.
    terrane_format::tree_format::validate_key(&path[1..])
        .map_err(terrane_format::indexing::evaluation::Error::from)?;
    Ok(())
}

async fn walk<S: ContentStore>(
    store: &S,
    snapshot: &AuthorizedSnapshot,
    attribute: &str,
    value: &[u8],
    revisions: indexing::SemanticRevisions,
    minimum: u64,
) -> Result<Discovery, IndexLookupError> {
    // Match the pure candidate value preflight; no equality is inferred from absence.
    if let Ok(name) = terrane_format::derived::AttributeName::parse(attribute) {
        terrane_format::derived::AttributeValue::decode(name, value)
            .map_err(terrane_format::indexing::evaluation::Error::from)?;
    }
    IndexKey::new(value, [0; 32]).map_err(terrane_format::indexing::evaluation::Error::from)?;
    let loaded = indexing::load_source(store, snapshot.evidence.root, revisions, minimum).await?;
    let sources = loaded.sources()?;
    let mut work = IndexLookupWork {
        loading: loaded.loading(),
        reconstruction: sources.work,
        preparation: None,
        candidates: Default::default(),
        present_routes: Vec::new(),
        gaps: Default::default(),
        missing_routes: Vec::new(),
        walked_files: 0,
        current: Default::default(),
    };
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for occurrence in snapshot.evidence.occurrences(minimum)? {
        let tree = sources
            .trees
            .get(&occurrence.root)
            .ok_or(crate::guard::invalid())?;
        for item in tree.iter() {
            let EntryKind::File { content, size, .. } = &item.entry.kind else {
                continue;
            };
            count(&mut work.walked_files, 1)?;
            let actual = item
                .entry
                .attrs
                .iter()
                .find(|entry| entry.name == attribute);
            if actual.is_some_and(|entry| entry.value != value) {
                continue;
            }
            let mut path = occurrence.path.clone();
            append(&mut path, &item.key)?;
            let row = Row {
                path,
                source_root: occurrence.root,
                content: *content,
                size: *size,
                value: actual.map(|entry| entry.value.to_vec()),
            };
            if actual.is_some() {
                present.push(row);
            } else {
                missing.push(row);
            }
        }
    }
    Ok(Discovery {
        present,
        missing,
        work,
        method: IndexLookupMethod::Walk,
    })
}
