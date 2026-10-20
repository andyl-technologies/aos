//! Projects scoped, currently authorized immutable views without leaking witnesses.

use std::collections::BTreeMap;

use terrane_format::{
    cbor,
    identity::Digest,
    provenance::Selector,
    surface::{TreeSchema, View, ViewTarget},
    tree_format::{self, EntryKind},
};

use crate::{
    guard::AuthorizedSnapshot,
    store::{Clock, LocalFs, Store},
};

use super::{Error, Repository, schema};

/// Owned canonical metadata and plaintext, with no identity lookup capability.
pub(crate) struct ReadEntry {
    /// Canonical entry key relative to the selected view subtree.
    pub(crate) key: Vec<u8>,
    /// Canonical core entry encoding authenticated by the selected snapshot.
    pub(crate) encoded: Vec<u8>,
    /// Original graft metadata, before checkout maps it to a directory.
    schema_graft: Option<Vec<u8>>,
    #[cfg(all(feature = "surface-sdk", unix))]
    /// Verified plaintext for files; absent for other entry kinds.
    pub(crate) plaintext: Option<Vec<u8>>,
}

#[cfg(all(feature = "surface-sdk", unix))]
/// Owns the scoped checkout projection of one currently authorized snapshot.
pub(crate) struct ReadView {
    /// Exact immutable commit that supplied the projected entries.
    pub(crate) commit: Digest,
    /// Configured minimum chunk size used to decode canonical entry metadata.
    pub(crate) minimum: u64,
    /// Scoped entries with verified file plaintext and relative keys.
    pub(crate) entries: Vec<ReadEntry>,
}

/// Retains repository-owned authority and metadata until exact-snapshot presentation.
///
/// Surfaces cannot inspect history, credentials or storage witnesses through it.
#[cfg_attr(
    not(all(feature = "surface-sdk", unix)),
    allow(
        dead_code,
        reason = "Targets without the native SDK cannot consume opaque presentation preparations."
    )
)]
pub(crate) struct PreparedView {
    snapshot: AuthorizedSnapshot,
    entries: Vec<ReadEntry>,
    commit: Digest,
    minimum: u64,
}

impl<S, C, F> Repository<S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    /// Validates a resolved view's schema using authorized metadata only.
    ///
    /// Returned properties are canonical allowed values equivalent to the
    /// effective recorded policy; private history and backend access stay here.
    ///
    /// # Errors
    /// Rejects authorization, policy, subtree and schema failures before any
    /// object plaintext is requested.
    pub async fn validate_view_schema(
        &self,
        view: &View,
        token: &[u8],
        surface: &str,
        schema: &TreeSchema,
    ) -> Result<schema::ViewMetadata, Error> {
        Ok(self
            .prepare_schema_metadata(view, token, surface, schema)
            .await?
            .1)
    }

    /// Retains the original authority binding alongside the validated commit.
    pub(crate) async fn prepare_view_schema(
        &self,
        view: &View,
        token: &[u8],
        surface: &str,
        schema: &TreeSchema,
    ) -> Result<PreparedView, Error> {
        Ok(self
            .prepare_schema_metadata(view, token, surface, schema)
            .await?
            .0)
    }

    /// Builds the public projection while retaining private authority separately.
    async fn prepare_schema_metadata(
        &self,
        view: &View,
        token: &[u8],
        surface: &str,
        schema: &TreeSchema,
    ) -> Result<(PreparedView, schema::ViewMetadata), Error> {
        let (snapshot, entries) = self.metadata(view, token, surface).await?;
        let minimum = self.chunk_profile().minimum() as u64;
        let mut path = b"/".to_vec();
        path.extend_from_slice(&view.subtree);
        let occurrences = snapshot.evidence.occurrences(minimum)?;
        let occurrence = occurrences
            .iter()
            .filter(|occurrence| {
                path == occurrence.path
                    || path
                        .strip_prefix(occurrence.path.as_slice())
                        .is_some_and(|suffix| occurrence.path == b"/" || suffix.starts_with(b"/"))
            })
            .max_by_key(|occurrence| occurrence.path.len())
            .ok_or(Error::Absent)?;
        let layers = occurrence
            .layers
            .iter()
            .map(
                |(properties, overrides)| terrane_format::properties::RootLayer {
                    properties,
                    overrides,
                },
            )
            .collect::<Vec<_>>();
        let guard = self.coordinator.guard();
        let effective = snapshot
            .interpretation
            .resolve(&layers, guard.defaults_for(&snapshot.evidence))?;
        let mut properties = Vec::new();
        for (name, allowed) in &schema.required_properties {
            let mut matched = None;
            for value in allowed {
                let property = tree_format::Property { name, value };
                let (key, candidate) = terrane_format::properties::validate_property(&property)
                    .map_err(|_| Error::Schema)?;
                if effective.get(key) == Some(&candidate) {
                    matched = Some(value.clone());
                    break;
                }
            }
            properties.push((name.clone(), matched.ok_or(Error::Schema)?));
        }
        let root_attributes = if view.subtree.is_empty() {
            Vec::new()
        } else {
            let (location, _) = snapshot
                .history
                .locate(snapshot.commit.identity(), &view.subtree)
                .map_err(|_| Error::Absent)?;
            snapshot
                .history
                .entry(&location)
                .map_err(|_| Error::Absent)?
                .attrs
                .iter()
                .map(|attribute| (attribute.name.to_owned(), attribute.value.to_vec()))
                .collect()
        };
        let metadata = schema::ViewMetadata {
            commit: snapshot.commit.identity(),
            minimum_chunk_size: minimum,
            entries: entries
                .iter()
                .map(|entry| {
                    (
                        entry.key.clone(),
                        entry
                            .schema_graft
                            .as_ref()
                            .unwrap_or(&entry.encoded)
                            .clone(),
                    )
                })
                .collect(),
            root_attributes,
            properties,
        };
        schema::validate_schema(schema, &metadata)?;
        drop(effective);
        drop(layers);
        drop(occurrences);
        Ok((
            PreparedView {
                commit: metadata.commit,
                minimum: metadata.minimum_chunk_size,
                snapshot,
                entries,
            },
            metadata,
        ))
    }

    /// Reads one authenticated file under the view's current authority.
    ///
    /// The returned identity is the exact immutable commit that supplied the
    /// plaintext. Scope, live ACL, capability, and provenance trust checks
    /// precede content access; no sibling entry or history witness is returned.
    ///
    /// # Errors
    /// Rejects invalid keys, unknown policies, absent or untrusted files,
    /// insufficient current authority, and failed verified object reads.
    pub async fn read_file(
        &self,
        view: &View,
        path: &[u8],
        token: &[u8],
        surface: &str,
    ) -> Result<(Digest, Vec<u8>), Error> {
        tree_format::validate_key(path)?;
        if view.policy.is_some() {
            return Err(Error::UnavailableOperation("unregistered view policy"));
        }
        let mut relative = view.subtree.clone();
        if !relative.is_empty() {
            relative.push(b'/');
        }
        relative.extend_from_slice(path);
        let absolute = absolute_path(b"/", &relative);
        let guard = self.coordinator.guard();
        let snapshot = match &view.target {
            ViewTarget::Ref(reference) => {
                guard
                    .read_snapshot(reference.as_str(), token, &absolute, surface)
                    .await?
            }
            ViewTarget::Commit(identity) => {
                guard
                    .read_commit_snapshot(*identity, token, &absolute, surface)
                    .await?
            }
        };
        let (content, size) = {
            let mut any = Vec::new();
            cbor::write_text(&mut any, "any");
            let selector = Selector::from_property(&any).map_err(|_| Error::Denied)?;
            let trust = snapshot
                .interpretation
                .evaluator(
                    &snapshot.history,
                    (snapshot.commit.identity(), snapshot.evidence.root),
                    selector,
                    &snapshot.storage_domain,
                    None,
                )
                .map_err(|_| Error::Denied)?;
            if !trust.accepts_path(&relative) {
                return Err(Error::Absent);
            }
            let (location, _) = snapshot
                .history
                .locate(snapshot.commit.identity(), &relative)
                .map_err(|_| Error::Absent)?;
            match snapshot
                .history
                .entry(&location)
                .map_err(|_| Error::Absent)?
                .kind
            {
                EntryKind::File { content, size, .. } => (content, size),
                _ => return Err(Error::Unrealizable),
            }
        };
        let bytes = guard
            .read_content(&snapshot, &absolute, content, size)
            .await?;
        Ok((snapshot.commit.identity(), bytes))
    }

    #[cfg(all(test, feature = "surface-sdk", unix))]
    /// Reads scoped metadata and file plaintext under current view authority.
    ///
    /// # Errors
    /// Rejects unregistered policies, unauthenticated or unauthorized metadata,
    /// malformed entries, and failed verified content reads.
    pub(crate) async fn read_view(
        &self,
        view: &View,
        token: &[u8],
        surface: &str,
    ) -> Result<ReadView, Error> {
        let prepared = self
            .prepare_view_schema(view, token, surface, &TreeSchema::default())
            .await?;
        self.read_prepared_view(prepared).await
    }

    #[cfg(all(feature = "surface-sdk", unix))]
    /// Requests plaintext only after rechecking the original selected authority.
    pub(crate) async fn read_prepared_view(
        &self,
        prepared: PreparedView,
    ) -> Result<ReadView, Error> {
        let PreparedView {
            snapshot,
            mut entries,
            commit,
            minimum,
        } = prepared;
        let guard = self.coordinator.guard();
        for item in &entries {
            let path = absolute_path(&snapshot.scope, &item.key);
            guard.authorize_snapshot_path(&snapshot, &path).await?;
        }
        for item in &mut entries {
            let full_path = absolute_path(&snapshot.scope, &item.key);
            let entry = tree_format::decode_entry_bytes(&item.encoded, minimum)?;
            if let EntryKind::File { content, size, .. } = entry.kind {
                item.plaintext = Some(
                    guard
                        .read_content(&snapshot, &full_path, content, size)
                        .await?,
                );
            }
        }
        // An empty tree still requires a fresh current-authority check.
        guard
            .authorize_snapshot_path(&snapshot, &snapshot.scope)
            .await?;
        Ok(ReadView {
            commit,
            minimum,
            entries,
        })
    }

    /// Projects scoped canonical entries and retains their authorized snapshot.
    ///
    /// # Errors
    /// Rejects unregistered policies, invalid or untrusted snapshots and entries,
    /// and insufficient current authority for any projected path.
    pub(super) async fn metadata(
        &self,
        view: &View,
        token: &[u8],
        surface: &str,
    ) -> Result<(AuthorizedSnapshot, Vec<ReadEntry>), Error> {
        if view.policy.is_some() {
            return Err(Error::UnavailableOperation("unregistered view policy"));
        }
        let mut scope = b"/".to_vec();
        scope.extend_from_slice(&view.subtree);
        let guard = self.coordinator.guard();
        let snapshot = match &view.target {
            ViewTarget::Ref(reference) => {
                guard
                    .read_snapshot(reference.as_str(), token, &scope, surface)
                    .await?
            }
            ViewTarget::Commit(identity) => {
                guard
                    .read_commit_snapshot(*identity, token, &scope, surface)
                    .await?
            }
        };
        let minimum = self.chunk_profile().minimum() as u64;

        // Rc-backed trees and trust evaluators exist only inside projection;
        // all following awaited operations retain exclusively owned bytes.
        let entries = project(&snapshot, minimum, &view.subtree)?;
        for item in &entries {
            let full_path = absolute_path(&scope, &item.key);
            guard.authorize_snapshot_path(&snapshot, &full_path).await?;
        }
        Ok((snapshot, entries))
    }
}

fn absolute_path(scope: &[u8], key: &[u8]) -> Vec<u8> {
    let mut path = scope.to_vec();
    if path != b"/" {
        path.push(b'/');
    }
    path.extend_from_slice(key);
    path
}

fn within(path: &[u8], parent: &[u8]) -> bool {
    parent.is_empty()
        || path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn project(
    snapshot: &AuthorizedSnapshot,
    minimum: u64,
    scope: &[u8],
) -> Result<Vec<ReadEntry>, Error> {
    let mut any = Vec::new();
    cbor::write_text(&mut any, "any");
    let selector = Selector::from_property(&any).map_err(|_| Error::Denied)?;
    let trust = snapshot
        .interpretation
        .evaluator(
            &snapshot.history,
            (snapshot.commit.identity(), snapshot.evidence.root),
            selector,
            &snapshot.storage_domain,
            None,
        )
        .map_err(|_| Error::Denied)?;
    let mut pending = vec![(snapshot.evidence.root, Vec::new(), Vec::new())];
    let mut output = Vec::new();
    let mut link_groups = BTreeMap::new();
    let mut hidden = Vec::new();
    let mut found_scope = scope.is_empty();

    while let Some((root, prefix, mut ancestors)) = pending.pop() {
        if ancestors.contains(&root) || ancestors.len() > tree_format::MAX_GRAFT_DEPTH {
            return Err(Error::Unrealizable);
        }
        ancestors.push(root);
        let tree = snapshot.evidence.tree(root, minimum)?;
        for item in tree.iter() {
            let mut full = prefix.clone();
            if !full.is_empty() {
                full.push(b'/');
            }
            full.extend_from_slice(&item.key);
            if !(within(&full, scope) || within(scope, &full))
                || hidden.iter().any(|path: &Vec<u8>| within(&full, path))
            {
                continue;
            }
            if !trust.accepts_path(&full) {
                hidden.push(full);
                continue;
            }
            let mut entry = item.entry.clone();
            let schema_graft = if matches!(&entry.kind, EntryKind::Tree { .. }) {
                Some(tree_format::encode_entry(&entry, minimum)?)
            } else {
                None
            };
            if let EntryKind::Tree { root, .. } = &entry.kind {
                pending.push((*root, full.clone(), ancestors.clone()));
                // A graft has no source inode or permission field. Its virtual
                // checkout directory uses private mode0700; stored root and
                // override properties remain in the guarded evidence.
                entry.kind = EntryKind::Directory { mode: 0o700 };
            }
            if full == scope {
                if !matches!(entry.kind, EntryKind::Directory { .. }) {
                    return Err(Error::Unrealizable);
                }
                found_scope = true;
                continue;
            }
            if !within(&full, scope) {
                continue;
            }
            let relative = if scope.is_empty() {
                full
            } else {
                full.strip_prefix(scope)
                    .and_then(|suffix| suffix.strip_prefix(b"/"))
                    .ok_or(Error::PathEscape)?
                    .to_vec()
            };
            match &entry.kind {
                EntryKind::File {
                    link_id: Some(first),
                    ..
                } => {
                    link_groups.insert(relative.clone(), (root, first.to_vec()));
                }
                EntryKind::File { .. }
                | EntryKind::Directory { .. }
                | EntryKind::Symlink { .. } => {}
                _ => return Err(Error::Unrealizable),
            }
            output.push(ReadEntry {
                key: relative,
                schema_graft,
                encoded: tree_format::encode_entry(&entry, minimum)?,
                #[cfg(all(feature = "surface-sdk", unix))]
                plaintext: None,
            });
        }
    }
    if !found_scope {
        return Err(Error::Absent);
    }
    output.sort_by(|left, right| left.key.cmp(&right.key));

    // Link IDs reveal only the first key inside the presented subtree, never
    // an original sibling key or the same path in an unexposed graft root.
    let mut first_keys = BTreeMap::new();
    for item in &mut output {
        if let Some(group) = link_groups.get(&item.key) {
            let first = first_keys
                .entry(group.clone())
                .or_insert_with(|| item.key.clone());
            let encoded = {
                let mut entry = tree_format::decode_entry_bytes(&item.encoded, minimum)?;
                if let EntryKind::File { link_id, .. } = &mut entry.kind {
                    *link_id = Some(first.as_slice());
                }
                tree_format::encode_entry(&entry, minimum)?
            };
            item.encoded = encoded;
        }
    }
    let mut links = BTreeMap::new();
    for item in &output {
        let entry = tree_format::decode_entry_bytes(&item.encoded, minimum)?;
        if let EntryKind::Symlink { target } = entry.kind {
            links.insert(item.key.clone(), target.to_vec());
        }
    }
    super::path::validate_symlink_targets(&links)?;
    Ok(output)
}

#[cfg(all(test, feature = "tokio", feature = "surface-sdk", unix))]
#[path = "read/schema_tests.rs"]
mod schema_tests;
