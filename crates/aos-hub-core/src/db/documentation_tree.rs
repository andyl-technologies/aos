//! Bounded configuration-tree browsing and indexed release-scoped search.
//!
//! Node identities hash typed path segments, so an attribute containing a dot
//! cannot be mistaken for two attributes. Immediate children and search results
//! use keyset cursors bound to the registry, source commit, and query. A cursor
//! never continues into a replacement release generation.

mod indexing;
pub(super) use indexing::extend_tree_projection;

use anyhow::{ensure, Result};
use aos_doc_model::PathSegment;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::Database;

/// Maximum immediate children, variants, or search results in one response.
pub const DOCUMENTATION_TREE_PAGE_SIZE: usize = 50;

/// One configuration path and the counts needed to browse it lazily.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentationTreeNode {
    /// Stable hash of the complete typed path.
    pub key: String,
    /// Exact literal and dynamic segments from the documentation schema.
    pub path: Vec<PathSegment>,
    /// Label of this path's final segment.
    pub label: String,
    /// Number of immediate child nodes, without descendants.
    pub child_count: usize,
    /// Number of exact documented variants at this path.
    pub entry_count: usize,
    /// Kind of the representative documented variant, absent for pure branches.
    pub kind: Option<String>,
    /// Human-readable option type of the representative variant.
    pub type_signature: Option<String>,
    /// Bounded plain-text description of the representative variant.
    pub summary: Option<String>,
    #[serde(skip)]
    sort_key: String,
}

/// One exact option or documentation search result.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentationTreeEntry {
    /// Immutable entry identity used to choose an exact documented variant.
    pub key: String,
    /// Configuration node, absent for guides and runtime documentation.
    pub node_key: Option<String>,
    /// Digest of the exact source document.
    pub document_sha256: String,
    /// Package that published the documentation.
    pub package_name: String,
    /// Exact package version.
    pub package_version: String,
    /// Exact package platform.
    pub platform: String,
    /// Kind: option, package, service, credential, or capability.
    pub kind: String,
    /// Stable key inside the document.
    pub document_key: String,
    /// Human-readable result title.
    pub title: String,
    /// Bounded plain-text description.
    pub summary: String,
    /// Human-readable option type, absent for other entry kinds.
    pub type_signature: Option<String>,
    /// Deterministic search rank; zero outside search responses.
    pub score: i64,
}

/// A bounded page with an opaque continuation cursor.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentationTreePage<T> {
    /// Only the requested immediate children or search results.
    pub items: Vec<T>,
    /// Cursor for the next page, absent at the end of the result set.
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    scope: String,
    sort: String,
    key: String,
    score: i64,
}

fn cursor_scope(registry_id: i64, commit: &str, selection: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(registry_id.to_be_bytes());
    digest.update(commit.as_bytes());
    digest.update([0]);
    digest.update(selection.as_bytes());
    hex::encode(digest.finalize())
}

/// An invalid or stale browser query, safe to describe to the reader.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct InvalidDocumentationQuery(pub(crate) &'static str);

fn decode_cursor(encoded: Option<&str>, scope: &str) -> Result<Option<Cursor>> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let invalid = || {
        InvalidDocumentationQuery(
            "The documentation cursor is invalid. Open the subtree again to start a new page.",
        )
    };
    if encoded.len() > 4096 {
        return Err(invalid().into());
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?;
    let cursor: Cursor = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if cursor.scope != scope {
        return Err(InvalidDocumentationQuery("This page belongs to a different release or search. Open the subtree again to continue.").into());
    }
    if cursor.key.len() != 64 || !cursor.key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid().into());
    }
    Ok(Some(cursor))
}

fn encode_cursor(cursor: Cursor) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor)?))
}

/// Returns a stable node identity for a complete typed configuration path.
#[must_use]
pub fn documentation_node_key(path: &[PathSegment]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aos.documentation.path/v1");
    for segment in path {
        let (kind, value) = match segment {
            PathSegment::Literal { value } => (0u8, value),
            PathSegment::Wildcard { name } => (1u8, name),
        };
        hash.update([kind]);
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hex::encode(hash.finalize())
}

/// Returns the exact identity of an entry within an immutable document.
///
/// # Errors
/// Returns an error if the identity cannot be serialized.
pub fn documentation_entry_key(digest: &str, kind: &str, key: &str) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        digest, kind, key,
    ))?)))
}

/// Returns the human label of one exact or dynamic path segment.
#[must_use]
pub fn path_segment_label(segment: &PathSegment) -> String {
    match segment {
        PathSegment::Literal { value } => value.clone(),
        PathSegment::Wildcard { name } => format!("<{name}>"),
    }
}

fn search_token(term: &str) -> String {
    term.chars().take(128).collect()
}

// Every node read carries one representative documented variant so listings can
// show a type and description without a second round trip. The variant index
// makes each correlated lookup a bounded seek; the smallest entry key wins so
// the representative is stable across pages and releases.
const NODE_COLUMNS: &str = "node.node_key, node.path_json, node.label, node.child_count, node.entry_count, node.sort_key,
    (SELECT entry.kind FROM release_browse_tree_entries entry WHERE entry.registry_id = node.registry_id
       AND entry.source_commit = node.source_commit AND entry.node_key = node.node_key ORDER BY entry.entry_key LIMIT 1),
    (SELECT entry.type_signature FROM release_browse_tree_entries entry WHERE entry.registry_id = node.registry_id
       AND entry.source_commit = node.source_commit AND entry.node_key = node.node_key ORDER BY entry.entry_key LIMIT 1),
    (SELECT entry.summary FROM release_browse_tree_entries entry WHERE entry.registry_id = node.registry_id
       AND entry.source_commit = node.source_commit AND entry.node_key = node.node_key ORDER BY entry.entry_key LIMIT 1)";
const ENTRY_COLUMNS: &str = "entry_key, node_key, document_sha256, package_name, package_version,
    platform, kind, document_key, title, summary, type_signature";

impl Database {
    /// Resolves a release to the source commit of its completed browse catalog.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed row values.
    pub async fn documentation_tree_commit(
        &self,
        registry_id: i64,
        release: &str,
    ) -> Result<Option<String>> {
        self.backend.query_opt(
            "SELECT rel.commit_oid FROM releases rel JOIN release_browse_catalogs catalog
               ON catalog.registry_id = rel.registry_id AND catalog.source_commit = rel.commit_oid
             JOIN release_artifact_snapshot_heads head
               ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot
               ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
              AND snapshot.registry_id = rel.registry_id AND snapshot.release_id = rel.id
              AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid
              AND snapshot.state = 'complete'
             WHERE rel.registry_id = ?1 AND rel.semver = ?2",
            &vals![registry_id, release],
        ).await?.map(|row| row.get(0)).transpose()
    }

    /// Finds a published release containing an exact documentation object.
    ///
    /// This supports historical human links that predate release query values.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed release metadata.
    pub async fn documentation_release_for_digest(
        &self,
        registry_id: i64,
        digest: &str,
    ) -> Result<Option<String>> {
        self.backend.query_opt(
            "SELECT rel.semver FROM releases rel
             JOIN release_browse_tree_entries entry
               ON entry.registry_id = rel.registry_id AND entry.source_commit = rel.commit_oid
             JOIN release_artifact_snapshot_heads head ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
               AND snapshot.registry_id = rel.registry_id AND snapshot.release_id = rel.id
               AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid AND snapshot.state = 'complete'
             WHERE rel.registry_id = ?1 AND entry.document_sha256 = ?2
             ORDER BY rel.tagged_at DESC, rel.semver DESC LIMIT 1", &vals![registry_id, digest],
        ).await?.map(|row| row.get(0)).transpose()
    }

    /// Finds published releases containing an exact legacy documentation selection.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed release metadata.
    pub async fn documentation_releases_for_package(
        &self,
        registry_id: i64,
        package: &str,
        version: &str,
        platform: &str,
    ) -> Result<Vec<String>> {
        self.backend.query(
            "SELECT rel.semver FROM releases rel
             JOIN release_artifact_snapshot_heads head ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
               AND snapshot.registry_id = rel.registry_id AND snapshot.release_id = rel.id
               AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid AND snapshot.state = 'complete'
             JOIN release_package_documentation document ON document.registry_id = rel.registry_id
               AND document.release_id = rel.id AND document.snapshot_id = snapshot.snapshot_id
             WHERE rel.registry_id = ?1 AND document.package_name = ?2 AND document.package_version = ?3 AND document.platform = ?4",
            &vals![registry_id, package, version, platform],
        ).await?.into_iter().map(|row| row.get(0)).collect()
    }

    /// Loads one node without expanding any children.
    ///
    /// Callers resolve `commit` through [`Database::documentation_tree_commit`]
    /// after authorizing the registry. The commit pins the entire request.
    ///
    /// # Errors
    /// Returns an error on database failure or invalid path metadata.
    pub async fn documentation_tree_node(
        &self,
        registry_id: i64,
        commit: &str,
        key: &str,
    ) -> Result<Option<DocumentationTreeNode>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {NODE_COLUMNS} FROM release_browse_tree_nodes node
            WHERE node.registry_id = ?1 AND node.source_commit = ?2 AND node.node_key = ?3"
                ),
                &vals![registry_id, commit, key],
            )
            .await?
            .map(node_from_row)
            .transpose()
    }

    /// Lists one bounded page of a node's immediate children.
    ///
    /// # Errors
    /// Returns an error for invalid or stale cursors, database failures, or
    /// malformed indexed rows.
    pub async fn documentation_tree_children(
        &self,
        registry_id: i64,
        commit: &str,
        parent: &str,
        after: Option<&str>,
    ) -> Result<DocumentationTreePage<DocumentationTreeNode>> {
        let scope = cursor_scope(registry_id, commit, &format!("children:{parent}"));
        let cursor = decode_cursor(after, &scope)?;
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {NODE_COLUMNS} FROM release_browse_tree_nodes node
            WHERE node.registry_id = ?1 AND node.source_commit = ?2 AND node.parent_key = ?3
              AND (?4 IS NULL OR node.sort_key > ?4 OR (node.sort_key = ?4 AND node.node_key > ?5))
            ORDER BY node.sort_key, node.node_key LIMIT ?6"
                ),
                &vals![
                    registry_id,
                    commit,
                    parent,
                    cursor.as_ref().map(|cursor| cursor.sort.as_str()),
                    cursor.as_ref().map(|cursor| cursor.key.as_str()),
                    (DOCUMENTATION_TREE_PAGE_SIZE + 1) as i64
                ],
            )
            .await?;
        let mut items = rows
            .into_iter()
            .map(node_from_row)
            .collect::<Result<Vec<_>>>()?;
        let has_more = items.len() > DOCUMENTATION_TREE_PAGE_SIZE;
        items.truncate(DOCUMENTATION_TREE_PAGE_SIZE);
        let next_cursor = if has_more {
            items
                .last()
                .map(|node| {
                    encode_cursor(Cursor {
                        scope,
                        sort: node.sort_key.clone(),
                        key: node.key.clone(),
                        score: 0,
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok(DocumentationTreePage { items, next_cursor })
    }

    /// Lists one bounded page of every documented option beneath a node.
    ///
    /// The listing flattens the subtree: pure branches are skipped and each
    /// documented path appears once, in dotted-path order, regardless of depth.
    /// The root itself is included when it is documented. Ancestry comes from
    /// the precomputed table, so the query stays indexed at any depth.
    ///
    /// # Errors
    /// Returns an error for invalid or stale cursors, database failures, or
    /// malformed indexed rows.
    pub async fn documentation_tree_descendants(
        &self,
        registry_id: i64,
        commit: &str,
        root: &str,
        after: Option<&str>,
    ) -> Result<DocumentationTreePage<DocumentationTreeNode>> {
        let scope = cursor_scope(registry_id, commit, &format!("descendants:{root}"));
        let cursor = decode_cursor(after, &scope)?;
        // Ordering by the serialized path keeps each subtree contiguous and its
        // siblings in label order; a documented branch sorts after its own
        // descendants because the closing bracket outranks a continuing comma.
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {NODE_COLUMNS} FROM release_browse_tree_ancestors ancestor
            JOIN release_browse_tree_nodes node
              ON node.registry_id = ancestor.registry_id AND node.source_commit = ancestor.source_commit
             AND node.node_key = ancestor.node_key
            WHERE ancestor.registry_id = ?1 AND ancestor.source_commit = ?2 AND ancestor.ancestor_key = ?3
              AND node.entry_count > 0
              AND (?4 IS NULL OR node.path_json > ?4 OR (node.path_json = ?4 AND node.node_key > ?5))
            ORDER BY node.path_json, node.node_key LIMIT ?6"
                ),
                &vals![
                    registry_id,
                    commit,
                    root,
                    cursor.as_ref().map(|cursor| cursor.sort.as_str()),
                    cursor.as_ref().map(|cursor| cursor.key.as_str()),
                    (DOCUMENTATION_TREE_PAGE_SIZE + 1) as i64
                ],
            )
            .await?;
        let mut items = rows
            .into_iter()
            .map(node_from_row)
            .collect::<Result<Vec<_>>>()?;
        let has_more = items.len() > DOCUMENTATION_TREE_PAGE_SIZE;
        items.truncate(DOCUMENTATION_TREE_PAGE_SIZE);
        let next_cursor = if has_more {
            items
                .last()
                .map(|node| {
                    encode_cursor(Cursor {
                        scope,
                        sort: serde_json::to_string(&node.path)?,
                        key: node.key.clone(),
                        score: 0,
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok(DocumentationTreePage { items, next_cursor })
    }

    /// Lists a bounded page of documented package/platform variants at one node.
    ///
    /// # Errors
    /// Returns an error on stale cursors, database failure, or malformed rows.
    pub async fn documentation_tree_variants(
        &self,
        registry_id: i64,
        commit: &str,
        node: &str,
        after: Option<&str>,
    ) -> Result<DocumentationTreePage<DocumentationTreeEntry>> {
        let scope = cursor_scope(registry_id, commit, &format!("variants:{node}"));
        let cursor = decode_cursor(after, &scope)?;
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {ENTRY_COLUMNS}, 0 FROM release_browse_tree_entries
            WHERE registry_id = ?1 AND source_commit = ?2 AND node_key = ?3
              AND (?4 IS NULL OR entry_key > ?4) ORDER BY entry_key LIMIT ?5"
                ),
                &vals![
                    registry_id,
                    commit,
                    node,
                    cursor.as_ref().map(|cursor| cursor.key.as_str()),
                    (DOCUMENTATION_TREE_PAGE_SIZE + 1) as i64
                ],
            )
            .await?;
        entry_page(rows, scope)
    }

    /// Loads one exact search entry in a pinned release generation.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed rows.
    pub async fn documentation_tree_entry(
        &self,
        registry_id: i64,
        commit: &str,
        key: &str,
    ) -> Result<Option<DocumentationTreeEntry>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {ENTRY_COLUMNS}, 0 FROM release_browse_tree_entries
            WHERE registry_id = ?1 AND source_commit = ?2 AND entry_key = ?3"
                ),
                &vals![registry_id, commit, key],
            )
            .await?
            .map(entry_from_row)
            .transpose()
    }

    /// Searches indexed tokens within the whole release or any configuration subtree.
    ///
    /// Only one page crosses the database boundary. Ranking and keyset pagination
    /// run in SQL, using the token-prefix index and precomputed ancestry.
    ///
    /// # Errors
    /// Returns an error for more than sixteen query terms, stale cursors,
    /// database failures, or malformed search data.
    pub async fn search_documentation_tree(
        &self,
        registry_id: i64,
        commit: &str,
        root: Option<&str>,
        query: &str,
        kind: Option<&str>,
        after: Option<&str>,
    ) -> Result<DocumentationTreePage<DocumentationTreeEntry>> {
        let terms = aos_doc_model::tokenize(query)
            .iter()
            .map(|term| search_token(term))
            .collect::<std::collections::BTreeSet<_>>();
        if terms.len() > 16 {
            return Err(InvalidDocumentationQuery("Use at most 16 search terms.").into());
        }
        if terms.is_empty() {
            return Ok(DocumentationTreePage {
                items: Vec::new(),
                next_cursor: None,
            });
        }
        let selection = serde_json::to_string(&(root, &terms, kind))?;
        let scope = cursor_scope(registry_id, commit, &format!("search:{selection}"));
        let cursor = decode_cursor(after, &scope)?;
        let mut values = vals![registry_id, commit].to_vec();
        let mut predicates = Vec::new();
        let mut scores = Vec::new();
        for term in terms {
            let lower = values.len() + 1;
            values.push(crate::value::Value::Text(term.clone()));
            values.push(crate::value::Value::Text(format!("{term}\u{10ffff}")));
            let predicate = format!("term >= ?{lower} AND term < ?{}", lower + 1);
            scores.push(format!("MAX(CASE WHEN {predicate} THEN weight ELSE 0 END)"));
            predicates.push(format!("({predicate})"));
        }
        let root_arg = values.len() + 1;
        values.extend(vals![
            root,
            kind,
            cursor.as_ref().map(|cursor| cursor.score),
            cursor.as_ref().map(|cursor| cursor.key.as_str()),
            (DOCUMENTATION_TREE_PAGE_SIZE + 1) as i64
        ]);
        let columns = ENTRY_COLUMNS
            .split(',')
            .map(|column| format!("entry.{}", column.trim()))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("WITH ranked AS (
            SELECT entry_key, {} AS score FROM release_browse_search_terms
             WHERE registry_id = ?1 AND source_commit = ?2 AND ({}) GROUP BY entry_key
          ) SELECT {columns}, ranked.score FROM ranked JOIN release_browse_tree_entries entry
              ON entry.registry_id = ?1 AND entry.source_commit = ?2 AND entry.entry_key = ranked.entry_key
            WHERE (?{root_arg} IS NULL OR EXISTS (
                SELECT 1 FROM release_browse_tree_ancestors ancestor
                 WHERE ancestor.registry_id = ?1 AND ancestor.source_commit = ?2
                   AND ancestor.ancestor_key = ?{root_arg} AND ancestor.node_key = entry.node_key))
              AND (?{} IS NULL OR entry.kind = ?{})
              AND (?{} IS NULL OR ranked.score < ?{} OR (ranked.score = ?{} AND entry.entry_key > ?{}))
            ORDER BY ranked.score DESC, entry.entry_key LIMIT ?{}",
            scores.join(" + "), predicates.join(" OR "), root_arg + 1, root_arg + 1,
            root_arg + 2, root_arg + 2, root_arg + 2, root_arg + 3, root_arg + 4);
        entry_page(self.backend.query(&sql, &values).await?, scope)
    }
}

fn node_from_row(row: crate::value::Row) -> Result<DocumentationTreeNode> {
    let path: String = row.get(1)?;
    let node = DocumentationTreeNode {
        key: row.get(0)?,
        path: serde_json::from_str(&path)?,
        label: row.get(2)?,
        child_count: usize::try_from(row.get::<i64>(3)?)?,
        entry_count: usize::try_from(row.get::<i64>(4)?)?,
        sort_key: row.get(5)?,
        kind: row.get(6)?,
        type_signature: row.get(7)?,
        summary: row.get(8)?,
    };
    ensure!(
        node.key == documentation_node_key(&node.path),
        "documentation node path identity mismatch"
    );
    Ok(node)
}

fn entry_from_row(row: crate::value::Row) -> Result<DocumentationTreeEntry> {
    Ok(DocumentationTreeEntry {
        key: row.get(0)?,
        node_key: row.get(1)?,
        document_sha256: row.get(2)?,
        package_name: row.get(3)?,
        package_version: row.get(4)?,
        platform: row.get(5)?,
        kind: row.get(6)?,
        document_key: row.get(7)?,
        title: row.get(8)?,
        summary: row.get(9)?,
        type_signature: row.get(10)?,
        score: row.get(11)?,
    })
}

fn entry_page(
    rows: Vec<crate::value::Row>,
    scope: String,
) -> Result<DocumentationTreePage<DocumentationTreeEntry>> {
    let mut items = rows
        .into_iter()
        .map(entry_from_row)
        .collect::<Result<Vec<_>>>()?;
    let has_more = items.len() > DOCUMENTATION_TREE_PAGE_SIZE;
    items.truncate(DOCUMENTATION_TREE_PAGE_SIZE);
    let next_cursor = if has_more {
        items
            .last()
            .map(|entry| {
                encode_cursor(Cursor {
                    scope,
                    sort: String::new(),
                    key: entry.key.clone(),
                    score: entry.score,
                })
            })
            .transpose()?
    } else {
        None
    };
    Ok(DocumentationTreePage { items, next_cursor })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{IndexedDocumentationOption, IndexedPackageDocumentation};

    fn literal(value: &str) -> PathSegment {
        PathSegment::Literal {
            value: value.into(),
        }
    }

    fn document(count: usize) -> IndexedPackageDocumentation {
        let options = (0..count)
            .map(|index| IndexedDocumentationOption {
                key: format!("services.child{index:03}.enable"),
                path: vec![
                    literal("services"),
                    literal(&format!("child{index:03}")),
                    literal("enable"),
                ],
                type_signature: "bool".into(),
            })
            .collect::<Vec<_>>();
        IndexedPackageDocumentation {
            package_name: "config".into(),
            package_version: "1.0.0".into(),
            platform: "x86_64-linux".into(),
            artifact: aos_registry_surface::manifest::DocumentationArtifactMeta {
                format: aos_doc_model::DOCUMENT_FORMAT.into(),
                store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-config-docs".into(),
                nar_hash: format!("sha256-{}", "A".repeat(43)),
                nar_size: 4096,
                document_sha256: format!("sha256:{}", "b".repeat(64)),
                document_size: 2048,
                semantic_schema_sha256: "c".repeat(64),
                system_module_nar_hash: None,
                references: Vec::new(),
            },
            search: options
                .iter()
                .enumerate()
                .map(|(index, option)| aos_doc_model::SearchDocument {
                    kind: "option".into(),
                    key: option.key.clone(),
                    title: option.key.clone(),
                    summary: "Enable service".into(),
                    terms: std::collections::BTreeMap::from([
                        ("enable".into(), 100),
                        (format!("child{index:03}"), 50),
                    ]),
                })
                .collect(),
            options,
        }
    }

    #[test]
    fn typed_paths_preserve_literal_dots_and_wildcards_at_any_depth() {
        assert_ne!(
            documentation_node_key(&[literal("a.b")]),
            documentation_node_key(&[literal("a"), literal("b")])
        );
        assert_ne!(
            documentation_node_key(&[literal("<name>")]),
            documentation_node_key(&[PathSegment::Wildcard {
                name: "name".into()
            }])
        );
        let deep = (0..32)
            .map(|index| literal(&format!("level{index}")))
            .collect::<Vec<_>>();
        assert_eq!(documentation_node_key(&deep).len(), 64);
        assert_ne!(
            documentation_node_key(&deep),
            documentation_node_key(&deep[..31])
        );
    }

    async fn first_page_cursor(db: &Database, registry: i64, node: &str) -> Option<String> {
        db.documentation_tree_descendants(registry, "commit-a", node, None)
            .await
            .unwrap()
            .next_cursor
    }

    #[tokio::test]
    async fn lazy_children_search_and_cursors_stay_bounded_and_isolated() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("lazy-docs", "Lazy docs").await.unwrap();
        let registry = db
            .create_managed_registry(org, "", "main", "public", &[], false)
            .await
            .unwrap();
        let doc = document(137);
        db.retain_release_browse_catalog(registry, "commit-a", &[], None, &[doc.clone()])
            .await
            .unwrap();
        let root = documentation_node_key(&[]);
        let roots = db
            .documentation_tree_children(registry, "commit-a", &root, None)
            .await
            .unwrap();
        assert_eq!(roots.items.len(), 1);
        assert_eq!(roots.items[0].label, "services");
        assert_eq!(roots.items[0].child_count, 137);
        let services = &roots.items[0].key;
        let mut cursor = None;
        let mut keys = std::collections::BTreeSet::new();
        loop {
            let page = db
                .documentation_tree_children(registry, "commit-a", services, cursor.as_deref())
                .await
                .unwrap();
            assert!(page.items.len() <= 50);
            for node in page.items {
                assert_eq!(node.child_count, 1);
                assert_eq!(node.entry_count, 0);
                assert!(keys.insert(node.key));
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(keys.len(), 137);
        // Every documented path beneath `services` is one flattened page set,
        // in dotted order, with the representative variant's summary and type.
        let mut flattened = Vec::new();
        let mut cursor = None;
        loop {
            let page = db
                .documentation_tree_descendants(registry, "commit-a", services, cursor.as_deref())
                .await
                .unwrap();
            assert!(page.items.len() <= 50);
            for node in page.items {
                assert_eq!(node.child_count, 0);
                assert_eq!(node.entry_count, 1);
                assert_eq!(node.kind.as_deref(), Some("option"));
                assert_eq!(node.type_signature.as_deref(), Some("bool"));
                assert_eq!(node.summary.as_deref(), Some("Enable service"));
                flattened.push(path_segment_label(&node.path[1]));
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        let mut expected = (0..137)
            .map(|index| format!("child{index:03}"))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(flattened, expected);
        let everything = db
            .documentation_tree_descendants(registry, "commit-a", &root, None)
            .await
            .unwrap();
        assert_eq!(everything.items.len(), 50);
        assert!(everything.next_cursor.is_some());
        assert!(db
            .documentation_tree_descendants(
                registry,
                "commit-a",
                &root,
                first_page_cursor(&db, registry, services).await.as_deref()
            )
            .await
            .is_err());
        let branches = db
            .documentation_tree_children(registry, "commit-a", &root, None)
            .await
            .unwrap();
        assert!(branches.items[0].kind.is_none() && branches.items[0].summary.is_none());

        let first = db
            .documentation_tree_children(registry, "commit-a", services, None)
            .await
            .unwrap();
        let cursor = first.next_cursor.as_deref();
        assert!(db
            .documentation_tree_children(registry, "commit-b", services, cursor)
            .await
            .is_err());
        assert!(db
            .documentation_tree_children(registry, "commit-a", &root, cursor)
            .await
            .is_err());
        assert!(db
            .documentation_tree_children(registry + 1, "commit-a", services, cursor)
            .await
            .is_err());

        let first_search = db
            .search_documentation_tree(registry, "commit-a", None, "enable", Some("option"), None)
            .await
            .unwrap();
        assert_eq!(first_search.items.len(), 50);
        let mut seen = first_search
            .items
            .iter()
            .map(|entry| entry.key.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let mut after = first_search.next_cursor.clone();
        while let Some(cursor) = after {
            let page = db
                .search_documentation_tree(
                    registry,
                    "commit-a",
                    None,
                    "enable",
                    Some("option"),
                    Some(&cursor),
                )
                .await
                .unwrap();
            assert!(page.items.len() <= 50);
            for entry in page.items {
                assert!(seen.insert(entry.key));
            }
            after = page.next_cursor;
        }
        assert_eq!(seen.len(), 137);
        for (commit, root, term, kind) in [
            ("commit-b", None, "enable", Some("option")),
            (
                "commit-a",
                Some(services.as_str()),
                "enable",
                Some("option"),
            ),
            ("commit-a", None, "child", Some("option")),
            ("commit-a", None, "enable", None),
        ] {
            assert!(db
                .search_documentation_tree(
                    registry,
                    commit,
                    root,
                    term,
                    kind,
                    first_search.next_cursor.as_deref()
                )
                .await
                .is_err());
        }
        let branch = documentation_node_key(&[literal("services"), literal("child073")]);
        let scoped = db
            .search_documentation_tree(registry, "commit-a", Some(&branch), "enab", None, None)
            .await
            .unwrap();
        assert_eq!(scoped.items.len(), 1);
        assert_eq!(scoped.items[0].document_key, "services.child073.enable");
        let leaf = scoped.items[0].node_key.as_deref().unwrap();
        let variants = db
            .documentation_tree_variants(registry, "commit-a", leaf, None)
            .await
            .unwrap();
        assert_eq!(variants.items.len(), 1);
        assert_eq!(
            variants.items[0].document_sha256,
            doc.artifact.document_sha256
        );
        assert!(db
            .documentation_tree_children(registry, "commit-a", leaf, None)
            .await
            .unwrap()
            .items
            .is_empty());

        // Rebuilding one generation replaces its search projection atomically;
        // cascade deletion must not retain stale terms from removed options.
        db.retain_release_browse_catalog(registry, "commit-a", &[], None, &[document(1)])
            .await
            .unwrap();
        assert!(db
            .search_documentation_tree(registry, "commit-a", None, "child073", None, None)
            .await
            .unwrap()
            .items
            .is_empty());
        assert!(
            db.documentation_tree_commit(registry, "1.0.0")
                .await
                .unwrap()
                .is_none(),
            "preparation alone must not publish a release"
        );
    }
}
