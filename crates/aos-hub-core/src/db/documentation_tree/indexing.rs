//! Prepares immutable, indexed configuration paths and search tokens.
//!
//! The index stores immediate-child edges and ancestry once per source commit.
//! Readers therefore never need to deserialize every document or expand a
//! complete tree to show one folder or search within a subtree.

use anyhow::{ensure, Context as _, Result};
use aos_doc_model::PathSegment;
use std::collections::{BTreeMap, BTreeSet};

use super::{documentation_node_key, path_segment_label, search_token};
use crate::backend::Statement;
use crate::db::{extend_multirow_insert, IndexedPackageDocumentation};

#[derive(Default)]
struct Node {
    path: Vec<PathSegment>,
    children: BTreeSet<String>,
    entries: usize,
}

/// Adds the complete tree projection to the catalog's atomic preparation batch.
pub(in crate::db) fn extend_tree_projection(
    statements: &mut Vec<Statement>,
    registry_id: i64,
    commit: &str,
    documents: &[IndexedPackageDocumentation],
) -> Result<()> {
    for table in [
        "release_browse_tree_entries",
        "release_browse_tree_ancestors",
        "release_browse_tree_nodes",
    ] {
        statements.push(Statement::new(
            format!("DELETE FROM {table} WHERE registry_id = ?1 AND source_commit = ?2"),
            vals![registry_id, commit].to_vec(),
        ));
    }
    let mut nodes = BTreeMap::<String, Node>::new();
    nodes.insert(documentation_node_key(&[]), Node::default());
    let mut entries = Vec::new();
    let mut terms = Vec::new();
    let mut seen_entries = BTreeSet::new();
    for document in documents {
        let options = document
            .options
            .iter()
            .map(|option| (option.key.as_str(), option))
            .collect::<BTreeMap<_, _>>();
        for row in &document.search {
            let entry_key = super::documentation_entry_key(
                &document.artifact.document_sha256,
                &row.kind,
                &row.key,
            )?;
            if !seen_entries.insert(entry_key.clone()) {
                continue;
            }
            let option = if row.kind == "option" {
                Some(
                    *options
                        .get(row.key.as_str())
                        .context("documentation search option has no structural path")?,
                )
            } else {
                None
            };
            let node_key = option.map(|option| documentation_node_key(&option.path));
            if let Some(option) = option {
                for depth in 0..=option.path.len() {
                    let prefix = &option.path[..depth];
                    let key = documentation_node_key(prefix);
                    let node = nodes.entry(key).or_insert_with(|| Node {
                        path: prefix.to_vec(),
                        ..Node::default()
                    });
                    if depth < option.path.len() {
                        node.children
                            .insert(documentation_node_key(&option.path[..depth + 1]));
                    } else {
                        node.entries += 1;
                    }
                }
            }
            entries.push(vals![
                registry_id,
                commit,
                entry_key,
                node_key,
                document.artifact.document_sha256,
                document.package_name,
                document.package_version,
                document.platform,
                row.kind,
                row.key,
                row.title,
                row.summary,
                option.map(|option| option.type_signature.as_str())
            ]);
            let mut bounded_terms = BTreeMap::<String, u16>::new();
            for (term, weight) in &row.terms {
                let token = search_token(term);
                let value = bounded_terms.entry(token).or_default();
                *value = (*value).max(*weight);
            }
            for (term, weight) in bounded_terms {
                terms.push(vals![
                    registry_id,
                    commit,
                    term,
                    entry_key,
                    i64::from(weight)
                ]);
            }
        }
    }
    let mut node_rows = Vec::with_capacity(nodes.len());
    let mut ancestors = Vec::new();
    for (key, node) in nodes {
        let parent_key = node
            .path
            .len()
            .checked_sub(1)
            .map(|depth| documentation_node_key(&node.path[..depth]));
        let label = node
            .path
            .last()
            .map(path_segment_label)
            .unwrap_or_else(|| "Configuration".into());
        let sort_key = label.to_lowercase();
        ensure!(
            label.len() <= 1024 && sort_key.len() <= 1024,
            "documentation path segment exceeds the navigation bound"
        );
        node_rows.push(vals![
            registry_id,
            commit,
            key,
            parent_key,
            serde_json::to_string(&node.path)?,
            label,
            sort_key,
            i64::try_from(node.children.len())?,
            i64::try_from(node.entries)?
        ]);
        for depth in 0..=node.path.len() {
            ancestors.push(vals![
                registry_id,
                commit,
                documentation_node_key(&node.path[..depth]),
                key
            ]);
        }
    }
    extend_multirow_insert(statements, "INSERT INTO release_browse_tree_nodes
        (registry_id, source_commit, node_key, parent_key, path_json, label, sort_key, child_count, entry_count)", &node_rows, "")?;
    extend_multirow_insert(statements, "INSERT INTO release_browse_tree_entries
        (registry_id, source_commit, entry_key, node_key, document_sha256, package_name, package_version,
         platform, kind, document_key, title, summary, type_signature)", &entries, "")?;
    extend_multirow_insert(
        statements,
        "INSERT INTO release_browse_search_terms
        (registry_id, source_commit, term, entry_key, weight)",
        &terms,
        "",
    )?;
    extend_multirow_insert(
        statements,
        "INSERT INTO release_browse_tree_ancestors
        (registry_id, source_commit, ancestor_key, node_key)",
        &ancestors,
        "",
    )?;
    Ok(())
}
