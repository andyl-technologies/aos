//! Projects a release's indexed tree onto one immutable package document.
//!
//! Filtering happens before pagination. Counts and representative descriptions
//! come from the same document as the visible paths, including shared branches.

use anyhow::Result;

use crate::db::Database;
use crate::value::{Row, Value};

impl Database {
    pub(super) async fn query_documentation_node(
        &self,
        sql: &str,
        values: &[Value],
        document: Option<&str>,
    ) -> Result<Option<Row>> {
        Ok(self
            .query_documentation(sql, values, document)
            .await?
            .into_iter()
            .next())
    }

    pub(super) async fn query_documentation(
        &self,
        sql: &str,
        values: &[Value],
        document: Option<&str>,
    ) -> Result<Vec<Row>> {
        let Some(document) = document else {
            return self.backend.query(sql, values).await;
        };
        let mut values = values.to_vec();
        values.push(Value::Text(document.to_owned()));
        let document_arg = values.len();
        let query = sql
            .replace("release_browse_tree_entries", "document_entries")
            .replace("release_browse_tree_nodes", "document_nodes");
        // Search already owns a CTE. Join its declarations to the projection
        // instead of nesting WITH statements, which keeps SQLite/D1 identical.
        let query = match query.strip_prefix("WITH ") {
            Some(query) => format!(", {query}"),
            None => format!(" {query}"),
        };
        let sql = format!(
            "WITH document_entries AS (
                SELECT * FROM release_browse_tree_entries
                 WHERE registry_id = ?1 AND source_commit = ?2
                   AND document_sha256 = ?{document_arg}
            ), document_paths AS (
                SELECT DISTINCT ancestor.ancestor_key AS node_key
                  FROM release_browse_tree_ancestors ancestor
                  JOIN document_entries entry ON entry.node_key = ancestor.node_key
                 WHERE ancestor.registry_id = ?1 AND ancestor.source_commit = ?2
            ), document_nodes AS (
                SELECT node.registry_id, node.source_commit, node.node_key, node.parent_key,
                       node.path_json, node.label, node.sort_key,
                       (SELECT COUNT(*) FROM release_browse_tree_nodes child
                         JOIN document_paths path ON path.node_key = child.node_key
                        WHERE child.registry_id = ?1 AND child.source_commit = ?2
                          AND child.parent_key = node.node_key) AS child_count,
                       (SELECT COUNT(*) FROM document_entries entry
                         WHERE entry.node_key = node.node_key) AS entry_count
                  FROM release_browse_tree_nodes node
                 WHERE node.registry_id = ?1 AND node.source_commit = ?2
                   AND (node.parent_key IS NULL OR node.node_key IN (SELECT node_key FROM document_paths))
            ){query}"
        );
        self.backend.query(&sql, &values).await
    }
}
