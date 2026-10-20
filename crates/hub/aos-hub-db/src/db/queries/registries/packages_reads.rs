//! Packages reads in the registries capability.

use super::*;

impl Database {
    /// List every package in a registry with its newest indexed version.
    ///
    /// Used by the registry home, the indexer's package count, and the
    /// `ListPackages` RPC. For the anonymous browse UI — whose request cost an
    /// attacker controls by indexing an arbitrarily large registry — prefer
    /// [`Database::list_packages_capped`], which bounds the rows loaded.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_packages(&self, registry_id: i64) -> Result<Vec<PackageRow>> {
        let (rows, _truncated) = self.query_package_rows(registry_id, None).await?;
        Ok(rows)
    }

    /// List a registry's packages for the browse UI, capped at `limit` rows.
    ///
    /// Identical in shape to [`Database::list_packages`] but applies a DB-side
    /// `LIMIT` so a pathologically large registry cannot force the hub to
    /// materialize an unbounded package set per anonymous page view. Returns
    /// the (name-ordered) rows and a `truncated` flag that is `true` when the
    /// registry holds more packages than `limit` — the handler surfaces this as
    /// a "showing first N of many" indicator. The rich client-side filter still
    /// operates over the capped set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_packages_capped(
        &self,
        registry_id: i64,
        limit: usize,
    ) -> Result<(Vec<PackageRow>, bool)> {
        self.query_package_rows(registry_id, Some(limit)).await
    }

    /// Lists release tags and commits with a complete authenticated artifact snapshot.
    ///
    /// Empty snapshots remain selectable; incomplete snapshots never masquerade as
    /// empty catalogs. Reads are scoped to the registry and current signed tag.
    ///
    /// # Errors
    /// Returns an error on database failure or invalid retained row values.
    pub async fn list_complete_package_snapshots(
        &self,
        registry_id: i64,
    ) -> Result<Vec<(String, String)>> {
        self.backend
            .query(
                "SELECT rel.semver, rel.commit_oid FROM releases rel
             JOIN release_artifact_snapshot_heads head
               ON head.release_id = rel.id AND head.registry_id = rel.registry_id
             JOIN release_artifact_snapshots snapshot
               ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
              AND snapshot.release_id = rel.id AND snapshot.registry_id = rel.registry_id
              AND snapshot.state = 'complete' AND snapshot.source_commit = rel.commit_oid
              AND snapshot.verified_tag_oid = rel.tag_oid
             WHERE rel.registry_id = ?1 ORDER BY rel.semver",
                &vals![registry_id],
            )
            .await?
            .iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?)))
            .collect()
    }
}
