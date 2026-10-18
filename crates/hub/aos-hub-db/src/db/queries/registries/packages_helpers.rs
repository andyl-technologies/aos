//! Packages helpers in the registries capability.

use super::*;

impl Database {
    /// Single-query package listing shared by [`Database::list_packages`] and
    /// [`Database::list_packages_capped`].
    ///
    /// Joins each package to its newest version (`MAX(package_versions.id)`)
    /// and that version's platform artifacts in **one** round-trip — replacing
    /// the former per-package sub-query (an O(packages) N+1) with a single
    /// `LEFT JOIN`. Rows arrive ordered by package name then platform, so the
    /// per-package platform list and primary-platform closure size are folded
    /// in a single linear pass.
    ///
    /// When `limit` is `Some(n)`, the package set is bounded with a DB-side
    /// `LIMIT` over a name-ordered subquery; the returned flag is `true` when
    /// the registry actually holds more than `n` packages. With `None` every
    /// package is returned and the flag is always `false`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub(in crate::db) async fn query_package_rows(
        &self,
        registry_id: i64,
        limit: Option<usize>,
    ) -> Result<(Vec<PackageRow>, bool)> {
        // Bound the *packages* (not the joined platform rows) so the LIMIT
        // selects whole packages: filter to a capped name-ordered subset of
        // package ids, then join in their newest version's platforms. One
        // extra row beyond the cap is requested to detect truncation without a
        // second COUNT query.
        let probe = limit.map(|n| n.saturating_add(1) as i64);
        let rows = match probe {
            Some(probe) => {
                self.backend
                    .query(
                        "SELECT p.id, p.name, p.description, p.license,
                        (SELECT v.version FROM package_versions v
                         WHERE v.package_id = p.id ORDER BY v.id DESC LIMIT 1),
                        vp.platform, vp.closure_size
                 FROM (SELECT id, name, description, license
                       FROM packages
                       WHERE registry_id = ?1
                       ORDER BY name LIMIT ?2) p
                 LEFT JOIN version_platforms vp
                   ON vp.version_id = (SELECT MAX(v.id) FROM package_versions v
                                       WHERE v.package_id = p.id)
                 ORDER BY p.name, vp.platform",
                        &vals![registry_id, probe],
                    )
                    .await?
            }
            None => {
                self.backend
                    .query(
                        "SELECT p.id, p.name, p.description, p.license,
                        (SELECT v.version FROM package_versions v
                         WHERE v.package_id = p.id ORDER BY v.id DESC LIMIT 1),
                        vp.platform, vp.closure_size
                 FROM packages p
                 LEFT JOIN version_platforms vp
                   ON vp.version_id = (SELECT MAX(v.id) FROM package_versions v
                                       WHERE v.package_id = p.id)
                 WHERE p.registry_id = ?1
                 ORDER BY p.name, vp.platform",
                        &vals![registry_id],
                    )
                    .await?
            }
        };

        // Fold the joined rows into one [`PackageRow`] per package, in the
        // name order the query guarantees. A package with no platform
        // artifacts appears as a single row with NULL platform/closure.
        let mut out: Vec<PackageRow> = Vec::new();
        let mut current_id: Option<i64> = None;
        for row in &rows {
            let package_id: i64 = row.get(0)?;
            if current_id != Some(package_id) {
                current_id = Some(package_id);
                out.push(PackageRow {
                    name: row.get(1)?,
                    description: row.get(2)?,
                    license: row.get(3)?,
                    latest_version: row.get(4)?,
                    closure_size: None,
                    platforms: Vec::new(),
                });
            }
            // `out` is non-empty: the first iteration always pushes (its id
            // cannot equal the sentinel `None`), and later iterations only skip
            // the push when the current package's row is already on top.
            if let Some(entry) = out.last_mut() {
                if let Some(platform) = row.get::<Option<String>>(5)? {
                    entry.platforms.push(platform);
                    if entry.closure_size.is_none() {
                        entry.closure_size = row.get::<Option<u64>>(6)?;
                    }
                }
            }
        }

        // The probe row (cap + 1th package) signals truncation; drop it so the
        // caller sees exactly `limit` packages.
        let truncated = match limit {
            Some(n) if out.len() > n => {
                out.truncate(n);
                true
            }
            _ => false,
        };
        Ok((out, truncated))
    }
}
