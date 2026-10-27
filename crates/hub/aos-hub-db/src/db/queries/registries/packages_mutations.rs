//! Packages mutations in the registries capability.

use super::*;

impl Database {
    /// Counts the packages currently projected for a registry.
    ///
    /// Registry overview pages display only this count. Keeping the count in
    /// SQL avoids materializing every package, newest version, and platform
    /// row merely to call `len()`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn package_count(&self, registry_id: i64) -> Result<usize> {
        let row = self
            .backend
            .query(
                "SELECT COUNT(*) FROM packages WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .into_iter()
            .next()
            .context("package count query returned no row")?;
        let count = row.get::<i64>(0)?;
        usize::try_from(count).context("package count is outside usize")
    }

    /// Load one package's full detail.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn package_detail(
        &self,
        registry_id: i64,
        name: &str,
    ) -> Result<Option<PackageDetail>> {
        let header = self
            .backend
            .query_opt(
                "SELECT id, name, description, homepage, license, maintainer, sysroot
             FROM packages WHERE registry_id = ?1 AND name = ?2",
                &vals![registry_id, name],
            )
            .await?;
        let Some(header) = header else {
            return Ok(None);
        };
        let package_id: i64 = header.get(0)?;
        let mut detail = PackageDetail {
            name: header.get(1)?,
            description: header.get(2)?,
            homepage: header.get(3)?,
            license: header.get(4)?,
            maintainer: header.get(5)?,
            sysroot: header.get(6)?,
            versions: Vec::new(),
        };

        let version_rows = self
            .backend
            .query(
                "SELECT id, version, previous FROM package_versions
             WHERE package_id = ?1 ORDER BY id DESC",
                &vals![package_id],
            )
            .await?;
        let versions = version_rows
            .iter()
            .map(|row| {
                Ok((
                    row.get::<i64>(0)?,
                    row.get::<String>(1)?,
                    row.get::<Option<String>>(2)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        for (version_id, version, previous) in versions {
            let platform_rows = self
                .backend
                .query(
                    "SELECT platform, store_path, nar_hash, nar_size, closure_size, refs, images,
                        source_drv
                 FROM version_platforms WHERE version_id = ?1 ORDER BY platform",
                    &vals![version_id],
                )
                .await?;
            let platforms = platform_rows
                .iter()
                .map(|row| {
                    // refs/images are index-written JSON; tolerate (skip) a
                    // malformed value the same way registry rows are read.
                    let refs_json: String = row.get(5)?;
                    let images_json: String = row.get(6)?;
                    Ok(PlatformDetail {
                        platform: row.get(0)?,
                        store_path: row.get(1)?,
                        nar_hash: row.get(2)?,
                        nar_size: row.get(3)?,
                        closure_size: row.get(4)?,
                        source_drv: row.get(7)?,
                        refs: serde_json::from_str(&refs_json).unwrap_or_default(),
                        images: serde_json::from_str(&images_json).unwrap_or_default(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            detail.versions.push(VersionDetail {
                version,
                previous,
                platforms,
            });
        }
        Ok(Some(detail))
    }
}
