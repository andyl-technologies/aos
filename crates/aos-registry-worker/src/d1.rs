//! The Worker's async D1 read access layer (wasm32-only).
//!
//! D1 is sqlite (RFC-0004 "D1 is the sqlite backend (same dialect, different
//! driver)"), so this layer runs the *exact* read queries the native hub runs
//! ([`crate::sql`]) — only the driver differs: async `worker::D1Database`
//! prepared statements instead of the native sync `rusqlite`. The native
//! `db::Backend` trait is sync and cannot be reused, so this is the Worker's
//! own small async access layer, deliberately scoped to the read path.
//!
//! D1 returns each row as a JS object keyed by column name; `serde-wasm-bindgen`
//! (via `D1Result::results::<T>`) deserializes those into the per-query row
//! structs below, which are then mapped into the pure [`crate::model`] types
//! the renderer and JSON API consume.

use worker::{D1Database, Result};

use crate::model::{
    ChannelSummary, IndexInfo, PackageDetail, PackageRow, PlatformDetail, Registry, ReleaseRow,
    VersionDetail,
};
use crate::sql;

/// A read handle over one bound D1 database.
///
/// Cheap to construct per request from `env.d1(binding)`.
pub struct Db<'a> {
    inner: &'a D1Database,
}

impl<'a> Db<'a> {
    /// Wrap a bound D1 database for reading.
    #[must_use]
    pub fn new(inner: &'a D1Database) -> Self {
        Self { inner }
    }

    /// Apply the read schema to the database (the init path).
    ///
    /// Idempotent: [`sql::SCHEMA`] uses `CREATE TABLE IF NOT EXISTS`. Intended
    /// for a one-shot init handler when `wrangler d1 migrations apply` is not
    /// used; the same DDL backs `migrations/0001_schema.sql`.
    ///
    /// # Errors
    ///
    /// Returns an error if D1 rejects the DDL batch.
    pub async fn migrate(&self) -> Result<()> {
        self.inner.exec(sql::SCHEMA).await?;
        Ok(())
    }

    /// Look up one public registry by slug.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn registry_by_slug(&self, slug: &str) -> Result<Option<Registry>> {
        let row: Option<RegistryRowJs> = self
            .inner
            .prepare(sql::REGISTRY_BY_SLUG)
            .bind(&[slug.into()])?
            .first(None)
            .await?;
        Ok(row.map(Into::into))
    }

    /// List every public registry, slug-ordered.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn list_public_registries(&self) -> Result<Vec<Registry>> {
        let rows: Vec<RegistryRowJs> = self
            .inner
            .prepare(sql::LIST_PUBLIC_REGISTRIES)
            .all()
            .await?
            .results()?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// The index freshness row for a registry, or a default `IndexInfo` when
    /// the registry has never been indexed.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn registry_index(&self, registry_id: i64) -> Result<IndexInfo> {
        let row: Option<IndexInfo> = self
            .inner
            .prepare(sql::REGISTRY_INDEX)
            .bind(&[registry_id.into()])?
            .first(None)
            .await?;
        Ok(row.unwrap_or_default())
    }

    /// List a registry's packages with their latest version.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn list_packages(&self, registry_id: i64) -> Result<Vec<PackageRow>> {
        self.inner
            .prepare(sql::LIST_PACKAGES)
            .bind(&[registry_id.into()])?
            .all()
            .await?
            .results()
    }

    /// Load one package's full detail (header + versions × platforms).
    ///
    /// Mirrors the native `package_detail`: three queries (header, versions,
    /// then per-version platforms) assembled into a [`PackageDetail`].
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn package_detail(
        &self,
        registry_id: i64,
        name: &str,
    ) -> Result<Option<PackageDetail>> {
        let header: Option<PackageHeaderJs> = self
            .inner
            .prepare(sql::PACKAGE_HEADER)
            .bind(&[registry_id.into(), name.into()])?
            .first(None)
            .await?;
        let Some(header) = header else {
            return Ok(None);
        };

        let versions: Vec<VersionRowJs> = self
            .inner
            .prepare(sql::PACKAGE_VERSIONS)
            .bind(&[header.id.into()])?
            .all()
            .await?
            .results()?;

        let mut out_versions = Vec::with_capacity(versions.len());
        for version in versions {
            let platforms: Vec<PlatformDetail> = self
                .inner
                .prepare(sql::VERSION_PLATFORMS)
                .bind(&[version.id.into()])?
                .all()
                .await?
                .results()?;
            out_versions.push(VersionDetail {
                version: version.version,
                previous: version.previous,
                platforms,
            });
        }

        Ok(Some(PackageDetail {
            name: header.name,
            description: header.description,
            homepage: header.homepage,
            license: header.license,
            maintainer: header.maintainer,
            sysroot: header.sysroot != 0,
            versions: out_versions,
        }))
    }

    /// List channels with their full 256-bucket partition maps.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn list_channels(&self, registry_id: i64) -> Result<Vec<ChannelSummary>> {
        let channels: Vec<ChannelRowJs> = self
            .inner
            .prepare(sql::LIST_CHANNELS)
            .bind(&[registry_id.into()])?
            .all()
            .await?
            .results()?;

        let mut out = Vec::with_capacity(channels.len());
        for channel in channels {
            let parts: Vec<PartitionRowJs> = self
                .inner
                .prepare(sql::CHANNEL_PARTITIONS)
                .bind(&[channel.id.into()])?
                .all()
                .await?
                .results()?;
            let mut partitions = vec![None; 256];
            for p in parts {
                if let Some(slot) = partitions.get_mut(p.bucket as usize) {
                    *slot = Some(p.release);
                }
            }
            out.push(ChannelSummary {
                name: channel.name,
                frontier: channel.frontier,
                partitions,
            });
        }
        Ok(out)
    }

    /// Load one channel by name.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn channel(&self, registry_id: i64, name: &str) -> Result<Option<ChannelSummary>> {
        Ok(self
            .list_channels(registry_id)
            .await?
            .into_iter()
            .find(|c| c.name == name))
    }

    /// List a registry's verified releases, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn list_releases(&self, registry_id: i64) -> Result<Vec<ReleaseRow>> {
        self.inner
            .prepare(sql::LIST_RELEASES)
            .bind(&[registry_id.into()])?
            .all()
            .await?
            .results()
    }

    /// The trust roster mirror as `(key_id, public_key, status)` rows.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn list_roster(&self, registry_id: i64) -> Result<Vec<(String, String, String)>> {
        let rows: Vec<RosterRowJs> = self
            .inner
            .prepare(sql::LIST_ROSTER)
            .bind(&[registry_id.into()])?
            .all()
            .await?
            .results()?;
        Ok(rows
            .into_iter()
            .map(|r| (r.key_id, r.public_key, r.status))
            .collect())
    }
}

// -- D1 row deserialization structs ----------------------------------------
//
// D1 yields each row as a JS object keyed by column name; these mirror the
// `SELECT` column lists in `crate::sql` and are mapped into `crate::model`.

#[derive(serde::Deserialize)]
struct RegistryRowJs {
    id: i64,
    slug: String,
    source_url: String,
    trust_keys: String,
    require_signatures: i64,
    visibility: String,
    prefix: String,
}

impl From<RegistryRowJs> for Registry {
    fn from(r: RegistryRowJs) -> Self {
        Registry {
            id: r.id,
            slug: r.slug,
            source_url: r.source_url,
            trust_keys: r.trust_keys,
            require_signatures: r.require_signatures,
            visibility: r.visibility,
            prefix: r.prefix,
        }
    }
}

#[derive(serde::Deserialize)]
struct PackageHeaderJs {
    id: i64,
    name: String,
    description: String,
    homepage: Option<String>,
    license: String,
    maintainer: String,
    sysroot: i64,
}

#[derive(serde::Deserialize)]
struct VersionRowJs {
    id: i64,
    version: String,
    previous: Option<String>,
}

#[derive(serde::Deserialize)]
struct ChannelRowJs {
    id: i64,
    name: String,
    frontier: Option<String>,
}

#[derive(serde::Deserialize)]
struct PartitionRowJs {
    bucket: i64,
    release: String,
}

#[derive(serde::Deserialize)]
struct RosterRowJs {
    key_id: String,
    public_key: String,
    status: String,
}
