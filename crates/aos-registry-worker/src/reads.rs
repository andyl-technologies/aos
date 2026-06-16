//! The Worker's read access layer over the shared `core::Database` (wasm32-only).
//!
//! RFC-0004 Phase 5: rather than re-implement the hub's read queries against the
//! `worker` crate's D1 API (the former `crate::d1`, which also tripped the
//! pinned-workerd `i64`→BigInt bind quirk and the serde-wasm-bindgen
//! null-`Option` quirk), the Worker now drives the *exact*
//! [`aos_registry_core::db::Database`] read methods the native hub runs, over
//! the [`D1Backend`](crate::d1backend::D1Backend) (which binds integers as JS
//! numbers and reads rows positionally). This [`Reads`] facade is a thin
//! presentation boundary: it keeps the same method surface the request handlers
//! and [`crate::render`] already consume — returning [`crate::model`] types —
//! while sourcing every row from `core`.
//!
//! Two behaviours are preserved from the old read layer: only `public`
//! registries resolve (the Worker's anonymous surface; private/internal 404),
//! and a missing index yields a default [`IndexInfo`](crate::model::IndexInfo).

use worker::{D1Database, Result};

use aos_registry_core::db::Database;

use crate::d1backend::D1Backend;
use crate::model::{
    ChannelSummary, IndexInfo, PackageDetail, PackageRow, PlatformDetail, Registry, ReleaseRow,
    VersionDetail,
};

/// Maps a `core` read error (an `anyhow::Error`) into the `worker::Error` the
/// Worker's request handlers propagate.
fn rust_err(err: anyhow::Error) -> worker::Error {
    worker::Error::RustError(format!("{err:#}"))
}

/// A per-request read handle: `core::Database` over a bound D1 database.
///
/// Constructed fresh from `env.d1(binding)` each request via [`Reads::new`]. The
/// schema is applied out of band (the `/_init` handler, once after deploy), so
/// this attaches the backend without migrating.
pub struct Reads {
    db: Database,
}

impl Reads {
    /// Wraps a bound D1 database for reading through `core::Database`.
    #[must_use]
    pub fn new(handle: D1Database) -> Self {
        Self {
            db: Database::attach(Box::new(D1Backend::new(handle))),
        }
    }

    /// Look up one **public** registry by slug (private/internal resolve to
    /// `None`, matching the Worker's anonymous read surface).
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn registry_by_slug(&self, slug: &str) -> Result<Option<Registry>> {
        Ok(self
            .db
            .registry_by_slug(slug)
            .await
            .map_err(rust_err)?
            .filter(|r| r.visibility == "public")
            .map(to_model_registry))
    }

    /// List every public registry, slug-ordered.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn list_public_registries(&self) -> Result<Vec<Registry>> {
        let mut registries: Vec<Registry> = self
            .db
            .list_registries()
            .await
            .map_err(rust_err)?
            .into_iter()
            .filter(|r| r.visibility == "public")
            .map(to_model_registry)
            .collect();
        registries.sort_by(|a, b| a.slug.cmp(&b.slug));
        Ok(registries)
    }

    /// The index freshness row for a registry, or a default [`IndexInfo`] when
    /// the registry has never been indexed.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn registry_index(&self, registry_id: i64) -> Result<IndexInfo> {
        Ok(self
            .db
            .index_status(registry_id)
            .await
            .map_err(rust_err)?
            .map(|s| IndexInfo {
                state: s.state,
                error: s.error,
                last_indexed_commit: s.last_indexed_commit,
                name: s.name,
                description: s.description,
                indexed_at: s.indexed_at,
            })
            .unwrap_or_default())
    }

    /// List a registry's packages with their latest version.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn list_packages(&self, registry_id: i64) -> Result<Vec<PackageRow>> {
        Ok(self
            .db
            .list_packages(registry_id)
            .await
            .map_err(rust_err)?
            .into_iter()
            .map(|p| PackageRow {
                name: p.name,
                description: p.description,
                license: p.license,
                latest: p.latest_version,
            })
            .collect())
    }

    /// Load one package's full detail (header + versions × platforms).
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn package_detail(
        &self,
        registry_id: i64,
        name: &str,
    ) -> Result<Option<PackageDetail>> {
        Ok(self
            .db
            .package_detail(registry_id, name)
            .await
            .map_err(rust_err)?
            .map(|d| PackageDetail {
                name: d.name,
                description: d.description,
                homepage: d.homepage,
                license: d.license,
                maintainer: d.maintainer,
                sysroot: d.sysroot,
                versions: d
                    .versions
                    .into_iter()
                    .map(|v| VersionDetail {
                        version: v.version,
                        previous: v.previous,
                        platforms: v
                            .platforms
                            .into_iter()
                            .map(|pl| PlatformDetail {
                                platform: pl.platform,
                                store_path: pl.store_path,
                                nar_hash: pl.nar_hash,
                                nar_size: pl.nar_size as i64,
                                closure_size: pl.closure_size as i64,
                            })
                            .collect(),
                    })
                    .collect(),
            }))
    }

    /// List channels with their full 256-bucket partition maps.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn list_channels(&self, registry_id: i64) -> Result<Vec<ChannelSummary>> {
        Ok(self
            .db
            .list_channels(registry_id)
            .await
            .map_err(rust_err)?
            .into_iter()
            .map(|c| ChannelSummary {
                name: c.name,
                frontier: c.frontier,
                partitions: c.partitions,
            })
            .collect())
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
        Ok(self
            .db
            .list_releases(registry_id)
            .await
            .map_err(rust_err)?
            .into_iter()
            .map(|r| ReleaseRow {
                semver: r.semver,
                tag_oid: r.tag_oid,
                commit_oid: r.commit_oid,
                signer: r.signer,
                tagged_at: r.tagged_at,
                pack_present: i64::from(r.pack_present),
            })
            .collect())
    }

    /// The trust roster mirror as `(key_id, public_key, status)` rows.
    ///
    /// # Errors
    ///
    /// Returns an error on a D1 query failure.
    pub async fn list_roster(&self, registry_id: i64) -> Result<Vec<(String, String, String)>> {
        Ok(self.db.list_roster(registry_id).await.map_err(rust_err)?)
    }
}

/// Projects a `core` [`RegistryRecord`](aos_registry_core::db::RegistryRecord)
/// onto the Worker's presentation [`Registry`], encoding the trust-anchor list
/// back to the stored JSON-array string and the signature flag to its `0`/`1`
/// integer form.
fn to_model_registry(r: aos_registry_core::db::RegistryRecord) -> Registry {
    Registry {
        id: r.id,
        slug: r.slug,
        source_url: r.source_url,
        trust_keys: serde_json::to_string(&r.trust_keys).unwrap_or_else(|_| "[]".to_string()),
        require_signatures: i64::from(r.require_signatures),
        visibility: r.visibility,
        prefix: r.prefix,
    }
}
