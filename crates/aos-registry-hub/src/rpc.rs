//! ConnectRPC implementation of the `aos.registry.v1` read-path services.
//!
//! The browser, the CLIs, and third parties share one schema
//! (`crates/aos-proto/src/proto/aos/registry/v1/registry.proto`): registry
//! summaries with verified index status, package listings and detail,
//! channel partition maps, and signed releases. Everything answers from
//! the rebuildable index — these RPCs never touch a registry surface
//! directly, so they are as fast and as available as the database.
//!
//! Phase-1 hub content is read-only and public, matching the anonymous
//! browse pages; per-registry visibility enforcement arrives with tenancy
//! (RFC-0004 phase 2). List RPCs paginate with opaque offset tokens.

// `ConnectError`'s size is fixed by the connectrpc service traits, which
// return it un-boxed; boxing the local helpers would only add unwrapping
// noise at every `?` site.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use aos_proto::aos::registry::v1::*;
use buffa::view::OwnedView;
use buffa::MessageField;
use connectrpc::{ConnectError, Context, ErrorCode};

use crate::db::{Database, IndexStatus, RegistryRecord};

/// Default page size when a list request leaves `page_size` at zero.
const DEFAULT_PAGE_SIZE: u32 = 500;
/// Hard ceiling on page size.
const MAX_PAGE_SIZE: u32 = 1000;

/// Shared implementation state for all three services.
pub struct RegistryRpc {
    /// The hub database.
    pub db: Arc<Database>,
}

fn internal(err: anyhow::Error) -> ConnectError {
    tracing::error!(error = %format!("{err:#}"), "rpc failed");
    ConnectError::new(ErrorCode::Internal, "internal error")
}

fn not_found(what: &str) -> ConnectError {
    ConnectError::new(ErrorCode::NotFound, format!("{what} not found"))
}

/// Slice one page out of `items` using an opaque offset token.
///
/// Returns the page and the `next_page_token` (empty when exhausted).
fn paginate<T>(
    items: Vec<T>,
    page_size: u32,
    token: &str,
) -> Result<(Vec<T>, String), ConnectError> {
    let offset: usize = if token.is_empty() {
        0
    } else {
        token
            .parse()
            .map_err(|_| ConnectError::new(ErrorCode::InvalidArgument, "invalid page_token"))?
    };
    let size = match page_size {
        0 => DEFAULT_PAGE_SIZE,
        n => n.min(MAX_PAGE_SIZE),
    } as usize;
    let end = offset.saturating_add(size).min(items.len());
    let next = if end < items.len() {
        end.to_string()
    } else {
        String::new()
    };
    let page = items
        .into_iter()
        .skip(offset)
        .take(end.saturating_sub(offset))
        .collect();
    Ok((page, next))
}

impl RegistryRpc {
    fn registry_or_not_found(&self, slug: &str) -> Result<RegistryRecord, ConnectError> {
        self.db
            .registry_by_slug(slug)
            .map_err(internal)?
            .ok_or_else(|| not_found("registry"))
    }

    fn registry_message(
        &self,
        record: &RegistryRecord,
        status: Option<IndexStatus>,
    ) -> Result<Registry, ConnectError> {
        let caches = self
            .db
            .list_caches(record.id)
            .map_err(internal)?
            .into_iter()
            .map(|(url, priority)| Cache {
                url,
                priority,
                ..Default::default()
            })
            .collect();
        let roster = self
            .db
            .list_roster(record.id)
            .map_err(internal)?
            .into_iter()
            .map(|(id, key, status)| RosterKey {
                id,
                key,
                status,
                ..Default::default()
            })
            .collect();
        let status = status.unwrap_or(IndexStatus {
            state: "indexing".into(),
            error: None,
            last_indexed_commit: None,
            name: None,
            description: None,
            indexed_at: None,
        });
        Ok(Registry {
            slug: record.slug.clone(),
            name: status.name.unwrap_or_default(),
            description: status.description.unwrap_or_default(),
            source_url: record.source_url.clone(),
            index_state: status.state,
            index_error: status.error.unwrap_or_default(),
            last_indexed_commit: status.last_indexed_commit.unwrap_or_default(),
            indexed_at: status.indexed_at.unwrap_or_default(),
            trust_keys: record.trust_keys.clone(),
            caches,
            roster,
            ..Default::default()
        })
    }
}

impl RegistryService for RegistryRpc {
    /// `ListRegistries` — every registered registry with index status.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for a malformed `page_token` and
    /// `Internal` on database failure.
    async fn list_registries(
        &self,
        ctx: Context,
        req: OwnedView<ListRegistriesRequestView<'static>>,
    ) -> Result<(ListRegistriesResponse, Context), ConnectError> {
        let records = self.db.list_registries().map_err(internal)?;
        let mut registries = Vec::with_capacity(records.len());
        for record in &records {
            let status = self.db.index_status(record.id).map_err(internal)?;
            registries.push(self.registry_message(record, status)?);
        }
        let (registries, next_page_token) = paginate(registries, req.page_size, req.page_token)?;
        Ok((
            ListRegistriesResponse {
                registries,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `GetRegistry` — one registry by slug.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug and `Internal` on database
    /// failure.
    async fn get_registry(
        &self,
        ctx: Context,
        req: OwnedView<GetRegistryRequestView<'static>>,
    ) -> Result<(GetRegistryResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let status = self.db.index_status(record.id).map_err(internal)?;
        Ok((
            GetRegistryResponse {
                registry: Some(self.registry_message(&record, status)?).into(),
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `ListReleases` — verified signed releases, newest first.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug, `InvalidArgument` for a
    /// malformed `page_token`, and `Internal` on database failure.
    async fn list_releases(
        &self,
        ctx: Context,
        req: OwnedView<ListReleasesRequestView<'static>>,
    ) -> Result<(ListReleasesResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let releases: Vec<Release> = self
            .db
            .list_releases(record.id)
            .map_err(internal)?
            .into_iter()
            .map(|r| Release {
                semver: r.semver,
                tag_oid: r.tag_oid,
                commit_oid: r.commit_oid,
                signer: r.signer.unwrap_or_default(),
                tagged_at: r.tagged_at.unwrap_or_default(),
                ..Default::default()
            })
            .collect();
        let (releases, next_page_token) = paginate(releases, req.page_size, req.page_token)?;
        Ok((
            ListReleasesResponse {
                releases,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl PackageService for RegistryRpc {
    /// `ListPackages` — package summaries with the newest version.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug, `InvalidArgument` for a
    /// malformed `page_token`, and `Internal` on database failure.
    async fn list_packages(
        &self,
        ctx: Context,
        req: OwnedView<ListPackagesRequestView<'static>>,
    ) -> Result<(ListPackagesResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let packages: Vec<PackageSummary> = self
            .db
            .list_packages(record.id)
            .map_err(internal)?
            .into_iter()
            .map(|p| PackageSummary {
                name: p.name,
                description: p.description,
                license: p.license,
                latest_version: p.latest_version.unwrap_or_default(),
                ..Default::default()
            })
            .collect();
        let (packages, next_page_token) = paginate(packages, req.page_size, req.page_token)?;
        Ok((
            ListPackagesResponse {
                packages,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `GetPackage` — full version × platform detail for one package.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug or package name and
    /// `Internal` on database failure.
    async fn get_package(
        &self,
        ctx: Context,
        req: OwnedView<GetPackageRequestView<'static>>,
    ) -> Result<(GetPackageResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let detail = self
            .db
            .package_detail(record.id, req.name)
            .map_err(internal)?
            .ok_or_else(|| not_found("package"))?;
        let versions = detail
            .versions
            .into_iter()
            .map(|v| Version {
                version: v.version,
                previous: v.previous.unwrap_or_default(),
                platforms: v
                    .platforms
                    .into_iter()
                    .map(|p| Platform {
                        platform: p.platform,
                        store_path: p.store_path,
                        nar_hash: p.nar_hash,
                        nar_size: p.nar_size,
                        closure_size: p.closure_size,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
            .collect();
        Ok((
            GetPackageResponse {
                package: MessageField::some(Package {
                    name: detail.name,
                    description: detail.description,
                    homepage: detail.homepage.unwrap_or_default(),
                    license: detail.license,
                    maintainer: detail.maintainer,
                    sysroot: detail.sysroot,
                    versions,
                    ..Default::default()
                }),
                ..Default::default()
            },
            ctx,
        ))
    }
}

impl ChannelService for RegistryRpc {
    /// `ListChannels` — channels with full partition maps.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug, `InvalidArgument` for a
    /// malformed `page_token`, and `Internal` on database failure.
    async fn list_channels(
        &self,
        ctx: Context,
        req: OwnedView<ListChannelsRequestView<'static>>,
    ) -> Result<(ListChannelsResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let channels: Vec<Channel> = self
            .db
            .list_channels(record.id)
            .map_err(internal)?
            .into_iter()
            .map(channel_message)
            .collect();
        let (channels, next_page_token) = paginate(channels, req.page_size, req.page_token)?;
        Ok((
            ListChannelsResponse {
                channels,
                next_page_token,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `GetChannel` — one channel's partition map by name.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown slug or channel name and
    /// `Internal` on database failure.
    async fn get_channel(
        &self,
        ctx: Context,
        req: OwnedView<GetChannelRequestView<'static>>,
    ) -> Result<(GetChannelResponse, Context), ConnectError> {
        let record = self.registry_or_not_found(req.slug)?;
        let channel = self
            .db
            .list_channels(record.id)
            .map_err(internal)?
            .into_iter()
            .find(|c| c.name == req.name)
            .ok_or_else(|| not_found("channel"))?;
        Ok((
            GetChannelResponse {
                channel: Some(channel_message(channel)).into(),
                ..Default::default()
            },
            ctx,
        ))
    }
}

fn channel_message(channel: crate::db::ChannelSummary) -> Channel {
    Channel {
        name: channel.name,
        frontier: channel.frontier.unwrap_or_default(),
        partitions: channel
            .partitions
            .iter()
            .enumerate()
            .filter_map(|(bucket, release)| {
                release.as_ref().map(|release| Partition {
                    bucket: bucket as u32,
                    release: release.clone(),
                    ..Default::default()
                })
            })
            .collect(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paginate_slices_and_tokens() {
        let items: Vec<u32> = (0..10).collect();
        let (page, next) = paginate(items.clone(), 4, "").unwrap();
        assert_eq!(page, vec![0, 1, 2, 3]);
        assert_eq!(next, "4");
        let (page, next) = paginate(items.clone(), 4, "8").unwrap();
        assert_eq!(page, vec![8, 9]);
        assert_eq!(next, "");
        assert!(paginate(items, 4, "bogus").is_err());
    }

    #[test]
    fn paginate_defaults_and_caps_page_size() {
        let items: Vec<u32> = (0..2000).collect();
        let (page, _) = paginate(items.clone(), 0, "").unwrap();
        assert_eq!(page.len(), DEFAULT_PAGE_SIZE as usize);
        let (page, _) = paginate(items, 9999, "").unwrap();
        assert_eq!(page.len(), MAX_PAGE_SIZE as usize);
    }
}
