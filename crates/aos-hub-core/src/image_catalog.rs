//! Signed system-image discovery and resolution.
//!
//! This module derives end-user image records exclusively from authenticated
//! registry [`PackageToml`] documents. Every indexed image carries the complete
//! signed direct-delivery contract.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use aos_registry_surface::manifest::{
    ImageCompression, ImageDelivery, ImageTarget, ImageVerificationState, PackageToml,
};
use serde::{Deserialize, Serialize};
use url::Url;

/// Selection criteria for an end-user system image.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageQuery {
    /// Exact immutable release, when selected directly.
    pub release: Option<String>,
    /// Mutable channel whose signed payload resolves to a release.
    pub channel: Option<String>,
    /// Required architecture, such as `x86_64`.
    pub architecture: Option<String>,
    /// Required disk encoding, such as `qcow2`.
    pub format: Option<String>,
    /// Required end-user target.
    pub target: Option<ImageTarget>,
}

/// One downloadable encoding derived from a signed sysroot release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageRecord {
    /// Sysroot package carrying the release.
    pub package: String,
    /// Immutable signed release identity.
    pub release: String,
    /// Selected channel, when resolution began from a channel.
    pub channel: Option<String>,
    /// Complete platform triple.
    pub platform: String,
    /// Architecture component.
    pub architecture: String,
    /// Disk encoding.
    pub format: String,
    /// Stable identity shared by all encodings of the logical disk.
    pub logical_image_id: String,
    /// Exact useful download filename.
    pub filename: String,
    /// Immutable direct-download URL serving disk bytes.
    pub download_url: String,
    /// Exact media type.
    pub media_type: String,
    /// Encoding applied to the downloadable disk bytes.
    pub compression: ImageCompression,
    /// Exact encoded byte size.
    pub byte_size: u64,
    /// Lowercase SHA-256 of the served bytes.
    pub sha256: String,
    /// Compatible end-user targets.
    pub compatible_targets: Vec<ImageTarget>,
    /// Boot-payload verification state, distinct from release verification.
    pub verification: ImageVerificationState,
    /// Immutable object key for the disk bytes.
    pub object_key: String,
    /// Immutable object key for canonical `image-info.json`.
    pub image_info_object_key: String,
    /// Immutable URL for canonical `image-info.json`.
    pub image_info_url: String,
    /// Exact media type of canonical `image-info.json`.
    pub image_info_media_type: String,
    /// Exact byte size of canonical `image-info.json`.
    pub image_info_byte_size: u64,
    /// SHA-256 of canonical `image-info.json`.
    pub image_info_sha256: String,
}

/// Read-only image index derived from one authenticated registry snapshot.
pub struct SignedImageCatalog {
    records: Vec<ImageRecord>,
    roots: BTreeSet<String>,
}

impl SignedImageCatalog {
    /// Builds a catalog from authenticated package documents and signed channel resolutions.
    ///
    /// `download_base` is the registry's canonical immutable image-delivery
    /// route. Object keys are appended as path segments without changing
    /// their signed spelling.
    ///
    /// # Errors
    ///
    /// Returns an error when a direct-delivery contract is invalid, a channel
    /// resolves ambiguously, or the download base cannot form an immutable URL.
    pub fn build(
        packages: &[PackageToml],
        channels: &BTreeMap<String, String>,
        download_base: &Url,
    ) -> Result<Self> {
        validate_download_base(download_base)?;
        let mut records = Vec::new();
        let mut roots = BTreeSet::new();
        for package in packages.iter().filter(|package| package.package.sysroot) {
            for version in &package.versions {
                let release_channels: Vec<_> = channels
                    .iter()
                    .filter(|(_, release)| *release == &version.version)
                    .map(|(channel, _)| channel.clone())
                    .collect();
                for (platform, artifact) in &version.platforms {
                    for image in &artifact.images {
                        // Older signed sysroot catalogs describe only a Nix
                        // store path.  They remain valid for `apm install
                        // --image`, but cannot safely produce a direct disk
                        // download URL because they bind neither the served
                        // bytes nor the accompanying image-info document.
                        if image.delivery.is_store_only() {
                            continue;
                        }
                        let delivery = &image.delivery;
                        image
                            .validate_delivery(&version.version, platform)
                            .with_context(|| {
                                format!(
                                    "validating signed image {} {} {platform}/{}",
                                    package.package.name, version.version, image.format
                                )
                            })?;
                        roots.insert(delivery.object_key.clone());
                        roots.insert(delivery.image_info.object_key.clone());
                        records.push(record(
                            &package.package.name,
                            &version.version,
                            platform,
                            &image.format,
                            delivery,
                            None,
                            download_base,
                        )?);
                        for channel in &release_channels {
                            records.push(record(
                                &package.package.name,
                                &version.version,
                                platform,
                                &image.format,
                                delivery,
                                Some(channel.clone()),
                                download_base,
                            )?);
                        }
                    }
                }
            }
        }
        records.sort_by(|left, right| {
            (
                &left.package,
                &left.release,
                &left.platform,
                &left.format,
                &left.channel,
            )
                .cmp(&(
                    &right.package,
                    &right.release,
                    &right.platform,
                    &right.format,
                    &right.channel,
                ))
        });
        Ok(Self { records, roots })
    }

    /// Lists every record matching `query`.
    #[must_use]
    pub fn list(&self, query: &ImageQuery) -> Vec<&ImageRecord> {
        self.records
            .iter()
            .filter(|record| matches_query(record, query))
            .collect()
    }

    /// Resolves `query` to exactly one immutable image encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when no record or more than one record matches.
    pub fn resolve(&self, query: &ImageQuery) -> Result<&ImageRecord> {
        let matches = self.list(query);
        match matches.as_slice() {
            [record] => Ok(*record),
            [] => bail!("no signed system image matches the selection"),
            _ => bail!("image selection is ambiguous; specify architecture, format, or target"),
        }
    }

    /// Returns immutable disk and metadata keys that retention and GC must preserve.
    pub fn retention_roots(&self) -> impl Iterator<Item = &str> {
        self.roots.iter().map(String::as_str)
    }
}

fn record(
    package: &str,
    release: &str,
    platform: &str,
    format: &str,
    delivery: &ImageDelivery,
    channel: Option<String>,
    download_base: &Url,
) -> Result<ImageRecord> {
    let download_url = object_url(download_base, &delivery.object_key)?;
    let image_info_url = object_url(download_base, &delivery.image_info.object_key)?;
    Ok(ImageRecord {
        package: package.to_owned(),
        release: release.to_owned(),
        channel,
        platform: platform.to_owned(),
        architecture: delivery.architecture.clone(),
        format: format.to_owned(),
        logical_image_id: delivery.logical_image_id.clone(),
        filename: delivery.filename.clone(),
        download_url: download_url.to_string(),
        media_type: delivery.media_type.clone(),
        compression: delivery.compression,
        byte_size: delivery.byte_size,
        sha256: delivery.sha256.clone(),
        compatible_targets: delivery.compatible_targets.clone(),
        verification: delivery.uki.verification,
        object_key: delivery.object_key.clone(),
        image_info_object_key: delivery.image_info.object_key.clone(),
        image_info_url: image_info_url.to_string(),
        image_info_media_type: delivery.image_info.media_type.clone(),
        image_info_byte_size: delivery.image_info.byte_size,
        image_info_sha256: delivery.image_info.sha256.clone(),
    })
}

fn validate_download_base(download_base: &Url) -> Result<()> {
    if !matches!(download_base.scheme(), "http" | "https")
        || !download_base.username().is_empty()
        || download_base.password().is_some()
        || download_base.query().is_some()
        || download_base.fragment().is_some()
    {
        bail!("image download base must be an HTTP(S) URL without credentials, query, or fragment");
    }
    Ok(())
}

fn object_url(download_base: &Url, object_key: &str) -> Result<Url> {
    let mut url = download_base.clone();
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("image download base cannot carry path segments"))?
        .pop_if_empty()
        .extend(object_key.split('/'));
    Ok(url)
}

fn matches_query(record: &ImageRecord, query: &ImageQuery) -> bool {
    query
        .release
        .as_ref()
        .is_none_or(|value| value == &record.release)
        && match &query.channel {
            Some(value) => record.channel.as_ref() == Some(value),
            None => record.channel.is_none(),
        }
        && query
            .architecture
            .as_ref()
            .is_none_or(|value| value == &record.architecture)
        && query
            .format
            .as_ref()
            .is_none_or(|value| value == &record.format)
        && query
            .target
            .is_none_or(|value| record.compatible_targets.contains(&value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_surface::manifest::parse_package_file;

    fn package() -> PackageToml {
        parse_package_file(&format!(
            r#"
[package]
name = "server"
description = "AOS server"
license = "MIT"
maintainer = "aos"
sysroot = true

[[versions]]
version = "2026.08"

[versions.platforms.x86_64-linux]
store_path = "/aos/store/server"
closure_size = 1
source_drv = ""
source_nar_hash = ""

[[versions.platforms.x86_64-linux.images]]
format = "raw"
store_path = "/aos/store/server-raw"
nar_hash = "sha256:nar"
nar_size = 1
sb_signer_cert_sha256 = "{signer}"
sbat = [{{ component = "aos", generation = 1 }}]

[versions.platforms.x86_64-linux.images.delivery]
schema_version = 1
release = "2026.08"
platform = "x86_64-linux"
architecture = "x86_64"
logical_image_id = "{logical}"
logical_disk_sha256 = "{disk}"
rootfs_sha256 = "{rootfs}"
filename = "aos-server.img"
object_key = "images/sha256/{image}/aos-server.img"
media_type = "application/vnd.aos.disk-image.raw"
compression = "none"
byte_size = 10
sha256 = "{image}"
compatible_targets = ["bare-metal"]

[versions.platforms.x86_64-linux.images.delivery.uki]
filename = "aos-server.efi"
esp_path = "EFI/Linux/aos-server.efi"
byte_size = 4
sha256 = "{uki}"
verification = "policy-verified"
signer_cert_sha256 = "{signer}"
sbat = [{{ component = "aos", generation = 1 }}]

[versions.platforms.x86_64-linux.images.delivery.image_info]
filename = "image-info.json"
object_key = "images/sha256/{image}/metadata/{info}/image-info.json"
media_type = "application/vnd.aos.image-info+json"
byte_size = 20
sha256 = "{info}"
"#,
            logical = "b".repeat(64),
            disk = "a".repeat(64),
            rootfs = "f".repeat(64),
            signer = "9".repeat(64),
            image = "a".repeat(64),
            uki = "d".repeat(64),
            info = "c".repeat(64),
        ))
        .unwrap()
    }

    #[test]
    fn signed_records_resolve_channels_and_root_disk_and_metadata() {
        let channels = BTreeMap::from([("stable".into(), "2026.08".into())]);
        let catalog = SignedImageCatalog::build(
            &[package()],
            &channels,
            &Url::parse("https://hub.invalid/download/").unwrap(),
        )
        .unwrap();
        let resolved = catalog
            .resolve(&ImageQuery {
                channel: Some("stable".into()),
                target: Some(ImageTarget::BareMetal),
                ..ImageQuery::default()
            })
            .unwrap();
        assert_eq!(resolved.filename, "aos-server.img");
        assert!(resolved.download_url.contains("/download/images/sha256/"));
        assert!(resolved.image_info_url.contains("/download/images/sha256/"));
        assert_eq!(
            resolved.image_info_media_type,
            "application/vnd.aos.image-info+json"
        );
        let release = catalog
            .resolve(&ImageQuery {
                release: Some("2026.08".into()),
                target: Some(ImageTarget::BareMetal),
                ..ImageQuery::default()
            })
            .unwrap();
        assert_eq!(release.channel, None);
        assert_eq!(catalog.list(&ImageQuery::default()).len(), 1);
        assert_eq!(catalog.retention_roots().count(), 2);
    }

    #[test]
    fn store_only_images_remain_installable_but_are_not_direct_downloads() {
        let mut package = package();
        package.versions[0]
            .platforms
            .get_mut("x86_64-linux")
            .unwrap()
            .images[0]
            .delivery = ImageDelivery::store_only();
        let catalog = SignedImageCatalog::build(
            &[package],
            &BTreeMap::new(),
            &Url::parse("https://hub.invalid/download/").unwrap(),
        )
        .unwrap();
        assert!(catalog.list(&ImageQuery::default()).is_empty());
        assert_eq!(catalog.retention_roots().count(), 0);
    }
}
