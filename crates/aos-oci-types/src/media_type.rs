//! Frozen first-release OCI, Docker schema 2, and AOS media-type allowlist.
//!
//! Media types are matched exactly, without parameters or case folding. Adding
//! a variant is an RFC-0017 compatibility change that requires parser, runtime,
//! storage, and garbage-collection coverage.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// An exact media type admitted by RFC-0017.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MediaType {
    /// Generic bytes accepted by the Distribution blob-upload transport.
    OctetStream,
    /// OCI image manifest version 1.
    OciImageManifest,
    /// OCI image index version 1.
    OciImageIndex,
    /// OCI image configuration version 1.
    OciImageConfig,
    /// Uncompressed distributable OCI filesystem layer.
    OciLayerTar,
    /// Gzip-compressed distributable OCI filesystem layer.
    OciLayerGzip,
    /// Zstandard-compressed distributable OCI filesystem layer.
    OciLayerZstd,
    /// Docker distribution schema 2 image manifest.
    DockerImageManifest,
    /// Docker distribution schema 2 manifest list.
    DockerImageIndex,
    /// Docker schema 2 image configuration.
    DockerImageConfig,
    /// Uncompressed Docker filesystem layer.
    DockerLayerTar,
    /// Gzip-compressed Docker filesystem layer.
    DockerLayerGzip,
    /// Canonical empty JSON object used as an artifact config.
    OciEmptyJson,
    /// Signed AOS container-release sidecar.
    AosContainerRelease,
    /// AOS realized Nix closure inventory.
    AosNixClosure,
    /// AOS corresponding-source closure inventory.
    AosSourceClosure,
    /// Deterministic gzip-compressed AOS corresponding-source archive.
    AosSourceArchive,
    /// AOS license report.
    AosLicenseReport,
    /// SPDX 2.3 JSON software bill of materials.
    SpdxJson,
    /// Versioned AOS in-toto provenance statement.
    InTotoJson,
    /// DSSE attestation envelope.
    DsseEnvelope,
}

impl MediaType {
    /// Every media type admitted by the first-release compatibility contract.
    pub const ALL: [Self; 21] = [
        Self::OctetStream,
        Self::OciImageManifest,
        Self::OciImageIndex,
        Self::OciImageConfig,
        Self::OciLayerTar,
        Self::OciLayerGzip,
        Self::OciLayerZstd,
        Self::DockerImageManifest,
        Self::DockerImageIndex,
        Self::DockerImageConfig,
        Self::DockerLayerTar,
        Self::DockerLayerGzip,
        Self::OciEmptyJson,
        Self::AosContainerRelease,
        Self::AosNixClosure,
        Self::AosSourceClosure,
        Self::AosSourceArchive,
        Self::AosLicenseReport,
        Self::SpdxJson,
        Self::InTotoJson,
        Self::DsseEnvelope,
    ];

    /// Parses an exact allowlisted media type.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DockerSchema1Unsupported`] for the two known Docker
    /// schema 1 spellings and [`Error::UnsupportedMediaType`] for every other
    /// value outside the frozen allowlist.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "application/octet-stream" => Ok(Self::OctetStream),
            "application/vnd.oci.image.manifest.v1+json" => Ok(Self::OciImageManifest),
            "application/vnd.oci.image.index.v1+json" => Ok(Self::OciImageIndex),
            "application/vnd.oci.image.config.v1+json" => Ok(Self::OciImageConfig),
            "application/vnd.oci.image.layer.v1.tar" => Ok(Self::OciLayerTar),
            "application/vnd.oci.image.layer.v1.tar+gzip" => Ok(Self::OciLayerGzip),
            "application/vnd.oci.image.layer.v1.tar+zstd" => Ok(Self::OciLayerZstd),
            "application/vnd.docker.distribution.manifest.v2+json" => Ok(Self::DockerImageManifest),
            "application/vnd.docker.distribution.manifest.list.v2+json" => {
                Ok(Self::DockerImageIndex)
            }
            "application/vnd.docker.container.image.v1+json" => Ok(Self::DockerImageConfig),
            "application/vnd.docker.image.rootfs.diff.tar" => Ok(Self::DockerLayerTar),
            "application/vnd.docker.image.rootfs.diff.tar.gzip" => Ok(Self::DockerLayerGzip),
            "application/vnd.oci.empty.v1+json" => Ok(Self::OciEmptyJson),
            "application/vnd.aos.container-release.v1+json" => Ok(Self::AosContainerRelease),
            "application/vnd.aos.nix-closure.v1+json" => Ok(Self::AosNixClosure),
            "application/vnd.aos.source-closure.v1+json" => Ok(Self::AosSourceClosure),
            "application/vnd.aos.source-closure.v1.tar+gzip" => Ok(Self::AosSourceArchive),
            "application/vnd.aos.license-report.v1+json" => Ok(Self::AosLicenseReport),
            "application/spdx+json" => Ok(Self::SpdxJson),
            "application/vnd.in-toto+json" => Ok(Self::InTotoJson),
            "application/vnd.dsse.envelope.v1+json" => Ok(Self::DsseEnvelope),
            "application/vnd.docker.distribution.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v1+prettyjws" => {
                Err(Error::DockerSchema1Unsupported {
                    media_type: value.to_string(),
                })
            }
            _ => Err(Error::UnsupportedMediaType {
                media_type: value.to_string(),
            }),
        }
    }

    /// Returns the exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OctetStream => "application/octet-stream",
            Self::OciImageManifest => "application/vnd.oci.image.manifest.v1+json",
            Self::OciImageIndex => "application/vnd.oci.image.index.v1+json",
            Self::OciImageConfig => "application/vnd.oci.image.config.v1+json",
            Self::OciLayerTar => "application/vnd.oci.image.layer.v1.tar",
            Self::OciLayerGzip => "application/vnd.oci.image.layer.v1.tar+gzip",
            Self::OciLayerZstd => "application/vnd.oci.image.layer.v1.tar+zstd",
            Self::DockerImageManifest => "application/vnd.docker.distribution.manifest.v2+json",
            Self::DockerImageIndex => "application/vnd.docker.distribution.manifest.list.v2+json",
            Self::DockerImageConfig => "application/vnd.docker.container.image.v1+json",
            Self::DockerLayerTar => "application/vnd.docker.image.rootfs.diff.tar",
            Self::DockerLayerGzip => "application/vnd.docker.image.rootfs.diff.tar.gzip",
            Self::OciEmptyJson => "application/vnd.oci.empty.v1+json",
            Self::AosContainerRelease => "application/vnd.aos.container-release.v1+json",
            Self::AosNixClosure => "application/vnd.aos.nix-closure.v1+json",
            Self::AosSourceClosure => "application/vnd.aos.source-closure.v1+json",
            Self::AosSourceArchive => "application/vnd.aos.source-closure.v1.tar+gzip",
            Self::AosLicenseReport => "application/vnd.aos.license-report.v1+json",
            Self::SpdxJson => "application/spdx+json",
            Self::InTotoJson => "application/vnd.in-toto+json",
            Self::DsseEnvelope => "application/vnd.dsse.envelope.v1+json",
        }
    }

    /// Returns whether the media type identifies a runnable image manifest.
    #[must_use]
    pub const fn is_image_manifest(self) -> bool {
        matches!(self, Self::OciImageManifest | Self::DockerImageManifest)
    }

    /// Returns whether the media type identifies an image index or manifest list.
    #[must_use]
    pub const fn is_image_index(self) -> bool {
        matches!(self, Self::OciImageIndex | Self::DockerImageIndex)
    }

    /// Returns whether the media type identifies a runnable image configuration.
    #[must_use]
    pub const fn is_image_config(self) -> bool {
        matches!(self, Self::OciImageConfig | Self::DockerImageConfig)
    }

    /// Returns whether the media type identifies an OCI filesystem layer.
    #[must_use]
    pub const fn is_oci_layer(self) -> bool {
        matches!(
            self,
            Self::OciLayerTar | Self::OciLayerGzip | Self::OciLayerZstd
        )
    }

    /// Returns whether the media type identifies a Docker schema 2 layer.
    #[must_use]
    pub const fn is_docker_layer(self) -> bool {
        matches!(self, Self::DockerLayerTar | Self::DockerLayerGzip)
    }

    /// Returns whether the media type identifies a JSON artifact payload.
    #[must_use]
    pub const fn is_artifact_payload(self) -> bool {
        matches!(
            self,
            Self::AosContainerRelease
                | Self::AosNixClosure
                | Self::AosSourceClosure
                | Self::AosLicenseReport
                | Self::SpdxJson
                | Self::InTotoJson
                | Self::DsseEnvelope
        )
    }

    /// Returns whether the media type identifies retained corresponding-source bytes.
    #[must_use]
    pub const fn is_source_archive(self) -> bool {
        matches!(self, Self::AosSourceArchive)
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for MediaType {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for MediaType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MediaType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_frozen_media_type_round_trips() {
        for media_type in MediaType::ALL {
            assert_eq!(
                MediaType::parse(media_type.as_str()).expect("parse"),
                media_type
            );
            let json = serde_json::to_string(&media_type).expect("serialize");
            assert_eq!(
                serde_json::from_str::<MediaType>(&json).expect("deserialize"),
                media_type
            );
        }
    }

    #[test]
    fn rejects_schema_one_and_unlisted_extensions() {
        for schema_one in [
            "application/vnd.docker.distribution.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v1+prettyjws",
        ] {
            assert!(matches!(
                MediaType::parse(schema_one),
                Err(Error::DockerSchema1Unsupported { .. })
            ));
        }
        assert!(matches!(
            MediaType::parse("application/vnd.example.layer.v1+json"),
            Err(Error::UnsupportedMediaType { .. })
        ));
        assert!(
            MediaType::parse("application/vnd.oci.image.manifest.v1+json; charset=utf-8").is_err()
        );
    }

    #[test]
    fn classifications_are_closed() {
        assert!(MediaType::OciImageManifest.is_image_manifest());
        assert!(MediaType::DockerImageIndex.is_image_index());
        assert!(MediaType::OciImageConfig.is_image_config());
        assert!(MediaType::OciLayerZstd.is_oci_layer());
        assert!(MediaType::DockerLayerGzip.is_docker_layer());
        assert!(MediaType::SpdxJson.is_artifact_payload());
        assert!(MediaType::AosSourceArchive.is_source_archive());
        assert!(!MediaType::AosSourceArchive.is_artifact_payload());
        assert!(!MediaType::OciEmptyJson.is_artifact_payload());
    }
}
