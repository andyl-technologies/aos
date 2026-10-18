//! Complete registry references, platform selectors, and artifact formats.
//!
//! Repository paths and tag/digest components delegate to `aos-oci-types` so
//! Hub routing, authorization, and the CLI share one exact grammar. Registry
//! authorities are canonicalized through `url` and never percent-decoded.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
use aos_oci_types::{ManifestReference, RepositoryName, Sha256Digest, Tag};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// A complete OCI registry reference with an authority and repository-local reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryReference {
    authority: String,
    repository: RepositoryName,
    reference: ManifestReference,
}

impl RegistryReference {
    /// Parses `authority/repository[:tag|@sha256:digest]` exactly once.
    ///
    /// An omitted tag is canonicalized to `latest`. A colon after the final
    /// slash starts a tag; an at-sign starts a digest. Schemes, URL paths,
    /// credentials, queries, and fragments are not part of a registry
    /// reference and are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error when the authority is absent or malformed, the
    /// repository violates the AOS grammar, or the tag/digest is invalid.
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            !value.contains("//"),
            "registry reference must not include a URL scheme"
        );
        ensure!(
            !value.contains('?'),
            "registry reference must not include a query"
        );
        ensure!(
            !value.contains('#'),
            "registry reference must not include a fragment"
        );

        let (authority, local) = value
            .split_once('/')
            .context("registry reference must be AUTHORITY/REPOSITORY[:TAG|@DIGEST]")?;
        let authority = canonical_authority(authority)?;
        ensure!(!local.is_empty(), "registry repository must not be empty");

        let (repository, reference) = if let Some((repository, digest)) = split_single(local, '@')?
        {
            ensure!(
                !repository.contains(':'),
                "repository must not contain a colon"
            );
            (
                RepositoryName::parse(repository)?,
                ManifestReference::Digest(Sha256Digest::parse(digest)?),
            )
        } else {
            let final_slash = local.rfind('/').map_or(0, |index| index + 1);
            let final_component = &local[final_slash..];
            if let Some(tag_offset) = final_component.rfind(':') {
                let tag_index = final_slash + tag_offset;
                let repository = &local[..tag_index];
                let tag = &local[tag_index + 1..];
                (
                    RepositoryName::parse(repository)?,
                    ManifestReference::Tag(Tag::parse(tag)?),
                )
            } else {
                (
                    RepositoryName::parse(local)?,
                    ManifestReference::Tag(Tag::parse("latest")?),
                )
            }
        };

        Ok(Self {
            authority,
            repository,
            reference,
        })
    }

    /// Returns the normalized registry authority, including a non-default port.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Returns the repository name local to the registry authority.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryName {
        &self.repository
    }

    /// Returns the mutable tag or immutable digest reference.
    #[must_use]
    pub const fn manifest_reference(&self) -> &ManifestReference {
        &self.reference
    }

    /// Returns the default HTTPS origin for this registry authority.
    ///
    /// # Errors
    ///
    /// Returns an error only if the already-validated authority cannot be
    /// reassembled as an HTTPS URL.
    pub fn default_origin(&self) -> Result<Url> {
        Url::parse(&format!("https://{}/", self.authority))
            .context("constructing registry HTTPS origin")
    }

    /// Returns the canonical Distribution scope for an action list.
    #[must_use]
    pub fn scope(&self, actions: &str) -> String {
        format!("repository:{}:{actions}", self.repository)
    }
}

impl fmt::Display for RegistryReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reference {
            ManifestReference::Tag(tag) => {
                write!(formatter, "{}/{}:{tag}", self.authority, self.repository)
            }
            ManifestReference::Digest(digest) => {
                write!(formatter, "{}/{}@{digest}", self.authority, self.repository)
            }
        }
    }
}

impl FromStr for RegistryReference {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

/// An exact OCI platform selector in `os/architecture[/variant]` form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformSelector {
    /// Go-style operating-system token.
    pub os: String,
    /// Go-style architecture token.
    pub architecture: String,
    /// Optional architecture variant.
    pub variant: Option<String>,
}

impl PlatformSelector {
    /// Parses `os/architecture` or `os/architecture/variant`.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong component count or a component outside
    /// the lowercase OCI platform-token grammar.
    pub fn parse(value: &str) -> Result<Self> {
        let parts = value.split('/').collect::<Vec<_>>();
        ensure!(
            matches!(parts.len(), 2 | 3),
            "platform must be OS/ARCHITECTURE[/VARIANT]"
        );
        for part in &parts {
            ensure!(
                !part.is_empty()
                    && part.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b'-')
                    }),
                "platform components must be lowercase ASCII tokens"
            );
        }
        Ok(Self {
            os: parts[0].to_string(),
            architecture: parts[1].to_string(),
            variant: parts.get(2).map(|part| (*part).to_string()),
        })
    }

    /// Returns the native platform understood by the current AOS build.
    #[must_use]
    pub fn native() -> Self {
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        Self {
            os: std::env::consts::OS.to_string(),
            architecture: architecture.to_string(),
            variant: None,
        }
    }

    /// Returns whether an OCI platform matches this selector exactly.
    #[must_use]
    pub fn matches(&self, platform: &aos_oci_types::Platform) -> bool {
        platform.os == self.os
            && platform.architecture == self.architecture
            && platform.variant == self.variant
    }
}

impl fmt::Display for PlatformSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.os, self.architecture)?;
        if let Some(variant) = &self.variant {
            write!(formatter, "/{variant}")?;
        }
        Ok(())
    }
}

impl FromStr for PlatformSelector {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

/// A local artifact representation accepted by container build and pull commands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactFormat {
    /// A directory containing `oci-layout`, `index.json`, and content blobs.
    #[default]
    OciLayout,
    /// An uncompressed tar archive of an OCI image layout.
    OciArchive,
    /// A Docker-load-compatible archive for one selected platform.
    DockerArchive,
}

impl ArtifactFormat {
    /// Parses the stable CLI spelling of an artifact format.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported format.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "oci-layout" => Ok(Self::OciLayout),
            "oci-archive" => Ok(Self::OciArchive),
            "docker-archive" => Ok(Self::DockerArchive),
            _ => bail!("format must be oci-layout, oci-archive, or docker-archive"),
        }
    }
}

impl fmt::Display for ArtifactFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OciLayout => "oci-layout",
            Self::OciArchive => "oci-archive",
            Self::DockerArchive => "docker-archive",
        })
    }
}

fn split_single(value: &str, delimiter: char) -> Result<Option<(&str, &str)>> {
    let Some((left, right)) = value.split_once(delimiter) else {
        return Ok(None);
    };
    ensure!(
        !right.contains(delimiter),
        "registry reference contains more than one '{delimiter}'"
    );
    ensure!(
        !left.is_empty() && !right.is_empty(),
        "registry reference has an empty component"
    );
    Ok(Some((left, right)))
}

fn canonical_authority(value: &str) -> Result<String> {
    ensure!(!value.is_empty(), "registry authority must not be empty");
    ensure!(value.is_ascii(), "registry authority must be ASCII");
    let url = Url::parse(&format!("https://{value}/")).context("invalid registry authority")?;
    ensure!(
        url.username().is_empty(),
        "registry authority must not contain credentials"
    );
    ensure!(
        url.password().is_none(),
        "registry authority must not contain credentials"
    );
    ensure!(
        url.path() == "/",
        "registry authority must not contain a path"
    );
    ensure!(
        url.query().is_none(),
        "registry authority must not contain a query"
    );
    ensure!(
        url.fragment().is_none(),
        "registry authority must not contain a fragment"
    );

    let host = url
        .host()
        .context("registry authority must contain a host")?;
    let host = match host {
        Host::Ipv6(address) => format!("[{address}]"),
        Host::Ipv4(address) => address.to_string(),
        Host::Domain(domain) => domain.to_ascii_lowercase(),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_tags_digests_ports_and_defaults() {
        let tagged = RegistryReference::parse("REGISTRY.example:5443/team/aos:edge")
            .expect("tagged reference");
        assert_eq!(tagged.to_string(), "registry.example:5443/team/aos:edge");

        let latest = RegistryReference::parse("registry.example/aos").expect("latest reference");
        assert_eq!(latest.to_string(), "registry.example/aos:latest");

        let digest = aos_oci_types::Sha256Digest::digest(b"manifest");
        let pinned = RegistryReference::parse(&format!("registry.example/aos@{digest}"))
            .expect("digest reference");
        assert!(pinned.manifest_reference().is_digest());
    }

    #[test]
    fn rejects_url_and_ambiguous_reference_forms() {
        for value in [
            "https://registry.example/aos:latest",
            "registry.example/aos:one@sha256:bad",
            "registry.example/aos@@sha256:bad",
            "registry.example/aos@latest",
            "registry.example/Upper:latest",
            "registry.example/aos?tag=latest",
        ] {
            assert!(RegistryReference::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn platform_selector_is_exact() {
        let selector = PlatformSelector::parse("linux/arm64/v8").expect("platform");
        let mut platform = aos_oci_types::Platform::linux_arm64();
        platform.variant = Some("v8".to_string());
        assert!(selector.matches(&platform));
        assert_eq!(selector.to_string(), "linux/arm64/v8");
        assert!(PlatformSelector::parse("linux/AMD64").is_err());
    }
}
