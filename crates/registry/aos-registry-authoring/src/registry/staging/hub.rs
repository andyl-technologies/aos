//! Shared Hub destination selection and candidate upload/publication effects.
//!
//! HTTP destinations identify a Hub through its public deployment endpoint.
//! Canonical registry slugs come from the configured origin path, while local
//! configuration aliases remain confined to authoring commands.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use aos_cli_ui::output::Printer;
use aos_registry_format::staging::{StageRecord, StageRevision, StageState};

use crate::registry::hub_publication::{self, PublicationAccess};
use crate::registry::hub_stage::HubStageClient;

/// Identifies a discovered Hub and its canonical registry namespace.
#[derive(Clone, Debug)]
pub struct HubTarget {
    /// Hub control origin without a registry path.
    pub origin: String,
    /// Canonical registry slug, independent of local configuration aliases.
    pub registry: String,
}

/// Discovers whether a configured upload URL addresses an AOS Hub.
///
/// A missing public deployment endpoint selects ordinary static storage.
/// Failed transport or malformed Hub identity fails closed.
///
/// # Errors
///
/// Returns an error for invalid HTTP URLs, failed discovery, malformed deployment
/// identity, or a Hub URL lacking its canonical registry namespace.
pub async fn target(destination: &str, registry: &str) -> Result<Option<HubTarget>> {
    let parsed = match url::Url::parse(destination) {
        Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => parsed,
        _ => return Ok(None),
    };
    ensure!(
        parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "Hub upload URL cannot contain credentials, a query, or a fragment"
    );
    let origin = parsed.origin().ascii_serialization();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut response = client
        .get(format!("{origin}/.well-known/aos-deployment"))
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    response.error_for_status_ref()?;
    let Some(header) = response.headers().get("x-aos-deployment-id") else {
        return Ok(None);
    };
    let header = header
        .to_str()
        .context("Hub deployment identity is not ASCII")?
        .to_owned();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len().saturating_add(chunk.len()) <= 1_024,
            "Hub deployment identity is oversized"
        );
        body.extend_from_slice(&chunk);
    }
    ensure!(
        !header.is_empty() && std::str::from_utf8(&body)?.trim() == header,
        "Hub deployment identity header and body differ"
    );

    Ok(Some(HubTarget {
        origin,
        registry: canonical_registry(parsed.path(), registry)?,
    }))
}

/// Preserves flat instance slugs and arbitrary-depth organization project paths.
fn canonical_registry(path: &str, fallback: &str) -> Result<String> {
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let canonical = if path.is_empty() { fallback } else { path };
    ensure!(
        canonical.split('/').all(|segment| {
            !segment.is_empty()
                && !matches!(segment, "." | "..")
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        }),
        "Hub upload URL has an invalid canonical registry namespace"
    );
    Ok(canonical.to_owned())
}

/// Registers a draft before admitting and uploading its exact immutable surface.
///
/// # Errors
///
/// Returns an error when credentials, compare-and-swap, exact object admission,
/// resumable transfer, or the Hub's complete candidate verification fails.
pub async fn upload(
    revision: &StageRevision,
    surface_root: &Path,
    origin: &str,
    token: Option<&str>,
    printer: &Printer,
) -> Result<StageRecord> {
    revision.validate()?;
    let access = PublicationAccess {
        hub: Some(origin.to_owned()),
        token: token.map(str::to_owned),
    };
    hub_publication::stage_registry_candidate(
        &access,
        revision,
        revision.revision - 1,
        surface_root,
        printer,
    )
    .await?;
    let stage = HubStageClient::connect(origin, &revision.registry, token)
        .await?
        .show(&revision.id)
        .await?;
    ensure!(
        stage.record.revision == *revision && stage.record.state == StageState::Ready,
        "Hub has not verified the complete exact candidate inventory"
    );
    Ok(stage.record)
}

/// Publishes the exact frozen candidate through the Hub's atomic pointer effects.
///
/// The Hub owns stored pointer installation and release indexing. A `Releasing`
/// response remains resumable until the committed release is indexed.
///
/// # Errors
///
/// Returns an error for mismatched candidate bytes, failed credential renewal,
/// rejected pointer preconditions, or failed Hub publication.
pub async fn publish(
    revision: &StageRevision,
    origin: &str,
    token: Option<&str>,
) -> Result<StageRecord> {
    revision.validate()?;
    let stage = HubStageClient::connect(origin, &revision.registry, token)
        .await?
        .finalize(revision)
        .await?;
    Ok(stage.record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_existing_flat_and_nested_hub_registry_routes() {
        for (path, expected) in [
            ("/main", "main"),
            ("/acme/main", "acme/main"),
            ("/nested/acme/project/main/", "nested/acme/project/main"),
            ("/nested/acme/project/main.git", "nested/acme/project/main"),
        ] {
            assert_eq!(
                canonical_registry(path, "unused").expect("existing Hub route"),
                expected
            );
        }
        assert_eq!(
            canonical_registry("/", "main").expect("instance fallback"),
            "main"
        );
    }

    #[test]
    fn rejects_unsafe_or_empty_canonical_registry_segments() {
        for path in [
            "/acme//main",
            "/acme/../main",
            "/acme/./main",
            "/acme/%2Fmain",
            "/acme/main?query",
        ] {
            assert!(
                canonical_registry(path, "unused").is_err(),
                "accepted {path}"
            );
        }
        assert!(canonical_registry("/", "").is_err());
        assert!(canonical_registry("/", "acme//main").is_err());
    }
}
