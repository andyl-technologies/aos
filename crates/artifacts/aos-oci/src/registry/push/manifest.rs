//! Checks exact immutable manifest presence before a legacy Distribution write.
//!
//! The read uses the existing bounded HEAD recovery after long blob uploads.
//! Tags and Direct publication keep their original mutation authority. A lost
//! PUT response never authorizes another mutation through this check.

use anyhow::{bail, ensure, Context as _, Result};
use aos_oci_types::{MediaType, Sha256Digest};
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::RegistryClient;

/// Checks whether the immutable manifest has an exact remote projection.
///
/// # Errors
/// Refuses failed reads, unexpected statuses, or contradictory digest, size,
/// or media type headers.
pub(super) async fn already_present(
    client: &RegistryClient,
    url: Url,
    scope: &str,
    media_type: MediaType,
    expected_digest: Sha256Digest,
    expected_bytes: usize,
    cancellation: &CancellationToken,
) -> Result<bool> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, media_type.as_str().parse()?);
    let response = client
        .send(Method::HEAD, url, scope, &headers, None, cancellation)
        .await?;
    match response.status() {
        // Registries without manifest HEAD support retain the original PUT.
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_IMPLEMENTED => {
            return Ok(false);
        }
        StatusCode::OK => {}
        status => bail!("manifest existence check failed with HTTP {status}"),
    }

    let headers = response.headers();
    let (Some(digest), Some(length), Some(content_type)) = (
        headers.get("docker-content-digest"),
        headers.get(CONTENT_LENGTH),
        headers.get(CONTENT_TYPE),
    ) else {
        // An incomplete projection cannot replace an exact-byte write.
        return Ok(false);
    };
    ensure!(
        Sha256Digest::parse(digest.to_str().context("manifest digest is not ASCII")?)?
            == expected_digest,
        "registry manifest digest differs from the requested descriptor"
    );
    ensure!(
        length
            .to_str()
            .context("manifest Content-Length is not ASCII")?
            .parse::<u64>()
            .context("manifest Content-Length is invalid")?
            == u64::try_from(expected_bytes)?,
        "registry manifest size differs from the local descriptor"
    );
    ensure!(
        content_type
            .to_str()
            .context("manifest Content-Type is not ASCII")?
            == media_type.as_str(),
        "registry manifest media type differs from the local descriptor"
    );
    Ok(true)
}
