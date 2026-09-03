//! Shared public verification for isolated Hub release transitions.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use futures_util::StreamExt as _;
use reqwest::header::{CONTENT_RANGE, RANGE};
use sha2::{Digest as _, Sha256};

const DEPLOYMENT_ID_PATH: &str = "/.well-known/aos-deployment";
const MAX_DEPLOYMENT_ID_BYTES: usize = 1024;
const RANGE_PROBE_BYTES: usize = 64 * 1024;

pub(super) fn public_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()
        .context("building Hub public verification client")
}

pub(super) async fn verify_deployment(
    client: &reqwest::Client,
    hub: &str,
    expected: &str,
) -> Result<()> {
    let url = format!("{hub}{DEPLOYMENT_ID_PATH}");
    let response = client.get(&url).send().await?.error_for_status()?;
    let header = response
        .headers()
        .get("x-aos-deployment-id")
        .context("Hub deployment response lacks its identity header")?
        .to_str()
        .context("Hub deployment identity header is not ASCII")?
        .to_owned();
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_DEPLOYMENT_ID_BYTES {
        bail!("Hub deployment identity response is oversized");
    }
    let body = std::str::from_utf8(&bytes)
        .context("Hub deployment identity is not UTF-8")?
        .trim();
    if header != expected || body != expected {
        bail!("Hub deployment identity does not match the release plan");
    }
    Ok(())
}

pub(super) async fn read_back_publication(
    client: &reqwest::Client,
    hub: &str,
    registry: &str,
    publication: &aos_remote::hub_types::RegistryPublication,
) -> Result<()> {
    let base = url::Url::parse(&format!("{hub}/{registry}/"))?;
    for object in &publication.objects {
        if !object.verified || object.byte_size < 0 {
            bail!("Hub publication contains an unverified object");
        }
        aos_release::artifact::BundlePath::parse(&object.path)
            .context("Hub returned an invalid publication path")?;
        let url = base.join(&object.path)?;
        if !url.as_str().starts_with(base.as_str()) {
            bail!("Hub returned a path outside the registry surface");
        }
        let expected_size = u64::try_from(object.byte_size)?;
        let (prefix, suffix) = read_full(client, &url, expected_size, &object.sha256)
            .await
            .with_context(|| format!("reading back complete Hub object {}", object.path))?;
        if expected_size > 0 {
            verify_range(client, &url, 0, &prefix, expected_size)
                .await
                .with_context(|| format!("reading back prefix of Hub object {}", object.path))?;
            let suffix_start = expected_size
                .checked_sub(u64::try_from(suffix.len())?)
                .context("range suffix exceeded object size")?;
            verify_range(client, &url, suffix_start, &suffix, expected_size)
                .await
                .with_context(|| format!("reading back suffix of Hub object {}", object.path))?;
        }
    }
    Ok(())
}

async fn read_full(
    client: &reqwest::Client,
    url: &url::Url,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let response = client.get(url.clone()).send().await?.error_for_status()?;
    let mut stream = response.bytes_stream();
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut prefix = Vec::with_capacity(RANGE_PROBE_BYTES);
    let mut suffix = Vec::with_capacity(RANGE_PROBE_BYTES);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        size = size
            .checked_add(u64::try_from(chunk.len())?)
            .context("public read-back size overflowed")?;
        if size > expected_size {
            bail!("public read-back object is larger than its declaration");
        }
        let prefix_needed = RANGE_PROBE_BYTES.saturating_sub(prefix.len());
        prefix.extend_from_slice(&chunk[..chunk.len().min(prefix_needed)]);
        suffix.extend_from_slice(&chunk);
        if suffix.len() > RANGE_PROBE_BYTES {
            suffix.drain(..suffix.len() - RANGE_PROBE_BYTES);
        }
        digest.update(&chunk);
    }
    let found = format!("{:x}", digest.finalize());
    if size != expected_size || found != expected_sha256 {
        bail!("public read-back digest or size differs");
    }
    Ok((prefix, suffix))
}

async fn verify_range(
    client: &reqwest::Client,
    url: &url::Url,
    start: u64,
    expected: &[u8],
    complete_size: u64,
) -> Result<()> {
    let end = start
        .checked_add(u64::try_from(expected.len())?)
        .and_then(|value| value.checked_sub(1))
        .context("range endpoint overflowed")?;
    let response = client
        .get(url.clone())
        .header(RANGE, format!("bytes={start}-{end}"))
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        bail!("Hub did not honor the exact byte-range read-back request");
    }
    let expected_header = format!("bytes {start}-{end}/{complete_size}");
    if response
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        != Some(expected_header.as_str())
    {
        bail!("Hub returned a mismatched content-range header");
    }
    let bytes = response.bytes().await?;
    if bytes.as_ref() != expected {
        bail!("Hub byte-range read-back differs from the full object");
    }
    Ok(())
}
