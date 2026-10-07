//! Anonymous public read-back of surface objects.
//!
//! Every mutation of a publication surface is followed by reading its exact
//! objects back through the route consumers use: HTTPS for Hub deployments and
//! HTTP static origins, or the filesystem for `file://` origins. Each object's
//! SHA-256 and size must match; over HTTP the exact prefix and suffix byte
//! ranges must match too, proving the origin serves partial content correctly.
//!
//! Hub objects live below `<hub>/<registry>/`; a static origin's read-back
//! root is the registry root itself.

use std::io::Read as _;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use futures_util::{StreamExt as _, TryStreamExt as _, stream};
use reqwest::header::{CONTENT_RANGE, RANGE};
use sha2::{Digest as _, Sha256};
use url::Url;

use super::SurfaceObject;

const DEPLOYMENT_ID_PATH: &str = "/.well-known/aos-deployment";
const MAX_DEPLOYMENT_ID_BYTES: usize = 1024;
const RANGE_PROBE_BYTES: usize = 64 * 1024;
/// Whole-request deadline for small objects and probes.
const BASE_REQUEST_SECS: u64 = 120;
/// Slowest per-stream rate a full read-back may sustain before it fails.
const MIN_READ_BACK_BYTES_PER_SEC: u64 = 256 * 1024;
const PUBLIC_READ_BACK_CONCURRENCY: usize = 16;

/// Static surface identity file at the read-back root.
pub(in crate::commands::release) const SURFACE_IDENTITY_PATH: &str = ".aos-surface";

/// Builds the redirect-free anonymous client used for every read-back.
pub(in crate::commands::release) fn public_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        // A stalled response fails after this long without a byte; the
        // whole-request deadline is per request so large objects can finish.
        .read_timeout(Duration::from_secs(BASE_REQUEST_SECS))
        .timeout(Duration::from_secs(BASE_REQUEST_SECS))
        .build()
        .context("building public read-back client")
}

/// Requires a Hub to identify as `expected` in both header and body.
pub(in crate::commands::release) async fn verify_deployment(
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

/// Requires a static surface to serve `identity` at `<base>/.aos-surface`.
pub(in crate::commands::release) async fn verify_static_identity(
    client: &reqwest::Client,
    base: &Url,
    identity: &str,
) -> Result<()> {
    let bytes = fetch_small(client, base, SURFACE_IDENTITY_PATH, MAX_DEPLOYMENT_ID_BYTES)
        .await?
        .context("static surface serves no .aos-surface identity")?;
    let found = std::str::from_utf8(&bytes)
        .context("static surface identity is not UTF-8")?
        .trim();
    if found != identity {
        bail!("static surface identity {found:?} does not match the release plan");
    }
    Ok(())
}

/// Parses a read-back origin into a directory base URL ending in `/`.
pub(in crate::commands::release) fn base_url(origin: &str) -> Result<Url> {
    let base = Url::parse(&format!("{}/", origin.trim_end_matches('/')))
        .with_context(|| format!("parsing read-back origin {origin}"))?;
    if !matches!(base.scheme(), "https" | "http" | "file") {
        bail!("read-back origin must use https or file: {origin}");
    }
    Ok(base)
}

/// Reads every object back from `base` and verifies its identity.
///
/// `ranges` additionally checks exact prefix and suffix byte ranges over
/// HTTP; it is ignored for `file://` bases.
pub(in crate::commands::release) async fn read_back_objects(
    client: &reqwest::Client,
    base: &Url,
    objects: &[SurfaceObject],
    ranges: bool,
) -> Result<()> {
    stream::iter(objects)
        .map(|object| async move {
            let url = object_url(base, &object.path)?;
            if url.scheme() == "file" {
                read_file_object(base, &object.path, object)
                    .with_context(|| format!("reading back surface object {}", object.path))
            } else {
                read_http_object(client, &url, object, ranges)
                    .await
                    .with_context(|| format!("reading back surface object {}", object.path))
            }
        })
        .buffer_unordered(PUBLIC_READ_BACK_CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await?;
    Ok(())
}

/// Fetches one small public object, or `None` when it does not exist.
pub(in crate::commands::release) async fn fetch_small(
    client: &reqwest::Client,
    base: &Url,
    path: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    let url = object_url(base, path)?;
    if url.scheme() == "file" {
        let Some(mut file) = open_file_object(base, path)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        (&mut file)
            .take(u64::try_from(maximum)?.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            bail!("public object {path} exceeds {maximum} bytes");
        }
        return Ok(Some(bytes));
    }
    let response = client.get(url.clone()).send().await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response.error_for_status()?;
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        bytes.extend_from_slice(&chunk?);
        if bytes.len() > maximum {
            bail!("public object {path} exceeds {maximum} bytes");
        }
    }
    Ok(Some(bytes))
}

/// Joins a validated relative surface path onto a base without escaping it.
fn object_url(base: &Url, path: &str) -> Result<Url> {
    if path != SURFACE_IDENTITY_PATH {
        aos_release::artifact::BundlePath::parse(path)
            .with_context(|| format!("invalid surface object path {path}"))?;
    }
    let url = base.join(path)?;
    if !url.as_str().starts_with(base.as_str()) {
        bail!("surface object path escapes the read-back root: {path}");
    }
    Ok(url)
}

async fn read_http_object(
    client: &reqwest::Client,
    url: &Url,
    object: &SurfaceObject,
    ranges: bool,
) -> Result<()> {
    let (prefix, suffix) = read_full(client, url, object.byte_size, &object.sha256).await?;
    if ranges && object.byte_size > 0 {
        verify_range(client, url, 0, &prefix, object.byte_size).await?;
        let suffix_start = object
            .byte_size
            .checked_sub(u64::try_from(suffix.len())?)
            .context("range suffix exceeded object size")?;
        verify_range(client, url, suffix_start, &suffix, object.byte_size).await?;
    }
    Ok(())
}

async fn read_full(
    client: &reqwest::Client,
    url: &Url,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Full read-backs run concurrently and include NARs of hundreds of MiB,
    // so their deadline scales with the declared size.
    let deadline = BASE_REQUEST_SECS.saturating_add(expected_size / MIN_READ_BACK_BYTES_PER_SEC);
    let response = client
        .get(url.clone())
        .timeout(Duration::from_secs(deadline))
        .send()
        .await?
        .error_for_status()?;
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
    url: &Url,
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
        bail!("origin did not honor the exact byte-range read-back request");
    }
    let expected_header = format!("bytes {start}-{end}/{complete_size}");
    if response
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        != Some(expected_header.as_str())
    {
        bail!("origin returned a mismatched content-range header");
    }
    let bytes = response.bytes().await?;
    if bytes.as_ref() != expected {
        bail!("byte-range read-back differs from the full object");
    }
    Ok(())
}

fn read_file_object(base: &Url, relative: &str, object: &SurfaceObject) -> Result<()> {
    let mut file = open_file_object(base, relative)?.context("surface object is absent")?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; RANGE_PROBE_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .context("file read-back size overflowed")?;
        if size > object.byte_size {
            bail!("file read-back object is larger than its declaration");
        }
        digest.update(&buffer[..count]);
    }
    if size != object.byte_size || format!("{:x}", digest.finalize()) != object.sha256 {
        bail!("file read-back digest or size differs");
    }
    Ok(())
}

/// Opens a `file://` object without following any link below the surface root.
///
/// The configured root itself may be reached through links (for example
/// `/var` on macOS); every component of the object's relative path is opened
/// with `O_NOFOLLOW`. Returns `None` when a component does not exist.
fn open_file_object(base: &Url, relative: &str) -> Result<Option<std::fs::File>> {
    use rustix::fs::{Mode, OFlags};

    let root = base
        .to_file_path()
        .map_err(|()| anyhow::anyhow!("invalid file read-back URL {base}"))?;
    let mut directory = match rustix::fs::open(
        &root,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening read-back root {}", root.display()));
        }
    };
    let mut components = relative.split('/').peekable();
    while let Some(component) = components.next() {
        if component.is_empty() || component == "." || component == ".." {
            bail!("surface object path is not a normalized relative path: {relative}");
        }
        let last = components.peek().is_none();
        let flags = OFlags::RDONLY
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | if last {
                OFlags::empty()
            } else {
                OFlags::DIRECTORY
            };
        directory = match rustix::fs::openat(&directory, component, flags, Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("opening surface object {relative} without following links")
                });
            }
        };
    }
    let file = std::fs::File::from(directory);
    if !file.metadata()?.is_file() {
        bail!("file read-back object is not a regular file");
    }
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(path: &str, bytes: &[u8]) -> SurfaceObject {
        SurfaceObject {
            path: path.to_owned(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            byte_size: bytes.len() as u64,
            mutable: false,
            media_type: "application/octet-stream".to_owned(),
        }
    }

    #[tokio::test]
    async fn file_read_back_verifies_exact_bytes() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::create_dir_all(root.path().join("objects/aa"))?;
        std::fs::write(root.path().join("objects/aa/one"), b"one")?;
        let base = base_url(&format!("file://{}", root.path().display()))?;
        let client = public_client()?;

        read_back_objects(&client, &base, &[object("objects/aa/one", b"one")], true).await?;
        assert!(
            read_back_objects(&client, &base, &[object("objects/aa/one", b"two")], true)
                .await
                .is_err()
        );
        assert!(
            read_back_objects(&client, &base, &[object("objects/aa/missing", b"")], true)
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn file_read_back_refuses_symbolic_links() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("target"), b"one")?;
        std::os::unix::fs::symlink(root.path().join("target"), root.path().join("link"))?;
        let base = base_url(&format!("file://{}", root.path().display()))?;
        let client = public_client()?;
        assert!(
            read_back_objects(&client, &base, &[object("link", b"one")], false)
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn static_identity_must_match() -> Result<()> {
        let root = tempfile::tempdir()?;
        let base = base_url(&format!("file://{}", root.path().display()))?;
        let client = public_client()?;
        assert!(
            verify_static_identity(&client, &base, "cdn-1")
                .await
                .is_err()
        );
        std::fs::write(root.path().join(SURFACE_IDENTITY_PATH), b"cdn-1\n")?;
        verify_static_identity(&client, &base, "cdn-1").await?;
        assert!(
            verify_static_identity(&client, &base, "cdn-2")
                .await
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn object_paths_cannot_escape_the_base() -> Result<()> {
        let base = base_url("https://cdn.example/registry")?;
        assert_eq!(
            object_url(&base, "objects/aa/one")?.as_str(),
            "https://cdn.example/registry/objects/aa/one"
        );
        assert!(object_url(&base, "../escape").is_err());
        assert!(object_url(&base, "/absolute").is_err());
        Ok(())
    }
}
