//! Verified, resumable Distribution push with immutable-before-tag ordering.

use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use aos_oci_types::{
    Descriptor, ImageIndex, ManifestReference, MediaType, Sha256Digest, to_canonical_json,
};
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue, RANGE};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{
    PushOptions, PushResult, RegistryClient, TransferEvent, build_headers, check_response, emit,
    ensure_not_cancelled, header, repository_path, resolve_location,
};
use crate::layout::{
    VerifiedImage, open_verified_blob, read_root_file, read_verified_blob, verify_layout,
};
use crate::reference::RegistryReference;

const CHECKPOINT_SCHEMA: &str = "aos.oci.upload-checkpoint/v1";
const UPLOAD_STATE_SCHEMA: &str = "aos.oci.upload-state/v1";
static CHECKPOINT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) async fn run(
    client: &RegistryClient,
    reference: &RegistryReference,
    options: &PushOptions,
) -> Result<PushResult> {
    ensure!(
        options.chunk_bytes > 0,
        "OCI upload chunk size must be positive"
    );
    ensure_not_cancelled(&options.cancellation)?;

    // Verification is deliberately complete before the first network effect.
    // A corrupt local layer/config can therefore never advance a remote tag.
    let verified = verify_layout(&options.source, Some(&options.platform))?;
    let (index_bytes, index_digest) = selected_index_bytes(&options.source, &verified)?;
    if let ManifestReference::Digest(expected) = reference.manifest_reference() {
        ensure!(
            expected == &index_digest,
            "destination digest does not match the verified source index"
        );
    }
    let scope = reference.scope("pull,push");
    let state_directory = open_private_state_directory(&options.state_directory, reference)?;

    upload_blob(
        client,
        reference,
        &verified.config,
        &scope,
        &state_directory,
        options,
    )
    .await?;
    for layer in &verified.layers {
        upload_blob(client, reference, layer, &scope, &state_directory, options).await?;
    }

    let manifest_bytes = read_verified_blob(&options.source, &verified.manifest)?;
    put_manifest(
        client,
        reference,
        &verified.manifest.digest.to_string(),
        verified.manifest.media_type,
        manifest_bytes,
        &scope,
        Some(&options.cancellation),
    )
    .await?;

    put_manifest(
        client,
        reference,
        &index_digest.to_string(),
        MediaType::OciImageIndex,
        index_bytes.clone(),
        &scope,
        Some(&options.cancellation),
    )
    .await?;

    match reference.manifest_reference() {
        ManifestReference::Digest(_) => {}
        ManifestReference::Tag(tag) => {
            ensure_not_cancelled(&options.cancellation)?;
            // This is the only mutable-pointer operation and is intentionally
            // last, after every blob, child manifest, and index-by-digest PUT.
            put_manifest(
                client,
                reference,
                &tag.to_string(),
                MediaType::OciImageIndex,
                index_bytes,
                &scope,
                None,
            )
            .await?;
        }
    }
    Ok(PushResult {
        image: verified,
        published_index_digest: index_digest,
    })
}

async fn upload_blob(
    client: &RegistryClient,
    reference: &RegistryReference,
    descriptor: &Descriptor,
    scope: &str,
    state_directory: &File,
    options: &PushOptions,
) -> Result<()> {
    ensure_not_cancelled(&options.cancellation)?;
    emit(
        &options.events,
        TransferEvent::Checking {
            digest: descriptor.digest.to_string(),
        },
    );
    let repository = repository_path(reference);
    let blob_path = format!("v2/{repository}/blobs/{}", descriptor.digest);
    let response = client
        .send(
            Method::HEAD,
            client.url(&blob_path)?,
            scope,
            &HeaderMap::new(),
            None,
            &options.cancellation,
        )
        .await?;
    match response.status() {
        StatusCode::OK => {
            emit(
                &options.events,
                TransferEvent::Complete {
                    digest: descriptor.digest.to_string(),
                    size: descriptor.size,
                },
            );
            return Ok(());
        }
        StatusCode::NOT_FOUND => {}
        status => bail!("blob existence check failed with HTTP {status}"),
    }

    let checkpoint_name = checkpoint_name(reference, &descriptor.digest);
    let mut checkpoint = match load_checkpoint(state_directory, &checkpoint_name)? {
        Some(checkpoint) => {
            validate_checkpoint(client, reference, descriptor, &checkpoint)?;
            match query_upload(client, &checkpoint.location, scope, &options.cancellation).await? {
                Some((location, offset)) => UploadCheckpoint {
                    location: location.to_string(),
                    offset,
                    ..checkpoint
                },
                None => {
                    start_upload(client, reference, descriptor, scope, &options.cancellation)
                        .await?
                }
            }
        }
        None => start_upload(client, reference, descriptor, scope, &options.cancellation).await?,
    };
    save_checkpoint(state_directory, &checkpoint_name, &checkpoint)?;

    let mut file = open_verified_blob(&options.source, descriptor)?;
    file.seek(SeekFrom::Start(checkpoint.offset))
        .context("seeking to resumed upload offset")?;
    let mut buffer = vec![0_u8; options.chunk_bytes];
    while checkpoint.offset < descriptor.size {
        ensure_not_cancelled(&options.cancellation)?;
        let remaining = descriptor.size - checkpoint.offset;
        let wanted = usize::try_from(remaining.min(options.chunk_bytes as u64))
            .context("upload chunk length conversion")?;
        file.read_exact(&mut buffer[..wanted])
            .context("reading OCI upload chunk")?;
        let start = checkpoint.offset;
        let end = start
            .checked_add(u64::try_from(wanted).context("upload chunk size conversion")?)
            .and_then(|offset| offset.checked_sub(1))
            .context("upload range overflow")?;
        let headers = build_headers([
            header("content-type", "application/octet-stream")?,
            header("content-range", &format!("{start}-{end}"))?,
        ]);
        let location = checked_upload_url(client, &checkpoint.location)?;
        let response = client
            .send(
                Method::PATCH,
                location.clone(),
                scope,
                &headers,
                Some(Bytes::copy_from_slice(&buffer[..wanted])),
                &options.cancellation,
            )
            .await?;
        check_response(&response, &[StatusCode::ACCEPTED], "blob upload chunk")?;
        let next_location = resolve_location(&location, &response)?;
        validate_upload_location(client, &next_location)?;
        checkpoint.location = next_location.to_string();
        let submitted_end = end
            .checked_add(1)
            .context("upload acknowledgement overflow")?;
        checkpoint.offset =
            acknowledged_offset(response.headers().get(RANGE))?.unwrap_or(submitted_end);
        ensure!(
            checkpoint.offset > start && checkpoint.offset <= submitted_end,
            "registry acknowledged an offset outside the submitted upload range"
        );
        save_checkpoint(state_directory, &checkpoint_name, &checkpoint)?;
        emit(
            &options.events,
            TransferEvent::Uploading {
                digest: descriptor.digest.to_string(),
                offset: checkpoint.offset,
                total: descriptor.size,
            },
        );
        file.seek(SeekFrom::Start(checkpoint.offset))
            .context("seeking to acknowledged upload offset")?;
    }

    ensure_not_cancelled(&options.cancellation)?;
    let mut finalize = checked_upload_url(client, &checkpoint.location)?;
    finalize
        .query_pairs_mut()
        .append_pair("digest", &descriptor.digest.to_string());
    let response = client
        .send(
            Method::PUT,
            finalize,
            scope,
            &HeaderMap::new(),
            Some(Bytes::new()),
            &options.cancellation,
        )
        .await?;
    check_response(
        &response,
        &[StatusCode::CREATED],
        "blob upload finalization",
    )?;
    if let Some(remote_digest) = response.headers().get("docker-content-digest") {
        let remote_digest = Sha256Digest::parse(
            remote_digest
                .to_str()
                .context("upload digest response header is not ASCII")?,
        )?;
        ensure!(
            remote_digest == descriptor.digest,
            "registry finalized a different blob digest"
        );
    }
    match rustix::fs::unlinkat(
        state_directory,
        &checkpoint_name,
        rustix::fs::AtFlags::empty(),
    ) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error).context("removing completed upload checkpoint"),
    }
    emit(
        &options.events,
        TransferEvent::Complete {
            digest: descriptor.digest.to_string(),
            size: descriptor.size,
        },
    );
    Ok(())
}

async fn start_upload(
    client: &RegistryClient,
    reference: &RegistryReference,
    descriptor: &Descriptor,
    scope: &str,
    cancellation: &CancellationToken,
) -> Result<UploadCheckpoint> {
    let repository = repository_path(reference);
    let path = format!("v2/{repository}/blobs/uploads/");
    let url = client.url(&path)?;
    let response = client
        .send(
            Method::POST,
            url.clone(),
            scope,
            &HeaderMap::new(),
            Some(Bytes::new()),
            cancellation,
        )
        .await?;
    check_response(&response, &[StatusCode::ACCEPTED], "starting blob upload")?;
    let location = resolve_location(&url, &response)?;
    validate_upload_location(client, &location)?;
    Ok(UploadCheckpoint {
        schema: CHECKPOINT_SCHEMA.to_string(),
        authority: reference.authority().to_string(),
        repository: reference.repository().to_string(),
        digest: descriptor.digest,
        size: descriptor.size,
        location: location.to_string(),
        offset: 0,
    })
}

async fn query_upload(
    client: &RegistryClient,
    location: &str,
    scope: &str,
    cancellation: &CancellationToken,
) -> Result<Option<(Url, u64)>> {
    let location = checked_upload_url(client, location)?;
    let response = client
        .send(
            Method::GET,
            location.clone(),
            scope,
            &HeaderMap::new(),
            None,
            cancellation,
        )
        .await?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    check_response(
        &response,
        &[StatusCode::NO_CONTENT, StatusCode::ACCEPTED],
        "querying blob upload",
    )?;
    let next = resolve_location(&location, &response).unwrap_or(location);
    validate_upload_location(client, &next)?;
    let Some(offset) = acknowledged_offset(response.headers().get(RANGE))? else {
        return Ok(None);
    };
    Ok(Some((next, offset)))
}

async fn put_manifest(
    client: &RegistryClient,
    reference: &RegistryReference,
    manifest_reference: &str,
    media_type: MediaType,
    bytes: Vec<u8>,
    scope: &str,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let repository = repository_path(reference);
    let path = format!("v2/{repository}/manifests/{manifest_reference}");
    let url = client.url(&path)?;
    let headers = build_headers([header("content-type", media_type.as_str())?]);
    let commit = CancellationToken::new();
    let cancellation = cancellation.unwrap_or(&commit);
    let response = client
        .send(
            Method::PUT,
            url,
            scope,
            &headers,
            Some(Bytes::from(bytes)),
            cancellation,
        )
        .await?;
    check_response(
        &response,
        &[StatusCode::CREATED, StatusCode::ACCEPTED],
        "manifest upload",
    )
}

fn selected_index_bytes(root: &Path, verified: &VerifiedImage) -> Result<(Vec<u8>, Sha256Digest)> {
    let source = read_root_file(root, "index.json")?;
    let source_digest = Sha256Digest::digest(&source);
    ensure!(
        source_digest == verified.index_digest,
        "source OCI index changed during push"
    );
    let index = ImageIndex::from_json(&source).context("validating source OCI index")?;
    if index.manifests.len() == 1 && index.manifests[0].digest == verified.manifest.digest {
        return Ok((source, source_digest));
    }

    let mut manifest = verified.manifest.clone();
    manifest.platform = Some(verified.platform.clone());
    let selected = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![manifest],
        subject: None,
        annotations: index.annotations,
    };
    selected.validate()?;
    let bytes = to_canonical_json(&selected)?;
    let digest = Sha256Digest::digest(&bytes);
    Ok((bytes, digest))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UploadCheckpoint {
    schema: String,
    authority: String,
    repository: String,
    digest: Sha256Digest,
    size: u64,
    location: String,
    offset: u64,
}

fn checkpoint_name(reference: &RegistryReference, digest: &Sha256Digest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reference.authority().as_bytes());
    hasher.update(b"\0");
    hasher.update(reference.repository().as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(digest.as_bytes());
    format!("{}.json", hex::encode(hasher.finalize()))
}

fn load_checkpoint(directory: &File, name: &str) -> Result<Option<UploadCheckpoint>> {
    let descriptor = match rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).context("opening upload checkpoint"),
    };
    let mut file = File::from(descriptor);
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file(),
        "upload checkpoint is not a regular file"
    );
    ensure!(
        metadata.len() <= 64 * 1024,
        "upload checkpoint is oversized"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            metadata.nlink() == 1,
            "upload checkpoint must not be hard-linked"
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .context("reading upload checkpoint")?;
    ensure!(bytes.len() <= 64 * 1024, "upload checkpoint grew oversized");
    let checkpoint: UploadCheckpoint =
        serde_json::from_slice(&bytes).context("decoding upload checkpoint")?;
    ensure!(
        checkpoint.schema == CHECKPOINT_SCHEMA,
        "unsupported upload checkpoint schema"
    );
    Ok(Some(checkpoint))
}

fn save_checkpoint(directory: &File, name: &str, checkpoint: &UploadCheckpoint) -> Result<()> {
    let bytes = serde_json::to_vec(checkpoint).context("encoding upload checkpoint")?;
    let sequence = CHECKPOINT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!(".{name}.{}.{}.tmp", std::process::id(), sequence);
    let descriptor = rustix::fs::openat(
        directory,
        &temporary_name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .context("creating temporary upload checkpoint")?;
    let mut temporary = File::from(descriptor);
    temporary
        .write_all(&bytes)
        .context("writing upload checkpoint")?;
    temporary.sync_all().context("syncing upload checkpoint")?;
    set_file_private(&mut temporary)?;
    drop(temporary);
    if let Err(error) = rustix::fs::renameat(directory, &temporary_name, directory, name) {
        let _ = rustix::fs::unlinkat(directory, &temporary_name, rustix::fs::AtFlags::empty());
        return Err(error).context("persisting upload checkpoint");
    }
    Ok(())
}

fn validate_checkpoint(
    client: &RegistryClient,
    reference: &RegistryReference,
    descriptor: &Descriptor,
    checkpoint: &UploadCheckpoint,
) -> Result<()> {
    ensure!(
        checkpoint.schema == CHECKPOINT_SCHEMA,
        "unsupported upload checkpoint schema"
    );
    ensure!(
        checkpoint.authority == reference.authority(),
        "upload checkpoint authority mismatch"
    );
    ensure!(
        checkpoint.repository == reference.repository().as_str(),
        "upload checkpoint repository mismatch"
    );
    ensure!(
        checkpoint.digest == descriptor.digest,
        "upload checkpoint digest mismatch"
    );
    ensure!(
        checkpoint.size == descriptor.size,
        "upload checkpoint size mismatch"
    );
    ensure!(
        checkpoint.offset <= descriptor.size,
        "upload checkpoint offset exceeds blob size"
    );
    checked_upload_url(client, &checkpoint.location).map(|_| ())
}

fn checked_upload_url(client: &RegistryClient, value: &str) -> Result<Url> {
    let url = Url::parse(value).context("upload checkpoint Location is not a URL")?;
    validate_upload_location(client, &url)?;
    Ok(url)
}

fn validate_upload_location(client: &RegistryClient, url: &Url) -> Result<()> {
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "upload Location contains credentials"
    );
    ensure!(
        url.fragment().is_none(),
        "upload Location contains a fragment"
    );
    ensure!(
        url.scheme() == client.inner.origin.scheme()
            && url.host() == client.inner.origin.host()
            && url.port_or_known_default() == client.inner.origin.port_or_known_default(),
        "upload Location changes registry authority"
    );
    Ok(())
}

fn acknowledged_offset(range: Option<&HeaderValue>) -> Result<Option<u64>> {
    let Some(range) = range else {
        return Ok(None);
    };
    let range = range.to_str().context("upload Range header is not ASCII")?;
    let range = range.strip_prefix("bytes=").unwrap_or(range);
    let (start, end) = range
        .split_once('-')
        .context("malformed upload Range header")?;
    ensure!(start == "0", "upload Range does not start at zero");
    let end = end
        .parse::<u64>()
        .context("invalid upload Range endpoint")?;
    end.checked_add(1)
        .map(Some)
        .context("upload Range endpoint overflow")
}

fn open_private_state_directory(path: &Path, reference: &RegistryReference) -> Result<File> {
    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_dir(),
                "OCI upload state must be a non-symlink directory"
            );
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("reading OCI upload-state destination"),
    };
    if !existed {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .with_context(|| format!("creating OCI upload state at {}", path.display()))?;
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .context("opening private upload-state directory")?;
    let directory = File::from(descriptor);
    let identity = format!(
        "{UPLOAD_STATE_SCHEMA}\nauthority={}\nrepository={}\n",
        reference.authority(),
        reference.repository()
    );
    match open_state_marker(&directory)? {
        Some(bytes) => ensure!(
            bytes == identity.as_bytes(),
            "OCI upload state belongs to a different repository"
        ),
        None if existed => bail!("existing OCI upload-state directory is not owned by AOS"),
        None => write_new_state_marker(&directory, identity.as_bytes())?,
    }
    rustix::fs::fchmod(
        &directory,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
    )
    .context("setting private upload-state directory mode")?;
    Ok(directory)
}

fn open_state_marker(directory: &File) -> Result<Option<Vec<u8>>> {
    let descriptor = match rustix::fs::openat(
        directory,
        ".aos-oci-upload-state",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).context("opening OCI upload-state marker"),
    };
    let mut file = File::from(descriptor);
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "OCI upload-state marker is not regular");
    ensure!(
        metadata.len() <= 4096,
        "OCI upload-state marker is oversized"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            metadata.nlink() == 1,
            "OCI upload-state marker must not be hard-linked"
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "OCI upload-state marker grew oversized"
    );
    Ok(Some(bytes))
}

fn write_new_state_marker(directory: &File, bytes: &[u8]) -> Result<()> {
    let descriptor = rustix::fs::openat(
        directory,
        ".aos-oci-upload-state",
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .context("creating OCI upload-state marker")?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn set_file_private(file: &mut File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("setting private upload-checkpoint mode")?;
    }
    Ok(())
}
