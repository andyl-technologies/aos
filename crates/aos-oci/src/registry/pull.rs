//! Resumable Distribution pull into a verified single-platform OCI layout.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail, ensure};
use aos_oci_types::limits::MAX_JSON_BYTES;
use aos_oci_types::{
    Annotations, Descriptor, ImageIndex, ImageManifest, ManifestReference, MediaType, Platform,
    Sha256Digest, to_canonical_json,
};
use futures_util::StreamExt as _;
use reqwest::header::{CONTENT_RANGE, CONTENT_TYPE, HeaderMap, HeaderValue, RANGE};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use sha2::Digest as _;

use super::{
    PullOptions, RegistryClient, TransferEvent, build_headers, check_response, emit,
    ensure_not_cancelled, header, repository_path,
};
use crate::layout::verify_layout;
use crate::reference::{PlatformSelector, RegistryReference};

const ACCEPT_MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";
const MAX_INDEX_DEPTH: usize = 8;
const PULL_STATE_SCHEMA: &str = "aos.oci.pull-state/v1";
static PULL_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) async fn run(
    client: &RegistryClient,
    reference: &RegistryReference,
    options: &PullOptions,
) -> Result<crate::layout::VerifiedImage> {
    ensure_not_cancelled(&options.cancellation)?;
    let destination = PullDestination::open(reference, options)?;
    let scope = reference.scope("pull");

    let top_reference = reference.manifest_reference().to_string();
    let remote = fetch_manifest(
        client,
        reference,
        &top_reference,
        &scope,
        &options.cancellation,
    )
    .await?;
    if let ManifestReference::Digest(expected) = reference.manifest_reference() {
        ensure!(
            &remote.digest == expected,
            "pulled manifest digest does not match the immutable reference"
        );
    }

    let resolved = resolve_remote_manifest(client, reference, remote, &scope, options).await?;
    let manifest_bytes = resolved.remote.bytes;
    let manifest_media_type = resolved.remote.media_type;
    let manifest_digest = resolved.remote.digest;
    let manifest_platform = resolved.platform;

    let manifest =
        ImageManifest::from_json(&manifest_bytes).context("validating pulled image manifest")?;
    ensure!(
        manifest.artifact_type.is_none(),
        "registry reference selected an artifact, not a runnable image"
    );
    let manifest_descriptor = Descriptor {
        media_type: manifest_media_type,
        digest: manifest_digest,
        size: u64::try_from(manifest_bytes.len()).context("manifest size conversion")?,
        urls: Vec::new(),
        annotations: manifest.annotations.clone(),
        data: None,
        artifact_type: None,
        platform: Some(manifest_platform),
    };
    destination.store_exact_blob(&manifest_descriptor, &manifest_bytes)?;

    ensure!(
        manifest.config.size
            <= u64::try_from(MAX_JSON_BYTES).context("config size limit conversion")?,
        "image config descriptor exceeds the JSON limit"
    );
    download_blob(
        client,
        reference,
        &manifest.config,
        &scope,
        &destination,
        options,
    )
    .await?;
    for layer in &manifest.layers {
        download_blob(client, reference, layer, &scope, &destination, options).await?;
    }

    let mut annotations = Annotations::new();
    annotations.insert(
        "org.opencontainers.image.ref.name".to_string(),
        reference.to_string(),
    )?;
    let output_index = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![manifest_descriptor],
        subject: None,
        annotations,
    };
    output_index.validate()?;
    let index_bytes = to_canonical_json(&output_index)?;
    ensure_not_cancelled(&options.cancellation)?;
    destination.atomic_root_write("index.json", &index_bytes)?;
    destination.atomic_root_write("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#)?;

    verify_layout(&options.destination, Some(&options.platform))
}

struct RemoteManifest {
    bytes: Vec<u8>,
    digest: Sha256Digest,
    media_type: MediaType,
}

async fn fetch_manifest(
    client: &RegistryClient,
    reference: &RegistryReference,
    manifest_reference: &str,
    scope: &str,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<RemoteManifest> {
    let repository = repository_path(reference);
    let path = format!("v2/{repository}/manifests/{manifest_reference}");
    let url = client.url(&path)?;
    let headers = build_headers([header("accept", ACCEPT_MANIFESTS)?]);
    let response = client
        .send(Method::GET, url, scope, &headers, None, cancellation)
        .await?;
    check_response(&response, &[StatusCode::OK], "manifest download")?;
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let declared_digest = response
        .headers()
        .get("docker-content-digest")
        .map(|value| {
            value
                .to_str()
                .context("manifest digest header is not ASCII")
        })
        .transpose()?
        .map(Sha256Digest::parse)
        .transpose()?;
    let bytes =
        super::read_bounded_body(response, MAX_JSON_BYTES, cancellation, "manifest response")
            .await?;
    let digest = Sha256Digest::digest(&bytes);
    if let Some(declared) = declared_digest {
        ensure!(
            declared == digest,
            "registry manifest digest header does not match response bytes"
        );
    }
    let media_type = manifest_media_type(&bytes, content_type.as_deref())?;
    Ok(RemoteManifest {
        bytes: bytes.to_vec(),
        digest,
        media_type,
    })
}

fn manifest_media_type(bytes: &[u8], content_type: Option<&str>) -> Result<MediaType> {
    let value: Value =
        serde_json::from_slice(bytes).context("decoding manifest JSON projection")?;
    let embedded = value.get("mediaType").and_then(Value::as_str);
    let parsed_content_type = content_type.map(MediaType::parse).transpose()?;
    let parsed_embedded = embedded.map(MediaType::parse).transpose()?;
    if let (Some(header), Some(embedded)) = (parsed_content_type, parsed_embedded) {
        ensure!(
            header == embedded,
            "manifest Content-Type differs from embedded mediaType"
        );
    }
    let media_type = parsed_content_type.or(parsed_embedded).or_else(|| {
        if value.get("manifests").is_some() {
            Some(MediaType::OciImageIndex)
        } else if value.get("layers").is_some() && value.get("config").is_some() {
            Some(MediaType::OciImageManifest)
        } else {
            None
        }
    });
    let media_type =
        media_type.context("manifest response does not identify an accepted media type")?;
    ensure!(
        media_type.is_image_manifest() || media_type.is_image_index(),
        "manifest response media type is not runnable"
    );
    Ok(media_type)
}

struct ResolvedRemoteManifest {
    remote: RemoteManifest,
    platform: Platform,
}

struct RemoteCandidate {
    remote: RemoteManifest,
    platform: Option<Platform>,
    depth: usize,
}

async fn resolve_remote_manifest(
    client: &RegistryClient,
    reference: &RegistryReference,
    root: RemoteManifest,
    scope: &str,
    options: &PullOptions,
) -> Result<ResolvedRemoteManifest> {
    let mut pending = VecDeque::from([RemoteCandidate {
        remote: root,
        platform: None,
        depth: 0,
    }]);
    let mut resolved = Vec::new();
    while let Some(candidate) = pending.pop_front() {
        ensure_not_cancelled(&options.cancellation)?;
        ensure!(
            candidate.depth <= MAX_INDEX_DEPTH,
            "remote OCI index nesting exceeds {MAX_INDEX_DEPTH}"
        );
        if candidate.remote.media_type.is_image_manifest() {
            resolved.push(ResolvedRemoteManifest {
                remote: candidate.remote,
                platform: candidate
                    .platform
                    .unwrap_or_else(|| selector_platform(&options.platform)),
            });
            continue;
        }
        ensure!(
            candidate.remote.media_type.is_image_index(),
            "registry returned a non-runnable manifest media type"
        );
        let index = ImageIndex::from_json(&candidate.remote.bytes)
            .context("validating pulled image index")?;
        for descriptor in index.manifests {
            ensure!(
                descriptor.media_type.is_image_manifest() || descriptor.media_type.is_image_index(),
                "remote index contains a non-runnable descriptor"
            );
            if descriptor
                .platform
                .as_ref()
                .is_some_and(|platform| !options.platform.matches(platform))
            {
                continue;
            }
            let remote = fetch_manifest(
                client,
                reference,
                &descriptor.digest.to_string(),
                scope,
                &options.cancellation,
            )
            .await?;
            ensure!(
                remote.digest == descriptor.digest,
                "pulled child manifest digest differs from its index descriptor"
            );
            ensure!(
                remote.bytes.len() as u64 == descriptor.size,
                "pulled child manifest size differs from its index descriptor"
            );
            ensure!(
                remote.media_type == descriptor.media_type,
                "pulled child media type differs from its index descriptor"
            );
            pending.push_back(RemoteCandidate {
                remote,
                platform: descriptor.platform.or_else(|| candidate.platform.clone()),
                depth: candidate.depth + 1,
            });
        }
    }
    ensure!(
        resolved.len() == 1,
        "remote index does not resolve exactly once to {}",
        options.platform
    );
    resolved
        .pop()
        .context("selected remote manifest disappeared")
}

async fn download_blob(
    client: &RegistryClient,
    reference: &RegistryReference,
    descriptor: &Descriptor,
    scope: &str,
    destination: &PullDestination,
    options: &PullOptions,
) -> Result<()> {
    ensure_not_cancelled(&options.cancellation)?;
    emit(
        &options.events,
        TransferEvent::Checking {
            digest: descriptor.digest.to_string(),
        },
    );
    let final_name = descriptor.digest.encoded();
    if let Some(mut final_file) = destination.open_blob(&final_name, false)? {
        if verify_regular_file(&mut final_file, descriptor).is_ok() {
            emit(
                &options.events,
                TransferEvent::Complete {
                    digest: descriptor.digest.to_string(),
                    size: descriptor.size,
                },
            );
            return Ok(());
        }
        destination.remove_blob(&final_name)?;
    }

    let partial_name = format!("{final_name}.partial");
    let mut file = destination
        .open_blob(&partial_name, true)?
        .context("creating partial OCI blob")?;
    let mut offset = file.metadata()?.len();
    ensure!(
        offset <= descriptor.size,
        "partial OCI blob exceeds descriptor size"
    );
    if offset == descriptor.size {
        if verify_regular_file(&mut file, descriptor).is_ok() {
            drop(file);
            destination.promote_blob(&partial_name, &final_name)?;
            emit(
                &options.events,
                TransferEvent::Complete {
                    digest: descriptor.digest.to_string(),
                    size: descriptor.size,
                },
            );
            return Ok(());
        }
        file.set_len(0)
            .context("clearing invalid complete partial OCI blob")?;
        offset = 0;
    }

    let repository = repository_path(reference);
    let path = format!("v2/{repository}/blobs/{}", descriptor.digest);
    let url = client.url(&path)?;
    let mut headers = HeaderMap::new();
    if offset > 0 {
        headers.insert(RANGE, HeaderValue::from_str(&format!("bytes={offset}-"))?);
    }
    let response = client
        .get_blob(url, scope, &headers, &options.cancellation)
        .await?;
    if offset > 0 && response.status() == StatusCode::OK {
        offset = 0;
    } else if offset > 0 {
        check_response(
            &response,
            &[StatusCode::PARTIAL_CONTENT],
            "resumed blob download",
        )?;
        validate_content_range(
            response.headers().get(CONTENT_RANGE),
            offset,
            descriptor.size,
        )?;
    } else {
        check_response(&response, &[StatusCode::OK], "blob download")?;
    }

    if offset == 0 {
        file.set_len(0).context("truncating partial OCI blob")?;
        file.seek(SeekFrom::Start(0))
            .context("rewinding partial OCI blob")?;
    } else {
        file.seek(SeekFrom::End(0))
            .context("seeking to partial OCI blob end")?;
    }
    let mut stream = response.bytes_stream();
    loop {
        let next = tokio::select! {
            () = options.cancellation.cancelled() => bail!("OCI transfer cancelled"),
            next = stream.next() => next,
        };
        let Some(chunk) = next else { break };
        let chunk = chunk.context("reading OCI blob response")?;
        offset = offset
            .checked_add(u64::try_from(chunk.len()).context("blob chunk size conversion")?)
            .context("downloaded blob size overflow")?;
        ensure!(
            offset <= descriptor.size,
            "registry sent more bytes than the blob descriptor declares"
        );
        file.write_all(&chunk).context("writing partial OCI blob")?;
        emit(
            &options.events,
            TransferEvent::Downloading {
                digest: descriptor.digest.to_string(),
                offset,
                total: descriptor.size,
            },
        );
    }
    file.sync_all().context("syncing partial OCI blob")?;
    ensure!(
        offset == descriptor.size,
        "registry blob response ended before descriptor size"
    );
    ensure_not_cancelled(&options.cancellation)?;
    file.seek(SeekFrom::Start(0))?;
    if let Err(error) = verify_regular_file(&mut file, descriptor) {
        file.set_len(0)
            .context("clearing invalid partial OCI blob")?;
        file.sync_all()
            .context("syncing cleared partial OCI blob")?;
        return Err(error).context("downloaded OCI blob failed descriptor verification");
    }
    drop(file);
    destination.promote_blob(&partial_name, &final_name)?;
    emit(
        &options.events,
        TransferEvent::Complete {
            digest: descriptor.digest.to_string(),
            size: descriptor.size,
        },
    );
    Ok(())
}

struct PullDestination {
    root: File,
    blobs: File,
}

impl PullDestination {
    fn open(reference: &RegistryReference, options: &PullOptions) -> Result<Self> {
        let existed = match fs::symlink_metadata(&options.destination) {
            Ok(metadata) => {
                ensure!(
                    metadata.file_type().is_dir(),
                    "OCI pull state must be a non-symlink directory"
                );
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error).context("reading OCI pull-state destination"),
        };
        if !existed {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder.create(&options.destination).with_context(|| {
                format!(
                    "creating OCI pull state at {}",
                    options.destination.display()
                )
            })?;
        }
        let descriptor = rustix::fs::open(
            &options.destination,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .context("opening private OCI pull-state directory")?;
        let root = File::from(descriptor);

        let identity = format!(
            "{PULL_STATE_SCHEMA}\nauthority={}\nrepository={}\nreference={}\nplatform={}\n",
            reference.authority(),
            reference.repository(),
            reference.manifest_reference(),
            options.platform
        );
        match open_regular_at(&root, ".aos-oci-pull-state", false)? {
            Some(mut marker) => {
                ensure!(
                    marker.metadata()?.len() <= 4096,
                    "OCI pull-state marker is oversized"
                );
                let mut bytes = Vec::new();
                marker.read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 4096, "OCI pull-state marker grew oversized");
                ensure!(
                    bytes == identity.as_bytes(),
                    "OCI pull state belongs to a different reference or platform"
                );
            }
            None if existed => bail!("existing OCI pull-state directory is not owned by AOS"),
            None => atomic_write_at(&root, ".aos-oci-pull-state", identity.as_bytes())?,
        }
        rustix::fs::fchmod(
            &root,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
        )
        .context("setting private OCI pull-state directory mode")?;
        let blobs = open_or_create_directory(&root, "blobs")?;
        let blobs = open_or_create_directory(&blobs, "sha256")?;
        let destination = Self { root, blobs };
        Ok(destination)
    }

    fn open_blob(&self, name: &str, create: bool) -> Result<Option<File>> {
        open_regular_at(&self.blobs, name, create)
    }

    fn remove_blob(&self, name: &str) -> Result<()> {
        rustix::fs::unlinkat(&self.blobs, name, rustix::fs::AtFlags::empty())
            .context("removing invalid OCI blob")
    }

    fn promote_blob(&self, partial: &str, final_name: &str) -> Result<()> {
        rustix::fs::renameat(&self.blobs, partial, &self.blobs, final_name)
            .context("promoting verified OCI blob")
    }

    fn store_exact_blob(&self, descriptor: &Descriptor, bytes: &[u8]) -> Result<()> {
        descriptor.verify(bytes)?;
        let name = descriptor.digest.encoded();
        if let Some(mut file) = self.open_blob(&name, false)? {
            return verify_regular_file(&mut file, descriptor);
        }
        atomic_write_at(&self.blobs, &name, bytes)
    }

    fn atomic_root_write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        atomic_write_at(&self.root, name, bytes)
    }
}

fn open_or_create_directory(directory: &File, name: &str) -> Result<File> {
    match rustix::fs::mkdirat(
        directory,
        name,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
    ) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error).context("creating OCI pull-state directory"),
    }
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .context("opening OCI pull-state directory")?;
    Ok(File::from(descriptor))
}

fn open_regular_at(directory: &File, name: &str, create: bool) -> Result<Option<File>> {
    ensure!(
        !name.is_empty() && !name.contains('/'),
        "OCI pull-state file name must be one component"
    );
    let mut flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    if create {
        flags |= rustix::fs::OFlags::CREATE;
    }
    let descriptor = match rustix::fs::openat(
        directory,
        name,
        flags,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
        Err(error) => return Err(error).context("opening OCI pull-state file without links"),
    };
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "OCI pull-state entry is not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            metadata.nlink() == 1,
            "OCI pull-state files must not be hard-linked"
        );
    }
    Ok(Some(file))
}

fn atomic_write_at(directory: &File, name: &str, bytes: &[u8]) -> Result<()> {
    let sequence = PULL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
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
    .context("creating temporary OCI pull-state file")?;
    let mut file = File::from(descriptor);
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        rustix::fs::renameat(directory, &temporary_name, directory, name)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(directory, &temporary_name, rustix::fs::AtFlags::empty());
    }
    result.context("persisting OCI pull-state file")
}

fn verify_regular_file(file: &mut File, descriptor: &Descriptor) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(metadata.len() == descriptor.size, "OCI blob size mismatch");
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = sha2::Sha256::new();
    std::io::copy(file, &mut DigestWriter(&mut hasher)).context("hashing OCI blob")?;
    let actual = Sha256Digest::from_bytes(hasher.finalize().into());
    ensure!(actual == descriptor.digest, "OCI blob digest mismatch");
    Ok(())
}

struct DigestWriter<'a>(&'a mut sha2::Sha256);

impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        use sha2::Digest as _;
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_content_range(value: Option<&HeaderValue>, offset: u64, total: u64) -> Result<()> {
    let value = value
        .context("resumed blob response lacks Content-Range")?
        .to_str()
        .context("blob Content-Range is not ASCII")?;
    let prefix = format!("bytes {offset}-");
    ensure!(
        value.starts_with(&prefix),
        "blob Content-Range starts at the wrong offset"
    );
    ensure!(
        value.ends_with(&format!("/{total}")),
        "blob Content-Range has the wrong total size"
    );
    Ok(())
}

fn selector_platform(selector: &PlatformSelector) -> Platform {
    Platform {
        architecture: selector.architecture.clone(),
        os: selector.os.clone(),
        os_version: None,
        os_features: Vec::new(),
        variant: selector.variant.clone(),
        features: Vec::new(),
    }
}
