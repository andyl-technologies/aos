//! Signed system-image discovery and resumable disk-byte downloads.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use aos_core::output::Printer;
use aos_remote::hub::{HubClient, hub_rpc};
use aos_remote::hub_types::{ListImagesRequest, ResolveImageRequest, SystemImage};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;

use crate::cli::{ImageCommand, ImageDownloadArgs, ImageSelectionArgs};

const IMAGE_PAGE_SIZE: u32 = 1_000;
const MAX_IMAGE_RESULTS: usize = 100_000;
const MAX_IMAGE_PAGES: usize = 1_000;

/// Runs an `aos image` command.
///
/// # Errors
///
/// Returns an error when selection, authentication, API decoding, local file
/// I/O, resume validation, or checksum verification fails.
pub async fn run(command: &ImageCommand, printer: &Printer) -> Result<()> {
    match command {
        ImageCommand::List(args) => {
            let images = request_images(&args.selection, false).await?;
            if printer.json_if_active(&serde_json::to_value(&images)?) {
                return Ok(());
            }
            for image in images {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    image.package,
                    image.release,
                    if image.channel.is_empty() {
                        "-"
                    } else {
                        &image.channel
                    },
                    image.architecture,
                    image.format,
                    image.compatible_targets.join(","),
                    image.byte_size,
                    image.verification,
                    image.sha256,
                    image.filename,
                );
            }
            Ok(())
        }
        ImageCommand::Show(args) => {
            let image = resolve_image(&args.selection).await?;
            if !printer.json_if_active(&serde_json::to_value(&image)?) {
                println!("{}", serde_json::to_string_pretty(&image)?);
            }
            Ok(())
        }
        ImageCommand::Download(args) => download(args, printer).await,
    }
}

async fn request_images(selection: &ImageSelectionArgs, resolve: bool) -> Result<Vec<SystemImage>> {
    reject_insecure_bearer(&selection.hub, selection.token.as_deref())?;
    let client = match selection.token.as_deref() {
        Some(token) => HubClient::connect_with_token(&selection.hub, token)?,
        None => HubClient::connect_anonymous(&selection.hub)?,
    };
    if resolve {
        let response = client
            .call_topology(
                hub_rpc::ResolveImage,
                &ResolveImageRequest {
                    slug: selection.registry.clone(),
                    release: selection.release.clone().unwrap_or_default(),
                    channel: selection.channel.clone().unwrap_or_default(),
                    architecture: selection.architecture.clone().unwrap_or_default(),
                    format: selection.format.clone().unwrap_or_default(),
                    target: selection.target.clone().unwrap_or_default(),
                    package: selection.package.clone().unwrap_or_default(),
                },
            )
            .await?;
        Ok(vec![
            response.image.context("Hub returned no resolved image")?,
        ])
    } else {
        let mut pagination = ImagePagination::default();
        let mut page_token = String::new();
        loop {
            let response = client
                .call_topology(
                    hub_rpc::ListImages,
                    &ListImagesRequest {
                        slug: selection.registry.clone(),
                        release: selection.release.clone().unwrap_or_default(),
                        channel: selection.channel.clone().unwrap_or_default(),
                        architecture: selection.architecture.clone().unwrap_or_default(),
                        format: selection.format.clone().unwrap_or_default(),
                        target: selection.target.clone().unwrap_or_default(),
                        page_size: IMAGE_PAGE_SIZE,
                        page_token,
                        package: selection.package.clone().unwrap_or_default(),
                    },
                )
                .await?;
            match pagination.accept(response.images, response.next_page_token)? {
                Some(next) => page_token = next,
                None => return Ok(pagination.images),
            }
        }
    }
}

#[derive(Default)]
struct ImagePagination {
    images: Vec<SystemImage>,
    seen_tokens: BTreeSet<String>,
    pages: usize,
}

impl ImagePagination {
    fn accept(
        &mut self,
        page: Vec<SystemImage>,
        next_page_token: String,
    ) -> Result<Option<String>> {
        self.pages = self
            .pages
            .checked_add(1)
            .context("image page count overflow")?;
        if self.pages > MAX_IMAGE_PAGES {
            bail!("Hub image listing exceeded the {MAX_IMAGE_PAGES} page safety limit");
        }
        let total = self
            .images
            .len()
            .checked_add(page.len())
            .context("image result count overflow")?;
        if total > MAX_IMAGE_RESULTS {
            bail!("Hub image listing exceeded the {MAX_IMAGE_RESULTS} result safety limit");
        }
        if page.is_empty() && !next_page_token.is_empty() {
            bail!("Hub returned an empty non-terminal image page");
        }
        self.images.extend(page);
        if next_page_token.is_empty() {
            return Ok(None);
        }
        if !self.seen_tokens.insert(next_page_token.clone()) {
            bail!("Hub repeated an image page token");
        }
        Ok(Some(next_page_token))
    }
}

async fn resolve_image(selection: &ImageSelectionArgs) -> Result<SystemImage> {
    let mut images = request_images(selection, true).await?;
    images.pop().context("Hub returned no resolved image")
}

async fn download(args: &ImageDownloadArgs, printer: &Printer) -> Result<()> {
    let image = resolve_image(&args.selection).await?;
    validate_filename(&image.filename)?;
    validate_sha256(&image.sha256)?;
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(&image.filename));
    let mut destination = SecureDestination::open(&output, args.no_resume)?;
    let existing = destination.existing_len();
    if existing > image.byte_size {
        bail!("existing output is larger than the signed image size");
    }
    if existing < image.byte_size {
        let download_url = validate_download_url(&image.download_url)?;
        let hub_url = reqwest::Url::parse(&args.selection.hub).context("invalid Hub URL")?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building image download client")?;
        let mut request = client.get(download_url.clone());
        if same_origin(&hub_url, &download_url)
            && let Some(token) = &args.selection.token
        {
            request = request.bearer_auth(token);
        }
        if existing > 0 {
            request = request.header(reqwest::header::RANGE, format!("bytes={existing}-"));
        }
        let response = request.send().await.context("downloading image bytes")?;
        let expected = if existing > 0 {
            reqwest::StatusCode::PARTIAL_CONTENT
        } else {
            reqwest::StatusCode::OK
        };
        if response.status() != expected {
            bail!(
                "image download returned {}, expected {expected}",
                response.status()
            );
        }
        if existing > 0 {
            let content_range = response
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                .context("resumed image response omitted Content-Range")?;
            let expected_range = format!(
                "bytes {existing}-{}/{}",
                image.byte_size - 1,
                image.byte_size
            );
            if content_range != expected_range {
                bail!("resumed image response has inconsistent Content-Range");
            }
        }
        let expected_body = image.byte_size - existing;
        if response.content_length() != Some(expected_body) {
            bail!("image response length does not match signed remaining byte count");
        }
        let mut file = destination.take_async_file()?;
        let mut received = 0_u64;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("reading image response")?;
            received = received
                .checked_add(chunk.len() as u64)
                .context("image response byte count overflow")?;
            if received > expected_body {
                bail!("image response exceeded the signed byte size");
            }
            destination.hash_bytes(&chunk);
            file.write_all(&chunk).await?;
        }
        if received != expected_body {
            bail!("image response ended before the signed byte size");
        }
        file.sync_all().await?;
        destination.restore_async_file(file).await?;
    }
    let size = destination.current_len()?;
    if size != image.byte_size {
        bail!(
            "downloaded image size {size} does not match signed size {}",
            image.byte_size
        );
    }
    let actual = destination.final_sha256()?;
    if actual != image.sha256 {
        bail!(
            "downloaded image SHA-256 mismatch: expected {}, got {actual}",
            image.sha256
        );
    }
    destination.commit()?;
    if printer.json_if_active(&serde_json::json!({
        "path": output,
        "byteSize": image.byte_size,
        "sha256": image.sha256,
        "verified": true,
        "resumedFrom": existing,
    })) {
        return Ok(());
    }
    printer.success(&format!("Downloaded {}", output.display()));
    println!("{}", output.display());
    Ok(())
}

/// Descriptor-relative destination state for resumable, atomic downloads.
struct SecureDestination {
    directory: fs::File,
    final_name: OsString,
    partial_name: OsString,
    file: Option<fs::File>,
    hasher: Option<Sha256>,
    existing: u64,
    partial_identity: DestinationIdentity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DestinationIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    links: u64,
}

impl SecureDestination {
    fn open(output: &Path, restart: bool) -> Result<Self> {
        let final_name = output
            .file_name()
            .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
            .context("image output must name a file")?
            .to_os_string();
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = fs::File::from(
            rustix::fs::open(
                parent,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .with_context(|| format!("opening output directory {}", parent.display()))?,
        );
        let mut partial_name = OsString::from(".");
        partial_name.push(&final_name);
        partial_name.push(".aos-part");

        if open_regular_at(&directory, &final_name, false)?.is_some() {
            bail!(
                "final image destination already exists; remove it explicitly before downloading"
            );
        }
        let mut file = if restart {
            open_regular_at(&directory, &partial_name, true)?
                .context("creating resumable image output")?
        } else {
            match open_regular_at(&directory, &partial_name, false)? {
                Some(file) => file,
                None => open_regular_at(&directory, &partial_name, true)?
                    .context("creating resumable image output")?,
            }
        };
        let existing = file.metadata()?.len();
        let partial_identity = destination_identity(&file.metadata()?)?;
        let mut hasher = Sha256::new();
        if !restart {
            file.seek(SeekFrom::Start(0))?;
            let mut buffer = [0_u8; 128 * 1024];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            directory,
            final_name,
            partial_name,
            file: Some(file),
            hasher: Some(hasher),
            existing: if restart { 0 } else { existing },
            partial_identity,
        })
    }

    fn existing_len(&self) -> u64 {
        self.existing
    }

    fn hash_bytes(&mut self, bytes: &[u8]) {
        if let Some(hasher) = &mut self.hasher {
            hasher.update(bytes);
        }
    }

    fn take_async_file(&mut self) -> Result<tokio::fs::File> {
        self.file
            .take()
            .map(tokio::fs::File::from_std)
            .context("image destination descriptor is unavailable")
    }

    async fn restore_async_file(&mut self, file: tokio::fs::File) -> Result<()> {
        self.file = Some(file.into_std().await);
        Ok(())
    }

    fn current_len(&self) -> Result<u64> {
        Ok(self
            .file
            .as_ref()
            .context("image destination descriptor is unavailable")?
            .metadata()?
            .len())
    }

    fn final_sha256(&mut self) -> Result<String> {
        let digest = self
            .hasher
            .take()
            .context("image destination has already been verified")?
            .finalize();
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn commit(mut self) -> Result<()> {
        self.commit_with_hook(|| {})
    }

    #[cfg(target_os = "linux")]
    fn commit_with_hook(mut self, after_descriptor_link: impl FnOnce()) -> Result<()> {
        let file = self
            .file
            .take()
            .context("image destination descriptor is unavailable")?;
        file.sync_all()?;
        let retained = destination_identity(&file.metadata()?)?;
        if retained.device_inode() != self.partial_identity.device_inode()
            || !retained.single_link()
        {
            bail!("resumable image output identity changed before finalization");
        }

        let staging_name = descriptor_link_at(&self.directory, &file)?;
        let result = (|| {
            let linked = open_regular_at_allow_links(&self.directory, &staging_name)?
                .context("verified image descriptor link disappeared before finalization")?;
            let linked_identity = destination_identity_allow_links(&linked.metadata()?);
            if linked_identity.device_inode() != retained.device_inode()
                || linked_identity.links != 2
            {
                bail!("verified image descriptor link has an unexpected identity");
            }

            after_descriptor_link();
            if open_regular_at(&self.directory, &self.final_name, false)?.is_some() {
                bail!("final image destination appeared during download");
            }
            rustix::fs::renameat_with(
                &self.directory,
                &staging_name,
                &self.directory,
                &self.final_name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .context("atomically finalizing verified image download")?;

            let installed = open_regular_at_allow_links(&self.directory, &self.final_name)?
                .context("final image destination disappeared after finalization")?;
            if destination_identity_allow_links(&installed.metadata()?).device_inode()
                != retained.device_inode()
            {
                bail!("final image destination does not identify the verified descriptor");
            }

            if let Some(named) = open_regular_at_allow_links(&self.directory, &self.partial_name)?
                && destination_identity_allow_links(&named.metadata()?).device_inode()
                    == retained.device_inode()
            {
                rustix::fs::unlinkat(
                    &self.directory,
                    &self.partial_name,
                    rustix::fs::AtFlags::empty(),
                )
                .context("removing finalized resumable image name")?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ =
                rustix::fs::unlinkat(&self.directory, &staging_name, rustix::fs::AtFlags::empty());
        }
        result?;
        rustix::fs::fsync(&self.directory).context("syncing image output directory")?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn commit_with_hook(self, _after_descriptor_link: impl FnOnce()) -> Result<()> {
        bail!(
            "secure image finalization requires Linux; run `aos image download` on an AOS/Linux host"
        )
    }
}

#[cfg(target_os = "linux")]
fn descriptor_link_at(directory: &fs::File, file: &fs::File) -> Result<OsString> {
    static NEXT_LINK: AtomicU64 = AtomicU64::new(0);

    let descriptor_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    for _ in 0..32 {
        let sequence = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
        let staging_name = OsString::from(format!(
            ".aos-image-commit-{}-{sequence}",
            std::process::id()
        ));
        match rustix::fs::linkat(
            rustix::fs::CWD,
            descriptor_path.as_str(),
            directory,
            &staging_name,
            rustix::fs::AtFlags::SYMLINK_FOLLOW,
        ) {
            Ok(()) => return Ok(staging_name),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => {
                return Err(error)
                    .context("linking the verified image descriptor for finalization");
            }
        }
    }
    bail!("could not allocate a unique verified image finalization name")
}

fn destination_identity(metadata: &fs::Metadata) -> Result<DestinationIdentity> {
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        bail!("download output must not be hard-linked");
    }
    Ok(DestinationIdentity {
        len: metadata.len(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        links: metadata.nlink(),
    })
}

fn destination_identity_allow_links(metadata: &fs::Metadata) -> DestinationIdentity {
    DestinationIdentity {
        len: metadata.len(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        links: metadata.nlink(),
    }
}

impl DestinationIdentity {
    #[cfg(unix)]
    fn device_inode(self) -> (u64, u64) {
        (self.device, self.inode)
    }

    #[cfg(not(unix))]
    fn device_inode(self) -> u64 {
        self.len
    }

    #[cfg(unix)]
    fn single_link(self) -> bool {
        self.links == 1
    }

    #[cfg(not(unix))]
    fn single_link(self) -> bool {
        true
    }
}

fn open_regular_at(directory: &fs::File, name: &OsStr, truncate: bool) -> Result<Option<fs::File>> {
    let mut flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    if truncate {
        flags |= rustix::fs::OFlags::CREATE | rustix::fs::OFlags::TRUNC;
    }
    let descriptor = match rustix::fs::openat(
        directory,
        name,
        flags,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) if !truncate => return Ok(None),
        Err(error) => return Err(error).context("opening image output without symlink traversal"),
    };
    let file = fs::File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("download output must be a regular non-symlink file");
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        bail!("download output must not be hard-linked");
    }
    Ok(Some(file))
}

fn open_regular_at_allow_links(directory: &fs::File, name: &OsStr) -> Result<Option<fs::File>> {
    let descriptor = match rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(error).context("opening linked image output without symlink traversal");
        }
    };
    let file = fs::File::from(descriptor);
    if !file.metadata()?.is_file() {
        bail!("download output must be a regular non-symlink file");
    }
    Ok(Some(file))
}

fn validate_filename(filename: &str) -> Result<()> {
    if filename.is_empty()
        || filename.len() > 128
        || !filename.is_ascii()
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !filename
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || filename.contains("..")
    {
        bail!("Hub returned an unsafe image filename");
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("Hub returned an invalid image SHA-256");
    }
    Ok(())
}

fn validate_download_url(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("Hub returned an invalid image download URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("Hub returned an unsafe image download URL");
    }
    Ok(url)
}

fn same_origin(left: &reqwest::Url, right: &reqwest::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn reject_insecure_bearer(hub: &str, token: Option<&str>) -> Result<()> {
    let url = reqwest::Url::parse(hub).context("invalid Hub URL")?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if token.is_some() && url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!("refusing to send an image bearer token over non-HTTPS, non-loopback Hub transport");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_pagination_collects_every_page() {
        let mut pagination = ImagePagination::default();
        let mut first = SystemImage::default();
        first.filename = "first.raw".into();
        let mut second = SystemImage::default();
        second.filename = "second.qcow2".into();

        assert_eq!(
            pagination.accept(vec![first], "page-2".into()).unwrap(),
            Some("page-2".into())
        );
        assert_eq!(
            pagination.accept(vec![second], String::new()).unwrap(),
            None
        );
        assert_eq!(
            pagination
                .images
                .iter()
                .map(|image| image.filename.as_str())
                .collect::<Vec<_>>(),
            ["first.raw", "second.qcow2"]
        );
    }

    #[test]
    fn image_pagination_rejects_repeated_tokens_and_empty_middle_pages() {
        let mut repeated = ImagePagination::default();
        assert_eq!(
            repeated
                .accept(vec![SystemImage::default()], "again".into())
                .unwrap(),
            Some("again".into())
        );
        assert!(
            repeated
                .accept(vec![SystemImage::default()], "again".into())
                .is_err()
        );

        let mut empty = ImagePagination::default();
        assert!(empty.accept(Vec::new(), "next".into()).is_err());
    }

    #[test]
    fn filename_policy_is_portable_and_header_safe() {
        assert!(validate_filename("aos-server.qcow2").is_ok());
        for filename in [
            "../server.img",
            "server/image.img",
            "server\".img",
            "a..img",
        ] {
            assert!(validate_filename(filename).is_err());
        }
    }

    #[test]
    fn bearer_auth_is_scoped_to_the_hub_origin() {
        let hub = reqwest::Url::parse("https://hub.example/base/").unwrap();
        let proxied = reqwest::Url::parse("https://hub.example/images/object").unwrap();
        let storage = reqwest::Url::parse("https://storage.example/images/object").unwrap();
        assert!(same_origin(&hub, &proxied));
        assert!(!same_origin(&hub, &storage));
        assert!(reject_insecure_bearer("http://hub.example", Some("secret")).is_err());
        assert!(reject_insecure_bearer("http://localhost:8420", Some("secret")).is_err());
        assert!(reject_insecure_bearer("http://127.0.0.1:8420", Some("secret")).is_ok());
        assert!(reject_insecure_bearer("http://[::1]:8420", Some("secret")).is_ok());
        assert!(reject_insecure_bearer("https://hub.example", Some("secret")).is_ok());
    }

    #[test]
    fn download_url_rejects_embedded_credentials_and_fragments() {
        assert!(validate_download_url("https://images.example/object?signature=ok").is_ok());
        assert!(validate_download_url("https://token@images.example/object").is_err());
        assert!(validate_download_url("https://images.example/object#fragment").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_finalize_installs_retained_descriptor_after_early_name_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("disk.img");
        let destination = SecureDestination::open(&output, true).unwrap();
        let partial = temp.path().join(".disk.img.aos-part");
        let displaced = temp.path().join("displaced");
        std::fs::rename(&partial, &displaced).unwrap();
        std::fs::write(&partial, b"replacement").unwrap();
        destination.commit().unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"");
        assert_eq!(std::fs::read(&partial).unwrap(), b"replacement");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_finalize_survives_replacement_after_descriptor_link() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("disk.img");
        let destination = SecureDestination::open(&output, true).unwrap();
        let partial = temp.path().join(".disk.img.aos-part");
        let displaced = temp.path().join("displaced");
        destination
            .commit_with_hook(|| {
                std::fs::rename(&partial, &displaced).unwrap();
                std::fs::write(&partial, b"replacement").unwrap();
            })
            .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"");
        assert_eq!(std::fs::read(&partial).unwrap(), b"replacement");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_finalize_rejects_hardlinked_partial() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("disk.img");
        let destination = SecureDestination::open(&output, true).unwrap();
        std::fs::hard_link(
            temp.path().join(".disk.img.aos-part"),
            temp.path().join("alias"),
        )
        .unwrap();
        assert!(destination.commit().is_err());
        assert!(!output.exists());
    }
}
