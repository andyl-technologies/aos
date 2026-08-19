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
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aos_core::error::AosError;
use aos_core::output::{OutputMode, Printer, TransferProgress};
use aos_remote::hub::{HubClient, hub_rpc};
use aos_remote::hub_types::{ListImagesRequest, ResolveImageRequest, SystemImage};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;

use crate::cli::{ImageCommand, ImageDownloadArgs, ImageSelectionArgs};

const IMAGE_PAGE_SIZE: u32 = 1_000;
const MAX_IMAGE_RESULTS: usize = 100_000;
const MAX_IMAGE_PAGES: usize = 1_000;
const RETRY_BASE_DELAY: Duration = Duration::from_secs(1);

/// Runs an `aos image` command.
///
/// # Errors
///
/// Returns an error when selection, authentication, API decoding, local file
/// I/O, resume validation, or checksum verification fails.
pub async fn run(command: &ImageCommand, printer: &Printer) -> Result<()> {
    match command {
        ImageCommand::List(args) => {
            printer.info(&format!("Resolving images from {}...", args.selection.hub));
            let images = request_images(&args.selection, false).await?;
            if printer.json_if_active(&serde_json::to_value(&images)?) {
                return Ok(());
            }
            print_image_table(&images);
            Ok(())
        }
        ImageCommand::Show(args) => {
            printer.info(&format!("Resolving image from {}...", args.selection.hub));
            let image = resolve_image(&args.selection).await?;
            if !printer.json_if_active(&serde_json::to_value(&image)?) {
                print_image_details(&image);
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
    printer.info(&format!("Resolving image from {}...", args.selection.hub));
    let image = resolve_image(&args.selection).await?;
    validate_filename(&image.filename)?;
    validate_sha256(&image.sha256)?;
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(&image.filename));
    print_download_summary(&image, &output, printer)?;

    if existing_final_matches(&output, &image, printer)? {
        print_download_result(&output, &image, 0, Duration::ZERO, true, printer)?;
        return Ok(());
    }

    prepare_partial_identity(&output, &image, args.no_resume, printer)?;
    let mut transfer = printer.transfer("Checking partial download", image.byte_size);
    let mut destination = SecureDestination::open(&output, args.no_resume, Some(&transfer))?;
    let existing = destination.existing_len();
    if existing > image.byte_size {
        bail!("existing output is larger than the signed image size");
    }
    if existing < image.byte_size {
        transfer.phase("Downloading image");
        transfer.set_position(existing);
        let file = destination.take_async_file()?;
        let file =
            download_image_bytes(args, &image, &output, &mut destination, file, &transfer).await?;
        file.sync_all().await?;
        destination.restore_async_file(file).await?;
    }
    transfer.phase("Verifying SHA-256");
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
    let elapsed = transfer.elapsed();
    transfer.finish();
    print_download_result(&output, &image, existing, elapsed, false, printer)
}

async fn download_image_bytes(
    args: &ImageDownloadArgs,
    image: &SystemImage,
    output: &Path,
    destination: &mut SecureDestination,
    mut file: tokio::fs::File,
    transfer: &TransferProgress,
) -> Result<tokio::fs::File> {
    let download_url = validate_download_url(&image.download_url)?;
    let hub_url = reqwest::Url::parse(&args.selection.hub).context("invalid Hub URL")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .build()
        .context("building image download client")?;
    let mut attempt = 0_u32;

    loop {
        let current = file.metadata().await?.len();
        if current == image.byte_size {
            return Ok(file);
        }
        let mut request = client.get(download_url.clone());
        if same_origin(&hub_url, &download_url)
            && let Some(token) = &args.selection.token
        {
            request = request.bearer_auth(token);
        }
        if current > 0 {
            request = request.header(reqwest::header::RANGE, format!("bytes={current}-"));
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(error) if attempt < args.retries => {
                attempt += 1;
                retry_transfer(transfer, attempt, args.retries, &error.to_string()).await;
                continue;
            }
            Err(error) => return Err(error).context("downloading image bytes"),
        };
        validate_image_response(&response, current, image.byte_size)?;

        let mut stream = response.bytes_stream();
        let mut stream_error = None;
        loop {
            let next = tokio::select! {
                signal = tokio::signal::ctrl_c() => {
                    signal.context("installing image download interrupt handler")?;
                    file.sync_data().await.context("syncing interrupted image download")?;
                    let partial = partial_path(output)?;
                    return Err(AosError::Interrupted {
                        message: format!(
                            "download paused at {}; partial saved at {}; run the same command to resume",
                            human_bytes(file.metadata().await?.len()),
                            partial.display(),
                        ),
                    }
                    .into());
                }
                chunk = stream.next() => chunk,
            };
            let Some(chunk) = next else {
                break;
            };
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    stream_error = Some(error);
                    break;
                }
            };
            let new_size = file
                .metadata()
                .await?
                .len()
                .checked_add(chunk.len() as u64)
                .context("image response byte count overflow")?;
            if new_size > image.byte_size {
                bail!("image response exceeded the signed byte size");
            }
            destination.hash_bytes(&chunk);
            file.write_all(&chunk).await?;
            transfer.inc(chunk.len() as u64);
        }

        let current = file.metadata().await?.len();
        if stream_error.is_none() && current == image.byte_size {
            return Ok(file);
        }
        if attempt >= args.retries {
            if let Some(error) = stream_error {
                return Err(error).context("reading image response");
            }
            bail!(
                "image response ended at {}, before the signed size {}",
                human_bytes(current),
                human_bytes(image.byte_size),
            );
        }
        attempt += 1;
        let reason = stream_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "server ended the response early".to_string());
        retry_transfer(transfer, attempt, args.retries, &reason).await;
    }
}

fn validate_image_response(response: &reqwest::Response, existing: u64, total: u64) -> Result<()> {
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
        let expected_range = format!("bytes {existing}-{}/{total}", total - 1);
        if content_range != expected_range {
            bail!("resumed image response has inconsistent Content-Range");
        }
    }
    let expected_body = total - existing;
    if response
        .content_length()
        .is_some_and(|length| length != expected_body)
    {
        bail!("image response length does not match signed remaining byte count");
    }
    Ok(())
}

async fn retry_transfer(transfer: &TransferProgress, attempt: u32, retries: u32, reason: &str) {
    let exponent = attempt.saturating_sub(1).min(3);
    let delay = RETRY_BASE_DELAY.saturating_mul(2_u32.pow(exponent));
    transfer.warning(&format!(
        "transfer interrupted ({reason}); retrying in {}s (attempt {}/{})",
        delay.as_secs(),
        attempt + 1,
        retries + 1,
    ));
    tokio::time::sleep(delay).await;
}

fn existing_final_matches(output: &Path, image: &SystemImage, printer: &Printer) -> Result<bool> {
    let metadata = match fs::symlink_metadata(output) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", output.display()));
        }
    };
    if !metadata.file_type().is_file() {
        bail!("final image destination exists and is not a regular file");
    }
    if metadata.len() != image.byte_size {
        bail!(
            "final image destination already exists but has size {}, expected {}; choose another --output or remove it explicitly",
            human_bytes(metadata.len()),
            human_bytes(image.byte_size),
        );
    }

    let progress = printer.transfer("Checking existing image", image.byte_size);
    let mut file = fs::File::open(output)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        progress.inc(count as u64);
    }
    let actual = format!("{:x}", hasher.finalize());
    progress.finish();
    if actual != image.sha256 {
        bail!(
            "final image destination already exists but its SHA-256 does not match; choose another --output or remove it explicitly"
        );
    }
    Ok(true)
}

fn print_download_summary(image: &SystemImage, output: &Path, printer: &Printer) -> Result<()> {
    if matches!(printer.mode(), OutputMode::Quiet | OutputMode::Json) {
        return Ok(());
    }
    printer.header(&format!("{} {}", image.package, image.release));
    printer.plain(&format!(
        "  {} · {} · {}",
        image.architecture,
        image.format,
        human_bytes(image.byte_size),
    ));
    printer.plain(&format!("  -> {}", absolute_path(output)?.display()));
    if image.boot_verification != "verified" {
        printer.warning(&format!(
            "boot payload is {}; review firmware trust policy before booting",
            image.boot_verification,
        ));
    }
    Ok(())
}

fn print_download_result(
    output: &Path,
    image: &SystemImage,
    resumed_from: u64,
    elapsed: Duration,
    already_present: bool,
    printer: &Printer,
) -> Result<()> {
    let path = absolute_path(output)?;
    if printer.json_if_active(&serde_json::json!({
        "status": if already_present { "already_downloaded" } else { "downloaded" },
        "path": path,
        "release": image.release,
        "byteSize": image.byte_size,
        "sha256": image.sha256,
        "verified": true,
        "resumedFrom": resumed_from,
        "elapsedMs": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
    })) {
        return Ok(());
    }
    let verb = if already_present {
        "Already downloaded"
    } else {
        "Downloaded"
    };
    printer.success(&format!(
        "{verb} {} · {} in {}",
        output.display(),
        human_bytes(image.byte_size),
        format_duration(elapsed),
    ));
    printer.plain(&format!(
        "  Verified release · sha256:{}...",
        &image.sha256[..12]
    ));
    println!("{}", path.display());
    Ok(())
}

fn print_image_table(images: &[SystemImage]) {
    println!(
        "{:<20} {:<8} {:<7} {:<24} {:>10}  {:<9} {:<10}",
        "RELEASE", "ARCH", "FORMAT", "TARGETS", "SIZE", "RELEASE", "BOOT"
    );
    for image in images {
        println!(
            "{:<20} {:<8} {:<7} {:<24} {:>10}  {:<9} {:<10}",
            image.release,
            image.architecture,
            image.format,
            image.compatible_targets.join(","),
            human_bytes(image.byte_size),
            image.release_verification,
            image.boot_verification,
        );
    }
}

fn print_image_details(image: &SystemImage) {
    println!("{} {}", image.package, image.release);
    println!("  Architecture       {}", image.architecture);
    println!("  Format             {}", image.format);
    println!(
        "  Targets            {}",
        image.compatible_targets.join(", ")
    );
    println!("  Download size      {}", human_bytes(image.byte_size));
    println!("  Release signature  {}", image.release_verification);
    println!("  Boot payload       {}", image.boot_verification);
    println!("  SHA-256            {}", image.sha256);
    println!("  Filename           {}", image.filename);
}

fn partial_path(output: &Path) -> Result<PathBuf> {
    let filename = output
        .file_name()
        .context("image output must name a file")?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let mut partial = OsString::from(".");
    partial.push(filename);
    partial.push(".aos-part");
    Ok(parent.join(partial))
}

fn partial_identity_path(output: &Path) -> Result<PathBuf> {
    let partial = partial_path(output)?;
    let filename = partial
        .file_name()
        .context("partial image output must name a file")?;
    let mut identity = filename.to_os_string();
    identity.push(".json");
    Ok(partial.with_file_name(identity))
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PartialDownloadIdentity {
    schema_version: u32,
    package: String,
    release: String,
    architecture: String,
    format: String,
    byte_size: u64,
    sha256: String,
}

impl From<&SystemImage> for PartialDownloadIdentity {
    fn from(image: &SystemImage) -> Self {
        Self {
            schema_version: 1,
            package: image.package.clone(),
            release: image.release.clone(),
            architecture: image.architecture.clone(),
            format: image.format.clone(),
            byte_size: image.byte_size,
            sha256: image.sha256.clone(),
        }
    }
}

fn prepare_partial_identity(
    output: &Path,
    image: &SystemImage,
    restart: bool,
    printer: &Printer,
) -> Result<()> {
    let expected = PartialDownloadIdentity::from(image);
    let identity_path = partial_identity_path(output)?;
    let partial_exists = partial_path(output)?.exists();
    if let Some(found) = read_partial_identity(&identity_path)? {
        if found == expected && !restart {
            return Ok(());
        }
        if found != expected && !restart {
            bail!(
                "partial download belongs to {} {} ({}), but the selected image is {} {} ({}); choose another --output or restart with --no-resume",
                found.package,
                found.release,
                found.sha256.get(..12).unwrap_or(&found.sha256),
                expected.package,
                expected.release,
                expected.sha256.get(..12).unwrap_or(&expected.sha256),
            );
        }
        fs::remove_file(&identity_path)
            .with_context(|| format!("replacing {}", identity_path.display()))?;
    } else if partial_exists && !restart {
        printer.warning(
            "resuming a partial created by an older CLI; final size and SHA-256 will still be verified",
        );
    }

    let parent = identity_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating download identity in {}", parent.display()))?;
    serde_json::to_writer(temporary.as_file_mut(), &expected)
        .context("encoding partial download identity")?;
    use std::io::Write as _;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(&identity_path)
        .map_err(|error| error.error)
        .with_context(|| format!("installing {}", identity_path.display()))?;
    Ok(())
}

fn read_partial_identity(path: &Path) -> Result<Option<PartialDownloadIdentity>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    };
    if !metadata.file_type().is_file() {
        bail!("partial download identity must be a regular non-symlink file");
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        bail!("partial download identity must not be hard-linked");
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding {}", path.display()))
        .map(Some)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("resolving current directory")?
            .join(path))
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_duration(duration: Duration) -> String {
    if duration < Duration::from_secs(1) {
        format!("{}ms", duration.as_millis())
    } else {
        format!("{:.1}s", duration.as_secs_f64())
    }
}

/// Descriptor-relative destination state for resumable, atomic downloads.
struct SecureDestination {
    directory: fs::File,
    final_name: OsString,
    partial_name: OsString,
    identity_name: OsString,
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
    fn open(output: &Path, restart: bool, progress: Option<&TransferProgress>) -> Result<Self> {
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
        let mut identity_name = partial_name.clone();
        identity_name.push(".json");

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
                if let Some(progress) = progress {
                    progress.inc(count as u64);
                }
            }
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            directory,
            final_name,
            partial_name,
            identity_name,
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

    fn commit(self) -> Result<()> {
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
            let named = open_regular_at_allow_links(&self.directory, &self.partial_name)?
                .context("resumable image output name changed during finalization")?;
            let named_identity = destination_identity_allow_links(&named.metadata()?);
            if named_identity.device_inode() != retained.device_inode() || named_identity.links != 2
            {
                bail!("resumable image output name changed during finalization");
            }
            rustix::fs::unlinkat(
                &self.directory,
                &self.partial_name,
                rustix::fs::AtFlags::empty(),
            )
            .context("removing the verified resumable image name")?;
            if destination_identity_allow_links(&file.metadata()?).links != 1 {
                bail!("verified image acquired an unexpected hard link");
            }
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
            let installed_identity = destination_identity_allow_links(&installed.metadata()?);
            if installed_identity.device_inode() != retained.device_inode() {
                bail!("final image destination does not identify the verified descriptor");
            }
            if installed_identity.links != 1 {
                rustix::fs::unlinkat(
                    &self.directory,
                    &self.final_name,
                    rustix::fs::AtFlags::empty(),
                )
                .context("removing a hard-linked finalized image")?;
                bail!("final image acquired an unexpected hard link");
            }
            let _ = rustix::fs::unlinkat(
                &self.directory,
                &self.identity_name,
                rustix::fs::AtFlags::empty(),
            );
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
    #[cfg(target_vendor = "apple")]
    fn commit_with_hook(mut self, after_verified_link: impl FnOnce()) -> Result<()> {
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

        // Darwin has atomic RENAME_EXCL but no Linux-style AT_EMPTY_PATH link.
        // Pin the partial name with a hard link, then prove that link identifies
        // the already-verified open descriptor before it can become final.
        let staging_name = verified_named_link_at(&self.directory, &self.partial_name)?;
        let result = (|| {
            let linked = open_regular_at_allow_links(&self.directory, &staging_name)?
                .context("verified image link disappeared before finalization")?;
            let linked_identity = destination_identity_allow_links(&linked.metadata()?);
            let retained_identity = destination_identity_allow_links(&file.metadata()?);
            if linked_identity.device_inode() != retained.device_inode()
                || retained_identity.device_inode() != retained.device_inode()
                || linked_identity.links != 2
                || retained_identity.links != 2
            {
                bail!("verified image link does not identify the retained descriptor");
            }

            after_verified_link();
            let named = open_regular_at_allow_links(&self.directory, &self.partial_name)?
                .context("resumable image output name changed during finalization")?;
            let named_identity = destination_identity_allow_links(&named.metadata()?);
            if named_identity.device_inode() != retained.device_inode() || named_identity.links != 2
            {
                bail!("resumable image output name changed during finalization");
            }
            rustix::fs::unlinkat(
                &self.directory,
                &self.partial_name,
                rustix::fs::AtFlags::empty(),
            )
            .context("removing the verified resumable image name")?;
            if destination_identity_allow_links(&file.metadata()?).links != 1 {
                bail!("verified image acquired an unexpected hard link");
            }
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
            let installed_identity = destination_identity_allow_links(&installed.metadata()?);
            if installed_identity.device_inode() != retained.device_inode() {
                bail!("final image destination does not identify the verified descriptor");
            }
            if installed_identity.links != 1 {
                rustix::fs::unlinkat(
                    &self.directory,
                    &self.final_name,
                    rustix::fs::AtFlags::empty(),
                )
                .context("removing a hard-linked finalized image")?;
                bail!("final image acquired an unexpected hard link");
            }
            let _ = rustix::fs::unlinkat(
                &self.directory,
                &self.identity_name,
                rustix::fs::AtFlags::empty(),
            );
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

    #[cfg(all(not(target_os = "linux"), not(target_vendor = "apple")))]
    fn commit_with_hook(self, _after_descriptor_link: impl FnOnce()) -> Result<()> {
        bail!("secure image finalization is unsupported on this operating system")
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

#[cfg(target_vendor = "apple")]
fn verified_named_link_at(directory: &fs::File, partial_name: &OsStr) -> Result<OsString> {
    static NEXT_LINK: AtomicU64 = AtomicU64::new(0);

    for _ in 0..32 {
        let sequence = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
        let staging_name = OsString::from(format!(
            ".aos-image-commit-{}-{sequence}",
            std::process::id()
        ));
        match rustix::fs::linkat(
            directory,
            partial_name,
            directory,
            &staging_name,
            rustix::fs::AtFlags::empty(),
        ) {
            Ok(()) => return Ok(staging_name),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => {
                return Err(error).context("pinning the verified image name for finalization");
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
    let loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(_)) | None => false,
    };
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

    #[test]
    fn partial_identity_prevents_cross_release_resume() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("disk.img");
        let printer = Printer::new(0, true, false);
        let mut first = SystemImage {
            package: "aos".into(),
            release: "1.0.0".into(),
            architecture: "x86_64".into(),
            format: "qcow2".into(),
            byte_size: 1024,
            sha256: "a".repeat(64),
            ..SystemImage::default()
        };
        prepare_partial_identity(&output, &first, false, &printer).unwrap();
        fs::write(partial_path(&output).unwrap(), b"partial").unwrap();

        first.release = "1.0.1".into();
        first.sha256 = "b".repeat(64);
        let error = prepare_partial_identity(&output, &first, false, &printer).unwrap_err();
        assert!(error.to_string().contains("belongs to aos 1.0.0"));

        prepare_partial_identity(&output, &first, true, &printer).unwrap();
        assert_eq!(
            read_partial_identity(&partial_identity_path(&output).unwrap())
                .unwrap()
                .unwrap(),
            PartialDownloadIdentity::from(&first),
        );
    }

    #[test]
    fn partial_identity_rejects_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("disk.img");
        let identity = partial_identity_path(&output).unwrap();
        let target = temp.path().join("target");
        fs::write(&target, b"{}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &identity).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &identity).unwrap();

        assert!(read_partial_identity(&identity).is_err());
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn atomic_finalize_installs_one_verified_inode_without_overwrite() {
        use std::io::Write as _;

        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("disk.img");
        let mut destination = SecureDestination::open(&output, true, None).unwrap();
        destination
            .file
            .as_mut()
            .unwrap()
            .write_all(b"disk")
            .unwrap();
        destination.commit().unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"disk");
        assert!(!temp.path().join(".disk.img.aos-part").exists());
        assert_eq!(std::fs::metadata(&output).unwrap().nlink(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_finalize_rejects_early_name_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("disk.img");
        let destination = SecureDestination::open(&output, true, None).unwrap();
        let partial = temp.path().join(".disk.img.aos-part");
        let displaced = temp.path().join("displaced");
        std::fs::rename(&partial, &displaced).unwrap();
        std::fs::write(&partial, b"replacement").unwrap();
        assert!(destination.commit().is_err());
        assert!(!output.exists());
        assert_eq!(std::fs::read(&partial).unwrap(), b"replacement");
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn atomic_finalize_rejects_replacement_after_verified_link() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("disk.img");
        let destination = SecureDestination::open(&output, true, None).unwrap();
        let partial = temp.path().join(".disk.img.aos-part");
        let displaced = temp.path().join("displaced");
        assert!(
            destination
                .commit_with_hook(|| {
                    std::fs::rename(&partial, &displaced).unwrap();
                    std::fs::write(&partial, b"replacement").unwrap();
                })
                .is_err()
        );
        assert!(!output.exists());
        assert_eq!(std::fs::read(&partial).unwrap(), b"replacement");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_finalize_rejects_hardlinked_partial() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("disk.img");
        let destination = SecureDestination::open(&output, true, None).unwrap();
        std::fs::hard_link(
            temp.path().join(".disk.img.aos-part"),
            temp.path().join("alias"),
        )
        .unwrap();
        assert!(destination.commit().is_err());
        assert!(!output.exists());
    }
}
