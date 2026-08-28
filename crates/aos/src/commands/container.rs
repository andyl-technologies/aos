//! `aos container` - Nix-defined builds and daemon-free OCI artifact operations.
//!
//! Definition list/show/build create a [`NixRunner`] lazily. Local inspection,
//! archive conversion, registry pull, and registry push use `aos-oci` directly,
//! so they remain available in scratch containers and ordinary hosts without a
//! Nix daemon, Docker daemon, or AOS checkout.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use aos_core::nix::NixRunner;
use aos_core::output::{OutputMode, Printer, ProgressMode, TransferProgress};
use aos_oci::{
    ArtifactFormat, PlatformSelector, PullOptions, PushOptions, RegistryClient, RegistryReference,
    TransferEvent, prepare_layout, read_verified_index, verify_layout, write_docker_archive,
    write_oci_archive, write_oci_layout,
};
use aos_oci_types::{ManifestReference, RepositoryName};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::cli::{ContainerCommand, ContainerFormat};

const OUTPUT_SCHEMA: &str = "aos.container.cli/v1";

/// Dispatches the complete local container command family.
///
/// # Errors
///
/// Returns an error for invalid names/platforms/references, unavailable Nix on
/// definition operations, build failure, corrupt OCI content, unsafe output
/// replacement, authentication/transfer failure, or cancellation.
pub async fn run(command: &ContainerCommand, printer: &Printer) -> Result<()> {
    match command {
        ContainerCommand::List => list(printer),
        ContainerCommand::Show { name } => show(name, printer),
        ContainerCommand::Build {
            name,
            platform,
            format,
            output,
            remote,
            view,
            token,
        } => {
            build(
                name,
                platform.as_deref(),
                *format,
                output.as_deref(),
                remote.as_deref(),
                view,
                token.as_deref(),
                printer,
            )
            .await
        }
        ContainerCommand::Inspect {
            target,
            platform,
            raw,
            hub,
            token,
        } => {
            inspect(
                target,
                platform.as_deref(),
                *raw,
                hub.as_deref(),
                token.as_deref(),
                printer,
            )
            .await
        }
        ContainerCommand::Pull {
            reference,
            platform,
            format,
            output,
            force,
            hub,
            token,
        } => {
            pull(
                reference,
                platform.as_deref(),
                *format,
                output.as_deref(),
                *force,
                hub.as_deref(),
                token.as_deref(),
                printer,
            )
            .await
        }
        ContainerCommand::Push {
            source,
            reference,
            platform,
            hub,
            token,
        } => {
            push(
                source,
                reference,
                platform.as_deref(),
                hub.as_deref(),
                token.as_deref(),
                printer,
            )
            .await
        }
        ContainerCommand::Publish {
            name,
            reference,
            platform,
            hub,
            token,
        } => {
            publish(
                name,
                reference,
                platform.as_deref(),
                hub.as_deref(),
                token.as_deref(),
                printer,
            )
            .await
        }
    }
}

fn list(printer: &Printer) -> Result<()> {
    let nix = NixRunner::new(0, printer.mode() == OutputMode::Quiet)?;
    let definitions = nix
        .eval_json("containerDefinitions")
        .context("evaluating container definitions")?;
    let object = definitions
        .as_object()
        .context("containerDefinitions did not evaluate to an object")?;
    let containers = object
        .iter()
        .map(|(name, definition)| {
            json!({
                "name": name,
                "platform": definition.get("platform"),
                "publication": definition.get("publication"),
            })
        })
        .collect::<Vec<_>>();
    let output = json!({
        "schema": OUTPUT_SCHEMA,
        "operation": "list",
        "containers": containers,
    });
    if printer.json_if_active(&output) {
        return Ok(());
    }
    printer.header("Container definitions");
    for name in object.keys() {
        printer.plain(name);
    }
    Ok(())
}

fn show(name: &str, printer: &Printer) -> Result<()> {
    validate_definition_name(name)?;
    let nix = NixRunner::new(0, printer.mode() == OutputMode::Quiet)?;
    let definition = nix
        .eval_json(&format!("containerDefinitions.{name}"))
        .with_context(|| format!("evaluating container definition '{name}'"))?;
    let output = json!({
        "schema": OUTPUT_SCHEMA,
        "operation": "show",
        "container": definition,
    });
    if printer.json_if_active(&output) {
        return Ok(());
    }
    printer.header(&format!("Container: {name}"));
    render_definition(printer, &definition);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn build(
    name: &str,
    platform: Option<&str>,
    format: ContainerFormat,
    output: Option<&Path>,
    remote: Option<&str>,
    view: &str,
    token: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_definition_name(name)?;
    let selector = parse_platform(platform)?;
    let format = ArtifactFormat::from(format);
    let attr = build_attr(name, &selector, format)?;
    let nix = NixRunner::new(0, printer.mode() == OutputMode::Quiet)?;
    if let Some(remote) = remote {
        ensure_definition_platform(&nix, name, &selector)?;
        ensure!(
            output.is_none(),
            "--output is unavailable for remote builds because the artifact remains in the remote store"
        );
        let remote_result = crate::commands::build::run_remote_attr(
            &nix,
            printer,
            &attr,
            &format!("container {name} ({selector}, {format})"),
            remote,
            view,
            token,
        )
        .await?;
        let response = json!({
            "schema": OUTPUT_SCHEMA,
            "operation": "build",
            "name": name,
            "platform": selector,
            "format": format,
            "remote": remote,
            "derivation": remote_result.derivation,
            "success": remote_result.success,
            "message": remote_result.message,
        });
        printer.json_if_active(&response);
        return Ok(());
    }

    let output = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_build_output(name, format));
    let produced = build_local(&nix, name, &selector, format, Some(&output), printer)?;
    let response = json!({
        "schema": OUTPUT_SCHEMA,
        "operation": "build",
        "name": name,
        "platform": selector,
        "format": format,
        "output": output,
        "store_path": produced.store_path,
    });
    if !printer.json_if_active(&response) {
        printer.success(&format!("Built {name} -> {}", output.display()));
    }
    Ok(())
}

async fn inspect(
    target: &str,
    platform: Option<&str>,
    raw: bool,
    hub: Option<&str>,
    token: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let selector = parse_platform(platform)?;
    let path = Path::new(target);
    if path.exists() {
        return inspect_path(path, &selector, raw, printer);
    }

    if let Ok(reference) = RegistryReference::parse(target) {
        let temporary = tempfile::tempdir().context("creating registry inspection directory")?;
        let verified = pull_layout(
            &reference,
            temporary.path().to_path_buf(),
            selector,
            hub,
            token,
            printer,
        )
        .await?;
        return render_inspection(temporary.path(), target, &verified, raw, printer);
    }

    validate_definition_name(target).with_context(|| {
        "inspect target is neither an existing path, a registry reference, nor a definition name"
    })?;
    let nix = NixRunner::new(0, printer.mode() == OutputMode::Quiet)?;
    let produced = build_local(
        &nix,
        target,
        &selector,
        ArtifactFormat::OciLayout,
        None,
        printer,
    )?;
    inspect_path(&produced.store_path, &selector, raw, printer)
}

fn inspect_path(
    source: &Path,
    selector: &PlatformSelector,
    raw: bool,
    printer: &Printer,
) -> Result<()> {
    let prepared = prepare_layout(source)?;
    let verified = verify_layout(prepared.root(), Some(selector))?;
    render_inspection(
        prepared.root(),
        &source.display().to_string(),
        &verified,
        raw,
        printer,
    )
}

fn render_inspection(
    root: &Path,
    source: &str,
    verified: &aos_oci::VerifiedImage,
    raw: bool,
    printer: &Printer,
) -> Result<()> {
    if raw {
        let bytes = read_verified_index(root, &verified.index_digest)?;
        let value = std::str::from_utf8(&bytes).context("OCI index JSON is not UTF-8")?;
        printer.raw(value);
        return Ok(());
    }
    let output = json!({
        "schema": OUTPUT_SCHEMA,
        "operation": "inspect",
        "source": source,
        "image": verified,
    });
    if printer.json_if_active(&output) {
        return Ok(());
    }
    printer.header(&format!("Container artifact: {source}"));
    printer.kv(
        "Platform",
        &format!(
            "{}/{}",
            verified.platform.os, verified.platform.architecture
        ),
    );
    printer.kv("Index", &verified.index_digest.to_string());
    printer.kv("Manifest", &verified.manifest.digest.to_string());
    printer.kv("Layers", &verified.layers.len().to_string());
    printer.kv("Compressed bytes", &verified.compressed_bytes.to_string());
    printer.kv(
        "Uncompressed bytes",
        &verified.uncompressed_bytes.to_string(),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn pull(
    reference: &str,
    platform: Option<&str>,
    format: ContainerFormat,
    output: Option<&Path>,
    force: bool,
    hub: Option<&str>,
    token: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let reference = RegistryReference::parse(reference)?;
    let selector = parse_platform(platform)?;
    let format = ArtifactFormat::from(format);
    let output = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_pull_output(&reference, format));
    let prepared_output = prepare_pull_output(&output, format, force)?;

    let partial_layout = sibling_partial_layout(prepared_output.path(), &reference, &selector)?;
    let verified = pull_layout(
        &reference,
        partial_layout.clone(),
        selector.clone(),
        hub,
        token,
        printer,
    )
    .await?;
    match format {
        ArtifactFormat::OciLayout => {
            install_verified_layout(&partial_layout, &prepared_output)?;
        }
        ArtifactFormat::OciArchive => {
            write_pulled_archive(&prepared_output, |staging| {
                write_oci_archive(&partial_layout, staging)
            })?;
        }
        ArtifactFormat::DockerArchive => {
            let repository_tags = match reference.manifest_reference() {
                ManifestReference::Tag(_) => vec![reference.to_string()],
                ManifestReference::Digest(_) => Vec::new(),
            };
            write_pulled_archive(&prepared_output, |staging| {
                write_docker_archive(&partial_layout, staging, Some(&selector), &repository_tags)
                    .map(|_| ())
            })?;
        }
    }

    let response = json!({
        "schema": OUTPUT_SCHEMA,
        "operation": "pull",
        "reference": reference.to_string(),
        "platform": selector,
        "format": format,
        "output": output,
        "index_digest": verified.index_digest,
        "manifest_digest": verified.manifest.digest,
    });
    if !printer.json_if_active(&response) {
        printer.success(&format!("Pulled {} -> {}", reference, output.display()));
    }
    Ok(())
}

async fn push(
    source: &str,
    reference: &str,
    platform: Option<&str>,
    hub: Option<&str>,
    token: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let reference = RegistryReference::parse(reference)?;
    let selector = parse_platform(platform)?;
    let source_path = Path::new(source);
    if source_path.exists() {
        let prepared = prepare_layout(source_path)?;
        return push_layout(
            prepared.root(),
            source,
            &reference,
            selector,
            hub,
            token,
            printer,
        )
        .await;
    }

    validate_definition_name(source)
        .with_context(|| "push source is neither an existing OCI artifact nor a definition name")?;
    let nix = NixRunner::new(0, printer.mode() == OutputMode::Quiet)?;
    let produced = build_local(
        &nix,
        source,
        &selector,
        ArtifactFormat::OciLayout,
        None,
        printer,
    )?;
    push_layout(
        &produced.store_path,
        source,
        &reference,
        selector,
        hub,
        token,
        printer,
    )
    .await
}

async fn publish(
    name: &str,
    reference: &str,
    platform: Option<&str>,
    hub: Option<&str>,
    token: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_definition_name(name)?;
    let reference = RegistryReference::parse(reference)?;
    let selector = parse_platform(platform)?;
    let nix = NixRunner::new(0, printer.mode() == OutputMode::Quiet)?;
    let produced = build_local(
        &nix,
        name,
        &selector,
        ArtifactFormat::OciLayout,
        None,
        printer,
    )?;
    push_layout(
        &produced.store_path,
        name,
        &reference,
        selector,
        hub,
        token,
        printer,
    )
    .await
}

async fn pull_layout(
    reference: &RegistryReference,
    destination: PathBuf,
    platform: PlatformSelector,
    hub: Option<&str>,
    token: Option<&str>,
    printer: &Printer,
) -> Result<aos_oci::VerifiedImage> {
    let client = registry_client(reference, hub, token).await?;
    let cancellation = CancellationToken::new();
    let signal = cancellation_on_signal(cancellation.clone());
    let (events, reporter) = progress_reporter(printer, "Pulling");
    let options = PullOptions {
        destination,
        platform,
        cancellation,
        events,
    };
    let result = client.pull(reference, &options).await;
    drop(options);
    finish_reporter(reporter).await?;
    signal.abort();
    result
}

async fn push_layout(
    source: &Path,
    source_label: &str,
    reference: &RegistryReference,
    platform: PlatformSelector,
    hub: Option<&str>,
    token: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let client = registry_client(reference, hub, token).await?;
    let cancellation = CancellationToken::new();
    let signal = cancellation_on_signal(cancellation.clone());
    let (events, reporter) = progress_reporter(printer, "Pushing");
    let options = PushOptions {
        source: source.to_path_buf(),
        platform: platform.clone(),
        state_directory: upload_state_directory(reference)?,
        chunk_bytes: 4 * 1024 * 1024,
        cancellation,
        events,
    };
    let result = client.push(reference, &options).await;
    drop(options);
    finish_reporter(reporter).await?;
    signal.abort();
    let published = result?;

    let response = json!({
        "schema": OUTPUT_SCHEMA,
        "operation": "push",
        "source": source_label,
        "reference": reference.to_string(),
        "platform": platform,
        "index_digest": published.published_index_digest,
        "manifest_digest": published.image.manifest.digest,
    });
    if !printer.json_if_active(&response) {
        printer.success(&format!("Pushed {source_label} -> {reference}"));
    }
    Ok(())
}

async fn registry_client(
    reference: &RegistryReference,
    hub: Option<&str>,
    token: Option<&str>,
) -> Result<RegistryClient> {
    let default_origin = reference.default_origin()?.to_string();
    let selected_origin = hub.unwrap_or(&default_origin);
    if token.is_none() {
        crate::commands::hub_auth::prepare_registry_profile(selected_origin).await?;
    }
    let (origin, token) =
        crate::commands::hub_auth::resolve_registry_access(hub, token, &default_origin)?;
    RegistryClient::new(reference, Some(&origin), token)
}

struct BuildOutput {
    store_path: PathBuf,
}

fn build_local(
    nix: &NixRunner,
    name: &str,
    platform: &PlatformSelector,
    format: ArtifactFormat,
    output: Option<&Path>,
    printer: &Printer,
) -> Result<BuildOutput> {
    ensure_definition_platform(nix, name, platform)?;
    let attr = build_attr(name, platform, format)?;
    let activity = printer.activity(&format!("building {name} ({platform}, {format})"));
    let store_path = match format {
        ArtifactFormat::OciLayout => {
            let store_path = nix.build(&attr, None)?;
            let layout = if store_path.join("oci-layout").is_file() {
                store_path.clone()
            } else {
                store_path.join("layout")
            };
            ensure!(
                layout.join("oci-layout").is_file(),
                "built output does not contain an OCI layout"
            );
            if let Some(output) = output {
                atomic_symlink(&layout, output)?;
            }
            layout
        }
        ArtifactFormat::OciArchive | ArtifactFormat::DockerArchive => {
            let store_path = nix.build(&attr, None)?;
            if let Some(output) = output {
                let member = match format {
                    ArtifactFormat::OciArchive => "image.oci.tar",
                    ArtifactFormat::DockerArchive => "image.docker.tar",
                    ArtifactFormat::OciLayout => unreachable!(),
                };
                atomic_copy(&store_path.join(member), output)?;
            }
            store_path
        }
    };
    activity.finish_and_clear();
    Ok(BuildOutput { store_path })
}

fn ensure_definition_platform(
    nix: &NixRunner,
    name: &str,
    platform: &PlatformSelector,
) -> Result<()> {
    let requested = aos_system(platform)?;
    let value = nix
        .eval_json(&format!("containerDefinitions.{name}.platform.aosSystem"))
        .with_context(|| format!("evaluating exported platform for container '{name}'"))?;
    ensure!(
        value.as_str() == Some(requested),
        "container '{name}' is exported only for {}, not {platform}",
        value.as_str().unwrap_or("an invalid platform")
    );
    Ok(())
}

fn build_attr(name: &str, platform: &PlatformSelector, format: ArtifactFormat) -> Result<String> {
    validate_definition_name(name)?;
    let aos_system = aos_system(platform)?;
    let suffix = match format {
        ArtifactFormat::OciLayout | ArtifactFormat::OciArchive => "ociLayout",
        ArtifactFormat::DockerArchive => "dockerArchive",
    };
    Ok(format!(
        "containerImages.{name}.platforms.{aos_system}.{suffix}"
    ))
}

fn aos_system(platform: &PlatformSelector) -> Result<&'static str> {
    ensure!(
        platform.os == "linux" && platform.variant.is_none(),
        "AOS container builds support linux/amd64 and linux/arm64"
    );
    match platform.architecture.as_str() {
        "amd64" => Ok("x86_64-linux"),
        "arm64" => Ok("aarch64-linux"),
        _ => bail!("AOS container builds support linux/amd64 and linux/arm64"),
    }
}

fn parse_platform(value: Option<&str>) -> Result<PlatformSelector> {
    value.map_or_else(|| Ok(PlatformSelector::native()), PlatformSelector::parse)
}

fn validate_definition_name(name: &str) -> Result<()> {
    let name = RepositoryName::parse(name)?;
    ensure!(
        !name.as_str().contains('/'),
        "container definition names are one component"
    );
    Ok(())
}

fn render_definition(printer: &Printer, definition: &Value) {
    for key in [
        "name",
        "platform",
        "publication",
        "packageManagement",
        "budgets",
    ] {
        if let Some(value) = definition.get(key) {
            printer.kv(key, &compact_value(value));
        }
    }
}

fn compact_value(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn default_build_output(name: &str, format: ArtifactFormat) -> PathBuf {
    match format {
        ArtifactFormat::OciLayout => PathBuf::from(format!("result-container-{name}")),
        ArtifactFormat::OciArchive => PathBuf::from(format!("{name}.oci.tar")),
        ArtifactFormat::DockerArchive => PathBuf::from(format!("{name}.docker.tar")),
    }
}

fn default_pull_output(reference: &RegistryReference, format: ArtifactFormat) -> PathBuf {
    let base = reference
        .repository()
        .as_str()
        .rsplit('/')
        .next()
        .unwrap_or("image");
    match format {
        ArtifactFormat::OciLayout => PathBuf::from(format!("{base}.oci")),
        ArtifactFormat::OciArchive => PathBuf::from(format!("{base}.oci.tar")),
        ArtifactFormat::DockerArchive => PathBuf::from(format!("{base}.docker.tar")),
    }
}

struct PreparedPullOutput {
    path: PathBuf,
    parent: File,
    name: OsString,
    existing: Option<File>,
    format: ArtifactFormat,
}

impl PreparedPullOutput {
    fn path(&self) -> &Path {
        &self.path
    }

    fn install(&self, staging: &Path) -> Result<()> {
        let staging_relative = staging
            .strip_prefix(
                self.path
                    .parent()
                    .context("pull destination lacks a parent")?,
            )
            .context("pull staging path escaped its output directory")?;
        let flags = if self.existing.is_some() {
            rustix::fs::RenameFlags::EXCHANGE
        } else {
            rustix::fs::RenameFlags::NOREPLACE
        };
        rustix::fs::renameat_with(
            &self.parent,
            staging_relative,
            &self.parent,
            &self.name,
            flags,
        )
        .context("installing pulled artifact atomically")?;

        if let Some(existing) = &self.existing {
            let verified_displaced = (|| -> Result<()> {
                let displaced =
                    open_output_at(&self.parent, staging_relative.as_os_str(), self.format)?
                        .context("replaced pull destination disappeared")?;
                ensure!(
                    same_file(existing, &displaced)?,
                    "pull destination identity changed before replacement"
                );
                Ok(())
            })();
            if let Err(error) = verified_displaced {
                rustix::fs::renameat_with(
                    &self.parent,
                    staging_relative,
                    &self.parent,
                    &self.name,
                    rustix::fs::RenameFlags::EXCHANGE,
                )
                .context("restoring pull destination after an identity race")?;
                return Err(error);
            }
            match self.format {
                ArtifactFormat::OciLayout => fs::remove_dir_all(staging),
                ArtifactFormat::OciArchive | ArtifactFormat::DockerArchive => {
                    fs::remove_file(staging)
                }
            }
            .context("removing replaced pull destination")?;
        }
        rustix::fs::fsync(&self.parent).context("syncing pull output directory")?;
        Ok(())
    }
}

fn prepare_pull_output(
    output: &Path,
    format: ArtifactFormat,
    force: bool,
) -> Result<PreparedPullOutput> {
    let parent_path =
        fs::canonicalize(output_parent(output)).context("resolving pull output parent")?;
    let name = output
        .file_name()
        .context("pull destination lacks a file name")?
        .to_os_string();
    let parent = File::from(
        rustix::fs::open(
            &parent_path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .context("opening pull output parent")?,
    );
    let existing = open_output_at(&parent, &name, format)?;
    ensure!(
        existing.is_none() || force,
        "destination {} already exists; pass --force to replace it",
        output.display()
    );
    Ok(PreparedPullOutput {
        path: parent_path.join(&name),
        parent,
        name,
        existing,
        format,
    })
}

fn open_output_at(parent: &File, name: &OsStr, format: ArtifactFormat) -> Result<Option<File>> {
    let mut flags =
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    if format == ArtifactFormat::OciLayout {
        flags |= rustix::fs::OFlags::DIRECTORY;
    }
    let descriptor = match rustix::fs::openat(parent, name, flags, rustix::fs::Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(error).context("opening pull destination without following links");
        }
    };
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    ensure!(
        match format {
            ArtifactFormat::OciLayout => metadata.is_dir(),
            ArtifactFormat::OciArchive | ArtifactFormat::DockerArchive => metadata.is_file(),
        },
        "existing destination has the wrong artifact type"
    );
    #[cfg(unix)]
    if metadata.is_file() {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            metadata.nlink() == 1,
            "existing archive destination must not be hard-linked"
        );
    }
    Ok(Some(file))
}

fn same_file(expected: &File, actual: &File) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let expected = expected.metadata()?;
        let actual = actual.metadata()?;
        Ok(expected.dev() == actual.dev()
            && expected.ino() == actual.ino()
            && (!expected.is_file() || actual.nlink() == 1))
    }
    #[cfg(not(unix))]
    Ok(expected.metadata()?.len() == actual.metadata()?.len())
}

fn sibling_partial_layout(
    output: &Path,
    reference: &RegistryReference,
    platform: &PlatformSelector,
) -> Result<PathBuf> {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .context("archive output file name is not UTF-8")?;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(reference.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(platform.to_string().as_bytes());
    let identity = hex::encode(hasher.finalize());
    Ok(output.with_file_name(format!(".{name}.aos-oci-pull-{}", &identity[..16])))
}

fn install_verified_layout(source: &Path, output: &PreparedPullOutput) -> Result<()> {
    let parent = output
        .path
        .parent()
        .context("OCI layout output lacks a parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".aos-oci-layout-")
        .tempdir_in(parent)
        .context("creating OCI layout staging directory")?;
    write_oci_layout(source, staging.path())?;
    let staging_path = staging.keep();
    output.install(&staging_path)
}

fn write_pulled_archive(
    output: &PreparedPullOutput,
    write: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let parent = output
        .path
        .parent()
        .context("archive output lacks a parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".aos-oci-archive-")
        .tempdir_in(parent)
        .context("creating archive staging directory")?;
    let artifact = staging.path().join("artifact");
    write(&artifact)?;
    let staging = staging.keep();
    let artifact = staging.join("artifact");
    output.install(&artifact)?;
    fs::remove_dir(&staging).context("removing empty archive staging directory")
}

fn atomic_copy(source: &Path, output: &Path) -> Result<()> {
    let parent = output_parent(output);
    ensure!(parent.is_dir(), "output parent does not exist");
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("creating temporary output")?;
    let mut input = fs::File::open(source)
        .with_context(|| format!("opening built artifact {}", source.display()))?;
    std::io::copy(&mut input, temporary.as_file_mut()).context("copying built artifact")?;
    temporary
        .as_file_mut()
        .sync_all()
        .context("syncing built artifact")?;
    temporary
        .persist(output)
        .map_err(|error| error.error)
        .with_context(|| format!("persisting {}", output.display()))?;
    Ok(())
}

fn atomic_symlink(source: &Path, output: &Path) -> Result<()> {
    let parent = output_parent(output);
    ensure!(parent.is_dir(), "output parent does not exist");
    let temporary_directory = tempfile::Builder::new()
        .prefix(".aos-container-link-")
        .tempdir_in(parent)
        .context("creating private output-link staging directory")?;
    let temporary = temporary_directory.path().join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(source, &temporary).context("creating temporary output symlink")?;
    #[cfg(not(unix))]
    return Err(anyhow::anyhow!(
        "OCI layout output links require a Unix host"
    ));
    fs::rename(&temporary, output)
        .with_context(|| format!("installing output link {}", output.display()))?;
    Ok(())
}

fn upload_state_directory(reference: &RegistryReference) -> Result<PathBuf> {
    let cache = if let Some(path) = env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(path)
    } else if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home).join(".cache")
    } else {
        bail!("HOME or XDG_CACHE_HOME is required for resumable upload state");
    };
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(reference.authority().as_bytes());
    hasher.update(b"\0");
    hasher.update(reference.repository().as_str().as_bytes());
    Ok(cache
        .join("aos/oci/uploads")
        .join(hex::encode(hasher.finalize())))
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn cancellation_on_signal(cancellation: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancellation.cancel();
        }
    })
}

fn progress_reporter(
    printer: &Printer,
    action: &'static str,
) -> (
    Option<mpsc::UnboundedSender<TransferEvent>>,
    Option<JoinHandle<()>>,
) {
    if printer.mode() == OutputMode::Json
        || printer.mode() == OutputMode::Quiet
        || printer.progress_mode() == ProgressMode::Off
    {
        return (None, None);
    }
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let printer = printer.clone();
    let reporter = tokio::spawn(async move {
        let mut progress = BTreeMap::<String, TransferProgress>::new();
        while let Some(event) = receiver.recv().await {
            match event {
                TransferEvent::Checking { .. } => {}
                TransferEvent::Downloading {
                    digest,
                    offset,
                    total,
                }
                | TransferEvent::Uploading {
                    digest,
                    offset,
                    total,
                } => {
                    let short = digest.get(..19).unwrap_or(&digest).to_string();
                    progress
                        .entry(digest)
                        .or_insert_with(|| printer.transfer(&format!("{action} {short}"), total))
                        .set_position(offset);
                }
                TransferEvent::Complete { digest, .. } => {
                    if let Some(progress) = progress.remove(&digest) {
                        progress.finish();
                    }
                }
            }
        }
    });
    (Some(sender), Some(reporter))
}

async fn finish_reporter(reporter: Option<JoinHandle<()>>) -> Result<()> {
    if let Some(reporter) = reporter {
        reporter
            .await
            .context("OCI progress reporter task failed")?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn exact_path_wins_and_missing_slash_values_are_definitions() {
        let directory = tempfile::tempdir().expect("temporary path");
        let local = directory.path().join("registry.example/aos:latest");
        fs::create_dir_all(&local).expect("path fixture");
        assert!(local.exists());
        assert!(RegistryReference::parse("aos").is_err());
        validate_definition_name("aos").expect("definition");
    }

    #[test]
    fn build_attributes_are_closed_platform_mappings() {
        assert_eq!(
            build_attr(
                "aos",
                &PlatformSelector::parse("linux/amd64").expect("platform"),
                ArtifactFormat::OciLayout,
            )
            .expect("attribute"),
            "containerImages.aos.platforms.x86_64-linux.ociLayout"
        );
        assert!(
            build_attr(
                "aos",
                &PlatformSelector::parse("linux/riscv64").expect("platform"),
                ArtifactFormat::OciLayout,
            )
            .is_err()
        );
    }

    #[test]
    fn partial_archive_path_is_hidden_and_sibling_scoped() {
        let partial = sibling_partial_layout(
            Path::new("output/aos.oci.tar"),
            &RegistryReference::parse("registry.example/aos:latest").expect("reference"),
            &PlatformSelector::parse("linux/amd64").expect("platform"),
        )
        .expect("partial");
        assert_eq!(partial.parent(), Some(Path::new("output")));
        let name = partial
            .file_name()
            .and_then(|name| name.to_str())
            .expect("name");
        assert!(name.starts_with(".aos.oci.tar.aos-oci-pull-"));
        assert_eq!(name.len(), ".aos.oci.tar.aos-oci-pull-".len() + 16);
    }

    #[test]
    fn force_validation_preserves_the_existing_artifact() {
        let directory = tempfile::tempdir().expect("output directory");
        let output = directory.path().join("image.oci");
        fs::create_dir(&output).expect("existing layout");
        let sentinel = output.join("keep-me");
        fs::write(&sentinel, b"original").expect("sentinel");

        prepare_pull_output(&output, ArtifactFormat::OciLayout, true)
            .expect("validate force destination");
        assert_eq!(
            fs::read(&sentinel).expect("preserved sentinel"),
            b"original"
        );
    }

    #[test]
    fn atomic_install_refuses_a_destination_identity_swap() {
        let directory = tempfile::tempdir().expect("output directory");
        let output = directory.path().join("image.oci");
        fs::create_dir(&output).expect("existing layout");
        let prepared =
            prepare_pull_output(&output, ArtifactFormat::OciLayout, true).expect("prepared output");

        let original = directory.path().join("original");
        fs::rename(&output, &original).expect("move original layout");
        fs::create_dir(&output).expect("racing replacement");
        fs::write(output.join("attacker"), b"preserve").expect("replacement marker");
        let staging = directory.path().join("staging");
        fs::create_dir(&staging).expect("staging layout");

        assert!(prepared.install(&staging).is_err());
        assert_eq!(
            fs::read(output.join("attacker")).expect("replacement preserved"),
            b"preserve"
        );
        assert!(staging.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn pull_output_rejects_even_broken_symlinks() {
        let directory = tempfile::tempdir().expect("output directory");
        let output = directory.path().join("image.oci");
        std::os::unix::fs::symlink("missing", &output).expect("broken output symlink");
        assert!(prepare_pull_output(&output, ArtifactFormat::OciLayout, true).is_err());
    }
}
