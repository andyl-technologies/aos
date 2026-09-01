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
    TransferEvent, VerifiedPublicationCommit, VerifiedPublicationHook, VerifiedPublicationRequest,
    VerifiedPublicationResult, VerifiedPublicationSession, prepare_layout, read_verified_index,
    verify_layout, write_docker_archive, write_oci_archive, write_oci_layout,
};
use aos_oci_types::{
    ContainerRelease, ContainerSignatureInput, ManifestReference, RepositoryName, Sha256Digest,
    to_canonical_json,
};
use aos_remote::{HubClient, hub_rpc, hub_types};
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
            mount_from,
            hub,
            token,
        } => {
            push(
                source,
                reference,
                platform.as_deref(),
                mount_from,
                hub.as_deref(),
                token.as_deref(),
                printer,
            )
            .await
        }
        ContainerCommand::Publish {
            name,
            reference,
            release,
            release_layout,
            signature_input,
            registry,
            mount_from,
            expected_tag_resource_version,
            expected_tag_digest,
            idempotency_key,
            stage_only,
            registry_origin,
            registry_token,
            hub,
            token,
        } => {
            publish(
                PublishInput {
                    name,
                    reference,
                    release_path: release,
                    release_layout,
                    signature_input_path: signature_input,
                    registry,
                    mount_from,
                    expected_tag_resource_version: expected_tag_resource_version.as_deref(),
                    expected_tag_digest: expected_tag_digest.as_deref(),
                    idempotency_key,
                    stage_only: *stage_only,
                    registry_origin: registry_origin.as_deref(),
                    registry_token: registry_token.as_deref(),
                    hub: hub.as_deref(),
                    token: token.as_deref(),
                },
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
            None,
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
    mount_from: &[String],
    hub: Option<&str>,
    token: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let reference = RegistryReference::parse(reference)?;
    let selector = parse_platform(platform)?;
    let mount_from = parse_mount_sources(mount_from, &reference)?;
    let source_path = Path::new(source);
    if source_path.exists() {
        let prepared = prepare_layout(source_path)?;
        let published = push_layout(
            prepared.root(),
            &reference,
            selector,
            &mount_from,
            hub,
            token,
            printer,
        )
        .await?;
        return render_push_result(source, &reference, &published, printer);
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
    let published = push_layout(
        &produced.store_path,
        &reference,
        selector,
        &mount_from,
        hub,
        token,
        printer,
    )
    .await?;
    render_push_result(source, &reference, &published, printer)
}

struct PublishInput<'a> {
    name: &'a str,
    reference: &'a str,
    release_path: &'a Path,
    release_layout: &'a Path,
    signature_input_path: &'a Path,
    registry: &'a str,
    mount_from: &'a [String],
    expected_tag_resource_version: Option<&'a str>,
    expected_tag_digest: Option<&'a str>,
    idempotency_key: &'a str,
    stage_only: bool,
    registry_origin: Option<&'a str>,
    registry_token: Option<&'a str>,
    hub: Option<&'a str>,
    token: Option<&'a str>,
}

async fn publish(input: PublishInput<'_>, printer: &Printer) -> Result<()> {
    let PublishInput {
        name,
        reference,
        release_path,
        release_layout,
        signature_input_path,
        registry,
        mount_from,
        expected_tag_resource_version,
        expected_tag_digest,
        idempotency_key,
        stage_only,
        registry_origin,
        registry_token,
        hub,
        token,
    } = input;
    validate_definition_name(name)?;
    let reference = RegistryReference::parse(reference)?;
    ensure!(
        !registry.is_empty() && registry.len() <= 255,
        "--registry must contain 1..255 bytes"
    );
    ensure!(
        !idempotency_key.is_empty() && idempotency_key.len() <= 120,
        "--idempotency-key must contain 1..120 bytes"
    );
    let release_bytes = read_release_sidecar(release_path)?;
    let release = ContainerRelease::from_canonical_json(&release_bytes)
        .context("validating signed container release sidecar")?;
    ensure!(
        release.identity.image == name,
        "signed release image '{}' does not match definition '{name}'",
        release.identity.image
    );
    ensure!(
        release.nix.definition.attribute == format!("containerImages.{name}"),
        "signed release Nix attribute '{}' does not match container definition '{name}'",
        release.nix.definition.attribute
    );
    validate_signature_input(signature_input_path, &release)?;

    let target_tag = match reference.manifest_reference() {
        ManifestReference::Tag(tag) => Some(tag.to_string()),
        ManifestReference::Digest(digest) => {
            ensure!(
                digest == &release.oci.index.digest,
                "destination digest does not match the signed release index"
            );
            None
        }
    };
    ensure!(
        target_tag.is_some()
            || (expected_tag_resource_version.is_none() && expected_tag_digest.is_none()),
        "tag compare-and-swap inputs require a tagged destination"
    );
    ensure!(
        expected_tag_digest.is_none() || expected_tag_resource_version.is_some(),
        "--expected-tag-digest requires --expected-tag-resource-version"
    );
    let expected_tag_digest = expected_tag_digest
        .map(Sha256Digest::parse)
        .transpose()
        .context("parsing --expected-tag-digest")?;

    let mount_from = parse_mount_sources(mount_from, &reference)?;
    ensure!(
        release_layout.exists(),
        "signed release layout does not exist: {}",
        release_layout.display()
    );
    let prepared = prepare_layout(release_layout)
        .with_context(|| format!("opening signed release layout {}", release_layout.display()))?;
    let immutable_reference = RegistryReference::parse(&format!(
        "{}/{}@{}",
        reference.authority(),
        reference.repository(),
        release.oci.index.digest
    ))?;
    let default_registry_origin = immutable_reference.default_origin()?.to_string();
    let registry_origin = registry_origin.unwrap_or(&default_registry_origin);
    let control_access = if !stage_only || registry_token.is_none() {
        if hub.is_none() || token.is_none() {
            crate::commands::hub_auth::prepare_active_profile().await?;
        }
        let (control_origin, control_token) =
            crate::commands::hub_auth::resolve_access(hub, token)?;
        let control_token = control_token.context(
            "verified publication requires an authenticated Hub profile or explicit --token",
        )?;
        Some((control_origin, control_token))
    } else {
        None
    };
    let registry_token = match registry_token {
        Some(token) => token.to_string(),
        None => {
            let (control_origin, control_token) = control_access.as_ref().context(
                "staging requires --registry-token or same-origin authenticated Hub access",
            )?;
            publication_registry_token(registry_origin, control_origin, None, control_token)?
        }
    };
    let registry_client = RegistryClient::new(
        &immutable_reference,
        Some(registry_origin),
        Some(registry_token),
    )?;
    let cancellation = CancellationToken::new();
    let signal = cancellation_on_signal(cancellation.clone());
    let (events, reporter) = progress_reporter(printer, "Publishing");
    let options = PushOptions {
        source: prepared.root().to_path_buf(),
        // Complete release publication is platform-independent. This field is
        // unused by push_release_graph and remains part of the generic upload
        // options only for checkpoint/progress compatibility.
        platform: PlatformSelector::native(),
        state_directory: upload_state_directory(&immutable_reference)?,
        chunk_bytes: 4 * 1024 * 1024,
        cancellation: cancellation.clone(),
        events,
    };
    let graph = registry_client
        .push_release_graph(&immutable_reference, &options, &release, &mount_from)
        .await;
    drop(options);
    let report = finish_reporter(reporter).await;
    if let Err(error) = report {
        signal.abort();
        return Err(error);
    }
    let graph = match graph {
        Ok(graph) => graph,
        Err(error) => {
            signal.abort();
            return Err(error);
        }
    };

    if stage_only {
        signal.abort();
        let response = json!({
            "schema": OUTPUT_SCHEMA,
            "operation": "publish",
            "state": "staged",
            "name": name,
            "reference": reference.to_string(),
            "registry": registry,
            "release": release.identity.release,
            "index_digest": graph.root_index_digest,
            "object_count": graph.object_count,
            "tag_updated": false,
            "verification": "pending-control-plane-commit",
        });
        if !printer.json_if_active(&response) {
            printer.success(&format!(
                "Staged immutable release graph {} ({} objects); no tag was updated.",
                graph.root_index_digest, graph.object_count
            ));
        }
        return Ok(());
    }

    let (control_origin, control_token) = control_access
        .context("verified publication finalization requires authenticated Hub control access")?;
    let hub_client = HubClient::connect_with_token(&control_origin, &control_token)?;

    let target_kind = if target_tag.is_none()
        || target_tag.as_deref() == Some(release.identity.release.as_str())
    {
        "release"
    } else {
        "channel"
    };
    let request = VerifiedPublicationRequest {
        registry: registry.to_string(),
        repository: reference.repository().clone(),
        release,
        target_kind: target_kind.to_string(),
        target_tag,
        expected_tag_version: expected_tag_resource_version.map(str::to_owned),
        expected_tag_digest,
        idempotency_key: idempotency_key.to_string(),
    };
    let adapter = HubPublicationAdapter { client: hub_client };
    let publication = publish_verified(&adapter, &request, &cancellation)
        .await
        .context(
            "finalizing verified container publication; the canonical sidecar must already be committed and indexed through a signed AOS registry release",
        );
    signal.abort();
    let publication = publication?;

    ensure!(
        publication.root_index_digest == graph.root_index_digest,
        "Hub committed a different container index than the uploaded graph"
    );
    let response = json!({
        "schema": OUTPUT_SCHEMA,
        "operation": "publish",
        "name": name,
        "reference": reference.to_string(),
        "registry": registry,
        "release": request.release.identity.release,
        "publication_id": publication.publication_id,
        "resource_version": publication.resource_version,
        "verified_release_root": publication.verified_release_root,
        "index_digest": publication.root_index_digest,
        "target_tag": publication.target_tag,
        "topology_digest": publication.topology_digest,
        "required_placement_count": publication.required_placement_count,
        "source_kind": publication.source_kind,
        "object_count": graph.object_count,
        "verification": "verified",
    });
    if !printer.json_if_active(&response) {
        printer.success(&format!(
            "Published verified {} -> {}",
            publication.root_index_digest, reference
        ));
    }
    Ok(())
}

fn read_release_sidecar(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading signed release sidecar metadata {}", path.display()))?;
    ensure!(metadata.is_file(), "signed release sidecar is not a file");
    ensure!(
        metadata.len() <= 4 * 1024 * 1024,
        "signed release sidecar exceeds the 4 MiB limit"
    );
    let bytes = fs::read(path)
        .with_context(|| format!("reading signed release sidecar {}", path.display()))?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "signed release sidecar grew beyond the 4 MiB limit"
    );
    Ok(bytes)
}

fn validate_signature_input(path: &Path, release: &ContainerRelease) -> Result<()> {
    let bytes = read_bounded_json_file(path, "Nix signature input")?;
    let input = ContainerSignatureInput::from_canonical_json(&bytes)
        .with_context(|| format!("validating Nix signature input {}", path.display()))?;
    input
        .validate_final_release(release)
        .context("binding Nix signature input to the signed container release")
}

fn read_bounded_json_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading {label} metadata {}", path.display()))?;
    ensure!(metadata.is_file(), "{label} is not a file");
    ensure!(
        metadata.len() <= 4 * 1024 * 1024,
        "{label} exceeds the 4 MiB limit"
    );
    let bytes = fs::read(path).with_context(|| format!("reading {label} {}", path.display()))?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "{label} grew beyond the 4 MiB limit"
    );
    Ok(bytes)
}

struct HubPublicationAdapter {
    client: HubClient,
}

impl VerifiedPublicationHook for HubPublicationAdapter {
    async fn begin(
        &self,
        request: &VerifiedPublicationRequest,
        cancellation: &CancellationToken,
    ) -> Result<VerifiedPublicationSession> {
        ensure_publication_active(cancellation)?;
        let container_release_json = to_canonical_json(&request.release)?;
        let response = self
            .client
            .call_topology(
                hub_rpc::BeginContainerPublication,
                &hub_types::BeginContainerPublicationRequest {
                    registry: request.registry.clone(),
                    repository: request.repository.to_string(),
                    container_release_json,
                    target_tag: request.target_tag.clone().unwrap_or_default(),
                    expected_tag_resource_version: request
                        .expected_tag_version
                        .clone()
                        .unwrap_or_default(),
                    expected_tag_digest: request
                        .expected_tag_digest
                        .map(|digest| digest.to_string())
                        .unwrap_or_default(),
                    idempotency_key: request.idempotency_key.clone(),
                    target_kind: request.target_kind.clone(),
                },
            )
            .await?;
        publication_session(response)
    }

    async fn get(
        &self,
        publication_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<VerifiedPublicationSession> {
        ensure_publication_active(cancellation)?;
        let response = self
            .client
            .call_topology(
                hub_rpc::GetContainerPublication,
                &hub_types::GetContainerPublicationRequest {
                    publication_id: publication_id.to_string(),
                    registry: String::new(),
                },
            )
            .await?;
        publication_session(response)
    }

    async fn commit(
        &self,
        request: &VerifiedPublicationCommit,
        cancellation: &CancellationToken,
    ) -> Result<VerifiedPublicationResult> {
        ensure_publication_active(cancellation)?;
        let response = self
            .client
            .call_topology(
                hub_rpc::CommitContainerPublication,
                &hub_types::CommitContainerPublicationRequest {
                    publication_id: request.publication_id.clone(),
                    expected_resource_version: request.resource_version.clone(),
                    idempotency_key: request.idempotency_key.clone(),
                    confirmation_hash: request.confirmation_hash.to_string(),
                },
            )
            .await?;
        publication_result(response)
    }

    async fn abort(
        &self,
        publication_id: &str,
        resource_version: &str,
        idempotency_key: &str,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        ensure_publication_active(cancellation)?;
        let response = self
            .client
            .call_topology(
                hub_rpc::AbortContainerPublication,
                &hub_types::AbortContainerPublicationRequest {
                    publication_id: publication_id.to_string(),
                    expected_resource_version: resource_version.to_string(),
                    idempotency_key: idempotency_key.to_string(),
                },
            )
            .await?;
        ensure!(
            response.publication_id == publication_id && response.state == "aborted",
            "Hub did not confirm the requested container publication abort"
        );
        Ok(())
    }
}

fn publication_session(
    publication: hub_types::ContainerPublication,
) -> Result<VerifiedPublicationSession> {
    ensure!(
        !publication.publication_id.is_empty(),
        "Hub returned a container publication without an id"
    );
    ensure!(
        !publication.resource_version.is_empty(),
        "Hub returned a container publication without a resource version"
    );
    ensure!(
        !publication.state.is_empty(),
        "Hub returned a container publication without a state"
    );
    let (topology_digest, required_placement_count, source_kind) =
        publication_topology(&publication)?;
    Ok(VerifiedPublicationSession {
        publication_id: publication.publication_id,
        resource_version: publication.resource_version,
        expires_at: publication.expires_at,
        state: publication.state,
        confirmation_hash: Sha256Digest::parse(&publication.confirmation_hash)
            .context("Hub returned an invalid publication confirmation hash")?,
        topology_digest,
        required_placement_count,
        source_kind,
    })
}

fn publication_result(
    publication: hub_types::ContainerPublication,
) -> Result<VerifiedPublicationResult> {
    ensure!(
        publication.state == "ready",
        "Hub commit returned container publication state '{}'",
        publication.state
    );
    ensure!(
        !publication.verified_release_root.is_empty(),
        "Hub ready publication omitted its verified release root"
    );
    let root_index_digest = Sha256Digest::parse(&publication.root_digest)
        .context("Hub returned an invalid root index digest")?;
    let verified_release_root = Sha256Digest::parse(&publication.verified_release_root)
        .context("Hub returned an invalid verified release root")?;
    ensure!(
        verified_release_root == root_index_digest,
        "Hub verified release root differs from its container index"
    );
    let (topology_digest, required_placement_count, source_kind) =
        publication_topology(&publication)?;
    Ok(VerifiedPublicationResult {
        publication_id: publication.publication_id,
        resource_version: publication.resource_version,
        verified_release_root,
        root_index_digest,
        target_tag: (!publication.target_tag.is_empty()).then_some(publication.target_tag),
        topology_digest,
        required_placement_count,
        source_kind,
    })
}

fn publication_topology(
    publication: &hub_types::ContainerPublication,
) -> Result<(Sha256Digest, u64, String)> {
    let topology_digest = Sha256Digest::parse(&publication.topology_digest)
        .context("Hub returned an invalid publication topology digest")?;
    let required_placement_count = u64::try_from(publication.required_placement_count)
        .context("Hub returned a negative required placement count")?;
    ensure!(
        required_placement_count > 0,
        "Hub returned a publication without required placements"
    );
    ensure!(
        matches!(publication.source_kind.as_str(), "release" | "channel"),
        "Hub returned invalid publication source kind '{}'",
        publication.source_kind
    );
    Ok((
        topology_digest,
        required_placement_count,
        publication.source_kind.clone(),
    ))
}

async fn publish_verified(
    hook: &impl VerifiedPublicationHook,
    request: &VerifiedPublicationRequest,
    cancellation: &CancellationToken,
) -> Result<VerifiedPublicationResult> {
    let begun = hook.begin(request, cancellation).await?;
    let current = hook
        .get(&begun.publication_id, cancellation)
        .await
        .context(
            "publication began, but its current state could not be recovered; retry with the same --idempotency-key",
        )?;
    ensure!(
        current.publication_id == begun.publication_id,
        "Hub recovered a different container publication"
    );
    ensure!(
        current.topology_digest == begun.topology_digest
            && current.required_placement_count == begun.required_placement_count
            && current.source_kind == begun.source_kind,
        "Hub changed the frozen container publication topology"
    );
    if current.confirmation_hash != begun.confirmation_hash {
        abort_confirmed_publication(hook, request, &current, cancellation).await?;
        bail!("Hub changed the frozen container publication confirmation hash");
    }
    ensure!(
        current.state != "aborted",
        "container publication is already aborted"
    );

    let commit = VerifiedPublicationCommit {
        publication_id: current.publication_id.clone(),
        resource_version: current.resource_version.clone(),
        idempotency_key: publication_retry_key(&request.idempotency_key, "commit"),
        confirmation_hash: current.confirmation_hash,
    };
    match hook.commit(&commit, cancellation).await {
        Ok(result) => validate_publication_result(request, &current, result),
        Err(commit_error) => {
            let recovered = hook
                .get(&current.publication_id, cancellation)
                .await
                .with_context(|| {
                    format!(
                        "container publication commit failed ({commit_error:#}); its outcome is ambiguous, so it was not aborted; retry with the same --idempotency-key"
                    )
                })?;
            ensure!(
                recovered.publication_id == current.publication_id,
                "Hub recovered a different container publication after commit failure"
            );
            ensure!(
                recovered.confirmation_hash == current.confirmation_hash,
                "Hub changed the frozen container publication after commit failure; the ambiguous publication was not aborted"
            );
            if recovered.state == "ready" {
                let retry = VerifiedPublicationCommit {
                    publication_id: recovered.publication_id.clone(),
                    resource_version: recovered.resource_version.clone(),
                    idempotency_key: commit.idempotency_key,
                    confirmation_hash: recovered.confirmation_hash,
                };
                return hook
                    .commit(&retry, cancellation)
                    .await
                    .and_then(|result| validate_publication_result(request, &recovered, result))
                    .with_context(|| {
                        format!(
                            "container publication committed, but result recovery failed after the initial error: {commit_error:#}"
                        )
                    });
            }
            if recovered.state != "aborted" {
                abort_confirmed_publication(hook, request, &recovered, cancellation)
                    .await
                    .with_context(|| {
                        format!(
                            "container publication commit failed ({commit_error:#}) and safe abort also failed"
                        )
                    })?;
            }
            Err(commit_error).context("container publication was not committed and is aborted")
        }
    }
}

async fn abort_confirmed_publication(
    hook: &impl VerifiedPublicationHook,
    request: &VerifiedPublicationRequest,
    session: &VerifiedPublicationSession,
    cancellation: &CancellationToken,
) -> Result<()> {
    ensure!(
        session.state != "ready",
        "refusing to abort an already committed container publication"
    );
    if session.state == "aborted" {
        return Ok(());
    }
    hook.abort(
        &session.publication_id,
        &session.resource_version,
        &publication_retry_key(&request.idempotency_key, "abort"),
        cancellation,
    )
    .await
}

fn publication_retry_key(base: &str, operation: &str) -> String {
    format!("{base}:{operation}")
}

fn validate_publication_result(
    request: &VerifiedPublicationRequest,
    session: &VerifiedPublicationSession,
    result: VerifiedPublicationResult,
) -> Result<VerifiedPublicationResult> {
    ensure!(
        result.verified_release_root == request.release.oci.index.digest
            && result.root_index_digest == request.release.oci.index.digest,
        "Hub committed a verified release root different from the signed sidecar"
    );
    ensure!(
        result.target_tag == request.target_tag,
        "Hub committed a different target tag than requested"
    );
    ensure!(
        result.topology_digest == session.topology_digest
            && result.required_placement_count == session.required_placement_count,
        "Hub committed a different placement topology than the frozen publication"
    );
    ensure!(
        result.source_kind == request.target_kind && result.source_kind == session.source_kind,
        "Hub committed a different tag source kind than requested"
    );
    Ok(result)
}

fn ensure_publication_active(cancellation: &CancellationToken) -> Result<()> {
    ensure!(
        !cancellation.is_cancelled(),
        "container publication cancelled"
    );
    Ok(())
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
    reference: &RegistryReference,
    platform: PlatformSelector,
    mount_from: &[RepositoryName],
    hub: Option<&str>,
    token: Option<&str>,
    printer: &Printer,
) -> Result<aos_oci::PushResult> {
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
    let result = client
        .push_with_mounts(reference, &options, mount_from)
        .await;
    drop(options);
    finish_reporter(reporter).await?;
    signal.abort();
    result
}

fn render_push_result(
    source_label: &str,
    reference: &RegistryReference,
    published: &aos_oci::PushResult,
    printer: &Printer,
) -> Result<()> {
    let response = json!({
        "schema": OUTPUT_SCHEMA,
        "operation": "push",
        "source": source_label,
        "reference": reference.to_string(),
        "platform": published.image.platform,
        "index_digest": published.published_index_digest,
        "manifest_digest": published.image.manifest.digest,
    });
    if !printer.json_if_active(&response) {
        printer.success(&format!("Pushed {source_label} -> {reference}"));
    }
    Ok(())
}

fn parse_mount_sources(
    values: &[String],
    reference: &RegistryReference,
) -> Result<Vec<RepositoryName>> {
    let mut sources = values
        .iter()
        .map(|value| RepositoryName::parse(value).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    sources.retain(|source| source != reference.repository());
    sources.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    sources.dedup();
    Ok(sources)
}

async fn registry_client(
    reference: &RegistryReference,
    hub: Option<&str>,
    token: Option<&str>,
) -> Result<RegistryClient> {
    let (origin, token) = registry_access(reference, hub, token).await?;
    RegistryClient::new(reference, Some(&origin), token)
}

async fn registry_access(
    reference: &RegistryReference,
    hub: Option<&str>,
    token: Option<&str>,
) -> Result<(String, Option<String>)> {
    let default_origin = reference.default_origin()?.to_string();
    let selected_origin = hub.unwrap_or(&default_origin);
    if token.is_none() {
        crate::commands::hub_auth::prepare_registry_profile(selected_origin).await?;
    }
    crate::commands::hub_auth::resolve_registry_access(hub, token, &default_origin)
}

fn same_http_origin(left: &str, right: &str) -> Result<bool> {
    let left = url::Url::parse(left).context("parsing OCI Distribution origin")?;
    let right = url::Url::parse(right).context("parsing Hub control origin")?;
    Ok(left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default())
}

fn publication_registry_token(
    registry_origin: &str,
    control_origin: &str,
    explicit_registry_token: Option<&str>,
    control_token: &str,
) -> Result<String> {
    if let Some(token) = explicit_registry_token {
        return Ok(token.to_string());
    }
    ensure!(
        same_http_origin(registry_origin, control_origin)?,
        "OCI Distribution origin {registry_origin} differs from Hub control origin {control_origin}; provide a separate --registry-token"
    );
    Ok(control_token.to_string())
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
    use aos_oci_types::{
        Annotations, CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA,
        ContainerEvidenceMappingQualification, ContainerEvidenceQualification,
        ContainerEvidenceQualificationCheck, ContainerNixProvenance, ContainerOciRelease,
        ContainerReleaseEvidence, ContainerReleaseIdentity, Descriptor, MediaType,
        NixDefinitionIdentity, NixOutputIdentity, Platform,
    };
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::extract::State;
    use axum::http::{Request, Response, StatusCode};
    use axum::routing::any;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct MockPublicationHook {
        calls: Mutex<Vec<&'static str>>,
        fail_commit: bool,
    }

    struct ConnectPublicationState {
        calls: Mutex<Vec<String>>,
    }

    impl MockPublicationHook {
        fn session(&self) -> VerifiedPublicationSession {
            VerifiedPublicationSession {
                publication_id: "publication-1".to_string(),
                resource_version: "2".to_string(),
                expires_at: 1_800_000_000,
                state: "preparing".to_string(),
                confirmation_hash: Sha256Digest::digest(b"confirmation"),
                topology_digest: Sha256Digest::digest(b"topology"),
                required_placement_count: 2,
                source_kind: "channel".to_string(),
            }
        }

        fn record(&self, call: &'static str) {
            self.calls.lock().expect("call log").push(call);
        }
    }

    impl VerifiedPublicationHook for MockPublicationHook {
        async fn begin(
            &self,
            _request: &VerifiedPublicationRequest,
            _cancellation: &CancellationToken,
        ) -> Result<VerifiedPublicationSession> {
            self.record("begin");
            Ok(self.session())
        }

        async fn get(
            &self,
            _publication_id: &str,
            _cancellation: &CancellationToken,
        ) -> Result<VerifiedPublicationSession> {
            self.record("get");
            Ok(self.session())
        }

        async fn commit(
            &self,
            _request: &VerifiedPublicationCommit,
            _cancellation: &CancellationToken,
        ) -> Result<VerifiedPublicationResult> {
            self.record("commit");
            if self.fail_commit {
                bail!("deliberate commit rejection");
            }
            let request = publication_request();
            Ok(VerifiedPublicationResult {
                publication_id: "publication-1".to_string(),
                resource_version: "3".to_string(),
                verified_release_root: request.release.oci.index.digest,
                root_index_digest: request.release.oci.index.digest,
                target_tag: request.target_tag,
                topology_digest: Sha256Digest::digest(b"topology"),
                required_placement_count: 2,
                source_kind: "channel".to_string(),
            })
        }

        async fn abort(
            &self,
            _publication_id: &str,
            _resource_version: &str,
            _idempotency_key: &str,
            _cancellation: &CancellationToken,
        ) -> Result<()> {
            self.record("abort");
            Ok(())
        }
    }

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
    fn credential_reuse_requires_the_exact_same_http_origin() {
        assert!(
            same_http_origin("https://hub.example", "https://hub.example/").expect("same origin")
        );
        assert!(
            !same_http_origin("https://oci.example", "https://hub.example")
                .expect("different host")
        );
        assert!(
            !same_http_origin("https://hub.example", "http://hub.example")
                .expect("different scheme")
        );
        assert!(
            !same_http_origin("https://hub.example:8443", "https://hub.example")
                .expect("different port")
        );
        assert_eq!(
            publication_registry_token(
                "https://hub.example",
                "https://hub.example/",
                None,
                "hub-secret",
            )
            .expect("same-origin credential"),
            "hub-secret"
        );
        assert!(
            publication_registry_token(
                "https://oci.example",
                "https://hub.example",
                None,
                "hub-secret",
            )
            .is_err()
        );
        assert_eq!(
            publication_registry_token(
                "https://oci.example",
                "https://hub.example",
                Some("registry-secret"),
                "hub-secret",
            )
            .expect("explicit registry credential"),
            "registry-secret"
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

    #[tokio::test]
    async fn verified_publication_uses_begin_get_and_commit_in_order() {
        let hook = MockPublicationHook {
            calls: Mutex::new(Vec::new()),
            fail_commit: false,
        };
        let request = publication_request();
        let result = publish_verified(&hook, &request, &CancellationToken::new())
            .await
            .expect("verified publication");
        assert_eq!(result.root_index_digest, request.release.oci.index.digest);
        assert_eq!(result.required_placement_count, 2);
        assert_eq!(result.source_kind, "channel");
        assert_eq!(
            *hook.calls.lock().expect("call log"),
            ["begin", "get", "commit"]
        );
    }

    #[tokio::test]
    async fn verified_publication_aborts_only_after_confirming_nonterminal_state() {
        let hook = MockPublicationHook {
            calls: Mutex::new(Vec::new()),
            fail_commit: true,
        };
        let error = publish_verified(&hook, &publication_request(), &CancellationToken::new())
            .await
            .expect_err("deliberate commit failure");
        assert!(error.to_string().contains("aborted"));
        assert_eq!(
            *hook.calls.lock().expect("call log"),
            ["begin", "get", "commit", "get", "abort"]
        );
    }

    #[tokio::test]
    async fn hub_adapter_uses_typed_connect_lifecycle_and_control_credential() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Connect listener");
        let origin = format!(
            "http://{}/",
            listener.local_addr().expect("listener address")
        );
        let state = Arc::new(ConnectPublicationState {
            calls: Mutex::new(Vec::new()),
        });
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .fallback(any(connect_publication_response))
                    .with_state(server_state),
            )
            .await
            .expect("serve Connect fixture");
        });
        let adapter = HubPublicationAdapter {
            client: HubClient::connect_with_token(&origin, "control-secret").expect("Hub client"),
        };
        let request = publication_request();
        let result = publish_verified(&adapter, &request, &CancellationToken::new())
            .await
            .expect("Connect publication");
        assert_eq!(result.root_index_digest, request.release.oci.index.digest);
        assert_eq!(result.required_placement_count, 2);
        assert_eq!(result.source_kind, "channel");
        assert_eq!(
            *state.calls.lock().expect("Connect calls"),
            [
                "/aos.hub.v1.ContainerService/BeginContainerPublication",
                "/aos.hub.v1.ContainerService/GetContainerPublication",
                "/aos.hub.v1.ContainerService/CommitContainerPublication",
            ]
        );
        task.abort();
    }

    async fn connect_publication_response(
        State(state): State<Arc<ConnectPublicationState>>,
        request: Request<Body>,
    ) -> Response<Body> {
        assert_eq!(
            request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer control-secret")
        );
        assert_eq!(
            request
                .headers()
                .get("connect-protocol-version")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        let path = request.uri().path().to_string();
        let body = to_bytes(request.into_body(), 4 * 1024 * 1024)
            .await
            .expect("Connect request body");
        let body: Value = serde_json::from_slice(&body).expect("Connect request JSON");
        if path.ends_with("/BeginContainerPublication") {
            assert_eq!(body["registry"], "core");
            assert_eq!(body["repository"], "aos");
            assert_eq!(body["targetTag"], "stable");
            assert_eq!(body["targetKind"], "channel");
            assert_eq!(body["idempotencyKey"], "release-1");
            assert!(body["containerReleaseJson"].is_string());
        } else if path.ends_with("/CommitContainerPublication") {
            assert_eq!(body["expectedResourceVersion"], "2");
            assert_eq!(body["idempotencyKey"], "release-1:commit");
        }
        state
            .calls
            .lock()
            .expect("Connect calls")
            .push(path.clone());

        let ready = path.ends_with("/CommitContainerPublication");
        let root = publication_request().release.oci.index.digest.to_string();
        let response = json!({
            "publicationId": "publication-1",
            "registry": "core",
            "repository": "aos",
            "rootDigest": root,
            "catalogDigest": Sha256Digest::digest(b"catalog").to_string(),
            "state": if ready { "ready" } else { "preparing" },
            "targetTag": "stable",
            "resourceVersion": if ready { "3" } else { "2" },
            "expiresAt": "1800000000",
            "createdAt": "1700000000",
            "committedAt": if ready { "1700000001" } else { "0" },
            "confirmationHash": Sha256Digest::digest(b"confirmation").to_string(),
            "verifiedReleaseRoot": if ready { root } else { String::new() },
            "topologyDigest": Sha256Digest::digest(b"topology").to_string(),
            "requiredPlacementCount": "2",
            "sourceKind": "channel",
        });
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&response).expect("Connect response JSON"),
            ))
            .expect("Connect response")
    }

    fn publication_request() -> VerifiedPublicationRequest {
        VerifiedPublicationRequest {
            registry: "core".to_string(),
            repository: RepositoryName::parse("aos").expect("repository"),
            release: release_fixture(),
            target_tag: Some("stable".to_string()),
            target_kind: "channel".to_string(),
            expected_tag_version: None,
            expected_tag_digest: None,
            idempotency_key: "release-1".to_string(),
        }
    }

    fn release_fixture() -> ContainerRelease {
        let mut platform_manifest = descriptor(MediaType::OciImageManifest, "manifest");
        platform_manifest.platform = Some(Platform::linux_amd64());
        ContainerRelease {
            schema_version: 1,
            media_type: MediaType::AosContainerRelease,
            identity: ContainerReleaseIdentity {
                release: "1.0.0".to_string(),
                package: "aos".to_string(),
                package_version: "0.1.0".to_string(),
                image: "aos".to_string(),
            },
            oci: ContainerOciRelease {
                index: descriptor(MediaType::OciImageIndex, "index"),
                platform_manifests: vec![platform_manifest],
            },
            nix: ContainerNixProvenance {
                definition: NixDefinitionIdentity {
                    attribute: "containerImages.aos".to_string(),
                    derivation_path:
                        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container.drv".to_string(),
                },
                output: NixOutputIdentity {
                    name: "out".to_string(),
                    store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container"
                        .to_string(),
                },
                closure: evidence_descriptor(MediaType::AosNixClosure, "closure"),
            },
            qualification: ContainerEvidenceQualification {
                schema: CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA.to_string(),
                mapping: ContainerEvidenceMappingQualification {
                    complete: true,
                    unknown_paths: Vec::new(),
                },
                corresponding_source: ContainerEvidenceQualificationCheck {
                    complete: true,
                    unknown_paths: Vec::new(),
                },
                licensing: ContainerEvidenceQualificationCheck {
                    complete: true,
                    unknown_paths: Vec::new(),
                },
                ready_for_verified_publication: true,
            },
            evidence: ContainerReleaseEvidence {
                sbom: evidence_descriptor(MediaType::SpdxJson, "sbom"),
                source: evidence_descriptor(MediaType::AosSourceClosure, "source"),
                license: evidence_descriptor(MediaType::AosLicenseReport, "license"),
                provenance: evidence_descriptor(MediaType::InTotoJson, "provenance"),
                signature: evidence_descriptor(MediaType::DsseEnvelope, "signature"),
            },
        }
    }

    fn evidence_descriptor(artifact_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            artifact_type: Some(artifact_type),
            ..descriptor(MediaType::OciImageManifest, label)
        }
    }

    fn descriptor(media_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            media_type,
            digest: Sha256Digest::digest(label.as_bytes()),
            size: label.len() as u64,
            urls: Vec::new(),
            annotations: Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        }
    }
}
