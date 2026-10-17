//! Checks the actual installed tuple and distinct serving-helper observation.

use std::{
    io::Read as _,
    os::unix::fs::MetadataExt as _,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::direct_upload::{
    DirectWorkerInstallationMeasurement, DirectWorkerInstallationReport,
    DirectWorkerQualificationArtifact, direct_worker_emulated_script_id, valid_direct_digest,
};

use super::{
    assembly, files,
    observations::{ArtifactManifest, Namespace, NativeObservation, TupleFile},
    selection::*,
};

fn store_root(path: &Path, derivation: bool) -> bool {
    path.parent() == Some(Path::new("/nix/store"))
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.len() > 33
                    && name.as_bytes()[32] == b'-'
                    && name[..32]
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    && name.ends_with(".drv") == derivation
            })
}

pub(super) fn store_observer_image(path: &Path) -> Result<std::path::PathBuf> {
    if !std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Ok(path.to_owned());
    }

    // The source-built classic entry point is an exact sibling alias. Keep its
    // invocation name, but hash the regular executable without widening custody
    // for any installed business artifact or arbitrary symbolic-link chain.
    ensure!(
        path.file_name() == Some(std::ffi::OsStr::new("nix-store"))
            && std::fs::read_link(path)? == Path::new("nix"),
        "Mirror store observer has an unsupported executable alias"
    );
    Ok(path
        .parent()
        .context("Mirror store observer has no parent")?
        .join("nix"))
}

fn query_deriver(observer: &Path, file: &TupleFile) -> Result<()> {
    ensure!(
        store_root(&file.store_path, false)
            && store_root(&file.deriver, true)
            && file.file.starts_with(&file.store_path)
            && !file
                .file
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir)),
        "Mirror installed tuple path or deriver differs"
    );
    let mut child = Command::new(observer)
        .args(["--query", "--deriver"])
        .arg(&file.store_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let result = (|| -> Result<()> {
        let mut stdout = child
            .stdout
            .take()
            .context("Mirror store observer has no output")?;
        rustix::fs::fcntl_setfl(&stdout, rustix::fs::OFlags::NONBLOCK)?;
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            ensure!(
                Instant::now() < deadline,
                "Mirror store observer exceeded bound"
            );
            match stdout.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    ensure!(
                        bytes.len() + count <= 4096,
                        "Mirror store observer output exceeds bound"
                    );
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        }
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            ensure!(
                Instant::now() < deadline,
                "Mirror store observer did not exit"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        ensure!(
            status.success()
                && std::str::from_utf8(&bytes)?.trim()
                    == file
                        .deriver
                        .to_str()
                        .context("Mirror deriver is not text")?,
            "Mirror actual installed deriver differs from the retained tuple"
        );
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

pub(super) fn selected_installed(
    base: &Path,
    selected: &MirrorReviewFile,
    recorded: &TupleFile,
) -> Result<()> {
    ensure!(
        valid_direct_digest(&selected.sha256)
            && selected.byte_size > 0
            && base.join(&selected.path) == recorded.file
            && recorded.sha256 == selected.sha256
            && recorded.byte_size == selected.byte_size
            && files::hash_installed(&base.join(&selected.path))?
                == (selected.sha256.clone(), selected.byte_size),
        "Mirror selected installed bytes differ from the actual tuple"
    );
    Ok(())
}

pub(super) fn validate_namespace(
    namespace: &Namespace,
    selected: &ExternalMirrorReviewSelection,
) -> Result<()> {
    ensure!(
        namespace.version == 1
            && namespace.observation_scope == "selected_external_copy_namespace_readback"
            && !namespace.observed_at.is_empty()
            && namespace.runner_pid > 1
            && namespace.runner_start_ticks.parse::<u64>()? > 0
            && namespace.configuration_sha256 == selected.inputs.configuration.sha256
            && namespace.runner_sha256 == selected.inputs.runner.sha256
            && namespace.script_sha256 == selected.inputs.script.sha256
            && valid_direct_digest(&namespace.isolation_module_sha256)
            && valid_direct_digest(&namespace.miniflare_module_sha256)
            && !namespace.application_worker_name.is_empty()
            && !namespace.source_worker_name.is_empty()
            && namespace.persistence_root.is_absolute()
            && namespace.namespaces.len() == 2
            && namespace.participating_isolate_identity.is_none()
            && (namespace.source_worker_name == namespace.application_worker_name
                && namespace.source_trigger_exclusions.is_empty()
                || namespace.source_worker_name != namespace.application_worker_name
                    && namespace.source_trigger_exclusions
                        == ["queueProducers", "queueConsumers", "routes", "crons"]),
        "Mirror actual External namespace or selected installation differs"
    );
    for (binding, class) in [
        ("EXTERNAL_OBJECT_GUARD", "ExternalObjectGuard"),
        ("HYBRID_BINDING_STATE", "HybridBindingState"),
    ] {
        let rows = namespace
            .namespaces
            .iter()
            .filter(|row| row.binding_name == binding)
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1
                && rows[0].class_name == class
                && rows[0].worker_name == namespace.source_worker_name
                && !rows[0].namespace_key.is_empty()
                && rows[0].namespace_key.len() <= 512
                && rows[0].object_ids.len() <= 1024
                && rows[0].object_ids.iter().all(|id| valid_direct_digest(id)),
            "Mirror observed External physical namespace differs"
        );
    }
    Ok(())
}

fn process_pin(
    observed: &NativeObservation,
    selected: &MirrorReviewFile,
) -> Result<(u64, Vec<u8>)> {
    ensure!(
        observed.pid > 1
            && observed.arguments.len() <= 256
            && !observed.arguments.is_empty()
            && observed
                .arguments
                .iter()
                .all(|argument| !argument.contains('\0')),
        "Mirror Native process pin malformed"
    );
    let root = std::path::PathBuf::from(format!("/proc/{}", observed.pid));
    let stat = std::fs::read(root.join("stat"))?;
    ensure!(
        stat.len() <= 4096,
        "Mirror Native process stat exceeds bound"
    );
    let fields = std::str::from_utf8(&stat)?
        .rsplit_once(')')
        .context("Mirror Native process stat malformed")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    ensure!(
        fields.len() > 19
            && fields[0] != "Z"
            && fields[19] == observed.start_ticks
            && root.metadata()?.uid() == observed.owner_uid
            && observed.arguments[0]
                == selected
                    .path
                    .to_str()
                    .context("Mirror serving executable path is not text")?
            && std::fs::read_link(root.join("exe"))? == selected.path,
        "Mirror actual serving process lifetime, role or executable path differs"
    );
    let arguments = observed
        .arguments
        .iter()
        .flat_map(|argument| argument.as_bytes().iter().copied().chain([0]))
        .collect::<Vec<_>>();
    ensure!(
        arguments.len() <= 64 * 1024 && files::digest(&arguments) == observed.command_line_sha256,
        "Mirror Native argv observation differs"
    );
    let mut command_line = Vec::new();
    std::fs::File::open(root.join("cmdline"))?
        .take(64 * 1024 + 1)
        .read_to_end(&mut command_line)?;
    ensure!(
        command_line == arguments,
        "Mirror current Native argv differs from actual retained pin"
    );
    // CPU and scheduling fields legitimately change while the helper serves.
    // Compare the stable process lifetime and exact argv, rather than all stat bytes.
    Ok((fields[19].parse()?, command_line))
}

pub(super) fn validate_serving(
    base: &Path,
    selected: &ExternalMirrorReviewSelection,
    manifest: &ArtifactManifest,
) -> Result<()> {
    let observed: NativeObservation =
        assembly::document(base, &selected.inputs.native_observation)?;
    ensure!(
        observed.version == 1
            && observed.role == "controlled_external_oci_native_origin"
            && manifest.native_serving_role == observed.role
            && observed.executable_sha256 == selected.inputs.native_serving_executable.sha256
            && observed.common_source_store_path == manifest.common_source_store_path
            && observed.worker_source_store_path == manifest.worker_source_store_path
            && observed.serving_store_path == manifest.native_serving.store_path
            && observed.serving_deriver == manifest.native_serving.deriver
            && observed.input_sha256 == selected.inputs.native_input.sha256
            && observed.readiness_sha256 == selected.inputs.native_readiness.sha256,
        "Mirror actual serving-role observation differs from the common tuple"
    );
    let before = process_pin(&observed, &selected.inputs.native_serving_executable)?;
    selected_installed(
        base,
        &selected.inputs.native_serving_executable,
        &manifest.native_serving,
    )?;
    let input: serde_json::Value = assembly::document(base, &selected.inputs.native_input)?;
    let ready: serde_json::Value = assembly::document(base, &selected.inputs.native_readiness)?;
    let identity = &ready["identity"];
    ensure!(
        input["version"] == 1
            && input["workerSourceDigest"] == selected.source_digest
            && input["workerScriptVersion"] == selected.script_version
            && input["deploymentId"] == selected.deployment_id
            && input["publicOrigin"] == selected.public_origin
            && input["expectedExecutableSha256"] == observed.executable_sha256
            && ready["version"] == 1
            && ready["scope"] == observed.role
            && identity["pid"] == observed.pid
            && identity["startTicks"] == observed.start_ticks
            && identity["executableSha256"] == observed.executable_sha256
            && identity["executableBytes"] == selected.inputs.native_serving_executable.byte_size
            && identity["inputSha256"] == observed.input_sha256
            && identity["selectedWorkerSourceDigest"] == selected.source_digest
            && identity["selectedWorkerScriptVersion"] == selected.script_version
            && identity["publicOrigin"] == selected.public_origin,
        "Mirror actual helper constructor/readiness differs from its selected input"
    );
    for (field, selected_file) in [
        ("acceptanceFile", &selected.inputs.prerequisite_artifact),
        ("reviewKeysFile", &selected.inputs.prerequisite_review_keys),
    ] {
        let actual = input["files"]["direct"][field]
            .as_str()
            .context("Mirror helper Direct files absent")?;
        let bytes = files::private_bytes(Path::new(actual), 256 * 1024)?;
        ensure!(
            files::digest(&bytes) == selected_file.sha256
                && bytes.len() as u64 == selected_file.byte_size,
            "Mirror serving helper consumed a different Direct prerequisite selection"
        );
    }
    ensure!(
        process_pin(&observed, &selected.inputs.native_serving_executable)? == before,
        "Mirror actual Native serving process changed during review"
    );
    Ok(())
}

pub(super) fn validate(
    base: &Path,
    selected: &ExternalMirrorReviewSelection,
    prerequisite: &DirectWorkerQualificationArtifact,
    public: &str,
) -> Result<()> {
    let manifest: ArtifactManifest = assembly::document(base, &selected.inputs.artifact_manifest)?;
    ensure!(
        manifest.version == 1
            && store_root(&manifest.common_source_store_path, false)
            && store_root(&manifest.worker_source_store_path, false)
            && store_root(&manifest.native_source_store_path, false)
            && store_root(&manifest.worker_distribution_store_path, false)
            && files::digest(
                manifest
                    .worker_source_store_path
                    .as_os_str()
                    .as_encoded_bytes()
            ) == selected.source_digest
            && manifest.worker_source_digest == selected.source_digest
            && manifest.worker_script_version == selected.script_version
            && selected.script_version
                == direct_worker_emulated_script_id(&selected.source_digest)?
            && manifest.wasm.store_path == manifest.worker_distribution_store_path
            && manifest.script.store_path == manifest.worker_distribution_store_path,
        "Mirror actual common source or installed Worker tuple differs"
    );
    let observer = base.join(&selected.inputs.nix_store_executable.path);
    ensure!(
        observer.file_name() == Some(std::ffi::OsStr::new("nix-store"))
            && observer.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("bin"))
            && observer
                .parent()
                .and_then(Path::parent)
                .is_some_and(|root| store_root(root, false)),
        "Mirror store observer is not the selected immutable classic entry point"
    );
    let observer_image = store_observer_image(&observer)?;
    ensure!(
        files::hash_installed(&observer_image)?
            == (
                selected.inputs.nix_store_executable.sha256.clone(),
                selected.inputs.nix_store_executable.byte_size
            ),
        "Mirror actual source-built store observer differs"
    );
    for (actual, recorded) in [
        (&selected.inputs.wasm, &manifest.wasm),
        (&selected.inputs.script, &manifest.script),
        (&selected.inputs.runner, &manifest.runner),
        (
            &selected.inputs.runtime_executable,
            &manifest.runtime_executable,
        ),
        (
            &selected.inputs.native_serving_executable,
            &manifest.native_serving,
        ),
        (
            &selected.inputs.provider_conformance_executable,
            &manifest.provider_conformance,
        ),
    ] {
        selected_installed(base, actual, recorded)?;
        query_deriver(&observer, recorded)?;
    }
    // The ordinary Native release remains a separate observed tuple member.
    // Its bytes cannot substitute for the helper that actually serves this window.
    ensure!(
        files::hash_installed(&manifest.normal_native.file)?
            == (
                manifest.normal_native.sha256.clone(),
                manifest.normal_native.byte_size
            ),
        "Mirror common normal Native tuple bytes differ"
    );
    query_deriver(&observer, &manifest.normal_native)?;
    ensure!(
        store_observer_image(&observer)? == observer_image
            && files::hash_installed(&observer_image)?
                == (
                    selected.inputs.nix_store_executable.sha256.clone(),
                    selected.inputs.nix_store_executable.byte_size
                ),
        "Mirror source-built store observer changed during tuple queries"
    );
    let report: DirectWorkerInstallationReport =
        assembly::document(base, &selected.inputs.worker_installation)?;
    DirectWorkerInstallationMeasurement {
        observation_sha256: selected.inputs.worker_installation.sha256.clone(),
        report: report.clone(),
    }
    .validate(prerequisite)?;
    ensure!(
        report.wasm_sha256 == selected.inputs.wasm.sha256
            && report.wasm_byte_size.get() == selected.inputs.wasm.byte_size
            && report.shim_sha256 == selected.inputs.script.sha256
            && report.shim_byte_size.get() == selected.inputs.script.byte_size
            && report.runtime_bindings_sha256 == selected.inputs.configuration.sha256
            && report.runner_sha256.as_deref() == Some(&selected.inputs.runner.sha256)
            && report.runtime_executable_sha256.as_deref()
                == Some(&selected.inputs.runtime_executable.sha256),
        "Mirror actual installed report differs from reopened current files"
    );
    let namespace: Namespace = assembly::document(base, &selected.inputs.namespace)?;
    validate_namespace(&namespace, selected)?;
    validate_serving(base, selected, &manifest)?;
    ensure!(
        valid_direct_digest(public),
        "Mirror functional verifier malformed"
    );
    Ok(())
}
