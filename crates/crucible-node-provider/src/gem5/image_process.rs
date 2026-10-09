//! Genuine stopped process-image capture and fresh private controller rebinding.

use std::{
    fs,
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
};

use crucible_node_contract::Id;
use serde_json::json;

use super::{connect, exchange_read, path_text};
use crate::ProviderError;
use crate::gem5::images::{measure_file, validate_private_directory};
use crate::gem5::protocol::Ready;
use crate::gem5::{
    GEM5_NATIVE_PROTOCOL, Gem5CapturedImage, Gem5CustodySlot, Gem5NativeCustody, Gem5NativeProcess,
    Gem5RestoreTarget,
};

#[path = "saved_files_manifest.rs"]
mod saved_files_manifest;

impl Gem5NativeProcess {
    /// Captures genuine native process custody at the unchanged stopped boundary.
    ///
    /// `preserved_root` must be an empty private directory. Transport descriptors
    /// are closed before image creation and the original source must reconnect.
    /// Native CPU/profile qualification is separate from this mechanical capture.
    ///
    /// # Errors
    /// Rejects missing tools, uncertain effects, occupied resource preservation,
    /// failed original reconnection, changed native state or unpinned artifacts.
    pub fn capture(
        &mut self,
        capture: Id,
        preserved_root: &Path,
    ) -> Result<Gem5CapturedImage, ProviderError> {
        if self.unresolved.is_some()
            || self.unresolved_capture.is_some()
            || self.launch.process_images.is_none()
        {
            return Err(ProviderError::Conflict(
                "gem5 process capture lacks stopped native custody",
            ));
        }
        validate_private_directory(preserved_root)?;
        if fs::read_dir(preserved_root)?.next().is_some() {
            return Err(ProviderError::Conflict(
                "gem5 capture preservation root occupied",
            ));
        }
        self.unresolved_capture = Some(capture.clone());
        let response = self.exchange(json!({"kind":"capture","capture":capture}))?;
        if response != json!({"kind":"capture_ready","capture":capture,"boundary":self.boundary}) {
            return Err(ProviderError::Correlation(
                "gem5 original capture cut differs",
            ));
        }
        self.stream = None;
        let child = self.child.as_mut().ok_or(ProviderError::Correlation(
            "gem5 captured native child omitted",
        ))?;
        let listener = self.listener.as_ref().ok_or(ProviderError::Correlation(
            "gem5 captured original endpoint omitted",
        ))?;
        let mut stream = connect(listener, child, self.launch.timeout)?;
        let ready: Ready = serde_json::from_value(exchange_read(&mut stream, self.launch.timeout)?)
            .map_err(|_| ProviderError::Frame("gem5 captured native readiness shape"))?;
        if ready.kind != "ready"
            || ready.schema != GEM5_NATIVE_PROTOCOL
            || ready.owner != self.launch.owner
            || ready.incarnation != self.launch.incarnation
            || ready.generation != self.launch.generation
            || ready.continuation != "captured"
            || ready.boundary != self.boundary
        {
            return Err(ProviderError::Correlation(
                "gem5 captured original native lineage differs",
            ));
        }
        self.stream = Some(stream);
        let image = Gem5CapturedImage::collect(
            capture,
            self.launch.clone(),
            self.boundary.clone(),
            preserved_root,
            self.completed.clone(),
            self.pending.clone(),
            self.last_acknowledged.clone(),
        )?;
        self.unresolved_capture = None;
        Ok(image)
    }

    /// Reconstructs exact captured native state behind a fresh private controller gate.
    ///
    /// Every retained original output/request remains unchanged. Fresh owner
    /// identity is operational authority; no native event runs during rebinding.
    /// Whole-world restoration must still authenticate and publish its activation
    /// before any public CNP grant is accepted.
    ///
    /// # Errors
    /// Rejects missing or tampered artifacts, stale identities, occupied private
    /// roots, unproved actual native peer/code mappings or changed event state.
    /// After spawning, all failures transfer actual child custody to supervision.
    pub fn restore(
        image: &Gem5CapturedImage,
        target: Gem5RestoreTarget,
        supervisor: Box<dyn Gem5CustodySlot>,
    ) -> Result<Self, ProviderError> {
        if target.incarnation == image.source.incarnation
            || target.generation <= image.source.generation
            || target.timeout.is_zero()
        {
            return Err(ProviderError::Correlation(
                "gem5 fresh restore identity is stale",
            ));
        }
        validate_private_directory(&target.temporary_root)?;
        validate_private_directory(&target.image_root)?;
        if fs::read_dir(&target.image_root)?.next().is_some()
            || target.image_root.starts_with(&target.resource_root)
            || target.resource_root.starts_with(&target.image_root)
            || target.image_root.starts_with(&target.temporary_root)
            || target.temporary_root.starts_with(&target.image_root)
        {
            return Err(ProviderError::Correlation(
                "gem5 fresh capture namespace is occupied or shared",
            ));
        }
        image.prepare_resources(&target.resource_root)?;
        let tools = image
            .source
            .process_images
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "gem5 captured tool custody omitted",
            ))?;
        for artifact in [
            &image.source.executable,
            &tools.launcher,
            &tools.restarter,
            &tools.reconstruction_executable,
            &tools.resource_helper,
        ] {
            if measure_file(&artifact.path)? != artifact.content {
                return Err(ProviderError::Correlation(
                    "gem5 restore installed native image scope changed",
                ));
            }
        }
        let image_path = image.process_image()?;
        // DMTCP's saved-file copy paths belong to the original image, whereas
        // the next capture directory belongs to this new incarnation. Only the
        // authenticated complete image supplies the old spelling and the
        // privately materialized destination; no old path is opened here.
        let supplementary_root = image.materialized_supplementary_files_root()?;
        let supplementary_manifest =
            saved_files_manifest::write(image, &supplementary_root, &target.temporary_root)?;
        let socket = target.resource_root.join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let stdout = fs::File::options()
            .write(true)
            .create_new(true)
            .open(target.temporary_root.join("restart.stdout"))?;
        let stderr = fs::File::options()
            .write(true)
            .create_new(true)
            .open(target.temporary_root.join("restart.stderr"))?;
        let mut child = Command::new(&tools.restarter.path)
            .current_dir(&target.temporary_root)
            .process_group(0)
            .args(["--new-coordinator", "--coord-port", "0", "--interval", "0"])
            .arg("--ckptdir")
            .arg(&target.image_root)
            .arg("--tmpdir")
            .arg(&target.temporary_root)
            .arg(image_path)
            .env("CRUCIBLE_RESTORE_RESOURCE_ROOT", &target.resource_root)
            .env(
                "CRUCIBLE_RESTORE_SAVED_FILES_SOURCE_ROOT",
                image.source_supplementary_files_root(),
            )
            .env(
                "CRUCIBLE_RESTORE_SAVED_FILES_TARGET_ROOT",
                &supplementary_root,
            )
            .env(
                "CRUCIBLE_RESTORE_SAVED_FILES_MANIFEST",
                &supplementary_manifest,
            )
            .env("CRUCIBLE_GEM5_OPERATIONAL_ROOT", &target.temporary_root)
            .env("CRUCIBLE_GEM5_CONTROL_SOCKET", &socket)
            .env(
                "DMTCP_PATH_MAPPING",
                format!(
                    "{}:{}",
                    path_text(&image.source.resource_root)?,
                    path_text(&target.resource_root)?
                ),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        let identity = super::containment::capture_identity(&child);
        let mut kernel_identity = None;
        let mut launch = image.source.clone();
        launch.resource_root = target.resource_root;
        launch.incarnation = target.incarnation;
        launch.generation = target.generation;
        launch.timeout = target.timeout;
        if let Some(tools) = &mut launch.process_images {
            tools.image_root = target.image_root;
            tools.temporary_root = target.temporary_root;
        }
        launch.owner_script.path = launch.resource_root.join("native-owner.py");
        launch.model_script.path = launch.resource_root.join("native-owner-model.py");
        launch.guest.path = launch.resource_root.join("guest.elf");
        let mut preparation = super::Gem5PreparationCustody::AwaitingReady;
        let mut prepared_stream = None;
        let ready = (|| {
            kernel_identity = Some(identity?);
            prepared_stream = Some(connect(&listener, &mut child, launch.timeout)?);
            let stream = prepared_stream.as_mut().ok_or(ProviderError::Correlation(
                "gem5 restored preparation control session is absent",
            ))?;
            verify_restored_code(child.id(), &image.source)?;
            let mut io = super::DeadlineIo {
                stream,
                deadline: super::deadline(launch.timeout)?,
            };
            crate::transport::write_frame(
                &mut io,
                &json!({
                    "kind":"restore_bind", "owner":launch.owner,
                    "source_incarnation":image.source.incarnation,"source_generation":image.source.generation,
                    "incarnation":launch.incarnation,"generation":launch.generation,"capture":image.capture,
                }),
                super::GEM5_NATIVE_FRAME_BYTES,
            )?;
            let frame = super::exchange_read_retained(stream, launch.timeout)?;
            preparation = super::Gem5PreparationCustody::Received(frame.bytes);
            let ready: Ready = serde_json::from_value(frame.value)
                .map_err(|_| ProviderError::Frame("gem5 fresh restored native readiness shape"))?;
            if ready.kind != "ready"
                || ready.schema != GEM5_NATIVE_PROTOCOL
                || ready.owner != launch.owner
                || ready.incarnation != launch.incarnation
                || ready.generation != launch.generation
                || ready.continuation != "restored"
                || ready.boundary != image.boundary
            {
                return Err(ProviderError::Correlation(
                    "gem5 fresh native lineage or stopped state differs",
                ));
            }
            preparation.authenticate(
                &child,
                &launch,
                ready,
                super::PreparationOrigin::Restored {
                    source_capture: image.capture.clone(),
                },
            )?;
            Ok(())
        })();
        match ready {
            Ok(()) => {}
            Err(error) => {
                supervisor.retain(Gem5NativeCustody {
                    kernel_identity,
                    child,
                    stream: prepared_stream.take(),
                    listener: Some(listener),
                    boundary: Some(image.boundary.clone()),
                    launch,
                    completed: image.completed.clone(),
                    pending: image.pending.clone(),
                    last_acknowledged: image.last_acknowledged.clone(),
                    unresolved: None,
                    unresolved_capture: Some(image.capture.clone()),
                    source_image: Some(image.clone()),
                    preparation,
                    quarantine: None,
                });
                return Err(error);
            }
        };
        Ok(Self {
            kernel_identity,
            child: Some(child),
            launch,
            stream: prepared_stream,
            listener: Some(listener),
            boundary: image.boundary.clone(),
            completed: image.completed.clone(),
            pending: image.pending.clone(),
            last_acknowledged: image.last_acknowledged.clone(),
            unresolved: None,
            unresolved_capture: None,
            source_image: Some(image.clone()),
            preparation,
            quarantine: None,
            supervisor: Some(supervisor),
        })
    }
}

fn verify_restored_code(pid: u32, source: &super::Gem5Launch) -> Result<(), ProviderError> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let native = path_text(&source.executable.path)?;
    let helper = source
        .process_images
        .as_ref()
        .ok_or(ProviderError::Correlation(
            "gem5 native restore helper omitted",
        ))?;
    let helper_path = path_text(&helper.resource_helper.path)?;
    if crate::conformance::measure_executable(Path::new(&format!("/proc/{pid}/exe")))?
        != helper.reconstruction_executable.content
    {
        return Err(ProviderError::Correlation(
            "gem5 actual reconstruction executable differs",
        ));
    }
    let executable_mapping = |path: &str| {
        maps.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.len() == 6 && fields[1].as_bytes().get(2) == Some(&b'x') && fields[5] == path
        })
    };
    if !executable_mapping(&native) || !executable_mapping(&helper_path) {
        return Err(ProviderError::Correlation(
            "gem5 restored actual native code mappings differ",
        ));
    }
    Ok(())
}
