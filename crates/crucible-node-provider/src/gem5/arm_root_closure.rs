//! Current opaque process-byte authority for the fixed ARM root model.
//!
//! The certificate is constructed only after the trusted installed auditor has
//! compared genuine captured task, descriptor and map bodies with the actual
//! image. It does not promote partial modeled diagnostics, guest readiness,
//! device parity or CPU timing fidelity.

use std::{
    fs,
    io::{Read, Write},
    net::Shutdown,
    os::{
        fd::OwnedFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use crucible_node_contract::{ContentRef, HashRef, Id, canonical};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::arm_root_budget::HostBudget;
use super::arm_root_group::ArmRootGroup;
use super::images::{measure_image_file, validate_private_directory};
use super::{ArmRootCapturedImage, ArmRootNativeProcess};
use crate::ProviderError;

const AUDIT_BYTES: usize = 16 * 1024 * 1024;
const PROFILE: &str = "arm-linux-vexpress-atomic-root-functional-v1";

/// Retains an independently audited complete byte closure at an actual stopped cut.
#[derive(Debug)]
pub struct ArmRootProcessClosure {
    pub(crate) pid: u32,
    pub(crate) start_ticks: String,
    pub(crate) capture: Id,
    pub(crate) source_scope: HashRef,
    pub(crate) boundary: super::Gem5Boundary,
    pub(crate) image: ContentRef,
    pub(crate) evidence: ContentRef,
    pub(crate) bytes: Vec<u8>,
}

impl ArmRootProcessClosure {
    /// Borrows the exact complete opaque byte evidence and its immutable identity.
    pub fn evidence(&self) -> (&ContentRef, &[u8]) {
        (&self.evidence, &self.bytes)
    }

    /// Returns the exact original native capture identity.
    pub fn capture_id(&self) -> &Id {
        &self.capture
    }

    /// Verifies original image lineage without issuing fresh live authority.
    ///
    /// # Errors
    /// Refuses changed image bytes, model/source scope, capture identity or cut.
    pub fn verify_image(&self, image: &ArmRootCapturedImage) -> Result<(), ProviderError> {
        image.verify()?;
        self.evidence.verify(&self.bytes)?;
        if self.capture != *image.capture_id()
            || self.boundary != *image.boundary()
            || self.source_scope != image.source().scope()?
            || self.image != measure_image_file(image.process_image()?)?
        {
            return Err(ProviderError::Correlation(
                "ARM opaque image certificate lineage differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn require_current(
        &self,
        process: &ArmRootNativeProcess,
    ) -> Result<(), ProviderError> {
        let custody = process
            .custody
            .as_ref()
            .ok_or(ProviderError::Frame("ARM closure custody absent"))?;
        let group = custody
            .group
            .as_ref()
            .ok_or(ProviderError::Frame("ARM closure actual child absent"))?;
        group.require_live()?;
        if group.identity() != (self.pid, self.start_ticks.as_str())
            || process.boundary != self.boundary
            || custody.launch.scope()? != self.source_scope
            || process.unresolved.is_some()
            || process.unresolved_capture.is_some()
        {
            return Err(ProviderError::Correlation(
                "ARM opaque closure is not current live owner",
            ));
        }
        self.evidence.verify(&self.bytes)?;
        Ok(())
    }
}

impl ArmRootNativeProcess {
    /// Audits the genuine current nondrained capture against the installed policy.
    ///
    /// The source-owned model disables all host listeners and admits only fixed
    /// kernel, initramfs and bootloader assets. No caller-provided boolean, hash
    /// allowlist or sampling success creates this certificate.
    ///
    /// # Errors
    /// Refuses changed installed bytes, foreign captures, missing ledger bodies,
    /// unowned kernel peers, incomplete byte closure, or bounded auditor failure.
    pub fn qualify_capture(
        &mut self,
        image: &ArmRootCapturedImage,
        owned: &Path,
    ) -> Result<ArmRootProcessClosure, ProviderError> {
        validate_private_directory(owned)?;
        let launch = self.launch()?.clone();
        if self.quarantined
            || self.unresolved.is_some()
            || self.unresolved_capture.is_some()
            || image.boundary() != &self.boundary
            || image.source().scope()? != launch.scope()?
            || !launch.resource_root.starts_with(owned)
            || !image.process_image()?.starts_with(owned)
        {
            return Err(ProviderError::Correlation(
                "ARM audit lacks authentic current owned cut",
            ));
        }
        // Remeasure the compiled source-owned bundle, then compare its identity
        // with this already running owner's immutable launch binding.
        let installed = super::arm_root_installed::InstalledArmRootMechanism::load()?;
        if installed.manifest_content()? != launch.profile {
            return Err(ProviderError::Correlation("ARM installed profile changed"));
        }
        image.verify()?;
        let original = image.original_image_for_audit()?;
        let native = self.exchange(json!({"kind":"process_inventory"}))?;
        if native.get("kind") != Some(&json!("process_inventory"))
            || native.get("schema") != Some(&json!("crucible.gem5.native-process-inventory.v1"))
            || native.get("boundary")
                != Some(
                    &serde_json::to_value(&self.boundary)
                        .map_err(|_| ProviderError::Frame("ARM audit cut encoding"))?,
                )
        {
            return Err(ProviderError::Correlation(
                "ARM native inventory cut differs",
            ));
        }
        let (pid, start_ticks) = self
            .custody
            .as_ref()
            .and_then(|custody| custody.group.as_ref())
            .ok_or(ProviderError::Frame("ARM actual audit peer absent"))?
            .identity();
        let start_ticks = start_ticks.to_owned();
        let mut assets = Vec::new();
        for role in ["native_executable", "image_guard"] {
            let artifact = launch.artifact(role)?;
            if measure_image_file(&artifact.path)? != artifact.content {
                return Err(ProviderError::Correlation(
                    "ARM audit immutable native asset changed",
                ));
            }
            assets.push(
                json!({"path":artifact.path,"sha256":launch.metadata["artifacts"][role]["sha256"]}),
            );
        }
        for (name, role) in [
            ("native-controller.py", "controller"),
            ("native-controller-arm-root.py", "entrypoint"),
            ("native-controller-arm-root-model.py", "model"),
            ("native-controller-arm-model.py", "board_model"),
            ("native-controller-models.py", "publication_model"),
            ("native-model-assets.py", "asset_checker"),
            ("full-system-process-image-audit.py", "auditor"),
            ("process-image-audit-core.py", "auditor_core"),
            ("kernel.elf", "kernel"),
            ("initrd.img", "initramfs"),
            ("boot_v2.arm64", "firmware"),
        ] {
            let path = launch.resource_root.join(name);
            if measure_image_file(&path)? != launch.artifact(role)?.content {
                return Err(ProviderError::Correlation(
                    "ARM audit managed source/guest asset changed",
                ));
            }
            assets.push(json!({"path":path,"sha256":launch.metadata["artifacts"][role]["sha256"]}));
        }
        let boundary_sha = hex_sha(&canonical::canonical_json(
            &serde_json::to_value(&self.boundary)
                .map_err(|_| ProviderError::Frame("ARM audit frontier encoding"))?,
        )?);
        let request = json!({"schema":"crucible.gem5.process-closure-request.v1",
            "pid":pid.to_string(),"start_ticks":start_ticks,"owned_root":owned,
            "modeled_root":launch.resource_root,"image":original,"profile":PROFILE,
            "guest_isa":"aarch64","guest_executable":launch.resource_root.join("kernel.elf"),
            "model_scope":self.ready.model_scope,"boundary_sha256":boundary_sha,"assets":assets,
            "thread_contexts":native.get("thread_contexts"),
            "captured_descriptors":native.get("captured_descriptors"),
            "captured_maps":native.get("captured_maps"),
            "captured_file_maps":native.get("captured_file_maps"),
            "operational_shared_maps":native.get("operational_shared_maps"),"native_inventory":native});
        let bytes = self.audit(&request)?;
        let receipt = canonical::parse_json(&bytes, AUDIT_BYTES)?;
        if receipt.get("schema") != Some(&json!("crucible.gem5.process-closure-mechanism.v1"))
            || receipt.get("byte_closure_complete") != Some(&json!(true))
            || receipt.get("modeled_diagnostics_complete") != Some(&json!(false))
            || receipt.get("execution_admission_qualified") != Some(&json!(false))
            || receipt.get("full_system_admission_qualified") != Some(&json!(false))
            || !receipt
                .get("omissions")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            || receipt.get("pid") != Some(&json!(pid.to_string()))
            || receipt.get("start_ticks") != Some(&json!(start_ticks))
            || receipt.get("boundary_sha256") != Some(&json!(boundary_sha))
            || receipt.get("profile") != Some(&json!(PROFILE))
            || receipt.get("guest_isa") != Some(&json!("aarch64"))
            || receipt.get("image_sha256") != Some(&json!(file_sha(&original)?))
        {
            return Err(ProviderError::Correlation(
                "ARM audit original closure receipt differs",
            ));
        }
        image.verify()?;
        if image.original_image_for_audit()? != original {
            return Err(ProviderError::Correlation(
                "ARM audited image route changed",
            ));
        }
        let observed = self.exchange(json!({"kind":"observe"}))?;
        if observed != json!({"kind":"observed","boundary":self.boundary}) {
            return Err(ProviderError::Correlation(
                "ARM audit advanced modeled execution",
            ));
        }
        let evidence = canonical::content_ref(&bytes, "application/json")?;
        let result = ArmRootProcessClosure {
            pid,
            start_ticks,
            capture: image.capture_id().clone(),
            source_scope: launch.scope()?,
            boundary: self.boundary.clone(),
            image: measure_image_file(image.process_image()?)?,
            evidence,
            bytes,
        };
        result.require_current(self)?;
        Ok(result)
    }

    fn audit(&mut self, request: &Value) -> Result<Vec<u8>, ProviderError> {
        let launch = self.launch()?.clone();
        let bytes = canonical::canonical_json(request)?;
        if bytes.len() > super::GEM5_NATIVE_FRAME_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "ARM closure request credit",
            ));
        }
        let (mut stream, child_stream) = UnixStream::pair()?;
        stream.set_read_timeout(Some(launch.timeout))?;
        stream.set_write_timeout(Some(launch.timeout))?;
        let output: OwnedFd = child_stream.try_clone()?.into();
        let diagnostics: OwnedFd = child_stream.try_clone()?.into();
        let input: OwnedFd = child_stream.into();
        let custody = self
            .custody
            .as_mut()
            .ok_or(ProviderError::Frame("ARM audit supervision absent"))?;
        if custody.audit_workers.len() + custody.unenrolled_helpers.len() >= 64 {
            return Err(ProviderError::ResourceExhausted(
                "ARM retained auditor-worker credit",
            ));
        }
        // Reserve both possible ownership routes before creating an actual child.
        custody
            .audit_workers
            .try_reserve(1)
            .map_err(|_| ProviderError::ResourceExhausted("ARM reserved auditor-worker storage"))?;
        custody.unenrolled_helpers.try_reserve(1).map_err(|_| {
            ProviderError::ResourceExhausted("ARM reserved unenrolled-helper storage")
        })?;
        let original_deadline = super::arm_root_io::deadline(launch.timeout)?;
        let child = Command::new(&launch.artifact("python")?.path)
            .env_clear()
            .env("LC_ALL", "C")
            .env("PYTHONHASHSEED", "0")
            .env("PYTHONNOUSERSITE", "1")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg("-B")
            .arg(
                launch
                    .resource_root
                    .join("full-system-process-image-audit.py"),
            )
            .current_dir(&launch.tools.temporary_root)
            .process_group(0)
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::from(diagnostics))
            .spawn()?;
        // Storage was reserved before spawn. Retain first, then measure while
        // the original Child remains owned through errors and unwinding.
        custody.unenrolled_helpers.push(child);
        custody.audit_workers.push(ArmRootGroup::enroll_helper(
            &mut custody.unenrolled_helpers,
        )?);
        super::arm_root_io::NativeDeadlineIo::new(&mut stream, original_deadline)
            .write_all(&bytes)?;
        stream.shutdown(Shutdown::Write)?;
        let mut receipt = Vec::new();
        super::arm_root_io::NativeDeadlineIo::new(&mut stream, original_deadline)
            .take(AUDIT_BYTES as u64 + 1)
            .read_to_end(&mut receipt)?;
        if receipt.len() > AUDIT_BYTES {
            return Err(ProviderError::ResourceExhausted("ARM audit receipt credit"));
        }
        let worker = custody
            .audit_workers
            .last_mut()
            .ok_or(ProviderError::Frame("ARM audit worker lost"))?;
        let end = HostBudget::after(Duration::from_secs(10))?;
        let status = loop {
            if let Some(status) = worker.exit_observation()? {
                break status;
            }
            if end.is_expired() {
                return Err(ProviderError::Frame("ARM audit exit deadline"));
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        worker.begin_retirement()?;
        while !worker.poll_retirement()? {
            std::thread::sleep(Duration::from_millis(5));
        }
        if !status {
            return Err(std::io::Error::other(format!(
                "installed ARM auditor refused: {}",
                String::from_utf8_lossy(&receipt[..receipt.len().min(4096)])
            ))
            .into());
        }
        Ok(receipt)
    }
}

fn hex_sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn file_sha(path: &Path) -> Result<String, ProviderError> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
