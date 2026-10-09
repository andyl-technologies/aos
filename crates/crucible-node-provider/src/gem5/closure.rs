//! Private whole-process capture closure beneath an installed narrow profile.
//!
//! The certificate binds an actual parked kernel peer, native captured ledgers,
//! measured image, immutable launch assets and independently executed auditor.
//! It never changes the partial modeled observer's coverage claim.

use std::net::Shutdown;

use crucible_node_contract::{HashRef, canonical};
use sha2::{Digest, Sha256};

use super::*;
use crate::gem5::Gem5CapturedImage;

const MAX_AUDIT_BYTES: usize = 16 * 1024 * 1024;
const PROFILE: &str = "freestanding-o3-classic-ddr3-v1";

/// Authenticates the installed complete closed profile and its native auditor.
pub trait Gem5OpaqueProfileVerifier {
    /// Verifies known guest syscalls, model/device closure, and actual installed code.
    ///
    /// The selected fixed guest must have no host-derived clock, randomness,
    /// file, network or device input. A measured executable alone is insufficient.
    ///
    /// # Errors
    /// Refuses unknown guests, unqualified native sources, unsupported devices,
    /// unavailable complete process custody or an untrusted auditor artifact.
    fn verify_opaque_profile(
        &self,
        launch: &Gem5Launch,
        auditor: &Gem5LaunchArtifact,
    ) -> Result<(), ProviderError>;
}

/// Retains independently audited exact capture without claiming complete diagnostics.
#[derive(Debug)]
pub struct Gem5ProcessClosure {
    pid: u32,
    start_ticks: String,
    capture: Id,
    source_scope: HashRef,
    boundary: Gem5Boundary,
    image: ContentRef,
    auditor: ContentRef,
    evidence: ContentRef,
    bytes: Vec<u8>,
}

/// Retains the complete native diagnostic object behind a compact summary.
#[derive(Debug)]
pub struct Gem5DiagnosticObject {
    reference: ContentRef,
    bytes: Vec<u8>,
}

impl Gem5DiagnosticObject {
    /// Returns the original verified diagnostic bytes and their portable content identity.
    pub fn content(&self) -> (&ContentRef, &[u8]) {
        (&self.reference, &self.bytes)
    }
}

impl Gem5ProcessClosure {
    pub(super) fn live_scope(
        &self,
        process: &Gem5NativeProcess,
    ) -> Result<(u32, String, HashRef), ProviderError> {
        if process.child_pid() != Some(self.pid)
            || kernel_start_ticks(self.pid)? != self.start_ticks
            || process.boundary != self.boundary
            || source_scope(&process.launch)? != self.source_scope
        {
            return Err(ProviderError::Correlation(
                "gem5 capture closure is not current live readiness",
            ));
        }
        self.evidence.verify(&self.bytes)?;
        Ok((
            self.pid,
            self.start_ticks.clone(),
            self.source_scope.clone(),
        ))
    }

    /// Returns the original authentic native capture identity.
    pub fn capture_id(&self) -> &Id {
        &self.capture
    }

    /// Returns the independently audited unchanged native boundary.
    pub fn boundary(&self) -> &Gem5Boundary {
        &self.boundary
    }

    /// Returns the measured installed auditor used for this exact capture.
    pub fn auditor(&self) -> &ContentRef {
        &self.auditor
    }

    /// Returns immutable complete closure evidence for durable provenance.
    pub fn evidence(&self) -> (&ContentRef, &[u8]) {
        (&self.evidence, &self.bytes)
    }

    /// Verifies this certificate's exact original image and source lineage.
    ///
    /// This check preserves artifact authority only. World restoration and
    /// execution still require their separate native activation contracts.
    ///
    /// # Errors
    /// Refuses changed image bytes, capture identity, source scope or boundary.
    pub fn verify_image(&self, image: &Gem5CapturedImage) -> Result<(), ProviderError> {
        image.verify()?;
        if self.capture != *image.capture_id()
            || self.boundary != *image.boundary()
            || self.source_scope != source_scope(image.source())?
            || self.image != crate::gem5::images::measure_image_file(image.process_image()?)?
        {
            return Err(ProviderError::Correlation(
                "gem5 opaque capture certificate scope differs",
            ));
        }
        self.evidence.verify(&self.bytes)?;
        Ok(())
    }
}

impl Gem5NativeProcess {
    /// Retrieves complete diagnostic bytes retained by an actual native boundary.
    ///
    /// Summary digests are not complete modeled-state visitors or execution
    /// authority. This copies original evidence before any publication ACK.
    ///
    /// # Errors
    /// Rejects foreign boundaries, unsupported summary schemas, unsafe paths,
    /// missing or changed objects, and exceeded finite diagnostic allowances.
    pub fn diagnostic_object(
        &self,
        boundary: &Gem5Boundary,
    ) -> Result<Gem5DiagnosticObject, ProviderError> {
        if boundary != &self.boundary
            && !self
                .completed
                .values()
                .any(|prefix| boundary == &prefix.before || boundary == &prefix.after)
        {
            return Err(ProviderError::Correlation(
                "gem5 diagnostic boundary lacks native custody",
            ));
        }
        let summary = &boundary.inventory;
        if summary.get("schema").and_then(Value::as_str)
            != Some("crucible.gem5.modeled-state-summary.v1")
        {
            return Err(ProviderError::Correlation(
                "gem5 native diagnostic summary unavailable",
            ));
        }
        let blob = summary.get("full_blob").ok_or(ProviderError::Frame(
            "gem5 original diagnostic object absent",
        ))?;
        let relative = blob
            .get("path")
            .and_then(Value::as_str)
            .ok_or(ProviderError::Frame("gem5 diagnostic object path absent"))?;
        let digest = blob
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or(ProviderError::Frame("gem5 diagnostic digest malformed"))?;
        if relative != format!("native-diagnostics/{digest}.json") {
            return Err(ProviderError::Correlation(
                "gem5 diagnostic route is not original content-addressed custody",
            ));
        }
        let length: U64 = serde_json::from_value(
            blob.get("bytes")
                .cloned()
                .ok_or(ProviderError::Frame("gem5 diagnostic length absent"))?,
        )
        .map_err(|_| ProviderError::Frame("gem5 diagnostic length malformed"))?;
        if length.get() > 64 * 1024 * 1024 {
            return Err(ProviderError::ResourceExhausted(
                "gem5 diagnostic object allowance",
            ));
        }
        let path = self.launch.resource_root.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != length.get() {
            return Err(ProviderError::Correlation(
                "gem5 native diagnostic object custody differs",
            ));
        }
        let mut bytes = Vec::new();
        File::open(&path)?
            .take(length.get() + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length.get() || sha256(&bytes) != digest {
            return Err(ProviderError::Correlation(
                "gem5 native diagnostic object changed",
            ));
        }
        let original = canonical::parse_json(&bytes, 64 * 1024 * 1024)?;
        if original.get("schema") != summary.get("native_schema")
            || original.get("native_tick") != summary.get("native_tick")
            || original.get("complete") != summary.get("native_complete")
            || original.get("unsupported_domains") != summary.get("unsupported_domains")
        {
            return Err(ProviderError::Correlation(
                "gem5 summary differs from its complete original diagnostic object",
            ));
        }
        Ok(Gem5DiagnosticObject {
            reference: canonical::content_ref(&bytes, "application/json")?,
            bytes,
        })
    }

    /// Audits an actual stopped image under a separately authenticated closed profile.
    ///
    /// The native owner supplies captured thread, descriptor and mapping ledger
    /// bodies. The installed auditor compares them with actual image intervals
    /// and kernel resources. Missing evidence refuses certification; partial
    /// modeled diagnostics remain explicitly incomplete.
    ///
    /// # Errors
    /// Rejects foreign images, uncertain native effects, changed launch assets,
    /// unqualified profiles, missing native ledgers, helper failures, resource
    /// limits or complete receipts that do not bind the actual original cut.
    pub fn qualify_capture(
        &mut self,
        image: &Gem5CapturedImage,
        owned_scope: &Path,
        auditor: &Gem5LaunchArtifact,
        verifier: &dyn Gem5OpaqueProfileVerifier,
    ) -> Result<Gem5ProcessClosure, ProviderError> {
        if self.quarantine.is_some()
            || self.unresolved.is_some()
            || self.unresolved_capture.is_some()
            || image.boundary() != &self.boundary
            || source_scope(image.source())? != source_scope(&self.launch)?
        {
            return Err(ProviderError::Correlation(
                "gem5 capture audit lacks original stopped custody",
            ));
        }
        verifier.verify_opaque_profile(&self.launch, auditor)?;
        crate::gem5::images::validate_private_directory(owned_scope)?;
        if !self.launch.resource_root.starts_with(owned_scope)
            || !image.process_image()?.starts_with(owned_scope)
        {
            return Err(ProviderError::Correlation(
                "gem5 capture audit resource scope is incomplete",
            ));
        }
        image.verify()?;
        // Native FileConnection receipts contain original saved paths. Audit that
        // exact live tree after verifying every byte against the independent seal.
        let original_image = image.original_image_for_audit()?;
        let installed_auditor = measured_sha256(auditor)?;
        let native = self.exchange(json!({"kind":"process_inventory"}))?;
        if native.get("kind").and_then(Value::as_str) != Some("process_inventory")
            || native.get("schema").and_then(Value::as_str)
                != Some("crucible.gem5.native-process-inventory.v1")
            || native.get("boundary")
                != Some(
                    &serde_json::to_value(&self.boundary)
                        .map_err(|_| ProviderError::Frame("gem5 audit boundary encoding"))?,
                )
        {
            return Err(ProviderError::Correlation(
                "gem5 native capture audit frontier differs",
            ));
        }
        let pid = self
            .child_pid()
            .ok_or(ProviderError::Correlation("gem5 actual native peer absent"))?;
        let start_ticks = kernel_start_ticks(pid)?;
        let tools = self
            .launch
            .process_images
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "gem5 capture audit native image tools absent",
            ))?;
        let mut assets = Vec::new();
        for artifact in [
            &self.launch.executable,
            &self.launch.owner_script,
            &self.launch.model_script,
            &self.launch.guest,
            &tools.resource_helper,
        ] {
            assets.push(json!({"path":path_text(&artifact.path)?,
                "sha256":measured_sha256(artifact)?}));
        }
        // Operational copies are measured against original immutable content.
        for (name, artifact) in [
            ("native-owner.py", &self.launch.owner_script),
            ("native-owner-model.py", &self.launch.model_script),
            ("guest.elf", &self.launch.guest),
        ] {
            let copy = Gem5LaunchArtifact {
                path: self.launch.resource_root.join(name),
                content: artifact.content.clone(),
            };
            assets.push(json!({"path":path_text(&copy.path)?,"sha256":measured_sha256(&copy)?}));
        }
        let boundary_bytes = canonical::canonical_json(
            &serde_json::to_value(&self.boundary)
                .map_err(|_| ProviderError::Frame("gem5 audit boundary encoding"))?,
        )?;
        let boundary_sha256 = sha256(&boundary_bytes);
        let request = json!({
            "schema":"crucible.gem5.process-closure-request.v1",
            "pid":pid.to_string(),"start_ticks":start_ticks,
            "owned_root":path_text(owned_scope)?,"image":path_text(&original_image)?,
            "assets":&assets,"profile":PROFILE,"guest_isa":self.launch.guest_isa,
            "guest_executable":path_text(&self.launch.resource_root.join("guest.elf"))?,
            "boundary_sha256":boundary_sha256,
            "thread_contexts":native.get("thread_contexts"),
            "captured_descriptors":native.get("captured_descriptors"),
            "captured_maps":native.get("captured_maps"),
            "captured_file_maps":native.get("captured_file_maps"),
            "operational_shared_maps":native.get("operational_shared_maps"),
            "native_inventory":native,
        });
        let bytes = execute_auditor(auditor, &request, self.launch.timeout)?;
        let receipt = canonical::parse_json(&bytes, MAX_AUDIT_BYTES)?;
        if receipt.get("schema").and_then(Value::as_str) != Some("crucible.gem5.process-closure.v1")
            || receipt.get("complete") != Some(&Value::Bool(true))
            || receipt.get("modeled_diagnostics_complete") != Some(&Value::Bool(false))
            || !receipt
                .get("omissions")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            || receipt.get("pid").and_then(Value::as_str) != Some(pid.to_string().as_str())
            || receipt.get("start_ticks").and_then(Value::as_str) != Some(start_ticks.as_str())
            || receipt.get("boundary_sha256").and_then(Value::as_str)
                != Some(boundary_sha256.as_str())
            || receipt.get("profile").and_then(Value::as_str) != Some(PROFILE)
            || receipt.get("guest_isa").and_then(Value::as_str)
                != Some(self.launch.guest_isa.as_str())
        {
            return Err(ProviderError::Correlation(
                "gem5 process closure is incomplete or foreign",
            ));
        }
        let image_reference = crate::gem5::images::measure_image_file(image.process_image()?)?;
        if receipt.get("image_sha256").and_then(Value::as_str)
            != Some(
                file_sha256_with_limit(image.process_image()?, crate::gem5::GEM5_MAX_IMAGE_BYTES)?
                    .as_str(),
            )
            || installed_auditor != measured_sha256(auditor)?
            || kernel_start_ticks(pid)? != start_ticks
        {
            return Err(ProviderError::Correlation(
                "gem5 capture audit artifacts or peer changed",
            ));
        }
        image.verify()?;
        if image.original_image_for_audit()? != original_image {
            return Err(ProviderError::Correlation(
                "gem5 original audit image route changed",
            ));
        }
        for asset in assets.iter() {
            let path = asset
                .get("path")
                .and_then(Value::as_str)
                .ok_or(ProviderError::Frame("gem5 measured asset path missing"))?;
            let expected = asset
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or(ProviderError::Frame("gem5 measured asset digest missing"))?;
            if file_sha256(Path::new(path))? != expected {
                return Err(ProviderError::Correlation(
                    "gem5 immutable launch asset changed during native audit",
                ));
            }
        }
        self.observe()?;
        let bytes = canonical::canonical_json(&receipt)?;
        Ok(Gem5ProcessClosure {
            pid,
            start_ticks,
            capture: image.capture_id().clone(),
            source_scope: source_scope(&self.launch)?,
            boundary: self.boundary.clone(),
            image: image_reference,
            auditor: auditor.content.clone(),
            evidence: canonical::content_ref(&bytes, "application/json")?,
            bytes,
        })
    }
}

pub(super) fn source_scope(launch: &Gem5Launch) -> Result<HashRef, ProviderError> {
    Ok(canonical::json_hash(
        "cnp.gem5-opaque-capture-scope.v1",
        &(
            &launch.owner,
            &launch.incarnation,
            launch.generation,
            &launch.guest_isa,
            &launch.executable.content,
            &launch.owner_script.content,
            &launch.model_script.content,
            &launch.guest.content,
            &launch.resource_root,
            launch.process_images.as_ref().map(|tools| {
                (
                    &tools.launcher.content,
                    &tools.restarter.content,
                    &tools.reconstruction_executable.content,
                    &tools.resource_helper.content,
                )
            }),
        ),
    )?)
}

fn measured_sha256(artifact: &Gem5LaunchArtifact) -> Result<String, ProviderError> {
    if crate::conformance::measure_executable(&artifact.path)? != artifact.content {
        return Err(ProviderError::Correlation(
            "gem5 capture audit installed asset changed",
        ));
    }
    file_sha256(&artifact.path)
}

fn file_sha256(path: &Path) -> Result<String, ProviderError> {
    file_sha256_with_limit(path, 1024 * 1024 * 1024)
}

fn file_sha256_with_limit(path: &Path, maximum_bytes: u64) -> Result<String, ProviderError> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > maximum_bytes {
        return Err(ProviderError::ResourceExhausted(
            "gem5 audit file digest allowance",
        ));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut read_bytes = 0u64;
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        read_bytes =
            read_bytes
                .checked_add(length as u64)
                .ok_or(ProviderError::ResourceExhausted(
                    "gem5 audit digest byte counter",
                ))?;
        if read_bytes > before.len() {
            return Err(ProviderError::Correlation(
                "gem5 audit digest file grew during inspection",
            ));
        }
        hash.update(&buffer[..length]);
    }
    let after = file.metadata()?;
    if read_bytes != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(ProviderError::Correlation("gem5 audit digest file changed"));
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn kernel_start_ticks(pid: u32) -> Result<String, ProviderError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .filter(|value| value.parse::<u64>().is_ok())
        .map(str::to_owned)
        .ok_or(ProviderError::Frame("gem5 kernel start identity absent"))
}

fn execute_auditor(
    auditor: &Gem5LaunchArtifact,
    request: &Value,
    timeout: Duration,
) -> Result<Vec<u8>, ProviderError> {
    let request = canonical::canonical_json(request)?;
    if request.len() > GEM5_NATIVE_FRAME_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "gem5 process closure request allowance",
        ));
    }
    #[cfg(test)]
    if let Some(root) = std::env::var_os("CRUCIBLE_GEM5_AUDIT_EVIDENCE") {
        let root = PathBuf::from(root);
        crate::gem5::images::validate_private_directory(&root)?;
        let path = root.join(format!("{}.request.json", sha256(&request)));
        let mut evidence = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        evidence.write_all(&request)?;
        evidence.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    }
    let (mut stream, inherited) = UnixStream::pair()?;
    let output: OwnedFd = inherited.try_clone()?.into();
    let diagnostics: OwnedFd = inherited.try_clone()?.into();
    let input: OwnedFd = inherited.into();
    let mut child = Command::new(&auditor.path)
        // Operational diagnostics must not depend on a caller's uninstalled
        // locale: the measured shell wrapper shares the bounded receipt pipe.
        .env("LC_ALL", "C")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(diagnostics))
        .spawn()?;
    let result = (|| {
        let mut io = DeadlineIo {
            stream: &mut stream,
            deadline: deadline(timeout)?,
        };
        io.write_all(&request)?;
        io.stream.shutdown(Shutdown::Write)?;
        let mut bytes = Vec::new();
        io.take(MAX_AUDIT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_AUDIT_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "gem5 process closure receipt allowance",
            ));
        }
        let end = deadline(timeout)?;
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    let detail = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
                    return Err(std::io::Error::other(format!(
                        "gem5 installed auditor refused closure: {detail}"
                    ))
                    .into());
                }
                break;
            }
            if end.is_expired() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "gem5 capture auditor deadline",
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(bytes)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
#[path = "closure_locale_tests.rs"]
mod locale_tests;
