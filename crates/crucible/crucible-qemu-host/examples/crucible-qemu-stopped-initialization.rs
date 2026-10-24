//! Drives one genuine guarded x86/Q35 SIM stopped four-CPU constructor.
//!
//! This qualification operator retains the original child, descriptor capsule,
//! finite initial socket and stdout journals. It never sends RUN, stages guest
//! input, offers SourceReadyACK or grants guest execution. A pinned configuration
//! is installed by the outer source-built AOS guest operator before invocation.
//!
//! ```text
//! crucible-qemu-stopped-initialization CONFIG_JSON OUTPUT_JSON
//! ```

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use crucible_engine::ContentHash;
use crucible_qemu_host::{
    LaunchProfileCandidate, LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory,
    QemuChildProcessContract, QemuLaunchArtifact, QemuLaunchCommand, QemuLaunchCommandBuilder,
    QemuLaunchPluginConfig, QemuRootImageFormat, QemuSpawnError, QemuVmLaunchConfig,
    QemuWholeLaunchCustody, QemuWholeLaunchCustodySlot,
    spawn_selected_qemu_child_for_stopped_initialization,
    spawn_selected_qemu_child_for_stopped_rr_preparation,
};
use crucible_qemu_protocol::whole_control::WholeControlProfile;
use crucible_qemu_protocol::whole_control::inventory::WholeQueueRole;
use crucible_qemu_protocol::whole_control::staged::StagedControlProfile;
use crucible_qemu_protocol::whole_control::staged::launch::{LaunchArchitecture, LaunchAsset};
use crucible_qemu_protocol::whole_control::staged::launch2::{
    LaunchSelection2, LaunchSelection2Parts,
};
use crucible_qemu_protocol::whole_control::staged::selection::{
    LogicalQueueRole, WholeConstructorSelection,
};
use crucible_qemu_shmem::RegionConfig;
use rustix::pipe::{PipeFlags, pipe_with};
use rustix::time::{ClockId, clock_gettime};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const ROOT_SOURCE: &str = "4fdf30a24c3c1424ac8ecc77f8b08d3bd14a36f0";
const NATIVE_SOURCE: &str = "76a9f7c3d9b79154d751273ac308c0fb0edd4c86";
const HOOK_SOURCE: &str = "38b8898a4ab64d6675a55ab747e970890e91156149e590a7b0860f4f2ed7ebe0";
const RR_NATIVE_SOURCE: &str = "6695f4ba0c893044c0d2c969a866fd0304b1fe78";
// The complete diagnostic patch binds the issuer and finite stdout hook.
// A real matching package/plugin tuple is still required before dispatch.
const RR_HOOK_SOURCE: Option<&str> =
    Some("f81f5d86880e5993b3b40c8ecdc1a9e4dc4249b73c02deed1552991d96a6ffe0");
const ASSET_SOURCE: &str = "93906e44fd95be6808cd84868b72f9bc0093cb1e9d068acbdf64698539ddaac1";
const MAXIMUM_ASSET: u64 = 512 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema_version: u32,
    diagnostic_profile: DiagnosticProfile,
    root_source: String,
    native_source: String,
    hook_source: String,
    asset_source: String,
    qemu: Artifact,
    image_tool: Artifact,
    plugin: Artifact,
    kernel: Artifact,
    initrd: Artifact,
    firmware: Artifact,
    disk: Artifact,
    cgroup_root: PathBuf,
    run_root: PathBuf,
    namespace: String,
    child_uid: u32,
    child_gid: u32,
    first_project_id: u32,
    run_seed: u64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DiagnosticProfile {
    FourCpuInitialization,
    StoppedRoundRobinPreparation,
}

struct OriginalArtifact {
    file: File,
    path: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    digest: [u8; 32],
    content: ContentHash,
}

impl OriginalArtifact {
    fn open(expected: &Artifact) -> Result<Self, Box<dyn Error>> {
        if !expected.path.is_absolute() || expected.bytes == 0 || expected.bytes > MAXIMUM_ASSET {
            return Err(refusal(
                "artifact extent/path is outside the finite proposal",
            ));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&expected.path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != expected.bytes {
            return Err(refusal(
                "original artifact is not the expected regular extent",
            ));
        }
        let mut hash = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            bytes = bytes
                .checked_add(count as u64)
                .ok_or_else(|| refusal("artifact read overflow"))?;
            if bytes > expected.bytes {
                return Err(refusal("original artifact grew"));
            }
            hash.update(&buffer[..count]);
        }
        let digest: [u8; 32] = hash.finalize().into();
        if bytes != expected.bytes || hex(&digest) != expected.sha256 {
            return Err(refusal("original artifact full-body digest changed"));
        }
        file.seek(SeekFrom::Start(0))?;
        let content = ContentHash::from_reader(&mut file)?;
        file.seek(SeekFrom::Start(0))?;
        let original = Self {
            file,
            path: expected.path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            digest,
            content,
        };
        original.revalidate()?;
        Ok(original)
    }

    fn revalidate(&self) -> io::Result<()> {
        let original = self.file.metadata()?;
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?
            .metadata()?;
        if original.dev() != self.device
            || original.ino() != self.inode
            || original.len() != self.length
            || named.dev() != self.device
            || named.ino() != self.inode
            || named.len() != self.length
        {
            return Err(io::Error::other(
                "original artifact name/inode/extent changed",
            ));
        }
        Ok(())
    }

    fn launch_artifact(&self) -> Result<QemuLaunchArtifact, Box<dyn Error>> {
        Ok(QemuLaunchArtifact::new(self.content, text(&self.path)?))
    }
}

struct QualifiedCustodySlot {
    original_contract: QemuChildProcessContract,
    original_artifacts: Vec<OriginalArtifact>,
    expected_setup: [u8; 32],
    retained: Rc<RefCell<Option<RetainedQualification>>>,
}

struct RetainedQualification {
    capsule: Option<Box<QemuWholeLaunchCustody>>,
    contract: Option<QemuChildProcessContract>,
    artifacts: Vec<OriginalArtifact>,
}

impl Drop for RetainedQualification {
    fn drop(&mut self) {
        // Even a broken supervisor cannot run ordinary cleanup on unresolved
        // originals. Actual process exit is separate termination evidence.
        if let Some(capsule) = self.capsule.take() {
            std::mem::forget(capsule);
        }
        if let Some(contract) = self.contract.take() {
            std::mem::forget(contract);
        }
        std::mem::forget(std::mem::take(&mut self.artifacts));
    }
}

impl QemuWholeLaunchCustodySlot for QualifiedCustodySlot {
    fn validate_constructor(
        &self,
        command: &QemuLaunchCommand,
        contract: &QemuChildProcessContract,
    ) -> Result<(), QemuSpawnError> {
        if !contract.retains_same_attempt(&self.original_contract) {
            return Err(spawn_refusal("original production attempt binding changed"));
        }
        let body = command
            .plugin_setup_plan()
            .encode()
            .map_err(|error| spawn_refusal(error.to_string()))?;
        let digest: [u8; 32] = Sha256::digest(&body).into();
        if digest != self.expected_setup {
            return Err(spawn_refusal("original complete setup changed"));
        }
        for artifact in &self.original_artifacts {
            artifact.revalidate().map_err(|source| QemuSpawnError::Io {
                operation: "revalidate original stopped constructor artifact",
                source,
            })?;
        }
        Ok(())
    }

    fn retain(self: Box<Self>, original: Box<QemuWholeLaunchCustody>) {
        let Self {
            original_contract,
            original_artifacts,
            expected_setup: _,
            retained,
        } = *self;
        let preserved = RetainedQualification {
            capsule: Some(original),
            contract: Some(original_contract),
            artifacts: original_artifacts,
        };
        let mut destination = retained.borrow_mut();
        if destination.is_some() {
            // One preclaimed slot cannot discard either original incarnation.
            std::mem::forget(preserved);
            return;
        }
        *destination = Some(preserved);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let config_path = args
        .next()
        .ok_or_else(|| refusal("missing pinned configuration"))?;
    let output_path = args
        .next()
        .ok_or_else(|| refusal("missing diagnostic output path"))?;
    if args.next().is_some() {
        return Err(refusal("unexpected argument"));
    }
    let mut config_bytes = Vec::new();
    File::open(config_path)?
        .take(65537)
        .read_to_end(&mut config_bytes)?;
    if config_bytes.len() > 65536 {
        return Err(refusal("configuration exceeds finite bound"));
    }
    let config: Configuration = serde_json::from_slice(&config_bytes)?;
    let (native_source, hook_source) = match config.diagnostic_profile {
        DiagnosticProfile::FourCpuInitialization => (NATIVE_SOURCE, HOOK_SOURCE),
        DiagnosticProfile::StoppedRoundRobinPreparation => (
            RR_NATIVE_SOURCE,
            RR_HOOK_SOURCE.ok_or_else(|| refusal("RR diagnostic source issuer is not frozen"))?,
        ),
    };
    if config.schema_version != 2
        || config.root_source != ROOT_SOURCE
        || config.native_source != native_source
        || config.hook_source != hook_source
        || config.asset_source != ASSET_SOURCE
    {
        return Err(refusal("source/proposal provenance changed"));
    }
    let fixed_assets = [
        (
            &config.kernel,
            16_991_232,
            "af10eb4efed5a5d613e39bf983f0d5dd3e8990d5b3cdbccb4881adfb42258452",
        ),
        (
            &config.initrd,
            308_213,
            "8f9ccb428617f5ee3921b2d15874632c016310afe2ae54de575090624dc7b334",
        ),
        (
            &config.firmware,
            262_144,
            "04979dd3e1ad62c2e48f3b743e1a3653a85e44b89fbcd42973b17d6fb25f9dd1",
        ),
        (
            &config.disk,
            268_435_456,
            "a4d9df37ebff426f1bd548841a07a5b242f1815139f5fd5feeeb5b0861a31f0b",
        ),
    ];
    for (artifact, length, digest) in fixed_assets {
        if artifact.bytes != length || artifact.sha256 != digest {
            return Err(refusal(
                "artifact disagrees with the reviewed source-built asset roster",
            ));
        }
    }
    let mut artifacts = Vec::new();
    artifacts.try_reserve_exact(7)?;
    for artifact in [
        &config.qemu,
        &config.image_tool,
        &config.plugin,
        &config.kernel,
        &config.initrd,
        &config.firmware,
        &config.disk,
    ] {
        artifacts.push(OriginalArtifact::open(artifact)?);
    }
    if config.image_tool.path != config.qemu.path.with_file_name("qemu-img") {
        return Err(refusal("image helper is outside the original native tuple"));
    }
    let candidate = LaunchProfileCandidate::default()
        .with_memory_mib(128)
        .with_smp_vcpus(4)
        .with_run_seed(config.run_seed);
    let profile = candidate.try_into_deterministic()?;
    let entropy = profile.guest_entropy_seed_file();
    let now = clock_gettime(ClockId::Monotonic);
    let deadline = u64::try_from(now.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(now.tv_nsec as u64))
        .and_then(|value| value.checked_add(120_000_000_000))
        .ok_or_else(|| refusal("physical deadline overflow"))?;
    let scope: [u8; 32] = Sha256::digest(
        format!(
            "stopped-init:{}:{}:{}",
            ROOT_SOURCE,
            std::process::id(),
            deadline
        )
        .as_bytes(),
    )
    .into();
    let control = StagedControlProfile {
        compute: WholeControlProfile {
            scope,
            operation_capacity: 1,
            body_byte_limit: 65536,
            native_history_byte_limit: 128 * 1024 * 1024,
            provider_history_byte_limit: 32 * 1024 * 1024,
            administrative_read_attempt_limit: 4096,
            administrative_read_byte_limit: 8 * 1024 * 1024,
            administrative_write_attempt_limit: 4096,
            administrative_write_byte_limit: 8 * 1024 * 1024,
            deadline_monotonic_ns: deadline,
            cpu_retirement_limit: 1024,
            event_step_limit: 4096,
            input_byte_limit: 0,
            input_record_limit: 0,
            output_byte_limit: 0,
            output_record_limit: 0,
        },
        input_stage_limit: 1,
        stage_body_byte_limit: 1024,
    };
    let mut assets = [LaunchAsset {
        role: 0,
        present: true,
        inherited_fd: 0,
        byte_length: 0,
        sha256: [0; 32],
    }; 4];
    for (index, artifact) in artifacts[3..6].iter().enumerate() {
        assets[index] = LaunchAsset {
            role: (index + 1) as u16,
            present: true,
            inherited_fd: 10 + index as u32,
            byte_length: artifact.length,
            sha256: artifact.digest,
        };
    }
    assets[3] = LaunchAsset {
        role: 4,
        present: true,
        inherited_fd: 13,
        byte_length: 32,
        sha256: Sha256::digest(entropy.bytes()).into(),
    };
    let launch_parts = LaunchSelection2Parts {
        architecture: LaunchArchitecture::X86_64,
        kernel_command_line: profile.kernel_cmdline(),
        ram_byte_length: 128 * 1024 * 1024,
        ram_backing_kind: 2,
        ram_inherited_fd: u32::MAX,
        ram_backing_offset: 0,
        run_seed: config.run_seed,
        rr_switch_quantum: profile.rr_switch_quantum(),
        assets,
    };
    let mut launch_bytes = vec![0; launch_parts.encoded_len()?];
    launch_parts.encode_into(&mut launch_bytes)?;
    let launch = LaunchSelection2::decode(&launch_bytes)?;
    let roles = [LogicalQueueRole {
        role: WholeQueueRole::BlockRequest,
        node: "stopped-q35",
        port: "block",
        lane: "request",
    }];
    let selection = WholeConstructorSelection::new2(control, &launch, &roles)?;
    let vm = match config.diagnostic_profile {
        DiagnosticProfile::FourCpuInitialization => QemuVmLaunchConfig::new(
            "stopped-q35",
            artifacts[3].launch_artifact()?,
            artifacts[6].launch_artifact()?,
        ),
        DiagnosticProfile::StoppedRoundRobinPreparation => {
            // This explicit component profile owns no block/net/9p endpoint.
            // Its zero presence field never stands in for a full-world seal.
            QemuVmLaunchConfig::new_diskless(
                "stopped-q35",
                artifacts[3].launch_artifact()?,
                artifacts[5].launch_artifact()?,
            )
        }
    }
    .with_initrd(artifacts[4].launch_artifact()?)
    .with_firmware(artifacts[5].launch_artifact()?)
    .with_root_image_format(QemuRootImageFormat::Raw);
    let plugin = QemuLaunchPluginConfig::new(text(&config.plugin.path)?, 0)
        .with_fault_target_node("stopped-q35")
        .with_whole_constructor(selection);
    let command = QemuLaunchCommandBuilder::new_for_whole_preparing(
        profile,
        vm,
        text(&config.qemu.path)?,
        plugin,
    )?
    .build()?;
    let encoded_setup = command.plugin_setup_plan().encode()?;
    let setup_digest: [u8; 32] = Sha256::digest(&encoded_setup).into();
    let setup_extent = encoded_setup.len() as u64;
    drop(encoded_setup);

    // These are the actual production enforcement owners. No test-support
    // contract, guessed directory, /dev/null descriptor or Ready slot is used.
    let host_config = LinuxQemuAttemptHostConfig::new(
        &config.cgroup_root,
        &config.run_root,
        &config.namespace,
        config.first_project_id,
        1,
        config.child_uid,
        config.child_gid,
        128,
        32768,
        Duration::from_secs(15),
    )?;
    let mut factory = LinuxQemuAttemptHostFactory::open(host_config)?;
    let mut host = factory.begin(4, 512 * 1024 * 1024, 1024 * 1024 * 1024)?;
    let contract = host
        .process_contract()?
        .try_clone_for_attempt_generation()?;
    let expected_contract = host
        .process_contract()?
        .try_clone_for_attempt_generation()?;
    let mut directory = host.prepare_generation_run_directory(command.resource_requirements())?;
    let root_image = match config.diagnostic_profile {
        DiagnosticProfile::FourCpuInitialization => Some(config.disk.path.as_path()),
        DiagnosticProfile::StoppedRoundRobinPreparation => None,
    };
    if let Err(mut error) =
        directory.prepare_fresh_artifacts_guarded(&config.qemu.path, root_image, &contract)
    {
        if let Some(child) = error.take_unreaped_child() {
            host.retain_failed_child(child);
        }
        return Err(Box::new(error));
    }
    entropy.write_to_dir(directory.path())?;
    let retained = Rc::new(RefCell::new(None));
    let slot = QualifiedCustodySlot {
        original_contract: expected_contract,
        original_artifacts: artifacts,
        expected_setup: setup_digest,
        retained: Rc::clone(&retained),
    };
    let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    let spawn = match config.diagnostic_profile {
        DiagnosticProfile::FourCpuInitialization => {
            spawn_selected_qemu_child_for_stopped_initialization
        }
        DiagnosticProfile::StoppedRoundRobinPreparation => {
            spawn_selected_qemu_child_for_stopped_rr_preparation
        }
    };
    let mut original = spawn(
        &command,
        directory,
        RegionConfig::new(1, 1),
        0,
        contract,
        Box::new(slot),
        [reader, writer],
    )?;
    let original_pid = original.process_id();
    let mut initial_complete = false;
    let mut stopped_record = None;
    let record = loop {
        let physical = clock_gettime(ClockId::Monotonic);
        let physical_ns = u64::try_from(physical.tv_sec)?
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(physical.tv_nsec as u64))
            .ok_or_else(|| refusal("physical watchdog overflow"))?;
        if physical_ns >= deadline {
            return Err(refusal("original stopped constructor deadline exhausted"));
        }
        if !initial_complete {
            initial_complete = original.poll_initial_setup()?;
        }
        if stopped_record.is_none() {
            stopped_record = match config.diagnostic_profile {
                DiagnosticProfile::FourCpuInitialization => original
                    .poll_stopped_initialization_record()?
                    .map(StoppedRecord::Initialization),
                DiagnosticProfile::StoppedRoundRobinPreparation => original
                    .poll_stopped_rr_preparation_record()?
                    .map(StoppedRecord::RoundRobinPreparation),
            };
        }
        // The source may exit after transmitting SetupACK while the host still
        // owns a partial socket cursor. Finish that exact original journal; a
        // retained stdout record cannot replace the buffered acknowledgement.
        if initial_complete && let Some(record) = stopped_record {
            break record;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (status, record_bytes, endpoint_binding) = match &record {
        StoppedRecord::Initialization(bytes) => {
            validate_record(bytes, original_pid, setup_extent, setup_digest)?;
            ("STOPPED_INIT_PASS", bytes.as_slice(), None)
        }
        StoppedRecord::RoundRobinPreparation(bytes) => {
            let binding = validate_rr_record(bytes, original_pid, setup_extent, setup_digest)?;
            (
                "STOPPED_RR_PREPARATION_PASS",
                bytes.as_slice(),
                Some(hex(&binding)),
            )
        }
    };
    let output = serde_json::json!({"schema":2,"status":status,
        "qualification":"Preparing only; no RUN/guest/whole-source Ready",
        "process":original_pid,"native_source":native_source,"root_source":ROOT_SOURCE,
        "setup_sha256":hex(&setup_digest),"setup_extent":setup_extent,
        "endpoint_binding_digest":endpoint_binding,"record_hex":hex(record_bytes)});
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    serde_json::to_writer(&mut file, &output)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    // Natural reap does not retire the native mapping or source journals.
    // Keep the original capsule in the preclaimed supervisor mailbox.
    drop(original);
    if retained.borrow().is_none() {
        return Err(refusal("original custody was not retained"));
    }
    let _retained_until_supervisor_exit = Box::leak(Box::new((host, factory, retained)));
    println!("{status} pid={original_pid}");
    Ok(())
}

fn validate_record(
    record: &[u8; 128],
    pid: u32,
    extent: u64,
    digest: [u8; 32],
) -> Result<(), Box<dyn Error>> {
    if &record[..8] != b"CWINIT01"
        || be32(record, 8) != 1
        || be32(record, 12) != 128
        || be64(record, 16) != u64::from(pid)
        || be64(record, 24) != u64::from(pid)
        || be64(record, 32) == 0
        || be64(record, 40) != 0
        || be64(record, 48) != 0
        || be32(record, 56) != 15
        || be32(record, 60) != 0
        || be64(record, 64) != extent
        || record[72..104] != digest
        || be32(record, 120) != 15
        || be32(record, 124) != 0
    {
        return Err(refusal(
            "original stopped record scope/clock/setup fields changed",
        ));
    }
    for index in 0..4 {
        if be32(record, 104 + 4 * index) != index as u32 {
            return Err(refusal("original four-CPU roster changed"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum StoppedRecord {
    Initialization([u8; 128]),
    RoundRobinPreparation([u8; 192]),
}

fn validate_rr_record(
    record: &[u8; 192],
    pid: u32,
    extent: u64,
    digest: [u8; 32],
) -> Result<[u8; 32], Box<dyn Error>> {
    if &record[..8] != b"CWRRPRP1"
        || be32(record, 8) != 1
        || be32(record, 12) != 192
        || be64(record, 16) != u64::from(pid)
        || be64(record, 24) != u64::from(pid)
        || be64(record, 32) == 0
        || be64(record, 32) == u64::from(pid)
        || be64(record, 40) != 0
        || be64(record, 48) != 0
        || be32(record, 56) != 15
        || be32(record, 60) != 31
        || be64(record, 64) != extent
        || record[72..104] != digest
        || be32(record, 120) != 15
        || be32(record, 124) != 0
        || be32(record, 128) != 4
        || be32(record, 132) != 31
        || record[136..168].iter().all(|byte| *byte == 0)
        || record[168..].iter().any(|byte| *byte != 0)
    {
        return Err(refusal("original stopped RR preparation fields changed"));
    }
    for index in 0..4 {
        if be32(record, 104 + 4 * index) != index as u32 {
            return Err(refusal("original stopped RR four-CPU roster changed"));
        }
    }
    // The original source issues this process-private binding correlation.
    // Host metadata cannot recompute it or turn it into effect permission.
    let mut binding = [0; 32];
    binding.copy_from_slice(&record[136..168]);
    Ok(binding)
}

fn be32<const BYTES: usize>(bytes: &[u8; BYTES], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(value)
}

fn be64<const BYTES: usize>(bytes: &[u8; BYTES], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn text(path: &Path) -> Result<&str, Box<dyn Error>> {
    path.to_str()
        .ok_or_else(|| refusal("artifact path is not UTF-8"))
}

fn refusal(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Diagnostic codec assertions intentionally panic on failure."
)]
mod tests {
    use super::*;

    fn rr_record() -> [u8; 192] {
        let mut record = [0; 192];
        record[..8].copy_from_slice(b"CWRRPRP1");
        for (offset, value) in [
            (8, 1_u32),
            (12, 192),
            (56, 15),
            (60, 31),
            (104, 0),
            (108, 1),
            (112, 2),
            (116, 3),
            (120, 15),
            (128, 4),
            (132, 31),
        ] {
            record[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [(16, 42_u64), (24, 42), (32, 43), (64, 1004)] {
            record[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        record[72..104].fill(17);
        record[136..168].fill(19);
        record
    }

    #[test]
    fn rr_record_requires_explicit_phase_scope_and_source_correlation() {
        let original = rr_record();
        assert_eq!(
            validate_rr_record(&original, 42, 1004, [17; 32]).unwrap(),
            [19; 32]
        );

        for offset in [
            0, 8, 12, 16, 24, 40, 48, 56, 60, 64, 72, 108, 120, 124, 128, 132, 168, 176, 184,
        ] {
            let mut changed = original;
            changed[offset] ^= 1;
            assert!(validate_rr_record(&changed, 42, 1004, [17; 32]).is_err());
        }
        let mut no_binding = original;
        no_binding[136..168].fill(0);
        assert!(validate_rr_record(&no_binding, 42, 1004, [17; 32]).is_err());
        let mut constructor_thread = original;
        constructor_thread[32..40].copy_from_slice(&42_u64.to_be_bytes());
        assert!(validate_rr_record(&constructor_thread, 42, 1004, [17; 32]).is_err());
    }

    #[test]
    fn old_init_record_cannot_be_reinterpreted_as_rr_preparation() {
        let mut old = rr_record();
        old[..8].copy_from_slice(b"CWINIT01");
        old[12..16].copy_from_slice(&128_u32.to_be_bytes());
        old[60..64].fill(0);
        old[128..].fill(0);
        assert!(validate_rr_record(&old, 42, 1004, [17; 32]).is_err());
    }
}

fn spawn_refusal(message: impl Into<String>) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation: "authenticate original stopped constructor custody",
        source: io::Error::other(message.into()),
    }
}
