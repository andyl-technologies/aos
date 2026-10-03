//! Exact VMState and host-continuation capture at completed boundaries.

use super::*;
use crate::ProductionFaultRuntimeCheckpoint;
use crucible::{
    Checkpoint, Configuration, ContentHash, NodeId, SingleSchedulerCheckpoint, VirtualTime,
};
#[cfg(target_os = "linux")]
use rustix::fs::{FileType, OFlags, SeekFrom, fcntl_getfl, fstat, seek};
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Read as _;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

mod capture;

const EXACT_RAM_TARGET_IDENTITY_DOMAIN: &str = "crucible.production-vm-exact-ram-target.v1";
const EXACT_RAM_FRONTIER_IDENTITY_DOMAIN: &str = "crucible.production-vm-exact-ram-frontier.v1";

/// Typed immutable provenance for one production exact-checkpoint capture.
struct QemuExactCheckpointCaptureBasis<'a> {
    configuration: &'a Configuration,
    immutable_backing: ContentHash,
    node: &'a NodeId,
    counter: u64,
    scheduler_time: VirtualTime,
    checkpoint: &'a Checkpoint,
    fault_identity: ContentHash,
    scheduler: &'a SingleSchedulerCheckpoint,
}

/// Modeled boundary authenticated for one exact checkpoint capture.
pub struct QemuExactCheckpointCaptureBoundary<'a> {
    /// Configuration whose node is being captured.
    pub configuration: &'a Configuration,
    /// Immutable guest root image used by the captured process.
    pub immutable_root_image: &'a Path,
    /// Node whose execution boundary is being captured.
    pub node: &'a NodeId,
    /// Node-local retired-instruction counter at the boundary.
    pub counter: u64,
    /// Scheduler frontier at the boundary.
    pub scheduler_time: VirtualTime,
    /// Modeled checkpoint that owns the capture.
    pub checkpoint: &'a Checkpoint,
    /// Fault-runtime continuation bound to the checkpoint.
    pub fault: &'a ProductionFaultRuntimeCheckpoint,
    /// Scheduler continuation bound to the checkpoint.
    pub scheduler: &'a SingleSchedulerCheckpoint,
}

/// Output limits and paths for one exact checkpoint capture.
pub struct QemuExactCheckpointCaptureOutputs<'a> {
    /// Maximum admitted RAM output length.
    pub maximum_ram_bytes: u64,
    /// Maximum admitted device-state output length.
    pub maximum_device_bytes: u64,
    /// Path whose already-opened file receives RAM bytes.
    pub ram: &'a Path,
    /// Path whose already-opened file receives device-state bytes.
    pub device: &'a Path,
}

impl<'a> QemuExactCheckpointCaptureBasis<'a> {
    /// Authenticates all immutable inputs used to derive the QMP identity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the checkpoint does not belong to the
    /// supplied configuration, node counter, virtual time, or scenario.
    fn admit(boundary: QemuExactCheckpointCaptureBoundary<'a>) -> Result<Self, QemuNodeError> {
        let QemuExactCheckpointCaptureBoundary {
            configuration,
            immutable_root_image,
            node,
            counter,
            scheduler_time,
            checkpoint,
            fault,
            scheduler,
        } = boundary;
        let immutable_backing = hash_capture_input(immutable_root_image).map_err(|error| {
            QemuNodeError::checkpoint(format!(
                "hash exact checkpoint immutable root {}: {error}",
                immutable_root_image.display()
            ))
        })?;
        let fault_identity = fault.id();
        let node_counter = checkpoint
            .node_icounts
            .get(node)
            .map(|icount| icount.retired);
        if checkpoint.configuration != configuration.id()
            || checkpoint.scenario_ref != configuration.def.id()
            || checkpoint.virtual_time != scheduler_time
            || node_counter != Some(counter)
        {
            return Err(QemuNodeError::checkpoint(
                "exact checkpoint capture provenance does not match the modeled boundary",
            ));
        }
        let scheduler_configuration =
            scheduler
                .configuration_for(&configuration.def)
                .map_err(|error| {
                    QemuNodeError::checkpoint(format!(
                        "exact checkpoint scheduler continuation is invalid: {error}"
                    ))
                })?;
        if scheduler_configuration.id() != configuration.id()
            || scheduler.frontier() != scheduler_time
        {
            return Err(QemuNodeError::checkpoint(
                "exact checkpoint scheduler continuation does not match the modeled boundary",
            ));
        }
        Ok(Self {
            configuration,
            immutable_backing,
            node,
            counter,
            scheduler_time,
            checkpoint,
            fault_identity,
            scheduler,
        })
    }

    /// Derives the exact target and scheduler-frontier identity.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the scheduler continuation cannot be
    /// encoded canonically.
    fn derive_identity(&self) -> Result<crate::QmpCheckpointIdentity, QemuNodeError> {
        let target = ContentHash::from_canonical_material(
            EXACT_RAM_TARGET_IDENTITY_DOMAIN,
            &format!(
                "configuration={}\nimmutable_backing={}\nnode={}\ncounter={}\nscheduler_time={}\nfault={}",
                self.configuration.id().to_hex(),
                self.immutable_backing.to_hex(),
                self.node.name,
                self.counter,
                self.scheduler_time.ticks,
                self.fault_identity.to_hex(),
            ),
        );
        let scheduler_bytes = self.scheduler.canonical_bytes().map_err(|error| {
            QemuNodeError::checkpoint(format!("encode exact RAM scheduler frontier: {error}"))
        })?;
        let mut scheduler_hex = String::with_capacity(scheduler_bytes.len().saturating_mul(2));
        use std::fmt::Write as _;
        for byte in scheduler_bytes {
            let _ = write!(scheduler_hex, "{byte:02x}");
        }
        let frontier = ContentHash::from_canonical_material(
            EXACT_RAM_FRONTIER_IDENTITY_DOMAIN,
            &scheduler_hex,
        );
        Ok(crate::QmpCheckpointIdentity::new(
            self.checkpoint.id,
            target,
            frontier,
        ))
    }
}

/// Borrowed descriptor set consumed by one exact checkpoint capture command.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct QemuExactCheckpointCaptureDescriptors<'a> {
    ram: BorrowedFd<'a>,
    device: BorrowedFd<'a>,
    cancellation: BorrowedFd<'a>,
}

/// Validated capture request and output ownership for one exact checkpoint.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct QemuExactCheckpointCaptureAdmission {
    checkpoint: ContentHash,
    node: NodeId,
    request: crate::QmpCheckpointCaptureRequest,
    ram: File,
    device: File,
}

#[cfg(target_os = "linux")]
impl QemuExactCheckpointCaptureAdmission {
    /// Admits one checkpoint-bound direct capture and its owned output handles.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the identity belongs to another checkpoint,
    /// the request bounds are invalid, either descriptor is not a writable
    /// regular file, or the descriptors alias.
    pub fn admit_direct(
        boundary: QemuExactCheckpointCaptureBoundary<'_>,
        outputs: QemuExactCheckpointCaptureOutputs<'_>,
    ) -> Result<Self, QemuNodeError> {
        let basis = QemuExactCheckpointCaptureBasis::admit(boundary)?;
        let QemuExactCheckpointCaptureOutputs {
            maximum_ram_bytes,
            maximum_device_bytes,
            ram: ram_output,
            device: device_output,
        } = outputs;
        let identity = basis.derive_identity()?;
        let request = crate::QmpCheckpointCaptureRequest::direct(
            identity,
            capture_descriptor("crucible-checkpoint-ram")?,
            capture_descriptor("crucible-checkpoint-device")?,
            capture_descriptor("crucible-checkpoint-cancel")?,
            maximum_ram_bytes,
            maximum_device_bytes,
        )
        .map_err(|error| {
            QemuNodeError::checkpoint(format!("build exact capture request: {error}"))
        })?;
        Self::admit(
            basis.checkpoint,
            basis.node.clone(),
            request,
            ram_output,
            device_output,
        )
    }

    /// Admits one checkpoint-bound delta capture and its owned output handles.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeError`] when the child or parent identity is invalid,
    /// the request bounds are invalid, either descriptor is not a writable
    /// regular file, or the descriptors alias.
    pub fn admit_delta(
        boundary: QemuExactCheckpointCaptureBoundary<'_>,
        parent: crate::QmpCheckpointIdentity,
        outputs: QemuExactCheckpointCaptureOutputs<'_>,
    ) -> Result<Self, QemuNodeError> {
        let basis = QemuExactCheckpointCaptureBasis::admit(boundary)?;
        let QemuExactCheckpointCaptureOutputs {
            maximum_ram_bytes,
            maximum_device_bytes,
            ram: ram_output,
            device: device_output,
        } = outputs;
        let identity = basis.derive_identity()?;
        if basis.checkpoint.parent != Some(parent.checkpoint()) {
            return Err(QemuNodeError::checkpoint(
                "exact checkpoint delta parent does not match the modeled checkpoint parent",
            ));
        }
        let request = crate::QmpCheckpointCaptureRequest::delta(
            identity,
            parent,
            capture_descriptor("crucible-checkpoint-ram")?,
            capture_descriptor("crucible-checkpoint-device")?,
            capture_descriptor("crucible-checkpoint-cancel")?,
            maximum_ram_bytes,
            maximum_device_bytes,
        )
        .map_err(|error| {
            QemuNodeError::checkpoint(format!("build exact capture request: {error}"))
        })?;
        Self::admit(
            basis.checkpoint,
            basis.node.clone(),
            request,
            ram_output,
            device_output,
        )
    }

    fn admit(
        checkpoint: &Checkpoint,
        node: NodeId,
        request: crate::QmpCheckpointCaptureRequest,
        ram_output: &Path,
        device_output: &Path,
    ) -> Result<Self, QemuNodeError> {
        validate_exact_checkpoint_request_binding(checkpoint, &request)?;
        let ram = create_capture_output(ram_output, "RAM")?;
        let device = match create_capture_output(device_output, "device-state") {
            Ok(device) => device,
            Err(error) => {
                drop(ram);
                let _ = std::fs::remove_file(ram_output);
                return Err(error);
            }
        };
        validate_exact_checkpoint_capture_outputs(ram.as_fd(), device.as_fd())?;
        Ok(Self {
            checkpoint: checkpoint.id,
            node,
            request,
            ram,
            device,
        })
    }
}

#[cfg(target_os = "linux")]
fn create_capture_output(path: &Path, role: &str) -> Result<File, QemuNodeError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            QemuNodeError::checkpoint(format!(
                "create exact checkpoint {role} output {}: {error}",
                path.display()
            ))
        })
}

#[cfg(target_os = "linux")]
fn hash_capture_input(path: &Path) -> Result<ContentHash, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    })
}

#[cfg(target_os = "linux")]
fn capture_descriptor(name: &'static str) -> Result<crate::QmpDescriptorName, QemuNodeError> {
    crate::QmpDescriptorName::new(name)
        .map_err(|error| QemuNodeError::checkpoint(format!("name capture descriptor: {error}")))
}

#[cfg(target_os = "linux")]
fn validate_exact_checkpoint_capture_outputs(
    ram: BorrowedFd<'_>,
    device: BorrowedFd<'_>,
) -> Result<(), QemuNodeError> {
    let ram_metadata = fstat(ram)
        .map_err(|error| QemuNodeError::checkpoint(format!("inspect exact RAM output: {error}")))?;
    let device_metadata = fstat(device).map_err(|error| {
        QemuNodeError::checkpoint(format!("inspect exact device-state output: {error}"))
    })?;
    if FileType::from_raw_mode(ram_metadata.st_mode) != FileType::RegularFile
        || FileType::from_raw_mode(device_metadata.st_mode) != FileType::RegularFile
    {
        return Err(QemuNodeError::checkpoint(
            "exact checkpoint outputs must be regular files",
        ));
    }
    if ram_metadata.st_size != 0 || device_metadata.st_size != 0 {
        return Err(QemuNodeError::checkpoint(
            "exact checkpoint outputs must be newly created empty files",
        ));
    }
    let ram_offset = seek(ram, SeekFrom::Current(0)).map_err(|error| {
        QemuNodeError::checkpoint(format!("inspect exact RAM output offset: {error}"))
    })?;
    let device_offset = seek(device, SeekFrom::Current(0)).map_err(|error| {
        QemuNodeError::checkpoint(format!("inspect exact device-state output offset: {error}"))
    })?;
    if ram_offset != 0 || device_offset != 0 {
        return Err(QemuNodeError::checkpoint(
            "exact checkpoint outputs must begin at offset zero",
        ));
    }
    let writable = |descriptor| {
        fcntl_getfl(descriptor)
            .map(|flags| flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR))
    };
    if !writable(ram).map_err(|error| {
        QemuNodeError::checkpoint(format!("inspect exact RAM output access mode: {error}"))
    })? || !writable(device).map_err(|error| {
        QemuNodeError::checkpoint(format!(
            "inspect exact device-state output access mode: {error}"
        ))
    })? {
        return Err(QemuNodeError::checkpoint(
            "exact checkpoint outputs must be writable",
        ));
    }
    if ram_metadata.st_dev == device_metadata.st_dev
        && ram_metadata.st_ino == device_metadata.st_ino
    {
        return Err(QemuNodeError::checkpoint(
            "exact RAM and device-state outputs must be distinct files",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
impl<'a> QemuExactCheckpointCaptureDescriptors<'a> {
    /// Binds the RAM, device-state, and cancellation descriptors for capture.
    #[must_use]
    pub(crate) const fn new(
        ram: BorrowedFd<'a>,
        device: BorrowedFd<'a>,
        cancellation: BorrowedFd<'a>,
    ) -> Self {
        Self {
            ram,
            device,
            cancellation,
        }
    }
}

/// Host continuation and QEMU report produced by one exact RAM capture.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct QemuExactCheckpointCaptureResult {
    snapshot: crate::QemuVmSnapshot,
    qemu: crate::QmpCheckpointCapture,
    parent: Option<crate::QmpCheckpointIdentity>,
    ram: File,
    device: File,
}

#[cfg(target_os = "linux")]
impl QemuExactCheckpointCaptureResult {
    /// Returns the captured Apache host continuation.
    #[must_use]
    pub const fn snapshot(&self) -> &crate::QemuVmSnapshot {
        &self.snapshot
    }

    /// Returns whether QEMU emitted complete or parent-relative RAM.
    #[must_use]
    pub const fn ram_kind(&self) -> crate::QmpCheckpointRamKind {
        self.qemu.kind()
    }

    /// Returns the checkpoint, target, and scheduler-frontier identity.
    #[must_use]
    pub const fn identity(&self) -> crate::QmpCheckpointIdentity {
        self.qemu.identity()
    }

    /// Returns the exact committed parent used for a delta capture.
    #[must_use]
    pub const fn parent(&self) -> Option<crate::QmpCheckpointIdentity> {
        self.parent
    }

    /// Returns the canonical RAMBlock topology identity.
    #[must_use]
    pub const fn topology(&self) -> crucible::ContentHash {
        self.qemu.topology()
    }

    /// Returns the number of canonical RAM regions in the artifact.
    #[must_use]
    pub const fn ram_regions(&self) -> u64 {
        self.qemu.ram_regions()
    }

    /// Returns the number of RAM records emitted by QEMU.
    #[must_use]
    pub const fn ram_records(&self) -> u64 {
        self.qemu.ram_records()
    }

    /// Returns the exact encoded RAM artifact length.
    #[must_use]
    pub const fn ram_bytes(&self) -> u64 {
        self.qemu.ram_bytes()
    }

    /// Returns the exact encoded device-state artifact length.
    #[must_use]
    pub const fn device_bytes(&self) -> u64 {
        self.qemu.device_bytes()
    }

    /// Returns the pinned RAM and device-state outputs written by QEMU.
    ///
    /// The files continue to name the admitted inodes even if an attacker
    /// replaces either staging pathname after capture. Callers must read these
    /// handles, rather than reopen the paths, through durable publication.
    #[must_use]
    pub fn output_files_mut(&mut self) -> (&mut File, &mut File) {
        (&mut self.ram, &mut self.device)
    }
}

#[cfg(target_os = "linux")]
struct ExactRamCapture<'a> {
    request: &'a crate::QmpCheckpointCaptureRequest,
    descriptors: QemuExactCheckpointCaptureDescriptors<'a>,
}

enum SnapshotCapture<'a> {
    NativeVmState(std::marker::PhantomData<&'a ()>),
    #[cfg(target_os = "linux")]
    ExactRam(ExactRamCapture<'a>),
}

impl SnapshotCapture<'_> {
    const fn native_vmstate() -> Self {
        Self::NativeVmState(std::marker::PhantomData)
    }
}

fn validate_exact_checkpoint_request_binding(
    checkpoint: &Checkpoint,
    request: &crate::QmpCheckpointCaptureRequest,
) -> Result<(), QemuNodeError> {
    if request.identity().checkpoint() != checkpoint.id {
        return Err(QemuNodeError::checkpoint(
            "exact RAM request identity does not name the captured host checkpoint",
        ));
    }
    Ok(())
}

fn validate_capture_admission_binding(
    admitted_checkpoint: ContentHash,
    admitted_node: &NodeId,
    checkpoint: ContentHash,
    node: &NodeId,
) -> Result<(), QemuNodeError> {
    if admitted_checkpoint != checkpoint {
        return Err(QemuNodeError::checkpoint(
            "exact checkpoint capture admission belongs to another checkpoint",
        ));
    }
    if admitted_node != node {
        return Err(QemuNodeError::checkpoint(
            "exact checkpoint capture admission belongs to another modeled node",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod capture_admission_tests {
    use super::{validate_capture_admission_binding, validate_exact_checkpoint_capture_outputs};
    use crucible::{ContentHash, NodeId};
    use std::error::Error;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Seek as _, SeekFrom, Write as _};
    use std::os::fd::AsFd as _;

    #[test]
    fn capture_outputs_reject_the_same_file_for_ram_and_device_state() -> Result<(), Box<dyn Error>>
    {
        let output = tempfile::NamedTempFile::new()?;

        let error = validate_exact_checkpoint_capture_outputs(
            output.as_file().as_fd(),
            output.as_file().as_fd(),
        )
        .err()
        .ok_or_else(|| io::Error::other("aliased capture outputs were accepted"))?;

        assert!(error.to_string().contains("must be distinct files"));
        Ok(())
    }

    #[test]
    fn capture_outputs_reject_read_only_files() -> Result<(), Box<dyn Error>> {
        let ram = tempfile::NamedTempFile::new()?;
        let device = tempfile::NamedTempFile::new()?;
        let read_only_ram = File::open(ram.path())?;
        let writable_device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device.path())?;

        let error = validate_exact_checkpoint_capture_outputs(
            read_only_ram.as_fd(),
            writable_device.as_fd(),
        )
        .err()
        .ok_or_else(|| io::Error::other("read-only capture output was accepted"))?;

        assert!(error.to_string().contains("must be writable"));
        Ok(())
    }

    #[test]
    fn capture_outputs_reject_non_regular_descriptors() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let directory_file = File::open(directory.path())?;
        let device = tempfile::NamedTempFile::new()?;

        let error = validate_exact_checkpoint_capture_outputs(
            directory_file.as_fd(),
            device.as_file().as_fd(),
        )
        .err()
        .ok_or_else(|| io::Error::other("directory capture output was accepted"))?;

        assert!(error.to_string().contains("must be regular files"));
        Ok(())
    }

    #[test]
    fn capture_outputs_reject_nonempty_files() -> Result<(), Box<dyn Error>> {
        let mut ram = tempfile::NamedTempFile::new()?;
        let device = tempfile::NamedTempFile::new()?;
        ram.write_all(b"already populated")?;

        let error = validate_exact_checkpoint_capture_outputs(
            ram.as_file().as_fd(),
            device.as_file().as_fd(),
        )
        .err()
        .ok_or_else(|| io::Error::other("nonempty capture output was accepted"))?;

        assert!(error.to_string().contains("newly created empty files"));
        Ok(())
    }

    #[test]
    fn capture_outputs_reject_nonzero_offsets() -> Result<(), Box<dyn Error>> {
        let mut ram = tempfile::NamedTempFile::new()?;
        let device = tempfile::NamedTempFile::new()?;
        ram.as_file_mut().seek(SeekFrom::Start(1))?;

        let error = validate_exact_checkpoint_capture_outputs(
            ram.as_file().as_fd(),
            device.as_file().as_fd(),
        )
        .err()
        .ok_or_else(|| io::Error::other("nonzero output offset was accepted"))?;

        assert!(error.to_string().contains("offset zero"));
        Ok(())
    }

    #[test]
    fn capture_admission_rejects_another_modeled_node() -> Result<(), Box<dyn Error>> {
        let checkpoint = ContentHash::from_bytes(b"capture checkpoint");
        let admitted = NodeId {
            name: String::from("admitted"),
        };
        let supplied = NodeId {
            name: String::from("supplied"),
        };

        let error =
            validate_capture_admission_binding(checkpoint, &admitted, checkpoint, &supplied)
                .err()
                .ok_or_else(|| {
                    io::Error::other("capture admission moved to another modeled node")
                })?;

        assert!(error.to_string().contains("another modeled node"));
        Ok(())
    }
}
