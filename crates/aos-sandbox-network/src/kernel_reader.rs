//! Privileged, read-only Linux Network inventory decoding.
//!
//! The fixed C BPF reader validates the complete pin set, map schemas, TCX
//! query results, program/map relationships, and reserved ABI fields before it
//! emits this closed JSON record. This module independently rejects unknown,
//! malformed, oversized, noncanonical, or internally inconsistent output and
//! converts it to the semantic kernel observation model.

use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::process::{FixedProcessOutcome, FixedProcessRequest, run_fixed_process};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::kernel_observation::{
    ObservedBpfArtifactV1, ObservedBpfAttachmentV1, ObservedBpfBindingV1, ObservedBpfMapV1,
    ObservedInterfaceV1, ObservedLeaseDirectionV1, ObservedLeaseGateV1, ObservedLeaseStateV1,
    ObservedNetworkNamespaceV1,
};

const MAXIMUM_BPF_OBSERVATION_BYTES: usize = 64 * 1024;
const MAXIMUM_BPF_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_HELPER_STDERR_BYTES: usize = 16 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);
const BPF_PIN_PREFIX: &str = "/sys/fs/bpf/aos/sandbox-network";
const NIX_STORE_ROOT: &str = "/nix/store";

/// Reports unreadable, malformed, extra, or inconsistent live kernel evidence.
#[derive(Debug, thiserror::Error)]
pub enum NetworkKernelReaderError {
    /// The fixed helper emitted an oversized or invalid closed JSON record.
    #[error("invalid Network BPF observation: {0}")]
    InvalidBpf(&'static str),
    /// The fixed iproute2 reader emitted unsupported or incomplete state.
    #[error("invalid Network rtnetlink observation: {0}")]
    InvalidRtnetlink(&'static str),
    /// The fixed nftables reader emitted unsupported or incomplete state.
    #[error("invalid Network nftables observation: {0}")]
    InvalidNftables(&'static str),
    /// JSON syntax or the closed schema was invalid.
    #[error("invalid Network BPF observation JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A fixed executable or immutable artifact path is unsafe.
    #[error("invalid fixed Network observer artifact: {0}")]
    InvalidArtifact(&'static str),
    /// A local file could not be opened, measured, or revalidated.
    #[error("Network kernel observer I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The bounded fixed helper process could not be executed safely.
    #[error("Network kernel observer process failed: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The fixed helper timed out, exceeded output bounds, or rejected state.
    #[error("fixed Network observer did not return a complete snapshot")]
    HelperFailed,
}

/// Executes the fixed read-only BPF observer against a handle-derived pin root.
#[derive(Debug)]
pub struct FixedBpfObservationReader {
    helper: PinnedArtifact,
    gate_object: PinnedArtifact,
}

impl FixedBpfObservationReader {
    /// Resolves and pins immutable helper and BPF object files in the Nix store.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelReaderError`] unless both paths are normalized
    /// Nix store paths reached through root-owned, protected, symlink-free
    /// ancestry and name root-owned regular files with no write bits. Their
    /// retained descriptors must have stable identities and contents inside
    /// the fixed byte ceiling.
    pub fn new(helper: PathBuf, gate_object: PathBuf) -> Result<Self, NetworkKernelReaderError> {
        Ok(Self {
            helper: PinnedArtifact::open(helper, true)?,
            gate_object: PinnedArtifact::open(gate_object, false)?,
        })
    }

    /// Reads one complete live BPF graph for a plan-derived handle.
    ///
    /// The only helper argument is derived from `network_handle`; no caller
    /// path, pin name, object name, program ID, map ID, or interface name can
    /// enter the invocation. The helper and measured object are revalidated
    /// before and after the bounded process.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelReaderError`] for a zero handle, changed fixed
    /// artifact, process timeout/failure, output overflow, or rejected snapshot.
    pub fn observe(
        &self,
        network_handle: [u8; 32],
    ) -> Result<ObservedLeaseGateV1, NetworkKernelReaderError> {
        if network_handle == [0; 32] {
            return Err(NetworkKernelReaderError::InvalidBpf(
                "network handle is zero",
            ));
        }
        self.gate_object.validate_current()?;

        let pin_root = format!("{BPF_PIN_PREFIX}/{}", encode_hex(network_handle));
        let output = self
            .helper
            .run(&[OsString::from(pin_root)], MAXIMUM_BPF_OBSERVATION_BYTES)?;
        let stdout = successful_helper_stdout(output)?;

        self.gate_object.validate_current()?;
        decode_bpf_observation(&stdout, self.gate_object.digest)
    }
}

pub(crate) fn successful_helper_stdout(
    outcome: FixedProcessOutcome,
) -> Result<Vec<u8>, NetworkKernelReaderError> {
    match outcome {
        FixedProcessOutcome::Completed(output)
            if output.exit_code == Some(0) && output.signal.is_none() =>
        {
            Ok(output.stdout)
        }
        FixedProcessOutcome::Completed(_)
        | FixedProcessOutcome::TimedOut
        | FixedProcessOutcome::OutputLimitExceeded => Err(NetworkKernelReaderError::HelperFailed),
    }
}

#[derive(Debug)]
pub(crate) struct PinnedArtifact {
    path: PathBuf,
    descriptor: File,
    ancestors: Vec<ArtifactAncestor>,
    identity: ArtifactIdentity,
    digest: ObjectDigest,
}

#[derive(Debug)]
struct ArtifactAncestor {
    descriptor: OwnedFd,
    identity: DirectoryIdentity,
    policy: DirectoryPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryPolicy {
    Protected,
    StoreRoot,
    Immutable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    owner: u32,
    group: u32,
}

impl PinnedArtifact {
    pub(crate) fn open(path: PathBuf, executable: bool) -> Result<Self, NetworkKernelReaderError> {
        let components = validate_artifact_path(&path)?;
        let (descriptor, ancestors) = open_store_artifact(&components)?;
        let identity = ArtifactIdentity::from_descriptor(&descriptor, executable)?;
        let digest = measure_file(&descriptor, identity.size)?;
        let artifact = Self {
            path,
            descriptor,
            ancestors,
            identity,
            digest,
        };
        artifact.validate_current()?;
        Ok(artifact)
    }

    pub(crate) fn validate_current(&self) -> Result<(), NetworkKernelReaderError> {
        for ancestor in &self.ancestors {
            let current =
                DirectoryIdentity::from_descriptor(&ancestor.descriptor, ancestor.policy)?;
            if current != ancestor.identity {
                return Err(NetworkKernelReaderError::InvalidArtifact(
                    "artifact ancestry changed",
                ));
            }
        }

        let executable = self.identity.mode & 0o111 != 0;
        let current = ArtifactIdentity::from_descriptor(&self.descriptor, executable)?;
        if current != self.identity || measure_file(&self.descriptor, current.size)? != self.digest
        {
            return Err(NetworkKernelReaderError::InvalidArtifact(
                "artifact identity or contents changed",
            ));
        }

        let components = validate_artifact_path(&self.path)?;
        let (resolved, resolved_ancestors) = open_store_artifact(&components)?;
        let resolved_identity = ArtifactIdentity::from_descriptor(&resolved, executable)?;
        if resolved_identity != self.identity
            || resolved_ancestors.len() != self.ancestors.len()
            || resolved_ancestors
                .iter()
                .zip(&self.ancestors)
                .any(|(current, retained)| current.identity != retained.identity)
        {
            return Err(NetworkKernelReaderError::InvalidArtifact(
                "fixed artifact path no longer names its retained object",
            ));
        }
        Ok(())
    }

    pub(crate) const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(crate) fn run(
        &self,
        arguments: &[OsString],
        maximum_stdout_bytes: usize,
    ) -> Result<FixedProcessOutcome, NetworkKernelReaderError> {
        self.validate_current()?;
        let outcome = run_fixed_process(FixedProcessRequest {
            executable: &self.path,
            arguments,
            timeout: HELPER_TIMEOUT,
            maximum_stdout_bytes,
            maximum_stderr_bytes: MAXIMUM_HELPER_STDERR_BYTES,
        })?;
        self.validate_current()?;
        Ok(outcome)
    }
}

impl ArtifactIdentity {
    fn from_descriptor(
        descriptor: &File,
        executable: bool,
    ) -> Result<Self, NetworkKernelReaderError> {
        let metadata = rustix::fs::fstat(descriptor).map_err(kernel_io)?;
        let size = u64::try_from(metadata.st_size)
            .map_err(|_| NetworkKernelReaderError::InvalidArtifact("artifact size is negative"))?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
            != rustix::fs::FileType::RegularFile
            || metadata.st_uid != 0
            || metadata.st_mode & 0o222 != 0
            || executable != (metadata.st_mode & 0o111 != 0)
            || size == 0
            || size > MAXIMUM_BPF_OBJECT_BYTES as u64
        {
            return Err(NetworkKernelReaderError::InvalidArtifact(
                "artifact metadata violates the fixed contract",
            ));
        }
        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            size,
            mode: metadata.st_mode,
            owner: metadata.st_uid,
            group: metadata.st_gid,
        })
    }
}

impl DirectoryIdentity {
    fn from_descriptor(
        descriptor: &OwnedFd,
        policy: DirectoryPolicy,
    ) -> Result<Self, NetworkKernelReaderError> {
        let metadata = rustix::fs::fstat(descriptor).map_err(kernel_io)?;
        let protected = valid_directory_mode(policy, metadata.st_mode);
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory
            || metadata.st_uid != 0
            || !protected
        {
            return Err(NetworkKernelReaderError::InvalidArtifact(
                "artifact ancestry is not protected",
            ));
        }
        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mode: metadata.st_mode,
            owner: metadata.st_uid,
            group: metadata.st_gid,
        })
    }
}

const fn valid_directory_mode(policy: DirectoryPolicy, mode: u32) -> bool {
    match policy {
        DirectoryPolicy::Protected => mode & 0o022 == 0,
        // Multi-user Nix stores are normally 01775. The sticky bit keeps
        // nixbld members from replacing an existing root-owned store entry.
        DirectoryPolicy::StoreRoot => {
            mode & 0o002 == 0 && (mode & 0o020 == 0 || mode & 0o1000 != 0)
        }
        DirectoryPolicy::Immutable => mode & 0o222 == 0,
    }
}

fn validate_artifact_path(path: &Path) -> Result<Vec<OsString>, NetworkKernelReaderError> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4096 {
        return Err(NetworkKernelReaderError::InvalidArtifact(
            "artifact path is not an absolute fixed-store path",
        ));
    }
    let relative = path.strip_prefix(NIX_STORE_ROOT).map_err(|_| {
        NetworkKernelReaderError::InvalidArtifact("artifact is outside the fixed Nix store")
    })?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_owned()),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => Err(NetworkKernelReaderError::InvalidArtifact(
                "artifact path is not normalized",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.len() < 2 || !valid_store_entry(&components[0]) {
        return Err(NetworkKernelReaderError::InvalidArtifact(
            "artifact path does not name a file in one fixed store output",
        ));
    }

    let mut normalized = PathBuf::from(NIX_STORE_ROOT);
    for component in &components {
        normalized.push(component);
    }
    if normalized.as_os_str().as_bytes() != path.as_os_str().as_bytes() {
        return Err(NetworkKernelReaderError::InvalidArtifact(
            "artifact path is not lexically normalized",
        ));
    }
    Ok(components)
}

fn valid_store_entry(component: &std::ffi::OsStr) -> bool {
    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

    let bytes = component.as_bytes();
    bytes.len() > 33
        && bytes[32] == b'-'
        && bytes[..32].iter().all(|byte| NIX_BASE32.contains(byte))
}

fn open_store_artifact(
    artifact_components: &[OsString],
) -> Result<(File, Vec<ArtifactAncestor>), NetworkKernelReaderError> {
    let root = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(kernel_io)?;
    let root_identity = DirectoryIdentity::from_descriptor(&root, DirectoryPolicy::Protected)?;
    let mut ancestors = vec![ArtifactAncestor {
        descriptor: root,
        identity: root_identity,
        policy: DirectoryPolicy::Protected,
    }];
    let mut components = vec![OsString::from("nix"), OsString::from("store")];
    components.extend_from_slice(artifact_components);

    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let flags = if final_component {
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC
        } else {
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
        };
        let descriptor = rustix::fs::openat2(
            ancestors
                .last()
                .ok_or(NetworkKernelReaderError::InvalidArtifact(
                    "artifact ancestry is empty",
                ))?
                .descriptor
                .as_fd(),
            component,
            flags,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_MAGICLINKS
                | rustix::fs::ResolveFlags::NO_SYMLINKS,
        )
        .map_err(kernel_io)?;
        if final_component {
            return Ok((File::from(descriptor), ancestors));
        }

        let policy = match index {
            0 => DirectoryPolicy::Protected,
            1 => DirectoryPolicy::StoreRoot,
            _ => DirectoryPolicy::Immutable,
        };
        let identity = DirectoryIdentity::from_descriptor(&descriptor, policy)?;
        ancestors.push(ArtifactAncestor {
            descriptor,
            identity,
            policy,
        });
    }
    Err(NetworkKernelReaderError::InvalidArtifact(
        "artifact path has no final component",
    ))
}

fn measure_file(file: &File, size: u64) -> Result<ObjectDigest, NetworkKernelReaderError> {
    let length = usize::try_from(size).map_err(|_| {
        NetworkKernelReaderError::InvalidArtifact("artifact size exceeds address space")
    })?;
    let mut bytes = vec![0; length];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = file.read_at(&mut bytes[offset..], offset as u64)?;
        if count == 0 {
            return Err(NetworkKernelReaderError::InvalidArtifact(
                "artifact became shorter while measured",
            ));
        }
        offset += count;
    }
    let mut trailing = [0];
    if file.read_at(&mut trailing, size)? != 0 {
        return Err(NetworkKernelReaderError::InvalidArtifact(
            "artifact read was not exact",
        ));
    }
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

fn kernel_io(error: rustix::io::Errno) -> NetworkKernelReaderError {
    NetworkKernelReaderError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
}

fn encode_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObservation {
    binding_map: RawMap,
    state_map: RawMap,
    binding: RawBinding,
    state: RawState,
    ingress: RawAttachment,
    egress: RawAttachment,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMap {
    id: u32,
    #[serde(rename = "type")]
    map_type: u32,
    name: String,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBinding {
    format_version: u32,
    provenance_version: u32,
    ingress_program_id: u32,
    egress_program_id: u32,
    network_handle: String,
    assignment_digest: String,
    gate_object_digest: String,
    assignment_epoch: u64,
    allocation_generation: u64,
    namespace_device: u64,
    namespace_inode: u64,
    boot_id: String,
    host_ifindex: u32,
    peer_ifindex: u32,
    host_mac: String,
    peer_mac: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawState {
    format_version: u32,
    ingress: RawDirection,
    egress: RawDirection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDirection {
    format_version: u32,
    armed: u32,
    assignment_epoch: u64,
    assignment_digest: String,
    lease_generation: u64,
    lease_digest: String,
    deadline_boottime_nanoseconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAttachment {
    link_id: u32,
    program_id: u32,
    program_tag: String,
    ifindex: u32,
    attach_type: u32,
    map_ids: Vec<u32>,
}

/// Decodes one independently validated BPF graph snapshot.
///
/// `installed_object_digest` must be measured by the Rust worker over its
/// pinned immutable object file. It is deliberately not taken from helper
/// output or copied from the kernel plan.
///
/// # Errors
///
/// Returns [`NetworkKernelReaderError`] for an oversized record, unknown or
/// missing field, noncanonical lowercase hexadecimal value, sentinel identity,
/// invalid boolean, unsorted map relationship, or cross-record disagreement.
pub fn decode_bpf_observation(
    bytes: &[u8],
    installed_object_digest: ObjectDigest,
) -> Result<ObservedLeaseGateV1, NetworkKernelReaderError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_BPF_OBSERVATION_BYTES {
        return Err(NetworkKernelReaderError::InvalidBpf(
            "record length is outside its fixed bound",
        ));
    }
    let raw: RawObservation = serde_json::from_slice(bytes)?;
    if raw.binding.format_version != 2
        || raw.binding.provenance_version != 1
        || raw.state.format_version != 2
        || raw.state.ingress.format_version != 2
        || raw.state.egress.format_version != 2
        || raw.binding.ingress_program_id != raw.ingress.program_id
        || raw.binding.egress_program_id != raw.egress.program_id
        || raw.binding.host_ifindex != raw.ingress.ifindex
        || raw.binding.host_ifindex != raw.egress.ifindex
        || raw.ingress.attach_type != 46
        || raw.egress.attach_type != 47
    {
        return Err(NetworkKernelReaderError::InvalidBpf(
            "binding, state, and attachment identities disagree",
        ));
    }

    let binding_map = decode_map(raw.binding_map)?;
    let state_map = decode_map(raw.state_map)?;
    if binding_map.id == state_map.id {
        return Err(NetworkKernelReaderError::InvalidBpf(
            "BPF maps share an object ID",
        ));
    }
    let expected_map_ids = if binding_map.id < state_map.id {
        vec![binding_map.id, state_map.id]
    } else {
        vec![state_map.id, binding_map.id]
    };

    let ingress = decode_attachment(raw.ingress, &expected_map_ids)?;
    let egress = decode_attachment(raw.egress, &expected_map_ids)?;
    if ingress.link_id == egress.link_id || ingress.program_id == egress.program_id {
        return Err(NetworkKernelReaderError::InvalidBpf(
            "BPF attachments are not distinct",
        ));
    }

    let lifecycle = ObservedLeaseStateV1 {
        format_version: raw.state.format_version,
        ingress: decode_direction(raw.state.ingress)?,
        egress: decode_direction(raw.state.egress)?,
    };
    let loader_object_digest = decode_object_digest(&raw.binding.gate_object_digest)?;
    Ok(ObservedLeaseGateV1 {
        artifact: ObservedBpfArtifactV1 {
            installed_object_digest,
            provenance_version: narrow_u16(raw.binding.provenance_version)?,
            loader_object_digest,
            loader_ingress_program_id: raw.binding.ingress_program_id,
            loader_egress_program_id: raw.binding.egress_program_id,
        },
        binding: ObservedBpfBindingV1 {
            format_version: narrow_u16(raw.binding.format_version)?,
            network_handle: decode_hex(&raw.binding.network_handle)?,
            assignment_digest: decode_object_digest(&raw.binding.assignment_digest)?,
            assignment_epoch: raw.binding.assignment_epoch,
            allocation_generation: raw.binding.allocation_generation,
            boot_id: decode_hex(&raw.binding.boot_id)?,
            namespace_device: raw.binding.namespace_device,
            namespace_inode: raw.binding.namespace_inode,
            host_ifindex: raw.binding.host_ifindex,
            peer_ifindex: raw.binding.peer_ifindex,
            host_mac: decode_hex(&raw.binding.host_mac)?,
            peer_mac: decode_hex(&raw.binding.peer_mac)?,
        },
        lease_state: lifecycle,
        binding_map,
        lease_state_map: state_map,
        ingress,
        egress,
    })
}

fn decode_map(raw: RawMap) -> Result<ObservedBpfMapV1, NetworkKernelReaderError> {
    let expected = match raw.name.as_str() {
        "binding" => (2, 192),
        "lease_state" => (1, 200),
        _ => {
            return Err(NetworkKernelReaderError::InvalidBpf(
                "map name is not admitted",
            ));
        }
    };
    if raw.id == 0
        || raw.map_type != expected.0
        || raw.key_size != 4
        || raw.value_size != expected.1
        || raw.max_entries != 1
        || raw.flags != 128
    {
        return Err(NetworkKernelReaderError::InvalidBpf(
            "map identity is invalid",
        ));
    }
    Ok(ObservedBpfMapV1 {
        id: raw.id,
        map_type: raw.map_type,
        name: raw.name,
        key_size: raw.key_size,
        value_size: raw.value_size,
        max_entries: raw.max_entries,
        flags: raw.flags,
    })
}

fn decode_attachment(
    raw: RawAttachment,
    expected_map_ids: &[u32],
) -> Result<ObservedBpfAttachmentV1, NetworkKernelReaderError> {
    if raw.link_id == 0
        || raw.program_id == 0
        || raw.ifindex == 0
        || raw.map_ids != expected_map_ids
    {
        return Err(NetworkKernelReaderError::InvalidBpf(
            "attachment identity is invalid",
        ));
    }
    let program_tag = decode_hex(&raw.program_tag)?;
    if program_tag == [0; 8] {
        return Err(NetworkKernelReaderError::InvalidBpf(
            "attached program tag is zero",
        ));
    }
    Ok(ObservedBpfAttachmentV1 {
        link_id: raw.link_id,
        program_id: raw.program_id,
        program_tag,
        interface: ObservedInterfaceV1 {
            namespace: ObservedNetworkNamespaceV1::Host,
            ifindex: raw.ifindex,
        },
        attach_type: raw.attach_type,
        map_ids: raw.map_ids,
    })
}

fn decode_direction(
    raw: RawDirection,
) -> Result<ObservedLeaseDirectionV1, NetworkKernelReaderError> {
    let armed = match raw.armed {
        0 => false,
        1 => true,
        _ => {
            return Err(NetworkKernelReaderError::InvalidBpf(
                "lease armed field is not Boolean",
            ));
        }
    };
    Ok(ObservedLeaseDirectionV1 {
        format_version: raw.format_version,
        armed,
        assignment_epoch: raw.assignment_epoch,
        assignment_digest: decode_object_digest(&raw.assignment_digest)?,
        lease_generation: raw.lease_generation,
        lease_digest: decode_object_digest_allow_zero(&raw.lease_digest)?,
        deadline_boottime_nanoseconds: raw.deadline_boottime_nanoseconds,
    })
}

fn decode_object_digest(text: &str) -> Result<ObjectDigest, NetworkKernelReaderError> {
    let bytes = decode_hex(text)?;
    if bytes == [0; 32] {
        return Err(NetworkKernelReaderError::InvalidBpf(
            "required digest is zero",
        ));
    }
    Ok(ObjectDigest::from_bytes(bytes))
}

fn decode_object_digest_allow_zero(text: &str) -> Result<ObjectDigest, NetworkKernelReaderError> {
    Ok(ObjectDigest::from_bytes(decode_hex(text)?))
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], NetworkKernelReaderError> {
    if text.len() != N * 2 {
        return Err(NetworkKernelReaderError::InvalidBpf(
            "hex field has the wrong length",
        ));
    }
    let mut output = [0; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(NetworkKernelReaderError::InvalidBpf(
            "hex field is not canonical lowercase",
        ))?;
        let low = hex_nibble(pair[1]).ok_or(NetworkKernelReaderError::InvalidBpf(
            "hex field is not canonical lowercase",
        ))?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn narrow_u16(value: u32) -> Result<u16, NetworkKernelReaderError> {
    u16::try_from(value)
        .map_err(|_| NetworkKernelReaderError::InvalidBpf("version exceeds its field width"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use aos_sandbox_linux::process::FixedProcessOutput;

    const FIXTURE: &str = r#"{
      "binding_map":{"id":11,"type":2,"name":"binding","key_size":4,"value_size":192,"max_entries":1,"flags":128},
      "state_map":{"id":12,"type":1,"name":"lease_state","key_size":4,"value_size":200,"max_entries":1,"flags":128},
      "binding":{"format_version":2,"provenance_version":1,"ingress_program_id":21,"egress_program_id":22,
        "network_handle":"7777777777777777777777777777777777777777777777777777777777777777",
        "assignment_digest":"3333333333333333333333333333333333333333333333333333333333333333",
        "gate_object_digest":"6666666666666666666666666666666666666666666666666666666666666666",
        "assignment_epoch":41,"allocation_generation":1,"namespace_device":71,"namespace_inode":81,
        "boot_id":"91919191919191919191919191919191","host_ifindex":7,"peer_ifindex":7,
        "host_mac":"02aabb000002","peer_mac":"02aabb000003"},
      "state":{"format_version":2,
        "ingress":{"format_version":2,"armed":0,"assignment_epoch":41,
          "assignment_digest":"3333333333333333333333333333333333333333333333333333333333333333",
          "lease_generation":0,"lease_digest":"0000000000000000000000000000000000000000000000000000000000000000",
          "deadline_boottime_nanoseconds":0},
        "egress":{"format_version":2,"armed":0,"assignment_epoch":41,
          "assignment_digest":"3333333333333333333333333333333333333333333333333333333333333333",
          "lease_generation":0,"lease_digest":"0000000000000000000000000000000000000000000000000000000000000000",
          "deadline_boottime_nanoseconds":0}},
      "ingress":{"link_id":31,"program_id":21,"program_tag":"a1a1a1a1a1a1a1a1","ifindex":7,"attach_type":46,"map_ids":[11,12]},
      "egress":{"link_id":32,"program_id":22,"program_tag":"a2a2a2a2a2a2a2a2","ifindex":7,"attach_type":47,"map_ids":[11,12]}
    }"#;

    #[test]
    fn complete_v2_bpf_graph_decodes() {
        let observation =
            decode_bpf_observation(FIXTURE.as_bytes(), ObjectDigest::from_bytes([0x66; 32]))
                .unwrap();

        assert_eq!(observation.binding.format_version, 2);
        assert_eq!(observation.binding_map.value_size, 192);
        assert_eq!(observation.ingress.map_ids, [11, 12]);
        assert_eq!(observation.lease_state.ingress.format_version, 2);
    }

    #[test]
    fn old_versions_unknown_fields_and_wrong_graphs_fail_closed() {
        for mutated in [
            FIXTURE.replace("\"format_version\":2", "\"format_version\":1"),
            FIXTURE.replace("\"binding_map\":", "\"unknown\":0,\"binding_map\":"),
            FIXTURE.replace("\"map_ids\":[11,12]", "\"map_ids\":[12,11]"),
        ] {
            assert!(
                decode_bpf_observation(mutated.as_bytes(), ObjectDigest::from_bytes([0x66; 32]))
                    .is_err()
            );
        }
    }

    #[test]
    fn direction_version_and_boolean_are_not_normalized() {
        let old_direction = FIXTURE.replacen(
            "\"format_version\":2,\"armed\":0",
            "\"format_version\":1,\"armed\":0",
            1,
        );
        let non_boolean = FIXTURE.replacen("\"armed\":0", "\"armed\":2", 1);

        assert!(
            decode_bpf_observation(
                old_direction.as_bytes(),
                ObjectDigest::from_bytes([0x66; 32])
            )
            .is_err()
        );
        assert!(
            decode_bpf_observation(non_boolean.as_bytes(), ObjectDigest::from_bytes([0x66; 32]))
                .is_err()
        );
    }

    #[test]
    fn complete_output_from_a_rejecting_helper_is_discarded() {
        let outcome = FixedProcessOutcome::Completed(FixedProcessOutput {
            exit_code: Some(1),
            signal: None,
            stdout: FIXTURE.as_bytes().to_vec(),
            stderr: b"pin inventory changed".to_vec(),
        });

        assert!(matches!(
            successful_helper_stdout(outcome),
            Err(NetworkKernelReaderError::HelperFailed)
        ));
    }

    #[test]
    fn artifact_paths_are_exact_normalized_store_descendants() {
        let hash = "0".repeat(32);
        let valid = format!("/nix/store/{hash}-observer/bin/helper");
        assert!(validate_artifact_path(Path::new(&valid)).is_ok());

        for invalid in [
            format!("/tmp/{hash}-observer/bin/helper"),
            format!("/nix/store//{hash}-observer/bin/helper"),
            format!("/nix/store/{hash}-observer/./bin/helper"),
            format!("/nix/store/{hash}-observer/bin/../helper"),
            format!("/nix/store/{}-observer/bin/helper", "0".repeat(31)),
            format!("/nix/store/{}e-observer/bin/helper", "0".repeat(31)),
            format!("/nix/store/{hash}-observer"),
        ] {
            assert!(
                validate_artifact_path(Path::new(&invalid)).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn artifact_directory_modes_enforce_each_ancestry_role() {
        assert!(valid_directory_mode(DirectoryPolicy::Protected, 0o40755));
        assert!(!valid_directory_mode(DirectoryPolicy::Protected, 0o40775));

        assert!(valid_directory_mode(DirectoryPolicy::StoreRoot, 0o40555));
        assert!(valid_directory_mode(DirectoryPolicy::StoreRoot, 0o41775));
        assert!(!valid_directory_mode(DirectoryPolicy::StoreRoot, 0o40775));
        assert!(!valid_directory_mode(DirectoryPolicy::StoreRoot, 0o41777));

        assert!(valid_directory_mode(DirectoryPolicy::Immutable, 0o40555));
        assert!(!valid_directory_mode(DirectoryPolicy::Immutable, 0o40755));
    }
}
