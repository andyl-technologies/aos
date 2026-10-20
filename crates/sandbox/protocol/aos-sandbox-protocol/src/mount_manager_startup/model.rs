//! Durable models for Mount-manager startup authority.

use serde::{Deserialize, Serialize};

/// Maximum number of descriptors admitted in one startup capture.
pub const MAXIMUM_STARTUP_DESCRIPTORS_V1: usize = 1_024;
/// Highest initial numeric descriptor admitted by the closed implementation.
pub const MAXIMUM_STARTUP_DESCRIPTOR_NUMBER_V1: u32 = 1_048_575;
/// Maximum number of absence subjects admitted in one startup capture.
pub const MAXIMUM_STARTUP_ABSENCE_SUBJECTS_V1: usize = 1_024;
/// Maximum bytes in one canonical activation name.
pub const MAXIMUM_STARTUP_NAME_BYTES_V1: usize = 255;
/// Maximum bytes in one canonical systemd unit or cgroup locator.
pub const MAXIMUM_STARTUP_LOCATOR_BYTES_V1: usize = 1_024;
/// Maximum bytes in all activation names in one capture.
pub const MAXIMUM_STARTUP_NAMES_BYTES_V1: usize = 512 * 1_024;
/// Maximum encoded policy bytes.
pub const MAXIMUM_STARTUP_POLICY_BYTES_V1: usize = 64 * 1_024;
/// Maximum encoded capture bytes.
pub const MAXIMUM_STARTUP_CAPTURE_BYTES_V1: usize = 8 * 1_024 * 1_024;
/// Maximum immutable capture rows admitted by one history validation.
pub const MAXIMUM_STARTUP_CAPTURE_HISTORY_RECORDS_V1: usize = 4_096;
/// Maximum aggregate encoded bytes admitted by one history validation.
pub const MAXIMUM_STARTUP_CAPTURE_HISTORY_BYTES_V1: usize = 256 * 1_024 * 1_024;

/// Identifies one exact fs-verity-protected executable build.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupExecutableIdentityV1 {
    /// Filesystem device containing the executable.
    pub device: u64,
    /// Inode pinned through `/proc/PID/exe`.
    pub inode: u64,
    /// Exact executable size.
    pub size: u64,
    /// Exact inode mode.
    pub mode: u32,
    /// Kernel SHA-256 fs-verity measurement.
    pub fs_verity_sha256: [u8; 32],
    /// SHA-256 commitment to the canonical GNU build-ID bytes.
    pub build_identity_digest: [u8; 32],
}

/// Stores every credential field returned for a pinned process.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupCredentialsV1 {
    /// Real user ID.
    pub real_uid: u32,
    /// Effective user ID.
    pub effective_uid: u32,
    /// Saved user ID.
    pub saved_uid: u32,
    /// Filesystem user ID.
    pub filesystem_uid: u32,
    /// Real group ID.
    pub real_gid: u32,
    /// Effective group ID.
    pub effective_gid: u32,
    /// Saved group ID.
    pub saved_gid: u32,
    /// Filesystem group ID.
    pub filesystem_gid: u32,
}

/// Describes one exact pinned service execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupExecutionIdentityV1 {
    /// Kernel boot containing the process.
    pub kernel_boot_id: [u8; 16],
    /// Process ID in the observing PID namespace.
    pub pid: u32,
    /// Thread-group leader ID.
    pub tgid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Boot-relative process start time.
    pub start_time_ticks: u64,
    /// Complete pidfd credential observation.
    pub credentials: StartupCredentialsV1,
    /// Kernel cgroup identifier.
    pub cgroup_id: u64,
    /// Canonical cgroup-v2 path.
    pub cgroup_path: String,
    /// Exact systemd unit derived from the cgroup path.
    pub unit: String,
    /// Pinned executable identity.
    pub executable: StartupExecutableIdentityV1,
}

/// Defines the protected identity and allocation policy for startup capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountManagerStartupPolicyV1 {
    /// Monotone policy generation.
    pub generation: u64,
    /// Immediately preceding policy generation, or zero for genesis.
    pub predecessor_generation: u64,
    /// Digest of the immediately preceding policy, or zero for genesis.
    pub predecessor_digest: [u8; 32],
    /// Stable deployment identity.
    pub deployment_id: [u8; 16],
    /// Monotone deployment-configuration generation.
    pub configuration_generation: u64,
    /// Exact protected deployment-configuration digest.
    pub configuration_digest: [u8; 32],
    /// Stable Mount-manager control signing-key identity.
    pub manager_control_key_id: [u8; 16],
    /// Monotone Mount-manager control signing-key generation.
    pub manager_control_key_generation: u64,
    /// Exact Ed25519 public key for manager control outcomes.
    pub manager_control_public_key: [u8; 32],
    /// Required service UID.
    pub service_uid: u32,
    /// Required service GID.
    pub service_gid: u32,
    /// Exact Mount-manager unit.
    pub service_unit: String,
    /// Exact Mount-manager cgroup path.
    pub service_cgroup: String,
    /// Required Mount-manager executable build.
    pub service_executable: StartupExecutableIdentityV1,
    /// Required launcher UID.
    pub launcher_uid: u32,
    /// Required launcher GID.
    pub launcher_gid: u32,
    /// Exact launcher unit.
    pub launcher_unit: String,
    /// Exact launcher cgroup path.
    pub launcher_cgroup: String,
    /// Required launcher executable build.
    pub launcher_executable: StartupExecutableIdentityV1,
    /// Bitmap of required inherited descriptors 0, 1, and 2.
    pub standard_descriptor_bitmap: u8,
    /// Highest initial numeric descriptor admitted by policy.
    pub maximum_descriptor_number: u32,
    /// Maximum complete initial descriptor count.
    pub maximum_descriptor_count: u32,
    /// Maximum activation descriptor count, including the listener.
    pub maximum_activation_count: u32,
    /// Maximum retained Mount descriptor count.
    pub maximum_mount_count: u32,
    /// Maximum retained SourceRoot descriptor count.
    pub maximum_source_count: u32,
    /// Maximum bytes in one activation name.
    pub maximum_name_bytes: u32,
    /// Maximum aggregate activation-name bytes.
    pub maximum_names_bytes: u32,
    /// Maximum encoded capture row bytes.
    pub maximum_capture_bytes: u32,
    /// Maximum elapsed boot-time nanoseconds across capture.
    pub maximum_capture_duration_ns: u64,
    /// Exact listener activation name.
    pub listener_name: String,
    /// Required listener address family (`AF_UNIX`).
    pub listener_domain: u32,
    /// Required listener socket type (`SOCK_SEQPACKET`).
    pub listener_socket_type: u32,
    /// Required listener accept state; the closed profile requires `true`.
    pub listener_accepting: bool,
    /// Exact local `sockaddr` bytes of the protected listener.
    pub listener_local_address: Vec<u8>,
    /// Self-digest of the canonical policy record.
    #[serde(skip)]
    pub record_digest: [u8; 32],
}

/// Classifies one expected startup descriptor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupDescriptorRoleV1 {
    /// Standard input.
    StandardInput,
    /// Standard output.
    StandardOutput,
    /// Standard error.
    StandardError,
    /// Mount-manager listening socket.
    Listener,
    /// PID 1 retained destination Mount.
    RetainedMount,
    /// PID 1 retained SourceRoot.
    SourceRoot,
}

/// Classifies whether durable state requires or merely permits an entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupDescriptorPresenceV1 {
    /// The descriptor must be present.
    Required,
    /// An in-flight removal permits either present or absent.
    Conditional,
}

/// Projects one exact descriptor expected from protected durable state.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedStartupDescriptorV1 {
    /// Semantic descriptor role.
    pub role: StartupDescriptorRoleV1,
    /// Required presence class.
    pub presence: StartupDescriptorPresenceV1,
    /// Exact activation name; standard streams have no name.
    pub name: Option<String>,
    /// Stable Mount handle or SourceRoot realization handle.
    pub logical_identity: [u8; 32],
    /// Kernel boot expected for retained Mount/SourceRoot state.
    pub kernel_boot_id: Option<[u8; 16]>,
    /// Expected device when the role is a SourceRoot.
    pub device: Option<u64>,
    /// Expected inode when the role is a SourceRoot.
    pub inode: Option<u64>,
    /// Expected unique Mount ID when durable state supplies one.
    pub unique_mount_id: Option<u64>,
    /// Expected SourceRoot descriptor commitment.
    pub descriptor_commitment: Option<[u8; 32]>,
    /// Exact owning AOSMSA acquisition identity for a SourceRoot.
    pub source_acquisition_id: Option<[u8; 32]>,
    /// Exact owning AOSMSA acquisition revision for a SourceRoot.
    pub source_acquisition_revision: Option<u64>,
    /// Exact owning AOSMSA acquisition record digest for a SourceRoot.
    pub source_acquisition_record_digest: Option<[u8; 32]>,
    /// Exact required socket observation for the listener.
    pub socket: Option<StartupSocketObservationV1>,
}

/// Classifies the kernel object behind one captured descriptor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupDescriptorObjectKindV1 {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Socket.
    Socket,
    /// FIFO or pipe.
    Fifo,
    /// Character device.
    Character,
    /// Block device.
    Block,
    /// Symbolic link.
    Symlink,
    /// Another kernel object class.
    Other,
}

/// Stores socket-specific descriptor observations.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupSocketObservationV1 {
    /// Kernel address-family number.
    pub domain: u32,
    /// Kernel socket-type number without flags.
    pub socket_type: u32,
    /// Whether the socket accepts connections.
    pub accepting: bool,
    /// Exact bounded local `sockaddr` bytes.
    pub local_address: Vec<u8>,
}

/// Stores one stable double-observed initial descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupDescriptorObservationV1 {
    /// Original process-start descriptor number.
    pub number: u32,
    /// Descriptor flags.
    pub descriptor_flags: u32,
    /// Open-file-description status flags.
    pub status_flags: u32,
    /// Kernel object class.
    pub object_kind: StartupDescriptorObjectKindV1,
    /// Object device.
    pub device: u64,
    /// Object inode.
    pub inode: u64,
    /// Object mode.
    pub mode: u32,
    /// Object device number for device nodes.
    pub special_device: u64,
    /// Object size.
    pub size: u64,
    /// Unique Mount ID when available.
    pub unique_mount_id: Option<u64>,
    /// Per-mount read-only state when available.
    pub mount_read_only: Option<bool>,
    /// Socket facts for socket objects.
    pub socket: Option<StartupSocketObservationV1>,
    /// Commitment to the complete physical observation.
    pub physical_commitment: [u8; 32],
}

/// Binds one nonauthoritative activation label to a captured slot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupActivationLabelV1 {
    /// Captured descriptor number.
    pub number: u32,
    /// Environment-supplied name after protected-state validation.
    pub name: String,
    /// Role derived from protected state, never from the name alone.
    pub role: StartupDescriptorRoleV1,
    /// Stable role identity.
    pub logical_identity: [u8; 32],
}

/// Commits the exact protected inputs used to derive startup expectations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountManagerStartupDerivationHeadV1 {
    /// Journal sequence observed before capture append.
    pub journal_sequence: u64,
    /// Complete namespace-40 record count.
    pub acquisition_record_count: u32,
    /// Digest of exact sorted namespace-40 key/value bytes.
    pub acquisition_state_digest: [u8; 32],
    /// Complete namespace-39 record count.
    pub source_pin_record_count: u32,
    /// Digest of exact sorted namespace-39 key/value bytes.
    pub source_pin_state_digest: [u8; 32],
    /// Mount-resource family record count in namespace 2.
    pub mount_resource_record_count: u32,
    /// Digest of exact sorted Mount-resource key/value bytes.
    pub mount_resource_state_digest: [u8; 32],
    /// Digest of all preceding derivation fields.
    pub derivation_digest: [u8; 32],
}

/// Names a pre-Release phase eligible for startup cleanup recovery.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupCleanupPhaseV1 {
    /// A terminal Acquire result has not yet been applied.
    PendingQuery,
    /// Descriptor custody was durably recorded but not read back.
    DescriptorCustodied,
    /// Positive custody was durably read back.
    Active,
    /// SourcePin/Create admission consumed the source.
    Consumed,
}

/// Retains an optional SourceRoot identity for cleanup projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupCleanupEvidenceV1 {
    /// Stable SourceRoot realization handle.
    pub source_realization_handle: [u8; 32],
    /// Exact SourceRoot descriptor commitment.
    pub descriptor_commitment: [u8; 32],
    /// SourceRoot kernel boot.
    pub source_kernel_boot_id: [u8; 16],
    /// SourceRoot device.
    pub source_device: u64,
    /// SourceRoot inode.
    pub source_inode: u64,
    /// SourceRoot unique Mount ID.
    pub source_unique_mount_id: u64,
}

/// Retains the persisted Mount-manager execution that last held custody.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupPersistedCustodyOwnerV1 {
    /// Exact provider attempt carrying this session.
    pub attempt_id: [u8; 32],
    /// Attempt revision.
    pub attempt_revision: u64,
    /// Attempt record digest.
    pub attempt_record_digest: [u8; 32],
    /// Exact provider session identity.
    pub session_id: [u8; 32],
    /// Session record digest.
    pub session_record_digest: [u8; 32],
    /// Session kernel boot.
    pub kernel_boot_id: [u8; 16],
    /// Root Mount writer thread-group ID.
    pub tgid: u32,
    /// Root Mount writer start time.
    pub start_time_ticks: u64,
    /// Root Mount writer cgroup commitment.
    pub cgroup_digest: [u8; 32],
}

/// Projects one exact pre-Release row eligible for cleanup after startup loss.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupCleanupSourceSubjectV1 {
    /// Mount acquisition identity.
    pub acquisition_id: [u8; 32],
    /// Exact acquisition revision.
    pub acquisition_revision: u64,
    /// Exact acquisition record digest.
    pub acquisition_record_digest: [u8; 32],
    /// Effective pre-Release phase.
    pub phase: StartupCleanupPhaseV1,
    /// Exact terminal Acquire attempt identity.
    pub acquire_attempt_id: [u8; 32],
    /// Acquire attempt revision.
    pub acquire_attempt_revision: u64,
    /// Acquire attempt record digest.
    pub acquire_attempt_record_digest: [u8; 32],
    /// Optional realized SourceRoot identity.
    pub evidence: Option<StartupCleanupEvidenceV1>,
    /// Persisted last-custody owner, absent before descriptor handoff.
    pub last_custody_owner: Option<StartupPersistedCustodyOwnerV1>,
}

/// Projects one exact terminal Releasing row eligible for absence recovery.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupTerminalSourceSubjectV1 {
    /// Mount acquisition identity.
    pub acquisition_id: [u8; 32],
    /// Exact acquisition revision.
    pub acquisition_revision: u64,
    /// Exact acquisition row digest.
    pub acquisition_record_digest: [u8; 32],
    /// Provider acquisition identity.
    pub provider_acquisition_id: [u8; 32],
    /// Provider acquisition sequence.
    pub provider_acquisition_sequence: u64,
    /// Stable SourceRoot realization handle.
    pub source_realization_handle: [u8; 32],
    /// Exact SourceRoot descriptor commitment.
    pub descriptor_commitment: [u8; 32],
    /// SourceRoot boot ID.
    pub source_kernel_boot_id: [u8; 16],
    /// SourceRoot device.
    pub source_device: u64,
    /// SourceRoot inode.
    pub source_inode: u64,
    /// SourceRoot unique Mount ID.
    pub source_unique_mount_id: u64,
    /// Lease identity.
    pub lease_id: [u8; 16],
    /// Signed lease digest.
    pub lease_digest: [u8; 32],
    /// Terminal Release/Inventory attempt identity.
    pub terminal_attempt_id: [u8; 32],
    /// Terminal attempt revision.
    pub terminal_attempt_revision: u64,
    /// Terminal attempt record digest.
    pub terminal_attempt_digest: [u8; 32],
}

/// Names one canonically sorted startup source recovery subject.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "subject_kind", content = "subject", rename_all = "snake_case")]
pub enum StartupSourceSubjectV1 {
    /// A pre-Release row may mint cleanup-only lost-custody authority if absent.
    Cleanup(StartupCleanupSourceSubjectV1),
    /// A terminal Releasing row must be absent and may mint terminal authority.
    Terminal(StartupTerminalSourceSubjectV1),
}

impl StartupSourceSubjectV1 {
    /// Returns the stable Mount acquisition identity.
    #[must_use]
    pub const fn acquisition_id(self) -> [u8; 32] {
        match self {
            Self::Cleanup(subject) => subject.acquisition_id,
            Self::Terminal(subject) => subject.acquisition_id,
        }
    }

    const fn variant_tag(self) -> u8 {
        match self {
            Self::Cleanup(_) => 1,
            Self::Terminal(_) => 2,
        }
    }
}

impl Ord for StartupSourceSubjectV1 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.acquisition_id()
            .cmp(&other.acquisition_id())
            .then_with(|| self.variant_tag().cmp(&other.variant_tag()))
            .then_with(|| match (self, other) {
                (Self::Cleanup(left), Self::Cleanup(right)) => left.cmp(right),
                (Self::Terminal(left), Self::Terminal(right)) => left.cmp(right),
                _ => std::cmp::Ordering::Equal,
            })
    }
}

impl PartialOrd for StartupSourceSubjectV1 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Stores one immutable complete Mount-manager startup capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountManagerStartupCaptureV1 {
    /// Gap-free capture sequence.
    pub capture_sequence: u64,
    /// Digest of the preceding capture row, or zero for the first capture.
    pub predecessor_capture_digest: [u8; 32],
    /// Deterministic capture identity.
    pub capture_id: [u8; 32],
    /// Policy generation applied to this capture.
    pub policy_generation: u64,
    /// Exact policy record digest.
    pub policy_digest: [u8; 32],
    /// Exact protected-state derivation head.
    pub derivation: MountManagerStartupDerivationHeadV1,
    /// Exact sorted expected descriptor table.
    pub expected_descriptors: Vec<ExpectedStartupDescriptorV1>,
    /// Exact sorted cleanup and terminal source-subject set.
    pub source_subjects: Vec<StartupSourceSubjectV1>,
    /// Current Mount-manager execution.
    pub execution: StartupExecutionIdentityV1,
    /// Exact direct-launcher execution.
    pub launcher: StartupExecutionIdentityV1,
    /// Earliest boot-time observation in nanoseconds.
    pub boot_time_before_ns: u64,
    /// Latest boot-time observation in nanoseconds.
    pub boot_time_after_ns: u64,
    /// Earliest realtime observation in nanoseconds since the Unix epoch.
    pub realtime_before_ns: i128,
    /// Latest realtime observation in nanoseconds since the Unix epoch.
    pub realtime_after_ns: i128,
    /// Exact original initial descriptor table.
    pub descriptor_table: Vec<StartupDescriptorObservationV1>,
    /// Exact complete initial descriptor count.
    pub descriptor_count: u32,
    /// Exact validated activation labels.
    pub activation_labels: Vec<StartupActivationLabelV1>,
    /// Exact validated activation descriptor count.
    pub activation_count: u32,
    /// Exact protected-state expectation count.
    pub expected_descriptor_count: u32,
    /// Exact total source-subject count.
    pub source_subject_count: u32,
    /// Exact cleanup source-subject count.
    pub cleanup_subject_count: u32,
    /// Exact terminal source-subject count.
    pub terminal_subject_count: u32,
    /// Captured listener descriptor number.
    pub listener_descriptor_number: u32,
    /// Captured listener physical commitment.
    pub listener_physical_commitment: [u8; 32],
    /// Digest of bounded raw `LISTEN_PID` bytes.
    pub listen_pid_hint_digest: [u8; 32],
    /// Byte count of raw `LISTEN_PID`, or absent when the variable was absent.
    pub listen_pid_hint_length: Option<u32>,
    /// Digest of bounded raw `LISTEN_FDS` bytes.
    pub listen_fds_hint_digest: [u8; 32],
    /// Byte count of raw `LISTEN_FDS`, or absent when the variable was absent.
    pub listen_fds_hint_length: Option<u32>,
    /// Digest of bounded raw `LISTEN_FDNAMES` bytes.
    pub listen_fdnames_hint_digest: [u8; 32],
    /// Byte count of raw names, or absent when the variable was absent.
    pub listen_fdnames_hint_length: Option<u32>,
    /// Count of scanner-owned descriptors excluded from the initial table.
    pub scanner_descriptor_count: u32,
    /// Commitment to exact scanner-owned descriptor numbers.
    pub scanner_descriptor_digest: [u8; 32],
    /// Commitment to the full descriptor table.
    pub descriptor_table_digest: [u8; 32],
    /// Commitment to exact activation labels.
    pub activation_table_digest: [u8; 32],
    /// Commitment to the exact expected table.
    pub expected_table_digest: [u8; 32],
    /// Commitment to the exact source-subject set.
    pub source_subjects_digest: [u8; 32],
    /// Self-digest of the canonical capture record.
    #[serde(skip)]
    pub record_digest: [u8; 32],
}

/// Returns the pure protected-state projection used by startup admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedMountManagerStartupV1 {
    /// Exact protected-state head.
    pub head: MountManagerStartupDerivationHeadV1,
    /// Canonically sorted descriptor expectations.
    pub expected_descriptors: Vec<ExpectedStartupDescriptorV1>,
    /// Canonically sorted cleanup and terminal source subjects.
    pub source_subjects: Vec<StartupSourceSubjectV1>,
    /// Commitment to the expected table.
    pub expected_table_digest: [u8; 32],
    /// Commitment to the source-subject set.
    pub source_subjects_digest: [u8; 32],
}
