//! Retained original Host component and boot-lifetime control custody.
//!
//! The fixed seven-entry process-start table is the only construction input.
//! Its immutable profile and genuine PID1 producer are independently joined
//! to the same resource-policy pair. This origin supplies neither a per-effect
//! reservation nor backend readiness, current Sandbox capacity, or a refund.
//!
//! The selected canonical profile extends the independently strict Canary
//! schema rather than changing its version or accepting unknown fields:
//!
//! ```text
//! profile-v3 = version || pid1-path/hash || host-path/hash
//!              || argv || exec-start-pre/post || unit-hash
//!              || policy-path/hash || payload-programs-path/hash
//!              || parent-resources[22] || cpu-period || host-limits[4]
//!              || kind || node[16] || resource-epoch[16]
//!              || resource-policy-hash[32] || host-service[22]
//!              || host-control[22]
//! profile-v4 = profile-v3 || host-execution-receiving:{prepare[22],accept[22]}
//! ```

mod execution_receiving;
mod manager_schedule;
mod component_phase0_receiving;
mod execution_operation;
mod recurring_observation;
mod terminal_inventory;
mod cleanup_preparation;
mod cold_session;
pub use cold_session::{HostControlColdSessionOwnerV1, HostControlColdSessionAccessV1,
    HostControlColdSessionLoanV1, HostControlColdSessionPurposeV1,
    HostControlColdSessionNativeRetentionV1, HostControlColdSessionClosedV1};
pub(crate) use terminal_inventory::HostControlPreparationReceivingV5;
pub(crate) use execution_receiving::HostControlCleanupTokenV1;
pub(crate) use cleanup_preparation::HostControlCleanupDisposalV1;
pub(crate) mod catalogpub;
mod stop_admission;
mod capture_control;
pub(crate) use capture_control::{HostCaptureNegativeControlV3, HostCaptureNegativeLoanV3};
pub(crate) use execution_operation::HostExecutionReceivingLoanV2;
pub(crate) use execution_operation::HostTerminalStageDisposalV3;
pub(crate) use execution_receiving::monitor_interval::ExecutionMonitorReservationV5;
pub(crate) use execution_receiving::query_interval::ExecutionQueryReservationV3;
pub(crate) use execution_receiving::{AcceptedContinuationV2, Request as HostExecutionRequestBindingV2};

use std::error::Error;
use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_controller_domain::ResourceReservationErrorV1;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_broker::receiving::OriginalEnrollmentPairAttemptV1;
use aos_linux_descriptors::boot::KernelBootId;
use aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1;
use aos_sandbox_linux::inherited_fd::HostComponentInitialActivationTableV2;
use aos_sandbox_linux::guest_confinement::CurrentThreadSubjectOriginalV1;
use aos_sandbox_linux::inventory::DescriptorMountObservation;
use aos_sandbox_linux::pidfd::CurrentSelfPidFdCustodyV1;
use aos_linux_descriptors::pidfd::PidFd;
use aos_sandbox_linux::pidfd::PidFdProcessIdentity;
use aos_sandbox_linux::pidfd::PidFdNegativeIdentityOriginalV1;
use aos_sandbox_linux::protected_file::{ExactReadFailure, read_exact_positioned_retaining_cause};
use aos_sandbox_linux::seqpacket::{
    ListenerAdmissionFailureRefV1, RecordSubjectListener, RecordSubjectListenerAdmissionAttemptV1,
};
use aos_systemd_client::{OwnedValue, SystemdClient, Value};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{HostStartupProfileViewV1, HostStartupPropertyPurposeV1, StartupFailure};
use crate::plan::NspawnExecutableSnapshot;
use crate::{HostError, Result};

const HOST_UNIT: &str = "aos-sandbox-hostd.service";
const HOST_CONTEXT: &str = "system_u:system_r:aos_sandbox_host_t";
const MAXIMUM_PROFILE_BYTES: usize = 1024 * 1024;
const MAXIMUM_FRAGMENT_BYTES: usize = 64 * 1024;
const MAXIMUM_PROGRAM_BYTES: usize = 98_504;
const MAXIMUM_ATTEMPTS: usize = 8;
// Execution uses separately prepaid slots; ordinary recheck entry keeps its limit.
const EXECUTION_ATTEMPTS: usize = 10;
const LISTENER_ROLES: [(&str, &str); 3] = [
    ("aos-sandbox-host", "/run/aos/sandbox-host/control.sock"),
    ("aos-sandbox-host-root-mount", "/run/aos/sandbox-host/root-mount.sock"),
    ("aos-sandbox-host-storage", "/run/aos/sandbox-host/storage.sock"),
];
const FILE_ROLES: [&str; 4] = [
    "aos-host-pid1-image",
    "aos-host-startup-profile",
    "aos-resource-image-policy-v1",
    "aos-resource-pid1-enrollment-v1",
];
const SERVICE_PROPERTIES: &[&str] = &[
    "ControlGroup", "OpenFile", "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax", "NFileDescriptorStore", "SELinuxContext",
    "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges",
    "ExecStart", "ExecStartPre", "ExecStartPost",
    "CPUQuotaPerSecUSec", "CPUQuotaPeriodUSec", "MemoryMax", "TasksMax",
    "LimitNOFILE", "LimitNOFILESoft",
];
const UNIT_PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];
type Properties = (Vec<OwnedValue>, Vec<OwnedValue>);

#[derive(Clone, Copy)]
enum FirstCauseV2 {
    Table,
    Listener(usize),
    CanonicalProfile,
    CanonicalFragment,
    OriginalBoot,
    Pid1Capture,
    Action(usize),
    Properties(usize, usize),
    PropertyCheck(usize, usize),
    Producer(usize, usize),
    ProducerCheck(usize, usize),
    Pair(usize, usize),
    Files(usize),
    Process(usize),
    NegativePreparation(usize),
    Pid1(usize),
    Boot(usize),
    BootCheck(usize),
    EntryRefusal,
    ExecutionReceiving,
    ExecutionManager(usize),
    RecurringAllocation,
}

// Field order is the installed canonical JSON order, including the explicit
// successor fields. The old Canary schema remains an independent strict type.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControlProfileV2 {
    version: u32,
    pid1_path: String,
    pid1_sha256: [u8; 32],
    host_path: String,
    host_sha256: [u8; 32],
    argv: Vec<String>,
    exec_start_pre: Vec<Vec<String>>,
    exec_start_post: Vec<Vec<String>>,
    unit_sha256: [u8; 32],
    policy_path: String,
    policy_sha256: [u8; 32],
    payload_programs_path: String,
    payload_programs_sha256: [u8; 32],
    parent_resources: [u64; 22],
    cpu_period_usec: u64,
    host_service_limits: [u64; 4],
    kind: String,
    node: [u8; 16],
    resource_epoch: [u8; 16],
    resource_policy_sha256: [u8; 32],
    host_service: [u64; 22],
    host_control: [u64; 22],
    // Absence preserves the exact version-three serialization. The installed
    // immutable version-five profile declares explicit subdivisions of HostService,
    // never an additional component grant or boot-Control budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_execution_receiving: Option<execution_receiving::ExecutionReceivingProfileV2>,
}

#[derive(Debug, thiserror::Error)]
enum OriginErrorV2 {
    #[error(transparent)]
    Native(#[from] rustix::io::Errno),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Read(#[from] ExactReadFailure),
    #[error(transparent)]
    Linux(#[from] aos_linux_descriptors::Error),
    #[error(transparent)]
    Host(#[from] HostError),
    #[error(transparent)]
    Profile(#[from] serde_json::Error),
    #[error(transparent)]
    Shared(#[from] StartupFailure),
    #[error("the original Host component binding changed or is unavailable")]
    Binding,
    #[error("the fixed Host component destination could not be reserved: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
}

// Every returned flight is stored before classification or another flight.
// A failed action never suppresses the four independent available postchecks.
struct OriginAttemptV2 {
    positive_scratch_disposed: bool,
    action: Option<std::result::Result<(), OriginErrorV2>>,
    properties: [Option<std::result::Result<Properties, aos_systemd_client::Error>>; 2],
    property_checks: [Option<std::result::Result<(), OriginErrorV2>>; 2],
    producer: [Option<std::result::Result<Properties, aos_systemd_client::Error>>; 2],
    producer_checks: [Option<std::result::Result<(), OriginErrorV2>>; 2],
    pair: [Option<std::result::Result<(), ResourceReservationErrorV1>>; 2],
    pair_originals: [Option<Box<OriginalEnrollmentPairAttemptV1>>; 2],
    files: Option<std::result::Result<(), OriginErrorV2>>,
    process: Option<std::result::Result<(), OriginErrorV2>>,
    pid1: Option<std::result::Result<(), OriginErrorV2>>,
    boot: Option<std::result::Result<KernelBootId, aos_linux_descriptors::Error>>,
    boot_original: Option<RootOriginalKernelBootIdAttemptV1>,
    // Admission's entered primary and its independently owed post must not
    // overwrite each other's native subject or reached proc input prefixes.
    process_subjects: [Option<CurrentThreadSubjectOriginalV1>; 2],
    process_subject_results: [Option<aos_linux_descriptors::Result<()>>; 2],
    negative_identity: Option<PidFdNegativeIdentityOriginalV1>,
    negative_preparation: Option<aos_linux_descriptors::Result<()>>,
    negative_observation: Option<aos_linux_descriptors::Result<()>>,
    process_bytes: [[Vec<u8>; 2]; 2],
    boot_check: Option<std::result::Result<(), OriginErrorV2>>,
}

impl OriginAttemptV2 {
    fn new() -> Self {
        Self {
            positive_scratch_disposed: false,
            action: None,
            properties: std::array::from_fn(|_| None),
            property_checks: std::array::from_fn(|_| None),
            producer: std::array::from_fn(|_| None),
            producer_checks: std::array::from_fn(|_| None),
            pair: std::array::from_fn(|_| None),
            pair_originals: std::array::from_fn(|_| None),
            files: None,
            process: None,
            pid1: None,
            boot: None,
            boot_original: None,
            process_subjects: std::array::from_fn(|_| None),
            process_subject_results: std::array::from_fn(|_| None),
            negative_identity: None,
            negative_preparation: None,
            negative_observation: None,
            process_bytes: std::array::from_fn(|_| std::array::from_fn(|_| Vec::new())),
            boot_check: None,
        }
    }

    fn require_positive_leaf_v2(&self) -> Result<()> {
        if self.positive_scratch_disposed || !matches!(self.action, Some(Ok(())))
            || !matches!(self.files, Some(Ok(()))) || !matches!(self.process, Some(Ok(())))
            || !matches!(self.pid1, Some(Ok(()))) || !matches!(self.boot_check, Some(Ok(())))
            || !matches!(self.property_checks[1], Some(Ok(())))
            || !matches!(self.producer_checks[1], Some(Ok(())))
            || !matches!(self.pair[1], Some(Ok(())))
        {
            return Err(HostError::Fence("Host Authorize native leaf is incomplete"));
        }
        Ok(())
    }

    fn dispose_positive_leaf_v2(&mut self) -> Result<()> {
        self.require_positive_leaf_v2()?;
        let completed = std::mem::replace(self, Self::new());
        // A completed tombstone blocks native reentry; this does not reset an
        // operation, financial highwater, manager interval or request identity.
        self.action = Some(Ok(()));
        self.positive_scratch_disposed = true;
        drop(completed);
        Ok(())
    }

    fn property_error(&self, slot: usize) -> Option<&dyn Error> {
        self.properties[slot].as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)
            .or_else(|| self.property_checks[slot].as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
    }

    fn producer_error(&self, slot: usize) -> Option<&dyn Error> {
        self.producer[slot].as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)
            .or_else(|| self.producer_checks[slot].as_ref().and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
    }
}

/// Reports a rejected fixed three-listener ownership transfer.
#[derive(Debug, thiserror::Error)]
pub enum HostComponentControlHandoffErrorV2 {
    /// Original admission failed, is incomplete, or was already transferred.
    #[error("original Host component startup is unavailable")]
    Original,
    /// At least one caller-owned fixed destination slot is occupied.
    #[error("original Host component destination is occupied")]
    Destination,
}

/// Retains the image-owned Host service and boot-lifetime control originals.
///
/// Only the fixed initial table can populate this owner. Its comparisons do
/// not issue a per-operation loan or enable Launch or decrease-only effects.
/// A failed selected attempt aborts before its original fields can unwind.
#[must_use]
pub struct HostComponentControlStartupV2 {
    capture_prelude: CapturePreludeV2,
    table: HostComponentInitialActivationTableV2,
    raw: [Option<OwnedFd>; 7],
    listener_attempts: [Option<RecordSubjectListenerAdmissionAttemptV1>; 3],
    listeners: [Option<RecordSubjectListener>; 3],
    files: [Option<File>; 9],
    identities: [Option<NspawnExecutableSnapshot>; 9],
    bytes: [Vec<u8>; 5],
    canonical_profile: Option<std::result::Result<Vec<u8>, serde_json::Error>>,
    normalized_fragment: Vec<u8>,
    profile: Option<ControlProfileV2>,
    profile_path: Option<PathBuf>,
    fragment_path: Option<PathBuf>,
    canonical_fragment: Option<std::io::Result<PathBuf>>,
    process: CurrentSelfPidFdCustodyV1,
    process_identity: Option<PidFdProcessIdentity>,
    pid1_process: Option<std::result::Result<PidFd, aos_linux_descriptors::Error>>,
    original_boot: Option<std::result::Result<KernelBootId, aos_linux_descriptors::Error>>,
    original_boot_capture: Option<RootOriginalKernelBootIdAttemptV1>,
    manager_preparation_issued: bool,
    component_phase0_funding: Option<std::result::Result<(), execution_receiving::Closed>>,
    permanent_baseline_demand: Option<Result<ResourceVector>>,
    execution_manager_growth: [Option<std::result::Result<(), aos_systemd_client::Error>>; 5],
    recipient: Option<[u8; 16]>,
    execution_origin: Option<crate::state::execution_origin::ExecutionOriginBindingV2>,
    producer: Option<[u8; 16]>,
    attempts: recurring_observation::OriginAttemptsV4,
    used: usize,
    capture_attempted: bool,
    admission_attempted: bool,
    admitted: bool,
    transferred: bool,
    armed: bool,
    first: Option<FirstCauseV2>,
    execution_receiving: Option<std::result::Result<execution_receiving::HostExecutionReceivingV2, execution_receiving::Closed>>,
    manager_schedule: Option<std::result::Result<manager_schedule::HostReadonlyManagerScheduleV2, OriginErrorV2>>,
    manager_original: Option<std::sync::Arc<aos_systemd_client::ReadonlyPropertyManagerOriginalV2>>,
    cold_session_original: Option<Box<cold_session::ColdSessionOriginalV1>>,
    refusal: OriginErrorV2,
}

// This is the same source quote used before the permanent Host model grows.
// It performs no allocation, native read, reservation or admission. Phase0's
// physical comparison uses it before retaining large Control destinations.
fn component_baseline_receiving_demand_v2() -> Result<ResourceVector> {
    let additional = crate::state::HostStateReadAttemptV2::receiving_demand_v2()
        .ok_or(HostError::ResourceExhausted)?;
    additional
        .checked_add(
            ResourceVector::ZERO
                .with(
                    aos_sandbox_model::ResourceDimension::MemoryBytes,
                    u64::try_from(
                        std::mem::size_of::<
                            crate::broker::HostBroker<
                                crate::catalog::FileHostCatalog,
                                crate::state::FileHostStateStore,
                                crate::worker::SystemdOneShotWorker,
                            >,
                        >()
                        .checked_mul(2)
                        .ok_or(HostError::ResourceExhausted)?,
                    )
                    .map_err(|_| HostError::ResourceExhausted)?,
                )
                .with(aos_sandbox_model::ResourceDimension::Pids, 1)
                // hostd keeps three distinct cgroup OFDs (raw, worker and
                // export), two catalog directory OFDs (reader and publisher),
                // and one flocked State directory OFD. Flock uses that same
                // State OFD; the snapshot reader above has its own seventh FD.
                .with(aos_sandbox_model::ResourceDimension::OpenFiles, 3 + 2 + 1),
        )
        .map_err(|_| HostError::ResourceExhausted)
}


// Set only at the end of the actual fixed-table/listener/immutable-profile
// prelude. Native PID1 pair admission still follows the paid bootstrap.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CapturePreludeV2 {
    Unreached,
    Completed,
}

// Pure progress DATA, shared with the phase regression. It deliberately
// cannot construct a fixed descriptor table or an execution receiving owner.
fn capture_body_in_progress_v2(used: usize, armed: bool, action_recorded: bool) -> bool {
    used == 1 && armed && !action_recorded
}

impl HostComponentControlStartupV2 {
    /// Creates the fixed resident slots without opening or observing anything.
    pub fn new() -> Self {
        Self {
            capture_prelude: CapturePreludeV2::Unreached,
            table: HostComponentInitialActivationTableV2::new(),
            raw: std::array::from_fn(|_| None),
            listener_attempts: std::array::from_fn(|_| None),
            listeners: std::array::from_fn(|_| None),
            files: std::array::from_fn(|_| None),
            identities: [None; 9],
            bytes: std::array::from_fn(|_| Vec::new()),
            canonical_profile: None,
            normalized_fragment: Vec::new(),
            profile: None,
            profile_path: None,
            fragment_path: None,
            canonical_fragment: None,
            process: CurrentSelfPidFdCustodyV1::new(),
            process_identity: None,
            pid1_process: None,
            original_boot: None,
            original_boot_capture: None,
            manager_preparation_issued: false,
            component_phase0_funding: None,
            permanent_baseline_demand: None,
            execution_manager_growth: std::array::from_fn(|_| None),
            recipient: None,
            execution_origin: None,
            producer: None,
            attempts: recurring_observation::OriginAttemptsV4::new(),
            used: 0,
            capture_attempted: false,
            admission_attempted: false,
            admitted: false,
            transferred: false,
            armed: false,
            first: None,
            execution_receiving: None,
            manager_schedule: None,
            manager_original: None,
            cold_session_original: None,
            refusal: OriginErrorV2::Binding,
        }
    }

    /// Captures all seven inherited originals once, before protected opens.
    ///
    /// # Errors
    /// Borrows the resident original capture, listener, read, or profile cause.
    /// Partial files and bytes survive refusal; no fallback or retry is allowed.
    pub fn capture_original_once(&mut self) -> std::result::Result<(), &dyn Error> {
        if self.capture_attempted || self.armed {
            return Err(self.refuse_entry());
        }
        self.capture_attempted = true;
        self.armed = true;
        self.used = 1;
        self.attempts[0].action = Some(self.capture_inner());
        if self.attempts[0].action.as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(FirstCauseV2::Action(0));
        }
        self.attempts[0].files = Some(self.require_original_files());
        if self.attempts[0].files.as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(FirstCauseV2::Files(0));
        }
        self.finish_boot(0);
        self.finish()
    }

    fn capture_inner(&mut self) -> std::result::Result<(), OriginErrorV2> {
        if self.table.observe_once().is_err() {
            self.first.get_or_insert(FirstCauseV2::Table);
            return Err(OriginErrorV2::Binding);
        }
        self.raw = self.table.take_completed_entries().ok_or(OriginErrorV2::Binding)?;
        if std::env::var("LISTEN_PID").ok().as_deref()
            != Some(std::process::id().to_string().as_str())
            || std::env::var("LISTEN_FDS").ok().as_deref() != Some("7")
        {
            return Err(OriginErrorV2::Binding);
        }
        let names = std::env::var("LISTEN_FDNAMES").map_err(|_| OriginErrorV2::Binding)?;
        if names.len() > 512 {
            return Err(OriginErrorV2::Binding);
        }
        let supplied: Vec<_> = names.split(':').collect();
        if supplied.len() != 7 {
            return Err(OriginErrorV2::Binding);
        }
        let roles = [LISTENER_ROLES[0].0, LISTENER_ROLES[1].0, LISTENER_ROLES[2].0,
            FILE_ROLES[0], FILE_ROLES[1], FILE_ROLES[2], FILE_ROLES[3]];
        let mut indices = [0; 7];
        for (role, index) in roles.iter().zip(&mut indices) {
            let mut matched = supplied.iter().enumerate().filter(|(_, name)| **name == *role);
            *index = matched.next().ok_or(OriginErrorV2::Binding)?.0;
            if matched.next().is_some() {
                return Err(OriginErrorV2::Binding);
            }
        }
        for (role, index) in indices.into_iter().enumerate() {
            let original = self.raw[index].take().ok_or(OriginErrorV2::Binding)?;
            if role < 3 {
                self.listener_attempts[role] = Some(RecordSubjectListenerAdmissionAttemptV1::new(original));
            } else {
                self.files[role - 3] = Some(File::from(original));
            }
        }
        for (index, (_, path)) in LISTENER_ROLES.iter().enumerate() {
            if self.listener_attempts[index].as_mut().ok_or(OriginErrorV2::Binding)?
                .admit_once(Path::new(path)).is_err()
            {
                self.first.get_or_insert(FirstCauseV2::Listener(index));
                return Err(OriginErrorV2::Binding);
            }
        }
        for index in 0..3 {
            self.listeners[index] = self.listener_attempts[index].as_mut()
                .and_then(RecordSubjectListenerAdmissionAttemptV1::take_completed_listener);
        }
        if self.listeners.iter().any(Option::is_none) {
            return Err(OriginErrorV2::Binding);
        }

        // The capsule is an anonymous sealed object, not an EROFS path. Its
        // exact RO/seal/name rules are checked by the sole shared pair engine.
        for slot in 0..3 {
            self.require_immutable_file(slot)?;
            self.identities[slot] = Some(crate::plan::nspawn_executable_snapshot(self.file(slot)?.as_fd())?);
        }
        self.profile_path = Some(std::fs::read_link(format!("/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(self.file(1)?)))?);
        super::require_store_path(self.profile_path.as_deref().ok_or(OriginErrorV2::Binding)?)?;
        self.read_fixed(1, 0, MAXIMUM_PROFILE_BYTES)?;
        self.profile = Some(serde_json::from_slice(&self.bytes[0])?);
        self.canonical_profile = Some(serde_json::to_vec(self.profile.as_ref().ok_or(OriginErrorV2::Binding)?));
        if self.canonical_profile.as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(FirstCauseV2::CanonicalProfile);
            return Err(OriginErrorV2::Binding);
        }
        let profile = self.profile.as_ref().ok_or(OriginErrorV2::Binding)?;
        let expected_version = profile.host_execution_receiving.map_or(3, |receiving|
            if receiving.boot_preparation_vector_v1().is_some() { 6 } else { 5 });
        if self.canonical_profile.as_ref().and_then(|result| result.as_ref().ok()) != Some(&self.bytes[0])
            || profile.version != expected_version
            || profile.kind != "host-component-control-v1"
            || profile.node == [0; 16] || profile.resource_epoch == [0; 16]
            || profile.resource_policy_sha256 == [0; 32]
            || profile.host_service[..4] != profile.host_service_limits
        {
            return Err(OriginErrorV2::Binding);
        }
        super::require_host_service_profile_v1(&profile.parent_resources,
            &profile.host_service_limits, profile.cpu_period_usec)?;
        if let Some(receiving) = profile.host_execution_receiving {
            receiving.require_subdivision(ResourceVector::new(profile.host_service))
                .map_err(|_| OriginErrorV2::Binding)?;
        }
        for path in [&profile.pid1_path, &profile.host_path, &profile.policy_path, &profile.payload_programs_path] {
            super::require_store_path(Path::new(path))?;
        }
        self.capture_prelude = CapturePreludeV2::Completed;
        if self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_some()) {
            // Only the selected fixed Parent route can establish this private
            // bootstrap owner. Its complete Control capacity is consumed before
            // any added boot reader or readonly-manager reservoir is reached.
            self.prepay_selected_control_v2().map_err(|_| OriginErrorV2::Binding)?;
            self.original_boot_capture = Some(RootOriginalKernelBootIdAttemptV1::new());
            self.original_boot = self.original_boot_capture.as_mut()
                .and_then(|attempt| attempt.observe_once().ok().copied()).map(Ok);
        } else {
            self.original_boot = Some(KernelBootId::current());
        }
        if !self.original_boot.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(FirstCauseV2::OriginalBoot);
            return Err(OriginErrorV2::Binding);
        }
        Ok(())
    }

    // This is an in-progress prelude, not a completed capture or native grant.
    // All seven real entries have moved into their exact role destinations;
    // the marker can only be set after the canonical immutable profile checks.
    fn capture_prelude_in_progress_v2(&self) -> bool {
        self.capture_attempted
            && capture_body_in_progress_v2(self.used, self.armed, self.attempts[0].action.is_some())
            && !self.admission_attempted && !self.admitted && !self.transferred
            && self.first.is_none()
    }

    fn has_capture_prelude_v2(&self) -> bool {
        self.capture_prelude == CapturePreludeV2::Completed
            && self.capture_prelude_in_progress_v2()
            && self.raw.iter().all(Option::is_none)
            && self.listeners.iter().all(Option::is_some)
            && self.files[..4].iter().all(Option::is_some)
            && self.identities[..3].iter().all(Option::is_some)
            && self.profile_path.is_some()
            && self.canonical_profile.as_ref().and_then(|result| result.as_ref().ok())
                == Some(&self.bytes[0])
            && self.original_boot.is_none() && self.original_boot_capture.is_none()
            && self.manager_original.is_none() && !self.manager_preparation_issued
            && self.execution_receiving.is_none()
            && self.manager_schedule.as_ref().is_some_and(|result| result.is_ok())
    }

    fn prepay_selected_control_v2(&mut self) -> std::result::Result<(), execution_receiving::Closed> {
        if self.execution_receiving.is_some() || self.manager_schedule.is_some() {
            return Err(execution_receiving::Closed);
        }
        self.manager_schedule = Some((|| {
            manager_schedule::HostReadonlyManagerScheduleV2::for_profile(
                self.profile.as_ref().ok_or(OriginErrorV2::Binding)?,
                self.profile_path.as_deref().ok_or(OriginErrorV2::Binding)?,
            )
        })());
        self.execution_receiving = Some(
            execution_receiving::HostExecutionReceivingV2::from_capture_prelude_v2(self),
        );
        // Park the actual financial owner before consumption can refuse. Its
        // original AccountingError must survive the returned stopping marker.
        let prepared = (|| {
            let schedule = self.manager_schedule.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(execution_receiving::Closed)?;
            let demand = schedule.control_preparation_demand_v2()
                .ok_or(execution_receiving::Closed)?;
            let receiving = self.execution_receiving.as_mut()
                .and_then(|result| result.as_mut().ok()).ok_or(execution_receiving::Closed)?;
            receiving.consume_control_once(demand)
        })();
        if prepared.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(execution_receiving::Closed);
        }
        Ok(())
    }

    /// Prepays the selected readonly manager before its constructor grows.
    ///
    /// `None` identifies only the independently strict old version-three
    /// profile. A selected version-four refusal never falls back to it.
    ///
    /// # Errors
    /// Refuses changed/reentered originals or insufficient declared Control.
    pub fn prepare_readonly_manager_once_v2(&mut self)
        -> std::result::Result<Option<aos_systemd_client::ReadonlyPropertyReceiveScheduleV2>, &dyn Error>
    {
        if !self.capture_attempted || self.armed || self.used != 1
            || self.admission_attempted || self.first.is_some()
        {
            return Err(self.refuse_entry());
        }
        if self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_none()) {
            return Ok(None);
        }
        if self.manager_preparation_issued || !self.execution_receiving.as_ref()
            .and_then(|result| result.as_ref().ok()).is_some_and(|owner| owner.control_was_consumed())
        { return Err(self.refuse_entry()); }
        self.manager_preparation_issued = true;
        Ok(self.manager_schedule.as_ref().and_then(|result| result.as_ref().ok())
            .map(|schedule| schedule.initial))
    }

    /// Moves the SAME prepaid manager/native owner into this original once.
    ///
    /// Refusal leaves the caller's source slot unchanged. This transfer does
    /// not admit execution; its native PID1/profile joins still follow.
    ///
    /// # Errors
    /// Refuses an unfunded, foreign, failed, ended or repeated manager transfer.
    pub fn adopt_readonly_manager_once_v2(
        &mut self,
        source: &mut Option<aos_systemd_client::ReadonlyPropertyManagerOriginalV2>,
        actual: &std::sync::Arc<SystemdClient>,
    ) -> std::result::Result<(), &dyn Error> {
        let source_matches = source.as_ref().is_some_and(|source| {
            source.client_v2().is_some_and(|manager| std::sync::Arc::ptr_eq(manager, actual))
                && !source.has_ended_v2()
        });
        if !source_matches || self.manager_original.is_some() || self.used != 1
            || self.armed || self.admission_attempted || self.first.is_some()
            || !self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
                .is_some_and(|owner| owner.control_was_consumed())
        {
            return Err(self.refuse_entry());
        }
        let Some(original) = source.take() else {
            return Err(self.refuse_entry());
        };
        self.manager_original = Some(std::sync::Arc::new(original));
        Ok(())
    }

    /// Admits the same original Host image, unit, and PID1 enrollment once.
    ///
    /// # Errors
    /// Borrows the resident first action or independent postcheck cause. Every
    /// available postcheck runs even after refusal, with the original boot last.
    pub async fn admit_once(&mut self, systemd: &SystemdClient) -> std::result::Result<(), &dyn Error> {
        if self.admission_attempted || self.armed || self.used != 1
            || (self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_some())
                && !self.manager_original.as_ref().is_some_and(|original| {
                    original.client_v2().is_some_and(|actual| std::ptr::eq(actual.as_ref(), systemd))
                        && !original.has_ended_v2()
                }))
        {
            return Err(self.refuse_entry());
        }
        self.admission_attempted = true;
        self.armed = true;
        self.used = 2;
        self.attempts[1].action = Some(self.admit_inner(systemd, 1).await);
        if self.attempts[1].action.as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(FirstCauseV2::Action(1));
        }
        self.post_available(systemd, 1).await;
        if self.first.is_some() {
            return Err(self.failure());
        }
        if self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_some()) {
            // Native startup admission does not unseal19/20. The selected
            // broker must first commit the same enrollment's spent-origin row
            // in its authenticated HostState and complete its independent post.
            if execution_receiving::HostExecutionReceivingV2::require_complete_original(self).is_err() {
                self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
                return Err(self.failure());
            }
        }
        if self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_some()) {
            // All independent native admission posts and original pair joins
            // are already positive. Check the SAME reserved service remainder
            // before hostd can open its permanent directory/cgroup originals.
            if self.prepare_permanent_baseline_once_v2().is_err() {
                self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
                return Err(self.failure());
            }
        }
        self.armed = false;
        self.admitted = true;
        Ok(())
    }

    fn prepare_permanent_baseline_once_v2(&mut self)
        -> std::result::Result<(), execution_receiving::Closed>
    {
        if self.permanent_baseline_demand.is_some() {
            return Err(execution_receiving::Closed);
        }
        // Retain source arithmetic failures as well as the actual ledger's
        // capacity result. No capacity is charged twice: the complete baseline
        // remainder was already reserved with the original subdivisions.
        self.permanent_baseline_demand = Some(component_baseline_receiving_demand_v2());
        let actual = self.permanent_baseline_demand.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
            .ok_or(execution_receiving::Closed)?;
        self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(execution_receiving::Closed)?
            .require_baseline_before_growth_v2(actual)
    }

    async fn admit_inner(
        &mut self,
        systemd: &SystemdClient,
        round: usize,
    ) -> std::result::Result<(), OriginErrorV2> {
        self.observe_properties(systemd, round, 0).await;
        self.observe_producer(systemd, round, 0).await;
        self.attempts[round].pair[0] = Some(self.require_pair(round, 0));
        if self.attempts[round].pair[0].as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(FirstCauseV2::Pair(round, 0));
        }
        if self.attempts[round].property_error(0).is_some()
            || self.attempts[round].producer_error(0).is_some()
            || self.attempts[round].pair[0].as_ref().is_some_and(|result| result.is_err())
        {
            return Err(OriginErrorV2::Binding);
        }

        let profile = self.profile.as_ref().ok_or(OriginErrorV2::Binding)?;
        let (_, digest) = super::super::readiness::snapshot_and_hash_executable(self.file(0)?.as_fd())?;
        if digest != profile.pid1_sha256 {
            return Err(OriginErrorV2::Binding);
        }
        let host_path = profile.host_path.clone();
        self.open_file(4, Path::new(&host_path))?;
        let actual = std::fs::metadata("/proc/self/exe")?;
        let held = self.identities[4].ok_or(OriginErrorV2::Binding)?;
        if actual.dev() != held.device || actual.ino() != held.inode {
            return Err(OriginErrorV2::Binding);
        }
        let (_, digest) = super::super::readiness::snapshot_and_hash_executable(self.file(4)?.as_fd())?;
        if digest != self.profile.as_ref().ok_or(OriginErrorV2::Binding)?.host_sha256 {
            return Err(OriginErrorV2::Binding);
        }
        self.process_identity = Some(self.process.capture_current()?);
        if self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_some()) {
            // Prearm the independent admission post before the primary can
            // fence healthy identity. The same stat OFD and pidfd stay held.
            self.prepare_owed_process_once_v2(round)?;
        }
        self.pid1_process = Some(PidFd::open(NonZeroU32::new(1).ok_or(OriginErrorV2::Binding)?));
        if self.pid1_process.as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(FirstCauseV2::Pid1Capture);
            return Err(OriginErrorV2::Binding);
        }
        for (slot, path) in [(6, "/proc/self/status"), (7, "/proc/self/cgroup")] {
            let descriptor = rustix::fs::open(path, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?;
            self.files[slot] = Some(File::from(descriptor));
            if rustix::fs::fstatfs(self.file(slot)?)?.f_type as u64 != 0x9fa0 {
                return Err(OriginErrorV2::Binding);
            }
        }
        if self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_some()) {
            self.require_process_retaining_v2(round, 0)?;
        } else {
            self.require_process()?;
        }
        let path = self.fragment_path.clone().ok_or(OriginErrorV2::Binding)?;
        self.canonical_fragment = Some(std::fs::canonicalize(&path));
        if self.canonical_fragment.as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(FirstCauseV2::CanonicalFragment);
            return Err(OriginErrorV2::Binding);
        }
        if self.canonical_fragment.as_ref().and_then(|result| result.as_ref().ok()) != Some(&path)
            || path.file_name().and_then(|name| name.to_str()) != Some(HOST_UNIT)
        {
            return Err(OriginErrorV2::Binding);
        }
        self.open_file(5, &path)?;
        self.read_fixed(5, 1, MAXIMUM_FRAGMENT_BYTES)?;
        self.require_fragment()?;
        let path = self.profile.as_ref().ok_or(OriginErrorV2::Binding)?.payload_programs_path.clone();
        self.open_file(8, Path::new(&path))?;
        self.read_fixed(8, 2, MAXIMUM_PROGRAM_BYTES)?;
        if <[u8; 32]>::from(Sha256::digest(&self.bytes[2]))
            != self.profile.as_ref().ok_or(OriginErrorV2::Binding)?.payload_programs_sha256
        {
            return Err(OriginErrorV2::Binding);
        }
        Ok(())
    }

    /// Rechecks the same retained originals without another admission or open.
    ///
    /// # Errors
    /// Refuses exhausted fixed slots or a previous failure and borrows actual
    /// retained action/debt. It never heals poison or renews a control interval.
    pub async fn recheck_original(&mut self, systemd: &SystemdClient) -> std::result::Result<(), &dyn Error> {
        if !self.admitted || self.armed || self.used == MAXIMUM_ATTEMPTS {
            return Err(self.refuse_entry());
        }
        let round = self.used;
        self.used += 1;
        self.armed = true;
        self.attempts[round].action = Some(self.require_fragment());
        if self.attempts[round].action.as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(FirstCauseV2::Action(round));
        }
        self.post_available(systemd, round).await;
        self.finish()
    }

    // A refused mutating entry permanently closes positive access. The local
    // diagnostic is preallocated, and an earlier native cause remains first.
    fn refuse_entry(&mut self) -> &dyn Error {
        self.admitted = false;
        self.armed = true;
        self.first.get_or_insert(FirstCauseV2::EntryRefusal);
        self.failure()
    }

    async fn post_available(&mut self, systemd: &SystemdClient, round: usize) {
        self.attempts[round].files = Some(self.require_original_files());
        if self.attempts[round].files.as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::Files(round));
        }
        self.attempts[round].process = Some(if self.profile.as_ref()
            .is_some_and(|profile| profile.host_execution_receiving.is_some())
        { self.require_process_retaining_v2(round, 1) } else { self.require_process() });
        if self.attempts[round].process.as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::Process(round));
        }
        self.attempts[round].pid1 = Some(self.require_pid1_process());
        if self.attempts[round].pid1.as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::Pid1(round));
        }
        self.observe_properties(systemd, round, 1).await;
        self.observe_producer(systemd, round, 1).await;
        self.attempts[round].pair[1] = Some(self.require_pair(round, 1));
        if self.attempts[round].pair[1].as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::Pair(round, 1));
        }
        self.finish_boot(round);
    }

    fn finish_boot(&mut self, round: usize) {
        if self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_some()) {
            if !self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
                .is_some_and(|owner| owner.has_consumed_control_v2())
            {
                // A financial refusal reached no native reader. Already paid
                // independent posts use the consumed slot even after closure.
                self.attempts[round].boot_check = Some(Err(OriginErrorV2::Binding));
                self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
                return;
            }
            self.attempts[round].boot_original = Some(RootOriginalKernelBootIdAttemptV1::new());
            self.attempts[round].boot = self.attempts[round].boot_original.as_mut()
                .and_then(|attempt| attempt.observe_once().ok().copied()).map(Ok);
        } else {
            self.attempts[round].boot = Some(KernelBootId::current());
        }
        if !self.attempts[round].boot.as_ref().is_some_and(|result| result.is_ok()) {
            self.record_origin_failure_v4(round, FirstCauseV2::Boot(round));
        }
        self.attempts[round].boot_check = Some(match (
            self.original_boot.as_ref().and_then(|result| result.as_ref().ok()),
            self.attempts[round].boot.as_ref().and_then(|result| result.as_ref().ok()),
        ) {
            (Some(original), Some(actual)) if original == actual => Ok(()),
            _ => Err(OriginErrorV2::Binding),
        });
        if self.attempts[round].boot_check.as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::BootCheck(round));
        }
    }

    fn finish(&mut self) -> std::result::Result<(), &dyn Error> {
        if self.first.is_some() {
            return Err(self.failure());
        }
        self.armed = false;
        Ok(())
    }

    /// Borrows the actual chronological failure without extracting any owner.
    #[must_use]
    pub fn failure(&self) -> &dyn Error {
        self.failure_for_first_v4(self.first)
    }

    // The ordinary chronological selector is unchanged. A fresh negative Stop
    // also retains its own new-row selector without replacing the older one.
    fn failure_for_first_v4(&self, first: Option<FirstCauseV2>) -> &dyn Error {
        let actual: Option<&dyn Error> = match first {
            Some(FirstCauseV2::Table) => self.table.failure().map(|error| error as &dyn Error),
            Some(FirstCauseV2::Listener(index)) => self.listener_attempts[index].as_ref()
                .and_then(|attempt| match attempt.first_failure() {
                    Some(ListenerAdmissionFailureRefV1::Cause(error)) => Some(error as &dyn Error),
                    _ => None,
                }),
            Some(FirstCauseV2::CanonicalProfile) => self.canonical_profile.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::CanonicalFragment) => self.canonical_fragment.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::OriginalBoot) => self.original_boot_capture.as_ref().and_then(|attempt| attempt.failure())
                .map(|error| error as &dyn Error).or_else(|| self.original_boot.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)),
            Some(FirstCauseV2::Pid1Capture) => self.pid1_process.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::Action(round)) => self.attempts[round].process_subjects[0].as_ref()
                .and_then(|original| original.failure())
                .or_else(|| self.attempts[round].action.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)),
            Some(FirstCauseV2::Properties(round, slot)) => self.attempts[round].properties[slot].as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::PropertyCheck(round, slot)) => self.attempts[round].property_checks[slot].as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::Producer(round, slot)) => self.attempts[round].producer[slot].as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::ProducerCheck(round, slot)) => self.attempts[round].producer_checks[slot].as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::Pair(round, slot)) => self.attempts[round].pair_originals[slot]
                .as_ref().and_then(|original| original.failure())
                .or_else(|| self.attempts[round].pair[slot].as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)),
            Some(FirstCauseV2::Files(round)) => self.attempts[round].files.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::Process(round)) => self.attempts[round].process_subjects[1].as_ref()
                .and_then(|original| original.failure())
                .or_else(|| self.attempts[round].negative_identity.as_ref().and_then(|original| original.failure()))
                .or_else(|| self.attempts[round].negative_observation.as_ref()
                    .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error))
                .or_else(|| self.attempts[round].process.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)),
            Some(FirstCauseV2::NegativePreparation(round)) => self.attempts[round].negative_identity.as_ref()
                .and_then(|original| original.failure())
                .or_else(|| self.attempts[round].negative_preparation.as_ref()
                    .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)),
            Some(FirstCauseV2::Pid1(round)) => self.attempts[round].pid1.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::Boot(round)) => self.attempts[round].boot_original.as_ref().and_then(|attempt| attempt.failure())
                .map(|error| error as &dyn Error).or_else(|| self.attempts[round].boot.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)),
            Some(FirstCauseV2::BootCheck(round)) => self.attempts[round].boot_check.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::EntryRefusal) => Some(&self.refusal),
            Some(FirstCauseV2::RecurringAllocation) => self.attempts.allocation_failure_v4(),
            Some(FirstCauseV2::ExecutionManager(phase)) => self.manager_growth_v4(phase)
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error),
            Some(FirstCauseV2::ExecutionReceiving) => self.permanent_baseline_demand.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error)
                .or_else(|| self.manager_schedule.as_ref()
                .and_then(|result| result.as_ref().err()).map(|error| error as &dyn Error))
                .or_else(|| self.execution_receiving.as_ref()
                .and_then(|result| match result {
                    Ok(original) => original.failure(),
                    Err(cause) => Some(cause as &dyn Error),
                })),
            None => None,
        };
        actual.unwrap_or(&self.refusal)
    }

    /// Transfers exactly the same three admitted listeners into vacant slots.
    ///
    /// # Errors
    /// Refuses an incomplete/failed/spent original or occupied destination.
    /// All checks precede the irreversible latch and three infallible moves.
    pub fn transfer_original_listeners_into(
        &mut self,
        destination: &mut [Option<RecordSubjectListener>; 3],
    ) -> std::result::Result<(), HostComponentControlHandoffErrorV2> {
        if destination.iter().any(Option::is_some) {
            return Err(HostComponentControlHandoffErrorV2::Destination);
        }
        if !self.admitted || self.armed || self.transferred || self.listeners.iter().any(Option::is_none) {
            return Err(HostComponentControlHandoffErrorV2::Original);
        }
        self.transferred = true;
        for (destination, original) in destination.iter_mut().zip(&mut self.listeners) {
            *destination = original.take();
        }
        Ok(())
    }

    pub(crate) fn pid1_original(&self) -> Result<BorrowedFd<'_>> {
        if !self.admitted || self.armed {
            return Err(HostError::Fence("original Host component is unavailable"));
        }
        self.require_original_files().map_err(|_| HostError::Fence("original Host component files changed"))?;
        Ok(self.file(0).map_err(|_| HostError::Fence("original Host PID1 is absent"))?.as_fd())
    }

    // This is only the selected opening's original-custody conjunction. It
    // lends no component claim, current account or per-effect eligibility.
    pub(crate) fn require_admitted_original(&self) -> Result<()> {
        if !self.admitted || self.armed || self.first.is_some() {
            return Err(HostError::Fence("original Host component is unavailable"));
        }
        Ok(())
    }

    pub(crate) fn execution_origin_binding_v2(&self)
        -> Result<Option<crate::state::execution_origin::ExecutionOriginBindingV2>>
    {
        self.require_admitted_original()?;
        if self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_none()) {
            return Ok(None);
        }
        self.execution_origin.map(Some).ok_or(HostError::Fence("execution original is absent"))
    }

    pub(crate) fn prepay_component_state_read_v2(&mut self) -> Result<bool> {
        self.require_admitted_original()?;
        if self.profile.as_ref().is_some_and(|profile| profile.host_execution_receiving.is_none()) {
            return Ok(false);
        }
        let additional = crate::state::HostStateReadAttemptV2::receiving_demand_v2()
            .ok_or(HostError::ResourceExhausted)?;
        // Admission already checked the complete permanent baseline before
        // any of its six native opens. This later snapshot entry must rejoin
        // that successful check, not reenter or reset its once-only result.
        if !self.permanent_baseline_demand.as_ref().is_some_and(|result| result.is_ok()) {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("original Host baseline was not prepaid"));
        }
        if self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(execution_receiving::Closed)
            .and_then(|owner| {
                owner.require_prepaid_baseline_v2()?;
                owner.extend_control_representation_v2(additional)
            }).is_err()
        {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("original Host snapshot receiving exceeds Control"));
        }
        Ok(true)
    }

    pub(crate) fn prepay_execution_origin_v2(&mut self, state: &crate::state::HostState) -> Result<()> {
        self.require_admitted_original()?;
        let additional = state.execution_origin_preparation_demand_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let result = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(execution_receiving::Closed)
            .and_then(|owner| owner.extend_control_representation_v2(additional));
        if result.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("execution origin Control capacity is insufficient"));
        }
        Ok(())
    }

    pub(crate) fn seal_execution_origin_v2(&mut self,
        committed: &crate::state::write_capture::ExecutionOriginCommitV2<'_>) -> Result<()>
    {
        self.require_admitted_original()?;
        if self.execution_origin != Some(committed.binding_v2()) {
            return Err(HostError::Fence("execution origin commit belongs to another original"));
        }
        if self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(execution_receiving::Closed).and_then(|owner| owner.admit_execution_once()).is_err()
        {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence("execution origin cannot unseal receiving"));
        }
        Ok(())
    }

    fn file(&self, slot: usize) -> std::result::Result<&File, OriginErrorV2> {
        self.files[slot].as_ref().ok_or(OriginErrorV2::Binding)
    }

    fn require_immutable_file(&self, slot: usize) -> std::result::Result<(), OriginErrorV2> {
        let file = self.file(slot)?;
        let stat = rustix::fs::fstat(file)?;
        // PID 1's inherited mount need not exist in this service's private
        // namespace. Query the mount held by this same descriptor directly.
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != 0 || stat.st_mode & 0o022 != 0
            || rustix::fs::fcntl_getfl(file)? & OFlags::ACCMODE != OFlags::RDONLY
            || !DescriptorMountObservation::capture(file.as_fd())?.is_read_only()
        {
            return Err(OriginErrorV2::Binding);
        }
        Ok(())
    }

    fn open_file(&mut self, slot: usize, path: &Path) -> std::result::Result<(), OriginErrorV2> {
        if self.files[slot].is_some() {
            return Err(OriginErrorV2::Binding);
        }
        super::require_store_path(path)?;
        let descriptor = rustix::fs::open(path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, Mode::empty())?;
        self.files[slot] = Some(File::from(descriptor));
        self.require_immutable_file(slot)?;
        self.identities[slot] = Some(crate::plan::nspawn_executable_snapshot(self.file(slot)?.as_fd())?);
        Ok(())
    }

    fn read_fixed(&mut self, file: usize, bytes: usize, maximum: usize) -> std::result::Result<(), OriginErrorV2> {
        let length = usize::try_from(self.identities[file].ok_or(OriginErrorV2::Binding)?.bytes)
            .map_err(|_| OriginErrorV2::Binding)?;
        if length == 0 || length > maximum {
            return Err(OriginErrorV2::Binding);
        }
        self.bytes[bytes].try_reserve_exact(length)?;
        self.bytes[bytes].resize(length, 0);
        read_exact_positioned_retaining_cause(self.files[file].as_ref().ok_or(OriginErrorV2::Binding)?, &mut self.bytes[bytes])?;
        Ok(())
    }

    fn require_original_files(&self) -> std::result::Result<(), OriginErrorV2> {
        for (slot, original) in self.identities.iter().enumerate() {
            let Some(original) = original else {
                continue;
            };
            self.require_immutable_file(slot)?;
            if crate::plan::nspawn_executable_snapshot(self.file(slot)?.as_fd())? != *original {
                return Err(OriginErrorV2::Binding);
            }
            let path = match slot {
                0 => self.profile.as_ref().map(|profile| Path::new(&profile.pid1_path)),
                1 => self.profile_path.as_deref(),
                4 => self.profile.as_ref().map(|profile| Path::new(&profile.host_path)),
                5 => self.fragment_path.as_deref(),
                8 => self.profile.as_ref().map(|profile| Path::new(&profile.payload_programs_path)),
                _ => None,
            };
            if let Some(path) = path {
                let named = rustix::fs::statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW)?;
                if named.st_dev != original.device || named.st_ino != original.inode {
                    return Err(OriginErrorV2::Binding);
                }
            }
        }
        Ok(())
    }

    async fn observe_properties(&mut self, systemd: &SystemdClient, round: usize, slot: usize) {
        self.attempts[round].properties[slot] = Some(systemd.observe_pid1_service_startup_properties(
            HOST_UNIT, std::process::id(), SERVICE_PROPERTIES, UNIT_PROPERTIES).await);
        if self.attempts[round].properties[slot].as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::Properties(round, slot));
        }
        self.attempts[round].property_checks[slot] = Some(self.check_properties(round, slot));
        if self.attempts[round].property_checks[slot].as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::PropertyCheck(round, slot));
        }
    }

    fn check_properties(&mut self, round: usize, slot: usize) -> std::result::Result<(), OriginErrorV2> {
        let actual = self.attempts[round].properties[slot].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(OriginErrorV2::Binding)?;
        let profile = self.profile.as_ref().ok_or(OriginErrorV2::Binding)?;
        super::require_host_startup_properties_v1(actual,
            self.profile_path.as_deref().ok_or(OriginErrorV2::Binding)?,
            HostStartupProfileViewV1 { pid1_path: &profile.pid1_path, host_path: &profile.host_path,
                argv: &profile.argv, exec_start_pre: &profile.exec_start_pre, exec_start_post: &profile.exec_start_post,
                cpu_period_usec: profile.cpu_period_usec, host_service_limits: profile.host_service_limits },
            HostStartupPropertyPurposeV1::ComponentControl)?;
        let invocation = fixed_id(actual.1.get(3).ok_or(OriginErrorV2::Binding)?)?;
        if self.recipient.is_some_and(|original| original != invocation) {
            return Err(OriginErrorV2::Binding);
        }
        self.recipient = Some(invocation);
        let path = Path::new(<&str>::try_from(actual.1.first().ok_or(OriginErrorV2::Binding)?)
            .map_err(|_| OriginErrorV2::Binding)?);
        super::require_store_path(path)?;
        match &self.fragment_path {
            Some(original) if original != path => return Err(OriginErrorV2::Binding),
            Some(_) => {}
            None => self.fragment_path = Some(path.to_owned()),
        }
        if round != 1 || slot != 0 {
            let original = self.attempts[1].properties[0].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(OriginErrorV2::Binding)?;
            if original != actual {
                return Err(OriginErrorV2::Binding);
            }
        }
        Ok(())
    }

    async fn observe_producer(&mut self, systemd: &SystemdClient, round: usize, slot: usize) {
        self.attempts[round].producer[slot] = Some(systemd.observe_pid1_service_startup_properties(
            HOST_UNIT, std::process::id(), &["AOSResourceProducerEpoch"], &["InvocationID"]).await);
        if self.attempts[round].producer[slot].as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::Producer(round, slot));
        }
        self.attempts[round].producer_checks[slot] = Some(self.check_producer(round, slot));
        if self.attempts[round].producer_checks[slot].as_ref().is_some_and(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::ProducerCheck(round, slot));
        }
    }

    fn check_producer(&mut self, round: usize, slot: usize) -> std::result::Result<(), OriginErrorV2> {
        let actual = self.attempts[round].producer[slot].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(OriginErrorV2::Binding)?;
        let [producer] = actual.0.as_slice() else {
            return Err(OriginErrorV2::Binding);
        };
        let [recipient] = actual.1.as_slice() else {
            return Err(OriginErrorV2::Binding);
        };
        let producer = fixed_id(producer)?;
        if self.recipient != Some(fixed_id(recipient)?) || self.producer.is_some_and(|original| original != producer) {
            return Err(OriginErrorV2::Binding);
        }
        self.producer = Some(producer);
        Ok(())
    }

    fn require_pair(&mut self, round: usize, slot: usize)
        -> std::result::Result<(), ResourceReservationErrorV1>
    {
        let unavailable = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let profile = self.profile.as_ref().ok_or_else(unavailable)?;
        let Some(execution) = profile.host_execution_receiving else {
            return self.require_ordinary_pair();
        };
        let expected = (profile.node, profile.resource_epoch, profile.resource_policy_sha256,
            ResourceVector::new(profile.host_service), ResourceVector::new(profile.host_control));
        let recipient = self.recipient.ok_or_else(unavailable)?;
        let producer = self.producer.ok_or_else(unavailable)?;
        let policy = self.files[2].as_ref().ok_or_else(unavailable)?;
        let delivery = self.files[3].as_ref().ok_or_else(unavailable)?;
        let destination = &mut self.attempts[round].pair_originals[slot];
        if destination.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // The enclosing selected Control preflight must include this exact
        // storage before allocation. The same observer retains native partials
        // rather than wrapping the consuming DATA adapter's returned marker.
        *destination = Some(Box::new(OriginalEnrollmentPairAttemptV1::new_component_data_v2()));
        let original = destination.as_mut().ok_or_else(unavailable)?
            .observe_once(policy, delivery).map_err(|_| unavailable())?;
        let provisions = original.policy.bootstrap_provisions();
        if !original.identity.matches_host_fields(expected.0, expected.1, expected.2, producer)
            || original.recipient_invocation != recipient
            || !original.policy.host_matches(expected.3, expected.4)
            || provisions.host_execution_prepare != Some(execution.prepare_vector())
            || provisions.host_execution_accept != Some(execution.accept_vector())
        {
            return Err(unavailable());
        }
        let prepare = aos_sandbox_protocol::domain_ledger::resource_bank::host_execution_prepare_claim(
            original.identity, original.policy).map_err(|_| unavailable())?.ok_or_else(unavailable)?.native_fields();
        let accept = aos_sandbox_protocol::domain_ledger::resource_bank::host_execution_accept_claim(
            original.identity, original.policy).map_err(|_| unavailable())?.ok_or_else(unavailable)?.native_fields();
        let fields = original.identity.native_fields();
        if prepare.account != accept.account || prepare.enrollment != original.identity
            || accept.enrollment != original.identity
        { return Err(unavailable()); }
        let binding = crate::state::execution_origin::ExecutionOriginBindingV2 {
            node: expected.0, epoch: expected.1, boot: fields.boot,
            producer: fields.invocation, manifest: expected.2,
            account: prepare.account, prepare_claim: prepare.id, accept_claim: accept.id,
            recipient, profile: Sha256::digest(&self.bytes[0]).into(),
        };
        if self.execution_origin.is_some_and(|earlier| earlier != binding) {
            return Err(unavailable());
        }
        self.execution_origin = Some(binding);
        Ok(())
    }

    fn require_ordinary_pair(&self) -> std::result::Result<(), ResourceReservationErrorV1> {
        let profile = self.profile.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        aos_sandbox_controller_domain::require_original_host_component_pair_v2(
            self.files[2].as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?,
            self.files[3].as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?,
            &profile.node, &profile.resource_epoch, &profile.resource_policy_sha256,
            &self.recipient.ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?,
            &self.producer.ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?,
            &ResourceVector::new(profile.host_service), &ResourceVector::new(profile.host_control),
        )
    }

    fn require_fragment(&mut self) -> std::result::Result<(), OriginErrorV2> {
        let profile = self.profile.as_ref().ok_or(OriginErrorV2::Binding)?;
        let path = self.profile_path.as_deref().ok_or(OriginErrorV2::Binding)?;
        let original = format!("OpenFile={}:aos-host-startup-profile:read-only\n", path.display());
        let replacement = b"OpenFile=@AOS_HOST_CANARY_PROFILE@:aos-host-startup-profile:read-only\n";
        let text = std::str::from_utf8(&self.bytes[1]).map_err(|_| OriginErrorV2::Binding)?;
        if text.split_inclusive('\n').filter(|line| *line == original).count() != 1 {
            return Err(OriginErrorV2::Binding);
        }
        let length = self.bytes[1].len().checked_sub(original.len()).and_then(|length| length.checked_add(replacement.len()))
            .filter(|length| *length <= MAXIMUM_FRAGMENT_BYTES).ok_or(OriginErrorV2::Binding)?;
        self.normalized_fragment.try_reserve_exact(length)?;
        self.normalized_fragment.clear();
        for line in text.split_inclusive('\n') {
            self.normalized_fragment.extend_from_slice(if line == original { replacement } else { line.as_bytes() });
        }
        if <[u8; 32]>::from(Sha256::digest(&self.normalized_fragment)) != profile.unit_sha256 {
            return Err(OriginErrorV2::Binding);
        }
        Ok(())
    }

    fn require_pid1_process(&self) -> std::result::Result<(), OriginErrorV2> {
        let original = self.pid1_process.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(OriginErrorV2::Binding)?;
        let info = original.info()?;
        let credentials = info.credentials().ok_or(OriginErrorV2::Binding)?;
        if info.pid() != 1 || !original.is_alive()?
            || [credentials.real_user_id(), credentials.effective_user_id(),
                credentials.saved_user_id(), credentials.filesystem_user_id()] != [0; 4]
        {
            return Err(OriginErrorV2::Binding);
        }
        Ok(())
    }

    fn prepare_owed_process_once_v2(&mut self, round: usize) -> std::result::Result<(), OriginErrorV2> {
        if self.attempts[round].negative_identity.is_some() {
            return Err(OriginErrorV2::Binding);
        }
        let mut original = PidFdNegativeIdentityOriginalV1::new();
        self.attempts[round].negative_preparation = Some(
            self.process.prepare_negative_identity_once_into_v1(&mut original));
        self.attempts[round].negative_identity = Some(original);
        if self.attempts[round].negative_preparation.as_ref().is_none_or(|result| result.is_err()) {
            self.record_origin_failure_v4(round, FirstCauseV2::NegativePreparation(round));
            return Err(OriginErrorV2::Binding);
        }
        Ok(())
    }

    fn require_process_retaining_v2(&mut self, round: usize, slot: usize) -> std::result::Result<(), OriginErrorV2> {
        let prior = [std::mem::take(&mut self.bytes[3]), std::mem::take(&mut self.bytes[4])];
        let reached = std::mem::replace(&mut self.attempts[round].process_bytes[slot],
            std::array::from_fn(|_| Vec::new()));
        let [status, membership] = reached;
        self.bytes[3] = status;
        self.bytes[4] = membership;
        let mut subject = self.attempts[round].process_subjects[slot].take()
            .unwrap_or_else(CurrentThreadSubjectOriginalV1::new);
        self.attempts[round].process_subject_results[slot] = Some(subject.observe_once(HOST_CONTEXT));
        // The independently prepaid post observes its prearmed original even
        // after subject refusal or a primary healthy-identity fence. It never
        // prepares a new source, obtains a healthy pin or restores Ready.
        let mut negative = if slot == 1 { self.attempts[round].negative_identity.take() } else { None };
        if let Some(original) = negative.as_mut() {
            self.attempts[round].negative_observation = Some(
                self.process.observe_negative_identity_once_v1(original));
        }
        let result = self.require_process_inner_v2(Some(&subject), negative.as_ref());
        if slot == 1 { self.attempts[round].negative_identity = negative; }
        self.attempts[round].process_subjects[slot] = Some(subject);
        self.attempts[round].process_bytes[slot] = [std::mem::take(&mut self.bytes[3]), std::mem::take(&mut self.bytes[4])];
        let [status, membership] = prior;
        self.bytes[3] = status;
        self.bytes[4] = membership;
        result
    }

    fn require_process(&mut self) -> std::result::Result<(), OriginErrorV2> {
        self.require_process_inner_v2(None, None)
    }

    fn require_process_inner_v2(&mut self, subject: Option<&CurrentThreadSubjectOriginalV1>,
        negative: Option<&PidFdNegativeIdentityOriginalV1>)
        -> std::result::Result<(), OriginErrorV2>
    {
        match subject {
            Some(original) if !original.is_complete() => return Err(OriginErrorV2::Binding),
            Some(_) => (),
            None => aos_sandbox_linux::guest_confinement::require_subject(HOST_CONTEXT)?,
        }
        if [rustix::process::getuid().as_raw(), rustix::process::geteuid().as_raw(),
            rustix::process::getgid().as_raw(), rustix::process::getegid().as_raw()] != [0; 4]
            || (negative.is_none() && self.process_identity != Some(self.process.observe_identity()?))
        {
            return Err(OriginErrorV2::Binding);
        }
        let process = if negative.is_none() { Some(self.process.pidfd()?) } else { None };
        let info = match negative {
            Some(original) => original.completed_info_v1().ok_or(OriginErrorV2::Binding)?,
            None => process.ok_or(OriginErrorV2::Binding)?.info()?,
        };
        let credentials = info.credentials().ok_or(OriginErrorV2::Binding)?;
        let alive = match process { Some(process) => process.is_alive()?, None => true };
        if !alive || info.parent_pid() != 1
            || [credentials.real_user_id(), credentials.effective_user_id(), credentials.saved_user_id(), credentials.filesystem_user_id()] != [0; 4]
            || [credentials.real_group_id(), credentials.effective_group_id(), credentials.saved_group_id(), credentials.filesystem_group_id()] != [0; 4]
        {
            return Err(OriginErrorV2::Binding);
        }
        let limits = self.profile.as_ref().ok_or(OriginErrorV2::Binding)?.host_service_limits;
        let descriptors = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        if descriptors.current != Some(limits[3]) || descriptors.maximum != Some(limits[3]) {
            return Err(OriginErrorV2::Binding);
        }
        self.read_proc(6, 3, 65_536)?;
        super::verify_zero_capability_status(std::str::from_utf8(&self.bytes[3]).map_err(|_| OriginErrorV2::Binding)?)?;
        self.read_proc(7, 4, 4096)?;
        let text = std::str::from_utf8(&self.bytes[4]).map_err(|_| OriginErrorV2::Binding)?;
        let mut unified = text.lines().filter(|line| line.starts_with("0::"));
        if unified.next() != Some("0::/system.slice/aos-sandbox-hostd.service") || unified.next().is_some() {
            return Err(OriginErrorV2::Binding);
        }
        Ok(())
    }

    fn read_proc(&mut self, slot: usize, bytes: usize, maximum: usize) -> std::result::Result<(), OriginErrorV2> {
        let output = &mut self.bytes[bytes];
        let file = self.files[slot].as_mut().ok_or(OriginErrorV2::Binding)?;
        super::read_bounded_original(file, output, maximum)?;
        Ok(())
    }
}

fn fixed_id(value: &OwnedValue) -> std::result::Result<[u8; 16], OriginErrorV2> {
    let Value::Array(values) = &**value else {
        return Err(OriginErrorV2::Binding);
    };
    if values.len() != 16 {
        return Err(OriginErrorV2::Binding);
    }
    let mut output = [0; 16];
    for (destination, value) in output.iter_mut().zip(values.inner()) {
        let Value::U8(value) = value else {
            return Err(OriginErrorV2::Binding);
        };
        *destination = *value;
    }
    if output == [0; 16] {
        return Err(OriginErrorV2::Binding);
    }
    Ok(output)
}

impl Default for HostComponentControlStartupV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HostComponentControlStartupV2 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod authorize_scratch_tests {
    use super::*;

    #[test]
    fn refused_leaf_disposal_preserves_native_cause_and_buffer_backing() {
        let mut original = OriginAttemptV2::new();
        let error = std::fs::File::open("/proc/self/aos-authorize-scratch-missing")
            .unwrap_err();
        let errno = error.raw_os_error();
        original.process = Some(Err(OriginErrorV2::Io(error)));
        original.process_bytes[1][0] = vec![7; 8192];
        let backing = original.process_bytes[1][0].as_ptr();

        assert!(original.dispose_positive_leaf_v2().is_err());

        assert!(!original.positive_scratch_disposed);
        assert!(original.action.is_none());
        assert_eq!(original.process_bytes[1][0].as_ptr(), backing);
        assert_eq!(original.process_bytes[1][0].len(), 8192);
        let Some(Err(OriginErrorV2::Io(error))) = &original.process else { panic!("native cause lost") };
        assert_eq!(error.raw_os_error(), errno);
    }
}

#[cfg(test)]
mod capture_prelude_tests {
    use super::*;

    #[test]
    fn active_capture_phase_precedes_its_recorded_action() {
        // capture_original_once has used=1/armed=true while capture_inner
        // evaluates, before the actual action Result is assigned. Exercise
        // that exact pure phase without constructing an armed native table.
        assert!(capture_body_in_progress_v2(1, true, false));
        assert!(!capture_body_in_progress_v2(1, false, true));
        assert!(!capture_body_in_progress_v2(1, true, true));
        assert!(!capture_body_in_progress_v2(0, false, false));
        assert!(!capture_body_in_progress_v2(2, true, false));

        // This gate is only progress DATA. Actual production construction
        // additionally requires the private completed prelude and all real
        // retained descriptor/listener/immutable-profile destinations.
    }
}
