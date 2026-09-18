//! Protected-state admission of the complete claimed startup descriptor table.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;

use aos_sandbox_linux::pidfd::{PidFd, PidFdCredentials};
use aos_sandbox_linux::startup_fd_table::{
    ClaimedInitialProcessFdTableV1, InitialDescriptorObjectKindV1, InitialDescriptorObservationV1,
    StartupProcessObservationV1,
};
use aos_sandbox_protocol::mount_manager_startup::{
    ExpectedStartupDescriptorV1, MountManagerStartupCaptureV1, StartupActivationLabelV1,
    StartupCredentialsV1, StartupDescriptorObjectKindV1, StartupDescriptorObservationV1,
    StartupDescriptorRoleV1, StartupExecutableIdentityV1, StartupExecutionIdentityV1,
    StartupSourceSubjectV1, manager_control_policy_witness_v1,
    seal_mount_manager_startup_capture_v1, startup_environment_hint_commitment_v1,
    startup_execution_identity_commitment_v1, startup_expected_table_digest_v1,
    startup_scanner_descriptor_digest_v1,
};
use aos_sandbox_protocol::mount_source_acquisition_state::RecordRefV2;
use sha2::{Digest as _, Sha256};

use super::{
    LostMountSourceCustodyProjectionV1, LostMountSourceCustodyV1, ManagerSourceControlAuthorityV1,
    ManagerSourcePresenceEvidenceProjectionV1, ManagerSourcePresenceOriginV1,
    MountManagerExecutionDeathKindV1, ReleasingSourceAbsenceBatchV1,
    StartupManagerSourcePresenceProjectionV1, StartupManagerSourcePresenceV1,
    TerminalMountSourceAbsenceProjectionV1,
};
use crate::journal::{MountManagerStartupCapturePreflightV1, MountManagerStartupCaptureReceiptV1};
use crate::{JournalError, ProtectedJournalAuthority};

/// Reports failure to establish exact startup descriptor authority.
#[derive(Debug, thiserror::Error)]
pub enum MountManagerSourceInventoryError {
    /// The Linux one-shot table changed or could not be revalidated.
    #[error("Mount-manager startup kernel capture failed")]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// Protected journal state was malformed, stale, or could not be committed.
    #[error("Mount-manager startup protected authority failed")]
    Journal(#[from] JournalError),
    /// Activation hints did not map the complete physical table to protected roles.
    #[error("Mount-manager startup descriptor mapping is invalid")]
    InvalidMapping,
    /// A terminally eligible SourceRoot was still physically present.
    #[error("a terminal Releasing SourceRoot remains present at startup")]
    ReleasingSourceStillPresent,
    /// The persisted last-custody Mount-manager execution remains alive.
    #[error("the prior Mount-manager custody execution remains alive")]
    PriorExecutionStillLive,
    /// Canonical capture construction rejected the observation.
    #[error("Mount-manager startup capture is invalid")]
    InvalidCapture,
    /// A poisoned append could not be classified because fixed-root reopen failed.
    #[error("Mount-manager startup capture durability remains indeterminate")]
    CaptureDurabilityIndeterminate {
        /// Reports the protected reopen or replay failure.
        #[source]
        source: JournalError,
    },
    /// Exact final readback proved that the staged capture was not committed.
    #[error("Mount-manager startup capture was not committed")]
    CaptureNotCommitted,
    /// The fixed-root owner lost its retained journal after failed recovery.
    #[error("Mount-manager startup protected owner is unavailable")]
    CaptureOwnerUnavailable,
}

/// Classifies one admitted non-listener activation descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountManagerActivationDescriptorKindV1 {
    /// Names one retained destination Mount.
    Mount,
    /// Names one retained SourceRoot.
    SourceRoot,
}

/// Owns one protected-state-admitted retained Mount descriptor.
pub struct MountManagerActivationDescriptorV1 {
    name: String,
    descriptor: OwnedFd,
}

/// Owns all non-SourceRoot descriptors released by startup admission.
pub struct MountManagerActivationDescriptorsV1 {
    listener: OwnedFd,
    standard: Vec<(u32, OwnedFd)>,
    mounts: Vec<MountManagerActivationDescriptorV1>,
}

/// Owns the complete post-commit result of one startup claim.
pub struct MountManagerStartupAuthorityV1 {
    descriptors: MountManagerActivationDescriptorsV1,
    sources: Vec<StartupManagerSourcePresenceV1>,
    losses: Vec<LostMountSourceCustodyV1>,
    absences: ReleasingSourceAbsenceBatchV1,
    control: ManagerSourceControlAuthorityV1,
    capture_sequence: u64,
    capture_id: [u8; 32],
    capture_record_digest: [u8; 32],
}

/// Retains descriptor capability while one exact capture append is unresolved.
pub(crate) struct StagedMountManagerStartupCaptureV1 {
    authority: MountManagerStartupAuthorityV1,
    capture: MountManagerStartupCaptureV1,
    preflight: MountManagerStartupCapturePreflightV1,
}

/// Compatibility name for the established startup authority.
pub type CapturedMountManagerStartupV1 = MountManagerStartupAuthorityV1;

impl MountManagerActivationDescriptorV1 {
    /// Returns the protected canonical activation name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the retained-Mount role.
    #[must_use]
    pub const fn kind(&self) -> MountManagerActivationDescriptorKindV1 {
        MountManagerActivationDescriptorKindV1::Mount
    }

    /// Consumes the capability into its owned retained Mount descriptor.
    #[must_use]
    pub fn into_fd(self) -> OwnedFd {
        self.descriptor
    }
}

impl MountManagerActivationDescriptorsV1 {
    /// Consumes the non-source set into listener, standard, and Mount owners.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        OwnedFd,
        Vec<(u32, OwnedFd)>,
        Vec<MountManagerActivationDescriptorV1>,
    ) {
        (self.listener, self.standard, self.mounts)
    }
}

impl MountManagerStartupAuthorityV1 {
    /// Returns the immutable capture sequence, identity, and record digest.
    #[must_use]
    pub const fn capture(&self) -> (u64, [u8; 32], [u8; 32]) {
        (
            self.capture_sequence,
            self.capture_id,
            self.capture_record_digest,
        )
    }

    /// Consumes the authority into typed descriptor owners and absence batch.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        MountManagerActivationDescriptorsV1,
        Vec<StartupManagerSourcePresenceV1>,
        Vec<LostMountSourceCustodyV1>,
        ReleasingSourceAbsenceBatchV1,
        ManagerSourceControlAuthorityV1,
    ) {
        (
            self.descriptors,
            self.sources,
            self.losses,
            self.absences,
            self.control,
        )
    }
}

impl StagedMountManagerStartupCaptureV1 {
    pub(crate) const fn capture_model(&self) -> &MountManagerStartupCaptureV1 {
        &self.capture
    }

    pub(crate) fn commit(
        &self,
        authority: &mut ProtectedJournalAuthority<'_>,
    ) -> Result<MountManagerStartupCaptureReceiptV1, JournalError> {
        authority.commit_mount_manager_startup_capture_v1(&self.preflight)
    }

    pub(crate) fn replace_preflight(&mut self, preflight: MountManagerStartupCapturePreflightV1) {
        self.preflight = preflight;
    }

    pub(crate) fn finish(
        self,
        receipt: Option<MountManagerStartupCaptureReceiptV1>,
    ) -> Result<MountManagerStartupAuthorityV1, MountManagerSourceInventoryError> {
        if let Some(receipt) = receipt {
            let expected = (
                self.capture.capture_sequence,
                self.capture.capture_id,
                self.capture.record_digest,
            );
            if receipt.capture() != expected {
                return Err(MountManagerSourceInventoryError::InvalidCapture);
            }
        }

        Ok(self.authority)
    }
}

/// Derives and stages one complete claimed startup table for the fixed owner.
///
/// No caller supplies names, roles, descriptor numbers, lifecycle selectors,
/// or physical identity. Activation environment bytes merely propose the
/// systemd slot-to-name mapping and authorize nothing until they exactly match
/// the protected projection and kernel observations.
///
/// # Errors
///
/// Returns an error for stale/malformed protected state, a noncanonical hint
/// mapping, any physical mismatch, a present terminal-loss subject, or failed
/// revalidation.
pub(crate) fn stage_mount_manager_startup_v1(
    authority: &mut ProtectedJournalAuthority<'_>,
    claimed: ClaimedInitialProcessFdTableV1,
) -> Result<StagedMountManagerStartupCaptureV1, MountManagerSourceInventoryError> {
    claimed.revalidate()?;
    let current_boot = claimed.execution().kernel_boot_id;
    let prepared = authority.prepare_mount_manager_startup_state_v1(current_boot)?;
    let expected = prepared.derived().expected_descriptors.clone();
    let source_subjects = prepared.derived().source_subjects.clone();
    let death_subjects = prepared
        .absence_death_subjects()
        .iter()
        .map(|subject| {
            (
                subject.acquisition_id,
                subject.terminal_proof_attempt,
                subject.terminal_proof_session.clone(),
                subject.last_custody_attempt,
                subject.last_custody_session.clone(),
            )
        })
        .collect::<Vec<_>>();
    let labels = derive_activation_labels(&claimed, &expected)?;
    let present_sources = labels
        .iter()
        .filter(|label| label.role == StartupDescriptorRoleV1::SourceRoot)
        .map(|label| label.logical_identity)
        .collect::<BTreeSet<_>>();
    for subject in &source_subjects {
        match subject {
            StartupSourceSubjectV1::Terminal(subject)
                if startup_source_alias_is_present(
                    subject.source_realization_handle,
                    subject.descriptor_commitment,
                    subject.source_kernel_boot_id,
                    subject.source_device,
                    subject.source_inode,
                    subject.source_unique_mount_id,
                    &labels,
                    &expected,
                    &claimed,
                ) =>
            {
                return Err(MountManagerSourceInventoryError::ReleasingSourceStillPresent);
            }
            StartupSourceSubjectV1::Cleanup(subject) => {
                let Some(evidence) = subject.evidence else {
                    continue;
                };
                if !present_sources.contains(&evidence.source_realization_handle)
                    && startup_source_alias_is_present(
                        evidence.source_realization_handle,
                        evidence.descriptor_commitment,
                        evidence.source_kernel_boot_id,
                        evidence.source_device,
                        evidence.source_inode,
                        evidence.source_unique_mount_id,
                        &labels,
                        &expected,
                        &claimed,
                    )
                {
                    return Err(MountManagerSourceInventoryError::InvalidMapping);
                }
            }
            StartupSourceSubjectV1::Terminal(_) => {}
        }
    }

    let (capture_sequence, predecessor_capture_digest) = prepared.next_capture_link()?;
    let (boot_time_before_ns, boot_time_after_ns) = claimed.boot_time_interval_ns();
    let (realtime_before_ns, realtime_after_ns) = claimed.realtime_interval_ns();
    let descriptor_table = protocol_descriptor_table(&claimed, &labels)?;
    let hints = claimed.activation_hints();
    let (listen_pid_hint_digest, listen_pid_hint_length) =
        startup_environment_hint_commitment_v1("LISTEN_PID", hints.listen_pid.as_deref())
            .map_err(|_| MountManagerSourceInventoryError::InvalidCapture)?;
    let (listen_fds_hint_digest, listen_fds_hint_length) =
        startup_environment_hint_commitment_v1("LISTEN_FDS", hints.listen_fds.as_deref())
            .map_err(|_| MountManagerSourceInventoryError::InvalidCapture)?;
    let (listen_fdnames_hint_digest, listen_fdnames_hint_length) =
        startup_environment_hint_commitment_v1("LISTEN_FDNAMES", hints.listen_fdnames.as_deref())
            .map_err(|_| MountManagerSourceInventoryError::InvalidCapture)?;
    let scanner_descriptor_count = u32::try_from(claimed.scanner_descriptor_numbers().len())
        .map_err(|_| MountManagerSourceInventoryError::InvalidCapture)?;
    let scanner_descriptor_digest =
        startup_scanner_descriptor_digest_v1(claimed.scanner_descriptor_numbers())
            .map_err(|_| MountManagerSourceInventoryError::InvalidCapture)?;
    let capture = seal_mount_manager_startup_capture_v1(MountManagerStartupCaptureV1 {
        capture_sequence,
        predecessor_capture_digest,
        capture_id: [0; 32],
        policy_generation: prepared.policy().generation,
        policy_digest: prepared.policy().record_digest,
        derivation: prepared.derived().head,
        expected_descriptors: expected.clone(),
        source_subjects: source_subjects.clone(),
        execution: protocol_execution(claimed.execution()),
        launcher: protocol_execution(claimed.launcher()),
        boot_time_before_ns,
        boot_time_after_ns,
        realtime_before_ns,
        realtime_after_ns,
        descriptor_table,
        descriptor_count: 0,
        activation_labels: labels.clone(),
        activation_count: 0,
        expected_descriptor_count: 0,
        source_subject_count: 0,
        cleanup_subject_count: 0,
        terminal_subject_count: 0,
        listener_descriptor_number: 0,
        listener_physical_commitment: [0; 32],
        listen_pid_hint_digest,
        listen_pid_hint_length,
        listen_fds_hint_digest,
        listen_fds_hint_length,
        listen_fdnames_hint_digest,
        listen_fdnames_hint_length,
        scanner_descriptor_count,
        scanner_descriptor_digest,
        descriptor_table_digest: [0; 32],
        activation_table_digest: [0; 32],
        expected_table_digest: prepared.derived().expected_table_digest,
        source_subjects_digest: prepared.derived().source_subjects_digest,
        record_digest: [0; 32],
    })
    .map_err(|_| MountManagerSourceInventoryError::InvalidCapture)?;
    let capture_id = capture.capture_id;
    let capture_record_digest = capture.record_digest;
    let control_policy = manager_control_policy_witness_v1(prepared.policy(), &capture)
        .map_err(|_| MountManagerSourceInventoryError::InvalidCapture)?;
    let source_presence_projections = derive_source_presence_projections(&capture)?;
    let terminal_projections = prove_terminal_absence_deaths(
        &source_subjects,
        &death_subjects,
        claimed.execution(),
        capture_id,
        capture_record_digest,
    )?;
    let cleanup_projections = prove_cleanup_losses(
        &source_subjects,
        &present_sources,
        claimed.execution(),
        capture_id,
        capture_record_digest,
    )?;
    let preflight =
        authority.preflight_mount_manager_startup_capture_v1(prepared, capture.clone())?;

    claimed.revalidate()?;
    validate_source_mount_read_only(&claimed, &labels)?;
    let (descriptors, sources) =
        release_typed_descriptors(claimed, &labels, &source_presence_projections)?;
    let losses = cleanup_projections
        .into_iter()
        .map(LostMountSourceCustodyV1::new)
        .collect();
    let absences =
        ReleasingSourceAbsenceBatchV1::new(terminal_projections, capture_id, capture_record_digest);
    Ok(StagedMountManagerStartupCaptureV1 {
        authority: MountManagerStartupAuthorityV1 {
            descriptors,
            sources,
            losses,
            absences,
            control: ManagerSourceControlAuthorityV1::new(control_policy),
            capture_sequence,
            capture_id,
            capture_record_digest,
        },
        capture,
        preflight,
    })
}

fn prove_terminal_absence_deaths(
    subjects: &[StartupSourceSubjectV1],
    death_subjects: &[(
        [u8; 32],
        RecordRefV2,
        aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderSessionV2,
        RecordRefV2,
        aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderSessionV2,
    )],
    current: &StartupProcessObservationV1,
    capture_id: [u8; 32],
    capture_record_digest: [u8; 32],
) -> Result<Vec<TerminalMountSourceAbsenceProjectionV1>, MountManagerSourceInventoryError> {
    subjects
        .iter()
        .filter_map(|subject| match subject {
            StartupSourceSubjectV1::Terminal(subject) => Some(subject),
            StartupSourceSubjectV1::Cleanup(_) => None,
        })
        .map(|subject| {
            let (_, terminal_proof_attempt, terminal_proof_session, last_custody_attempt, session) =
                death_subjects
                    .iter()
                    .find(|(acquisition_id, _, _, _, _)| *acquisition_id == subject.acquisition_id)
                    .ok_or(MountManagerSourceInventoryError::InvalidCapture)?;
            if (
                subject.terminal_attempt_id,
                subject.terminal_attempt_revision,
                subject.terminal_attempt_digest,
            ) != (
                terminal_proof_attempt.id,
                terminal_proof_attempt.revision,
                terminal_proof_attempt.record_digest,
            ) {
                return Err(MountManagerSourceInventoryError::InvalidCapture);
            }
            let writer = session.actual_writer_root_mount_process;
            let death_kind = prove_execution_dead(
                session.kernel_boot_id,
                writer.tgid,
                writer.start_time_ticks,
                current,
            )?;
            let mut projection = TerminalMountSourceAbsenceProjectionV1 {
                subject: *subject,
                capture_id,
                capture_record_digest,
                terminal_proof_attempt: *terminal_proof_attempt,
                terminal_proof_session_id: terminal_proof_session.session_id,
                terminal_proof_session_digest: terminal_proof_session.record_digest,
                last_custody_attempt: *last_custody_attempt,
                last_custody_session_id: session.session_id,
                last_custody_session_digest: session.record_digest,
                last_custody_kernel_boot_id: session.kernel_boot_id,
                last_custody_tgid: writer.tgid,
                last_custody_start_time_ticks: writer.start_time_ticks,
                last_custody_cgroup_digest: writer.cgroup_digest,
                death_kind,
                death_commitment: [0; 32],
            };
            projection.death_commitment = absence_death_commitment(&projection, current);
            Ok(projection)
        })
        .collect()
}

fn prove_cleanup_losses(
    subjects: &[StartupSourceSubjectV1],
    present_sources: &BTreeSet<[u8; 32]>,
    current: &StartupProcessObservationV1,
    capture_id: [u8; 32],
    capture_record_digest: [u8; 32],
) -> Result<Vec<LostMountSourceCustodyProjectionV1>, MountManagerSourceInventoryError> {
    subjects
        .iter()
        .filter_map(|subject| match subject {
            StartupSourceSubjectV1::Cleanup(subject)
                if subject.evidence.is_some_and(|evidence| {
                    !present_sources.contains(&evidence.source_realization_handle)
                }) =>
            {
                Some(subject)
            }
            StartupSourceSubjectV1::Cleanup(_) | StartupSourceSubjectV1::Terminal(_) => None,
        })
        .map(|subject| {
            let death_kind = subject
                .last_custody_owner
                .map(|owner| {
                    prove_execution_dead(
                        owner.kernel_boot_id,
                        owner.tgid,
                        owner.start_time_ticks,
                        current,
                    )
                })
                .transpose()?;
            let mut projection = LostMountSourceCustodyProjectionV1 {
                subject: *subject,
                capture_id,
                capture_record_digest,
                last_custody_owner: subject.last_custody_owner,
                death_kind,
                death_commitment: [0; 32],
            };
            projection.death_commitment = cleanup_death_commitment(&projection, current);
            Ok(projection)
        })
        .collect()
}

fn cleanup_death_commitment(
    projection: &LostMountSourceCustodyProjectionV1,
    current: &StartupProcessObservationV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount-manager.lost-source-cleanup.v1\0");
    hasher.update(projection.subject.acquisition_id);
    hasher.update(projection.subject.acquisition_revision.to_be_bytes());
    hasher.update(projection.subject.acquisition_record_digest);
    hasher.update(projection.subject.acquire_attempt_id);
    hasher.update(projection.subject.acquire_attempt_revision.to_be_bytes());
    hasher.update(projection.subject.acquire_attempt_record_digest);
    hasher.update(projection.capture_id);
    hasher.update(projection.capture_record_digest);
    if let Some(owner) = projection.last_custody_owner {
        hasher.update([1]);
        hasher.update(owner.attempt_id);
        hasher.update(owner.attempt_revision.to_be_bytes());
        hasher.update(owner.attempt_record_digest);
        hasher.update(owner.session_id);
        hasher.update(owner.session_record_digest);
        hasher.update(owner.kernel_boot_id);
        hasher.update(owner.tgid.to_be_bytes());
        hasher.update(owner.start_time_ticks.to_be_bytes());
        hasher.update(owner.cgroup_digest);
    } else {
        hasher.update([0]);
    }
    hasher.update([match projection.death_kind {
        None => 0,
        Some(MountManagerExecutionDeathKindV1::BootReplaced) => 1,
        Some(MountManagerExecutionDeathKindV1::PidfdExited) => 2,
        Some(MountManagerExecutionDeathKindV1::ProcessReplaced) => 3,
    }]);
    hasher.update(current.kernel_boot_id);
    hasher.update(current.process.pid().to_be_bytes());
    hasher.update(current.process.start_time_ticks().to_be_bytes());
    hasher.finalize().into()
}

fn prove_execution_dead(
    prior_boot: [u8; 16],
    prior_tgid: u32,
    prior_start_time_ticks: u64,
    current: &StartupProcessObservationV1,
) -> Result<MountManagerExecutionDeathKindV1, MountManagerSourceInventoryError> {
    if prior_boot != current.kernel_boot_id {
        return Ok(MountManagerExecutionDeathKindV1::BootReplaced);
    }
    let pid =
        NonZeroU32::new(prior_tgid).ok_or(MountManagerSourceInventoryError::InvalidCapture)?;
    let pidfd = match PidFd::open(pid) {
        Ok(pidfd) => pidfd,
        Err(aos_sandbox_linux::Error::Syscall { source, .. })
            if source.raw_os_error() == Some(3) =>
        {
            return Ok(MountManagerExecutionDeathKindV1::PidfdExited);
        }
        Err(error) => return Err(error.into()),
    };
    let identity = match pidfd.process_identity() {
        Ok(identity) => identity,
        Err(aos_sandbox_linux::Error::Syscall { source, .. })
            if source.raw_os_error() == Some(3) =>
        {
            return Ok(MountManagerExecutionDeathKindV1::PidfdExited);
        }
        Err(error) => return Err(error.into()),
    };
    if identity.pid() != prior_tgid || identity.start_time_ticks() != prior_start_time_ticks {
        return Ok(MountManagerExecutionDeathKindV1::ProcessReplaced);
    }
    if pidfd.is_alive()? {
        return Err(MountManagerSourceInventoryError::PriorExecutionStillLive);
    }
    Ok(MountManagerExecutionDeathKindV1::PidfdExited)
}

fn absence_death_commitment(
    projection: &TerminalMountSourceAbsenceProjectionV1,
    current: &StartupProcessObservationV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount-manager.lost-source-custody.v1\0");
    hasher.update(projection.subject.acquisition_id);
    hasher.update(projection.subject.acquisition_revision.to_be_bytes());
    hasher.update(projection.subject.acquisition_record_digest);
    hasher.update(projection.subject.source_realization_handle);
    hasher.update(projection.subject.descriptor_commitment);
    hasher.update(projection.capture_id);
    hasher.update(projection.capture_record_digest);
    hasher.update(projection.terminal_proof_session_id);
    hasher.update(projection.terminal_proof_session_digest);
    hasher.update(projection.last_custody_attempt.id);
    hasher.update(projection.last_custody_attempt.revision.to_be_bytes());
    hasher.update(projection.last_custody_attempt.record_digest);
    hasher.update(projection.last_custody_session_id);
    hasher.update(projection.last_custody_session_digest);
    hasher.update(projection.last_custody_kernel_boot_id);
    hasher.update(projection.last_custody_tgid.to_be_bytes());
    hasher.update(projection.last_custody_start_time_ticks.to_be_bytes());
    hasher.update(projection.last_custody_cgroup_digest);
    hasher.update([match projection.death_kind {
        MountManagerExecutionDeathKindV1::BootReplaced => 1,
        MountManagerExecutionDeathKindV1::PidfdExited => 2,
        MountManagerExecutionDeathKindV1::ProcessReplaced => 3,
    }]);
    hasher.update(current.kernel_boot_id);
    hasher.update(current.process.pid().to_be_bytes());
    hasher.update(current.process.start_time_ticks().to_be_bytes());
    hasher.finalize().into()
}

fn derive_activation_labels(
    claimed: &ClaimedInitialProcessFdTableV1,
    expected: &[ExpectedStartupDescriptorV1],
) -> Result<Vec<StartupActivationLabelV1>, MountManagerSourceInventoryError> {
    let hints = claimed.activation_hints();
    let pid = canonical_u32(hints.listen_pid.as_deref())?;
    let count = canonical_u32(hints.listen_fds.as_deref())?;
    if pid != claimed.execution().process.pid() {
        return Err(MountManagerSourceInventoryError::InvalidMapping);
    }
    let names = hints
        .listen_fdnames
        .as_deref()
        .ok_or(MountManagerSourceInventoryError::InvalidMapping)?
        .split(|byte| *byte == b':')
        .map(|bytes| {
            std::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| MountManagerSourceInventoryError::InvalidMapping)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if usize::try_from(count).ok() != Some(names.len()) {
        return Err(MountManagerSourceInventoryError::InvalidMapping);
    }
    let expected_by_name = expected
        .iter()
        .filter_map(|entry| entry.name.as_ref().map(|name| (name.as_str(), entry)))
        .collect::<BTreeMap<_, _>>();
    let mut labels = Vec::with_capacity(names.len());
    for (offset, name) in names.into_iter().enumerate() {
        let expected = expected_by_name
            .get(name.as_str())
            .ok_or(MountManagerSourceInventoryError::InvalidMapping)?;
        let number = u32::try_from(offset)
            .ok()
            .and_then(|offset| offset.checked_add(3))
            .ok_or(MountManagerSourceInventoryError::InvalidMapping)?;
        labels.push(StartupActivationLabelV1 {
            number,
            name,
            role: expected.role,
            logical_identity: expected.logical_identity,
        });
    }
    Ok(labels)
}

#[allow(clippy::too_many_arguments)]
fn startup_source_alias_is_present(
    source_realization_handle: [u8; 32],
    descriptor_commitment: [u8; 32],
    source_kernel_boot_id: [u8; 16],
    source_device: u64,
    source_inode: u64,
    source_unique_mount_id: u64,
    labels: &[StartupActivationLabelV1],
    expected: &[ExpectedStartupDescriptorV1],
    claimed: &ClaimedInitialProcessFdTableV1,
) -> bool {
    let logical_alias = labels
        .iter()
        .any(|label| label.logical_identity == source_realization_handle);
    let descriptor_alias = labels.iter().any(|label| {
        expected.iter().any(|entry| {
            entry.name.as_deref() == Some(label.name.as_str())
                && entry.role == StartupDescriptorRoleV1::SourceRoot
                && entry.descriptor_commitment == Some(descriptor_commitment)
        })
    });
    let physical_alias = source_kernel_boot_id == claimed.execution().kernel_boot_id
        && claimed.descriptors().iter().any(|entry| {
            let observation = entry.observation();
            entry.original_number() >= 3
                && observation.device == source_device
                && observation.inode == source_inode
                && observation.unique_mount_id == Some(source_unique_mount_id)
        });

    logical_alias || descriptor_alias || physical_alias
}

fn canonical_u32(value: Option<&[u8]>) -> Result<u32, MountManagerSourceInventoryError> {
    let value = value.ok_or(MountManagerSourceInventoryError::InvalidMapping)?;
    if value.is_empty()
        || (value.len() > 1 && value[0] == b'0')
        || !value.iter().all(u8::is_ascii_digit)
    {
        return Err(MountManagerSourceInventoryError::InvalidMapping);
    }
    std::str::from_utf8(value)
        .map_err(|_| MountManagerSourceInventoryError::InvalidMapping)?
        .parse()
        .map_err(|_| MountManagerSourceInventoryError::InvalidMapping)
}

fn protocol_descriptor_table(
    claimed: &ClaimedInitialProcessFdTableV1,
    labels: &[StartupActivationLabelV1],
) -> Result<Vec<StartupDescriptorObservationV1>, MountManagerSourceInventoryError> {
    claimed
        .descriptors()
        .iter()
        .map(|entry| {
            let mount_read_only = labels
                .iter()
                .find(|label| label.number == entry.original_number())
                .filter(|label| label.role == StartupDescriptorRoleV1::SourceRoot)
                .map(|_| entry.observe_current_mount_read_only())
                .transpose()?;
            Ok(protocol_descriptor(entry.observation(), mount_read_only))
        })
        .collect()
}

fn validate_source_mount_read_only(
    claimed: &ClaimedInitialProcessFdTableV1,
    labels: &[StartupActivationLabelV1],
) -> Result<(), MountManagerSourceInventoryError> {
    for label in labels
        .iter()
        .filter(|label| label.role == StartupDescriptorRoleV1::SourceRoot)
    {
        let entry = claimed
            .descriptors()
            .iter()
            .find(|entry| entry.original_number() == label.number)
            .ok_or(MountManagerSourceInventoryError::InvalidCapture)?;
        if !entry.observe_current_mount_read_only()? {
            return Err(MountManagerSourceInventoryError::InvalidCapture);
        }
    }
    Ok(())
}

fn protocol_descriptor(
    observation: &InitialDescriptorObservationV1,
    mount_read_only: Option<bool>,
) -> StartupDescriptorObservationV1 {
    StartupDescriptorObservationV1 {
        number: observation.number,
        descriptor_flags: observation.descriptor_flags,
        status_flags: observation.status_flags,
        object_kind: match observation.object_kind {
            InitialDescriptorObjectKindV1::Regular => StartupDescriptorObjectKindV1::Regular,
            InitialDescriptorObjectKindV1::Directory => StartupDescriptorObjectKindV1::Directory,
            InitialDescriptorObjectKindV1::Socket => StartupDescriptorObjectKindV1::Socket,
            InitialDescriptorObjectKindV1::Fifo => StartupDescriptorObjectKindV1::Fifo,
            InitialDescriptorObjectKindV1::Character => StartupDescriptorObjectKindV1::Character,
            InitialDescriptorObjectKindV1::Block => StartupDescriptorObjectKindV1::Block,
            InitialDescriptorObjectKindV1::Symlink => StartupDescriptorObjectKindV1::Symlink,
            InitialDescriptorObjectKindV1::Other => StartupDescriptorObjectKindV1::Other,
        },
        device: observation.device,
        inode: observation.inode,
        mode: observation.mode,
        special_device: observation.special_device,
        size: observation.size,
        unique_mount_id: observation.unique_mount_id,
        mount_read_only,
        socket: observation.socket.as_ref().map(|socket| {
            aos_sandbox_protocol::mount_manager_startup::StartupSocketObservationV1 {
                domain: socket.domain,
                socket_type: socket.socket_type,
                accepting: socket.accepting,
                local_address: socket.local_address.clone(),
            }
        }),
        physical_commitment: [0; 32],
    }
}

fn protocol_execution(observation: &StartupProcessObservationV1) -> StartupExecutionIdentityV1 {
    StartupExecutionIdentityV1 {
        kernel_boot_id: observation.kernel_boot_id,
        pid: observation.process.pid(),
        tgid: observation.process.thread_group_id(),
        ppid: observation.process.parent_pid(),
        start_time_ticks: observation.process.start_time_ticks(),
        credentials: protocol_credentials(observation.credentials),
        cgroup_id: observation.cgroup_id,
        cgroup_path: observation.cgroup_path.clone(),
        unit: observation.unit.clone(),
        executable: StartupExecutableIdentityV1 {
            device: observation.executable.device,
            inode: observation.executable.inode,
            size: observation.executable.size,
            mode: observation.executable.mode,
            fs_verity_sha256: observation.executable.fs_verity_sha256,
            build_identity_digest: Sha256::digest(observation.executable.build_identity.as_bytes())
                .into(),
        },
    }
}

const fn protocol_credentials(credentials: PidFdCredentials) -> StartupCredentialsV1 {
    StartupCredentialsV1 {
        real_uid: credentials.real_user_id(),
        effective_uid: credentials.effective_user_id(),
        saved_uid: credentials.saved_user_id(),
        filesystem_uid: credentials.filesystem_user_id(),
        real_gid: credentials.real_group_id(),
        effective_gid: credentials.effective_group_id(),
        saved_gid: credentials.saved_group_id(),
        filesystem_gid: credentials.filesystem_group_id(),
    }
}

fn release_typed_descriptors(
    claimed: ClaimedInitialProcessFdTableV1,
    labels: &[StartupActivationLabelV1],
    source_projections: &BTreeMap<u32, StartupManagerSourcePresenceProjectionV1>,
) -> Result<
    (
        MountManagerActivationDescriptorsV1,
        Vec<StartupManagerSourcePresenceV1>,
    ),
    MountManagerSourceInventoryError,
> {
    let labels = labels
        .iter()
        .map(|label| (label.number, label))
        .collect::<BTreeMap<_, _>>();
    let mut listener = None;
    let mut standard = Vec::new();
    let mut mounts = Vec::new();
    let mut sources = Vec::new();
    let (_, _, entries, _) = claimed.into_parts();
    for entry in entries {
        let number = entry.original_number();
        if number < 3 {
            standard.push((number, entry.into_fd()));
            continue;
        }
        let label = labels
            .get(&number)
            .ok_or(MountManagerSourceInventoryError::InvalidMapping)?;
        match label.role {
            StartupDescriptorRoleV1::Listener => listener = Some(entry.into_fd()),
            StartupDescriptorRoleV1::RetainedMount => {
                mounts.push(MountManagerActivationDescriptorV1 {
                    name: label.name.clone(),
                    descriptor: entry.into_fd(),
                });
            }
            StartupDescriptorRoleV1::SourceRoot => {
                let projection = source_projections
                    .get(&number)
                    .ok_or(MountManagerSourceInventoryError::InvalidMapping)?
                    .clone();
                sources.push(StartupManagerSourcePresenceV1::new(
                    entry.into_fd(),
                    projection,
                ));
            }
            StartupDescriptorRoleV1::StandardInput
            | StartupDescriptorRoleV1::StandardOutput
            | StartupDescriptorRoleV1::StandardError => {
                return Err(MountManagerSourceInventoryError::InvalidMapping);
            }
        }
    }
    Ok((
        MountManagerActivationDescriptorsV1 {
            listener: listener.ok_or(MountManagerSourceInventoryError::InvalidMapping)?,
            standard,
            mounts,
        },
        sources,
    ))
}

fn derive_source_presence_projections(
    capture: &MountManagerStartupCaptureV1,
) -> Result<BTreeMap<u32, StartupManagerSourcePresenceProjectionV1>, MountManagerSourceInventoryError>
{
    let expected_by_identity = capture
        .expected_descriptors
        .iter()
        .filter(|expected| expected.role == StartupDescriptorRoleV1::SourceRoot)
        .map(|expected| (expected.logical_identity, expected))
        .collect::<BTreeMap<_, _>>();
    let descriptors = capture
        .descriptor_table
        .iter()
        .map(|descriptor| (descriptor.number, descriptor))
        .collect::<BTreeMap<_, _>>();
    let mut projections = BTreeMap::new();

    for label in capture
        .activation_labels
        .iter()
        .filter(|label| label.role == StartupDescriptorRoleV1::SourceRoot)
    {
        let expected = expected_by_identity
            .get(&label.logical_identity)
            .filter(|expected| expected.name.as_ref() == Some(&label.name))
            .ok_or(MountManagerSourceInventoryError::InvalidCapture)?;
        let descriptor = descriptors
            .get(&label.number)
            .ok_or(MountManagerSourceInventoryError::InvalidCapture)?;
        let expected_entry_digest =
            startup_expected_table_digest_v1(std::slice::from_ref(*expected))
                .map_err(|_| MountManagerSourceInventoryError::InvalidCapture)?;
        let source_entry_commitment = startup_source_entry_commitment(
            capture.capture_sequence,
            capture.capture_id,
            capture.record_digest,
            label,
            expected_entry_digest,
            descriptor.physical_commitment,
        );
        let projection = StartupManagerSourcePresenceProjectionV1 {
            evidence: ManagerSourcePresenceEvidenceProjectionV1 {
                origin: ManagerSourcePresenceOriginV1::StartupCapture,
                manager_execution: capture.execution.clone(),
                manager_execution_commitment: startup_execution_identity_commitment_v1(
                    &capture.execution,
                )
                .map_err(|_| MountManagerSourceInventoryError::InvalidCapture)?,
                capture_sequence: capture.capture_sequence,
                capture_id: capture.capture_id,
                capture_record_digest: capture.record_digest,
                descriptor_count: capture.descriptor_count,
                activation_count: capture.activation_count,
                expected_descriptor_count: capture.expected_descriptor_count,
                source_subject_count: capture.source_subject_count,
                cleanup_subject_count: capture.cleanup_subject_count,
                terminal_subject_count: capture.terminal_subject_count,
                acquisition_id: expected
                    .source_acquisition_id
                    .ok_or(MountManagerSourceInventoryError::InvalidCapture)?,
                acquisition_revision: expected
                    .source_acquisition_revision
                    .ok_or(MountManagerSourceInventoryError::InvalidCapture)?,
                acquisition_record_digest: expected
                    .source_acquisition_record_digest
                    .ok_or(MountManagerSourceInventoryError::InvalidCapture)?,
                source_realization_handle: expected.logical_identity,
                descriptor_commitment: expected
                    .descriptor_commitment
                    .ok_or(MountManagerSourceInventoryError::InvalidCapture)?,
                manager_descriptor_number: label.number,
                source_kernel_boot_id: expected
                    .kernel_boot_id
                    .ok_or(MountManagerSourceInventoryError::InvalidCapture)?,
                source_device: expected
                    .device
                    .ok_or(MountManagerSourceInventoryError::InvalidCapture)?,
                source_inode: expected
                    .inode
                    .ok_or(MountManagerSourceInventoryError::InvalidCapture)?,
                source_unique_mount_id: expected
                    .unique_mount_id
                    .ok_or(MountManagerSourceInventoryError::InvalidCapture)?,
                source_entry_commitment,
            },
            expected: (*expected).clone(),
            expected_entry_digest,
            descriptor_physical_commitment: descriptor.physical_commitment,
        };
        if projections.insert(label.number, projection).is_some() {
            return Err(MountManagerSourceInventoryError::InvalidCapture);
        }
    }
    Ok(projections)
}

fn startup_source_entry_commitment(
    capture_sequence: u64,
    capture_id: [u8; 32],
    capture_record_digest: [u8; 32],
    label: &StartupActivationLabelV1,
    expected_entry_digest: [u8; 32],
    descriptor_physical_commitment: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount-manager.startup-source-entry.v1\0");
    hasher.update(capture_sequence.to_be_bytes());
    hasher.update(capture_id);
    hasher.update(capture_record_digest);
    hasher.update(label.number.to_be_bytes());
    hasher.update((label.name.len() as u64).to_be_bytes());
    hasher.update(label.name.as_bytes());
    hasher.update(label.logical_identity);
    hasher.update(expected_entry_digest);
    hasher.update(descriptor_physical_commitment);
    hasher.finalize().into()
}
