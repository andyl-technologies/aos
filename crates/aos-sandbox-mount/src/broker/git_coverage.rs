//! Original Mount custody for the opt-in exclusive Git-only cohort.
//!
//! The same broker writer, tables, worker and destination root are compared
//! with complete fixed PID1 FD-store observations and the signed fixed catalog.
//! Returned originals and failures remain resident before independent checks.
//! Birth/fence persistence only denies future allocations; it grants none.
//!
//! ```text
//! same mount.journal: DesiredState z-git-birth-v1[244], z-git-fence-v1[268]
//! original two-PUT UUID -> same native COMMIT/readback -> DATA response[340]
//! ```

use std::time::Duration;

use aos_sandbox::journal::{CommitResult, Journal, JournalError, JournalRecord, JournalTransaction,
    RecordNamespace, GitCoverageNativeHistoryErrorV1};
use aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_core::format::git_upload_enrollment::{
    GitCoverageBirthV1, GitCoverageBrokerRoleV1,
    GitCoverageCatalogV1, GitCoverageDataErrorV1, GitCoverageEnrollmentV1,
    GitCoverageFenceV1, GitCoverageFlightV1,
    GitCoverageJournalProfileV1, GitCoverageOutcomeFieldsV1,
};
use aos_sandbox_protocol::git_project_coverage::ValidatedGitProjectCoverageRequestV1;
use aos_systemd::fd_store::{
    FdStoreCoverageObservationV1, FdStoreCoverageTransportErrorV1, FdStoreInspector,
};

use super::MountBroker;
use crate::worker::{MountWorker, RetainedMountObservation};
use crate::{MountError, Result};

const STATE_ROOT: &str = "/var/lib/aos/sandbox-mount";
const STATE_NAME: &str = "mount.journal";
const MAXIMUM_DESCRIPTOR_STORE_ENTRIES: u32 = 1024;
const BIRTH_KEY: &[u8] = b"z-git-birth-v1";
const FENCE_KEY: &[u8] = b"z-git-fence-v1";

#[derive(Debug, thiserror::Error)]
enum CoverageCauseV1 {
    #[error("fixed Mount coverage credentials failed; their original cause is retained")]
    Credentials,
    #[error("fixed Mount FD-store inspector failed; its original result is retained")]
    Inspector,
    #[error("Mount FD-store snapshot {0} failed; its whole result is retained")]
    DescriptorStore(usize),
    #[error("Mount worker snapshot {0} failed; its whole result is retained")]
    Worker(usize),
    #[error("Mount coverage clock sample failed; its whole result is retained")]
    Clock,
    #[error("Mount coverage DATA failed: {0}")]
    Data(#[from] GitCoverageDataErrorV1),
    #[error("Mount coverage original native prefix failed: {0}")]
    Native(#[from] GitCoverageNativeHistoryErrorV1),
    #[error("Mount coverage original journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("Mount coverage comparison failed: {0}")]
    Mount(#[from] MountError),
    #[error("Mount coverage refused: {0}")]
    Refused(&'static str),
}

#[derive(Clone, Copy)]
struct NativeCutV1 {
    prefix: [u8; 32],
    origin: [u8; 32],
    records: usize,
    last: Option<([u8; 16], u64)>,
}

pub(super) struct MountGitCoverageV1 {
    inputs: GitCoverageCredentialCustodyV1,
    inspector: Option<std::result::Result<FdStoreInspector, String>>,
    descriptors: [Option<std::result::Result<FdStoreCoverageObservationV1,
        FdStoreCoverageTransportErrorV1>>; 2],
    workers: [Option<Result<Vec<RetainedMountObservation>>>; 2],
    clocks: [Option<Result<RawPairedClockSample>>; 2],
    last_clock: Option<RawPairedClockSample>,
    native: Option<std::result::Result<NativeCutV1, CoverageCauseV1>>,
    transaction: Option<JournalTransaction>,
    commit: Option<std::result::Result<CommitResult, JournalError>>,
    readback: Option<std::result::Result<NativeCutV1, CoverageCauseV1>>,
    outcome: Option<GitCoverageOutcomeFieldsV1>,
    first: Option<CoverageCauseV1>,
    final_bookend: Option<CoverageCauseV1>,
    closed: bool,
}

impl MountGitCoverageV1 {
    fn with_inputs(inputs: GitCoverageCredentialCustodyV1) -> Self {
        Self {
            inputs,
            inspector: None,
            descriptors: std::array::from_fn(|_| None),
            workers: std::array::from_fn(|_| None),
            clocks: std::array::from_fn(|_| None),
            last_clock: None,
            native: None,
            transaction: None,
            commit: None,
            readback: None,
            outcome: None,
            first: None,
            final_bookend: None,
            closed: false,
        }
    }

    fn begin(&mut self) -> std::result::Result<(), CoverageCauseV1> {
        if self.closed {
            return Err(CoverageCauseV1::Refused("original attempt is permanently closed"));
        }
        self.closed = true;
        Ok(())
    }

    fn finish(&mut self, result: std::result::Result<(), CoverageCauseV1>) -> Result<()> {
        if let Err(cause) = result {
            self.first.get_or_insert(cause);
        }
        if self.inputs.recheck_mount_inputs_v1().is_err() {
            self.final_bookend.get_or_insert(CoverageCauseV1::Credentials);
        }
        if self.first.is_some() || self.final_bookend.is_some() {
            return Err(MountError::Fence("exclusive Mount cohort retained a failure"));
        }
        self.closed = false;
        Ok(())
    }

    fn capture(&mut self) -> Result<()> {
        let result = (|| {
            self.begin()?;
            let captured = if self.inputs.ready().is_some() {
                self.inputs.recheck_mount_inputs_v1()
            } else {
                self.inputs.capture()
            };
            if captured.is_err() {
                return Err(CoverageCauseV1::Credentials);
            }
            self.inspector = Some(FdStoreInspector::connect_mount_git_coverage_v1(Duration::from_secs(5)));
            if !matches!(self.inspector, Some(Ok(_))) {
                return Err(CoverageCauseV1::Inspector);
            }
            Ok(())
        })();
        self.finish(result)
    }

    fn observe_clock(&mut self, slot: usize, boot: [u8; 16], deadline: Option<u64>)
        -> std::result::Result<(), CoverageCauseV1>
    {
        self.clocks[slot] = Some(crate::service::trusted_paired_clock_sample());
        let sample = match self.clocks[slot].as_ref() {
            Some(Ok(sample)) => *sample,
            _ => return Err(CoverageCauseV1::Clock),
        };
        if sample.host_boot_id() != boot
            || deadline.is_some_and(|cut| sample.boottime_nanoseconds() >= cut)
            || self.last_clock.is_some_and(|old| old.validate_later_sample(sample).is_err())
        {
            return Err(CoverageCauseV1::Refused("original clock or deadline changed"));
        }
        let data = self.inputs.ready().ok_or(CoverageCauseV1::Credentials)?;
        let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
        let (_, issued, expires) = enrollment.generation_interval();
        let seconds = u64::try_from(sample.wall_seconds())
            .map_err(|_| CoverageCauseV1::Refused("negative policy clock"))?;
        if seconds < issued || seconds >= expires {
            return Err(CoverageCauseV1::Refused("original enrollment interval expired"));
        }
        self.last_clock = Some(sample);
        Ok(())
    }

    fn observe_descriptors(&mut self, slot: usize)
        -> std::result::Result<(), CoverageCauseV1>
    {
        let inspector = match self.inspector.as_ref() {
            Some(Ok(inspector)) => inspector,
            _ => return Err(CoverageCauseV1::Inspector),
        };
        self.descriptors[slot] = Some(inspector.snapshot_mount_git_coverage_v1());
        let observation = match self.descriptors[slot].as_ref() {
            Some(Ok(observed)) => observed,
            _ => return Err(CoverageCauseV1::DescriptorStore(slot)),
        };
        let observed = observation.snapshot()
            .map_err(|_| CoverageCauseV1::DescriptorStore(slot))?;
        // Count alone is not an empty FD-store proof. Retain and compare the
        // complete dump as well as configured capacity and reported count.
        if observed.maximum_entries != MAXIMUM_DESCRIPTOR_STORE_ENTRIES
            || observed.reported_entries != 0
            || !observed.rows.is_empty()
        {
            return Err(CoverageCauseV1::Refused("PID1 retains Mount descriptors"));
        }
        if slot == 1 {
            let before_observation = match self.descriptors[0].as_ref() {
                Some(Ok(before)) => before,
                _ => return Err(CoverageCauseV1::DescriptorStore(0)),
            };
            let before = before_observation.snapshot()
                .map_err(|_| CoverageCauseV1::DescriptorStore(0))?;
            if observed.maximum_entries != before.maximum_entries
                || observed.reported_entries != before.reported_entries
                || observation.invocation() != before_observation.invocation()
                || observation.manager_owner() != before_observation.manager_owner()
            {
                return Err(CoverageCauseV1::Refused("original FD-store capacity changed"));
            }
        }
        Ok(())
    }
}

impl<W: MountWorker> MountBroker<W> {
    /// Captures the fixed optional coverage inputs in this same resident broker.
    ///
    /// The selected daemon calls this before serving requests. Returned errors
    /// leave all actual captures and causes resident; they require disposal of
    /// the whole owner, not retry or a new inspector. It grants no allocation.
    ///
    /// # Errors
    /// Rejects reinstallation, unsafe/missing fixed inputs or inspector failure.
    pub fn install_git_coverage_v1(&mut self) -> Result<()> {
        let mut inputs = Some(GitCoverageCredentialCustodyV1::mount());
        self.install_git_coverage_from_mount_inputs_v1(&mut inputs)
    }

    /// Parks the selected daemon's original fixed input reservoir.
    ///
    /// The daemon first uses this same reservoir to pre-arm its returned
    /// Journal before cold recovery. This transfer does not create a second
    /// credential capture or grant a mutation permission.
    ///
    /// # Errors
    /// Refuses reinstallation, a different fixed role, changed original inputs
    /// or unavailable same-connection FD-store observation. Failures remain
    /// resident in this broker and cannot be retried.
    #[doc(hidden)]
    pub fn install_git_coverage_from_mount_inputs_v1(
        &mut self,
        inputs: &mut Option<GitCoverageCredentialCustodyV1>,
    ) -> Result<()> {
        if self.git_coverage.is_some() {
            return Err(MountError::Fence("Mount coverage was already installed"));
        }
        let inputs = inputs.take()
            .ok_or(MountError::Fence("original Mount coverage inputs are absent"))?;
        self.git_coverage = Some(MountGitCoverageV1::with_inputs(inputs));
        // Pre-arm the actual same writer before capture/inspector failures.
        // This only refuses NEW Source effects; it proves neither enrollment
        // nor emptiness, and original negative settlement stays purpose-closed.
        let denial = self.journal.retain_mount_git_coverage_denial_v1(
            &self.git_coverage.as_ref()
                .ok_or(MountError::Fence("Mount coverage owner is absent"))?.inputs,
        );
        if let Err(cause) = denial {
            let owner = self.git_coverage.as_mut()
                .ok_or(MountError::Fence("Mount coverage owner is absent"))?;
            owner.closed = true;
            owner.first.get_or_insert(CoverageCauseV1::Journal(cause));
            return Err(MountError::Fence("Mount cohort pre-arm retained a failure"));
        }
        self.git_coverage.as_mut()
            .ok_or(MountError::Fence("Mount coverage owner is absent"))?.capture()
    }

    pub(super) fn require_git_coverage_new_admission_v1(&self) -> Result<()> {
        if self.git_coverage.is_some() || self.git_coverage_persisted {
            return Err(MountError::Fence("exclusive Git cohort denies new Mount admissions"));
        }
        Ok(())
    }

    /// Compares the genuine current unused Mount owners before selected Ready.
    ///
    /// # Errors
    /// Permanently retains nonempty, unclassified, changed or unavailable
    /// originals, actual native errors and independent postcheck debt.
    pub fn audit_git_coverage_startup_v1(&mut self) -> Result<()> {
        self.compare_git_coverage_v1(None)
    }

    pub(crate) fn compare_git_coverage_v1(&mut self, deadline: Option<u64>) -> Result<()> {
        let owner = self.git_coverage.as_mut()
            .ok_or(MountError::Fence("fixed Mount coverage inputs were not captured"))?;
        if owner.closed {
            return Err(MountError::Fence("original Mount coverage attempt is permanently closed"));
        }
        let result = (|| {
            owner.begin()?;
            owner.inputs.recheck_mount_inputs_v1()
                .map_err(|_| CoverageCauseV1::Credentials)?;
            owner.observe_clock(0, self.kernel_boot_id, deadline)?;
            self.journal.validate_held_root_owned_at(STATE_ROOT, STATE_NAME)?;
            if self.resources.resources().next().is_some()
                || self.source_pins.rows().next().is_some()
                || self.fuse_reservations.rows().next().is_some()
                || self.source_runtime.is_some()
                || self.source_runtime_failed
            {
                return Err(CoverageCauseV1::Refused("original Mount tables or source debt are nonempty"));
            }
            owner.workers[0] = Some(self.worker.custody_inventory());
            match owner.workers[0].as_ref() {
                Some(Ok(rows)) if rows.is_empty() => {}
                Some(Ok(_)) => return Err(CoverageCauseV1::Refused("worker retains mounts")),
                _ => return Err(CoverageCauseV1::Worker(0)),
            }
            owner.observe_descriptors(0)?;
            self.destination_slots.as_mut()
                .ok_or(CoverageCauseV1::Refused("original destination root is absent"))?
                .compare_empty_git_coverage_v1()?;

            let data = owner.inputs.ready().ok_or(CoverageCauseV1::Credentials)?;
            let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            let (project, deployment) = data.role_pins();
            enrollment.verify_role_credentials(project, deployment)?;
            catalog.compare_enrollment(&enrollment)?;
            owner.native = Some(observe_native(&self.journal, &catalog));
            if !matches!(owner.native, Some(Ok(_))) {
                // Keep the actual owning native Result before all bookends.
                return Err(CoverageCauseV1::Refused("original native comparison failed"));
            }
            Ok(())
        })();
        if let Err(cause) = result {
            owner.first.get_or_insert(cause);
        }

        // These independent same-owner checks run even after an earlier
        // failure. No success scalar or detached map substitutes for them.
        owner.workers[1] = Some(self.worker.custody_inventory());
        match owner.workers[1].as_ref() {
            Some(Ok(rows)) if rows.is_empty() => {}
            Some(Ok(_)) => {
                owner.final_bookend.get_or_insert(CoverageCauseV1::Refused("worker changed"));
            }
            _ => { owner.final_bookend.get_or_insert(CoverageCauseV1::Worker(1)); }
        }
        if let Err(cause) = owner.observe_descriptors(1) {
            owner.final_bookend.get_or_insert(cause);
        }
        if let Err(cause) = self.journal.validate_held_root_owned_at(STATE_ROOT, STATE_NAME) {
            owner.final_bookend.get_or_insert(CoverageCauseV1::Journal(cause));
        }
        if let Err(cause) = owner.observe_clock(1, self.kernel_boot_id, deadline) {
            owner.final_bookend.get_or_insert(cause);
        }
        owner.finish(Ok(()))
    }

    pub(crate) fn consume_git_coverage_v1(
        &mut self,
        request: &ValidatedGitProjectCoverageRequestV1,
    ) -> Result<GitCoverageOutcomeFieldsV1> {
        let deadline = request.header().deadline_boottime_nanoseconds();
        self.compare_git_coverage_v1(Some(deadline))?;
        let owner = self.git_coverage.as_mut()
            .ok_or(MountError::Fence("Mount coverage owner is absent"))?;
        let result = (|| {
            owner.begin()?;
            let comparison = request.comparison().map_err(MountError::from)?;
            let coordinates = comparison.coordinates();
            let data = owner.inputs.ready().ok_or(CoverageCauseV1::Credentials)?;
            let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            if coordinates.role != GitCoverageBrokerRoleV1::Mount
                || coordinates.project != enrollment.project()
                || (coordinates.node, coordinates.epoch) != enrollment.node_epoch()
                || coordinates.generation != enrollment.generation_interval().0
                || coordinates.enrollment != enrollment.digest()
                || coordinates.catalog != catalog.digest()
                || comparison.enrollment().is_some_and(|intent| intent.bytes() != enrollment.bytes())
            {
                return Err(CoverageCauseV1::Refused("request changed original fixed inputs"));
            }
            let cut = match owner.native.as_ref() {
                Some(Ok(cut)) => *cut,
                _ => return Err(CoverageCauseV1::Refused("original native cut is unavailable")),
            };
            if comparison.flight() == GitCoverageFlightV1::Prepare
                && self.journal.get(RecordNamespace::DesiredState, FENCE_KEY).is_none()
            {
                if owner.transaction.is_some() || owner.commit.is_some() {
                    return Err(CoverageCauseV1::Refused("original append was already attempted"));
                }
                let birth = enrollment.fixed_owner_birth_recipe_v1(
                    &catalog, GitCoverageJournalProfileV1::Mount, coordinates.nonce,
                )?;
                let birth_bytes = birth.encode()?;
                let birth_digest = GitCoverageBirthV1::decode(&birth_bytes)?.digest();
                if birth.predecessor_prefix != cut.prefix
                    || birth.provision_origin != cut.origin
                    || self.journal.snapshot_sequence().checked_add(3) != Some(birth.commit_sequence)
                    || coordinates.expected != cut.prefix
                    || coordinates.birth != birth_digest
                {
                    return Err(CoverageCauseV1::Refused("Prepare changed the genuine predecessor"));
                }
                let fence = birth.to_fence_fields(
                    coordinates.generation, birth_digest, coordinates.nonce,
                );
                owner.transaction = Some(JournalTransaction::new(birth.transaction, vec![
                    JournalRecord::put(RecordNamespace::DesiredState, BIRTH_KEY.to_vec(), birth_bytes.to_vec()),
                    JournalRecord::put(RecordNamespace::DesiredState, FENCE_KEY.to_vec(), fence.encode()?.to_vec()),
                ])?);
                let transaction = owner.transaction.as_ref()
                    .ok_or(CoverageCauseV1::Refused("original transaction is absent"))?;
                self.journal.preflight_transactions(std::slice::from_ref(transaction))?;
                owner.inputs.recheck_mount_inputs_v1()
                    .map_err(|_| CoverageCauseV1::Credentials)?;
                owner.observe_clock(0, self.kernel_boot_id, Some(deadline))?;
                self.journal.validate_held_root_owned_at(STATE_ROOT, STATE_NAME)?;
                owner.commit = Some(self.journal.commit(owner.transaction.as_ref()
                    .ok_or(CoverageCauseV1::Refused("original transaction is absent"))?));
                if !matches!(owner.commit, Some(Ok(_))) {
                    return Err(CoverageCauseV1::Refused("original append retained ambiguous debt"));
                }
                self.git_coverage_persisted = true;
            }

            let data = owner.inputs.ready().ok_or(CoverageCauseV1::Credentials)?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            owner.readback = Some(observe_native(&self.journal, &catalog));
            let actual = match owner.readback.as_ref() {
                Some(Ok(actual)) => *actual,
                _ => return Err(CoverageCauseV1::Refused("original native readback failed")),
            };
            let birth = GitCoverageBirthV1::decode(self.journal.get(RecordNamespace::DesiredState, BIRTH_KEY)
                .ok_or(CoverageCauseV1::Refused("durable birth is absent"))?)?;
            let fence = GitCoverageFenceV1::decode(self.journal.get(RecordNamespace::DesiredState, FENCE_KEY)
                .ok_or(CoverageCauseV1::Refused("durable fence is absent"))?)?;
            fence.compare_birth(&birth)?;
            let original = fence.fields();
            if coordinates.birth != birth.digest()
                || original.enrollment != coordinates.enrollment
                || original.catalog != coordinates.catalog
                || original.project != coordinates.project
                || (original.node, original.epoch) != (coordinates.node, coordinates.epoch)
                || original.generation != coordinates.generation
                || actual.last != Some((original.transaction, birth.fields().commit_sequence))
                || (comparison.flight() == GitCoverageFlightV1::Prepare
                    && (coordinates.expected != original.predecessor_prefix
                        || coordinates.nonce != original.prepare_nonce))
                || (comparison.flight() == GitCoverageFlightV1::Read
                    && coordinates.expected != fence.digest())
            {
                return Err(CoverageCauseV1::Refused("original fence or replay changed"));
            }
            owner.outcome = Some(GitCoverageOutcomeFieldsV1 {
                request: coordinates, transaction: original.transaction,
                predecessor_prefix: original.predecessor_prefix, fence: fence.digest(),
                commit_sequence: birth.fields().commit_sequence, native_prefix: actual.prefix,
                record_count: u32::try_from(actual.records)
                    .map_err(|_| CoverageCauseV1::Refused("native record count exhausted"))?,
            });
            Ok(())
        })();
        owner.finish(result)?;
        // Reobserve the actual worker/root/native/clock inputs after append or
        // exact replay. An error leaves the whole response/commit custody local.
        self.compare_git_coverage_v1(Some(deadline))?;
        self.git_coverage.as_ref().and_then(|owner| owner.outcome)
            .ok_or(MountError::Fence("Mount coverage response is absent"))
    }
}

fn observe_native(journal: &Journal, catalog: &GitCoverageCatalogV1<'_>)
    -> std::result::Result<NativeCutV1, CoverageCauseV1>
{
    let mut original = journal.mount_git_coverage_native_prefix_v1(catalog)?;
    let cut = NativeCutV1 {
        prefix: original.prefix_digest(), origin: original.provision_origin_digest(),
        records: original.counts().1, last: original.last_commit(),
    };
    original.recheck()?;
    Ok(cut)
}
