//! Original Storage comparison for the exclusive Git-only coverage cohort.
//!
//! This child reuses the same transaction store, authenticated resolver and
//! complete physical-inventory engine. Every returned observation and cause
//! is parked before independent checks. Birth/fence rows deny allocations;
//! their canonical response is DATA, never worker or floor authority.
//!
//! ```text
//! original storage-state.journal:
//! DesiredState z-git-birth-v1[244], z-git-fence-v1[268]
//! original two-PUT UUID -> native COMMIT/readback -> response DATA[340]
//! ```

use aos_sandbox::journal::{
    CommitResult, GitCoverageNativeHistoryErrorV1, GitCoverageNativePrefixLoanV1,
    JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_core::format::git_upload_enrollment::{
    GitCoverageBirthV1, GitCoverageBrokerRoleV1, GitCoverageCatalogV1,
    GitCoverageDataErrorV1, GitCoverageEnrollmentV1,
    GitCoverageFlightV1, GitCoverageJournalProfileV1, GitCoverageOutcomeFieldsV1,
};
use aos_sandbox_protocol::git_project_coverage::ValidatedGitProjectCoverageRequestV1;
use aos_sandbox_protocol::{
    MAXIMUM_RESPONSE_BYTES, ProtocolValidationError, ValidatedStorageInventory,
    decode_storage_resource_inventory_response,
};

use super::{StorageBrokerRuntime, StorageRuntimeError};
use crate::execution_output_credential::StorageExecutionOutputCustodyV1;
use crate::state::{StorageStateError, VerifiedStorageResolverJournalV1};

const STATE_ROOT: &str = "/var/lib/aos/sandbox-storage";

#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageGitCoverageCauseV1 {
    #[error("fixed Storage coverage credentials failed; their actual cause is resident")]
    Credentials,
    #[error("Storage coverage clock observation failed; its result is resident")]
    Clock,
    #[error("Storage coverage physical inventory failed; its result is resident")]
    Physical,
    #[error("Storage worker startup changed; its actual cause is resident")]
    Startup,
    #[error("Storage output custody changed; its actual cause is resident")]
    OutputCustody,
    #[error(transparent)]
    Data(#[from] GitCoverageDataErrorV1),
    #[error(transparent)]
    Native(#[from] GitCoverageNativeHistoryErrorV1),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    State(#[from] StorageStateError),
    #[error(transparent)]
    NativeLedger(Box<crate::native_issuance::StorageNativeIssuanceErrorV1>),
    #[error(transparent)]
    Workspace(Box<crate::workspace_catalog::StorageWorkspaceCatalogError>),
    #[error(transparent)]
    Output(Box<crate::execution_output::ExecutionOutputLedgerErrorV1>),
    #[error(transparent)]
    Service(Box<crate::service::StorageServiceError>),
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    #[error(transparent)]
    Runtime(#[from] StorageRuntimeError),
    #[error("Storage coverage refused: {0}")]
    Refused(&'static str),
}

impl From<crate::native_issuance::StorageNativeIssuanceErrorV1> for StorageGitCoverageCauseV1 {
    fn from(cause: crate::native_issuance::StorageNativeIssuanceErrorV1) -> Self {
        Self::NativeLedger(Box::new(cause))
    }
}

impl From<crate::workspace_catalog::StorageWorkspaceCatalogError> for StorageGitCoverageCauseV1 {
    fn from(cause: crate::workspace_catalog::StorageWorkspaceCatalogError) -> Self {
        Self::Workspace(Box::new(cause))
    }
}

impl From<crate::execution_output::ExecutionOutputLedgerErrorV1> for StorageGitCoverageCauseV1 {
    fn from(cause: crate::execution_output::ExecutionOutputLedgerErrorV1) -> Self {
        Self::Output(Box::new(cause))
    }
}

impl From<crate::service::StorageServiceError> for StorageGitCoverageCauseV1 {
    fn from(cause: crate::service::StorageServiceError) -> Self {
        Self::Service(Box::new(cause))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct StorageNativeCutV1 {
    pub(super) prefix: [u8; 32],
    pub(super) origin: [u8; 32],
    pub(super) records: usize,
    pub(super) last: Option<([u8; 16], u64)>,
}

pub(super) struct StorageGitCoverageV1 {
    inputs: GitCoverageCredentialCustodyV1,
    catalogs: [Option<Result<VerifiedStorageResolverJournalV1, StorageStateError>>; 2],
    physical: [Option<Result<Vec<u8>, StorageRuntimeError>>; 2],
    inventories: [Option<Result<ValidatedStorageInventory, ProtocolValidationError>>; 2],
    clocks: [Option<Result<RawPairedClockSample, StorageRuntimeError>>; 2],
    last_clock: Option<RawPairedClockSample>,
    startup: [Option<Result<(), crate::activation::StorageOriginalWorkerStartupCauseV3>>; 2],
    native_issuance: [Option<Result<StorageNativeCutV1, StorageGitCoverageCauseV1>>; 2],
    workspaces: [Option<Result<StorageNativeCutV1, StorageGitCoverageCauseV1>>; 2],
    output: [Option<Result<StorageNativeCutV1, StorageGitCoverageCauseV1>>; 2],
    output_custody: [Option<Result<(), crate::service::StorageServiceError>>; 2],
    output_bookends: [Option<Result<(), crate::service::StorageServiceError>>; 2],
    native: Option<Result<StorageNativeCutV1, StorageGitCoverageCauseV1>>,
    transaction: Option<JournalTransaction>,
    commit: Option<Result<CommitResult, StorageGitCoverageCauseV1>>,
    readback: Option<Result<StorageNativeCutV1, StorageGitCoverageCauseV1>>,
    outcome: Option<GitCoverageOutcomeFieldsV1>,
    first: Option<StorageGitCoverageCauseV1>,
    final_bookend: Option<StorageGitCoverageCauseV1>,
    closed: bool,
}

impl StorageGitCoverageV1 {
    pub(super) fn fixed() -> Self {
        Self {
            inputs: GitCoverageCredentialCustodyV1::storage(),
            catalogs: std::array::from_fn(|_| None),
            physical: std::array::from_fn(|_| None),
            inventories: std::array::from_fn(|_| None),
            clocks: std::array::from_fn(|_| None),
            last_clock: None,
            startup: std::array::from_fn(|_| None),
            native_issuance: std::array::from_fn(|_| None),
            workspaces: std::array::from_fn(|_| None),
            output: std::array::from_fn(|_| None),
            output_custody: std::array::from_fn(|_| None),
            output_bookends: std::array::from_fn(|_| None),
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

    fn begin(&mut self) -> Result<(), StorageGitCoverageCauseV1> {
        if self.closed {
            return Err(StorageGitCoverageCauseV1::Refused(
                "original Storage coverage attempt is permanently closed",
            ));
        }
        self.closed = true;
        Ok(())
    }

    fn finish(&mut self, result: Result<(), StorageGitCoverageCauseV1>)
        -> Result<(), StorageRuntimeError>
    {
        if let Err(cause) = result {
            self.first.get_or_insert(cause);
        }
        if self.inputs.recheck_storage_inputs_v1().is_err() {
            self.final_bookend.get_or_insert(StorageGitCoverageCauseV1::Credentials);
        }
        if self.first.is_some() || self.final_bookend.is_some() {
            return Err(StorageRuntimeError::Recovery);
        }
        self.closed = false;
        Ok(())
    }

    pub(super) fn capture(&mut self) -> Result<(), StorageRuntimeError> {
        let result = (|| {
            self.begin()?;
            if self.inputs.capture().is_err() {
                return Err(StorageGitCoverageCauseV1::Credentials);
            }
            Ok(())
        })();
        self.finish(result)
    }

    fn observe_clock(&mut self, slot: usize, deadline: Option<u64>)
        -> Result<RawPairedClockSample, StorageGitCoverageCauseV1>
    {
        self.clocks[slot] = Some(super::trusted_paired_clock_sample());
        let sample = match self.clocks[slot].as_ref() {
            Some(Ok(sample)) => *sample,
            _ => return Err(StorageGitCoverageCauseV1::Clock),
        };
        if deadline.is_some_and(|cut| sample.boottime_nanoseconds() >= cut)
            || self.last_clock.is_some_and(|old| old.validate_later_sample(sample).is_err())
        {
            return Err(StorageGitCoverageCauseV1::Refused("original clock or deadline changed"));
        }

        let data = self.inputs.ready().ok_or(StorageGitCoverageCauseV1::Credentials)?;
        let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
        let (_, issued, expires) = enrollment.generation_interval();
        let seconds = u64::try_from(sample.wall_seconds())
            .map_err(|_| StorageGitCoverageCauseV1::Refused("negative policy clock"))?;
        if seconds < issued || seconds >= expires {
            return Err(StorageGitCoverageCauseV1::Refused("original enrollment interval expired"));
        }
        self.last_clock = Some(sample);
        Ok(sample)
    }
}

impl StorageBrokerRuntime {
    /// Captures the fixed optional enrollment in this same resident Storage owner.
    ///
    /// The selected daemon calls this before Ready. Failure retains the actual
    /// credential captures and closes the attempt permanently; reinstallation
    /// or reopening in the same owner is not supported.
    ///
    /// # Errors
    /// Rejects duplicate installation or unavailable/changed fixed credentials.
    pub fn install_git_coverage_v1(&mut self) -> Result<(), StorageRuntimeError> {
        if self.git_coverage.is_some() {
            return Err(StorageRuntimeError::Recovery);
        }
        self.git_coverage = Some(StorageGitCoverageV1::fixed());
        self.git_coverage.as_mut().ok_or(StorageRuntimeError::Recovery)?.capture()
    }

    /// Audits the current fixed Storage originals before selected Ready.
    ///
    /// Output custody is borrowed from the actual daemon-owned credential and
    /// ledger. Absence is not an empty output domain. The comparison lends only
    /// DATA and does not authorize a worker, output reservation or allocation.
    ///
    /// # Errors
    /// Retains unavailable, changed, nonempty or unclassified originals and
    /// independent postcheck failures. No failed attempt can be retried.
    pub fn audit_git_coverage_startup_v1(
        &mut self,
        output: &StorageExecutionOutputCustodyV1,
    ) -> Result<(), StorageRuntimeError> {
        self.compare_git_coverage_v1(output, None)
    }

    pub(crate) fn compare_git_coverage_v1(
        &mut self,
        output: &StorageExecutionOutputCustodyV1,
        deadline: Option<u64>,
    ) -> Result<(), StorageRuntimeError> {
        if self.git_coverage.as_ref().is_none_or(|owner| owner.closed) {
            // Never overwrite a failed owner's original result slots with a
            // new observation, even if a later sample would be favorable.
            return Err(StorageRuntimeError::Recovery);
        }
        let mut original_cutoff = None;
        let result = (|| {
            let owner = self.git_coverage.as_mut()
                .ok_or(StorageGitCoverageCauseV1::Refused("fixed Storage inputs are absent"))?;
            owner.begin()?;
            owner.inputs.recheck_storage_inputs_v1()
                .map_err(|_| StorageGitCoverageCauseV1::Credentials)?;
            let sample = owner.observe_clock(0, deadline)?;
            let cut = match deadline {
                Some(cut) => cut,
                None => sample.boottime_nanoseconds().checked_add(
                    super::STARTUP_CATALOG_OBSERVATION_NANOSECONDS,
                ).ok_or(StorageGitCoverageCauseV1::Refused("original deadline overflow"))?,
            };
            original_cutoff = Some(cut);

            self.compare_git_coverage_owner_cuts_v1(output, 0)?;
            self.observe_git_coverage_physical_v1(0, cut)?;
            Ok(())
        })();
        let owner = self.git_coverage.as_mut().ok_or(StorageRuntimeError::Recovery)?;
        if let Err(cause) = result {
            owner.first.get_or_insert(cause);
        }

        // A returned inventory remains parked while the SAME engine performs
        // its final observation. Do not dispatch after a failure before the
        // original physical crossing was entered.
        if owner.physical[0].is_some() {
            if let Some(cut) = original_cutoff {
                if let Err(cause) = self.observe_git_coverage_physical_v1(1, cut) {
                    self.git_coverage.as_mut().ok_or(StorageRuntimeError::Recovery)?
                        .final_bookend.get_or_insert(cause);
                }
            }
        }
        if let Err(cause) = self.compare_git_coverage_owner_cuts_v1(output, 1) {
            self.git_coverage.as_mut().ok_or(StorageRuntimeError::Recovery)?
                .final_bookend.get_or_insert(cause);
        }
        let owner = self.git_coverage.as_mut().ok_or(StorageRuntimeError::Recovery)?;
        if let Err(cause) = owner.observe_clock(1, original_cutoff) {
            owner.final_bookend.get_or_insert(cause);
        }
        owner.finish(Ok(()))
    }

    fn compare_git_coverage_owner_cuts_v1(
        &mut self,
        output: &StorageExecutionOutputCustodyV1,
        slot: usize,
    ) -> Result<(), StorageGitCoverageCauseV1> {
        let owner = self.git_coverage.as_mut()
            .ok_or(StorageGitCoverageCauseV1::Refused("original Storage coverage is absent"))?;
        owner.inputs.recheck_storage_inputs_v1()
            .map_err(|_| StorageGitCoverageCauseV1::Credentials)?;
        let boot = owner.last_clock.ok_or(StorageGitCoverageCauseV1::Clock)?.host_boot_id();
        let data = owner.inputs.ready().ok_or(StorageGitCoverageCauseV1::Credentials)?;
        let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
        let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
        let (project, deployment) = data.role_pins();
        enrollment.verify_role_credentials(project, deployment)?;
        catalog.compare_enrollment(&enrollment)?;

        if self.held_reader_state_directory.as_deref() != Some(std::path::Path::new(STATE_ROOT))
            || self.operator_startup.is_some()
            || !self.original_measurements.originals.is_empty()
            || self.original_measurements.closed
            || self.original_measurements.first_admission_failure.is_some()
            || self.original_measurements.failed_carrier.is_some()
            || self.original_measurements.held_carrier_in_flight
        {
            return Err(StorageGitCoverageCauseV1::Refused("Storage retains prior or ambiguous work"));
        }
        self.native_escrow.require_git_coverage_empty_v1()?;
        owner.startup[slot] = Some(self.original_worker_startup.as_mut()
            .ok_or(StorageGitCoverageCauseV1::Refused("original worker startup is absent"))?
            .recheck());
        if !matches!(owner.startup[slot], Some(Ok(()))) {
            return Err(StorageGitCoverageCauseV1::Startup);
        }

        owner.catalogs[slot] = Some(self.coordinator.git_coverage_catalog_v1());
        if !matches!(owner.catalogs[slot], Some(Ok(_))) {
            return Err(StorageGitCoverageCauseV1::Refused("original primary catalog failed"));
        }
        owner.native_issuance[slot] = Some(self.native_issuance.as_mut()
            .ok_or(StorageGitCoverageCauseV1::Refused("original native issuance writer is absent"))?
            .compare_unused_git_coverage_v1(&catalog));
        if !matches!(owner.native_issuance[slot], Some(Ok(_))) {
            return Err(StorageGitCoverageCauseV1::Refused("native issuance history is not unused"));
        }
        owner.workspaces[slot] = Some(self.workspaces.as_mut()
            .ok_or(StorageGitCoverageCauseV1::Refused("original workspace writer is absent"))?
            .compare_unused_git_coverage_v1(&catalog, boot));
        if !matches!(owner.workspaces[slot], Some(Ok(_))) {
            return Err(StorageGitCoverageCauseV1::Refused("workspace history or physical root changed"));
        }
        owner.output_custody[slot] = Some(output.recheck(std::path::Path::new(STATE_ROOT)));
        if !matches!(owner.output_custody[slot], Some(Ok(()))) {
            return Err(StorageGitCoverageCauseV1::OutputCustody);
        }
        owner.output[slot] = Some(output.ledger().compare_unused_git_coverage_v1(&catalog));
        owner.output_bookends[slot] = Some(output.recheck(std::path::Path::new(STATE_ROOT)));
        if !matches!(owner.output[slot], Some(Ok(_))) {
            return Err(StorageGitCoverageCauseV1::Refused("original output history is not unused"));
        }
        if !matches!(owner.output_bookends[slot], Some(Ok(()))) {
            return Err(StorageGitCoverageCauseV1::OutputCustody);
        }
        if slot == 0 {
            owner.native = Some(self.coordinator.git_coverage_native_v1(&catalog));
            if !matches!(owner.native, Some(Ok(_))) {
                return Err(StorageGitCoverageCauseV1::Refused("original primary native history changed"));
            }
        } else {
            owner.readback = Some(self.coordinator.git_coverage_native_v1(&catalog));
            if !matches!(owner.readback, Some(Ok(_))) {
                return Err(StorageGitCoverageCauseV1::Refused("primary native readback changed"));
            }
            for cuts in [&owner.native_issuance, &owner.workspaces, &owner.output] {
                match (&cuts[0], &cuts[1]) {
                    (Some(Ok(before)), Some(Ok(after)))
                        if before.prefix == after.prefix && before.origin == after.origin
                            && before.records == after.records && before.last == after.last => {}
                    _ => return Err(StorageGitCoverageCauseV1::Refused("original lower native cut changed")),
                }
            }
            match (&owner.catalogs[0], &owner.catalogs[1]) {
                (Some(Ok(before)), Some(Ok(after)))
                    if before.genesis() == after.genesis()
                        && before.physical().binding() == after.physical().binding() => {}
                _ => return Err(StorageGitCoverageCauseV1::Refused("original primary catalog changed")),
            }
        }
        Ok(())
    }

    fn observe_git_coverage_physical_v1(
        &mut self,
        slot: usize,
        deadline: u64,
    ) -> Result<(), StorageGitCoverageCauseV1> {
        let owner = self.git_coverage.as_ref()
            .ok_or(StorageGitCoverageCauseV1::Refused("original Storage coverage is absent"))?;
        let sample = owner.last_clock.ok_or(StorageGitCoverageCauseV1::Clock)?;
        let cutoff = super::guest_root_inventory_cutoff(sample.boottime_nanoseconds(), deadline)?;
        // The existing worker/decoder/materializer is the sole physical engine.
        // Park its owning Result immediately, before decoding or other bookends.
        let result = self.inventory_resources(deadline, cutoff);
        let owner = self.git_coverage.as_mut()
            .ok_or(StorageGitCoverageCauseV1::Refused("original Storage coverage is absent"))?;
        owner.physical[slot] = Some(result);
        let bytes = match owner.physical[slot].as_ref() {
            Some(Ok(bytes)) => bytes,
            _ => return Err(StorageGitCoverageCauseV1::Physical),
        };
        owner.inventories[slot] = Some(decode_storage_resource_inventory_response(bytes, MAXIMUM_RESPONSE_BYTES));
        let current = match owner.inventories[slot].as_ref() {
            Some(Ok(current)) => current,
            _ => return Err(StorageGitCoverageCauseV1::Physical),
        };
        if !current.workspaces().is_empty()
            || !current.operator_repair_commits().is_empty()
            || current.kernel_boot_id() != &sample.host_boot_id()
            || current.broker_instance_id() != &self.broker_instance_id
        {
            return Err(StorageGitCoverageCauseV1::Refused("physical inventory is not the original empty owner"));
        }
        if slot == 1 {
            match owner.inventories[0].as_ref() {
                Some(Ok(before)) if before == current => {}
                _ => return Err(StorageGitCoverageCauseV1::Refused("original physical inventory changed")),
            }
        }
        Ok(())
    }

    pub(crate) fn consume_git_coverage_v1(
        &mut self,
        request: &ValidatedGitProjectCoverageRequestV1,
        output: &StorageExecutionOutputCustodyV1,
    ) -> Result<GitCoverageOutcomeFieldsV1, StorageRuntimeError> {
        let deadline = request.header().deadline_boottime_nanoseconds();
        self.compare_git_coverage_v1(output, Some(deadline))?;
        let owner = self.git_coverage.as_mut().ok_or(StorageRuntimeError::Recovery)?;
        let result = (|| {
            owner.begin()?;
            let comparison = request.comparison()?;
            let coordinates = comparison.coordinates();
            let data = owner.inputs.ready().ok_or(StorageGitCoverageCauseV1::Credentials)?;
            let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            if coordinates.role != GitCoverageBrokerRoleV1::Storage
                || coordinates.project != enrollment.project()
                || (coordinates.node, coordinates.epoch) != enrollment.node_epoch()
                || coordinates.generation != enrollment.generation_interval().0
                || coordinates.enrollment != enrollment.digest()
                || coordinates.catalog != catalog.digest()
                || comparison.enrollment().is_some_and(|intent| intent.bytes() != enrollment.bytes())
            {
                return Err(StorageGitCoverageCauseV1::Refused("request changed original fixed inputs"));
            }
            let cut = match owner.native.as_ref() {
                Some(Ok(cut)) => *cut,
                _ => return Err(StorageGitCoverageCauseV1::Refused("original native cut is unavailable")),
            };
            if comparison.flight() == GitCoverageFlightV1::Prepare
                && self.coordinator.git_coverage_durable_v1()?.is_none()
            {
                if owner.transaction.is_some() || owner.commit.is_some() {
                    return Err(StorageGitCoverageCauseV1::Refused("original append was already attempted"));
                }
                let birth = enrollment.fixed_owner_birth_recipe_v1(
                    &catalog, GitCoverageJournalProfileV1::StorageCatalog, coordinates.nonce,
                )?;
                let birth_bytes = birth.encode()?;
                let birth_digest = GitCoverageBirthV1::decode(&birth_bytes)?.digest();
                if birth.predecessor_prefix != cut.prefix
                    || birth.provision_origin != cut.origin
                    || coordinates.expected != cut.prefix
                    || coordinates.birth != birth_digest
                {
                    return Err(StorageGitCoverageCauseV1::Refused("Prepare changed the genuine predecessor"));
                }
                let fence = birth.to_fence_fields(
                    coordinates.generation, birth_digest, coordinates.nonce,
                );
                owner.transaction = Some(JournalTransaction::new(birth.transaction, vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState, b"z-git-birth-v1".to_vec(), birth_bytes.to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::DesiredState, b"z-git-fence-v1".to_vec(), fence.encode()?.to_vec(),
                    ),
                ])?);
                owner.inputs.recheck_storage_inputs_v1()
                    .map_err(|_| StorageGitCoverageCauseV1::Credentials)?;
                owner.observe_clock(0, Some(deadline))?;
                output.recheck(std::path::Path::new(STATE_ROOT))?;
                // The same store checks all eight actual native limits before
                // its sole commit. Park the whole result before postchecks.
                owner.commit = Some(self.coordinator.append_git_coverage_v1(
                    owner.transaction.as_ref()
                        .ok_or(StorageGitCoverageCauseV1::Refused("original transaction is absent"))?,
                ));
                if !matches!(owner.commit, Some(Ok(_))) {
                    return Err(StorageGitCoverageCauseV1::Refused("original append retained ambiguous debt"));
                }
            }

            let data = owner.inputs.ready().ok_or(StorageGitCoverageCauseV1::Credentials)?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            owner.readback = Some(self.coordinator.git_coverage_native_v1(&catalog));
            let actual = match owner.readback.as_ref() {
                Some(Ok(actual)) => *actual,
                _ => return Err(StorageGitCoverageCauseV1::Refused("original native readback failed")),
            };
            let (birth, fence) = self.coordinator.git_coverage_durable_v1()?
                .ok_or(StorageGitCoverageCauseV1::Refused("durable birth/fence is absent"))?;
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
                return Err(StorageGitCoverageCauseV1::Refused("original fence or replay changed"));
            }
            owner.outcome = Some(GitCoverageOutcomeFieldsV1 {
                request: coordinates,
                transaction: original.transaction,
                predecessor_prefix: original.predecessor_prefix,
                fence: fence.digest(),
                commit_sequence: birth.fields().commit_sequence,
                native_prefix: actual.prefix,
                record_count: u32::try_from(actual.records)
                    .map_err(|_| StorageGitCoverageCauseV1::Refused("native record count exhausted"))?,
            });
            Ok(())
        })();
        owner.finish(result)?;
        self.compare_git_coverage_v1(output, Some(deadline))?;
        self.git_coverage.as_ref().and_then(|owner| owner.outcome)
            .ok_or(StorageRuntimeError::Recovery)
    }
}

pub(crate) fn observe_native(
    store: &crate::state::StorageTransactionStore,
    catalog: &GitCoverageCatalogV1<'_>,
) -> Result<StorageNativeCutV1, StorageGitCoverageCauseV1> {
    cut_from_loan(store.git_coverage_native_v1(catalog)?)
}

// Each closed owner validates its own semantics before lending this same
// parser's DATA. This helper merely extracts its bounded coordinates and
// rejoins the original writer; it cannot construct a loan or open a journal.
pub(crate) fn cut_from_loan(
    mut original: GitCoverageNativePrefixLoanV1<'_>,
) -> Result<StorageNativeCutV1, StorageGitCoverageCauseV1> {
    let cut = StorageNativeCutV1 {
        prefix: original.prefix_digest(),
        origin: original.provision_origin_digest(),
        records: original.counts().1,
        last: original.last_commit(),
    };
    original.recheck()?;
    Ok(cut)
}
