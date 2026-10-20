//! Retains selected floor comparisons at their actual native call sites.
//!
//! One failed primary and one independently owed negative observation can stay
//! resident. Each complete positive native comparison really disposes its fresh
//! files and traversal backing before this fixed peak can be reused. This is
//! custody DATA under the original J admission, never a new floor or payer.

use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use aos_sandbox_controller_domain::{
    CreateStorageEndpointRevalidationShapeDataV1, Journal,
    ProtectedJournalCurrentnessOriginalsV1,
};
use aos_sandbox_model::ResourceDimension as D;

use super::owner::JournalOwnerV1;
use super::tpm_floor::FloorErrorV1;
use crate::BrokerSessionSecurityError;

pub(crate) type FloorCurrentnessSharedV1 = Arc<FloorCurrentnessArchiveV1>;

pub(super) enum FloorCurrentnessAdmissionV1 {
    StorageInitial(Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>),
    Create(Result<(), aos_sandbox_controller_domain::CreateStorageClientSessionClosedV1>),
    Initial {
        association: Result<(), aos_sandbox_controller_domain::ControllerInitialBrokerSessionClosedV1>,
        initial: Option<Result<(), aos_sandbox_controller_domain::ControllerInitialBrokerSessionClosedV1>>,
        create: Option<Result<(), aos_sandbox_controller_domain::CreateStorageClientSessionClosedV1>>,
    },
}

impl FloorCurrentnessAdmissionV1 {
    fn is_positive(&self) -> bool {
        match self {
            Self::StorageInitial(result) => result.is_ok(),
            Self::Create(result) => result.is_ok(),
            Self::Initial { association, initial, create } => {
                association.is_ok()
                    && matches!(initial, Some(Ok(())))
                    && create.as_ref().is_none_or(|result| result.is_ok())
            }
        }
    }
}


enum NativeComparisonV1 {
    Writer {
        originals: ProtectedJournalCurrentnessOriginalsV1,
        result: Option<Result<(), aos_sandbox_controller_domain::JournalError>>,
    },
    Mode(super::tpm_floor::ModeRevalidationOriginalV1),
    Provision(super::tpm_floor::ProvisionRevalidationOriginalV1),
    Absent(super::tpm_floor::AbsentFloorNamesOriginalV1),
    Completed(CompletedComparisonV1),
}

enum CompletedComparisonV1 {
    Writer(Result<(), aos_sandbox_controller_domain::JournalError>),
    Floor(Result<(), FloorErrorV1>),
}

enum ComparisonOutputV1 {
    Unit,
    Auth(zeroize::Zeroizing<[u8; 32]>),
}

impl NativeComparisonV1 {
    fn new(recipe: &ComparisonRecipeV1<'_>) -> Self {
        match recipe {
            ComparisonRecipeV1::Rooted { .. } | ComparisonRecipeV1::Names => Self::Writer {
                originals: ProtectedJournalCurrentnessOriginalsV1::new(),
                result: None,
            },
            ComparisonRecipeV1::Mode(_) => {
                Self::Mode(super::tpm_floor::ModeRevalidationOriginalV1::new())
            }
            ComparisonRecipeV1::Provision(_) => {
                Self::Provision(super::tpm_floor::ProvisionRevalidationOriginalV1::new())
            }
            ComparisonRecipeV1::Absent(_) => {
                Self::Absent(super::tpm_floor::AbsentFloorNamesOriginalV1::new())
            }
        }
    }

    fn observe(&mut self, journal: Option<&Journal>, recipe: ComparisonRecipeV1<'_>) {
        match (self, recipe) {
            (
                Self::Writer { originals, result },
                ComparisonRecipeV1::Rooted { owner, directory, name },
            ) => {
                let Some(journal) = journal else { std::process::abort() };
                *result = Some(owner.validate_held_retaining(journal, directory, name, originals));
            }
            (Self::Writer { originals, result }, ComparisonRecipeV1::Names) => {
                let Some(journal) = journal else { std::process::abort() };
                *result = Some(journal.validate_held_protected_names_retaining(originals));
            }
            (Self::Mode(original), ComparisonRecipeV1::Mode(pin)) => {
                let _ = original.observe_once(pin, super::tpm_floor::CredentialReadCustodyV1::Retained);
            }
            (Self::Provision(original), ComparisonRecipeV1::Provision(pin)) => {
                let _ = original.observe_once(pin, super::tpm_floor::CredentialReadCustodyV1::Retained);
            }
            (Self::Absent(original), ComparisonRecipeV1::Absent(directory)) => {
                let _ = original.observe_once(directory, super::tpm_floor::CredentialReadCustodyV1::Retained);
            }
            _ => std::process::abort(),
        }
    }

    fn is_complete(&self) -> bool {
        match self {
            Self::Writer { originals, result } => {
                matches!(result, Some(Ok(()))) && originals.is_complete()
            }
            Self::Mode(original) => original.is_complete(),
            Self::Provision(original) => original.is_complete(),
            Self::Absent(original) => original.is_complete(),
            Self::Completed(CompletedComparisonV1::Writer(result)) => result.is_ok(),
            Self::Completed(CompletedComparisonV1::Floor(result)) => result.is_ok(),
        }
    }

    fn take_completed(&mut self) -> Option<(CompletedComparisonV1, ComparisonOutputV1)> {
        if !self.is_complete() {
            return None;
        }
        match self {
            Self::Writer { result, .. } => result.take().map(|result| (
                CompletedComparisonV1::Writer(result), ComparisonOutputV1::Unit,
            )),
            Self::Mode(original) => original.take_completed_result().map(|result| (
                CompletedComparisonV1::Floor(result), ComparisonOutputV1::Unit,
            )),
            Self::Provision(original) => original.take_completed().map(|(result, auth)| (
                CompletedComparisonV1::Floor(result), ComparisonOutputV1::Auth(auth),
            )),
            Self::Absent(original) => original.take_completed_result().map(|result| (
                CompletedComparisonV1::Floor(result), ComparisonOutputV1::Unit,
            )),
            Self::Completed(_) => None,
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Writer { originals, result } => originals.failure().or_else(|| {
                result.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn Error)
            }),
            Self::Mode(original) => original.failure(),
            Self::Provision(original) => original.failure(),
            Self::Absent(original) => original.failure(),
            Self::Completed(CompletedComparisonV1::Writer(result)) => {
                result.as_ref().err().map(|cause| cause as &dyn Error)
            }
            Self::Completed(CompletedComparisonV1::Floor(result)) => {
                result.as_ref().err().map(|cause| cause as &dyn Error)
            }
        }
    }

    #[cfg(test)]
    fn retained_writer_file_count(&self) -> usize {
        match self {
            Self::Writer { originals, .. } => originals.retained_file_count(),
            _ => 0,
        }
    }
}

// A panic cannot unwind and silently dispose the actual in-flight native
// prefix. Result paths either park the whole negative or positively dispose it.
struct InFlightComparisonV1(Option<NativeComparisonV1>);

impl Drop for InFlightComparisonV1 {
    fn drop(&mut self) {
        if self.0.is_some() {
            std::process::abort();
        }
    }
}

// One primary refusal plus the actual independently owed Required pass:
// Mode, Provision, main rooted/name and sidecar rooted/name comparisons.
// Completed comparisons after failure retain compact results in these same
// finite destinations; no later operation or lifetime counter is admitted.
const FLOOR_REVALIDATION_DESTINATIONS_V1: usize = 5;

pub(crate) struct FloorCurrentnessArchiveV1 {
    observations: [OnceLock<NativeComparisonV1>; FLOOR_REVALIDATION_DESTINATIONS_V1],
    completed: OnceLock<CompletedComparisonV1>,
    exhausted: OnceLock<FloorErrorV1>,
    serial: Mutex<()>,
}

impl FloorCurrentnessArchiveV1 {
    pub(super) const fn new() -> Self {
        Self {
            observations: [const { OnceLock::new() }; FLOOR_REVALIDATION_DESTINATIONS_V1],
            completed: OnceLock::new(),
            exhausted: OnceLock::new(),
            serial: Mutex::new(()),
        }
    }

    fn observe(
        &self,
        journal: Option<&Journal>,
        recipe: ComparisonRecipeV1<'_>,
    ) -> Result<ComparisonOutputV1, FloorErrorV1> {
        let _serial = self.serial.lock().map_err(|_| FloorErrorV1::Unavailable)?;
        let Some(index) = self.observations.iter().position(|slot| slot.get().is_none()) else {
            let _ = self.exhausted.set(FloorErrorV1::RetainedJournalCurrentness { observation: FLOOR_REVALIDATION_DESTINATIONS_V1 });
            return Err(FloorErrorV1::RetainedJournalCurrentness { observation: FLOOR_REVALIDATION_DESTINATIONS_V1 });
        };
        if self.exhausted.get().is_some() {
            return Err(FloorErrorV1::RetainedJournalCurrentness { observation: FLOOR_REVALIDATION_DESTINATIONS_V1 });
        }
        let mut active = InFlightComparisonV1(Some(NativeComparisonV1::new(&recipe)));
        let observation = match active.0.as_mut() {
            Some(observation) => observation,
            None => std::process::abort(),
        };
        observation.observe(journal, recipe);
        let positive = observation.is_complete();
        let mut observation = match active.0.take() {
            Some(observation) => observation,
            None => std::process::abort(),
        };
        if !positive {
            // No fallible/native action separates the original move from its
            // never-overwritten resident slot. A failed unexpected setter keeps
            // that same original on the abort guard instead of dropping it.
            if let Err(original) = self.observations[index].set(observation) {
                active.0 = Some(original);
                std::process::abort();
            }
            return Err(FloorErrorV1::RetainedJournalCurrentness { observation: index });
        }

        let Some((completed, output)) = observation.take_completed() else {
            active.0 = Some(observation);
            std::process::abort();
        };

        // Completion is the actual final native/byte comparison. No subsequent
        // semantic work uses these fresh files or traversal buffers. Dispose
        // them now, retaining the actual compact result under the same owner.
        drop(observation);
        if self.observations.iter().any(|slot| slot.get().is_some()) {
            let compact = NativeComparisonV1::Completed(completed);
            if let Err(original) = self.observations[index].set(compact) {
                active.0 = Some(original);
                std::process::abort();
            }
        } else {
            let _ = self.completed.set(completed);
        }
        Ok(output)
    }

    fn healthy(&self) -> bool {
        self.serial.try_lock().is_ok() && self.exhausted.get().is_none()
            && self.observations.iter().all(|slot| slot.get().is_none())
    }
}

enum ComparisonRecipeV1<'a> {
    Rooted {
        owner: JournalOwnerV1,
        directory: &'a Path,
        name: &'a str,
    },
    Names,
    Mode(&'a super::tpm_floor::ModePinV1),
    Provision(&'a super::tpm_floor::ProvisionPinV1),
    Absent(&'a Path),
}

pub(super) fn failure_for<'a>(
    archive: &'a FloorCurrentnessSharedV1,
    error: &BrokerSessionSecurityError,
) -> Option<&'a (dyn Error + 'static)> {
    let BrokerSessionSecurityError::FloorRevalidation { observation } = error else {
        return None;
    };
    if *observation == FLOOR_REVALIDATION_DESTINATIONS_V1 {
        return archive.exhausted.get().map(|cause| cause as &dyn Error);
    }
    archive.observations.get(*observation)?.get()?.failure()
}

pub(super) fn validate_rooted(
    archive: Option<&FloorCurrentnessSharedV1>,
    owner: JournalOwnerV1,
    journal: &Journal,
    directory: &Path,
    name: &str,
) -> Result<(), FloorErrorV1> {
    match archive {
        Some(archive) => archive.observe(
            Some(journal), ComparisonRecipeV1::Rooted { owner, directory, name },
        ).map(|_| ()),
        None => owner.validate_held(journal, directory, name)
            .map_err(|_| FloorErrorV1::Unavailable),
    }
}

pub(super) fn validate_names(
    archive: Option<&FloorCurrentnessSharedV1>,
    journal: &Journal,
) -> Result<(), FloorErrorV1> {
    match archive {
        Some(archive) => archive.observe(Some(journal), ComparisonRecipeV1::Names).map(|_| ()),
        None => journal.validate_held_protected_names().map_err(|_| FloorErrorV1::Unavailable),
    }
}

pub(super) fn validate_mode(
    archive: &FloorCurrentnessSharedV1,
    mode: &super::tpm_floor::ModePinV1,
) -> Result<(), FloorErrorV1> {
    archive.observe(None, ComparisonRecipeV1::Mode(mode)).map(|_| ())
}

pub(super) fn validate_provision(
    archive: &FloorCurrentnessSharedV1,
    provision: &super::tpm_floor::ProvisionPinV1,
) -> Result<zeroize::Zeroizing<[u8; 32]>, FloorErrorV1> {
    match archive.observe(None, ComparisonRecipeV1::Provision(provision))? {
        ComparisonOutputV1::Auth(auth) => Ok(auth),
        ComparisonOutputV1::Unit => std::process::abort(),
    }
}

pub(super) fn validate_absent(
    archive: Option<&FloorCurrentnessSharedV1>,
    directory: &Path,
) -> Result<(), FloorErrorV1> {
    match archive {
        Some(archive) => archive.observe(None, ComparisonRecipeV1::Absent(directory)).map(|_| ()),
        None => super::tpm_floor::AbsentFloorNamesOriginalV1::new().observe_once(
            directory, super::tpm_floor::CredentialReadCustodyV1::Ordinary,
        ),
    }
}

pub(super) fn security_error(cause: FloorErrorV1) -> BrokerSessionSecurityError {
    match cause {
        FloorErrorV1::RetainedControllerPhysical => BrokerSessionSecurityError::ControllerPhysicalFloor,
        FloorErrorV1::RetainedJournalCurrentness { observation } => {
            BrokerSessionSecurityError::FloorRevalidation { observation }
        }
        _ => BrokerSessionSecurityError::Currentness,
    }
}

pub(super) fn floor_error(cause: BrokerSessionSecurityError) -> FloorErrorV1 {
    match cause {
        BrokerSessionSecurityError::ControllerPhysicalFloor => FloorErrorV1::RetainedControllerPhysical,
        BrokerSessionSecurityError::FloorRevalidation { observation } => {
            FloorErrorV1::RetainedJournalCurrentness { observation }
        }
        _ => FloorErrorV1::Unavailable,
    }
}

/// Describes the actual primary and independently owed Required comparisons.
///
/// Both fixed Storage directories are covered by the deeper Controller path;
/// session-floor.journal is the longer of the actual main/sidecar basenames.
/// The native supplier covers writer paths, backing and diagnostic work. The
/// additional fixed mode/provision/absence recipe covers their actual bounded
/// bytes and dominant canonicalization buffers; no decoded floor grants it.
pub(crate) fn floor_revalidation_footprint_v1()
    -> Option<CreateStorageEndpointRevalidationShapeDataV1>
{
    let fixed = super::fixed_endpoint(super::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient);
    let sample = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
        Path::new(fixed.journal_root), super::tpm_floor::FLOOR_SIDECAR_NAME,
    ).ok()?;
    let extra_memory = super::tpm_floor::auxiliary_currentness_work_bytes_v1()?;
    let memory = usize::try_from(sample.get(D::MemoryBytes)).ok()?
        .checked_add(extra_memory)?.checked_mul(FLOOR_REVALIDATION_DESTINATIONS_V1)?;
    // This is the closed Controller floor caller's whole failed program,
    // not a generic five-writer storage bound. A healthy primary stops at its
    // first refusal; the sole prearmed Required continuation independently
    // enters Mode, Provision, main and sidecar, consumed once on that owner.
    // Physical continuation has its own actual owner/supplier, not a writer
    // probe in this archive. Legacy's failed cold gate admits no extra pass.
    let writer_files = usize::try_from(sample.get(D::OpenFiles)).ok()?;
    let mode_files = usize::try_from(
        super::tpm_floor::mode_revalidation_receiving_demand_v1()?
            .get(D::OpenFiles),
    ).ok()?;
    // ProvisionRevalidationOriginal owns its two fixed public/auth readers.
    let provision_files = 2usize;
    let primary_files = writer_files.max(mode_files).max(provision_files);
    let owed_files = mode_files.checked_add(provision_files)?
        .checked_add(writer_files.checked_mul(2)?)?;
    let files = primary_files.checked_add(owed_files)?;
    Some(CreateStorageEndpointRevalidationShapeDataV1 {
        inline_bytes: std::mem::size_of::<FloorCurrentnessArchiveV1>(),
        heap_bytes: std::mem::size_of::<FloorCurrentnessArchiveV1>()
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(std::mem::align_of::<FloorCurrentnessArchiveV1>())?
            .checked_add(memory)?,
        file_descriptors: files,
        // Comparison carriers and raw Result fields consume bytes, not
        // namespace entries. Actual Journal namespace rows are paid by their
        // original main/sidecar prefix owners; these probes create no rows.
        metadata_cells: 0,
    })
}

impl super::ProtectedBrokerSessionOwnerV1 {
    /// Arms only this same fixed Client owner after its genuine J shape payment.
    pub(crate) fn arm_original_storage_floor_revalidation_once(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::OriginalCreateStorageClientSessionV1<'_, '_, '_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let footprint = floor_revalidation_footprint_v1()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if receiving.requires_existing_currentness_archives_v1() {
            self.require_fixed_storage_floor_v1()?;
            if !self.healthy_original_storage_floor_revalidation_v1() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            return receiving.require_fixed_floor_preparation_v1(footprint)
                .map_err(|_| BrokerSessionSecurityError::Currentness);
        }
        if self.journal.floor_currentness_admission.is_some() {
            // Boot acquired this same owner under original B funding. A later
            // genuine J can check its own already-admitted shape, but cannot
            // replace, clear or rearm the archive or its negative slots.
            self.require_fixed_storage_floor_v1()?;
            if !self.healthy_original_storage_floor_revalidation_v1() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let Some(FloorCurrentnessAdmissionV1::Initial { create, .. }) =
                self.journal.floor_currentness_admission.as_mut()
            else {
                return Err(BrokerSessionSecurityError::Currentness);
            };
            if create.is_some() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            *create = Some(receiving.require_fixed_floor_preparation_v1(footprint));
            return match create {
                Some(Ok(())) => Ok(()),
                _ => Err(BrokerSessionSecurityError::Currentness),
            };
        }
        self.require_unarmed_storage_floor_v1()?;
        let owner = &mut self.journal;
        owner.floor_currentness_admission = Some(FloorCurrentnessAdmissionV1::Create(
            receiving.require_fixed_floor_preparation_v1(footprint),
        ));
        if !owner.floor_currentness_admission.as_ref().is_some_and(|result| result.is_positive()) {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        self.install_paid_floor_archive_v1()
    }

    /// Arms the same already-held floor through its genuine initial B loan.
    pub(crate) fn arm_initial_storage_floor_revalidation_once(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let mut operation = super::BrokerFloorOperationV1::begin(&mut self.journal);
        let result = match operation.floor.as_mut() {
            Some(floor) => operation.owner.arm_initial_storage_floor_revalidation_once_v1(
                floor, receiving,
            ),
            None => Err(BrokerSessionSecurityError::Currentness),
        };
        operation.finish(result)
    }

    fn require_unarmed_storage_floor_v1(&self) -> Result<(), BrokerSessionSecurityError> {
        self.journal.require_unarmed_storage_floor_v1()
    }

    fn require_fixed_storage_floor_v1(&self) -> Result<(), BrokerSessionSecurityError> {
        self.journal.require_fixed_storage_floor_v1()
    }

    fn install_paid_floor_archive_v1(&mut self) -> Result<(), BrokerSessionSecurityError> {
        let archive = self.journal.prepare_paid_floor_archive_v1();
        self.journal.floor_currentness_binding = Some(
            self.journal.floor.install_currentness_archive_v1(archive),
        );
        self.journal.floor_archive_binding_result_v1()
    }

    /// Checks the same already-funded archive without IO, rearming or a grant.
    pub(crate) fn healthy_original_storage_floor_revalidation_v1(&self) -> bool {
        if !self.journal.floor_currentness_admission.as_ref().is_some_and(|result| result.is_positive())
            || !matches!(self.journal.floor_currentness_binding, Some(Ok(())))
        {
            return false;
        }
        self.journal.floor_currentness.as_ref().is_some_and(|archive| archive.healthy())
    }

    /// Resolves only the matching actual returned floor-observation marker.
    pub(crate) fn retained_storage_floor_revalidation_failure_for(
        &self,
        error: &BrokerSessionSecurityError,
    ) -> Option<&(dyn Error + 'static)> {
        if matches!(error, BrokerSessionSecurityError::ControllerPhysicalFloor) {
            return self.journal.floor.controller_physical_failure_v1();
        }
        failure_for(self.journal.floor_currentness.as_ref()?, error)
    }
}

impl super::ProtectedBrokerSessionJournalV1 {
    pub(super) fn arm_storage_receiving_floor_revalidation_v2(
        &mut self, floor: &mut super::tpm_floor::runtime::BrokerFloorV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let fixed = super::fixed_endpoint(super::ProtectedBrokerSessionFixedEndpointV1::StorageBroker);
        if self.floor_currentness_admission.is_some() || self.floor_currentness.is_some()
            || self.floor_currentness_binding.is_some() || self.owner != JournalOwnerV1::RootBroker
            || self.directory != Path::new(fixed.journal_root) || self.name != super::PROTECTED_SESSION_JOURNAL
            || self.endpoint.role() != aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Broker
            || self.endpoint.protected_protocol_and_node().0 != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
        { return Err(BrokerSessionSecurityError::Currentness); }
        let main = self.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let shape = floor_revalidation_footprint_v1().ok_or(BrokerSessionSecurityError::Currentness)?;
        let memory = shape.inline_bytes.checked_add(shape.heap_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(BrokerSessionSecurityError::Currentness)?;
        let files = u64::try_from(shape.file_descriptors).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        // This archive revisits the exact main/sidecar and fixed mode/provision
        // names already funded by their initial native suppliers. It retains
        // every independent byte/FD reservoir, never another path namespace or
        // a metadata fee for its control/result fields.
        let demand = aos_sandbox_model::ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::OpenFiles, files);
        self.floor_currentness_admission = Some(FloorCurrentnessAdmissionV1::StorageInitial(
            receiving.reserve_floor_revalidation_once_v2(main, demand),
        ));
        if !self.floor_currentness_admission.as_ref().is_some_and(|admission| admission.is_positive()) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let archive = self.prepare_paid_floor_archive_v1();
        self.floor_currentness_binding = Some(floor.install_initial_broker_currentness_archive_v2(archive));
        self.floor_archive_binding_result_v1()
    }

    /// Arms the same archive through the genuine initial Controller B loan.
    ///
    /// This uses the already-paid actual archive shape before allocation. It
    /// does not reuse warm Create funding or open a replacement floor owner.
    pub(super) fn arm_initial_storage_floor_revalidation_once_v1(
        &mut self,
        floor: &mut super::tpm_floor::runtime::BrokerFloorV1,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_unarmed_storage_floor_v1()?;
        let footprint = floor_revalidation_footprint_v1()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let shape = aos_sandbox_controller_domain::ControllerInitialBrokerSessionCaptureShapeV1 {
            inline_bytes: footprint.inline_bytes,
            heap_bytes: footprint.heap_bytes,
            open_files: footprint.file_descriptors,
            metadata_cells: footprint.metadata_cells,
        };
        // The passive width alone cannot bind this floor to the payer. Check
        // the actual role and the exact Native take Arc before admitting its
        // archive shape or allocating any observation owner.
        let association = (|| {
            if receiving.role_v1() != aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1::Storage {
                return Err(aos_sandbox_controller_domain::ControllerInitialBrokerSessionClosedV1);
            }
            let journal = self.journal.as_ref()
                .ok_or(aos_sandbox_controller_domain::ControllerInitialBrokerSessionClosedV1)?;
            receiving.require_opened_journal_v1(journal)
        })();
        self.floor_currentness_admission = Some(FloorCurrentnessAdmissionV1::Initial {
            association,
            initial: None,
            create: None,
        });
        let Some(FloorCurrentnessAdmissionV1::Initial { association, initial, .. }) =
            self.floor_currentness_admission.as_mut()
        else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        if association.is_err() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        *initial = Some(receiving.require_floor_revalidation_shape_v1(shape));
        if !self.floor_currentness_admission.as_ref().is_some_and(|result| result.is_positive()) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let archive = self.prepare_paid_floor_archive_v1();
        self.floor_currentness_binding = Some(floor.install_initial_broker_currentness_archive_v2(archive));
        self.floor_archive_binding_result_v1()
    }

    fn require_unarmed_storage_floor_v1(&self) -> Result<(), BrokerSessionSecurityError> {
        if self.floor_currentness_admission.is_some()
            || self.floor_currentness.is_some()
            || self.floor_currentness_binding.is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.require_fixed_storage_floor_v1()
    }

    fn require_fixed_storage_floor_v1(&self) -> Result<(), BrokerSessionSecurityError> {
        let owner = self;
        let fixed = super::fixed_endpoint(
            super::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
        );
        if !matches!(owner.owner, JournalOwnerV1::ServiceClient(_))
            || owner.directory != Path::new(fixed.journal_root)
            || owner.name != super::PROTECTED_SESSION_JOURNAL
            || owner.endpoint.role()
                != aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Client
            || owner.endpoint.protected_protocol_and_node().0
                != aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
            || owner.journal.is_none()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn prepare_paid_floor_archive_v1(&mut self) -> FloorCurrentnessSharedV1 {
        // Actual shape admission precedes allocation, and the same archive
        // stays on this owner before it is lent to the moved floor.
        let archive = Arc::new(FloorCurrentnessArchiveV1::new());
        self.floor_currentness = Some(archive.clone());
        archive
    }

    fn floor_archive_binding_result_v1(&self) -> Result<(), BrokerSessionSecurityError> {
        match self.floor_currentness_binding {
            Some(Ok(())) => Ok(()),
            Some(Err(cause)) => Err(security_error(cause)),
            None => Err(BrokerSessionSecurityError::Currentness),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn identity(error: &(dyn Error + 'static)) -> (
        Option<*const rustix::io::Errno>, Option<*const aos_sandbox_controller_domain::JournalError>,
    ) {
        let native = error.downcast_ref::<rustix::io::Errno>()
            .map(|cause| cause as *const rustix::io::Errno);
        let journal = error.downcast_ref::<aos_sandbox_controller_domain::JournalError>()
            .map(|cause| cause as *const aos_sandbox_controller_domain::JournalError);
        assert!(native.is_some() || journal.is_some());
        (native, journal)
    }

    #[test]
    fn completed_native_names_drop_actual_probes_before_next_comparison() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(
            directory.path(), "session.journal", aos_sandbox_controller_domain::JournalLimits::default(), uid,
        ).unwrap();
        let archive = Arc::new(FloorCurrentnessArchiveV1::new());

        for _ in 0..4 {
            validate_names(Some(&archive), &journal).unwrap();
            assert!(archive.healthy());
            assert!(matches!(archive.completed.get(), Some(CompletedComparisonV1::Writer(Ok(())))));
            assert!(archive.observations.iter().all(|slot| slot.get().is_none()));
        }

        std::fs::rename(directory.path().join("session.journal"), directory.path().join("held")).unwrap();
        std::fs::write(directory.path().join("session.journal"), b"").unwrap();
        assert!(validate_names(Some(&archive), &journal).is_err());
        assert!(!archive.healthy());
        assert!(archive.observations[0].get().unwrap().retained_writer_file_count() > 0);
    }

    #[test]
    fn failed_primary_and_owed_post_keep_distinct_stable_native_causes() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(
            directory.path(), "session.journal", aos_sandbox_controller_domain::JournalLimits::default(), uid,
        ).unwrap();
        let archive = Arc::new(FloorCurrentnessArchiveV1::new());
        std::fs::rename(directory.path().join("session.journal"), directory.path().join("held")).unwrap();
        std::fs::write(directory.path().join("session.journal"), b"").unwrap();

        let primary = security_error(validate_names(Some(&archive), &journal).unwrap_err());
        let first = identity(failure_for(&archive, &primary).unwrap());
        let owed = security_error(validate_names(Some(&archive), &journal).unwrap_err());
        let second = identity(failure_for(&archive, &owed).unwrap());

        assert_eq!(primary, BrokerSessionSecurityError::FloorRevalidation { observation: 0 });
        assert_eq!(owed, BrokerSessionSecurityError::FloorRevalidation { observation: 1 });
        assert_ne!(first, second);
        assert_eq!(identity(failure_for(&archive, &primary).unwrap()), first);
        assert!(failure_for(&archive, &BrokerSessionSecurityError::Currentness).is_none());
        for observation in 2..FLOOR_REVALIDATION_DESTINATIONS_V1 {
            assert_eq!(validate_names(Some(&archive), &journal).unwrap_err(),
                FloorErrorV1::RetainedJournalCurrentness { observation });
            assert_eq!(identity(failure_for(&archive, &primary).unwrap()), first);
        }
        let refused = validate_names(Some(&archive), &journal).unwrap_err();
        assert_eq!(refused, FloorErrorV1::RetainedJournalCurrentness { observation: FLOOR_REVALIDATION_DESTINATIONS_V1 });
        assert_eq!(identity(failure_for(&archive, &primary).unwrap()), first);
        assert_eq!(identity(failure_for(&archive, &owed).unwrap()), second);
    }

    #[test]
    fn absence_samples_retire_only_after_all_three_lookups_then_keep_native_failure() {
        let directory = tempfile::tempdir().unwrap();
        let archive = Arc::new(FloorCurrentnessArchiveV1::new());

        for _ in 0..3 {
            validate_absent(Some(&archive), directory.path()).unwrap();
            assert!(archive.healthy());
            assert!(archive.observations.iter().all(|slot| slot.get().is_none()));
        }

        let not_directory = directory.path().join("regular-file");
        std::fs::write(&not_directory, b"").unwrap();
        let primary = security_error(validate_absent(Some(&archive), &not_directory).unwrap_err());
        let native = failure_for(&archive, &primary).unwrap()
            .downcast_ref::<std::io::Error>().unwrap();
        assert_ne!(native.kind(), std::io::ErrorKind::NotFound);
        let identity = native as *const std::io::Error;
        assert!(!archive.healthy());

        let owed = security_error(validate_absent(Some(&archive), &not_directory).unwrap_err());
        assert_eq!(owed, BrokerSessionSecurityError::FloorRevalidation { observation: 1 });
        assert!(std::ptr::eq(identity, failure_for(&archive, &primary).unwrap()
            .downcast_ref::<std::io::Error>().unwrap() as *const std::io::Error));
        for _ in 2..FLOOR_REVALIDATION_DESTINATIONS_V1 {
            validate_absent(Some(&archive), directory.path()).unwrap();
        }
        assert_eq!(validate_absent(Some(&archive), directory.path()).unwrap_err(),
            FloorErrorV1::RetainedJournalCurrentness { observation: FLOOR_REVALIDATION_DESTINATIONS_V1 });
    }
}
