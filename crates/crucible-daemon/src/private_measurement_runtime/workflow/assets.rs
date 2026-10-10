//! Retains typed workflow artifacts, actual pinned files and compact models.
//!
//! All inputs come from the same authenticated workflow and original decoder.
//! Successful files and models are published in this owner before postcuts.
//! The prepared service imports through its existing repository; this module
//! copies authenticated lifecycle paths under the same account and retains
//! their file pins. Complete Source/prebirth purposes, native execution and
//! listener admission remain later stages.

use crucible::owned_decode::{
    ClosedJsonError, DecodeBudget, DecodeCustody, from_json_slice_closed,
};
use crucible::{ScenarioDefForm, Schedule};

use crate::campaign_bootstrap::OriginalPreparedCampaignServiceOwner;

mod creation;
pub(super) mod executor;
mod failure;
mod files;
mod lifecycle;
mod projection;

#[cfg(test)]
mod tests;

pub use failure::OriginalWorkflowArtifactsError;

use failure::{ArtifactFailurePurpose, ArtifactRefusal, ArtifactWork};
use files::PinnedInput;
use projection::{Artifact, Projection, ProjectionValidation};

const COMPACT_ROOT: &str = "/etc/crucible/measurement-inputs";

pub(super) struct OriginalWorkflowArtifactsOwner {
    executor_config: Option<Box<crate::PackagedQemuExecutorConfig>>,
    lifecycle: Option<std::sync::Arc<crucible_api::ProductionVmLifecycleConfig>>,
    projection: Option<Projection>,
    files: Vec<PinnedInput>,
    models: Vec<LoadedAttempt>,
    budget: DecodeBudget,
    custody: DecodeCustody,
    closed: bool,
}

struct LoadedAttempt {
    scenario: Option<ScenarioDefForm>,
    schedule: Option<Schedule>,
    imported: Option<crucible_campaign::ConfigurationArtifactId>,
    request: Option<crucible_campaign::CreateCampaignRequest>,
    generators: Vec<creation::LoadedGenerator>,
    response: Option<crucible_campaign::CreateCampaignResponse>,
}

#[derive(Debug, thiserror::Error)]
enum ArtifactCause {
    #[error("original catalog provider refused: {0}")]
    Catalog(#[from] crucible_cas::content_store::StoreError),
    #[error("executor configuration refused: {0}")]
    Executor(#[from] crate::PackagedQemuExecutorConfigError),
    #[error("executor endpoint refused: {0}")]
    Endpoint(#[from] crate::LocalComponentEndpointError),
    #[error("executor server refused: {0}")]
    Server(#[from] crate::ExecutorLoopbackServerConfigError),
    #[error("executor exchange timeout refused: {0}")]
    Timeout(#[from] crate::LoopbackExecutorProtocolError),
    #[error("executor capacity refused: {0}")]
    Capacity(#[from] crate::ExecutorCapacityError),
    #[error("executor operational capacity refused: {0}")]
    OperationalCapacity(#[from] crate::HostOperationalCapacityError),
    #[error("executor host configuration refused: {0}")]
    Host(#[from] crucible_qemu::AdmittedHostConfigurationError),
    #[error("original artifact interval refused: {0}")]
    OriginalBoundary(#[from] crucible_linux_resource::host_supervision::HostSupervisionError),
    #[error("original artifact allocation refused: {0}")]
    Admission(#[from] crucible::owned_decode::DecodeAdmissionError),
    #[error("artifact file operation refused: {0}")]
    Kernel(#[from] std::io::Error),
    #[error("admitted artifact buffer allocation refused: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("artifact JSON refused: {0}")]
    Json(#[from] ClosedJsonError),
    #[error("compact execution model refused: {0}")]
    Model(#[from] crucible::EngineError),
    #[error("canonical campaign input refused: {0}")]
    Campaign(#[from] crucible_campaign::CampaignCodecError),
    #[error("prepared campaign import refused: {0}")]
    Import(#[from] crate::campaign_bootstrap::OriginalPreparedServiceError),
    #[error("authenticated lifecycle construction refused: {0}")]
    Lifecycle(#[from] crucible_api::vm_lifecycle::ProductionVmGuestAssetAdmissionError),
    #[error("retained campaign state refused: {0}")]
    State(#[from] crate::campaign_bootstrap::OriginalCampaignStateError),
    #[error("a runtime still retains the authenticated lifecycle configuration")]
    LifecycleAliases,
    #[error("authenticated artifact identity differs from the actual input")]
    Identity,
}

impl OriginalWorkflowArtifactsOwner {
    pub(super) fn load_and_import(
        bytes: &[u8],
        decoder: &crucible_qemu::OriginalActorDecodeOwner,
        service: &OriginalPreparedCampaignServiceOwner,
    ) -> Result<Self, OriginalWorkflowArtifactsError> {
        service
            .verify_artifact_input(decoder, bytes)
            .map_err(OriginalWorkflowArtifactsError::account)?;
        let budget = decoder
            .budget()
            .map_err(OriginalWorkflowArtifactsError::account)?;
        let original = || service.verify_original();
        let mut failure = ArtifactFailurePurpose::prepare(budget, &original)?;
        let result = {
            let check = failure.work(&original);
            (|| {
                let mut owner = Self {
                    executor_config: None,
                    lifecycle: None,
                    projection: None,
                    files: Vec::new(),
                    models: Vec::new(),
                    budget: budget.clone(),
                    custody: budget.custody(),
                    closed: false,
                };
                let work = (|| {
                    check.verify_original()?;
                    budget.verify_live()?;
                    let _scope = budget.enter();
                    // Typed visitor/output admission and pinned JSON parser scratch
                    // precede decoding. No uncharged generic JSON value is built.
                    owner.projection = Some(from_json_slice_closed(bytes, budget)?);
                    budget.check()?;
                    Ok(())
                })();
                checked(&check, work)?;
                let count = checked(
                    &check,
                    owner
                        .projection
                        .as_ref()
                        .ok_or(ArtifactCause::Identity)
                        .and_then(Projection::validate),
                )?;
                let artifact_count = 4 + usize::from(
                    owner
                        .projection
                        .as_ref()
                        .is_some_and(|projection| projection.guest_assets.initrd.is_some()),
                );
                // Both actual arrays are admitted before capacity allocation. Decoded
                // DTO arrays remain separately charged while these outputs overlap.
                let input_count = owner
                    .projection
                    .as_ref()
                    .ok_or_else(|| check.error(ArtifactCause::Identity))?
                    .rows
                    .iter()
                    .flat_map(|row| &row.attempts)
                    .try_fold(artifact_count, |total, attempt| {
                        total
                            .checked_add(3)?
                            .checked_add(attempt.campaign_creation.generators.len())
                    })
                    .ok_or_else(|| check.error(ArtifactCause::Identity))?;
                let reserve = (|| {
                    budget.charge_array::<PinnedInput>(input_count)?;
                    owner.files.try_reserve_exact(input_count)?;
                    budget.charge_array::<LoadedAttempt>(count)?;
                    owner.models.try_reserve_exact(count)?;
                    Ok(())
                })();
                checked(&check, reserve)?;
                let projection = owner
                    .projection
                    .as_ref()
                    .ok_or_else(|| check.error(ArtifactCause::Identity))?;
                for artifact in [
                    &projection.executable,
                    &projection.plugin,
                    &projection.guest_assets.kernel,
                ] {
                    pin_artifact(&mut owner.files, artifact, budget, &check)?;
                }
                let root_prefix = pin_artifact(
                    &mut owner.files,
                    &projection.guest_assets.root_image,
                    budget,
                    &check,
                )?;
                if matches!(
                    projection.guest_assets.root_image_format,
                    projection::RootImageFormat::Qcow2
                ) && root_prefix != *b"QFI\xfb"
                {
                    return checked(&check, Err(ArtifactCause::Identity));
                }
                if let Some(initrd) = &projection.guest_assets.initrd {
                    pin_artifact(&mut owner.files, initrd, budget, &check)?;
                }
                for row in &projection.rows {
                    for attempt in &row.attempts {
                        let scenario_index = pin_compact(
                            &mut owner.files,
                            &attempt.scenario_file,
                            &attempt.scenario_blake3,
                            budget,
                            &check,
                        )?;
                        let schedule_index = pin_compact(
                            &mut owner.files,
                            &attempt.schedule_file,
                            &attempt.schedule_blake3,
                            budget,
                            &check,
                        )?;
                        owner.models.push(LoadedAttempt {
                            scenario: None,
                            schedule: None,
                            imported: None,
                            request: None,
                            generators: Vec::new(),
                            response: None,
                        });
                        let model = owner
                            .models
                            .last_mut()
                            .ok_or_else(|| check.error(ArtifactCause::Identity))?;
                        let work = (|| {
                            budget.verify_live()?;
                            let _scope = budget.enter();
                            let scenario_bytes = owner.files[scenario_index]
                                .bytes
                                .as_deref()
                                .ok_or(ArtifactCause::Identity)?;
                            // Existing compact visitors admit their actual typed
                            // collections before reserve; canonical grammar is unchanged.
                            model.scenario =
                                Some(ScenarioDefForm::from_compact_binary(scenario_bytes)?);
                            let scenario =
                                model.scenario.as_ref().ok_or(ArtifactCause::Identity)?;
                            if crucible_campaign::ScenarioDefId::from_hash(
                                crucible_campaign::CampaignHash::from_bytes(scenario.id().bytes),
                            ) != attempt.scenario_id
                            {
                                return Err(ArtifactCause::Identity);
                            }
                            validate_world(scenario, &projection.guest_assets)?;
                            let schedule_bytes = owner.files[schedule_index]
                                .bytes
                                .as_deref()
                                .ok_or(ArtifactCause::Identity)?;
                            model.schedule = Some(Schedule::from_compact_binary(schedule_bytes)?);
                            // Fixed authored genesis schedules contain no decisions.
                            if !model
                                .schedule
                                .as_ref()
                                .ok_or(ArtifactCause::Identity)?
                                .decisions()
                                .is_empty()
                            {
                                return Err(ArtifactCause::Identity);
                            }
                            budget.check()?;
                            Ok(())
                        })();
                        checked(&check, work)?;
                        let imported = service.import_configuration(
                            model
                                .scenario
                                .as_ref()
                                .ok_or_else(|| check.error(ArtifactCause::Identity))?,
                            model
                                .schedule
                                .as_ref()
                                .ok_or_else(|| check.error(ArtifactCause::Identity))?,
                        );
                        // Store a returned publication before this caller's postcut.
                        // An inner refusal can make the copy ID unavailable; the same
                        // service still retains any actual repository publication.
                        let work = imported
                            .inspect(|&imported| {
                                model.imported = Some(imported);
                            })
                            .map_err(Into::into);
                        let imported = checked(&check, work)?;
                        if imported != attempt.configuration_artifact_id {
                            return checked(&check, Err(ArtifactCause::Identity));
                        }
                        creation::load_and_create(
                            model,
                            &mut owner.files,
                            attempt,
                            budget,
                            service,
                            &check,
                        )?;
                    }
                }
                checked(&check, budget.verify_live().map_err(Into::into))?;
                Ok(owner)
            })()
        };
        failure.finish(result)
    }

    pub(super) fn try_close(
        &mut self,
        service: &OriginalPreparedCampaignServiceOwner,
    ) -> Result<(), OriginalWorkflowArtifactsError> {
        if self.closed {
            return Ok(());
        }
        let original = || service.verify_original();
        let mut failure = ArtifactFailurePurpose::prepare(&self.budget, &original)?;
        let result = {
            let check = failure.work(&original);
            (|| {
                checked(&check, self.budget.check().map_err(Into::into))?;
                checked(&check, self.budget.verify_live().map_err(Into::into))?;
                drop(self.executor_config.take());
                lifecycle::close_configuration(self, &check)?;
                // Models and input vectors close before any descriptor or buffer loan.
                self.models.clear();
                for file in &mut self.files {
                    file.close();
                }
                self.files.clear();
                drop(self.projection.take());
                checked(&check, self.budget.verify_live().map_err(Into::into))?;
                self.closed = true;
                Ok(())
            })()
        };
        failure.finish(result)
    }
}

impl Drop for OriginalWorkflowArtifactsOwner {
    fn drop(&mut self) {
        if !self.closed {
            // An error/unwind retains actual successful file/model owners and
            // the same external original account, without a cleanup worker.
            std::mem::forget(self.executor_config.take());
            std::mem::forget(self.lifecycle.take());
            std::mem::forget(std::mem::take(&mut self.models));
            std::mem::forget(std::mem::take(&mut self.files));
            std::mem::forget(self.projection.take());
            std::mem::forget(self.budget.clone());
            std::mem::forget(self.custody.clone());
        }
    }
}

fn pin_artifact(
    files: &mut Vec<PinnedInput>,
    artifact: &Artifact,
    budget: &DecodeBudget,
    check: &ArtifactWork<'_, '_>,
) -> Result<[u8; 4], ArtifactRefusal> {
    files.push(checked(check, PinnedInput::reserved(budget))?);
    let pin = files
        .last_mut()
        .ok_or_else(|| check.error(ArtifactCause::Identity))?;
    let metadata = pin.open(std::path::Path::new(&artifact.path), check)?;
    if metadata.len() != artifact.bytes {
        return checked(check, Err(ArtifactCause::Identity));
    }
    pin.authenticate_stream(artifact.bytes, &artifact.blake3, check)
}

fn pin_compact(
    files: &mut Vec<PinnedInput>,
    name: &str,
    digest: &str,
    budget: &DecodeBudget,
    check: &ArtifactWork<'_, '_>,
) -> Result<usize, ArtifactRefusal> {
    let path_bytes = COMPACT_ROOT
        .len()
        .checked_add(1)
        .and_then(|size| size.checked_add(name.len()))
        .ok_or_else(|| check.error(ArtifactCause::Identity))?;
    let path_credit = checked(
        check,
        budget
            .reserve_scratch_bytes(path_bytes as u64)
            .map_err(Into::into),
    )?;
    let mut path = String::new();
    checked(
        check,
        path.try_reserve_exact(path_bytes).map_err(Into::into),
    )?;
    path.push_str(COMPACT_ROOT);
    path.push('/');
    path.push_str(name);
    let index = files.len();
    files.push(checked(check, PinnedInput::reserved(budget))?);
    let pin = files
        .last_mut()
        .ok_or_else(|| check.error(ArtifactCause::Identity))?;
    let metadata = pin.open(std::path::Path::new(&path), check)?;
    pin.read_compact(metadata.len(), digest, budget, check)?;
    drop(path);
    drop(path_credit);
    Ok(index)
}

fn validate_world(
    scenario: &ScenarioDefForm,
    assets: &projection::GuestAssets,
) -> Result<(), ArtifactCause> {
    let mut nodes = scenario.world().vm_nodes().iter();
    let node = nodes.next().ok_or(ArtifactCause::Identity)?;
    let reference =
        |artifact: &Artifact| -> Result<crucible::ContentAddressedBlobRef, ArtifactCause> {
            let hash =
                blake3::Hash::from_hex(&artifact.blake3).map_err(|_| ArtifactCause::Identity)?;
            Ok(crucible::ContentAddressedBlobRef::from_hash(
                crucible::ContentHash {
                    bytes: *hash.as_bytes(),
                },
            ))
        };
    if nodes.next().is_some()
        || node.arch != crucible::VmArchitecture::X86_64
        || node.memory_mib != 512
        || node.smp_vcpus != 1
        || node.cmdline != assets.kernel_cmdline
        || node.kernel != Some(reference(&assets.kernel)?)
        || node.root_image != Some(reference(&assets.root_image)?)
        || node.initrd != assets.initrd.as_ref().map(reference).transpose()?
    {
        return Err(ArtifactCause::Identity);
    }
    Ok(())
}

fn checked<T>(
    check: &ArtifactWork<'_, '_>,
    work: Result<T, ArtifactCause>,
) -> Result<T, ArtifactRefusal> {
    check.checked(work)
}

pub(super) fn missing_service() -> OriginalWorkflowArtifactsError {
    OriginalWorkflowArtifactsError::missing_service()
}
