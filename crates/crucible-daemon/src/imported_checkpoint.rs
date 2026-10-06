//! One-use launch selection from a completely authenticated receiver archive.
//!
//! Import proves immutable contents, not a source executor's local execution
//! rows. This module binds a published archive and its durable exact pin to
//! receiver-selected compatibility and resource policy. A fresh admitted
//! Service consumes the result; no source execution identity is fabricated.

use std::sync::Arc;

use crucible::{Configuration, ScenarioDefForm};
use crucible_campaign::{
    AttemptResourceLimits, CampaignArchiveManifestId, CampaignArchivePolicy, CampaignHash,
    CampaignLineageId, CampaignName, CampaignPolicyId, CampaignRepository, CampaignRepositoryError,
    ConfigurationId, ExactCheckpointId,
};
use crucible_cas::ram::RamStoreError;
use thiserror::Error;

use crate::crucible_artifact::decode_crucible_configuration_artifact_from_repository;
use crate::executor_supervisor::SelectedExactCheckpointRoot;
use crate::{
    AttemptExecutionContext, CrucibleArtifactError, DirectoryExactPinMaterializationStore,
    ExactCheckpointStore, ExactCheckpointStoreError, ExactPinRetentionAdmin,
    ExactPinRetentionError, decode_crucible_scenario_artifact,
};

/// Receiver-authorized compatibility and semantic execution limits.
pub struct ReceiverCheckpointPolicy {
    /// Compatibility lineage selected by the trusted receiver operator.
    pub lineage: CampaignLineageId,
    /// Immutable campaign policy accepted by the receiver operator.
    pub policy: CampaignPolicyId,
    /// Semantic execution limits for this receiver realization.
    pub resources: AttemptResourceLimits,
    /// Receiver deployment's independent maximum semantic limits.
    pub resource_ceiling: AttemptResourceLimits,
}

/// Borrowed receiver inventories authenticated before a launch claim is issued.
pub struct ImportedCheckpointAdmission<'a, 'owner> {
    /// Receiver repository whose published refs select complete imported data.
    pub repository: Arc<CampaignRepository>,
    /// Checkpoint reader sharing the exact receiver backend allocation.
    pub checkpoints: &'a ExactCheckpointStore,
    /// Durable receiver selection journal populated by archive import.
    pub selections: &'a mut DirectoryExactPinMaterializationStore,
    /// Already published executable archive reference.
    pub archive: &'a str,
    /// Already published receiver campaign naming the archive snapshot.
    pub campaign: &'a CampaignName,
    /// Exact configuration selected by the trusted receiver caller.
    pub configuration: ConfigurationId,
    /// Independently selected receiver compatibility and limits.
    pub policy: ReceiverCheckpointPolicy,
    /// Already admitted owner supervising authentication and retained scratch.
    pub context: &'owner AttemptExecutionContext,
}

/// Non-cloneable archive selection that can authorize one physical launch.
///
/// The selection borrows the admitted authentication owner until a fresh
/// receiver Service accepts the decoded basis. It cannot be duplicated or
/// detached from that owner.
///
/// ```compile_fail
/// use crucible_daemon::imported_checkpoint::AuthenticatedImportedCheckpoint;
/// fn duplicate(claim: AuthenticatedImportedCheckpoint<'_>) {
///     let second_launch = claim.clone();
/// }
/// ```
///
/// ```compile_fail
/// use crucible_daemon::imported_checkpoint::AuthenticatedImportedCheckpoint;
/// fn detach(claim: AuthenticatedImportedCheckpoint<'_>)
///     -> AuthenticatedImportedCheckpoint<'static>
/// {
///     claim
/// }
/// ```
pub struct AuthenticatedImportedCheckpoint<'owner> {
    basis: ImportedCheckpointBasis,
    authentication_owner: &'owner AttemptExecutionContext,
    authentication_operation: crucible_linux_resource::host_supervision::HostOperationGuard,
}

/// Authenticated semantic material retained through receiver world cleanup.
pub(crate) struct ImportedCheckpointBasis {
    pub(crate) repository: Arc<CampaignRepository>,
    pub(crate) archive: CampaignArchiveManifestId,
    pub(crate) checkpoint: ExactCheckpointId,
    pub(crate) source: ScenarioDefForm,
    pub(crate) configuration: Configuration,
    pub(crate) resources: AttemptResourceLimits,
    pub(crate) budgets: crucible_linux_resource::host_supervision::HostOperationBudgets,
}

impl<'owner> AuthenticatedImportedCheckpoint<'owner> {
    /// Authenticates a published executable archive under original supervision.
    ///
    /// The caller chooses policy using trusted receiver configuration, before
    /// consuming imported bytes. An untrusted manifest cannot choose its own
    /// compatibility lineage, policy revision, or resource ceiling. The same
    /// receiver backend allocation must back both campaign and checkpoint I/O.
    /// The admitted authentication owner remains borrowed until a fresh receiver
    /// Service takes the decoded material. Its reservation must remain live;
    /// finishing that owner before consuming or dropping the claim is invalid.
    ///
    /// # Errors
    /// Refuses detached ownership, incompatible receiver policy, unpublished or
    /// incomplete archives, absent or changed pins, another backend authority,
    /// unpromoted roots, cancellation, corruption, or an expired boundary.
    pub fn prepare(
        admission: ImportedCheckpointAdmission<'_, 'owner>,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<Self, ImportedCheckpointError> {
        let ImportedCheckpointAdmission {
            repository,
            checkpoints,
            selections,
            archive,
            campaign,
            configuration,
            policy,
            context,
        } = admission;
        if context.host_ram_resource_ceiling().is_none()
            || context.host_operation_supervisor().is_none()
        {
            return Err(ImportedCheckpointError::Binding(
                "receiver owner is not admitted",
            ));
        }
        let supervisor =
            context
                .host_operation_supervisor()
                .ok_or(ImportedCheckpointError::Binding(
                    "receiver supervision is absent",
                ))?;
        let authentication_operation = supervisor
            .begin(crucible_linux_resource::host_supervision::HostOperationClass::Transfer)?;
        let mut supervised_boundary = || {
            authentication_operation
                .wait_slice()
                .map_err(|_| RamStoreError::Canceled)?;
            boundary()
        };
        let boundary = &mut supervised_boundary as &mut dyn FnMut() -> Result<(), RamStoreError>;
        let budgets = supervisor.budgets()?.1;
        // Fresh Replay Services have their own operation starts, with the
        // receiver's accepted allowances. They do not inherit an ended cap.
        budgets.validate(false)?;
        check_resources(policy.resources, policy.resource_ceiling)?;
        boundary()?;
        checkpoints.require_reuse_backend(&repository.blob_backend())?;
        let inspected = repository.inspect_campaign_archive_ref_with_boundary(archive, boundary)?;
        if inspected.manifest().policy() != CampaignArchivePolicy::Executable {
            return Err(ImportedCheckpointError::Binding(
                "archive is not executable",
            ));
        }
        let head = repository.head(campaign.as_str())?;
        if head.snapshot_id() != inspected.manifest().source_snapshot()
            || head.snapshot().lineage() != policy.lineage
            || head.snapshot().active_policy() != policy.policy
        {
            return Err(ImportedCheckpointError::Binding(
                "receiver campaign basis differs",
            ));
        }
        let selection = selections
            .acquire_exact_pin_retention_fence()?
            .selection(campaign, configuration)?
            .ok_or(ImportedCheckpointError::Binding(
                "durable exact pin is absent",
            ))?;
        if !inspected
            .manifest()
            .checkpoint_selections()
            .iter()
            .any(|record| {
                record.configuration() == configuration
                    && record.pin_fact() == selection.pin_fact()
                    && record.checkpoint() == selection.checkpoint()
            })
        {
            return Err(ImportedCheckpointError::Binding(
                "archive exact pin differs",
            ));
        }

        // Retain no selection-journal lock across checkpoint or artifact I/O.
        // Both the published snapshot and exact fact are immutable identities.
        let mut pin = None;
        repository.visit_pin_retention_roots_at(head.snapshot_id(), &mut |record| {
            if record.request().change.configuration() == configuration {
                pin = Some(record);
            }
        })?;
        let pin = pin.ok_or(ImportedCheckpointError::Binding(
            "snapshot exact pin is absent",
        ))?;
        if pin.fact() != selection.pin_fact()
            || pin.retention() != crucible_campaign::PinRetention::Exact
        {
            return Err(ImportedCheckpointError::Binding(
                "snapshot pin fact differs",
            ));
        }
        boundary()?;
        let scenario_artifact = repository.load_scenario_artifact(pin.scenario_artifact())?;
        let source = decode_crucible_scenario_artifact(&scenario_artifact)?;
        let lineage = repository.load_lineage(policy.lineage)?;
        if lineage.scenario_content() != pin.scenario_artifact() {
            return Err(ImportedCheckpointError::Binding("scenario lineage differs"));
        }
        let configuration_artifact =
            repository.load_configuration_artifact(pin.configuration_artifact())?;
        let decoded = decode_crucible_configuration_artifact_from_repository(
            &source,
            &scenario_artifact,
            &configuration_artifact,
            &repository,
        )?;
        if ConfigurationId::from_hash(CampaignHash::from_bytes(decoded.id().bytes)) != configuration
        {
            return Err(ImportedCheckpointError::Binding(
                "configuration artifact differs",
            ));
        }
        boundary()?;
        let loaded = checkpoints.load_production_closure_with_cancellation(
            selection.checkpoint(),
            context.cancellation(),
        )?;
        if loaded.scenario() != source.scenario_def().id() || loaded.configuration() != decoded.id()
        {
            return Err(ImportedCheckpointError::Binding(
                "checkpoint semantic basis differs",
            ));
        }
        let raw = loaded
            .promotion_source()
            .ok_or(ImportedCheckpointError::Binding(
                "checkpoint is not promoted",
            ))?;
        crate::exact_checkpoint_restore::authenticate_production_exact_checkpoint_replay_oracle_promotion(
            checkpoints, raw, selection.checkpoint(), &source, context.cancellation(),
        ).map_err(|source| ImportedCheckpointError::Restore(Box::new(source)))?;
        boundary()?;

        // Recheck mutable publication preconditions at claim issuance. Later
        // launch still authenticates the immutable closure and consumes this
        // claim; it cannot substitute another root or revive canceled authority.
        if repository.head(campaign.as_str())?.snapshot_id() != head.snapshot_id()
            || repository
                .inspect_campaign_archive_ref_with_boundary(archive, boundary)?
                .manifest_id()
                != inspected.manifest_id()
        {
            return Err(ImportedCheckpointError::Binding(
                "publication changed during admission",
            ));
        }
        Ok(Self {
            basis: ImportedCheckpointBasis {
                repository,
                archive: inspected.manifest_id(),
                checkpoint: selection.checkpoint(),
                source,
                configuration: decoded,
                resources: policy.resources,
                budgets,
            },
            authentication_owner: context,
            authentication_operation,
        })
    }

    pub(crate) fn source(&self) -> &ScenarioDefForm {
        &self.basis.source
    }

    pub(crate) fn repository(&self) -> &Arc<CampaignRepository> {
        &self.basis.repository
    }

    pub(crate) fn authentication_owner(&self) -> &AttemptExecutionContext {
        self.authentication_owner
    }

    pub(crate) fn resources(&self) -> AttemptResourceLimits {
        self.basis.resources
    }

    pub(crate) fn budgets(
        &self,
    ) -> crucible_linux_resource::host_supervision::HostOperationBudgets {
        self.basis.budgets
    }

    /// Returns the exact authenticated root selected for the one-use launch.
    pub fn checkpoint(&self) -> ExactCheckpointId {
        self.basis.checkpoint
    }

    /// Returns the completely authenticated published receiver archive identity.
    pub fn archive(&self) -> CampaignArchiveManifestId {
        self.basis.archive
    }

    /// Consumes the sole launch claim while retaining receiver provenance.
    pub(crate) fn into_launch(
        self,
    ) -> Result<
        (ImportedCheckpointBasis, SelectedExactCheckpointRoot),
        crucible_linux_resource::host_supervision::HostSupervisionError,
    > {
        self.authentication_operation.complete()?;
        let selected = SelectedExactCheckpointRoot::after_authenticated_import(&self);
        Ok((self.basis, selected))
    }
}

fn check_resources(
    resources: AttemptResourceLimits,
    ceiling: AttemptResourceLimits,
) -> Result<(), ImportedCheckpointError> {
    if resources.maximum_vcpus() > ceiling.maximum_vcpus()
        || resources.maximum_resident_bytes() > ceiling.maximum_resident_bytes()
        || resources.maximum_disk_bytes() > ceiling.maximum_disk_bytes()
        || resources.maximum_execution_quanta() > ceiling.maximum_execution_quanta()
    {
        return Err(ImportedCheckpointError::Binding(
            "receiver execution limits exceeded",
        ));
    }
    Ok(())
}

/// Typed refusal before receiver process-launch authority is exposed.
#[derive(Debug, Error)]
pub enum ImportedCheckpointError {
    /// Receiver trust or publication preconditions did not match.
    #[error("imported checkpoint binding refused: {0}")]
    Binding(&'static str),
    /// Receiver campaign authentication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Durable exact-pin selection authentication failed.
    #[error(transparent)]
    Pin(#[from] ExactPinRetentionError),
    /// Complete exact checkpoint authentication failed.
    #[error(transparent)]
    Store(#[from] ExactCheckpointStoreError),
    /// Scenario or configuration artifacts failed semantic decoding.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// Raw-to-promoted replay-oracle authentication failed.
    #[error("imported checkpoint replay oracle: {0}")]
    Restore(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The original operational boundary expired or was canceled.
    #[error(transparent)]
    Boundary(#[from] RamStoreError),
    /// Receiver budget policy or original supervision could not be observed.
    #[error(transparent)]
    Supervision(#[from] crucible_linux_resource::host_supervision::HostSupervisionError),
}
