//! Retains the authenticated fixed workflow input under its original decoder.
//!
//! The input file, raw bytes and descriptor custody close before their loans.
//! The service-policy projection contains no owning model data or bank getter.
//! Actual scenario/schedule import, Source admission and native initialization
//! qualification follow this read; an authenticated descriptor is not a VM
//! launch permission.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use crucible::owned_decode::{DecodeAdmissionError, DecodeDescriptorLoan, DecodeScratch};
use crucible_qemu::{OriginalActorDecodeOwner, OriginalActorServicePolicy};

use super::MeasurementRuntimeAdmissionError;
use super::actor_roles::OriginalActorRoleIssuer;

mod assets;
mod retirement;
pub use assets::OriginalWorkflowArtifactsError;
pub use retirement::OriginalWorkflowCloseError;

const WORKFLOW_PATH: &str = "/etc/crucible/measurement-workflow.json";

/// Keeps the descriptor and its original authority through subsequent use.
pub(super) struct OriginalResidentWorkflowOwner {
    policy: Option<OriginalActorServicePolicy>,
    input: Option<InstalledServiceInput>,
    decoder: Option<OriginalActorDecodeOwner>,
    bootstrap: Option<InstalledServiceInput>,
    campaign: Option<InstalledServiceInput>,
    projection: Option<InstalledServiceInput>,
    campaign_policy: Option<crate::campaign_policy::OriginalCampaignPolicyOwner>,
    catalog: Option<crate::private_measurement_runtime::catalog::OriginalActorCatalogOwner>,
    graph: Option<crucible_cas::content_store::OriginalSqliteGraphOwner>,
    refs: Option<crucible_cas::content_store::OriginalDirectoryRefOwner>,
    repository: Option<crate::campaign_bootstrap::OriginalCampaignRepositoryBootstrap>,
    service_state: Option<crate::campaign_bootstrap::OriginalCampaignStateBootstrap>,
    prepared_state: Option<crate::campaign_bootstrap::PreparedCampaignStateOwner>,
    retention: Option<crate::hot_checkpoint_retention::OriginalHotCheckpointRetentionOwner>,
    transfers: Option<crate::campaign_transfer::OriginalCampaignTransferJournalOwner>,
    prepared_retention: Option<std::sync::Arc<crate::DirectoryHotCheckpointFallbackRetentionStore>>,
    prepared_transfers: Option<crate::DirectoryCampaignTransferJournal>,
    prepared_policy: Option<std::sync::Arc<crate::UnixPeerCampaignPolicy>>,
    components: Option<InstalledServiceInput>,
    component_authorities: Option<(
        crucible_campaign::PlannerAuthorityKey,
        crucible_campaign::DebuggerAuthorityKey,
    )>,
    prepared_service: Option<crate::campaign_bootstrap::OriginalPreparedCampaignServiceOwner>,
    artifacts: Option<assets::OriginalWorkflowArtifactsOwner>,
    input_retirement_attempted: bool,
}

/// Preserves an actual read refusal before its independent original boundary.
#[derive(Debug, thiserror::Error)]
#[error("original workflow input refused: {source}; original: {original_after:?}")]
pub struct OriginalWorkflowReadError {
    /// First actual kernel read, file identity or allocation refusal.
    #[source]
    pub source: OriginalWorkflowInputError,
    /// The same decoder's independent sticky admission postcheck, when present.
    pub original_after: Option<DecodeAdmissionError>,
    /// The retained raw original boundary, independent of sticky decode state.
    pub guard_after: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
}

/// Classifies input failures without flattening their typed original causes.
#[derive(Debug, thiserror::Error)]
pub enum OriginalWorkflowInputError {
    /// The same closed actor's original custody refused without a new wrapper.
    #[error("workflow actor custody refused: {0}")]
    Actor(#[from] crucible_qemu::OriginalActorAccountError),
    /// The independently retained original interval refused.
    #[error("workflow original boundary refused: {0}")]
    Original(#[from] crucible_linux_resource::host_supervision::HostSupervisionError),
    /// The authenticated component bytes violate the existing key protocol.
    #[error("workflow component authority refused: {0}")]
    Component(#[from] crucible_campaign::CampaignCodecError),
    /// The actual fixed-path kernel operation failed.
    #[error("workflow kernel operation refused: {0}")]
    Io(#[from] std::io::Error),
    /// A buffer allocation failed after original admission.
    #[error("workflow buffer allocation refused: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    /// The original decoder refused credit before an effect.
    #[error("workflow original credit refused: {0}")]
    Admission(#[from] DecodeAdmissionError),
    /// The installed input is mutable, unowned, empty or cannot fit this target.
    #[error("workflow file identity or extent is inadmissible")]
    Identity,
}

impl OriginalResidentWorkflowOwner {
    pub(super) fn load(
        actor: &OriginalActorRoleIssuer,
    ) -> Result<Self, MeasurementRuntimeAdmissionError> {
        let decoder = actor.prepare_workflow_decode_owner()?;
        let mut owner = Self {
            policy: None,
            input: None,
            decoder: Some(decoder),
            bootstrap: None,
            campaign: None,
            projection: None,
            campaign_policy: None,
            service_state: None,
            prepared_state: None,
            retention: None,
            transfers: None,
            prepared_retention: None,
            prepared_transfers: None,
            prepared_policy: None,
            components: None,
            component_authorities: None,
            prepared_service: None,
            artifacts: None,
            input_retirement_attempted: false,
            catalog: None,
            graph: None,
            refs: None,
            repository: None,
        };
        let decoder =
            owner
                .decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained workflow decoder",
                ))?;
        owner.input = Some(InstalledServiceInput::read_workflow(decoder)?);
        let decoder =
            owner
                .decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained workflow decoder",
                ))?;
        let input = owner
            .input
            .as_ref()
            .map(|input| input.bytes.as_slice())
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained workflow input",
            ))?;
        owner.policy = Some(actor.admit_workflow_service(decoder, input)?);
        assets::executor::preflight(input, decoder)?;
        actor.require_original()?;
        Ok(owner)
    }

    pub(super) fn prepare_campaign_state(
        &mut self,
        heap: &crucible_cas::content_store::SqliteProcessHeap,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        heap.verify_live()
            .map_err(MeasurementRuntimeAdmissionError::ServiceHeap)?;
        let decoder =
            self.decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained workflow decoder",
                ))?;
        self.service_state =
            Some(crate::campaign_bootstrap::OriginalCampaignStateBootstrap::prepare(decoder)?);
        let state =
            self.service_state
                .as_mut()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained original state",
                ))?;
        self.prepared_state = Some(state.share_for_service()?.into());
        Ok(())
    }

    pub(super) fn prepare_catalog_owner(
        &mut self,
        actor: &OriginalActorRoleIssuer,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let decoder =
            self.decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained workflow decoder",
                ))?;
        self.catalog = Some(actor.prepare_catalog_owner(decoder)?);
        Ok(())
    }

    /// Prepares RAM catalog custody inside the existing original catalog.
    ///
    /// # Errors
    /// Refuses missing original catalog, installed quota, heap or credit.
    pub(super) fn prepare_ram_catalog_provider(
        &mut self,
        heap: &crucible_cas::content_store::SqliteProcessHeap,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        self.catalog
            .as_mut()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original catalog provider owner",
            ))?
            .prepare_ram_provider(heap)
            .map_err(MeasurementRuntimeAdmissionError::CampaignGraph)
    }

    pub(super) fn close_catalog_owner(
        &mut self,
    ) -> Result<(), crate::private_measurement_runtime::catalog::OriginalActorCatalogOwner> {
        if let Some(owner) = self.catalog.take() {
            owner.try_close()?;
        }
        Ok(())
    }

    pub(super) fn prepare_campaign_graph(
        &mut self,
        purpose: crucible_qemu::OriginalActorCatalogPurpose,
        heap: &crucible_cas::content_store::SqliteProcessHeap,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let catalog =
            self.catalog
                .as_mut()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained original catalog owner",
                ))?;
        catalog
            .bind_physical_catalog(purpose)
            .map_err(MeasurementRuntimeAdmissionError::CampaignGraph)?;
        self.graph = Some(
            crate::campaign_bootstrap::prepare_original_sqlite_graph(catalog, heap)
                .map_err(MeasurementRuntimeAdmissionError::CampaignGraph)?,
        );
        Ok(())
    }

    pub(super) fn close_campaign_graph(
        &mut self,
    ) -> Result<(), crucible_cas::content_store::OriginalSqliteGraphCloseError> {
        if let Some(owner) = self.graph.as_mut() {
            owner.try_close()?;
        }
        drop(self.graph.take());
        Ok(())
    }

    pub(super) fn prepare_campaign_refs(&mut self) -> Result<(), MeasurementRuntimeAdmissionError> {
        let catalog =
            self.catalog
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained original reference catalog",
                ))?;
        self.refs = Some(
            crate::campaign_bootstrap::prepare_original_directory_refs(catalog)
                .map_err(MeasurementRuntimeAdmissionError::CampaignReferences)?,
        );
        Ok(())
    }

    pub(super) fn close_campaign_refs(
        &mut self,
    ) -> Result<(), crucible_cas::content_store::StoreError> {
        if let Some(owner) = self.refs.as_mut() {
            owner.try_close()?;
        }
        drop(self.refs.take());
        Ok(())
    }

    pub(super) fn prepare_campaign_support(
        &mut self,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let catalog =
            self.catalog
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained original catalog for service support",
                ))?;
        let decoder =
            self.decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained original support decoder",
                ))?;
        let budget = decoder.budget()?;
        self.retention = Some(
            crate::hot_checkpoint_retention::OriginalHotCheckpointRetentionOwner::prepare(
                catalog
                    .supervisor()
                    .map_err(MeasurementRuntimeAdmissionError::CampaignGraph)?,
                catalog
                    .physical_quota()
                    .map_err(MeasurementRuntimeAdmissionError::CampaignGraph)?,
                budget,
            )
            .map_err(super::OriginalCampaignSupportError::Retention)?,
        );
        self.transfers = Some(
            crate::campaign_transfer::OriginalCampaignTransferJournalOwner::prepare(
                catalog
                    .supervisor()
                    .map_err(MeasurementRuntimeAdmissionError::CampaignGraph)?,
                catalog
                    .physical_quota()
                    .map_err(MeasurementRuntimeAdmissionError::CampaignGraph)?,
                budget,
            )
            .map_err(super::OriginalCampaignSupportError::Transfer)?,
        );
        // These are the actual handles destined for the existing prepared
        // service. The external owners remain alongside them through cleanup;
        // sharing creates no second control allocation or replacement bank.
        self.prepared_retention = Some(
            self.retention
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained original retention owner",
                ))?
                .share()
                .map_err(super::OriginalCampaignSupportError::Retention)?,
        );
        self.prepared_transfers = Some(
            self.transfers
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained original transfer owner",
                ))?
                .share()
                .map_err(super::OriginalCampaignSupportError::Transfer)?,
        );
        Ok(())
    }

    pub(super) fn close_campaign_support(
        &mut self,
    ) -> Result<(), super::OriginalCampaignSupportError> {
        drop(self.prepared_transfers.take());
        drop(self.prepared_retention.take());
        if let Some(transfers) = self.transfers.as_mut() {
            transfers
                .try_close()
                .map_err(super::OriginalCampaignSupportError::Transfer)?;
        }
        drop(self.transfers.take());
        if let Some(retention) = self.retention.as_mut() {
            retention
                .try_close()
                .map_err(super::OriginalCampaignSupportError::Retention)?;
        }
        drop(self.retention.take());
        Ok(())
    }

    pub(super) fn prepare_component_authorities(
        &mut self,
        declaration: &crucible_qemu::OriginalActorServiceLaunchPurpose,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let decoder =
            self.decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained component decoder",
                ))?;
        declaration.verify_decoder(decoder)?;
        let budget = decoder.budget()?;
        crate::campaign_bootstrap::OriginalPreparedCampaignServiceOwner::verify_declaration(
            declaration,
            budget,
        )?;
        self.components = Some(InstalledServiceInput::read_mode(
            decoder,
            "/etc/crucible/measurement-components.v1",
            Some(0o600),
            Some(72),
        )?);
        let input =
            self.components
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained component file",
                ))?;
        let work = (|| {
            if blake3::hash(&input.bytes).as_bytes() != declaration.component_authorities_digest()
                || input.bytes.len() != 72
                || &input.bytes[..8] != b"CRUCCA01"
            {
                return Err(OriginalWorkflowInputError::Identity);
            }
            let planner: [u8; 32] = input.bytes[8..40]
                .try_into()
                .map_err(|_| OriginalWorkflowInputError::Identity)?;
            let debugger: [u8; 32] = input.bytes[40..72]
                .try_into()
                .map_err(|_| OriginalWorkflowInputError::Identity)?;
            if planner == debugger {
                return Err(OriginalWorkflowInputError::Identity);
            }
            self.component_authorities = Some((
                crucible_campaign::PlannerAuthorityKey::from_bytes(planner)?,
                crucible_campaign::DebuggerAuthorityKey::from_bytes(debugger)?,
            ));
            Ok(())
        })();
        let after = budget.verify_live();
        let guard_after = decoder.verify_original_boundary();
        match (work, after, guard_after) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
            (Err(source), after, guard_after) => Err(OriginalWorkflowReadError {
                source,
                original_after: after.err(),
                guard_after: guard_after.err(),
            }
            .into()),
            (Ok(()), Err(source), guard_after) => Err(OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Admission(source),
                original_after: None,
                guard_after: guard_after.err(),
            }
            .into()),
            (Ok(()), Ok(()), Err(source)) => Err(OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Original(source),
                original_after: None,
                guard_after: None,
            }
            .into()),
        }
    }

    pub(super) fn prepare_service(
        &mut self,
        declaration: crucible_qemu::OriginalActorServiceLaunchPurpose,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let decoder =
            self.decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained service decoder",
                ))?;
        declaration.verify_decoder(decoder)?;
        let repository =
            self.repository
                .as_mut()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained service repository",
                ))?;
        let state =
            self.prepared_state
                .take()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained service state",
                ))?;
        let policy =
            self.prepared_policy
                .take()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained service policy",
                ))?;
        let retention = self.prepared_retention.take().ok_or(
            MeasurementRuntimeAdmissionError::MissingPurpose("retained service retention"),
        )?;
        let transfers = self.prepared_transfers.take().ok_or(
            MeasurementRuntimeAdmissionError::MissingPurpose("retained service transfers"),
        )?;
        self.prepared_service = Some(
            crate::campaign_bootstrap::OriginalPreparedCampaignServiceOwner::prepare(
                declaration,
                repository,
                state,
                policy,
                retention,
                transfers,
                decoder.budget()?,
            )?,
        );
        Ok(())
    }

    pub(super) fn import_fixed_campaign_inputs(
        &mut self,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let decoder =
            self.decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained artifact decoder",
                ))?;
        let bytes = self
            .input
            .as_ref()
            .map(|input| input.bytes.as_slice())
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained authenticated workflow",
            ))?;
        let service = self.prepared_service.as_ref().ok_or(
            MeasurementRuntimeAdmissionError::MissingPurpose("retained prepared campaign service"),
        )?;
        self.artifacts = Some(assets::OriginalWorkflowArtifactsOwner::load_and_import(
            bytes, decoder, service,
        )?);
        let state =
            self.service_state
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained campaign state namespace",
                ))?;
        let catalog = self
            .catalog
            .as_ref()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original RAM catalog owner",
            ))?
            .ram_provider_binding()
            .map_err(MeasurementRuntimeAdmissionError::CampaignGraph)?;
        self.artifacts
            .as_mut()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained authenticated artifact owner",
            ))?
            .prepare_lifecycle(state, service, &catalog)?;
        self.artifacts
            .as_mut()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained workflow artifacts",
            ))?
            .prepare_executor_config(bytes, state, service, &catalog)?;
        Ok(())
    }

    /// Moves the paid configuration into the genuine same-actor factory.
    ///
    /// # Errors
    /// Refuses missing original service/artifacts or typed factory preparation.
    pub(super) fn prepare_genuine_executor<'actor>(
        &mut self,
        issuer: &'actor mut OriginalActorRoleIssuer,
    ) -> Result<super::OriginalPreparedPackagedExecutor<'actor>, MeasurementRuntimeAdmissionError>
    {
        let service = self.prepared_service.as_ref().ok_or(
            MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained prepared service for original factory",
            ),
        )?;
        let artifacts =
            self.artifacts
                .as_mut()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained original executor configuration",
                ))?;
        let config = artifacts.take_executor_config(service)?;
        Ok(service.prepare_packaged_executor(issuer, config)?)
    }

    /// Advances actual created campaigns before the factory's physical retirement.
    ///
    /// # Errors
    /// Refuses missing authenticated input, service/artifact custody or actual
    /// command, driver and original boundary failures without replacing owners.
    pub(super) fn execute_campaigns(
        &mut self,
        executor: &super::OriginalPreparedPackagedExecutor<'_>,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let bytes = self
            .input
            .as_ref()
            .map(|input| input.bytes.as_slice())
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained execution input",
            ))?;
        let service = self.prepared_service.as_ref().ok_or(
            MeasurementRuntimeAdmissionError::MissingPurpose("retained execution service"),
        )?;
        let artifacts =
            self.artifacts
                .as_mut()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained execution artifacts",
                ))?;
        Ok(artifacts.execute_campaigns(bytes, service, executor)?)
    }

    /// Retires the same factory using the existing prepared failure purpose.
    ///
    /// # Errors
    /// Refuses absent service custody or typed retirement and original cuts.
    pub(super) fn retire_executor(
        &self,
        executor: &mut super::OriginalPreparedPackagedExecutor<'_>,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let service = self.prepared_service.as_ref().ok_or(
            MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained prepared service for physical executor retirement",
            ),
        )?;
        Ok(service.retire_packaged_executor(executor)?)
    }

    pub(super) fn close_artifacts(&mut self) -> Result<(), OriginalWorkflowArtifactsError> {
        if let Some(artifacts) = self.artifacts.as_mut() {
            let service = self
                .prepared_service
                .as_ref()
                .ok_or_else(assets::missing_service)?;
            artifacts.try_close(service)?;
        }
        drop(self.artifacts.take());
        Ok(())
    }

    pub(super) fn close_prepared_service(
        &mut self,
    ) -> Result<(), crate::campaign_bootstrap::OriginalPreparedServiceError> {
        if let Some(service) = self.prepared_service.as_mut() {
            service.try_close()?;
        }
        drop(self.prepared_service.take());
        Ok(())
    }

    pub(super) fn prepare_campaign_repository(
        &mut self,
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let decoder =
            self.decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained repository decoder",
                ))?;
        let graph = self
            .graph
            .as_mut()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained repository graph",
            ))?;
        let refs = self
            .refs
            .as_ref()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained repository references",
            ))?;
        self.repository = Some(
            crate::campaign_bootstrap::OriginalCampaignRepositoryBootstrap::prepare_with_components(
                graph,
                refs,
                decoder.budget()?,
                self.component_authorities.take().ok_or(MeasurementRuntimeAdmissionError::MissingPurpose("authenticated repository components"))?,
            )
            .map_err(MeasurementRuntimeAdmissionError::CampaignRepository)?,
        );
        Ok(())
    }

    pub(super) fn close_campaign_repository(
        &mut self,
    ) -> Result<(), crucible_cas::content_store::StoreError> {
        if let Some(owner) = self.repository.as_mut() {
            owner.try_close()?;
        }
        drop(self.repository.take());
        Ok(())
    }

    pub(super) fn close_campaign_state(
        &mut self,
    ) -> Result<(), crate::campaign_bootstrap::OriginalCampaignStateError> {
        drop(self.prepared_state.take());
        if let Some(state) = self.service_state.take() {
            state.try_close()?;
        }
        Ok(())
    }

    pub(super) fn install_sqlite(
        &mut self,
        sqlite: &mut super::sqlite::OriginalActorSqliteOwner,
        campaign_digest: &[u8; 32],
    ) -> Result<crucible_cas::content_store::SqliteProcessHeap, MeasurementRuntimeAdmissionError>
    {
        let decoder =
            self.decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained workflow decoder",
                ))?;
        let budget = decoder.budget()?;
        self.bootstrap = Some(InstalledServiceInput::read(
            decoder,
            "/etc/crucible/sqlite-bootstrap-target.json",
        )?);
        self.campaign = Some(InstalledServiceInput::read(
            decoder,
            "/etc/crucible/measurement-service-policy.toml",
        )?);
        let campaign =
            self.campaign
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained campaign policy",
                ))?;
        if blake3::hash(&campaign.bytes).as_bytes() != campaign_digest {
            return Err(OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Identity,
                original_after: budget.verify_live().err(),
                guard_after: decoder.verify_original_boundary().err(),
            }
            .into());
        }
        let bootstrap =
            self.bootstrap
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained SQLite bootstrap input",
                ))?;
        let qualification = sqlite.qualify_bootstrap(decoder, &bootstrap.bytes)?;
        Ok(sqlite.install(qualification)?)
    }

    pub(super) fn prepare_campaign_policy(
        &mut self,
        expected_projection: &[u8; 32],
        expected_toml: &[u8; 32],
    ) -> Result<(), MeasurementRuntimeAdmissionError> {
        let decoder =
            self.decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained policy decoder",
                ))?;
        self.projection = Some(InstalledServiceInput::read(
            decoder,
            "/etc/crucible/measurement-service-policy.json",
        )?);
        let projection =
            self.projection
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained policy projection",
                ))?;
        self.campaign_policy = Some(crate::campaign_policy::OriginalCampaignPolicyOwner::decode(
            &projection.bytes,
            expected_projection,
            expected_toml,
            decoder.budget()?,
        )?);
        self.campaign_policy
            .as_mut()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained policy owner",
            ))?
            .admit_service_arc()?;
        self.prepared_policy = Some(
            self.campaign_policy
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained service policy owner",
                ))?
                .share_for_service()?,
        );
        Ok(())
    }

    pub(super) fn close_campaign_policy(
        &mut self,
    ) -> Result<(), crate::campaign_policy::OriginalCampaignPolicyError> {
        drop(self.prepared_policy.take());
        if let Some(owner) = self.campaign_policy.as_mut() {
            owner.try_close()?;
        }
        drop(self.campaign_policy.take());
        Ok(())
    }

    pub(super) fn take_service_policy(
        &mut self,
    ) -> Result<OriginalActorServicePolicy, MeasurementRuntimeAdmissionError> {
        self.policy
            .take()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "unconsumed original workflow service policy",
            ))
    }
}

impl Drop for OriginalResidentWorkflowOwner {
    fn drop(&mut self) {
        drop(self.prepared_service.take());
        drop(self.prepared_policy.take());
        drop(self.prepared_transfers.take());
        drop(self.prepared_retention.take());
        drop(self.transfers.take());
        drop(self.retention.take());
        drop(self.repository.take());
        drop(self.refs.take());
        drop(self.graph.take());
        drop(self.prepared_state.take());
        drop(self.service_state.take());
        drop(self.catalog.take());
        drop(self.policy.take());
        drop(self.campaign_policy.take());
        drop(self.components.take());
        self.component_authorities = None;
        drop(self.projection.take());
        drop(self.campaign.take());
        drop(self.bootstrap.take());
        drop(self.input.take());
        if let Some(decoder) = self.decoder.take() {
            if self.input_retirement_attempted {
                std::mem::forget(decoder);
                return;
            }
            // A refused close returns the same fail-sticky owner. Its Drop
            // retains opaque errors and original credit until actor teardown.
            let _closed = decoder.try_close();
        }
    }
}

/// Pins one installed service object before each fallible original postcut.
struct InstalledServiceInput {
    bytes: Vec<u8>,
    file: Option<File>,
    descriptors: Option<DecodeDescriptorLoan>,
    credit: Option<DecodeScratch>,
}

impl InstalledServiceInput {
    fn read(
        decoder: &OriginalActorDecodeOwner,
        path: &'static str,
    ) -> Result<Self, OriginalWorkflowReadError> {
        Self::read_inner(decoder, path, None, None, false)
    }

    fn read_workflow(
        decoder: &OriginalActorDecodeOwner,
    ) -> Result<Self, OriginalWorkflowReadError> {
        // Only this authenticated fixed workflow locator may follow the trusted
        // rootfs symlink. Copied proof, policy and authority leaves remain NOFOLLOW.
        Self::read_inner(decoder, WORKFLOW_PATH, None, None, true)
    }

    fn read_mode(
        decoder: &OriginalActorDecodeOwner,
        path: &'static str,
        required_mode: Option<u32>,
        required_length: Option<u64>,
    ) -> Result<Self, OriginalWorkflowReadError> {
        Self::read_inner(decoder, path, required_mode, required_length, false)
    }

    fn read_inner(
        decoder: &OriginalActorDecodeOwner,
        path: &'static str,
        required_mode: Option<u32>,
        required_length: Option<u64>,
        follow_workflow: bool,
    ) -> Result<Self, OriginalWorkflowReadError> {
        let budget = decoder
            .budget()
            .map_err(|source| OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Actor(source),
                original_after: None,
                guard_after: decoder.verify_original_boundary().err(),
            })?;
        let mut owner = Self {
            bytes: Vec::new(),
            file: None,
            descriptors: None,
            credit: None,
        };
        let work: Result<(), OriginalWorkflowInputError> = (|| {
            decoder.verify_original_boundary()?;
            owner.descriptors = Some(budget.reserve_descriptors(1)?);
            budget.verify_live()?;
            owner.file = Some(
                rustix::fs::open(
                    path,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::CLOEXEC
                        | if follow_workflow {
                            rustix::fs::OFlags::empty()
                        } else {
                            rustix::fs::OFlags::NOFOLLOW
                        },
                    rustix::fs::Mode::empty(),
                )
                .map_err(|source| std::io::Error::from_raw_os_error(source.raw_os_error()))?
                .into(),
            );
            budget.verify_live()?;
            let file = owner
                .file
                .as_mut()
                .ok_or(OriginalWorkflowInputError::Identity)?;
            let metadata = file.metadata()?;
            budget.verify_live()?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.gid() != 0
                || required_mode.map_or(metadata.mode() & 0o222 != 0, |mode| {
                    metadata.mode() & 0o777 != mode
                })
                || required_length.is_some_and(|length| metadata.len() != length)
            {
                return Err(OriginalWorkflowInputError::Identity);
            }
            let length = usize::try_from(metadata.len())
                .ok()
                .filter(|length| *length != 0)
                .ok_or(OriginalWorkflowInputError::Identity)?;
            owner.credit = Some(budget.reserve_scratch_bytes(metadata.len())?);
            owner.bytes.try_reserve_exact(length)?;
            owner.bytes.resize(length, 0);
            budget.verify_live()?;
            file.read_exact(&mut owner.bytes)?;
            budget.verify_live()?;
            let mut trailing = [0];
            if file.read(&mut trailing)? != 0 {
                return Err(OriginalWorkflowInputError::Identity);
            }
            Ok(())
        })();
        let after = budget.verify_live();
        let guard_after = decoder.verify_original_boundary();
        match (work, after, guard_after) {
            (Ok(()), Ok(()), Ok(())) => Ok(owner),
            (Ok(()), Ok(()), Err(source)) => Err(OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Original(source),
                original_after: None,
                guard_after: None,
            }),
            (Err(source), after, guard_after) => Err(OriginalWorkflowReadError {
                source,
                original_after: after.err(),
                guard_after: guard_after.err(),
            }),
            (Ok(()), Err(source), guard_after) => Err(OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Admission(source),
                original_after: None,
                guard_after: guard_after.err(),
            }),
        }
    }
}

impl Drop for InstalledServiceInput {
    fn drop(&mut self) {
        // A containing field's Drop runs before its field allocation frees.
        // Explicitly free byte storage and the pinned FD before their loans.
        self.bytes = Vec::new();
        drop(self.file.take());
        drop(self.descriptors.take());
        drop(self.credit.take());
    }
}
