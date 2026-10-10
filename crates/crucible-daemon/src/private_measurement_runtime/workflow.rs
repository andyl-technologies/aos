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

const WORKFLOW_PATH: &str = "/etc/crucible/measurement-workflow.json";

/// Keeps the descriptor and its original authority through subsequent use.
pub(super) struct OriginalResidentWorkflowOwner {
    policy: Option<OriginalActorServicePolicy>,
    input: Option<Vec<u8>>,
    file: Option<File>,
    descriptors: Option<DecodeDescriptorLoan>,
    input_credit: Option<DecodeScratch>,
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
}

/// Preserves an actual read refusal before its independent original boundary.
#[derive(Debug, thiserror::Error)]
#[error("original workflow input refused: {source}; original: {original_after:?}")]
pub struct OriginalWorkflowReadError {
    /// First actual kernel read, file identity or allocation refusal.
    #[source]
    pub source: OriginalWorkflowInputError,
    /// The same decoder's original post-effect refusal, when present.
    pub original_after: Option<DecodeAdmissionError>,
}

/// Classifies input failures without flattening their typed original causes.
#[derive(Debug, thiserror::Error)]
pub enum OriginalWorkflowInputError {
    /// The same closed actor's original custody refused without a new wrapper.
    #[error("workflow actor custody refused: {0}")]
    Actor(#[from] crucible_qemu::OriginalActorAccountError),
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
            file: None,
            descriptors: None,
            input_credit: None,
            decoder: Some(decoder),
            bootstrap: None,
            campaign: None,
            projection: None,
            campaign_policy: None,
            service_state: None,
            prepared_state: None,
            catalog: None,
            graph: None,
            refs: None,
            repository: None,
        };
        owner.read_fixed_input()?;
        let decoder =
            owner
                .decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained workflow decoder",
                ))?;
        let input =
            owner
                .input
                .as_deref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained workflow input",
                ))?;
        owner.policy = Some(actor.admit_workflow_service(decoder, input)?);
        actor.require_original()?;
        Ok(owner)
    }

    fn read_fixed_input(&mut self) -> Result<(), OriginalWorkflowReadError> {
        let decoder = self
            .decoder
            .as_ref()
            .ok_or_else(|| OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Identity,
                original_after: None,
            })?;
        let budget = decoder
            .budget()
            .map_err(|source| OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Actor(source),
                original_after: None,
            })?;
        let result: Result<(), OriginalWorkflowInputError> = (|| {
            self.descriptors = Some(budget.reserve_descriptors(1)?);
            budget.verify_live()?;
            // The trusted rootfs installs a symlink to its immutable store
            // object. Pin the actual opened file before the fallible original
            // postcut; matching its contents is authenticated separately.
            self.file = Some(File::open(WORKFLOW_PATH)?);
            budget.verify_live()?;
            let file = self
                .file
                .as_mut()
                .ok_or(OriginalWorkflowInputError::Identity)?;
            let metadata = file.metadata()?;
            budget.verify_live()?;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o222 != 0 {
                return Err(OriginalWorkflowInputError::Identity);
            }
            let length = usize::try_from(metadata.len())
                .ok()
                .filter(|length| *length != 0)
                .ok_or(OriginalWorkflowInputError::Identity)?;
            self.input_credit = Some(budget.reserve_scratch_bytes(metadata.len())?);
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length)?;
            bytes.resize(length, 0);
            self.input = Some(bytes);
            budget.verify_live()?;
            let bytes = self
                .input
                .as_mut()
                .ok_or(OriginalWorkflowInputError::Identity)?;
            file.read_exact(bytes)?;
            budget.verify_live()?;
            // A fixed one-byte stack probe refuses a changed length. It owns
            // no extra retained buffer or independently inferred descriptor.
            let mut trailing = [0];
            if file.read(&mut trailing)? != 0 {
                return Err(OriginalWorkflowInputError::Identity);
            }
            Ok(())
        })();
        let after = budget.verify_live();
        match (result, after) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(source), after) => Err(OriginalWorkflowReadError {
                source,
                original_after: after.err(),
            }),
            (Ok(()), Err(source)) => Err(OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Admission(source),
                original_after: None,
            }),
        }
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
            crate::campaign_bootstrap::OriginalCampaignRepositoryBootstrap::prepare(
                graph,
                refs,
                decoder.budget()?,
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
                original_after: decoder.budget()?.verify_live().err(),
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
        drop(self.repository.take());
        drop(self.refs.take());
        drop(self.graph.take());
        drop(self.prepared_state.take());
        drop(self.service_state.take());
        drop(self.catalog.take());
        drop(self.policy.take());
        drop(self.campaign_policy.take());
        drop(self.projection.take());
        drop(self.campaign.take());
        drop(self.bootstrap.take());
        drop(self.input.take());
        drop(self.file.take());
        drop(self.descriptors.take());
        drop(self.input_credit.take());
        if let Some(decoder) = self.decoder.take() {
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
        let budget = decoder
            .budget()
            .map_err(|source| OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Actor(source),
                original_after: None,
            })?;
        let mut owner = Self {
            bytes: Vec::new(),
            file: None,
            descriptors: None,
            credit: None,
        };
        let work: Result<(), OriginalWorkflowInputError> = (|| {
            owner.descriptors = Some(budget.reserve_descriptors(1)?);
            budget.verify_live()?;
            owner.file = Some(File::open(path)?);
            budget.verify_live()?;
            let file = owner
                .file
                .as_mut()
                .ok_or(OriginalWorkflowInputError::Identity)?;
            let metadata = file.metadata()?;
            budget.verify_live()?;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o222 != 0 {
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
        match (work, after) {
            (Ok(()), Ok(())) => Ok(owner),
            (Err(source), after) => Err(OriginalWorkflowReadError {
                source,
                original_after: after.err(),
            }),
            (Ok(()), Err(source)) => Err(OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Admission(source),
                original_after: None,
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
