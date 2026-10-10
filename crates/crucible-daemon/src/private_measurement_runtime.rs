//! Owns the private daemon actor admission before its genuine packaged factory.
//!
//! The sole entry consumes the authenticated parent carrier and publishes its
//! original paired accounts through the closed actor issuer. A compiled exact
//! workflow and complete physical-purpose coverage remain prerequisites for
//! the genuine factory; actor arguments cannot provide either authority.

use crucible_linux_resource::host_services::HostServiceError;
use crucible_linux_resource::host_supervision::HostSupervisionError;
use crucible_linux_resource::measurement_origin::{
    AuthenticatedParentInvocation, MeasurementOriginError,
};

mod actor_roles;
pub(crate) mod catalog;
mod sqlite;
mod workflow;

pub use actor_roles::OriginalActorRoleIssuer;
pub use catalog::OriginalActorCatalogOwner;
pub use workflow::{OriginalWorkflowInputError, OriginalWorkflowReadError};

/// Names the fixed genuine service stage whose admission remains incomplete.
#[derive(Clone, Copy, Debug)]
pub enum OriginalServiceStage {
    /// The catalog graph, refs and repository require same-owner construction.
    CampaignRepository,
    /// Retention, transfer journal and the actual prepared service remain next.
    RetainedCampaignService,
}

impl std::fmt::Display for OriginalServiceStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CampaignRepository => formatter
                .write_str("original-paid campaign graph, reference and repository construction"),
            Self::RetainedCampaignService => formatter.write_str(
                "original-paid campaign retention, transfer journal and prepared service",
            ),
        }
    }
}

/// Retains the actual ordered cleanup cut after a known missing service stage.
#[derive(Debug, thiserror::Error)]
pub enum OriginalServiceCleanup {
    /// The genuine repository did not close its actual controls.
    #[error("repository cleanup refused: {0}")]
    Repository(#[source] crucible_cas::content_store::StoreError),
    /// The genuine reference owner did not close its actual controls.
    #[error("reference cleanup refused: {0}")]
    References(#[source] crucible_cas::content_store::StoreError),
    /// The graph retained aliases or a distinct same-original completion refusal.
    #[error("graph cleanup refused: {0}")]
    Graph(#[source] crucible_cas::content_store::OriginalSqliteGraphCloseError),
}

/// First refusal while deriving the closed original actor from its actual issuer.
#[derive(Debug, thiserror::Error)]
pub enum MeasurementRuntimeAdmissionError {
    /// The known absent continuation stays primary across actual cleanup refusal.
    #[error("original actor lacks {stage}; cleanup: {cleanup}")]
    MissingContinuationCleanup {
        /// The already-known first missing service stage.
        stage: OriginalServiceStage,
        /// Actual subsequent cleanup refusal remains typed and independently owned.
        #[source]
        cleanup: OriginalServiceCleanup,
    },
    /// The genuine repository retained its original control admission cause.
    #[error("original campaign repository refused: {0}")]
    CampaignRepository(#[source] crucible_cas::content_store::StoreError),
    /// Graph retirement retained its first alias or original completion cause.
    #[error("original campaign graph retirement refused: {0}")]
    CampaignGraphClose(#[source] crucible_cas::content_store::OriginalSqliteGraphCloseError),
    /// The same physical catalog retained its genuine reference control cause.
    #[error("original campaign references refused: {0}")]
    CampaignReferences(#[source] crucible_cas::content_store::StoreError),
    /// The genuine graph or its installed catalog quota retained its refusal.
    #[error("original campaign graph refused: {0}")]
    CampaignGraph(#[source] crucible_cas::content_store::StoreError),
    /// The genuine campaign state retained work and original boundary failures.
    #[error("{0}")]
    CampaignState(#[from] crate::campaign_bootstrap::OriginalCampaignStateError),
    /// The same installed SQLite heap refused before state effects.
    #[error("original service heap refused: {0}")]
    ServiceHeap(#[source] crucible_cas::content_store::StoreError),
    /// The missing graph purpose remains first across actual state closure.
    #[error("original actor lacks {stage}; state closure: {cleanup}")]
    MissingServicePurposeCleanup {
        /// Exact missing next genuine service purpose.
        stage: OriginalServiceStage,
        /// Separately retained actual state cleanup and original cause.
        #[source]
        cleanup: crate::campaign_bootstrap::OriginalCampaignStateError,
    },
    /// The fixed next purpose remains first across catalog control closure.
    #[error("original actor lacks {stage}; catalog closure: {cleanup}")]
    MissingCatalogPurposeCleanup {
        /// Fixed next genuine service stage.
        stage: OriginalServiceStage,
        /// Retains the same catalog owner and its typed original refusal.
        #[source]
        cleanup: crate::private_measurement_runtime::catalog::OriginalActorCatalogOwner,
    },
    /// The actual fixed workflow read failed under its original input owner.
    #[error("{0}")]
    WorkflowRead(#[from] OriginalWorkflowReadError),
    /// The authenticated source-built policy retained its original refusal.
    #[error("{0}")]
    CampaignPolicy(#[from] crate::campaign_policy::OriginalCampaignPolicyError),
    /// Actual native source qualification retains its separate original cut.
    #[error(transparent)]
    SqliteBootstrap(#[from] sqlite::OriginalActorSqliteBootstrapError),
    /// The actual native installation retained its first and original causes.
    #[error("{0}")]
    SqliteInstall(#[from] sqlite::OriginalActorSqliteInstallError),
    /// The actual issuer or same original absolute interval refused admission.
    #[error("original actor issuance refused: {0}")]
    Origin(#[from] MeasurementOriginError),
    /// A required compiled complete-purpose certificate is absent.
    #[error("original actor lacks compiled complete purpose at {0}")]
    MissingPurpose(&'static str),
    /// An absent purpose remains primary when the same original interval ends.
    #[error("original actor lacks {purpose}; post-original refusal: {after}")]
    MissingPurposeBoundary {
        /// Exact first omitted compiled purpose.
        purpose: &'static str,
        /// Same retained interval's separate postcheck refusal.
        after: MeasurementOriginError,
    },
    /// The same stack original paired accounts refused structural admission.
    #[error("original actor structural admission refused: {0}")]
    Account(#[from] HostServiceError),
    /// The same original supervisor or preparation refused publication.
    #[error("original actor supervision refused: {0}")]
    Supervision(#[from] HostSupervisionError),
    /// The same closed actor publication or external native credit refused.
    #[error("original actor account custody refused: {0}")]
    ActorAccounts(#[from] crucible_qemu::OriginalActorAccountError),
}

/// Runs the private actor through its authenticated parent and closed publisher.
///
/// The same consumed origin reaches the original supervisor; this entry cannot
/// receive a caller-authored bank, reset a clock or infer a launch permission
/// from an image inventory. The compiled workflow must subsequently select the
/// genuine packaged service and retain its same factory through retirement.
///
/// # Errors
/// Refuses original parent authentication or account publication. Until the
/// immutable workflow package is installed, retains the published custody and
/// refuses factory effects rather than substituting actor arguments.
pub fn run_original_actor() -> Result<(), MeasurementRuntimeAdmissionError> {
    let invocation = AuthenticatedParentInvocation::receive_original()?;
    let issuer = OriginalActorRoleIssuer::admit_parent(invocation)?;
    issuer.require_original()?;
    let mut workflow = workflow::OriginalResidentWorkflowOwner::load(&issuer)?;
    let mut policy = workflow.take_service_policy()?;
    let catalog_purpose = policy.take_catalog_purpose()?;
    let campaign_digest = *policy.campaign_policy_digest();
    let projection_digest = *policy.campaign_policy_projection_digest();
    workflow.prepare_campaign_policy(&projection_digest, &campaign_digest)?;
    let mut sqlite = issuer.prepare_workflow_sqlite(policy)?;
    let heap = workflow.install_sqlite(&mut sqlite, &campaign_digest)?;
    issuer.require_original()?;
    workflow.prepare_campaign_state(&heap)?;
    workflow.prepare_catalog_owner(&issuer)?;
    workflow.prepare_campaign_graph(catalog_purpose, &heap)?;
    workflow.prepare_campaign_refs()?;
    workflow.prepare_campaign_repository()?;
    // Process-global SQLite bootstrap/H outlive a stack facade. The same
    // issuer already retains their original payment; a late service refusal
    // must not report heap-handle Drop as native process retirement.
    std::mem::forget(heap);

    let purpose = "original-paid campaign retention, transfer journal and prepared service";
    let stage = OriginalServiceStage::RetainedCampaignService;
    workflow.close_campaign_repository().map_err(|source| {
        MeasurementRuntimeAdmissionError::MissingContinuationCleanup {
            stage,
            cleanup: OriginalServiceCleanup::Repository(source),
        }
    })?;
    workflow.close_campaign_refs().map_err(|source| {
        MeasurementRuntimeAdmissionError::MissingContinuationCleanup {
            stage,
            cleanup: OriginalServiceCleanup::References(source),
        }
    })?;
    workflow.close_campaign_graph().map_err(|source| {
        MeasurementRuntimeAdmissionError::MissingContinuationCleanup {
            stage,
            cleanup: OriginalServiceCleanup::Graph(source),
        }
    })?;
    if let Err(cleanup) = workflow.close_catalog_owner() {
        return Err(
            MeasurementRuntimeAdmissionError::MissingCatalogPurposeCleanup { stage, cleanup },
        );
    }
    if let Err(cleanup) = workflow.close_campaign_state() {
        return Err(
            MeasurementRuntimeAdmissionError::MissingServicePurposeCleanup { stage, cleanup },
        );
    }
    Err(MeasurementRuntimeAdmissionError::MissingPurpose(purpose))
}
