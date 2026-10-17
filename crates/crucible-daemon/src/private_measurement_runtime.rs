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

pub use actor_roles::{
    OriginalActorRoleIssuer, OriginalPackagedPreparationError, OriginalPreparedPackagedExecutor,
};
pub use catalog::OriginalActorCatalogOwner;
pub use workflow::{
    OriginalWorkflowArtifactsError, OriginalWorkflowCloseError, OriginalWorkflowInputError,
    OriginalWorkflowReadError,
};

/// Retains the actual ordered local retirement refusal after campaign work.
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

/// Preserves the genuine fresh service-support catalog before its original postcut.
#[derive(Debug, thiserror::Error)]
pub enum OriginalCampaignSupportError {
    /// The genuine fallback-retention catalog refused its original ownership.
    #[error("{0}")]
    Retention(#[source] crate::hot_checkpoint_retention::OriginalRetentionError),
    /// The genuine transfer journal refused its original ownership.
    #[error("{0}")]
    Transfer(#[source] crate::campaign_transfer::OriginalJournalError),
}

/// First refusal while deriving the closed original actor from its actual issuer.
#[derive(Debug, thiserror::Error)]
pub enum MeasurementRuntimeAdmissionError {
    /// Authenticated guest files or real compact campaign import refused.
    #[error("original workflow artifacts refused: {0}")]
    WorkflowArtifacts(#[from] OriginalWorkflowArtifactsError),
    /// Actual fixed input/decode closure retained its first refusal.
    #[error("original workflow retirement refused: {0}")]
    WorkflowClose(#[from] OriginalWorkflowCloseError),
    /// The actual prepared service refused under the same original owner.
    #[error("original prepared service refused: {0}")]
    PreparedService(#[from] crate::campaign_bootstrap::OriginalPreparedServiceError),
    /// Genuine retention/journal ownership refused without a replacement bank.
    #[error("original campaign support refused: {0}")]
    CampaignSupport(#[from] OriginalCampaignSupportError),
    /// Actual ordered local cleanup retained its initiating refusal.
    #[error("original local retirement refused: {0}")]
    RetirementCleanup(#[source] OriginalServiceCleanup),
    /// The genuine repository retained its original control admission cause.
    #[error("original campaign repository refused: {0}")]
    CampaignRepository(#[source] crucible_cas::content_store::StoreError),
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
    /// Actual catalog closure retained the same paid owner and refusal.
    #[error("original catalog retirement refused: {0}")]
    CatalogRetirement(
        #[source] crate::private_measurement_runtime::catalog::OriginalActorCatalogOwner,
    ),
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
/// Successful return acknowledges local campaign and executor retirement.
/// Process-global bootstrap and issuer custody remain in this process until
/// the genuine PID1 observes its real Child exit; external whole-VM payment
/// closes only after that parent's actual VM join and resource-owner finish.
///
/// # Errors
/// Preserves actual authentication, account, input, authorization, factory,
/// campaign execution and local retirement refusals. An unqualified native
/// purpose still refuses before birth; no success is inferred from this route.
pub fn run_original_actor() -> Result<(), MeasurementRuntimeAdmissionError> {
    let invocation = AuthenticatedParentInvocation::receive_original()?;
    let mut issuer = OriginalActorRoleIssuer::admit_parent(invocation)?;
    issuer.require_original()?;
    let mut workflow = workflow::OriginalResidentWorkflowOwner::load(&issuer)?;
    let mut policy = workflow.take_service_policy()?;
    let launch = policy.take_launch_purpose()?;
    workflow.prepare_component_authorities(&launch)?;
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
    workflow.prepare_ram_catalog_provider(&heap)?;
    workflow.prepare_campaign_refs()?;
    workflow.prepare_campaign_repository()?;
    workflow.prepare_campaign_support()?;
    workflow.prepare_service(launch)?;
    // Process-global SQLite bootstrap/H outlive a stack facade. The same
    // issuer already retains their original payment; a late service refusal
    // must not report heap-handle Drop as native process retirement.
    std::mem::forget(heap);
    workflow.import_fixed_campaign_inputs()?;

    let mut executor = workflow.prepare_genuine_executor(&mut issuer)?;
    workflow.execute_campaigns(&executor)?;
    workflow.retire_executor(&mut executor)?;
    drop(executor);
    workflow.close_artifacts()?;
    workflow.close_prepared_service()?;
    workflow.close_campaign_support()?;
    workflow.close_campaign_policy()?;
    workflow.close_campaign_repository().map_err(|cause| {
        MeasurementRuntimeAdmissionError::RetirementCleanup(OriginalServiceCleanup::Repository(
            cause,
        ))
    })?;
    workflow.close_campaign_refs().map_err(|cause| {
        MeasurementRuntimeAdmissionError::RetirementCleanup(OriginalServiceCleanup::References(
            cause,
        ))
    })?;
    workflow.close_campaign_graph().map_err(|cause| {
        MeasurementRuntimeAdmissionError::RetirementCleanup(OriginalServiceCleanup::Graph(cause))
    })?;
    workflow
        .close_catalog_owner()
        .map_err(MeasurementRuntimeAdmissionError::CatalogRetirement)?;
    workflow.close_campaign_state()?;
    workflow.close_inputs(&issuer)?;
    drop(workflow);
    drop(sqlite);

    // This is a local success acknowledgement, never a process-global refund.
    // PID1 observes the actual actor Child exit before sending completion; the
    // external parent retains its same whole pair through real VM join/finish.
    issuer.retain_until_parent_reap()
}
