//! Creation preflight over the actual imported execution-model artifact schema.

use super::*;
use crucible_campaign::{
    CampaignAuthorizationError, CampaignPrincipal, CampaignPrincipalAuthorizer,
    CampaignRepositoryError, CampaignService, CampaignServiceFailure, CampaignServiceFailureSource,
    CampaignServiceOperation, CreateCampaignRequest, RepositoryCampaignService,
    RepositoryCampaignServiceError,
};

struct CreationAuthority(CampaignHash);

impl CampaignPrincipalAuthorizer for CreationAuthority {
    fn authorize(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        campaign: &CampaignName,
        request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        if principal.as_str() == "creation-test"
            && operation == CampaignServiceOperation::CreateCampaign
            && campaign.as_str() == "current-artifact"
            && request_digest == self.0
        {
            Ok(())
        } else {
            Err(CampaignAuthorizationError::Unauthorized)
        }
    }
}

#[test]
fn campaign_creation_refuses_obsolete_schema_and_accepts_actual_imported_basis()
-> Result<(), Box<dyn std::error::Error>> {
    let scenario = crucible::happy_path_scenario()?.scenario;
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("creation-schema", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    let scenario_id = store.import_scenario(&scenario)?;
    let genesis_id = store.import_configuration(&scenario, &Schedule::empty())?;
    let imported_scenario = repository.load_scenario_artifact(scenario_id)?;
    let imported_genesis = repository.load_configuration_artifact(genesis_id)?;
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            imported_scenario.scenario(),
            CampaignSeed::from_bytes([42; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 1,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0)?,
            RetentionPolicy::new(true, 1, true, true),
            false,
        ),
    )?;

    for schema in [3, imported_scenario.payload_schema()] {
        let lineage = CampaignLineage::new(
            imported_scenario.scenario(),
            scenario_id,
            imported_genesis.configuration(),
            genesis_id,
            "creation-test",
            "codec-test",
            crate::packaged_qemu_identity::packaged_qemu_protocol_versions(),
            schema,
            crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        )?;
        let request = CreateCampaignRequest::new(
            CampaignPrincipal::new("creation-test")?,
            CampaignName::new("current-artifact")?,
            lineage,
            policy.clone(),
        )?;
        let service = RepositoryCampaignService::new(
            &repository,
            CreationAuthority(request.request_digest()),
        );
        let result = service.create_campaign(&request);
        if schema == 3 {
            let error = result
                .err()
                .ok_or("obsolete schema unexpectedly created a campaign")?;
            assert!(matches!(
                error,
                RepositoryCampaignServiceError::Repository(CampaignRepositoryError::Integrity {
                    reason: "lineage-execution-model-artifact-mismatch"
                })
            ));
            assert_eq!(
                error.campaign_service_failure(),
                CampaignServiceFailure::IntegrityFailure
            );
            assert!(matches!(
                repository.head("current-artifact"),
                Err(CampaignRepositoryError::NotFound)
            ));
        } else {
            let created = result?;
            created.validate_for(&request)?;
            assert_eq!(
                repository.head("current-artifact")?.snapshot_id(),
                created.snapshot()
            );
            assert_eq!(
                service.create_campaign(&request)?.snapshot(),
                created.snapshot()
            );
        }
    }
    Ok(())
}
