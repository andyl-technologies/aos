//! Reusable charged ownership for bounded local campaign runs.
//!
//! One caller-owned session retains the original durable ledger, capacity
//! actor, registry and catalog quota across independent accepted assignments.
//! Compatibility is fixed by the first run; no request can replace authority
//! or restart a previous execution's host deadline.

use super::*;

mod operation_error;
pub(crate) use operation_error::RetainedOperationError;
mod reproduction;
use crate::executor_pool::{CampaignActorPort, PreparedExecutorActor};
use crucible_cas::content_store::StorePhysicalQuotaGuard;
pub(crate) use reproduction::{CompletedReproductionBasis, CompletedReproductionError};
use std::sync::atomic::{AtomicU64, Ordering};

mod continuation;
mod finding_branch;
mod finding_midpoint;
mod imported;
pub use finding_midpoint::{GuardedFindingMidpointError, GuardedImportedFindingMidpoint};

/// Preserves the original packaged actor across the public listener handoff.
pub(super) struct PackagedGuardedState {
    pub(super) actor: CampaignActorPort<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
    pub(super) config: PackagedQemuExecutorConfig,
    pub(super) checkpoints: Arc<ExactCheckpointStore>,
    pub(super) host:
        Option<SharedQemuAttemptHostResourceFactory<LinuxQemuAttemptHostResourceFactory>>,
}

pub(crate) struct GuardedOwnerInner {
    pub(crate) actor: CampaignActorPort<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
    pub(crate) config: PackagedQemuExecutorConfig,
    pub(crate) repository: Arc<CampaignRepository>,
    pub(crate) planner: crucible_campaign::PlannerAuthorityKey,
    debugger: Option<crucible_campaign::DebuggerAuthorityKey>,
    pub(crate) checkpoints: Arc<ExactCheckpointStore>,
    pub(crate) host: SharedQemuAttemptHostResourceFactory<LinuxQemuAttemptHostResourceFactory>,
    admission: PackagedAttemptAdmission,
    profile: Mutex<Option<ExecutorCompatibilityProfile>>,
    sequence: AtomicU64,
    _quota: Option<Arc<dyn StorePhysicalQuotaGuard>>,
    imported_guest_assets: Option<Arc<dyn Send + Sync>>,
    _preparation:
        Option<PreparedExecutorActor<DirectoryAssignmentLedger, PackagedAttemptAdmission>>,
}

impl GuardedOwnerInner {
    pub(crate) fn journal_root(&self) -> PathBuf {
        self.config
            .lifecycle
            .run_state_root()
            .join("guarded-campaign")
            .join("prepared-results")
    }
}

/// Retains one genuine execution owner across local run and replay requests.
///
/// Clones share the original capacity ledger, catalog namespace and Linux host
/// allocator. Each submitted assignment receives its own original execution
/// capability and supervision guard. Durable bytes remain charged until their
/// enclosing catalog is explicitly retired.
#[derive(Clone)]
pub struct GuardedCampaignOwner {
    pub(crate) inner: Arc<GuardedOwnerInner>,
}

impl GuardedCampaignOwner {
    /// Returns the owner's admitted durable checkpoint publication store.
    ///
    /// Clones retain its authentic repository root leases. Callers must not
    /// replace it with a temporary store derived from modeled guest disk limits.
    #[must_use]
    pub fn checkpoints(&self) -> Arc<ExactCheckpointStore> {
        self.inner.checkpoints.clone()
    }

    /// Admits complete deployed resources before opening the guarded repository.
    ///
    /// # Errors
    /// Refuses incomplete entitlement, exhausted aggregate capacity, competing
    /// ledger or quota ownership, unsupported containment, and unavailable
    /// durable storage or Linux host-resource authority.
    pub fn open(config: PackagedQemuExecutorConfig) -> Result<Self, PackagedQemuExecutorError> {
        let admission = PackagedAttemptAdmission::default();
        let (actor, registry) = preparation::prepare_owner(&config, admission.clone())?;
        ram_catalog::admit_catalog_service(&config, &registry)?;
        let root = config.lifecycle.run_state_root().join("guarded-campaign");
        let storage = config
            .ram_catalog()
            .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?
            .open_guarded_storage(&root)?;
        let planner = crucible_campaign::PlannerAuthorityKey::from_bytes([0x31; 32])?;
        let debugger = crucible_campaign::DebuggerAuthorityKey::from_bytes([0x47; 32])?;
        let repository = Arc::new(CampaignRepository::with_component_authorities(
            storage.backend.clone(),
            storage.refs,
            planner.clone(),
            debugger.clone(),
        )?);
        let checkpoints = Arc::new(
            ExactCheckpointStore::new(
                storage.backend,
                config.maximum_checkpoint_bytes,
                repository.ram_retention_authority(),
            )?
            .with_ram_root_resources(storage.quota.clone()),
        );
        let host = SharedQemuAttemptHostResourceFactory::new(
            LinuxQemuAttemptHostResourceFactory::open(config.host.clone())?,
        );
        Ok(Self {
            inner: Arc::new(GuardedOwnerInner {
                actor: actor.campaign_port(),
                config,
                repository,
                planner,
                debugger: Some(debugger),
                checkpoints,
                host,
                admission,
                profile: Mutex::new(None),
                sequence: AtomicU64::new(0),
                _quota: Some(storage.quota),
                imported_guest_assets: None,
                _preparation: Some(actor),
            }),
        })
    }

    pub(super) fn from_packaged(
        state: &PackagedGuardedState,
        repository: Arc<CampaignRepository>,
        planner: crucible_campaign::PlannerAuthorityKey,
    ) -> Result<Self, PackagedQemuExecutorError> {
        use crucible_api::host_operational::HostOperationalError;
        let host = state
            .host
            .clone()
            .ok_or(HostOperationalError::Unavailable)?;
        let admission = state
            .actor
            .with_supervisor(|actor| Ok(actor.admission_validator().as_ref().clone()))?;
        let profile = admission
            .get()
            .map_err(|_| HostOperationalError::Unavailable)?
            .profile
            .clone();
        let quota = repository
            .blob_backend()
            .metadata_resources()
            .map_err(crucible_campaign::CampaignRepositoryError::from)?;
        Ok(Self {
            inner: Arc::new(GuardedOwnerInner {
                actor: state.actor.clone(),
                config: state.config.clone(),
                repository,
                planner,
                debugger: None,
                checkpoints: state.checkpoints.clone(),
                host,
                admission,
                profile: Mutex::new(Some(profile)),
                sequence: AtomicU64::new(0),
                _quota: Some(quota),
                imported_guest_assets: None,
                _preparation: None,
            }),
        })
    }

    pub(crate) fn validate_submission(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<crate::executor_supervisor::ValidatedSubmitAdmission, ExecutorRejection> {
        crate::executor_supervisor::ValidatedSubmitAdmission::validate(
            &self.inner.admission,
            request,
        )
    }

    pub(crate) fn replay_services(
        &self,
    ) -> Result<RetainedTemplateServiceFactory, crucible_api::host_operational::HostOperationalError>
    {
        let registry = self
            .inner
            .actor
            .with_supervisor(|actor| Ok(actor.host_operational_registry()))?;
        let factory = RetainedTemplateServiceFactory::from_owner(
            registry,
            self.inner.actor.capacity_custody(),
            &self.inner.config,
        );
        Ok(match &self.inner.imported_guest_assets {
            Some(assets) => factory.with_input_retention(Arc::clone(assets)),
            None => factory,
        })
    }

    pub(crate) fn bind_profile(
        &self,
        profile: ExecutorCompatibilityProfile,
        scenarios: BTreeSet<ScenarioArtifactId>,
    ) -> Result<(), crucible_api::host_operational::HostOperationalError> {
        use crucible_api::host_operational::HostOperationalError;
        let mut current = self
            .inner
            .profile
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        if let Some(current) = &*current {
            if current != &profile {
                return Err(HostOperationalError::Unavailable);
            }
            let admitted = self
                .inner
                .admission
                .get()
                .map_err(|_| HostOperationalError::Unavailable)?;
            return if scenarios.is_subset(&admitted.scenarios) {
                Ok(())
            } else {
                Err(HostOperationalError::Unavailable)
            };
        }
        self.inner
            .admission
            .bind(self.inner.repository.clone(), profile.clone(), scenarios)?;
        *current = Some(profile);
        Ok(())
    }

    pub(crate) fn campaign(
        &self,
        seed: crucible::Seed,
    ) -> Result<CampaignName, CampaignCodecError> {
        let ordinal = self
            .inner
            .sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CampaignCodecError::InvalidValue {
                reason: "guarded campaign operation ordinal exhausted",
            })?;
        CampaignName::new(format!(
            "guarded-campaign-run-{:016x}-{ordinal:016x}",
            seed.decision_rng_root_seed()
        ))
    }
}
