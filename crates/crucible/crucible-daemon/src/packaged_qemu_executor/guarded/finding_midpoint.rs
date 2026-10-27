//! Receiver archive publication and fresh charged finding debug realizations.

use super::*;
use crate::imported_checkpoint::{
    AuthenticatedImportedCheckpoint, ImportedCheckpointAdmission, ReceiverCheckpointPolicy,
};
use crucible_campaign::{
    CampaignArchiveCheckpointResolver, CampaignArchiveCheckpointSelection, CampaignArchiveLease,
    CampaignArchiveManifestId, CampaignArchivePlan, CampaignArchivePolicy, CampaignFactId,
    ConfigurationId, ExactCheckpointId, FindingId,
};
use crucible_store::content_store::DurabilityRequirement;
use crucible_store::owned_decode::DecodeBudget;
use crucible_store::ram::RamStoreError;

#[cfg(test)]
mod tests;

const FINDING_BUNDLE_ARCHIVE_NAME: &str = "exported-finding-bundle";

/// Retains the named source archive until one destination publication succeeds.
///
/// The reader claim replaces a lifetime source GC exclusion. Copying acquires
/// only the destination exclusion, and the handoff runs before that exclusion
/// and the source claim are released in that order.
struct RetainedFindingArchiveTransfer<'a> {
    source: &'a CampaignRepository,
    destination: &'a CampaignRepository,
    archive: CampaignArchiveManifestId,
    source_lease: CampaignArchiveLease,
}

impl<'a> RetainedFindingArchiveTransfer<'a> {
    /// Installs an independent source owner for the exact bundle archive.
    ///
    /// # Errors
    /// Returns an error when the named source archive changed, its reader claim
    /// cannot be published, or the original operation boundary is refused.
    fn retain(
        source: &'a CampaignRepository,
        destination: &'a CampaignRepository,
        archive: CampaignArchiveManifestId,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<Self, CampaignRepositoryError> {
        let source_lease = source.retain_campaign_archive_ref_with_boundary(
            FINDING_BUNDLE_ARCHIVE_NAME,
            archive,
            boundary,
        )?;
        Ok(Self {
            source,
            destination,
            archive,
            source_lease,
        })
    }

    /// Copies the retained archive and installs its destination successor.
    ///
    /// The handoff runs while destination GC remains excluded. Its successful
    /// result must therefore be produced only after publishing an ordinary
    /// archive ref. Failure releases partial destination objects without
    /// replacing the initiating error.
    ///
    /// # Errors
    /// Returns the exact copy or handoff error after releasing the destination
    /// exclusion before the independent source reader claim.
    fn transfer_with_handoff<T, E>(
        self,
        plan: &CampaignArchivePlan,
        durability: DurabilityRequirement,
        source_original: Option<&DecodeBudget>,
        destination_original: Option<&DecodeBudget>,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
        handoff: impl FnOnce(&mut dyn FnMut() -> Result<(), RamStoreError>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<CampaignRepositoryError>,
    {
        let Self {
            source,
            destination,
            archive,
            source_lease,
        } = self;
        if plan.manifest_id() != archive {
            return Err(E::from(CampaignRepositoryError::Integrity {
                reason: "retained-finding-archive-plan-mismatch",
            }));
        }
        let destination_gc = destination.acquire_gc_exclusion_guard().map_err(E::from)?;
        let result = source
            .transfer_campaign_archive_objects_with_boundary(
                destination,
                plan,
                durability,
                source_original,
                destination_original,
                boundary,
            )
            .map_err(E::from)
            .and_then(|_| handoff(boundary));

        // The published destination root, when present, precedes source claim
        // retirement. On failure, partial destination objects remain orphaned.
        drop(destination_gc);
        drop(source_lease);
        result
    }
}

/// A receiver-published finding and its original full resource owner.
///
/// Clones share immutable metadata and the charged owner. Each debug admission
/// authenticates a fresh one-use import claim and reserves a distinct Service.
#[derive(Clone)]
pub struct GuardedImportedFindingMidpoint {
    inner: Arc<GuardedFindingMidpointInner>,
}

struct GuardedFindingMidpointInner {
    owner: GuardedCampaignOwner,
    midpoint: crate::ArchivedFindingDebugMidpoint,
    decoding: crucible_engine::owned_decode::DecodeBudget,
    archive: String,
    campaign: CampaignName,
    selections: PathBuf,
}

impl GuardedImportedFindingMidpoint {
    /// Returns the complete receiver-authenticated checkpoint selection.
    #[must_use]
    pub fn midpoint(&self) -> &crate::ArchivedFindingDebugMidpoint {
        &self.inner.midpoint
    }

    /// Admits a fresh paused, read-only native session on the original actor.
    ///
    /// # Errors
    /// Refuses changed publication or pins, exhausted full resource capacity,
    /// incompatible native state, cancellation, or uncertain cleanup.
    pub async fn admit_read_only_session(
        &self,
    ) -> Result<crate::ArchivedFindingDebugSession, GuardedFindingMidpointError> {
        let replay = self.restore()?;
        self.inner
            .midpoint
            .admit_imported_read_only_session(replay, self.inner.decoding.clone())
            .await
            .map_err(GuardedFindingMidpointError::from)
    }

    /// Returns the original admitted receiver checkpoint reader.
    #[must_use]
    pub fn checkpoints(&self) -> Arc<ExactCheckpointStore> {
        self.inner.owner.checkpoints()
    }

    /// Returns the quota-backed receiver repository retained by this owner.
    #[must_use]
    pub fn repository(&self) -> Arc<CampaignRepository> {
        self.inner.owner.inner.repository.clone()
    }

    /// Returns the receiver campaign authenticated from this archive.
    #[must_use]
    pub fn campaign(&self) -> &CampaignName {
        &self.inner.campaign
    }

    /// Returns the same capacity actor for independently accepted branch work.
    #[must_use]
    pub fn owner(&self) -> GuardedCampaignOwner {
        self.inner.owner.clone()
    }

    /// Admits two independent read-only worlds for branch-local debug edits.
    ///
    /// # Errors
    /// Refuses changed pins, insufficient aggregate capacity, failed restore,
    /// or unproven cleanup. Both worlds retain their independent Service.
    pub async fn admit_debug_session_pair(
        &self,
    ) -> Result<crate::ArchivedFindingDebugSessionPair, GuardedFindingMidpointError> {
        let mut canonical = self.restore()?;
        let branch = match self.restore() {
            Ok(branch) => branch,
            Err(error) => {
                let _ = canonical.finish();
                return Err(error);
            }
        };
        self.inner
            .midpoint
            .admit_imported_debug_session_pair(canonical, branch, self.inner.decoding.clone())
            .await
            .map_err(GuardedFindingMidpointError::from)
    }

    fn restore(
        &self,
    ) -> Result<
        crate::qemu_baked_genesis::ImportedProductionCheckpointReplay,
        GuardedFindingMidpointError,
    > {
        let _decode_scope = self.inner.decoding.enter();
        let cancellation = ExecutionCancellation::default();
        let authentication = self.inner.owner.prepare_authentication_source(
            self.inner.midpoint.source(),
            cancellation.clone(),
            crucible_host_resources::host_supervision::HostOperationClass::Preparation,
        )?;
        authentication.check()?;
        let mut selections =
            crate::DirectoryExactPinMaterializationStore::open(&self.inner.selections)?;
        let head = self
            .inner
            .owner
            .inner
            .repository
            .head(self.inner.campaign.as_str())?;
        let resources = self.inner.owner.inner.config.assignment_limits().ok_or(
            GuardedFindingMidpointError::Refused("semantic ceiling is absent"),
        )?;
        let mut boundary = || {
            authentication
                .check()
                .map_err(|_| RamStoreError::Canceled)?;
            if cancellation.is_canceled() {
                Err(RamStoreError::Canceled)
            } else {
                Ok(())
            }
        };
        let imported = AuthenticatedImportedCheckpoint::prepare(
            ImportedCheckpointAdmission {
                repository: self.inner.owner.inner.repository.clone(),
                checkpoints: &self.inner.owner.inner.checkpoints,
                selections: &mut selections,
                archive: &self.inner.archive,
                campaign: &self.inner.campaign,
                configuration: ConfigurationId::from_hash(CampaignHash::from_bytes(
                    self.inner.midpoint.configuration().id().bytes,
                )),
                policy: ReceiverCheckpointPolicy {
                    lineage: head.snapshot().lineage(),
                    policy: head.snapshot().active_policy(),
                    resources,
                    resource_ceiling: resources,
                },
                context: authentication.context()?,
            },
            &mut boundary,
        )?;
        if imported.checkpoint() != self.inner.midpoint.checkpoint() {
            return Err(GuardedFindingMidpointError::Refused(
                "receiver midpoint changed",
            ));
        }
        let replay = self
            .inner
            .owner
            .begin_imported_checkpoint(imported, cancellation)?;
        authentication.complete()?;
        // Its actual child lease keeps the parent pending through child
        // supervisor closure. Exposing that child cannot wait parent finality.
        drop(authentication);
        Ok(replay)
    }
}

impl GuardedCampaignOwner {
    /// Prepares a contained import workspace using the original catalog owner.
    ///
    /// No native process or decoded guest input is needed to establish this
    /// quota-bound directory. Its namespace remains charged by this owner.
    ///
    /// # Errors
    /// Refuses absent provider authority, escaping or replaced directories,
    /// expired original supervision, and unavailable physical quota admission.
    pub fn prepare_import_workspace(
        &self,
    ) -> Result<PathBuf, crucible_store::content_store::StoreError> {
        let lifecycle = &self.inner.config.lifecycle;
        let provider = lifecycle.ram_catalog_provider().ok_or(
            crucible_store::content_store::StoreError::Unsupported {
                capability: "import-catalog-provider",
            },
        )?;
        let directory = lifecycle.run_state_root().join("finding-inputs");
        provider.prepare_directory(&directory)?;
        Ok(directory)
    }

    /// Returns the original admitted namespace's metadata resource authority.
    ///
    /// # Errors
    /// Refuses a backend without one authentic shared resource authority.
    pub fn repository_metadata_resources(
        &self,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, crucible_store::content_store::StoreError> {
        self.inner.repository.blob_backend().metadata_resources()
    }

    /// Borrows the original metadata admission retained by the repository owner.
    ///
    /// Independent readers derive children from this parent before opening
    /// inputs. Reusing it preserves earlier refusals and namespace cancellation.
    ///
    /// # Errors
    /// Refuses a repository without original namespace metadata admission.
    pub fn repository_decode_budget(
        &self,
    ) -> Result<
        &crucible_engine::owned_decode::DecodeBudget,
        crucible_store::content_store::StoreError,
    > {
        self.inner.repository.ram_admission().original().ok_or(
            crucible_store::content_store::StoreError::Unsupported {
                capability: "decoded-metadata-resources",
            },
        )
    }

    /// Adopts authenticated guest inputs before this owner is shared or used.
    ///
    /// Executable, plugin, contained namespace and catalog provider remain
    /// fixed by original admission. This consumes the sole unused owner rather
    /// than reopening its actor, quota or resource deadline.
    ///
    /// # Errors
    /// Refuses native identity changes, absent provider authority, a shared or
    /// already used owner, or a previously sealed compatibility profile.
    pub fn with_imported_lifecycle(
        mut self,
        lifecycle: ProductionVmLifecycleConfig,
    ) -> Result<Self, GuardedFindingMidpointError> {
        let inner = Arc::get_mut(&mut self.inner).ok_or(GuardedFindingMidpointError::Refused(
            "import owner was already shared",
        ))?;
        if inner.sequence.load(Ordering::Acquire) != 0
            || inner
                .profile
                .get_mut()
                .map_err(|_| {
                    GuardedFindingMidpointError::Refused("compatibility custody is unavailable")
                })?
                .is_some()
        {
            return Err(GuardedFindingMidpointError::Refused(
                "import owner was already used",
            ));
        }
        let admitted = &inner.config.lifecycle;
        if lifecycle.executable() != admitted.executable()
            || lifecycle.plugin() != admitted.plugin()
        {
            return Err(GuardedFindingMidpointError::Refused(
                "import native identity differs",
            ));
        }
        let provider = admitted.ram_catalog_provider().cloned().ok_or(
            GuardedFindingMidpointError::Refused("import catalog provider is absent"),
        )?;
        inner.config.lifecycle = Arc::new(
            lifecycle
                .with_run_state_root(admitted.run_state_root())
                .with_ram_catalog_provider(provider),
        );
        Ok(self)
    }

    /// Retains authenticated guest files through imported worlds and quarantine.
    ///
    /// # Errors
    /// Refuses a shared or used owner, replaced input custody, or exhausted
    /// original metadata admission.
    pub fn with_imported_guest_assets(
        mut self,
        assets: Arc<crate::MaterializedFindingReplayGuestAssets>,
    ) -> Result<Self, GuardedFindingMidpointError> {
        let inner = Arc::get_mut(&mut self.inner).ok_or(GuardedFindingMidpointError::Refused(
            "import owner was already shared",
        ))?;
        if inner.sequence.load(Ordering::Acquire) != 0 || inner.imported_guest_assets.is_some() {
            return Err(GuardedFindingMidpointError::Refused(
                "import guest custody was already sealed",
            ));
        }
        inner.imported_guest_assets = Some(assets);
        Ok(self)
    }

    /// Publishes a private authenticated finding copy under its admitted quota.
    ///
    /// Source objects and campaign refs remain unchanged. A temporary archive
    /// reader claim retains the exact source closure until the receiver's
    /// archive and campaign refs replace it. The owner must already contain
    /// the caller's exact packaged lifecycle and fault replay recipe. Imported
    /// execution rows are never installed; native launch follows full receiver
    /// archive and durable pin authentication.
    ///
    /// # Errors
    /// Refuses incomplete or substituted archives, another scenario, storage
    /// corruption, insufficient actual resources, or expired supervision.
    pub fn import_finding_midpoint(
        &self,
        source: &CampaignRepository,
        archive: CampaignArchiveManifestId,
        finding: FindingId,
        scenario: &ScenarioDefForm,
    ) -> Result<GuardedImportedFindingMidpoint, GuardedFindingMidpointError> {
        let original = self.repository_decode_budget()?;
        let decoding = original.child()?;
        let _decode_scope = decoding.enter();
        let cancellation = ExecutionCancellation::default();
        let authentication = self.prepare_authentication_source(
            scenario,
            cancellation.clone(),
            crucible_host_resources::host_supervision::HostOperationClass::Transfer,
        )?;
        let mut boundary = || {
            authentication.check().map_err(|source| {
                cancellation.cancel();
                crucible_store::content_store::StoreError::Supervision {
                    source: Box::new(source),
                }
                .into()
            })
        };
        let retained = RetainedFindingArchiveTransfer::retain(
            source,
            &self.inner.repository,
            archive,
            &mut boundary,
        )?;
        let inspected = source.inspect_campaign_archive_with_boundary(archive, &mut boundary)?;
        if inspected.manifest().policy() != CampaignArchivePolicy::Executable {
            return Err(GuardedFindingMidpointError::Refused(
                "finding archive is not executable",
            ));
        }
        let mut resolver = PublishedSelections(inspected.manifest().checkpoint_selections());
        let plan = source.plan_campaign_archive_with_boundary(
            inspected.manifest().source_snapshot(),
            CampaignArchivePolicy::Executable,
            [],
            Some(&mut resolver),
            &mut boundary,
        )?;
        if plan.manifest_id() != archive {
            return Err(GuardedFindingMidpointError::Refused(
                "receiver plan differs from archive",
            ));
        }
        let campaign = self.campaign(scenario.scenario_def().seed())?;
        let archive_name = campaign.as_str().to_owned();
        decoding.check()?;
        retained.transfer_with_handoff(
            &plan,
            DurabilityRequirement::new(1, false)?,
            source.ram_admission().original(),
            Some(original),
            &mut boundary,
            |boundary| {
                let selections_path = self
                    .inner
                    .journal_root()
                    .join(&archive_name)
                    .join("imported-pins");
                let mut selections =
                    crate::DirectoryExactPinMaterializationStore::open(&selections_path)?;
                for selection in plan.manifest().checkpoint_selections() {
                    boundary()?;
                    let prepared = crate::ExactPinMaterializationSelection::prepare_at_snapshot(
                        &self.inner.repository,
                        &self.inner.checkpoints,
                        &campaign,
                        plan.manifest().source_snapshot(),
                        selection.configuration(),
                        selection.pin_fact(),
                        selection.checkpoint(),
                    )?;
                    selections.select_import_if_absent(prepared)?;
                }
                self.inner.repository.publish_campaign_archive_with_boundary(
                    &archive_name,
                    None,
                    &plan,
                    boundary,
                )?;
                self.inner
                    .repository
                    .publish_transferred_campaign_with_boundary(
                        campaign.as_str(),
                        None,
                        archive,
                        boundary,
                    )?;
                let midpoint = crate::campaign_finding_handoff::prepare_archived_finding_debug_midpoint_with_boundary(
                    &self.inner.repository,
                    archive,
                    finding,
                    &self.inner.checkpoints,
                    authentication.context()?.cancellation(),
                    boundary,
                )?;
                if midpoint.source().id() != scenario.id() {
                    return Err(GuardedFindingMidpointError::Refused(
                        "finding scenario differs",
                    ));
                }
                decoding.check()?;
                decoding.charge_bytes(
                    (std::mem::size_of::<GuardedFindingMidpointInner>()
                        + 2 * std::mem::size_of::<usize>()) as u64,
                )?;
                authentication.complete()?;
                Ok(GuardedImportedFindingMidpoint {
                    inner: Arc::new(GuardedFindingMidpointInner {
                        owner: self.clone(),
                        midpoint,
                        decoding,
                        archive: archive_name,
                        campaign,
                        selections: selections_path,
                    }),
                })
            },
        )
    }
}

struct PublishedSelections<'a>(&'a [CampaignArchiveCheckpointSelection]);

impl CampaignArchiveCheckpointResolver for PublishedSelections<'_> {
    fn resolve_checkpoint(
        &mut self,
        configuration: ConfigurationId,
        pin_fact: CampaignFactId,
    ) -> Result<ExactCheckpointId, crucible_campaign::CampaignRepositoryError> {
        self.0
            .iter()
            .find(|entry| entry.configuration() == configuration && entry.pin_fact() == pin_fact)
            .map(|entry| entry.checkpoint())
            .ok_or(crucible_campaign::CampaignRepositoryError::Integrity {
                reason: "published-finding-checkpoint-selection-missing",
            })
    }
}

/// Retains a typed operational failure and its linear cleanup authority.
#[derive(Debug, thiserror::Error)]
pub enum GuardedFindingMidpointError {
    /// Authenticated receiver binding differs from the requested finding.
    #[error("guarded finding midpoint refused: {0}")]
    Refused(&'static str),
    /// The original operation failed while retaining cleanup authority.
    #[error("guarded finding midpoint: {source}")]
    Operation {
        /// Typed original failure held behind synchronized diagnostic access.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

macro_rules! operational_from {
    ($($kind:ty),+ $(,)?) => {$ (
        impl From<$kind> for GuardedFindingMidpointError {
            fn from(source: $kind) -> Self {
                Self::Operation { source: Box::new(RetainedOperationError::new(source)) }
            }
        }
    )+};
}

operational_from!(
    super::service_source::GuardedAuthenticationError,
    PackagedQemuExecutorError,
    crucible_control_api::host_operational::HostOperationalError,
    crucible_campaign::CampaignRepositoryError,
    crucible_campaign::CampaignCodecError,
    crate::ExactPinRetentionError,
    crate::CampaignFindingHandoffError,
    crate::imported_checkpoint::ImportedCheckpointError,
    crate::qemu_baked_genesis::ImportedProductionReplayError,
    crucible_host_resources::host_supervision::HostSupervisionError,
    crucible_store::content_store::StoreError,
    RamStoreError,
    crucible_engine::owned_decode::DecodeAdmissionError,
);
