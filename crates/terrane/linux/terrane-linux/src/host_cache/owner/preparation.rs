//! Retains actual native proofs before mutable cache-state initialization.

use super::NativeCacheOwnerConfig;
#[cfg(feature = "surface-fuse")]
use crate::host_quota::{NativeProject, ProjectInode, ProjectInodeBinding};
use crate::{
    host_cache::{NativeCacheStartupStage, NativeHostLayout, NativeSealCapability},
    host_quota::{HostQuotaClient, QuotaObservation, ROOT_LABELS, VerifiedQuotaObservation},
    publisher_local::client::Client,
    quota_confinement::Installed,
};
#[cfg(feature = "surface-fuse")]
use std::os::unix::fs::MetadataExt;
use std::{collections::BTreeSet, fmt, io, sync::Arc};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains real confinement, root, quota and probe custody before recovery.
///
/// Preparation creates no cache state or content files. It is not a writable
/// readiness receipt: the physical owner must still take exclusive cache-state
/// custody, perform bounded recovery, durably reconcile its accounting and
/// complete the registered publisher resume barrier before accepting writes.
pub struct NativeCachePreparation {
    pub(super) config: NativeCacheOwnerConfig,
    pub(super) confinement: Arc<Installed>,
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    quota_client: HostQuotaClient,
    observation: VerifiedQuotaObservation,
    publisher: Arc<Client<HostDomainLocation>>,
    seal: NativeSealCapability<HostDomainLocation>,
    pub(super) portable: Option<Arc<super::recovery_portable::PortableCatalog>>,
}

impl NativeCachePreparation {
    /// Borrows actual retained probe custody without creating admission authority.
    pub(super) fn probe_handle(&self) -> &std::fs::File {
        self.seal.probe_handle()
    }

    /// Retains actual readonly recovery inputs without issuing completion authority.
    ///
    /// # Errors
    /// Refuses stale confinement or replaced native domain roots.
    pub fn recovery_inspector(&self) -> io::Result<super::super::NativeRecoveryInspector> {
        self.confinement.check_current()?;
        self.layout.recheck()?;
        Ok(super::super::NativeRecoveryInspector::from_preparation(
            self,
        ))
    }

    /// Authenticates actual native custody without initializing writable state.
    ///
    /// The installed confinement receipt must originate from the current role
    /// bootstrap. Configuration is fully validated before opening native roots
    /// or connecting sockets. The actual publisher drain is an ordered barrier,
    /// not proof that cache recovery has completed.
    ///
    /// # Errors
    /// Rejects invalid configuration, another process or role, stale roots,
    /// unauthenticated/mismatched quota facts, failed publisher drain or probe,
    /// and failed independent kernel seal measurement.
    pub fn inspect(
        config: NativeCacheOwnerConfig,
        confinement: Arc<Installed>,
    ) -> io::Result<Self> {
        Self::inspect_with_stage(
            config,
            confinement,
            &mut NativeCacheStartupStage::Configuration,
        )
    }

    /// Observes preparation without exposing private source text or changing errors.
    ///
    /// # Errors
    /// Returns the same validation, custody and recovery failures as the public opener.
    pub(crate) fn inspect_with_stage(
        config: NativeCacheOwnerConfig,
        confinement: Arc<Installed>,
        stage: &mut NativeCacheStartupStage,
    ) -> io::Result<Self> {
        *stage = NativeCacheStartupStage::Configuration;
        config.validate()?;
        *stage = NativeCacheStartupStage::Confinement;
        confinement.check_current()?;
        *stage = NativeCacheStartupStage::ProcessIdentity;
        if rustix::process::geteuid().as_raw() != config.content_uid {
            return Err(invalid(
                "cache process does not have the configured content UID",
            ));
        }
        let primary_group = rustix::process::getegid().as_raw();
        let groups = rustix::process::getgroups()?;
        for required in [config.content_gid, config.state_gid] {
            if primary_group != required && !groups.iter().any(|group| group.as_raw() == required) {
                return Err(invalid(
                    "cache role lacks configured content or state group",
                ));
            }
        }
        *stage = NativeCacheStartupStage::NativeLayout;
        let layout = Arc::new(NativeHostLayout::inspect_with_administrative_root(
            config.location.clone(),
            config.administrative_root.as_deref(),
        )?);
        *stage = NativeCacheStartupStage::ContentCustody;
        check_content_custody(&config, &layout)?;
        *stage = NativeCacheStartupStage::QuotaConnect;
        let mut quota_client =
            HostQuotaClient::connect(&config.quota_socket, 0, config.quota_epoch)?;
        *stage = NativeCacheStartupStage::QuotaObservation;
        let observation = quota_client.query(&config.quota_owner, config.location.domain())?;
        check_observation(&config, &layout, &observation)?;

        // Client owns its configuration; retain the validated owner settings
        // separately for later recovery and repeated authenticated quota reads.
        let publisher_config = crate::publisher_local::client::ClientConfig {
            socket_path: config.publisher.socket_path.clone(),
            identities: config.publisher.identities,
            chunk_profile_name: config.publisher.chunk_profile_name.clone(),
            wait_budget_ms: config.publisher.wait_budget_ms,
        };
        *stage = NativeCacheStartupStage::PublisherConnect;
        let publisher = Client::connect(publisher_config, Arc::clone(&layout))
            .map_err(|source| publisher_failure("connect", source))?;
        *stage = NativeCacheStartupStage::PublisherDrain;
        publisher
            .drain()
            .map_err(|source| publisher_failure("drain", source))?;
        *stage = NativeCacheStartupStage::PublisherSealProbe;
        let probe = publisher
            .probe()
            .map_err(|source| publisher_failure("seal probe", source))?;
        *stage = NativeCacheStartupStage::SealVerification;
        let seal = NativeSealCapability::from_probe(probe)?;
        *stage = NativeCacheStartupStage::FinalCustody;
        confinement.check_current()?;
        layout.recheck()?;
        Ok(Self {
            config,
            confinement,
            layout,
            quota_client,
            observation,
            publisher: Arc::new(publisher),
            seal,
            portable: None,
        })
    }

    /// Records checked catalog bytes for independent native namespace comparison.
    pub(in crate::host_cache) fn bind_portable_catalog(
        &mut self,
        snapshot: &terrane_sdk::bucket::portable_reader::ValidatedPortableBucket,
    ) -> io::Result<()> {
        if snapshot.root() != self.config.location.root() || self.portable.is_some() {
            return Err(invalid(
                "portable catalog belongs to another root or was already bound",
            ));
        }
        self.portable = Some(Arc::new(super::recovery_portable::PortableCatalog::new(
            snapshot,
        )?));
        Ok(())
    }

    /// Borrows the actual retained physical domain and provisioning guard.
    pub fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        &self.layout
    }

    /// Reauthenticates current partition facts while retaining all custody.
    ///
    /// This refresh does not turn kernel charged-and-reserved usage into
    /// synchronized physical inode allocation or future policy capacity.
    ///
    /// # Errors
    /// Returns errors for stale confinement, roots, seal support or helper
    /// observations. Failed refresh never replaces the previous observation.
    pub fn recheck(&mut self) -> io::Result<()> {
        self.confinement.check_current()?;
        self.seal.recheck()?;
        check_content_custody(&self.config, &self.layout)?;
        let next = self
            .quota_client
            .query(&self.config.quota_owner, self.config.location.domain())?;
        check_observation(&self.config, &self.layout, &next)?;
        self.observation = next;
        Ok(())
    }

    /// Combines authenticated namespace custody with the actual unlinked probe.
    ///
    /// The original probe is retained through the helper's quota query. It was
    /// created under a private exclusive name and unlinked before receipt, so
    /// the subsequent namespace walk cannot count it. No bare count or caller
    /// descriptor substitutes for this privately minted original probe.
    #[cfg(feature = "surface-fuse")]
    pub(super) fn exposure_inodes_closed(
        &mut self,
        excluded: &[ProjectInodeBinding],
    ) -> io::Result<bool> {
        self.confinement.check_current()?;
        self.seal.recheck()?;
        check_content_custody(&self.config, &self.layout)?;
        let probe = self.seal.probe_handle();
        let before = probe.metadata()?;
        let identity = ProjectInode {
            device: before.dev(),
            inode: before.ino(),
        };
        if before.nlink() != 0
            || !before.is_file()
            || before.len() != 0
            || NativeProject::inspect(probe)?.project_id != self.config.project_id
            || identity.device != self.layout.directory_binding("objects")?.0
            || excluded.iter().any(|binding| binding.identity == identity)
        {
            return Err(invalid(
                "closure lost its original non-excluded probe custody",
            ));
        }
        let observed = self.quota_client.query_project_incarnation_census(
            &self.config.quota_owner,
            self.config.location.domain(),
            excluded,
        )?;
        check_quota_value(&self.config, &self.layout, observed.quota())?;
        self.seal.recheck()?;
        let after = probe.metadata()?;
        if after.dev() != before.dev()
            || after.ino() != before.ino()
            || after.nlink() != 0
            || after.len() != 0
            || NativeProject::inspect(probe)?.project_id != self.config.project_id
        {
            return Err(invalid(
                "closure probe changed through authenticated observation",
            ));
        }
        // The helper holds every counted named inode. This owner simultaneously
        // holds one distinct, already unlinked inode. Together they establish a
        // lower bound on the same actual project charge; missing other inodes
        // can delay equality but cannot create a successful closure proof.
        let retained = observed
            .observation()
            .retained_inodes
            .checked_add(1)
            .ok_or_else(|| invalid("closure retained inode count overflows"))?;
        if retained > observed.quota().charged_inodes {
            return Err(invalid(
                "closure custody exceeds actual kernel inode charge",
            ));
        }
        Ok(retained == observed.quota().charged_inodes)
    }

    /// Borrows the latest authenticated kernel charged-and-reserved observation.
    pub fn quota(&self) -> &VerifiedQuotaObservation {
        &self.observation
    }

    /// Borrows the authenticated drained publisher connection for readonly work.
    ///
    /// This exposes no resume or writable-admission authority.
    pub fn publisher(&self) -> &Client<HostDomainLocation> {
        &self.publisher
    }

    /// Retains this actual authenticated session without reconnecting its incarnation.
    pub(in crate::host_cache) fn publisher_session(&self) -> Arc<Client<HostDomainLocation>> {
        Arc::clone(&self.publisher)
    }

    /// Borrows validated configuration for the fixed readonly inspection binding.
    pub(in crate::host_cache) fn inspection_config(&self) -> &NativeCacheOwnerConfig {
        &self.config
    }

    /// Borrows the actual installed process receipt for readonly inspection.
    pub(in crate::host_cache) fn inspection_confinement(&self) -> &Arc<Installed> {
        &self.confinement
    }
}

fn check_content_custody(
    config: &NativeCacheOwnerConfig,
    layout: &NativeHostLayout<HostDomainLocation>,
) -> io::Result<()> {
    // Ordinary encoded bodies must remain movable by the publisher through
    // the shared group. O_PATH inspection works without opening private leaves
    // readably or granting the cache role access to publication state.
    for label in ["chunks", "objects", "quarantine"] {
        let directory = layout
            .directories
            .get(label)
            .ok_or_else(|| invalid("retained layout omits a required shared content directory"))?;
        let metadata = rustix::fs::fstat(directory)?;
        if metadata.st_uid != config.content_uid
            || metadata.st_gid != config.content_gid
            || metadata.st_mode & 0o7777 != 0o2770
        {
            return Err(invalid(
                "shared content directory has incorrect role custody",
            ));
        }
    }
    layout.recheck()
}

fn check_observation(
    config: &NativeCacheOwnerConfig,
    layout: &NativeHostLayout<HostDomainLocation>,
    verified: &VerifiedQuotaObservation,
) -> io::Result<()> {
    check_quota_value(config, layout, verified.observation())
}

fn check_quota_value(
    config: &NativeCacheOwnerConfig,
    layout: &NativeHostLayout<HostDomainLocation>,
    value: &QuotaObservation,
) -> io::Result<()> {
    if value.owner_id != config.quota_owner
        || value.domain != config.location.domain()
        || value.configuration_epoch != config.quota_epoch
        || value.filesystem_uuid != config.filesystem_uuid
        || value.project_id != config.project_id
        || !value.accounting
        || !value.enforcement
        || value.hard_limit_bytes != config.project_hard_limit_bytes
        || value.hard_inode_limit != config.project_hard_inode_limit
        || value.charged_reserved_bytes > value.hard_limit_bytes
        || (value.hard_inode_limit != 0 && value.charged_inodes > value.hard_inode_limit)
        || value.tier_charge_budget_bytes != config.tier_charge_budget_bytes
        || value.configured_limit_sum_bytes > value.tier_charge_budget_bytes
    {
        return Err(invalid(
            "quota observation differs from configured native owner",
        ));
    }
    let mut expected: BTreeSet<&str> = ROOT_LABELS.into_iter().collect();
    if config.administrative_root.is_some() {
        expected.insert("administrative-root");
    }
    for root in &value.roots {
        if !expected.remove(root.role_directory.as_str())
            || !root.project_inherit
            || layout.directory_binding(&root.role_directory)? != (root.device, root.inode)
        {
            return Err(invalid(
                "quota root differs from actual retained native root",
            ));
        }
    }
    if !expected.is_empty() {
        return Err(invalid(
            "quota observation omits configured allocation roots",
        ));
    }
    layout.recheck()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

// Preserve the original transport/native cause while identifying the boundary
// that failed before a physical owner could begin recovery.
#[derive(Debug)]
struct PublisherPreparationError {
    operation: &'static str,
    source: crate::publisher_local::Error,
}

impl fmt::Display for PublisherPreparationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "publisher {} failed: {}",
            self.operation, self.source
        )
    }
}

impl std::error::Error for PublisherPreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn publisher_failure(operation: &'static str, source: crate::publisher_local::Error) -> io::Error {
    io::Error::other(PublisherPreparationError { operation, source })
}
