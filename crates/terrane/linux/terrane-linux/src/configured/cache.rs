//! Opens every configured native domain through actual recovery and Running custody.
//!
//! The plan holds operator inputs only. Its opener obtains authenticated host
//! quota configuration, then independently invokes each physical native factory.
//! No decoded observation, configuration or portable snapshot grants readiness.

use super::{Preflight, ProcessRole, invalid, preflight_role};
use crate::{
    host_cache::{
        IndexRepairPolicy, NativeCacheOwnerConfig, NativeContentStore, NativePreparedObject,
        NativeReady,
    },
    host_quota::HostQuotaClient,
    publisher_local::client::ClientConfig,
    quota_confinement::Installed,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::Arc,
    time::Duration,
};
use terrane_sdk::{
    bucket::{FileBucketConfig, portable_reader::PortableReadLimits},
    config::host::{HostTier, Reassembly},
    host::cache::{
        CachePolicy, HostDomainLocation, HostReadLimits, PolicyConfig, ReassemblyMode, StateLimits,
    },
    store::StoreFailure,
};

/// Supplies explicit portable bindings and finite resources for one native domain.
///
/// These are operator settings, not quota observations or native capabilities.
/// The host-tier configuration selects the physical roots, publisher, charge
/// owner, chunk profile and retirement interval independently of this record.
pub struct NativeCacheDomainSettings {
    /// Existing portable bucket at exactly the configured native domain root.
    pub portable: FileBucketConfig,
    /// Finite bounds for each complete portable validation.
    pub portable_limits: PortableReadLimits,
    /// Private cache-state group, distinct from the publisher's content group.
    pub state_gid: u32,
    /// Finite admission and eviction policy, including consumer release grace.
    pub policy: PolicyConfig,
    /// Maximum individual encoded read allocation.
    pub reads: HostReadLimits,
    /// Maximum durable policy snapshot bytes and records.
    pub state: StateLimits,
    /// Maximum entries in a complete native recovery inventory.
    pub inventory_entries: usize,
    /// Maximum queued commands, excluding the active physical command.
    pub queued_commands: usize,
    /// Explicit future hold for metadata and snapshot synchronization.
    pub metadata_sync_hold_bytes: u64,
    /// Optional funded detached-index repair policy.
    pub index_repair: Option<IndexRepairPolicy>,
    /// Finite publisher request wait, from one through 300000 milliseconds.
    pub publisher_wait_budget_ms: u64,
    /// Whole-second consumer grant duration, from one through 300 seconds.
    pub consumer_lease_duration: Duration,
}

/// Retains a checked, complete configuration without opening native cache state.
///
/// Construction precedes irreversible confinement installation in a fresh
/// serving process. Only [`Self::open`] can produce content stores, after the
/// original physical owners complete recovery and actual publisher Resume.
pub struct NativeCachePlan {
    host: Preflight,
    domains: BTreeMap<String, NativeCacheDomainSettings>,
    reassembly: ReassemblyMode,
}

impl NativeCachePlan {
    /// Borrows one configured domain's immutable chunk profile without opening resources.
    ///
    /// This is operator intent only. A trusted caller compares it with the
    /// protected original repository profile before starting native recovery.
    pub fn chunk_profile(&self, domain: &str) -> Option<&terrane_format::chunking::ChunkProfile> {
        self.host
            .domains
            .iter()
            .find(|entry| entry.native.domain == domain)
            .map(|entry| &entry.native.profile)
    }

    /// Checks domain coverage, role identity, paths, profiles and resource policy.
    ///
    /// This performs no filesystem, publisher or quota IO. Every configured
    /// domain must have exactly one explicit resource record. Portable bindings
    /// cannot redirect a domain or substitute a different profile or seed.
    ///
    /// # Errors
    /// Refuses another process identity, unsupported wipe or profiles, missing
    /// domains, ambiguous paths, mismatched portable bindings and invalid bounds.
    pub fn new(
        host: &HostTier,
        domains: BTreeMap<String, NativeCacheDomainSettings>,
    ) -> io::Result<Self> {
        let reassembly = match host.reassembly {
            Reassembly::Never => ReassemblyMode::Never,
            Reassembly::Always => ReassemblyMode::Always,
        };
        let host = preflight_role(host, ProcessRole::Serve)?;
        if domains.len() != host.domains.len() {
            return Err(invalid("native cache resource domain coverage differs"));
        }
        if host.endpoint.identities.serve_uid == 0 || host.endpoint.identities.publish_uid == 0 {
            return Err(invalid("native cache requires distinct unprivileged roles"));
        }
        for domain in &host.domains {
            let settings = domains
                .get(&domain.native.domain)
                .ok_or_else(|| invalid("native cache domain resources missing"))?;
            settings.validate()?;
            if domain.native.content_uid != host.endpoint.identities.serve_uid
                || matches!(domain.native.content_gid, 0 | u32::MAX)
                || settings.state_gid == domain.native.content_gid
                || settings.policy.capacity > host.tier_budget
            {
                return Err(invalid(
                    "native cache resource custody or tier budget differs",
                ));
            }
            if settings.portable.root != domain.native.layout_root
                || settings.portable.chunk_profile_name != domain.profile_name
                || settings.portable.chunk_profile != domain.native.profile
            {
                return Err(invalid("portable and configured native domain differ"));
            }
        }
        Ok(Self {
            host,
            domains,
            reassembly,
        })
    }

    /// Checks explicit TOML cache resources and binds host locality to each domain.
    ///
    /// Every domain must configure its cache resource table. Portable roots and
    /// chunk profiles derive from that same domain's host configuration; neither
    /// an unrelated store expression nor repository credentials are opened.
    ///
    /// # Errors
    /// Refuses missing resources or publisher policy and every invalid binding,
    /// role identity or resource setting rejected by [`Self::new`].
    pub fn from_host(
        host: &HostTier,
        locality: terrane_format::refs::Locality,
    ) -> io::Result<Self> {
        let mut domains = BTreeMap::new();
        for (label, directory) in &host.domains {
            let cache = directory
                .cache
                .as_ref()
                .ok_or_else(|| invalid("explicit native cache resources required"))?;
            let publisher = directory
                .publisher
                .as_ref()
                .ok_or_else(|| invalid("native cache publisher profile required"))?;
            let settings = NativeCacheDomainSettings {
                portable: FileBucketConfig {
                    root: directory.path.clone().into(),
                    chunk_profile_name: publisher.chunk_profile.clone(),
                    chunk_profile: publisher.profile().map_err(io::Error::other)?,
                    locality: locality.clone(),
                    publication_control: None,
                },
                portable_limits: PortableReadLimits {
                    max_file_bytes: cache.portable.max_file_bytes,
                    max_input_bytes: cache.portable.max_input_bytes,
                    max_files: cache.portable.max_files,
                    max_selected_bytes: cache.portable.max_selected_bytes,
                },
                state_gid: cache.state_gid,
                policy: PolicyConfig {
                    capacity: cache.capacity_bytes,
                    low_watermark: cache.low_watermark_bytes,
                    probation_bytes: cache.probation_bytes,
                    release_grace: Duration::from_secs(cache.release_grace_seconds),
                    scan_limit: cache.scan_limit,
                },
                reads: HostReadLimits {
                    max_allocation_bytes: cache.max_read_bytes,
                },
                state: StateLimits {
                    bytes: cache.state_bytes,
                    records: cache.state_records,
                },
                inventory_entries: cache.inventory_entries,
                queued_commands: cache.queued_commands,
                metadata_sync_hold_bytes: cache.metadata_sync_hold_bytes,
                index_repair: cache.index_repair.map(|repair| IndexRepairPolicy {
                    max_index_bytes: repair.max_index_bytes,
                    future_hold_bytes: repair.future_hold_bytes,
                }),
                publisher_wait_budget_ms: cache.publisher_wait_budget_ms,
                consumer_lease_duration: Duration::from_secs(cache.consumer_lease_seconds),
            };
            domains.insert(label.clone(), settings);
        }
        Self::new(host, domains)
    }

    /// Opens genuinely recovered native stores under the original confinement.
    ///
    /// The caller installs confinement after checking the plan and before
    /// creating its executor. Authenticated quota queries select immutable host
    /// configuration only; every native opener independently retains the actual
    /// roots, verifies current quota custody and completes recovery and Resume.
    /// All owner configurations are validated before any domain opens mutable
    /// cache state. This never initializes missing portable buckets.
    ///
    /// Failure after opening a domain may leave genuine completed recovery
    /// effects. The caller must exit instead of resetting state or retrying
    /// under another role. Accepted work retains its original physical custody.
    ///
    /// # Errors
    /// Returns confinement, authenticated helper, partition, policy, native
    /// custody, portable validity, recovery, Resume or store-binding errors.
    pub async fn open(
        self,
        confinement: Arc<Installed>,
    ) -> io::Result<BTreeMap<String, NativeConfiguredCache>> {
        confinement.check_current()?;
        let mut helper = HostQuotaClient::connect(&self.host.quota_path, 0, self.host.quota_epoch)?;
        let mut prepared = Vec::with_capacity(self.host.domains.len());
        let mut projects = BTreeSet::new();
        let mut partition_sum = 0u64;
        let mut ledger_sum = None;
        let mut settings = self.domains;
        for domain in self.host.domains {
            let settings = settings
                .remove(&domain.native.domain)
                .ok_or_else(|| invalid("checked native domain resources disappeared"))?;
            let verified = helper.query(&domain.owner_id, &domain.native.domain)?;
            let observation = verified.observation();
            if !observation.accounting
                || !observation.enforcement
                || observation.charged_reserved_bytes > observation.hard_limit_bytes
                || (observation.hard_inode_limit != 0
                    && observation.charged_inodes > observation.hard_inode_limit)
                || observation.tier_charge_budget_bytes != self.host.tier_budget
                || observation.configured_limit_sum_bytes > self.host.tier_budget
                || ledger_sum.is_some_and(|sum| sum != observation.configured_limit_sum_bytes)
                || !projects.insert((observation.filesystem_uuid.clone(), observation.project_id))
            {
                return Err(invalid("native cache quota partition differs"));
            }
            ledger_sum = Some(observation.configured_limit_sum_bytes);
            partition_sum = partition_sum
                .checked_add(observation.hard_limit_bytes)
                .ok_or_else(|| invalid("native cache quota partition overflows"))?;

            // These authenticated scalars are expected configuration, never a
            // substitute for the native opener's fresh retained-root checks.
            let config = NativeCacheOwnerConfig {
                location: HostDomainLocation::new(
                    domain.native.layout_root,
                    domain.native.domain.clone(),
                    domain.native.profile,
                )
                .map_err(io::Error::other)?,
                administrative_root: domain.administrative_root,
                publisher: ClientConfig {
                    socket_path: self.host.endpoint.socket_path.clone(),
                    identities: self.host.endpoint.identities,
                    chunk_profile_name: domain.profile_name,
                    wait_budget_ms: settings.publisher_wait_budget_ms,
                },
                quota_socket: self.host.quota_path.clone(),
                quota_epoch: self.host.quota_epoch,
                quota_owner: domain.owner_id,
                filesystem_uuid: observation
                    .filesystem_uuid
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid("native cache quota UUID length differs"))?,
                project_id: observation.project_id,
                project_hard_limit_bytes: observation.hard_limit_bytes,
                project_hard_inode_limit: observation.hard_inode_limit,
                content_uid: domain.native.content_uid,
                content_gid: domain.native.content_gid,
                state_gid: settings.state_gid,
                tier_charge_budget_bytes: self.host.tier_budget,
                policy: settings.policy,
                retirement_interval: domain.native.retirement.interval(),
                reads: settings.reads,
                state: settings.state,
                inventory_entries: settings.inventory_entries,
                queued_commands: settings.queued_commands,
                metadata_sync_hold_bytes: settings.metadata_sync_hold_bytes,
                index_repair: settings.index_repair,
                surface_index: None,
            };
            config.validate()?;
            prepared.push((domain.native.domain, config, settings));
        }
        if partition_sum > ledger_sum.unwrap_or(0) {
            return Err(invalid(
                "native cache owners exceed authenticated partition",
            ));
        }
        drop(helper);
        confinement.check_current()?;

        let mut stores = BTreeMap::new();
        for (domain, config, settings) in prepared {
            let ready = NativeReady::open(
                config,
                settings.portable,
                settings.portable_limits,
                Arc::clone(&confinement),
            )
            .await?;
            let store = NativeContentStore::new(ready, settings.consumer_lease_duration)
                .map_err(io::Error::other)?;
            stores.insert(
                domain,
                NativeConfiguredCache {
                    content: store,
                    reassembly: self.reassembly,
                },
            );
        }
        Ok(stores)
    }
}

/// Retains a recovered domain and its operator-selected object preparation policy.
///
/// Only the configured opener constructs this value, after real native recovery
/// and publisher Resume. The mode controls representation; it grants no guest
/// authorization or filesystem authority.
pub struct NativeConfiguredCache {
    content: NativeContentStore,
    reassembly: ReassemblyMode,
}

impl NativeConfiguredCache {
    /// Borrows the genuine native content and maintenance adapter.
    ///
    /// Object-serving callers use [`Self::prepare_object`] to apply operator
    /// policy. This lower-level adapter also exposes explicit native primitives.
    pub fn content(&self) -> &NativeContentStore {
        &self.content
    }

    /// Transfers the genuine running content owner to a composed raw store.
    ///
    /// Callers retain their own object preparation policy. This transfer does
    /// not prepare objects, create authority or repeat native initialization.
    pub fn into_content(self) -> NativeContentStore {
        self.content
    }

    /// Returns the reassembly mode retained from the checked host configuration.
    pub fn reassembly(&self) -> ReassemblyMode {
        self.reassembly
    }

    /// Prepares verified object plaintext using the retained operator policy.
    ///
    /// Multi-chunk objects stream under `never` and seal under `always`.
    /// Inline and single-chunk objects use the direct sealed path in either mode.
    /// The result borrows this domain's original recovered content owner.
    ///
    /// # Errors
    /// Returns canonical metadata, content verification, native grant, capacity,
    /// publication or accounting failures from the actual native preparation.
    pub async fn prepare_object(
        &self,
        identity: &terrane_format::identity::Identity,
    ) -> Result<NativePreparedObject<'_>, StoreFailure> {
        self.content.prepare_object(identity, self.reassembly).await
    }
}

impl NativeCacheDomainSettings {
    fn validate(&self) -> io::Result<()> {
        CachePolicy::new(self.policy)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let portable = self.portable_limits;
        if self.state_gid == 0
            || self.state_gid == u32::MAX
            || self.reads.max_allocation_bytes == 0
            || self.state.bytes == 0
            || self.state.records == 0
            || self.inventory_entries == 0
            || !(1..=1024).contains(&self.queued_commands)
            || !(1..=300_000).contains(&self.publisher_wait_budget_ms)
            || !(1..=300).contains(&self.consumer_lease_duration.as_secs())
            || self.consumer_lease_duration.subsec_nanos() != 0
            || portable.max_file_bytes == 0
            || portable.max_input_bytes < portable.max_file_bytes
            || portable.max_files == 0
            || portable.max_selected_bytes == 0
            || self.metadata_sync_hold_bytes > self.policy.capacity
            || u64::try_from(self.state.bytes)
                .ok()
                .and_then(|bytes| bytes.checked_mul(2))
                .is_none_or(|overlap| self.metadata_sync_hold_bytes < overlap)
        {
            return Err(invalid(
                "native cache requires explicit finite resource bounds",
            ));
        }
        if let Some(repair) = self.index_repair {
            repair.validate(self.metadata_sync_hold_bytes, self.policy.capacity)?;
        }
        Ok(())
    }
}
