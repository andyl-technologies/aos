//! Bounded durable ownership for executor-produced exact checkpoint candidates.
//!
//! One versioned repository ref names an immutable index. The index contains
//! process-owner catalogs and per-execution publication handoffs. Replacing the
//! ref installs every surviving edge atomically, so a selected result gains its
//! own durable edge before a catalog entry can be retired.
//!
//! The canonical version-one body is:
//!
//! ```text
//! u32-be version (= 1)
//! u64-be catalog-count
//! repeated catalog-count times in ascending owner-hash order:
//!   [u8; 32] owner-hash
//!   u64-be entry-count
//!   repeated entry-count times in insertion order:
//!     typed-exact-root exact-root
//!     [u8; 32] configuration
//!   u64-be incomplete-configuration-count
//!   repeated incomplete-configuration-count times in ascending order:
//!     [u8; 32] configuration
//!   u8 globally-incomplete (0 or 1)
//! u64-be result-count
//! repeated result-count times in ascending execution-id order:
//!   [u8; 16] execution-id
//!   u64-be root-count
//!   repeated root-count times in ascending order:
//!     typed-exact-root exact-root
//! typed-exact-root =
//!   u64-be type-tag-byte-count
//!   [u8; type-tag-byte-count] UTF-8 "crucible.executor.exact-checkpoint-root"
//!   u64-be content-id-text-byte-count
//!   [u8; content-id-text-byte-count] canonical ASCII ContentId
//! ```
//!
//! Maps and sets use their canonical sorted encoding. Every catalog owner,
//! incomplete marker, result owner, and retained root consumes one of the
//! 65,536 repository-wide entries. Decoding rejects unknown versions,
//! duplicates, empty result claims, noncanonical order, more than 4,096 roots
//! or incomplete markers per configuration catalog, or more than 256 roots per
//! result.

use super::*;
use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{ExactCheckpointId, ExecutionId};

/// Authoritative ref containing all executor exact-retention ownership.
pub const EXECUTOR_EXACT_RETENTION_REF: &str = "executor-exact-retention/v1";

/// Maximum producer-controlled manifest entries retained by one repository.
pub const MAX_EXECUTOR_EXACT_RETENTION_EDGES: usize = 65_536;

const MAX_EXECUTOR_EXACT_RESULT_ROOTS: usize = crate::MAX_FINDING_EXACT_PINS;
const MAX_EXECUTOR_EXACT_CONFIG_ROOTS: usize =
    crate::MAX_FINDING_EXACT_RETENTION_CANDIDATES as usize;
const MAX_EXECUTOR_EXACT_RETENTION_BYTES: u64 = 32 * 1024 * 1024;
const UPDATE_ATTEMPTS: usize = 8;
const COLLECTION_GROWTH_COPIES: u64 = 3;
const RECEIPT_VECTOR_GROWTH_SLOTS: u64 = 4;
const CANONICAL_IMAGE_COPIES: u64 = 2;

/// One owner's complete bounded candidate catalog.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutorExactRetentionCatalog {
    entries: Vec<(ExactCheckpointId, ConfigurationId)>,
    incomplete_configurations: BTreeSet<ConfigurationId>,
    globally_incomplete: bool,
}

impl ExecutorExactRetentionCatalog {
    /// Builds a catalog in stable oldest-to-newest insertion order.
    ///
    /// # Errors
    ///
    /// Rejects duplicate roots, excessive global or per-configuration entries,
    /// and contradictory incomplete markers.
    pub fn new(
        entries: Vec<(ExactCheckpointId, ConfigurationId)>,
        incomplete_configurations: BTreeSet<ConfigurationId>,
        globally_incomplete: bool,
    ) -> Result<Self, CampaignCodecError> {
        let value = Self {
            entries,
            incomplete_configurations,
            globally_incomplete,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns catalog entries in oldest-to-newest insertion order.
    #[must_use]
    pub fn entries(&self) -> &[(ExactCheckpointId, ConfigurationId)] {
        &self.entries
    }

    /// Returns configurations whose candidate history was truncated.
    #[must_use]
    pub const fn incomplete_configurations(&self) -> &BTreeSet<ConfigurationId> {
        &self.incomplete_configurations
    }

    /// Returns whether bounded tracking lost configuration-specific detail.
    #[must_use]
    pub const fn globally_incomplete(&self) -> bool {
        self.globally_incomplete
    }

    /// Returns whether the owner has no candidate or loss marker to retain.
    #[must_use]
    pub fn is_empty_complete(&self) -> bool {
        self.entries.is_empty()
            && self.incomplete_configurations.is_empty()
            && !self.globally_incomplete
    }

    fn validate(&self) -> Result<(), CampaignCodecError> {
        if self.entries.len() > MAX_EXECUTOR_EXACT_RETENTION_EDGES
            || self.incomplete_configurations.len() > MAX_EXECUTOR_EXACT_CONFIG_ROOTS
            || (self.globally_incomplete && !self.incomplete_configurations.is_empty())
        {
            return Err(limit());
        }
        let mut roots = BTreeSet::new();
        let mut counts = BTreeMap::<ConfigurationId, usize>::new();
        for (root, configuration) in &self.entries {
            if !roots.insert(*root) {
                return Err(invalid(
                    "executor exact-retention catalog has duplicate roots",
                ));
            }
            let count = counts.entry(*configuration).or_default();
            *count = count.checked_add(1).ok_or_else(limit)?;
            if *count > MAX_EXECUTOR_EXACT_CONFIG_ROOTS {
                return Err(limit());
            }
        }
        Ok(())
    }

    fn producer_entries(&self) -> Result<usize, CampaignCodecError> {
        1_usize
            .checked_add(self.entries.len())
            .and_then(|count| count.checked_add(self.incomplete_configurations.len()))
            .ok_or_else(limit)
    }
}

impl Canonical for ExecutorExactRetentionCatalog {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.sequence(&self.entries, |encoder, (root, configuration)| {
            root.encode(encoder);
            configuration.encode(encoder);
        });
        self.incomplete_configurations.encode(encoder);
        self.globally_incomplete.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let entries = decoder.sequence_bounded(
            MAX_EXECUTOR_EXACT_RETENTION_EDGES,
            "executor-exact-retention-catalog-entries",
            |decoder| {
                Ok((
                    ExactCheckpointId::decode(decoder)?,
                    ConfigurationId::decode(decoder)?,
                ))
            },
        )?;
        let incomplete_configurations = decoder.sequence_bounded(
            MAX_EXECUTOR_EXACT_CONFIG_ROOTS,
            "executor-exact-retention-incomplete-configurations",
            ConfigurationId::decode,
        )?;
        let incomplete_len = incomplete_configurations.len();
        let incomplete_configurations = incomplete_configurations
            .into_iter()
            .collect::<BTreeSet<_>>();
        if incomplete_len != incomplete_configurations.len() {
            return Err(invalid(
                "executor exact-retention catalog has duplicate incomplete markers",
            ));
        }
        Self::new(entries, incomplete_configurations, bool::decode(decoder)?)
    }
}

/// Complete version-one executor exact-retention index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutorExactRetentionManifest {
    catalogs: BTreeMap<CampaignHash, ExecutorExactRetentionCatalog>,
    results: BTreeMap<ExecutionId, BTreeSet<ExactCheckpointId>>,
}

/// Prepaid decoded view of one executor exact-retention index generation.
///
/// The private scratch credit remains held for the full lifetime of the owned
/// maps and sets. This keeps callers from retaining decoded producer state
/// after the original metadata reservation that admitted it has closed.
pub struct ExecutorExactRetentionSnapshot {
    manifest: ExecutorExactRetentionManifest,
    _scratch: Option<crucible_store::owned_decode::DecodeScratch>,
    _decode_budget: Option<crucible_store::owned_decode::DecodeBudget>,
}

/// Prepaid owner catalog copied from one decoded index generation.
///
/// The snapshot credit retains the decoded predecessor while the additional
/// scratch covers both the selected catalog copy and one daemon-side index of
/// the same bounded entries.
pub struct ExecutorExactRetentionCatalogCustody {
    catalog: Option<ExecutorExactRetentionCatalog>,
    _snapshot: ExecutorExactRetentionSnapshot,
    _scratch: Option<crucible_store::owned_decode::DecodeScratch>,
}

/// Incremental prepaid custody for one live executor candidate catalog.
pub struct ExecutorExactCatalogAllocationCustody {
    admitted_entries: usize,
    original: crucible_store::owned_decode::DecodeBudget,
    allocations: Vec<crucible_store::owned_decode::DecodeScratch>,
}

impl ExecutorExactCatalogAllocationCustody {
    /// Returns the number of live catalog entries covered by this custody.
    #[must_use]
    pub const fn admitted_entries(&self) -> usize {
        self.admitted_entries
    }

    fn grow_to(&mut self, required_entries: usize) -> Result<(), CampaignRepositoryError> {
        if required_entries <= self.admitted_entries {
            return Ok(());
        }
        if required_entries > MAX_EXECUTOR_EXACT_RETENTION_EDGES {
            return Err(limit().into());
        }
        let target = required_entries
            .checked_next_power_of_two()
            .unwrap_or(MAX_EXECUTOR_EXACT_RETENTION_EDGES)
            .min(MAX_EXECUTOR_EXACT_RETENTION_EDGES);
        let current_bytes = catalog_owned_bytes(self.admitted_entries)?;
        let target_bytes = catalog_owned_bytes(target)?;
        let custody_slot = checked_array_bytes::<crucible_store::owned_decode::DecodeScratch>(
            1,
            RECEIPT_VECTOR_GROWTH_SLOTS,
        )?;
        let additional = target_bytes
            .checked_sub(current_bytes)
            .and_then(|bytes| bytes.checked_add(custody_slot))
            .ok_or(StoreError::Quota)?;
        let scratch =
            self.original
                .reserve_scratch_bytes(additional)
                .map_err(|source| {
                    CampaignRepositoryError::Ram(
                        crucible_store::ram::RamStoreError::from_admission(&self.original, source),
                    )
                })?;
        self.allocations
            .try_reserve(1)
            .map_err(|_| StoreError::Quota)?;
        self.allocations.push(scratch);
        self.admitted_entries = target;
        Ok(())
    }
}

impl ExecutorExactRetentionCatalogCustody {
    /// Returns the selected durable catalog when the owner has one.
    #[must_use]
    pub const fn catalog(&self) -> Option<&ExecutorExactRetentionCatalog> {
        self.catalog.as_ref()
    }
}

impl std::ops::Deref for ExecutorExactRetentionSnapshot {
    type Target = ExecutorExactRetentionManifest;

    fn deref(&self) -> &Self::Target {
        &self.manifest
    }
}

/// Process-local exclusive custody for one durable catalog owner.
pub struct ExecutorExactRetentionOwnerLease {
    owner: CampaignHash,
    owners: Arc<Mutex<BTreeSet<CampaignHash>>>,
    registered: bool,
    _scratch: Option<crucible_store::owned_decode::DecodeScratch>,
}

impl Drop for ExecutorExactRetentionOwnerLease {
    fn drop(&mut self) {
        if self.registered
            && let Ok(mut owners) = self.owners.lock()
        {
            owners.remove(&self.owner);
        }
    }
}

impl ExecutorExactRetentionManifest {
    /// Returns one durable owner catalog.
    #[must_use]
    pub fn catalog(&self, owner: CampaignHash) -> Option<&ExecutorExactRetentionCatalog> {
        self.catalogs.get(&owner)
    }

    /// Returns one durable in-flight result claim.
    #[must_use]
    pub fn result(&self, execution: ExecutionId) -> Option<&BTreeSet<ExactCheckpointId>> {
        self.results.get(&execution)
    }

    /// Returns the bounded executions with in-flight result ownership.
    pub fn result_executions(&self) -> impl Iterator<Item = ExecutionId> + '_ {
        self.results.keys().copied()
    }

    /// Visits every retained exact checkpoint root.
    pub fn visit_roots(&self, visitor: &mut dyn FnMut(ExactCheckpointId)) {
        for catalog in self.catalogs.values() {
            for (root, _) in catalog.entries() {
                visitor(*root);
            }
        }
        for roots in self.results.values() {
            for root in roots {
                visitor(*root);
            }
        }
    }

    /// Returns canonical version-one bytes.
    ///
    /// # Errors
    ///
    /// Rejects an invalid manifest or an encoded body above the fixed byte
    /// bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CampaignCodecError> {
        self.validate()?;
        let bytes = codec::encode(self);
        if bytes.len() > MAX_EXECUTOR_EXACT_RETENTION_BYTES as usize {
            return Err(limit());
        }
        Ok(bytes)
    }

    /// Decodes and validates canonical version-one bytes.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical bytes, unknown versions, and every exceeded bound.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode_bounded(
            bytes,
            MAX_EXECUTOR_EXACT_RETENTION_BYTES as usize,
            "executor-exact-retention-bytes",
        )
    }

    fn validate(&self) -> Result<(), CampaignCodecError> {
        let mut entries = 0_usize;
        for catalog in self.catalogs.values() {
            catalog.validate()?;
            entries = entries
                .checked_add(catalog.producer_entries()?)
                .ok_or_else(limit)?;
        }
        for roots in self.results.values() {
            if roots.is_empty() || roots.len() > MAX_EXECUTOR_EXACT_RESULT_ROOTS {
                return Err(limit());
            }
            entries = entries
                .checked_add(1)
                .and_then(|count| count.checked_add(roots.len()))
                .ok_or_else(limit)?;
        }
        if entries > MAX_EXECUTOR_EXACT_RETENTION_EDGES {
            return Err(limit());
        }
        Ok(())
    }

    fn producer_entries(&self) -> Result<usize, CampaignCodecError> {
        self.validate()?;
        let mut entries = 0_usize;
        for catalog in self.catalogs.values() {
            entries = entries
                .checked_add(catalog.producer_entries()?)
                .ok_or_else(limit)?;
        }
        for roots in self.results.values() {
            entries = entries
                .checked_add(1)
                .and_then(|count| count.checked_add(roots.len()))
                .ok_or_else(limit)?;
        }
        Ok(entries)
    }
}

impl Canonical for ExecutorExactRetentionManifest {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u32(1);
        self.catalogs.encode(encoder);
        self.results.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != 1 {
            return Err(invalid(
                "unsupported executor exact-retention manifest version",
            ));
        }
        let catalogs = decoder.sequence_bounded(
            MAX_EXECUTOR_EXACT_RETENTION_EDGES,
            "executor-exact-retention-catalog-owners",
            |decoder| {
                Ok((
                    CampaignHash::decode(decoder)?,
                    ExecutorExactRetentionCatalog::decode(decoder)?,
                ))
            },
        )?;
        let catalog_len = catalogs.len();
        let catalogs = catalogs.into_iter().collect::<BTreeMap<_, _>>();
        if catalog_len != catalogs.len() {
            return Err(invalid(
                "executor exact-retention has duplicate catalog owners",
            ));
        }
        let results = decoder.sequence_bounded(
            MAX_EXECUTOR_EXACT_RETENTION_EDGES,
            "executor-exact-retention-result-owners",
            |decoder| {
                let execution = ExecutionId::decode(decoder)?;
                let roots = decoder.sequence_bounded(
                    MAX_EXECUTOR_EXACT_RESULT_ROOTS,
                    "executor-exact-retention-result-roots",
                    ExactCheckpointId::decode,
                )?;
                let root_len = roots.len();
                let roots = roots.into_iter().collect::<BTreeSet<_>>();
                if root_len != roots.len() {
                    return Err(invalid(
                        "executor exact-retention result has duplicate roots",
                    ));
                }
                Ok((execution, roots))
            },
        )?;
        let result_len = results.len();
        let results = results.into_iter().collect::<BTreeMap<_, _>>();
        if result_len != results.len() {
            return Err(invalid(
                "executor exact-retention has duplicate result owners",
            ));
        }
        let value = Self { catalogs, results };
        value.validate()?;
        Ok(value)
    }
}

impl CampaignRepository {
    /// Claims one catalog owner for the lifetime of its executor actor.
    ///
    /// Durable reopen across process restart is authorized by the caller's
    /// external ledger writer lock. This lease additionally refuses concurrent
    /// sources sharing the same live repository actor.
    ///
    /// # Errors
    ///
    /// Refuses a duplicate live owner or poisoned custody state.
    pub fn claim_executor_exact_catalog_owner(
        &self,
        owner: CampaignHash,
    ) -> Result<ExecutorExactRetentionOwnerLease, CampaignRepositoryError> {
        let Some(original) = self.ram_admission.original() else {
            return Ok(ExecutorExactRetentionOwnerLease {
                owner,
                owners: Arc::clone(&self.executor_exact_owners),
                registered: false,
                _scratch: None,
            });
        };
        let mut owners = self
            .executor_exact_owners
            .lock()
            .map_err(|_| integrity("executor-exact-retention-owner-lock-poisoned"))?;
        if owners.contains(&owner) {
            return Err(integrity("executor-exact-retention-owner-already-live"));
        }
        if owners.len() == MAX_EXECUTOR_EXACT_RETENTION_EDGES {
            return Err(limit().into());
        }
        let bytes =
            crucible_store::owned_decode::DecodeBudget::btree_control_bytes::<CampaignHash, ()>(1)
                .map_err(CampaignCodecError::from)?;
        let scratch = original.reserve_scratch_bytes(bytes).map_err(|source| {
            CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                original, source,
            ))
        })?;
        owners.insert(owner);
        Ok(ExecutorExactRetentionOwnerLease {
            owner,
            owners: Arc::clone(&self.executor_exact_owners),
            registered: true,
            _scratch: Some(scratch),
        })
    }

    /// Loads the current executor exact-retention index.
    ///
    /// # Errors
    ///
    /// Absence is returned without requiring metadata authority. A present ref
    /// refuses unavailable original metadata authority, malformed targets,
    /// corrupt manifests, and noncanonical or excessive state.
    pub fn load_executor_exact_retention(
        &self,
    ) -> Result<ExecutorExactRetentionSnapshot, CampaignRepositoryError> {
        let name = RefName::new(String::from(EXECUTOR_EXACT_RETENTION_REF))?;
        match self.refs.read_ref(&name)? {
            Some(target) => self
                .read_executor_exact_retention_manifest(target)
                .map(|loaded| loaded.snapshot),
            None => Ok(ExecutorExactRetentionSnapshot {
                manifest: ExecutorExactRetentionManifest::default(),
                _scratch: None,
                _decode_budget: None,
            }),
        }
    }

    /// Replaces one owner's complete catalog and installs an in-flight result.
    ///
    /// The caller's already-held GC exclusion proves that every source root is
    /// still live until the single ref CAS installs its durable successor.
    ///
    /// # Errors
    ///
    /// Refuses absent original metadata authority, exceeded bounds, a changed
    /// claim for the same execution, or persistent compare-exchange conflict.
    pub fn retain_executor_exact_result_under(
        &self,
        gc_exclusion: &CampaignRepositoryGcExclusionGuard,
        owner: CampaignHash,
        catalog: ExecutorExactRetentionCatalog,
        execution: ExecutionId,
        result_roots: &BTreeSet<ExactCheckpointId>,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_executor_exact_guard(gc_exclusion)?;
        let incoming_entries = catalog
            .producer_entries()?
            .checked_add(1)
            .and_then(|count| count.checked_add(result_roots.len()))
            .ok_or_else(limit)?;
        self.update_executor_exact_retention(false, incoming_entries, |manifest| {
            catalog.validate()?;
            match manifest.results.get(&execution) {
                Some(current) if current != result_roots => {
                    return Err(invalid("executor exact-retention execution claim changed").into());
                }
                Some(_) => {}
                None => {
                    manifest.results.insert(execution, result_roots.clone());
                }
            }
            manifest.catalogs.insert(owner, catalog.clone());
            Ok(true)
        })
    }

    /// Replaces one owner's catalog beneath an already-held GC exclusion.
    ///
    /// # Errors
    ///
    /// Returns bounded validation, original-admission, storage, or conflict
    /// failures without weakening the caller's existing exclusion.
    pub fn replace_executor_exact_catalog_under(
        &self,
        gc_exclusion: &CampaignRepositoryGcExclusionGuard,
        owner: CampaignHash,
        catalog: ExecutorExactRetentionCatalog,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_executor_exact_guard(gc_exclusion)?;
        let incoming_entries = catalog.producer_entries()?;
        self.update_executor_exact_retention(false, incoming_entries, |manifest| {
            catalog.validate()?;
            manifest.catalogs.insert(owner, catalog.clone());
            Ok(true)
        })
    }

    /// Replaces one owner's durable catalog under a short new GC exclusion.
    ///
    /// # Errors
    ///
    /// Returns the same bounded storage and conflict failures as result install.
    pub fn replace_executor_exact_catalog(
        &self,
        owner: CampaignHash,
        catalog: ExecutorExactRetentionCatalog,
    ) -> Result<(), CampaignRepositoryError> {
        let incoming_entries = catalog.producer_entries()?;
        self.update_executor_exact_retention(true, incoming_entries, |manifest| {
            catalog.validate()?;
            manifest.catalogs.insert(owner, catalog.clone());
            Ok(true)
        })
    }

    /// Retires one completed execution claim after a durable ledger successor.
    ///
    /// # Errors
    ///
    /// Refuses storage, admission, or persistent CAS failure. Absence is
    /// idempotent and never removes another execution's roots.
    pub fn retire_executor_exact_result(
        &self,
        execution: ExecutionId,
    ) -> Result<(), CampaignRepositoryError> {
        self.update_executor_exact_retention(true, 0, |manifest| {
            Ok(manifest.results.remove(&execution).is_some())
        })
    }

    /// Retires one terminal result while startup keeps its existing exclusion.
    ///
    /// # Errors
    ///
    /// Refuses a guard from another repository and the same failures as the
    /// ordinary retirement operation.
    pub fn retire_executor_exact_result_under(
        &self,
        gc_exclusion: &CampaignRepositoryGcExclusionGuard,
        execution: ExecutionId,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_executor_exact_guard(gc_exclusion)?;
        self.update_executor_exact_retention(false, 0, |manifest| {
            Ok(manifest.results.remove(&execution).is_some())
        })
    }

    /// Retires a bounded set of ledger-authenticated terminal result claims.
    ///
    /// # Errors
    ///
    /// Refuses a guard from another repository and the same failures as an
    /// individual retirement operation.
    pub fn retire_executor_exact_results_under(
        &self,
        gc_exclusion: &CampaignRepositoryGcExclusionGuard,
        executions: &BTreeSet<ExecutionId>,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_executor_exact_guard(gc_exclusion)?;
        if executions.is_empty() {
            return Ok(());
        }
        self.update_executor_exact_retention(false, 0, |manifest| {
            let mut changed = false;
            for execution in executions {
                changed |= manifest.results.remove(execution).is_some();
            }
            Ok(changed)
        })
    }

    /// Retires one stopped owner's candidate catalog without touching results.
    ///
    /// # Errors
    ///
    /// Refuses storage, admission, or persistent CAS failure.
    pub fn retire_executor_exact_catalog(
        &self,
        owner: CampaignHash,
    ) -> Result<(), CampaignRepositoryError> {
        let _publication = self.acquire_gc_exclusion_guard()?;
        let name = RefName::new(String::from(EXECUTOR_EXACT_RETENTION_REF))?;
        if self.refs.read_ref(&name)?.is_none() {
            return Ok(());
        }
        self.update_executor_exact_retention(false, 0, |manifest| {
            Ok(manifest.catalogs.remove(&owner).is_some())
        })
    }

    /// Authenticates a manifest selected by GC's fenced ref inventory.
    ///
    /// # Errors
    ///
    /// Refuses the wrong object kind or schema, unavailable original metadata
    /// authority, corrupt bytes, and all encoded bound violations.
    pub fn inspect_executor_exact_retention_for_gc(
        &self,
        target: ContentId,
    ) -> Result<ExecutorExactRetentionSnapshot, CampaignRepositoryError> {
        self.read_executor_exact_retention_manifest(target)
            .map(|loaded| loaded.snapshot)
    }

    fn update_executor_exact_retention(
        &self,
        acquire_gc_exclusion: bool,
        incoming_entries: usize,
        mut update: impl FnMut(
            &mut ExecutorExactRetentionManifest,
        ) -> Result<bool, CampaignRepositoryError>,
    ) -> Result<(), CampaignRepositoryError> {
        let operation_budget = self.ram_operation_account()?;
        let _scope = operation_budget.enter();
        let _publication = if acquire_gc_exclusion {
            Some(self.acquire_gc_exclusion_guard()?)
        } else {
            None
        };
        let name = RefName::new(String::from(EXECUTOR_EXACT_RETENTION_REF))?;
        let blob_capabilities = self.blobs.capabilities();
        let ref_capabilities = self.refs.capabilities();
        if !blob_capabilities.durable
            || !blob_capabilities.conditional_create
            || !ref_capabilities.durable
        {
            return Err(StoreError::Unsupported {
                capability: "durable-executor-exact-retention",
            }
            .into());
        }

        for _ in 0..UPDATE_ATTEMPTS {
            operation_budget.verify_live().map_err(|source| {
                CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                    &operation_budget,
                    source,
                ))
            })?;
            let current = self.refs.read_ref(&name)?;
            let loaded = match current {
                Some(target) => self.read_executor_exact_retention_manifest(target)?,
                None => LoadedExecutorExactRetention {
                    snapshot: ExecutorExactRetentionSnapshot {
                        manifest: ExecutorExactRetentionManifest::default(),
                        _scratch: None,
                        _decode_budget: None,
                    },
                },
            };
            let maximum_entries = loaded
                .snapshot
                .producer_entries()?
                .checked_add(incoming_entries)
                .ok_or_else(limit)?;
            let _scratch = reserve_manifest_custody(self, maximum_entries)?;
            let LoadedExecutorExactRetention {
                snapshot:
                    ExecutorExactRetentionSnapshot {
                        mut manifest,
                        _scratch: _read_scratch,
                        _decode_budget: _read_budget,
                    },
                ..
            } = loaded;
            if !update(&mut manifest)? {
                return Ok(());
            }
            manifest.validate()?;
            let next_length = codec::encoded_length(&manifest)?;
            if next_length > MAX_EXECUTOR_EXACT_RETENTION_BYTES as usize {
                return Err(limit().into());
            }
            let _image_scratch = reserve_canonical_images(self, next_length)?;
            let bytes = manifest.canonical_bytes()?;
            operation_budget.check().map_err(CampaignCodecError::from)?;
            let next_length = u64::try_from(bytes.len()).map_err(|_| StoreError::Quota)?;
            let next = ContentId::for_bytes(ObjectKind::Projection, 1, &bytes);
            let receipt = self
                .blobs
                .put_if_absent(next, &BlobHandle::from_bytes(bytes))?;
            if receipt.id != next
                || receipt.durable_placements() == 0
                || receipt
                    .placements
                    .iter()
                    .any(|placement| placement.logical_length != next_length)
            {
                return Err(integrity("executor-exact-retention-receipt-mismatch"));
            }
            let persisted = self.blobs.read(next, None)?;
            if persisted.logical_length() != next_length {
                return Err(integrity("executor-exact-retention-persisted-length"));
            }
            let persisted_bytes = persisted.read_all(MAX_EXECUTOR_EXACT_RETENTION_BYTES)?;
            if ContentId::for_bytes(ObjectKind::Projection, 1, &persisted_bytes) != next {
                return Err(integrity("executor-exact-retention-persisted-content"));
            }
            operation_budget.check().map_err(CampaignCodecError::from)?;
            match self.refs.compare_exchange(&name, current, next) {
                Err(source) => return Err(source.into()),
                Ok(outcome) => match outcome {
                    RefCasOutcome::Advanced { next: installed } if installed == next => {
                        return Ok(());
                    }
                    RefCasOutcome::Conflict { .. } => continue,
                    _ => return Err(integrity("executor-exact-retention-ref-receipt-mismatch")),
                },
            }
        }
        Err(CampaignRepositoryError::RefConflict {
            current: self.refs.read_ref(&name)?,
        })
    }

    fn validate_executor_exact_guard(
        &self,
        guard: &CampaignRepositoryGcExclusionGuard,
    ) -> Result<(), CampaignRepositoryError> {
        if !Arc::ptr_eq(&self.blobs, &guard.repository_blobs)
            || !Arc::ptr_eq(&self.refs, &guard.repository_refs)
        {
            return Err(integrity(
                "executor-exact-retention-guard-repository-mismatch",
            ));
        }
        Ok(())
    }

    fn read_executor_exact_retention_manifest(
        &self,
        target: ContentId,
    ) -> Result<LoadedExecutorExactRetention, CampaignRepositoryError> {
        if target.kind() != ObjectKind::Projection || target.schema_version() != 1 {
            return Err(integrity("executor-exact-retention-target-kind"));
        }
        let handle = self.blobs.read(target, None)?;
        let encoded_length = handle.logical_length();
        if encoded_length > MAX_EXECUTOR_EXACT_RETENTION_BYTES {
            return Err(limit().into());
        }
        let decode_budget = self.ram_operation_account()?;
        let _scope = decode_budget.enter();
        let image_scratch = reserve_canonical_images(
            self,
            usize::try_from(encoded_length).map_err(|_| StoreError::Quota)?,
        )?;
        let bytes = handle.read_all(MAX_EXECUTOR_EXACT_RETENTION_BYTES)?;
        if ContentId::for_bytes(ObjectKind::Projection, 1, &bytes) != target {
            return Err(integrity("executor-exact-retention-content-id"));
        }
        let entries = preflight_manifest_entries(&bytes)?;
        let scratch = reserve_manifest_decode(self, entries)?;
        let manifest = ExecutorExactRetentionManifest::from_canonical_bytes(&bytes)?;
        if manifest.producer_entries()? != entries {
            return Err(integrity("executor-exact-retention-preflight-count"));
        }
        drop(bytes);
        drop(image_scratch);
        Ok(LoadedExecutorExactRetention {
            snapshot: ExecutorExactRetentionSnapshot {
                manifest,
                _scratch: Some(scratch),
                _decode_budget: Some(decode_budget),
            },
        })
    }
}

struct LoadedExecutorExactRetention {
    snapshot: ExecutorExactRetentionSnapshot,
}

fn checked_array_bytes<T>(count: usize, live_copies: u64) -> Result<u64, CampaignCodecError> {
    u64::try_from(std::mem::size_of::<T>())
        .ok()
        .and_then(|bytes| bytes.checked_mul(u64::try_from(count).ok()?))
        .and_then(|bytes| bytes.checked_mul(live_copies))
        .ok_or_else(limit)
}

fn checked_product(left: u64, right: usize) -> Result<u64, CampaignCodecError> {
    left.checked_mul(u64::try_from(right).map_err(|_| limit())?)
        .ok_or_else(limit)
}

fn checked_sum(parts: impl IntoIterator<Item = u64>) -> Result<u64, CampaignCodecError> {
    parts.into_iter().try_fold(0_u64, |total, part| {
        total.checked_add(part).ok_or_else(limit)
    })
}

fn btree_bytes<K, V>(count: usize) -> Result<u64, CampaignCodecError> {
    crucible_store::owned_decode::DecodeBudget::btree_control_bytes::<K, V>(count)
        .map_err(CampaignCodecError::from)
}

/// Prices the live executor maps at their worst bounded configuration split.
///
/// One root can occupy both the reverse map and a one-element per-configuration
/// set. The one-element node price matters because a maximally fragmented
/// catalog cannot amortize those set nodes. Three deque copies cover the old
/// allocation and the geometrically grown successor during reallocation.
fn catalog_owned_bytes(entries: usize) -> Result<u64, CampaignCodecError> {
    let one_configuration_set = btree_bytes::<ExactCheckpointId, ()>(1)?;
    checked_sum([
        btree_bytes::<ExactCheckpointId, ConfigurationId>(entries)?,
        checked_array_bytes::<ExactCheckpointId>(entries, COLLECTION_GROWTH_COPIES)?,
        btree_bytes::<ConfigurationId, BTreeSet<ExactCheckpointId>>(entries)?,
        checked_product(one_configuration_set, entries)?,
        btree_bytes::<ConfigurationId, ()>(entries)?,
        // Catalog validation temporarily indexes every root and configuration.
        btree_bytes::<ExactCheckpointId, ()>(entries)?,
        btree_bytes::<ConfigurationId, usize>(entries)?,
    ])
}

/// Prices one decoded global generation without relying on an average entry.
fn manifest_owned_bytes(entries: usize) -> Result<u64, CampaignCodecError> {
    let one_configuration_set = btree_bytes::<ConfigurationId, ()>(1)?;
    let one_result_set = btree_bytes::<ExactCheckpointId, ()>(1)?;
    checked_sum([
        btree_bytes::<CampaignHash, ExecutorExactRetentionCatalog>(entries)?,
        btree_bytes::<ExecutionId, BTreeSet<ExactCheckpointId>>(entries)?,
        checked_array_bytes::<(ExactCheckpointId, ConfigurationId)>(entries, 1)?,
        checked_product(one_configuration_set, entries)?,
        checked_product(one_result_set, entries)?,
        // Validation retains these two indexes only for one catalog at a time.
        btree_bytes::<ExactCheckpointId, ()>(entries)?,
        btree_bytes::<ConfigurationId, usize>(entries)?,
    ])
}

fn manifest_decode_peak_bytes(entries: usize) -> Result<u64, CampaignCodecError> {
    checked_sum([
        manifest_owned_bytes(entries)?,
        checked_array_bytes::<(CampaignHash, ExecutorExactRetentionCatalog)>(entries, 1)?,
        checked_array_bytes::<(ExecutionId, BTreeSet<ExactCheckpointId>)>(entries, 1)?,
        checked_array_bytes::<ConfigurationId>(entries, 1)?,
        checked_array_bytes::<ExactCheckpointId>(entries, 1)?,
    ])
}

fn preflight_manifest_entries(bytes: &[u8]) -> Result<usize, CampaignCodecError> {
    fn length(
        decoder: &mut Decoder<'_>,
        maximum: usize,
        limit_name: &'static str,
    ) -> Result<usize, CampaignCodecError> {
        let count = usize::try_from(decoder.u64()?)
            .map_err(|_| CampaignCodecError::LimitExceeded { limit: limit_name })?;
        if count > maximum {
            return Err(CampaignCodecError::LimitExceeded { limit: limit_name });
        }
        Ok(count)
    }

    fn add_entries(total: &mut usize, count: usize) -> Result<(), CampaignCodecError> {
        *total = total.checked_add(count).ok_or_else(limit)?;
        if *total > MAX_EXECUTOR_EXACT_RETENTION_EDGES {
            return Err(limit());
        }
        Ok(())
    }

    let mut decoder = Decoder::new(bytes);
    if decoder.u32()? != 1 {
        return Err(invalid(
            "unsupported executor exact-retention manifest version",
        ));
    }
    let mut entries = 0_usize;
    let catalog_count = length(
        &mut decoder,
        MAX_EXECUTOR_EXACT_RETENTION_EDGES,
        "executor-exact-retention-catalog-owners",
    )?;
    for _ in 0..catalog_count {
        CampaignHash::decode(&mut decoder)?;
        add_entries(&mut entries, 1)?;
        let root_count = length(
            &mut decoder,
            MAX_EXECUTOR_EXACT_RETENTION_EDGES,
            "executor-exact-retention-catalog-entries",
        )?;
        add_entries(&mut entries, root_count)?;
        for _ in 0..root_count {
            ExactCheckpointId::decode(&mut decoder)?;
            ConfigurationId::decode(&mut decoder)?;
        }
        let incomplete_count = length(
            &mut decoder,
            MAX_EXECUTOR_EXACT_CONFIG_ROOTS,
            "executor-exact-retention-incomplete-configurations",
        )?;
        add_entries(&mut entries, incomplete_count)?;
        for _ in 0..incomplete_count {
            ConfigurationId::decode(&mut decoder)?;
        }
        bool::decode(&mut decoder)?;
    }
    let result_count = length(
        &mut decoder,
        MAX_EXECUTOR_EXACT_RETENTION_EDGES,
        "executor-exact-retention-result-owners",
    )?;
    for _ in 0..result_count {
        ExecutionId::decode(&mut decoder)?;
        add_entries(&mut entries, 1)?;
        let root_count = length(
            &mut decoder,
            MAX_EXECUTOR_EXACT_RESULT_ROOTS,
            "executor-exact-retention-result-roots",
        )?;
        if root_count == 0 {
            return Err(limit());
        }
        add_entries(&mut entries, root_count)?;
        for _ in 0..root_count {
            ExactCheckpointId::decode(&mut decoder)?;
        }
    }
    decoder.finish()?;
    Ok(entries)
}

fn reserve_manifest_decode(
    repository: &CampaignRepository,
    entries: usize,
) -> Result<crucible_store::owned_decode::DecodeScratch, CampaignRepositoryError> {
    let bytes = manifest_decode_peak_bytes(entries)?;
    let original = repository
        .ram_admission
        .original()
        .ok_or(StoreError::Unsupported {
            capability: "executor-exact-retention-original",
        })?;
    original.reserve_scratch_bytes(bytes).map_err(|source| {
        CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
            original, source,
        ))
    })
}

fn reserve_manifest_custody(
    repository: &CampaignRepository,
    entries: usize,
) -> Result<crucible_store::owned_decode::DecodeScratch, CampaignRepositoryError> {
    if entries
        > MAX_EXECUTOR_EXACT_RETENTION_EDGES
            .checked_mul(2)
            .ok_or(StoreError::Quota)?
    {
        return Err(limit().into());
    }
    let peak = manifest_owned_bytes(entries)?;
    let original = repository
        .ram_admission
        .original()
        .ok_or(StoreError::Unsupported {
            capability: "executor-exact-retention-original",
        })?;
    original.reserve_scratch_bytes(peak).map_err(|source| {
        CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
            original, source,
        ))
    })
}

fn reserve_canonical_images(
    repository: &CampaignRepository,
    encoded_length: usize,
) -> Result<crucible_store::owned_decode::DecodeScratch, CampaignRepositoryError> {
    let bytes = u64::try_from(encoded_length)
        .map_err(|_| StoreError::Quota)?
        .checked_mul(CANONICAL_IMAGE_COPIES)
        .ok_or(StoreError::Quota)?;
    let original = repository
        .ram_admission
        .original()
        .ok_or(StoreError::Unsupported {
            capability: "executor-exact-retention-original",
        })?;
    original.reserve_scratch_bytes(bytes).map_err(|source| {
        CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
            original, source,
        ))
    })
}

impl CampaignExecutorStore {
    fn reserve_exact_catalog_entries(
        &self,
        entries: usize,
        capability: &'static str,
    ) -> Result<crucible_store::owned_decode::DecodeScratch, CampaignRepositoryError> {
        if entries > MAX_EXECUTOR_EXACT_RETENTION_EDGES {
            return Err(limit().into());
        }
        let bytes = catalog_owned_bytes(entries)?;
        let original = self
            .repository()
            .ram_admission
            .original()
            .ok_or(StoreError::Unsupported { capability })?;
        original.reserve_scratch_bytes(bytes).map_err(|source| {
            CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                original, source,
            ))
        })
    }

    /// Grows prepaid lifetime custody for one bounded candidate catalog.
    ///
    /// The custody value retains every admitted extent until the candidate maps
    /// are freed. Empty executors can defer admission until their first insert.
    ///
    /// # Errors
    ///
    /// Refuses an excessive entry count or unavailable original metadata
    /// authority.
    pub fn ensure_exact_catalog_custody(
        &self,
        custody: &mut Option<ExecutorExactCatalogAllocationCustody>,
        required_entries: usize,
    ) -> Result<(), CampaignRepositoryError> {
        if custody.is_none() {
            let original = self
                .repository()
                .ram_admission
                .original()
                .ok_or(StoreError::Unsupported {
                    capability: "executor-exact-catalog-custody-original",
                })?
                .clone();
            *custody = Some(ExecutorExactCatalogAllocationCustody {
                admitted_entries: 0,
                original,
                allocations: Vec::new(),
            });
        }
        custody
            .as_mut()
            .ok_or_else(|| integrity("executor-exact-catalog-custody-missing"))?
            .grow_to(required_entries)
    }

    /// Reserves one bounded catalog projection through its repository update.
    ///
    /// # Errors
    ///
    /// Refuses an excessive entry count or unavailable original metadata
    /// authority.
    pub fn reserve_exact_catalog_projection(
        &self,
        entries: usize,
    ) -> Result<crucible_store::owned_decode::DecodeScratch, CampaignRepositoryError> {
        self.reserve_exact_catalog_entries(entries, "executor-exact-catalog-projection-original")
    }

    /// Reserves one bounded exact-candidate inventory returned to an executor.
    ///
    /// # Errors
    ///
    /// Refuses an excessive candidate count or unavailable original metadata
    /// authority before the response vector is allocated.
    pub fn reserve_exact_candidate_inventory(
        &self,
        candidates: usize,
    ) -> Result<crucible_store::owned_decode::DecodeScratch, CampaignRepositoryError> {
        if candidates > MAX_EXECUTOR_EXACT_CONFIG_ROOTS {
            return Err(limit().into());
        }
        let bytes =
            checked_array_bytes::<ExactCheckpointId>(candidates, RECEIPT_VECTOR_GROWTH_SLOTS)?;
        let original =
            self.repository()
                .ram_admission
                .original()
                .ok_or(StoreError::Unsupported {
                    capability: "executor-exact-candidate-inventory-original",
                })?;
        original.reserve_scratch_bytes(bytes).map_err(|source| {
            CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                original, source,
            ))
        })
    }

    /// Claims process-local custody of one durable executor catalog.
    ///
    /// # Errors
    ///
    /// Refuses another live source for the same owner.
    pub fn claim_exact_catalog_owner(
        &self,
        owner: CampaignHash,
    ) -> Result<ExecutorExactRetentionOwnerLease, CampaignRepositoryError> {
        self.repository().claim_executor_exact_catalog_owner(owner)
    }

    /// Loads one stable executor owner's durable candidate catalog.
    ///
    /// # Errors
    ///
    /// Returns repository admission, decoding, or storage failures.
    pub fn load_exact_catalog(
        &self,
        owner: CampaignHash,
    ) -> Result<ExecutorExactRetentionCatalogCustody, CampaignRepositoryError> {
        let snapshot = self.repository().load_executor_exact_retention()?;
        let selected = snapshot.catalog(owner);
        let scratch = selected
            .map(|catalog| {
                self.reserve_exact_catalog_entries(
                    catalog.producer_entries()?,
                    "executor-exact-catalog-custody-original",
                )
            })
            .transpose()?;
        let catalog = selected.cloned();
        Ok(ExecutorExactRetentionCatalogCustody {
            catalog,
            _snapshot: snapshot,
            _scratch: scratch,
        })
    }

    /// Validates one execution's exact roots against its durable result claim.
    ///
    /// # Errors
    ///
    /// Returns repository admission, decoding, or storage failures.
    pub fn validates_exact_result_claim(
        &self,
        execution: ExecutionId,
        expected: &BTreeSet<ExactCheckpointId>,
    ) -> Result<Option<bool>, CampaignRepositoryError> {
        let snapshot = self.repository().load_executor_exact_retention()?;
        Ok(snapshot
            .result(execution)
            .map(|claimed| claimed == expected))
    }

    /// Installs a selected result before releasing the execution GC exclusion.
    ///
    /// # Errors
    ///
    /// Returns repository admission, validation, storage, or conflict failures.
    pub fn retain_exact_result_under(
        &self,
        gc_exclusion: &CampaignRepositoryGcExclusionGuard,
        owner: CampaignHash,
        catalog: ExecutorExactRetentionCatalog,
        execution: ExecutionId,
        roots: &BTreeSet<ExactCheckpointId>,
    ) -> Result<(), CampaignRepositoryError> {
        self.repository().retain_executor_exact_result_under(
            gc_exclusion,
            owner,
            catalog,
            execution,
            roots,
        )
    }

    /// Installs the current candidate catalog beneath an existing exclusion.
    ///
    /// # Errors
    ///
    /// Returns repository admission, validation, storage, or conflict failures.
    pub fn replace_exact_catalog_under(
        &self,
        gc_exclusion: &CampaignRepositoryGcExclusionGuard,
        owner: CampaignHash,
        catalog: ExecutorExactRetentionCatalog,
    ) -> Result<(), CampaignRepositoryError> {
        self.repository()
            .replace_executor_exact_catalog_under(gc_exclusion, owner, catalog)
    }

    /// Retires a result claim after operational completion or cancellation.
    ///
    /// # Errors
    ///
    /// Returns repository admission, storage, or conflict failures.
    pub fn retire_exact_result(
        &self,
        execution: ExecutionId,
    ) -> Result<(), CampaignRepositoryError> {
        self.repository().retire_executor_exact_result(execution)
    }

    /// Retires a stopped execution owner's candidate catalog.
    ///
    /// # Errors
    ///
    /// Returns repository admission, storage, or conflict failures.
    pub fn retire_exact_catalog(&self, owner: CampaignHash) -> Result<(), CampaignRepositoryError> {
        self.repository().retire_executor_exact_catalog(owner)
    }
}

fn limit() -> CampaignCodecError {
    CampaignCodecError::LimitExceeded {
        limit: "executor-exact-retention",
    }
}

fn invalid(reason: &'static str) -> CampaignCodecError {
    CampaignCodecError::InvalidValue { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_store::content_store::{MemoryBlobBackend, MemoryRefBackend};
    use crucible_store::owned_decode::{
        DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, ResourceLoan,
    };

    struct OwnerLeaseAuthority;

    impl DecodeResourceAuthority for OwnerLeaseAuthority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            Ok(())
        }

        fn reserve(&self, _bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
            Ok(ResourceLoan::new(()))
        }
    }

    fn exact(byte: u8) -> ExactCheckpointId {
        ExactCheckpointId::from_content_id(ContentId::for_bytes(
            ObjectKind::ExactManifest,
            6,
            &[byte],
        ))
        .expect("exact checkpoint identity")
    }

    #[test]
    fn canonical_manifest_round_trips_and_rejects_version_and_empty_claim_mutations() {
        let owner = CampaignHash::derive("executor-exact-retention-test-owner", b"owner");
        let configuration = ConfigurationId::from_hash(CampaignHash::derive(
            "executor-exact-retention-test-configuration",
            b"configuration",
        ));
        let execution = ExecutionId::from_bytes([0x71; 16]).expect("execution");
        let mut manifest = ExecutorExactRetentionManifest::default();
        manifest.catalogs.insert(
            owner,
            ExecutorExactRetentionCatalog::new(
                vec![(exact(1), configuration)],
                BTreeSet::new(),
                false,
            )
            .expect("catalog"),
        );
        manifest
            .results
            .insert(execution, BTreeSet::from([exact(2)]));

        let bytes = manifest.canonical_bytes().expect("canonical manifest");
        assert_eq!(
            ExecutorExactRetentionManifest::from_canonical_bytes(&bytes)
                .expect("round-trip manifest"),
            manifest
        );
        let mut unknown_version = bytes;
        unknown_version[..4].copy_from_slice(&2_u32.to_be_bytes());
        assert!(matches!(
            ExecutorExactRetentionManifest::from_canonical_bytes(&unknown_version),
            Err(CampaignCodecError::InvalidValue { .. })
        ));

        let mut empty_claim = ExecutorExactRetentionManifest::default();
        empty_claim.results.insert(execution, BTreeSet::new());
        let encoded_empty_claim = codec::encode(&empty_claim);
        assert!(matches!(
            ExecutorExactRetentionManifest::from_canonical_bytes(&encoded_empty_claim),
            Err(CampaignCodecError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn catalogs_reject_duplicate_roots_and_excess_incomplete_markers() {
        let configuration = ConfigurationId::from_hash(CampaignHash::derive(
            "executor-exact-retention-test-configuration",
            b"duplicate",
        ));
        assert!(matches!(
            ExecutorExactRetentionCatalog::new(
                vec![(exact(3), configuration), (exact(3), configuration)],
                BTreeSet::new(),
                false,
            ),
            Err(CampaignCodecError::InvalidValue { .. })
        ));

        let incomplete = (0..=MAX_EXECUTOR_EXACT_CONFIG_ROOTS)
            .map(|index| {
                ConfigurationId::from_hash(CampaignHash::derive(
                    "executor-exact-retention-test-incomplete",
                    &index.to_be_bytes(),
                ))
            })
            .collect();
        assert!(matches!(
            ExecutorExactRetentionCatalog::new(Vec::new(), incomplete, false),
            Err(CampaignCodecError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn preflight_rejects_aggregate_and_result_counts_before_missing_bodies() {
        let mut aggregate = Vec::new();
        aggregate.extend_from_slice(&1_u32.to_be_bytes());
        aggregate.extend_from_slice(&1_u64.to_be_bytes());
        aggregate.extend_from_slice(&[0x41; 32]);
        aggregate.extend_from_slice(&(MAX_EXECUTOR_EXACT_RETENTION_EDGES as u64).to_be_bytes());
        assert!(matches!(
            preflight_manifest_entries(&aggregate),
            Err(CampaignCodecError::LimitExceeded { .. })
        ));

        let mut result = Vec::new();
        result.extend_from_slice(&1_u32.to_be_bytes());
        result.extend_from_slice(&0_u64.to_be_bytes());
        result.extend_from_slice(&1_u64.to_be_bytes());
        result.extend_from_slice(&[0x42; 16]);
        result.extend_from_slice(&((MAX_EXECUTOR_EXACT_RESULT_ROOTS + 1) as u64).to_be_bytes());
        assert!(matches!(
            preflight_manifest_entries(&result),
            Err(CampaignCodecError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn catalog_owner_lease_refuses_concurrent_reopen_and_releases_exact_owner() {
        let original = DecodeBudget::new(Arc::new(OwnerLeaseAuthority), 1024 * 1024)
            .expect("finite exact-owner metadata account");
        let repository = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "executor-exact-retention-owner-test",
                1024,
            )),
            Arc::new(MemoryRefBackend::new()),
            CampaignRamAdmission::Available(original),
        );
        let owner = CampaignHash::derive("executor-exact-retention-owner-test", b"owner");
        let lease = repository
            .claim_executor_exact_catalog_owner(owner)
            .expect("first owner lease");
        assert!(matches!(
            repository.claim_executor_exact_catalog_owner(owner),
            Err(CampaignRepositoryError::Integrity { .. })
        ));
        drop(lease);
        repository
            .claim_executor_exact_catalog_owner(owner)
            .expect("owner lease after exact predecessor retirement");
    }

    #[test]
    fn exact_retention_guard_is_bound_to_both_repository_backends() {
        let refs: Arc<dyn MutableRefBackend> = Arc::new(MemoryRefBackend::new());
        let first = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("exact-guard-first", 1024)),
            Arc::clone(&refs),
            CampaignRamAdmission::Unavailable,
        );
        let second = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("exact-guard-second", 1024)),
            refs,
            CampaignRamAdmission::Unavailable,
        );
        let guard = first
            .acquire_gc_exclusion_guard()
            .expect("first repository guard");

        assert!(first.validate_executor_exact_guard(&guard).is_ok());
        assert!(matches!(
            second.validate_executor_exact_guard(&guard),
            Err(CampaignRepositoryError::Integrity { .. })
        ));
    }

    #[test]
    fn absent_catalog_retirement_needs_no_ram_authority() {
        let repository = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "executor-exact-retention-empty-retirement",
                1024,
            )),
            Arc::new(MemoryRefBackend::new()),
            CampaignRamAdmission::Unavailable,
        );
        let owner =
            CampaignHash::derive("executor-exact-retention-empty-retirement", b"absent owner");

        repository
            .retire_executor_exact_catalog(owner)
            .expect("absent index retirement is an idempotent no-op");
    }
}
