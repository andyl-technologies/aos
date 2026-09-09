//! Durable checked-plan bundles and recovery roots owned by a config generation.
//!
//! Each transaction is stored beneath
//! `gen-N/ability-transactions/<transaction>/`. The directory contains the
//! canonical reload bundle and a `cfgsrc/` symlink farm created by the same
//! production GC-root helper used for retained configuration inputs. Removing
//! the generation therefore releases both configuration and ability roots at
//! the existing profile-retention boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aos_ability_model::{
    AbilityValue, ArtifactReference, ExecutionStage, RequiredFeature, ScopedOperationKey,
    TransactionId,
};
use aos_ability_runtime::adapter::{
    CancellationToken, MonotonicClock, PlanRetentionReceipt, RootRetentionReceipt, TrustedAdapter,
    TrustedPlanStore, TrustedResourceCatalog, TrustedRootStore,
};
use aos_ability_runtime::bundle::{PLAN_BUNDLE_MAX_BYTES, PlanBundleError, ReloadablePlanBundle};
use aos_ability_runtime::execution::{
    AdmissionFailure, AdmissionResult, AdmittedOperation, ExecutionError, ExecutionStep,
    ExecutionTransaction, ReadyOperation, ResourceReleaseFailure, TransactionError,
    TrustedAdmissionPolicy,
};
use aos_ability_runtime::journal::JournalLimits;
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::activation::{SwitchLockGuard, acquire_switch_lock_pub, default_switch_lock_path};
use super::native_ability_fs::RootedDirectory;
pub use crate::ability_package::NativeAbilityRetentionVerifier;
use crate::ability_package::VerifiedAbilityPackageSet;
use crate::store::create_config_gc_roots;
use crate::types::ProfileScope;

pub(crate) mod inventory;
mod verification;

pub(crate) use inventory::NativeResourceReservation;
#[cfg(test)]
use inventory::save_native_resource_ledger;
use inventory::{
    NATIVE_RESOURCE_LEDGER_FILE, NativeInventoryState, load_native_resource_ledger,
    validate_generation_name,
};
pub use inventory::{NativeQualifiedResource, NativeResourceInventory};
use verification::{AbilityArtifactVerifier, NativeAbilityArtifactVerifier};

const TRANSACTION_ROOT: &str = "ability-transactions";
const PLAN_BUNDLE_FILE: &str = "plan-bundle.json";
const EXECUTION_JOURNAL_FILE: &str = "execution.journal";
const TERMINAL_MARKER_FILE: &str = "terminal.json";
const TERMINAL_MARKER_SCHEMA: &str = "aos.ability.transaction-terminal/v1";
const TERMINAL_MARKER_MAX_BYTES: usize = 64 * 1024;
const PLAN_EVIDENCE_SCHEMA: &str = "aos.ability.plan-retention/v1";
const ROOT_EVIDENCE_SCHEMA: &str = "aos.ability.root-retention/v1";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Reports why a config generation could not retain or reload ability state.
#[derive(Debug)]
pub enum GenerationAbilityStoreError {
    /// A filesystem durability operation failed.
    Io {
        /// Describes the operation that failed.
        operation: &'static str,
        /// Names the affected path.
        path: PathBuf,
        /// Preserves the operating-system error.
        source: std::io::Error,
    },
    /// A retained bundle is malformed, noncanonical, or no longer validates.
    Bundle(PlanBundleError),
    /// Retained state conflicts with the requested transaction or checked plan.
    Conflict(String),
    /// Trusted retention evidence exceeded the bounded ability-value contract.
    Evidence(aos_ability_model::ValueError),
    /// The production GC-root provider rejected an exact artifact path.
    Roots(anyhow::Error),
    /// An artifact did not match authenticated metadata or local store bytes.
    Artifact(anyhow::Error),
    /// The global system-switch ownership boundary could not be acquired.
    SwitchLock(anyhow::Error),
    /// The retained checked transaction could not be opened.
    Transaction(TransactionError),
    /// Native orchestration around the checked transaction failed.
    Operation(anyhow::Error),
}

impl fmt::Display for GenerationAbilityStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::Bundle(source) => write!(formatter, "retained plan bundle is invalid: {source}"),
            Self::Conflict(reason) => formatter.write_str(reason),
            Self::Evidence(source) => write!(formatter, "retention evidence is invalid: {source}"),
            Self::Roots(source) => write!(formatter, "retaining ability artifact roots: {source}"),
            Self::Artifact(source) => write!(formatter, "verifying ability artifact: {source}"),
            Self::SwitchLock(source) => {
                write!(
                    formatter,
                    "acquiring ability system-switch ownership: {source}"
                )
            }
            Self::Transaction(source) => write!(formatter, "opening ability transaction: {source}"),
            Self::Operation(source) => write!(formatter, "running ability transaction: {source}"),
        }
    }
}

impl std::error::Error for GenerationAbilityStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Bundle(source) => Some(source),
            Self::Evidence(source) => Some(source),
            Self::Roots(source) | Self::Artifact(source) | Self::SwitchLock(source) => {
                Some(source.as_ref())
            }
            Self::Transaction(source) => Some(source),
            Self::Operation(source) => Some(source.as_ref()),
            Self::Conflict(_) => None,
        }
    }
}

/// Preserves an owned native-session result when terminal-marker publication fails.
#[derive(Debug)]
pub struct NativeSessionPersistenceFailure<T> {
    outcome: Box<T>,
    marker_error: Box<GenerationAbilityStoreError>,
}

impl<T> NativeSessionPersistenceFailure<T> {
    /// Returns the operation outcome whose ownership remains with the caller.
    #[must_use]
    pub const fn outcome(&self) -> &T {
        &self.outcome
    }

    /// Returns the terminal-marker publication failure.
    #[must_use]
    pub const fn marker_error(&self) -> &GenerationAbilityStoreError {
        &self.marker_error
    }

    /// Separates the owned operation outcome from its marker failure.
    #[must_use]
    pub fn into_parts(self) -> (T, GenerationAbilityStoreError) {
        (*self.outcome, *self.marker_error)
    }
}

/// Represents a native session outcome whose ownership survives marker failure.
pub type NativeSessionResult<T> = Result<T, NativeSessionPersistenceFailure<T>>;

/// Represents post-settlement resource release, including retained handles.
pub type NativeResourceReleaseResult<'plan, Request, Handle> =
    Result<(), ResourceReleaseFailure<'plan, Request, Handle>>;

impl<T> fmt::Display for NativeSessionPersistenceFailure<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native operation completed but terminal-marker publication failed: {}",
            self.marker_error
        )
    }
}

impl<T> std::error::Error for NativeSessionPersistenceFailure<T>
where
    T: fmt::Debug,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.marker_error)
    }
}

/// Persists ability recovery state inside one retained config generation.
struct GenerationAbilityStore<Verifier> {
    generation: PathBuf,
    pending_bundle: Option<ReloadablePlanBundle>,
    supported_features: BTreeSet<RequiredFeature>,
    verifier: Verifier,
    switch_lock: Arc<SwitchLockGuard>,
}

/// Owns one native execution transaction and the global switch lock that guards it.
///
/// The transaction is intentionally accessible only through borrows of this
/// session. The concrete lock-owning store therefore cannot be dropped while
/// admission, effects, configuration publication, or recovery still use the
/// transaction.
pub struct NativeAbilitySession<'plan> {
    transaction: ExecutionTransaction<'plan>,
    inventory: Arc<NativeInventoryState>,
    inventory_admission: Arc<()>,
    store: GenerationAbilityStore<NativeAbilityArtifactVerifier>,
}

struct NativeSessionPaths {
    generation: PathBuf,
    journal: PathBuf,
    switch_lock: PathBuf,
}

/// Holds a revalidated retained plan and its protected execution journal path.
///
/// Construction accepts only a named generation under the configured system
/// profile and a private transaction directory owned by the effective user.
/// The plan bundle is decoded and replayed before this value is returned. The
/// journal descriptor remains bound to the protected directory walk so the
/// runtime's read-only snapshot boundary can acquire a stable shared lock.
#[derive(Debug)]
pub struct RetainedAbilityDiagnosticSource {
    plan: CheckedEffectPlan,
    plan_bundle: Sha256Digest,
    journal: File,
    journal_path: PathBuf,
}

impl RetainedAbilityDiagnosticSource {
    /// Resolves one retained generation and transaction for read-only diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation is outside the configured system
    /// profile, a path component is malformed or insufficiently protected, or
    /// the retained plan bundle is absent, noncanonical, or fails replay.
    pub fn load(
        generation: impl Into<PathBuf>,
        transaction: &TransactionId,
        supported_features: BTreeSet<RequiredFeature>,
    ) -> Result<Self, GenerationAbilityStoreError> {
        let generation = generation.into();
        let expected_profile = ProfileScope::System.profile_path();
        if generation.parent() != Some(expected_profile.as_path()) {
            return Err(GenerationAbilityStoreError::Conflict(format!(
                "ability diagnostic generation {} is outside the canonical system profile {}",
                generation.display(),
                expected_profile.display()
            )));
        }
        let generation_name = generation
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(format!(
                    "ability diagnostic generation {} has no UTF-8 name",
                    generation.display()
                ))
            })?;
        validate_generation_name(generation_name).map_err(|source| {
            GenerationAbilityStoreError::Conflict(format!(
                "invalid ability diagnostic generation {}: {source}",
                generation.display()
            ))
        })?;
        let trusted_owner = rustix::process::geteuid().as_raw();
        let generation_root =
            RootedDirectory::open(&generation, trusted_owner, "ability diagnostic generation")
                .map_err(|source| {
                    io_error("opening protected ability generation", &generation, source)
                })?;
        let transaction_root =
            generation_root
                .child_directory(TRANSACTION_ROOT)
                .map_err(|source| {
                    io_error(
                        "opening protected ability transaction root",
                        &generation.join(TRANSACTION_ROOT),
                        source,
                    )
                })?;
        let transaction_directory = transaction_root
            .child_directory(transaction.0.as_str())
            .map_err(|source| {
                io_error(
                    "opening protected ability transaction",
                    &generation
                        .join(TRANSACTION_ROOT)
                        .join(transaction.0.as_str()),
                    source,
                )
            })?;

        let bundle_file = transaction_directory
            .resolve(Path::new(PLAN_BUNDLE_FILE))
            .map_err(|source| {
                io_error(
                    "resolving retained plan bundle",
                    &generation
                        .join(TRANSACTION_ROOT)
                        .join(transaction.0.as_str())
                        .join(PLAN_BUNDLE_FILE),
                    source,
                )
            })?;
        let bytes = bundle_file
            .read(PLAN_BUNDLE_MAX_BYTES as u64)
            .map_err(|source| {
                io_error(
                    "reading retained plan bundle",
                    bundle_file.display(),
                    source,
                )
            })?;
        let journal_file = transaction_directory
            .resolve(Path::new(EXECUTION_JOURNAL_FILE))
            .map_err(|source| {
                io_error(
                    "resolving execution journal",
                    &generation
                        .join(TRANSACTION_ROOT)
                        .join(transaction.0.as_str())
                        .join(EXECUTION_JOURNAL_FILE),
                    source,
                )
            })?;
        let journal_path = journal_file.display().to_path_buf();
        let journal = journal_file
            .open_read_only()
            .map_err(|source| io_error("opening execution journal", &journal_path, source))?;
        let bundle =
            ReloadablePlanBundle::decode(&bytes).map_err(GenerationAbilityStoreError::Bundle)?;
        let plan_bundle = bundle
            .digest()
            .map_err(GenerationAbilityStoreError::Bundle)?;
        let plan = bundle
            .revalidate(supported_features)
            .map_err(GenerationAbilityStoreError::Bundle)?;

        Ok(Self {
            plan,
            plan_bundle,
            journal,
            journal_path,
        })
    }

    /// Returns the freshly replayed exact checked plan.
    #[must_use]
    pub const fn plan(&self) -> &CheckedEffectPlan {
        &self.plan
    }

    /// Returns the digest of the retained plan bundle in this transaction directory.
    #[must_use]
    pub const fn plan_bundle(&self) -> Sha256Digest {
        self.plan_bundle
    }

    /// Consumes the source into its checked plan, bundle identity, and journal.
    ///
    /// The open file descriptor remains bound to the regular file selected
    /// through the protected generation directory walk. The path is diagnostic
    /// text only after this boundary.
    #[must_use]
    pub fn into_parts(self) -> (CheckedEffectPlan, Sha256Digest, File, PathBuf) {
        (self.plan, self.plan_bundle, self.journal, self.journal_path)
    }
}

impl<'plan> NativeAbilitySession<'plan> {
    /// Opens or recovers an exact checked plan beneath one config generation.
    ///
    /// `packages` must contain freshly verified seals for every desired and
    /// retained package needed by the plan. Their complete authenticated live
    /// closure catalogs are rechecked before journal recovery. `bundle` is
    /// rechecked against any immutable bundle already retained for the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when lock acquisition, artifact verification, plan
    /// retention, journal recovery, or checked transaction initialization fails.
    pub fn open(
        plan: &'plan CheckedEffectPlan,
        transaction: TransactionId,
        limits: JournalLimits,
        generation: impl Into<PathBuf>,
        supported_features: BTreeSet<RequiredFeature>,
        bundle: ReloadablePlanBundle,
        packages: VerifiedAbilityPackageSet,
    ) -> Result<Self, GenerationAbilityStoreError> {
        let generation = generation.into();
        let expected_profile = ProfileScope::System.profile_path();
        if generation.parent() != Some(expected_profile.as_path()) {
            return Err(GenerationAbilityStoreError::Conflict(format!(
                "native ability generation {} is outside the canonical system profile {}",
                generation.display(),
                expected_profile.display()
            )));
        }
        let journal = generation
            .join(TRANSACTION_ROOT)
            .join(transaction.0.as_str())
            .join(EXECUTION_JOURNAL_FILE);
        let paths = NativeSessionPaths {
            generation,
            journal,
            switch_lock: default_switch_lock_path(),
        };
        Self::open_at(
            plan,
            transaction,
            limits,
            supported_features,
            bundle,
            packages,
            paths,
        )
    }

    fn open_at(
        plan: &'plan CheckedEffectPlan,
        transaction: TransactionId,
        limits: JournalLimits,
        supported_features: BTreeSet<RequiredFeature>,
        bundle: ReloadablePlanBundle,
        packages: VerifiedAbilityPackageSet,
        paths: NativeSessionPaths,
    ) -> Result<Self, GenerationAbilityStoreError> {
        let NativeSessionPaths {
            generation,
            journal,
            switch_lock,
        } = paths;
        require_host_effect_plan(plan)?;
        packages
            .verify_plan_inputs(
                &plan.binding_plan().environment().platform,
                plan.binding_plan().packages(),
                plan.required_runtime_artifacts(),
            )
            .map_err(GenerationAbilityStoreError::Artifact)?;
        packages
            .verify_live_retention(&NativeAbilityRetentionVerifier::new())
            .map_err(GenerationAbilityStoreError::Artifact)?;
        let verifier = NativeAbilityArtifactVerifier {
            authenticated: packages,
            platform: plan.binding_plan().environment().platform.clone(),
        };
        let mut store = GenerationAbilityStore::with_bundle_at(
            &generation,
            bundle,
            supported_features,
            verifier,
            &switch_lock,
        )?;
        let inventory = NativeInventoryState::for_generation(
            &generation,
            &transaction,
            plan,
            Arc::clone(&store.switch_lock),
        )?;
        let transaction =
            ExecutionTransaction::open(plan, transaction, &journal, limits, &mut store)
                .map_err(GenerationAbilityStoreError::Transaction)?;
        let inventory_admission = Arc::new(());
        Ok(Self {
            transaction,
            inventory,
            inventory_admission,
            store,
        })
    }

    /// Returns the lock-bound execution transaction.
    #[must_use]
    pub const fn transaction(&self) -> &ExecutionTransaction<'plan> {
        &self.transaction
    }

    /// Returns the switch-lock-bound inventory shared with native catalogs.
    #[must_use]
    pub fn resource_inventory(&self) -> NativeResourceInventory {
        NativeResourceInventory::new(&self.inventory, &self.inventory_admission)
    }

    /// Persists deterministic graph decisions and returns one bounded work batch.
    ///
    /// # Errors
    ///
    /// Returns an error when scheduling or terminal-marker publication fails.
    pub fn schedule_ready(
        &mut self,
        maximum_work: NonZeroUsize,
    ) -> Result<Vec<ReadyOperation>, GenerationAbilityStoreError> {
        let result = self
            .transaction
            .schedule_ready(maximum_work)
            .map_err(GenerationAbilityStoreError::Transaction);
        self.persist_terminal_marker()?;
        result
    }

    /// Performs fresh authorization, resource acquisition, and durable admission.
    ///
    /// The returned admitted token can dispatch only through this same session;
    /// the underlying mutable transaction never escapes the switch-lock owner.
    ///
    /// # Errors
    ///
    /// Returns the complete admission outcome inside the persistence failure
    /// when terminal-marker publication fails. This preserves an admitted token
    /// or every handle retained by an admission cleanup failure.
    pub fn admit<Adapter, Catalog, Policy, Clock>(
        &mut self,
        operation: &ScopedOperationKey,
        adapter: &Adapter,
        catalog: &mut Catalog,
        policy: &mut Policy,
        clock: &Clock,
    ) -> NativeSessionResult<AdmissionResult<'plan, Adapter::Request, Adapter::Handle>>
    where
        Adapter: TrustedAdapter,
        Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
    {
        let result = self
            .transaction
            .admit(operation, adapter, catalog, policy, clock);
        self.preserve_outcome_on_marker_failure(result)
    }

    /// Advances one admitted token through effect dispatch or reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an outer error when terminal-marker publication fails. Checked
    /// execution failures remain in the inner result.
    pub fn drive_admitted<Adapter, Policy, Clock>(
        &mut self,
        admitted: &AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        adapter: &mut Adapter,
        policy: &mut Policy,
        clock: &Clock,
        cancellation: &CancellationToken,
    ) -> Result<Result<ExecutionStep, ExecutionError>, GenerationAbilityStoreError>
    where
        Adapter: TrustedAdapter,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
    {
        let result =
            self.transaction
                .drive_admitted(admitted, adapter, policy, clock, cancellation);
        self.persist_terminal_marker()?;
        Ok(result)
    }

    /// Requests checked cancellation for one current admitted attempt.
    ///
    /// # Errors
    ///
    /// Returns an outer error when terminal-marker publication fails. Checked
    /// cancellation failures remain in the inner result.
    pub fn cancel_admitted<Adapter, Policy, Clock>(
        &mut self,
        admitted: &AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        adapter: &mut Adapter,
        policy: &mut Policy,
        clock: &Clock,
        cancellation: &CancellationToken,
    ) -> Result<Result<ExecutionStep, ExecutionError>, GenerationAbilityStoreError>
    where
        Adapter: TrustedAdapter,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
    {
        let result =
            self.transaction
                .cancel_admitted(admitted, adapter, policy, clock, cancellation);
        self.persist_terminal_marker()?;
        Ok(result)
    }

    /// Records a terminal failure when no effect may remain unresolved.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state does not permit settlement, journal
    /// persistence fails, or the final terminal marker cannot be published.
    pub fn settle_failure_before_effect(
        &mut self,
        operation: &ScopedOperationKey,
        evidence: AbilityValue,
    ) -> Result<(), GenerationAbilityStoreError> {
        self.transaction
            .settle_failure_before_effect(operation, evidence)
            .map_err(GenerationAbilityStoreError::Transaction)?;
        self.persist_terminal_marker()
    }

    /// Releases every held resource after durable operation settlement.
    ///
    /// # Errors
    ///
    /// Returns the complete release outcome inside the persistence failure when
    /// terminal-marker publication fails. A partial release therefore retains
    /// every unreleased handle for an explicit retry.
    pub fn release_admitted<Adapter, Catalog, Clock>(
        &mut self,
        admitted: AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        catalog: &mut Catalog,
        clock: &Clock,
    ) -> NativeSessionResult<NativeResourceReleaseResult<'plan, Adapter::Request, Adapter::Handle>>
    where
        Adapter: TrustedAdapter,
        Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
        Clock: MonotonicClock,
    {
        let result = self
            .transaction
            .release_admitted::<Adapter, _, _>(admitted, catalog, clock);
        self.preserve_outcome_on_marker_failure(result)
    }

    /// Retries cleanup retained by a failed admission while holding the switch lock.
    ///
    /// # Errors
    ///
    /// Returns the failure again while any resource handle remains owned.
    pub fn retry_admission_cleanup<Handle, Catalog>(
        &mut self,
        failure: AdmissionFailure<Handle>,
        catalog: &mut Catalog,
    ) -> Result<(), AdmissionFailure<Handle>>
    where
        Catalog: TrustedResourceCatalog<Handle = Handle>,
    {
        failure.retry_cleanup(catalog)
    }

    /// Retries an incomplete post-settlement release under this session's lock.
    ///
    /// # Errors
    ///
    /// Returns the complete release outcome inside the persistence failure when
    /// terminal-marker publication fails. A partial release therefore retains
    /// every unreleased handle for another explicit retry.
    pub fn retry_release<Request, Handle, Catalog, Clock>(
        &mut self,
        failure: ResourceReleaseFailure<'plan, Request, Handle>,
        catalog: &mut Catalog,
        clock: &Clock,
    ) -> NativeSessionResult<NativeResourceReleaseResult<'plan, Request, Handle>>
    where
        Catalog: TrustedResourceCatalog<Handle = Handle>,
        Clock: MonotonicClock,
    {
        let result = failure.retry(&mut self.transaction, catalog, clock);
        self.preserve_outcome_on_marker_failure(result)
    }

    fn preserve_outcome_on_marker_failure<T>(
        &self,
        outcome: T,
    ) -> Result<T, NativeSessionPersistenceFailure<T>> {
        match self.persist_terminal_marker() {
            Ok(()) => Ok(outcome),
            Err(marker_error) => Err(NativeSessionPersistenceFailure {
                outcome: Box::new(outcome),
                marker_error: Box::new(marker_error),
            }),
        }
    }

    fn persist_terminal_marker(&self) -> Result<(), GenerationAbilityStoreError> {
        let Some(terminal) = self.transaction.summary().terminal() else {
            return Ok(());
        };
        if !terminal_is_prune_eligible(terminal) {
            // Intervention is a durable journal state that recovery may later
            // resolve. Leave the marker absent until resources are released
            // and the transaction reaches a definitively settled result.
            return Ok(());
        }
        let marker = TerminalMarker {
            schema: TERMINAL_MARKER_SCHEMA.to_string(),
            transaction: self.transaction.transaction().clone(),
            plan: self.transaction.plan().id(),
            terminal,
        };
        let bytes = aos_contract::canonical::to_vec(&marker).map_err(|source| {
            GenerationAbilityStoreError::Operation(anyhow::anyhow!(
                "encoding terminal marker: {source:#}"
            ))
        })?;
        publish_named_immutable(
            &self
                .store
                .transaction_dir(self.transaction.transaction())
                .join(TERMINAL_MARKER_FILE),
            &bytes,
        )
    }
}

fn require_host_effect_plan(plan: &CheckedEffectPlan) -> Result<(), GenerationAbilityStoreError> {
    let binding_plan = plan.binding_plan();
    let host = |stage| stage == ExecutionStage::Host;
    if !host(binding_plan.environment().environment.stage)
        || binding_plan.bindings().iter().any(|binding| {
            !host(binding.provider.environment.stage)
                || !host(binding.request.consumer.environment.stage)
        })
        || plan
            .operations()
            .iter()
            .any(|operation| !host(operation.target.resource.provider.environment.stage))
    {
        return Err(GenerationAbilityStoreError::Conflict(
            "native host execution plan crosses a non-host environment boundary".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalMarker {
    schema: String,
    transaction: TransactionId,
    plan: aos_ability_model::PlanId,
    terminal: aos_ability_model::document::TerminalResult,
}

fn terminal_is_prune_eligible(terminal: aos_ability_model::document::TerminalResult) -> bool {
    matches!(
        terminal,
        aos_ability_model::document::TerminalResult::Succeeded
            | aos_ability_model::document::TerminalResult::SettledFailure
    )
}

impl<Verifier> GenerationAbilityStore<Verifier> {
    /// Opens an existing store under an explicit switch lock.
    ///
    /// This variant is used by rooted VM tests and callers whose AOS root has
    /// already resolved the concrete lock path.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock cannot be acquired.
    #[cfg(test)]
    fn open_at(
        generation: impl Into<PathBuf>,
        verifier: Verifier,
        switch_lock: impl AsRef<Path>,
    ) -> Result<Self, GenerationAbilityStoreError> {
        let switch_lock = Arc::new(
            acquire_switch_lock_pub(switch_lock.as_ref())
                .map_err(GenerationAbilityStoreError::SwitchLock)?,
        );
        Ok(Self {
            generation: generation.into(),
            pending_bundle: None,
            supported_features: BTreeSet::new(),
            verifier,
            switch_lock,
        })
    }

    /// Opens a new transaction store under an explicit switch lock.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock cannot be acquired.
    fn with_bundle_at(
        generation: impl Into<PathBuf>,
        bundle: ReloadablePlanBundle,
        supported_features: BTreeSet<RequiredFeature>,
        verifier: Verifier,
        switch_lock: impl AsRef<Path>,
    ) -> Result<Self, GenerationAbilityStoreError> {
        let switch_lock = Arc::new(
            acquire_switch_lock_pub(switch_lock.as_ref())
                .map_err(GenerationAbilityStoreError::SwitchLock)?,
        );
        Ok(Self {
            generation: generation.into(),
            pending_bundle: Some(bundle),
            supported_features,
            verifier,
            switch_lock,
        })
    }

    /// Reloads and semantically validates one transaction's retained plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation or bundle is unavailable,
    /// noncanonical, corrupt, or no longer valid for the supplied feature set.
    #[cfg(test)]
    fn load_plan(
        &self,
        transaction: &TransactionId,
        supported_features: std::collections::BTreeSet<RequiredFeature>,
    ) -> Result<CheckedEffectPlan, GenerationAbilityStoreError> {
        let path = self.bundle_path(transaction);
        let bytes = read_file(&path)?;
        ReloadablePlanBundle::decode(&bytes)
            .and_then(|bundle| bundle.revalidate(supported_features))
            .map_err(GenerationAbilityStoreError::Bundle)
    }

    fn transaction_dir(&self, transaction: &TransactionId) -> PathBuf {
        self.generation
            .join(TRANSACTION_ROOT)
            .join(transaction.0.as_str())
    }

    fn bundle_path(&self, transaction: &TransactionId) -> PathBuf {
        self.transaction_dir(transaction).join(PLAN_BUNDLE_FILE)
    }

    fn prepare_transaction_dir(
        &self,
        transaction: &TransactionId,
    ) -> Result<PathBuf, GenerationAbilityStoreError> {
        validate_generation_directory(&self.generation)?;
        let transaction_root = self.generation.join(TRANSACTION_ROOT);
        create_private_directory(&transaction_root)?;
        sync_directory(&self.generation)?;

        let transaction_dir = transaction_root.join(transaction.0.as_str());
        create_private_directory(&transaction_dir)?;
        sync_directory(&transaction_root)?;
        Ok(transaction_dir)
    }

    fn retained_bundle(
        &self,
        transaction: &TransactionId,
        plan: &CheckedEffectPlan,
    ) -> Result<(ReloadablePlanBundle, Vec<u8>, Sha256Digest), GenerationAbilityStoreError> {
        let path = self.bundle_path(transaction);
        let bundle = if path.is_file() {
            ReloadablePlanBundle::decode(&read_file(&path)?)
                .map_err(GenerationAbilityStoreError::Bundle)?
        } else {
            self.pending_bundle.clone().ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(format!(
                    "transaction {:?} has no retained plan bundle",
                    transaction
                ))
            })?
        };
        let revalidated = bundle
            .clone()
            .revalidate(self.supported_features.clone())
            .map_err(GenerationAbilityStoreError::Bundle)?;
        if !checked_plans_match(&revalidated, plan) {
            return Err(GenerationAbilityStoreError::Conflict(format!(
                "transaction {:?} plan bundle does not reconstruct the supplied checked plan",
                transaction
            )));
        }
        let bytes = bundle
            .canonical_bytes()
            .map_err(GenerationAbilityStoreError::Bundle)?;
        let digest = bundle
            .digest()
            .map_err(GenerationAbilityStoreError::Bundle)?;
        Ok((bundle, bytes, digest))
    }
}

fn checked_plans_match(left: &CheckedEffectPlan, right: &CheckedEffectPlan) -> bool {
    left.id() == right.id()
        && left.document() == right.document()
        && left.binding_plan().id() == right.binding_plan().id()
        && left.binding_plan().document() == right.binding_plan().document()
        && left.binding_plan().environment() == right.binding_plan().environment()
        && left.binding_plan().desired_state() == right.binding_plan().desired_state()
        && left.binding_plan().packages() == right.binding_plan().packages()
        && left.interfaces() == right.interfaces()
}

impl<Verifier> TrustedPlanStore for GenerationAbilityStore<Verifier>
where
    Verifier: AbilityArtifactVerifier,
{
    type Error = GenerationAbilityStoreError;

    fn retain_plan(
        &mut self,
        transaction: &TransactionId,
        plan: &CheckedEffectPlan,
    ) -> Result<PlanRetentionReceipt, Self::Error> {
        let (_, bytes, bundle_digest) = self.retained_bundle(transaction, plan)?;
        self.prepare_transaction_dir(transaction)?;
        let path = self.bundle_path(transaction);
        publish_named_immutable(&path, &bytes)?;

        let evidence = AbilityValue::new(serde_json::json!({
            "schema": PLAN_EVIDENCE_SCHEMA,
            "transaction": transaction,
            "plan": plan.id(),
            "bundle": bundle_digest,
        }))
        .map_err(GenerationAbilityStoreError::Evidence)?;
        Ok(PlanRetentionReceipt::new(
            transaction.clone(),
            plan.id(),
            bundle_digest,
            evidence,
        ))
    }
}

impl<Verifier> TrustedRootStore for GenerationAbilityStore<Verifier>
where
    Verifier: AbilityArtifactVerifier,
{
    type Error = GenerationAbilityStoreError;

    fn retain(
        &mut self,
        transaction: &TransactionId,
        artifacts: &[ArtifactReference],
    ) -> Result<RootRetentionReceipt, Self::Error> {
        let canonical = canonical_artifacts(artifacts)?;
        let mut paths = canonical
            .iter()
            .map(|artifact| {
                super::stock::store_root_and_suffix(Path::new(&artifact.store_path))
                    .map(|(root, _)| root.display().to_string())
                    .map_err(GenerationAbilityStoreError::Roots)
            })
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        paths.dedup();
        let transaction_dir = self.prepare_transaction_dir(transaction)?;

        // Publish roots before inspecting bytes so concurrent GC cannot remove
        // a valid object between verification and durable retention.
        create_config_gc_roots(&transaction_dir, &[], &paths)
            .map_err(GenerationAbilityStoreError::Roots)?;
        sync_directory(&transaction_dir)?;
        for artifact in &canonical {
            self.verifier
                .verify(artifact)
                .map_err(GenerationAbilityStoreError::Artifact)?;
        }

        let roots = canonical
            .iter()
            .map(|artifact| artifact.closure)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let evidence = AbilityValue::new(serde_json::json!({
            "schema": ROOT_EVIDENCE_SCHEMA,
            "transaction": transaction,
            "roots": roots,
            "artifacts": canonical,
        }))
        .map_err(GenerationAbilityStoreError::Evidence)?;
        Ok(RootRetentionReceipt::new(
            transaction.clone(),
            roots,
            evidence,
        ))
    }
}

fn canonical_artifacts(
    artifacts: &[ArtifactReference],
) -> Result<Vec<ArtifactReference>, GenerationAbilityStoreError> {
    let mut canonical = Vec::with_capacity(artifacts.len());
    let mut by_content = BTreeMap::new();
    let mut by_store_path = BTreeMap::new();
    for artifact in artifacts {
        super::stock::store_root_and_suffix(Path::new(&artifact.store_path)).map_err(|source| {
            GenerationAbilityStoreError::Conflict(format!(
                "ability artifact path {:?} is invalid: {source:#}",
                artifact.store_path
            ))
        })?;
        if by_content
            .insert(artifact.content, artifact.clone())
            .is_some_and(|existing| existing != *artifact)
            || by_store_path
                .insert(artifact.store_path.clone(), artifact.clone())
                .is_some_and(|existing| existing != *artifact)
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "ability artifact identity resolves to conflicting retained metadata".to_string(),
            ));
        }
        canonical.push(artifact.clone());
    }
    canonical.sort_by(|left, right| {
        left.closure
            .cmp(&right.closure)
            .then_with(|| left.store_path.cmp(&right.store_path))
            .then_with(|| left.content.cmp(&right.content))
            .then_with(|| left.nar_hash.cmp(&right.nar_hash))
    });
    canonical.dedup();
    Ok(canonical)
}

fn publish_named_immutable(
    path: &Path,
    contents: &[u8],
) -> Result<(), GenerationAbilityStoreError> {
    let parent = path.parent().ok_or_else(|| {
        GenerationAbilityStoreError::Conflict(format!(
            "plan bundle path {} has no parent",
            path.display()
        ))
    })?;
    create_private_directory(parent)?;

    if path.is_file() {
        return compare_existing(path, contents);
    }

    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(format!(
                "immutable ability file {} has no UTF-8 name",
                path.display()
            ))
        })?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        sequence
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|source| io_error("creating temporary plan bundle", &temporary, source))?;
    file.write_all(contents)
        .map_err(|source| io_error("writing temporary plan bundle", &temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error("syncing temporary plan bundle", &temporary, source))?;

    match std::fs::hard_link(&temporary, path) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            compare_existing(path, contents)?;
        }
        Err(source) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(io_error("publishing immutable plan bundle", path, source));
        }
    }
    std::fs::remove_file(&temporary)
        .map_err(|source| io_error("removing temporary plan bundle", &temporary, source))?;
    sync_directory(parent)
}

fn compare_existing(path: &Path, expected: &[u8]) -> Result<(), GenerationAbilityStoreError> {
    let existing = read_file(path)?;
    if existing == expected {
        Ok(())
    } else {
        Err(GenerationAbilityStoreError::Conflict(format!(
            "immutable ability file {} conflicts with requested bytes",
            path.display()
        )))
    }
}

fn create_private_directory(path: &Path) -> Result<(), GenerationAbilityStoreError> {
    std::fs::create_dir_all(path)
        .map_err(|source| io_error("creating ability transaction directory", path, source))?;
    let mut permissions = std::fs::metadata(path)
        .map_err(|source| io_error("reading ability transaction directory", path, source))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .map_err(|source| io_error("protecting ability transaction directory", path, source))?;
    Ok(())
}

fn validate_generation_directory(path: &Path) -> Result<(), GenerationAbilityStoreError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|source| io_error("reading configuration generation", path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "configuration generation {} is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

/// Reports whether a generation contains a live native consumer or recovery work.
///
/// The profile-level native ledger is checked first because a settled ability
/// transaction may still own a published native object. A malformed or
/// noncanonical ledger returns an error so pruning fails closed.
///
/// # Errors
///
/// Returns an error when the generation name or durable native ledger is
/// invalid, or when the transaction directory itself cannot be listed.
pub(crate) fn generation_must_be_retained(generation: &Path) -> anyhow::Result<bool> {
    let name = generation
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("generation {} has no UTF-8 name", generation.display()))?;
    validate_generation_name(name).map_err(anyhow::Error::new)?;
    let profile = generation.parent().ok_or_else(|| {
        anyhow::anyhow!("generation {} has no profile parent", generation.display())
    })?;
    let ledger = load_native_resource_ledger(&profile.join(NATIVE_RESOURCE_LEDGER_FILE))
        .map_err(anyhow::Error::new)?;
    if ledger
        .consumers
        .iter()
        .any(|consumer| consumer.generation == name)
    {
        return Ok(true);
    }
    generation_has_unfinished_transactions(generation)
}

/// Reports whether a generation contains recovery work that pruning must retain.
///
/// Missing transaction directories are complete by definition. Missing,
/// malformed, noncanonical, or mismatched terminal markers fail closed as
/// unfinished work.
///
/// # Errors
///
/// Returns an error when the transaction directory itself cannot be listed.
pub(crate) fn generation_has_unfinished_transactions(generation: &Path) -> anyhow::Result<bool> {
    use anyhow::Context as _;

    let root = generation.join(TRANSACTION_ROOT);
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("listing ability transactions in {}", generation.display())
            });
        }
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("reading entries in {}", root.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspecting {}", entry.path().display()))?;
        if !file_type.is_dir() || file_type.is_symlink() {
            return Ok(true);
        }
        let Some(transaction_name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            return Ok(true);
        };
        let marker_path = entry.path().join(TERMINAL_MARKER_FILE);
        let marker_bytes = match read_regular_file(
            &marker_path,
            TERMINAL_MARKER_MAX_BYTES,
            "ability terminal marker",
        ) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(true),
        };
        let marker: TerminalMarker =
            match aos_contract::canonical::from_slice(&marker_bytes, "ability terminal marker") {
                Ok(marker) => marker,
                Err(_) => return Ok(true),
            };
        if marker.schema != TERMINAL_MARKER_SCHEMA
            || marker.transaction.0.as_str() != transaction_name
        {
            return Ok(true);
        }
        if !terminal_is_prune_eligible(marker.terminal) {
            return Ok(true);
        }
        let bundle_path = entry.path().join(PLAN_BUNDLE_FILE);
        let bundle = match read_file(&bundle_path).and_then(|bytes| {
            ReloadablePlanBundle::decode(&bytes).map_err(GenerationAbilityStoreError::Bundle)
        }) {
            Ok(bundle) => bundle,
            Err(_) => return Ok(true),
        };
        if bundle.plan() != marker.plan {
            return Ok(true);
        }
        if !matches!(
            aos_contract::canonical::to_vec(&marker),
            Ok(canonical) if canonical == marker_bytes
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_file(path: &Path) -> Result<Vec<u8>, GenerationAbilityStoreError> {
    read_regular_file(path, PLAN_BUNDLE_MAX_BYTES, "retained plan bundle")
}

fn read_regular_file(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, GenerationAbilityStoreError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("opening retained plan bundle", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspecting retained plan bundle", path, source))?;
    if !metadata.is_file() {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "{label} {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "{label} {} exceeds the {}-byte limit",
            path.display(),
            max_bytes
        )));
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("reading retained plan bundle", path, source))?;
    if bytes.len() > max_bytes {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "{label} {} grew beyond the {}-byte limit while reading",
            path.display(),
            max_bytes
        )));
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), GenerationAbilityStoreError> {
    let directory = File::open(path)
        .map_err(|source| io_error("opening ability directory for sync", path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("syncing ability directory", path, source))
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> GenerationAbilityStoreError {
    GenerationAbilityStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_ability_model::{
        AbilityValue, AccessMode, AggregateId, ControllerAssignment, DependencyEdge,
        DependencyKind, LocalKey, MethodReference, OperationFamily, OperationId, PlanNodeKey,
        ProviderImplementationReference, ServiceAction, ValueExpression, ValuePhase, builtin,
    };
    use aos_ability_plan::test_support::verified_planning_transition_plan;
    use aos_ability_runtime::adapter::ReservationContext;
    use aos_ability_runtime::bundle::ReloadablePlanBundle;
    use aos_ability_validate::test_support::{
        checked_effect_plan, checked_systemd_manager_effect_plan,
    };

    use super::*;
    #[derive(Clone, Debug, Default)]
    struct TestArtifactVerifier;

    impl AbilityArtifactVerifier for TestArtifactVerifier {
        fn verify(&self, artifact: &ArtifactReference) -> anyhow::Result<()> {
            anyhow::ensure!(
                artifact.store_path.starts_with("/nix/store/"),
                "test artifact is outside the store"
            );
            Ok(())
        }
    }

    fn checked_systemd_read_write_plan() -> CheckedEffectPlan {
        let mut fixture = aos_ability_validate::test_support::plan_fixture();
        let artifact = fixture.binding_plan.bindings[0]
            .implementation
            .artifact
            .clone();
        fixture.interfaces = vec![
            builtin::systemd_manager_interface()
                .expect("built-in systemd interface must construct"),
        ];
        fixture.refresh_interface();

        let provider = builtin::systemd_manager_provider(artifact.clone())
            .expect("built-in systemd provider must construct");
        let implementation = ProviderImplementationReference {
            descriptor: provider
                .descriptor_digest()
                .expect("built-in systemd provider must have a digest"),
            artifact,
            handler: Some(
                builtin::systemd_manager_handler_key()
                    .expect("built-in systemd handler key must construct"),
            ),
        };
        fixture.binding_inputs.environment.providers[0].implementation = implementation.clone();
        fixture.binding_plan.bindings[0].implementation = implementation;

        let methods = vec![
            LocalKey::new("observe").unwrap(),
            LocalKey::new("start").unwrap(),
        ];
        fixture.binding_inputs.desired_state.child_requests[0].methods = methods.clone();
        fixture.binding_plan.requests[0].methods = methods.clone();
        fixture.binding_plan.bindings[0].caller_grant.methods = methods.clone();
        fixture.binding_plan.bindings[0].caller_grant.resources[0].access =
            AccessMode::ExclusiveWrite;
        fixture.binding_plan.bindings[0].caller_grant.resources[0].operations = methods;

        let resource = fixture.effect_plan.current_revisions[0].resource.clone();
        let controller = AggregateId {
            provider: resource.provider.clone(),
            group: LocalKey::new("systemd").unwrap(),
        };
        let controller_assignment = ControllerAssignment {
            resource,
            controller: controller.clone(),
        };
        fixture.binding_inputs.environment.controllers = vec![controller_assignment.clone()];
        fixture.binding_inputs.desired_state.controllers = vec![controller_assignment.clone()];
        fixture.effect_plan.controllers = vec![controller_assignment];

        let mut observe_a = fixture.effect_plan.operations[0].clone();
        observe_a.key.key = LocalKey::new("observe-a").unwrap();
        observe_a.target.operations = vec![LocalKey::new("observe").unwrap()];
        observe_a.inputs = ValueExpression::Literal {
            value: AbilityValue::new(serde_json::json!({"unit": "example.service"}))
                .expect("systemd observe fixture input must be bounded"),
        };
        observe_a.recovery.reconcile = Some(MethodReference {
            interface: observe_a.interface.clone(),
            method: LocalKey::new("observe").unwrap(),
        });
        let mut observe_b = observe_a.clone();
        observe_b.key.key = LocalKey::new("observe-b").unwrap();

        let mut start = observe_a.clone();
        start.key.key = LocalKey::new("start").unwrap();
        start.method = LocalKey::new("start").unwrap();
        start.family = OperationFamily::ServiceLifecycle {
            action: ServiceAction::Start,
        };
        start.input_phase = ValuePhase::Planning;
        start.target.operations = vec![LocalKey::new("start").unwrap()];
        start.accesses[0].mode = AccessMode::ExclusiveWrite;
        start.controller = Some(controller);
        start.recovery.reconcile = Some(MethodReference {
            interface: start.interface.clone(),
            method: LocalKey::new("observe").unwrap(),
        });

        fixture.effect_plan.edges = [&observe_a, &observe_b]
            .into_iter()
            .map(|observe| DependencyEdge {
                from: PlanNodeKey::Operation {
                    key: observe.key.clone(),
                },
                to: PlanNodeKey::Operation {
                    key: start.key.clone(),
                },
                kind: DependencyKind::RequiredSuccess,
            })
            .collect();
        fixture.effect_plan.operations = vec![observe_a, observe_b, start];
        fixture.refresh_commitments();

        fixture
            .validate()
            .expect("combined systemd read/write plan must pass production validation")
    }

    #[test]
    fn mutating_native_reservation_publishes_a_durable_conservative_claim()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-1");
        std::fs::create_dir(&generation)?;
        let plan = checked_systemd_manager_effect_plan();
        let transaction = TransactionId(aos_ability_model::LocalKey::new("native-start")?);
        let (inventory, _owner) =
            NativeResourceInventory::test_for_generation(&generation, &transaction, &plan)?;
        let operation = &plan.operations()[0];
        let operation_id = OperationId {
            plan: plan.id(),
            operation: operation.key.clone(),
        };
        let qualified = NativeQualifiedResource::systemd(
            operation.target.resource.clone(),
            "/org/freedesktop/systemd1/unit/example_2eservice",
        )?;

        let reservation = inventory.reserve(
            &qualified,
            ReservationContext {
                transaction: &transaction,
                operation: &operation_id,
                attempt: NonZeroU32::new(1).ok_or("test attempt must be positive")?,
                expected_provider: None,
                recovery_remaining_millis: 1_000,
            },
            operation,
            &operation.accesses[0],
        )?;
        let ledger =
            load_native_resource_ledger(&directory.path().join(NATIVE_RESOURCE_LEDGER_FILE))?;
        assert_eq!(ledger.consumers.len(), 1);
        let consumer = &ledger.consumers[0];
        assert_eq!(consumer.transaction, transaction);
        assert_eq!(consumer.plan, plan.id());
        assert_eq!(consumer.operation, operation_id);
        assert_eq!(consumer.attempt, 1);
        assert_eq!(consumer.artifacts, plan.required_runtime_artifacts());

        drop(reservation);
        assert_eq!(
            load_native_resource_ledger(&directory.path().join(NATIVE_RESOURCE_LEDGER_FILE))?
                .consumers
                .len(),
            1
        );
        assert!(generation_must_be_retained(&generation)?);
        Ok(())
    }

    #[test]
    fn read_only_native_reservation_does_not_publish_a_consumer_claim()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-1");
        std::fs::create_dir(&generation)?;
        let plan = checked_effect_plan();
        let transaction = TransactionId(aos_ability_model::LocalKey::new("native-observe")?);
        let (inventory, _owner) =
            NativeResourceInventory::test_for_generation(&generation, &transaction, &plan)?;
        let operation = &plan.operations()[0];
        let operation_id = OperationId {
            plan: plan.id(),
            operation: operation.key.clone(),
        };
        let qualified = NativeQualifiedResource::systemd(
            operation.target.resource.clone(),
            "/org/freedesktop/systemd1/unit/example_2eservice",
        )?;

        let _reservation = inventory.reserve(
            &qualified,
            ReservationContext {
                transaction: &transaction,
                operation: &operation_id,
                attempt: NonZeroU32::new(1).ok_or("test attempt must be positive")?,
                expected_provider: None,
                recovery_remaining_millis: 1_000,
            },
            operation,
            &operation.accesses[0],
        )?;

        assert!(
            load_native_resource_ledger(&directory.path().join(NATIVE_RESOURCE_LEDGER_FILE))?
                .consumers
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn exact_reads_share_one_logical_resource_and_block_checked_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-1");
        std::fs::create_dir(&generation)?;
        let plan = checked_systemd_read_write_plan();
        let transaction = TransactionId(aos_ability_model::LocalKey::new("native-sharing")?);
        let (inventory, _owner) =
            NativeResourceInventory::test_for_generation(&generation, &transaction, &plan)?;
        let observe_a = &plan.operations()[0];
        let observe_b = &plan.operations()[1];
        let start = &plan.operations()[2];
        assert_eq!(observe_a.accesses[0].mode, AccessMode::Read);
        assert_eq!(observe_b.accesses[0].mode, AccessMode::Read);
        assert_eq!(start.accesses[0].mode, AccessMode::ExclusiveWrite);
        assert_eq!(observe_a.target.resource, start.target.resource);

        let qualified = NativeQualifiedResource::systemd(
            observe_a.target.resource.clone(),
            "/org/freedesktop/systemd1/unit/example_2eservice",
        )?;
        let operation_id = |operation: &aos_ability_model::Operation| OperationId {
            plan: plan.id(),
            operation: operation.key.clone(),
        };
        let observe_a_id = operation_id(observe_a);
        let observe_b_id = operation_id(observe_b);
        let start_id = operation_id(start);
        let context = |operation| ReservationContext {
            transaction: &transaction,
            operation,
            attempt: NonZeroU32::new(1).expect("test attempt is positive"),
            expected_provider: None,
            recovery_remaining_millis: 1_000,
        };

        let read_a = inventory.reserve(
            &qualified,
            context(&observe_a_id),
            observe_a,
            &observe_a.accesses[0],
        )?;
        let read_b = inventory.reserve(
            &qualified,
            context(&observe_b_id),
            observe_b,
            &observe_b.accesses[0],
        )?;
        assert!(
            inventory
                .reserve(&qualified, context(&start_id), start, &start.accesses[0])
                .is_err()
        );

        drop(read_a);
        assert!(
            inventory
                .reserve(&qualified, context(&start_id), start, &start.accesses[0])
                .is_err()
        );

        drop(read_b);
        let _write =
            inventory.reserve(&qualified, context(&start_id), start, &start.accesses[0])?;
        Ok(())
    }

    #[test]
    fn stable_systemd_identity_rejects_a_foreign_logical_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-1");
        std::fs::create_dir(&generation)?;
        let plan = checked_systemd_manager_effect_plan();
        let transaction = TransactionId(aos_ability_model::LocalKey::new("native-owner")?);
        let (inventory, _owner) =
            NativeResourceInventory::test_for_generation(&generation, &transaction, &plan)?;
        let operation = &plan.operations()[0];
        let operation_id = OperationId {
            plan: plan.id(),
            operation: operation.key.clone(),
        };
        let qualified = NativeQualifiedResource::systemd(
            operation.target.resource.clone(),
            "/org/freedesktop/systemd1/unit/example_2eservice",
        )?;
        let reservation = inventory.reserve(
            &qualified,
            ReservationContext {
                transaction: &transaction,
                operation: &operation_id,
                attempt: NonZeroU32::new(1).ok_or("test attempt must be positive")?,
                expected_provider: None,
                recovery_remaining_millis: 1_000,
            },
            operation,
            &operation.accesses[0],
        )?;
        drop(reservation);

        let ledger_path = directory.path().join(NATIVE_RESOURCE_LEDGER_FILE);
        let mut ledger = load_native_resource_ledger(&ledger_path)?;
        let mut foreign = ledger.consumers[0].clone();
        foreign.logical.key = aos_ability_model::LocalKey::new("foreign-service")?;
        ledger.consumers.push(foreign);

        assert!(save_native_resource_ledger(&ledger_path, &ledger).is_err());
        assert_eq!(qualified.physical.authority, "system-manager");
        assert_eq!(
            qualified.physical.object,
            "/org/freedesktop/systemd1/unit/example_2eservice"
        );
        Ok(())
    }

    #[test]
    fn native_ledger_schema_domain_and_encoding_fail_closed_after_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-1");
        std::fs::create_dir(&generation)?;
        let plan = checked_systemd_manager_effect_plan();
        let transaction = TransactionId(aos_ability_model::LocalKey::new("native-ledger")?);
        let (inventory, _owner) =
            NativeResourceInventory::test_for_generation(&generation, &transaction, &plan)?;
        let operation = &plan.operations()[0];
        let operation_id = OperationId {
            plan: plan.id(),
            operation: operation.key.clone(),
        };
        let qualified = NativeQualifiedResource::systemd(
            operation.target.resource.clone(),
            "/org/freedesktop/systemd1/unit/example_2eservice",
        )?;
        let _reservation = inventory.reserve(
            &qualified,
            ReservationContext {
                transaction: &transaction,
                operation: &operation_id,
                attempt: NonZeroU32::new(1).ok_or("test attempt must be positive")?,
                expected_provider: None,
                recovery_remaining_millis: 1_000,
            },
            operation,
            &operation.accesses[0],
        )?;

        let ledger_path = directory.path().join(NATIVE_RESOURCE_LEDGER_FILE);
        let canonical = std::fs::read(&ledger_path)?;
        let value: serde_json::Value = serde_json::from_slice(&canonical)?;
        let mut mutations = Vec::new();

        let mut unsupported_schema = value.clone();
        unsupported_schema["schema"] = serde_json::json!("aos.ability.native-resource-ledger/v2");
        mutations.push(aos_contract::canonical::to_vec(&unsupported_schema)?);

        let mut unknown_field = value.clone();
        unknown_field["unexpected"] = serde_json::json!(true);
        mutations.push(aos_contract::canonical::to_vec(&unknown_field)?);

        for (field, forged) in [
            ("class", "foreign-resource"),
            ("authority", "foreign-manager"),
            ("object", "/org/example/foreign"),
        ] {
            let mut foreign_domain = value.clone();
            foreign_domain["consumers"][0]["physical"][field] = serde_json::json!(forged);
            mutations.push(aos_contract::canonical::to_vec(&foreign_domain)?);
        }

        mutations.push(serde_json::to_vec_pretty(&value)?);
        for malformed in mutations {
            std::fs::write(&ledger_path, malformed)?;
            assert!(load_native_resource_ledger(&ledger_path).is_err());
            assert!(generation_must_be_retained(&generation).is_err());
        }

        std::fs::write(&ledger_path, canonical)?;
        assert!(generation_must_be_retained(&generation)?);
        Ok(())
    }

    #[test]
    fn native_reservation_rejects_an_access_not_in_the_checked_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-1");
        std::fs::create_dir(&generation)?;
        let plan = checked_effect_plan();
        let transaction = TransactionId(aos_ability_model::LocalKey::new("native-access")?);
        let (inventory, _owner) =
            NativeResourceInventory::test_for_generation(&generation, &transaction, &plan)?;
        let operation = &plan.operations()[0];
        let operation_id = OperationId {
            plan: plan.id(),
            operation: operation.key.clone(),
        };
        let qualified = NativeQualifiedResource::systemd(
            operation.target.resource.clone(),
            "/org/freedesktop/systemd1/unit/example_2eservice",
        )?;
        let mut forged_access = operation.accesses[0].clone();
        forged_access.mode = AccessMode::SharedWrite;

        assert!(
            inventory
                .reserve(
                    &qualified,
                    ReservationContext {
                        transaction: &transaction,
                        operation: &operation_id,
                        attempt: NonZeroU32::new(1).ok_or("test attempt must be positive")?,
                        expected_provider: None,
                        recovery_remaining_millis: 1_000,
                    },
                    operation,
                    &forged_access,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn live_reservation_keeps_lock_owned_but_cannot_extend_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-1");
        std::fs::create_dir(&generation)?;
        let plan = checked_effect_plan();
        let transaction = TransactionId(aos_ability_model::LocalKey::new("native-lock")?);
        let (inventory, owner) =
            NativeResourceInventory::test_for_generation(&generation, &transaction, &plan)?;
        let operation = &plan.operations()[0];
        let operation_id = OperationId {
            plan: plan.id(),
            operation: operation.key.clone(),
        };
        let qualified = NativeQualifiedResource::systemd(
            operation.target.resource.clone(),
            "/org/freedesktop/systemd1/unit/example_2eservice",
        )?;
        let context = ReservationContext {
            transaction: &transaction,
            operation: &operation_id,
            attempt: NonZeroU32::new(1).ok_or("test attempt must be positive")?,
            expected_provider: None,
            recovery_remaining_millis: 1_000,
        };
        let mut reservation =
            inventory.reserve(&qualified, context, operation, &operation.accesses[0])?;
        let lock_path = directory.path().join(".ability-test-switch.lock");

        drop(owner);
        assert!(
            inventory
                .reserve(&qualified, context, operation, &operation.accesses[0])
                .is_err()
        );
        reservation.release()?;
        assert!(acquire_switch_lock_pub(&lock_path).is_err());

        drop(inventory);
        drop(reservation);
        let _replacement = acquire_switch_lock_pub(&lock_path)?;
        Ok(())
    }

    #[test]
    fn retains_and_reloads_an_exact_bundle_idempotently() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-7");
        std::fs::create_dir(&generation)?;
        let (planning, transition) = verified_planning_transition_plan();
        let plan = transition.checked_effect();
        let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?;
        let transaction = TransactionId(aos_ability_model::LocalKey::new("activate-7")?);
        let mut store = GenerationAbilityStore::with_bundle_at(
            &generation,
            bundle.clone(),
            BTreeSet::new(),
            TestArtifactVerifier,
            directory.path().join("switch.lock"),
        )?;

        let first = store.retain_plan(&transaction, plan)?;
        let second = store.retain_plan(&transaction, plan)?;

        assert_eq!(first.bundle(), bundle.digest()?);
        assert_eq!(second, first);
        drop(store);
        assert_eq!(
            GenerationAbilityStore::open_at(
                &generation,
                TestArtifactVerifier,
                directory.path().join("switch.lock"),
            )?
            .load_plan(&transaction, std::collections::BTreeSet::new())?
            .id(),
            plan.id()
        );
        Ok(())
    }

    #[test]
    fn conflicting_bundle_bytes_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-8");
        std::fs::create_dir(&generation)?;
        let (planning, transition) = verified_planning_transition_plan();
        let plan = transition.checked_effect();
        let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?;
        let transaction = TransactionId(aos_ability_model::LocalKey::new("activate-8")?);
        let mut store = GenerationAbilityStore::with_bundle_at(
            &generation,
            bundle,
            BTreeSet::new(),
            TestArtifactVerifier,
            directory.path().join("switch.lock"),
        )?;
        store.retain_plan(&transaction, plan)?;
        std::fs::write(store.bundle_path(&transaction), b"{}")?;

        assert!(matches!(
            store.retain_plan(&transaction, plan),
            Err(GenerationAbilityStoreError::Bundle(_))
        ));
        Ok(())
    }

    #[test]
    fn forged_plan_scalar_is_rejected_before_transaction_state_exists()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-forged");
        std::fs::create_dir(&generation)?;
        let (planning, transition) = verified_planning_transition_plan();
        let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?;
        let mut forged: serde_json::Value = serde_json::from_slice(&bundle.canonical_bytes()?)?;
        forged["transition"]["effect_document"]["limits"]["max_graph_edges"] = serde_json::json!(1);
        let forged = aos_contract::canonical::to_vec(&forged)?;

        assert!(ReloadablePlanBundle::decode(&forged).is_err());
        assert!(!generation.join(TRANSACTION_ROOT).exists());
        Ok(())
    }

    #[test]
    fn roots_use_the_generation_gc_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-9");
        std::fs::create_dir(&generation)?;
        let transaction = TransactionId(aos_ability_model::LocalKey::new("activate-9")?);
        let artifact = ArtifactReference {
            content: Sha256Digest::of_bytes("content"),
            store_path: "/nix/store/00000000000000000000000000000000-provider".to_string(),
            nar_hash: Sha256Digest::of_bytes("nar"),
            closure: Sha256Digest::of_bytes("closure"),
        };
        let mut store = GenerationAbilityStore::open_at(
            &generation,
            TestArtifactVerifier,
            directory.path().join("switch.lock"),
        )?;

        let receipt = store.retain(&transaction, std::slice::from_ref(&artifact))?;

        assert_eq!(receipt.roots(), &[artifact.closure]);
        assert_eq!(
            std::fs::read_link(
                store
                    .transaction_dir(&transaction)
                    .join("cfgsrc/00000000000000000000000000000000")
            )?,
            PathBuf::from(&artifact.store_path)
        );
        Ok(())
    }

    #[test]
    fn exact_artifacts_with_one_closure_remain_distinct() -> Result<(), Box<dyn std::error::Error>>
    {
        let closure = Sha256Digest::of_bytes("shared closure");
        let first = ArtifactReference {
            content: Sha256Digest::of_bytes("first content"),
            store_path: "/nix/store/00000000000000000000000000000000-first".to_string(),
            nar_hash: Sha256Digest::of_bytes("first nar"),
            closure,
        };
        let second = ArtifactReference {
            content: Sha256Digest::of_bytes("second content"),
            store_path: "/nix/store/11111111111111111111111111111111-second".to_string(),
            nar_hash: Sha256Digest::of_bytes("second nar"),
            closure,
        };

        let canonical = canonical_artifacts(&[second.clone(), first.clone(), first.clone()])?;

        assert_eq!(canonical, vec![first, second]);
        Ok(())
    }

    #[test]
    fn intervention_is_not_prune_eligible_until_resolution() {
        assert!(!terminal_is_prune_eligible(
            aos_ability_model::document::TerminalResult::InterventionRequired
        ));
        assert!(terminal_is_prune_eligible(
            aos_ability_model::document::TerminalResult::SettledFailure
        ));
        assert!(terminal_is_prune_eligible(
            aos_ability_model::document::TerminalResult::Succeeded
        ));
    }

    #[test]
    fn intervention_required_terminal_remains_prune_ineligible()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("gen-10");
        let transaction = TransactionId(aos_ability_model::LocalKey::new("activate-10")?);
        let transaction_dir = generation
            .join(TRANSACTION_ROOT)
            .join(transaction.0.as_str());
        std::fs::create_dir_all(&transaction_dir)?;

        let (planning, transition) = verified_planning_transition_plan();
        let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?;
        std::fs::write(
            transaction_dir.join(PLAN_BUNDLE_FILE),
            bundle.canonical_bytes()?,
        )?;
        let marker = TerminalMarker {
            schema: TERMINAL_MARKER_SCHEMA.to_string(),
            transaction,
            plan: bundle.plan(),
            terminal: aos_ability_model::document::TerminalResult::InterventionRequired,
        };
        std::fs::write(
            transaction_dir.join(TERMINAL_MARKER_FILE),
            aos_contract::canonical::to_vec(&marker)?,
        )?;

        assert!(generation_has_unfinished_transactions(&generation)?);
        Ok(())
    }
}
