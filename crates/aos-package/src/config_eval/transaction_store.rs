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
#[cfg(test)]
use std::fs;
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
use aos_ability_plan::TransitionReconciliation;
use aos_ability_runtime::adapter::{
    CancellationToken, MonotonicClock, PlanRetentionReceipt, RootRetentionReceipt, TrustedAdapter,
    TrustedPlanStore, TrustedResourceCatalog, TrustedRootStore,
};
use aos_ability_runtime::bundle::{PLAN_BUNDLE_MAX_BYTES, PlanBundleError, ReloadablePlanBundle};
use aos_ability_runtime::execution::{
    AdmissionFailure, AdmissionResult, AdmittedOperation, CheckedExecutionJournalSnapshot,
    ExecutionBoundaryObserver, ExecutionError, ExecutionStep, ExecutionTransaction, ReadyOperation,
    ResourceReleaseFailure, TerminalResult, TransactionError, TrustedAdmissionPolicy,
};
use aos_ability_runtime::journal::JournalLimits;
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::activation::{SwitchLockGuard, acquire_switch_lock_pub, default_switch_lock_path};
use super::protected_fs::RootedDirectory;
pub use crate::package_contract::NativePackageContractRetentionVerifier;
use crate::package_contract::VerifiedPackageContractSet;
use crate::store::create_config_gc_roots;
use crate::types::ProfileScope;

use super::transaction_verification::{AbilityArtifactVerifier, NativeAbilityArtifactVerifier};

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
pub enum GenerationTransactionStoreError {
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

impl fmt::Display for GenerationTransactionStoreError {
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

impl std::error::Error for GenerationTransactionStoreError {
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
pub struct SessionPersistenceFailure<T> {
    outcome: Box<T>,
    marker_error: Box<GenerationTransactionStoreError>,
}

impl<T> SessionPersistenceFailure<T> {
    /// Returns the operation outcome whose ownership remains with the caller.
    #[must_use]
    pub const fn outcome(&self) -> &T {
        &self.outcome
    }

    /// Returns the terminal-marker publication failure.
    #[must_use]
    pub const fn marker_error(&self) -> &GenerationTransactionStoreError {
        &self.marker_error
    }

    /// Separates the owned operation outcome from its marker failure.
    #[must_use]
    pub fn into_parts(self) -> (T, GenerationTransactionStoreError) {
        (*self.outcome, *self.marker_error)
    }
}

/// Represents a native session outcome whose ownership survives marker failure.
pub type SessionResult<T> = Result<T, SessionPersistenceFailure<T>>;

/// Represents post-settlement resource release, including retained handles.
pub type ResourceReleaseResult<'plan, Request, Handle> =
    Result<(), ResourceReleaseFailure<'plan, Request, Handle>>;

impl<T> fmt::Display for SessionPersistenceFailure<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native operation completed but terminal-marker publication failed: {}",
            self.marker_error
        )
    }
}

impl<T> std::error::Error for SessionPersistenceFailure<T>
where
    T: fmt::Debug,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.marker_error)
    }
}

/// Persists ability recovery state inside one retained config generation.
struct GenerationTransactionStore<Verifier> {
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
pub struct AbilityTransactionSession<'plan> {
    transaction: ExecutionTransaction<'plan>,
    store: GenerationTransactionStore<NativeAbilityArtifactVerifier>,
}

struct SessionPaths {
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
    generation: PathBuf,
    transaction: TransactionId,
    plan: CheckedEffectPlan,
    plan_bundle: Sha256Digest,
    desired_planning: Sha256Digest,
    reconciliation: Option<TransitionReconciliation>,
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
    ) -> Result<Self, GenerationTransactionStoreError> {
        let generation = generation.into();
        let expected_profile = ProfileScope::System.profile_path();
        Self::load_from_profile(
            generation,
            transaction,
            supported_features,
            &expected_profile,
        )
    }

    pub(in crate::config_eval::transaction_store) fn load_from_profile(
        generation: PathBuf,
        transaction: &TransactionId,
        supported_features: BTreeSet<RequiredFeature>,
        expected_profile: &Path,
    ) -> Result<Self, GenerationTransactionStoreError> {
        if generation.parent() != Some(expected_profile) {
            return Err(GenerationTransactionStoreError::Conflict(format!(
                "ability diagnostic generation {} is outside the canonical system profile {}",
                generation.display(),
                expected_profile.display()
            )));
        }
        let generation_name = generation
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                GenerationTransactionStoreError::Conflict(format!(
                    "ability diagnostic generation {} has no UTF-8 name",
                    generation.display()
                ))
            })?;
        validate_generation_name(generation_name).map_err(|source| {
            GenerationTransactionStoreError::Conflict(format!(
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
        let bundle = ReloadablePlanBundle::decode(&bytes)
            .map_err(GenerationTransactionStoreError::Bundle)?;
        let plan_bundle = bundle
            .digest()
            .map_err(GenerationTransactionStoreError::Bundle)?;
        let desired_planning = bundle.desired_planning_digest();
        let reconciliation = bundle.reconciliation().cloned();
        let plan = bundle
            .revalidate(supported_features)
            .map_err(GenerationTransactionStoreError::Bundle)?;

        Ok(Self {
            generation,
            transaction: transaction.clone(),
            plan,
            plan_bundle,
            desired_planning,
            reconciliation,
            journal,
            journal_path,
        })
    }

    pub(in crate::config_eval::transaction_store) fn operation_succeeded(
        self,
        limits: JournalLimits,
        operation: &aos_ability_model::OperationId,
        attempt: u32,
        terminal: TerminalResult,
    ) -> Result<bool, GenerationTransactionStoreError> {
        let expected_transaction = self.transaction.clone();
        let expected_bundle = self.plan_bundle;
        let snapshot = CheckedExecutionJournalSnapshot::read_file(
            &self.plan,
            self.journal,
            self.journal_path,
            limits,
        )
        .map_err(GenerationTransactionStoreError::Transaction)?;
        if snapshot.transaction() != &expected_transaction
            || snapshot.plan_bundle() != expected_bundle
            || snapshot.incomplete_tail_bytes() != 0
            || snapshot.terminal() != Some(terminal)
        {
            return Err(GenerationTransactionStoreError::Conflict(
                "retained native consumer journal differs from its protected terminal selection"
                    .to_string(),
            ));
        }
        let matching = snapshot
            .operations()
            .iter()
            .filter(|summary| summary.operation() == operation)
            .collect::<Vec<_>>();
        let [summary] = matching.as_slice() else {
            return Err(GenerationTransactionStoreError::Conflict(
                "retained native consumer operation is absent or ambiguous in its checked journal"
                    .to_string(),
            ));
        };
        Ok(
            summary.status() == aos_ability_runtime::execution::OperationStatus::Succeeded
                && summary.attempt().map(std::num::NonZeroU32::get) == Some(attempt),
        )
    }

    pub(in crate::config_eval::transaction_store) fn operation_reached_effect_intent(
        self,
        limits: JournalLimits,
        claimed_operation: &aos_ability_model::OperationId,
        claimed_attempt: u32,
        terminal: TerminalResult,
    ) -> Result<bool, GenerationTransactionStoreError> {
        let expected_transaction = self.transaction.clone();
        let expected_bundle = self.plan_bundle;
        let snapshot = CheckedExecutionJournalSnapshot::read_file(
            &self.plan,
            self.journal,
            self.journal_path,
            limits,
        )
        .map_err(GenerationTransactionStoreError::Transaction)?;
        if snapshot.transaction() != &expected_transaction
            || snapshot.plan_bundle() != expected_bundle
            || snapshot.incomplete_tail_bytes() != 0
            || snapshot.terminal() != Some(terminal)
        {
            return Err(GenerationTransactionStoreError::Conflict(
                "retained native owner claim journal differs from its protected terminal selection"
                    .to_string(),
            ));
        }
        let matching = snapshot
            .operations()
            .iter()
            .filter(|summary| summary.operation() == claimed_operation)
            .collect::<Vec<_>>();
        let [_summary] = matching.as_slice() else {
            return Err(GenerationTransactionStoreError::Conflict(
                "retained native owner claim operation is absent or ambiguous in its checked journal"
                    .to_string(),
            ));
        };
        Ok(snapshot.records().iter().any(|record| {
            matches!(
                record.body().body(),
                aos_ability_runtime::execution::ExecutionEventKind::EffectIntent {
                    operation: event_operation,
                    attempt: event_attempt,
                    ..
                } if event_operation == claimed_operation && event_attempt.get() == claimed_attempt
            )
        }))
    }

    /// Returns the freshly replayed exact checked plan.
    #[must_use]
    pub const fn plan(&self) -> &CheckedEffectPlan {
        &self.plan
    }

    /// Returns the transaction selected through the protected generation path.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// Returns the protected generation that owns the retained transaction.
    #[must_use]
    pub fn generation(&self) -> &Path {
        &self.generation
    }

    /// Returns the digest of the retained plan bundle in this transaction directory.
    #[must_use]
    pub const fn plan_bundle(&self) -> Sha256Digest {
        self.plan_bundle
    }

    /// Returns the planning state installed by the retained transaction.
    #[must_use]
    pub const fn desired_planning(&self) -> Sha256Digest {
        self.desired_planning
    }

    /// Returns the protected live classification retained by a repair graph.
    #[must_use]
    pub const fn reconciliation(&self) -> Option<&TransitionReconciliation> {
        self.reconciliation.as_ref()
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

    /// Replays this protected selection and returns its durable terminal state.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal is corrupt, has a torn tail, or names
    /// another selected transaction or plan bundle.
    pub(crate) fn terminal_result(
        self,
        limits: JournalLimits,
    ) -> Result<Option<TerminalResult>, GenerationTransactionStoreError> {
        let expected_transaction = self.transaction.clone();
        let expected_bundle = self.plan_bundle;
        let snapshot = CheckedExecutionJournalSnapshot::read_file(
            &self.plan,
            self.journal,
            self.journal_path,
            limits,
        )
        .map_err(GenerationTransactionStoreError::Transaction)?;
        if snapshot.transaction() != &expected_transaction
            || snapshot.plan_bundle() != expected_bundle
            || snapshot.incomplete_tail_bytes() != 0
        {
            return Err(GenerationTransactionStoreError::Conflict(
                "retained native transaction journal differs from its protected selection"
                    .to_string(),
            ));
        }
        Ok(snapshot.terminal())
    }
}

impl<'plan> AbilityTransactionSession<'plan> {
    /// Opens the runtime-owned blob store inside this durable transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected transaction or blob directories
    /// cannot be created, verified, or synchronized.
    pub(crate) fn transaction_blob_store(
        &self,
    ) -> Result<super::transaction_blob::TransactionBlobStore, GenerationTransactionStoreError>
    {
        let transaction = self.transaction.transaction();
        let directory = self.store.prepare_transaction_dir(transaction)?;
        super::transaction_blob::TransactionBlobStore::open(&directory, transaction).map_err(
            |source| io_error("opening ability transaction blob store", &directory, source),
        )
    }

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
        packages: VerifiedPackageContractSet,
    ) -> Result<Self, GenerationTransactionStoreError> {
        let generation = generation.into();
        let expected_profile = ProfileScope::System.profile_path();
        if generation.parent() != Some(expected_profile.as_path()) {
            return Err(GenerationTransactionStoreError::Conflict(format!(
                "native ability generation {} is outside the canonical system profile {}",
                generation.display(),
                expected_profile.display()
            )));
        }
        let journal = generation
            .join(TRANSACTION_ROOT)
            .join(transaction.0.as_str())
            .join(EXECUTION_JOURNAL_FILE);
        let paths = SessionPaths {
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

    /// Opens or recovers a checked stage transaction beneath a durable image root.
    ///
    /// Unlike [`Self::open`], this path is not a numbered configuration
    /// generation. The caller supplies a protected stage directory whose
    /// lifetime spans the initrd-to-host handoff, and the transaction store
    /// retains the exact plan bundle, artifact roots, blobs, and journal there.
    ///
    /// # Errors
    ///
    /// Returns an error when the stage directory or lock is unsafe, package
    /// artifacts differ, plan retention fails, or journal recovery fails.
    pub(crate) fn open_stage(
        plan: &'plan CheckedEffectPlan,
        transaction: TransactionId,
        limits: JournalLimits,
        stage_directory: impl Into<PathBuf>,
        supported_features: BTreeSet<RequiredFeature>,
        bundle: ReloadablePlanBundle,
        packages: VerifiedPackageContractSet,
    ) -> Result<Self, GenerationTransactionStoreError> {
        let generation = stage_directory.into();
        create_private_directory(&generation)?;
        let journal = generation
            .join(TRANSACTION_ROOT)
            .join(transaction.0.as_str())
            .join(EXECUTION_JOURNAL_FILE);
        let switch_lock = generation.join("execution.lock");
        let paths = SessionPaths {
            generation,
            journal,
            switch_lock,
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

    /// Opens or recovers a transaction while the caller retains the switch lock.
    ///
    /// This entry point lets configuration activation hold one uninterrupted
    /// ownership interval across generation publication and native effects.
    /// The session retains its own reference to `switch_lock`, so the lock
    /// cannot be released while a catalog handle or transaction remains live.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation lies outside the system profile,
    /// artifact or plan verification fails, or transaction recovery fails.
    pub(crate) fn open_with_switch_lock(
        plan: &'plan CheckedEffectPlan,
        transaction: TransactionId,
        limits: JournalLimits,
        generation: impl Into<PathBuf>,
        supported_features: BTreeSet<RequiredFeature>,
        bundle: ReloadablePlanBundle,
        packages: VerifiedPackageContractSet,
        switch_lock: Arc<SwitchLockGuard>,
    ) -> Result<Self, GenerationTransactionStoreError> {
        let generation = generation.into();
        let expected_profile = ProfileScope::System.profile_path();
        if generation.parent() != Some(expected_profile.as_path()) {
            return Err(GenerationTransactionStoreError::Conflict(format!(
                "native ability generation {} is outside the canonical system profile {}",
                generation.display(),
                expected_profile.display()
            )));
        }
        let journal = generation
            .join(TRANSACTION_ROOT)
            .join(transaction.0.as_str())
            .join(EXECUTION_JOURNAL_FILE);
        require_local_effect_plan(plan)?;
        packages
            .verify_plan_inputs(
                &plan.binding_plan().environment().platform,
                plan.binding_plan().packages(),
                plan.required_runtime_artifacts(),
            )
            .map_err(GenerationTransactionStoreError::Artifact)?;
        packages
            .verify_live_retention(&NativePackageContractRetentionVerifier::new())
            .map_err(GenerationTransactionStoreError::Artifact)?;
        let verifier = NativeAbilityArtifactVerifier {
            authenticated: packages,
            platform: plan.binding_plan().environment().platform.clone(),
        };
        let mut store = GenerationTransactionStore::with_bundle_and_lock(
            &generation,
            bundle,
            supported_features,
            verifier,
            switch_lock,
        );
        let transaction =
            ExecutionTransaction::open(plan, transaction, &journal, limits, &mut store)
                .map_err(GenerationTransactionStoreError::Transaction)?;
        Ok(Self { transaction, store })
    }

    fn open_at(
        plan: &'plan CheckedEffectPlan,
        transaction: TransactionId,
        limits: JournalLimits,
        supported_features: BTreeSet<RequiredFeature>,
        bundle: ReloadablePlanBundle,
        packages: VerifiedPackageContractSet,
        paths: SessionPaths,
    ) -> Result<Self, GenerationTransactionStoreError> {
        let SessionPaths {
            generation,
            journal,
            switch_lock,
        } = paths;
        require_local_effect_plan(plan)?;
        packages
            .verify_plan_inputs(
                &plan.binding_plan().environment().platform,
                plan.binding_plan().packages(),
                plan.required_runtime_artifacts(),
            )
            .map_err(GenerationTransactionStoreError::Artifact)?;
        packages
            .verify_live_retention(&NativePackageContractRetentionVerifier::new())
            .map_err(GenerationTransactionStoreError::Artifact)?;
        let verifier = NativeAbilityArtifactVerifier {
            authenticated: packages,
            platform: plan.binding_plan().environment().platform.clone(),
        };
        let mut store = GenerationTransactionStore::with_bundle_at(
            &generation,
            bundle,
            supported_features,
            verifier,
            &switch_lock,
        )?;
        let transaction =
            ExecutionTransaction::open(plan, transaction, &journal, limits, &mut store)
                .map_err(GenerationTransactionStoreError::Transaction)?;
        Ok(Self { transaction, store })
    }

    /// Opens a real journal around a checked test plan.
    #[cfg(test)]
    pub(crate) fn open_for_dispatch_test(
        plan: &'plan CheckedEffectPlan,
        transaction: TransactionId,
        generation: impl Into<PathBuf>,
        packages: VerifiedPackageContractSet,
    ) -> Result<Self, GenerationTransactionStoreError> {
        struct TestRetentionStore;

        impl TrustedPlanStore for TestRetentionStore {
            type Error = io::Error;

            fn retain_plan(
                &mut self,
                transaction: &TransactionId,
                plan: &CheckedEffectPlan,
            ) -> Result<PlanRetentionReceipt, Self::Error> {
                Ok(PlanRetentionReceipt::new(
                    transaction.clone(),
                    plan.id(),
                    Sha256Digest::of_bytes(b"native dispatcher test bundle"),
                    AbilityValue::new(serde_json::Value::Bool(true)).map_err(io::Error::other)?,
                ))
            }
        }

        impl TrustedRootStore for TestRetentionStore {
            type Error = io::Error;

            fn retain(
                &mut self,
                transaction: &TransactionId,
                artifacts: &[ArtifactReference],
            ) -> Result<RootRetentionReceipt, Self::Error> {
                Ok(RootRetentionReceipt::new(
                    transaction.clone(),
                    artifacts.iter().map(|artifact| artifact.closure).collect(),
                    AbilityValue::new(serde_json::Value::Bool(true)).map_err(io::Error::other)?,
                ))
            }
        }

        require_local_effect_plan(plan)?;
        let generation = generation.into();
        fs::create_dir_all(&generation).map_err(|source| {
            io_error(
                "creating native dispatcher test generation",
                &generation,
                source,
            )
        })?;
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o700)).map_err(|source| {
            io_error(
                "protecting native dispatcher test generation",
                &generation,
                source,
            )
        })?;
        let switch_lock = generation
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("native-dispatch-test.lock");
        let (planning, transition) =
            aos_ability_plan::test_support::verified_planning_transition_plan();
        let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)
            .map_err(GenerationTransactionStoreError::Bundle)?;
        let verifier = NativeAbilityArtifactVerifier {
            authenticated: packages,
            platform: plan.binding_plan().environment().platform.clone(),
        };
        let store = GenerationTransactionStore::with_bundle_at(
            &generation,
            bundle,
            BTreeSet::new(),
            verifier,
            &switch_lock,
        )?;
        let journal = generation
            .join(TRANSACTION_ROOT)
            .join(transaction.0.as_str())
            .join(EXECUTION_JOURNAL_FILE);
        let transaction_directory = journal.parent().ok_or_else(|| {
            GenerationTransactionStoreError::Conflict(
                "native dispatcher test journal has no parent directory".to_string(),
            )
        })?;
        create_private_directory(transaction_directory)?;
        let mut retention = TestRetentionStore;
        let transaction = ExecutionTransaction::open(
            plan,
            transaction,
            &journal,
            JournalLimits::default(),
            &mut retention,
        )
        .map_err(GenerationTransactionStoreError::Transaction)?;

        Ok(Self { transaction, store })
    }

    /// Returns the lock-bound execution transaction.
    #[must_use]
    pub const fn transaction(&self) -> &ExecutionTransaction<'plan> {
        &self.transaction
    }

    /// Publishes and applies the exact terminal outcome recovered by this session.
    ///
    /// Empty transactions must first publish their native no-op verification;
    /// callers therefore invoke this only after dispatch has performed that
    /// verification.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction is nonterminal, its immutable
    /// marker conflicts, or durable ownership finalization fails.
    pub(crate) fn finalize_terminal_outcome(&self) -> Result<(), GenerationTransactionStoreError> {
        if self.transaction.summary().terminal().is_none() {
            return Err(GenerationTransactionStoreError::Conflict(
                "native terminal finalization requires a terminal transaction".to_string(),
            ));
        }
        self.persist_terminal_marker()
    }

    /// Persists deterministic graph decisions and returns one bounded work batch.
    ///
    /// # Errors
    ///
    /// Returns an error when scheduling or terminal-marker publication fails.
    pub fn schedule_ready(
        &mut self,
        maximum_work: NonZeroUsize,
    ) -> Result<Vec<ReadyOperation>, GenerationTransactionStoreError> {
        let result = self
            .transaction
            .schedule_ready(maximum_work)
            .map_err(GenerationTransactionStoreError::Transaction);
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
    ) -> SessionResult<AdmissionResult<'plan, Adapter::Request, Adapter::Handle>>
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
    ) -> Result<Result<ExecutionStep, ExecutionError>, GenerationTransactionStoreError>
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

    /// Advances one admitted token while reporting exact execution boundaries.
    ///
    /// # Errors
    ///
    /// Returns an outer error when terminal-marker publication fails. Checked
    /// execution or observer failures remain in the inner result.
    pub fn drive_admitted_with_observer<Adapter, Policy, Clock, Observer>(
        &mut self,
        admitted: &AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        adapter: &mut Adapter,
        policy: &mut Policy,
        clock: &Clock,
        cancellation: &CancellationToken,
        observer: &mut Observer,
    ) -> Result<Result<ExecutionStep, ExecutionError>, GenerationTransactionStoreError>
    where
        Adapter: TrustedAdapter,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
        Observer: ExecutionBoundaryObserver,
    {
        let result = self.transaction.drive_admitted_with_observer(
            admitted,
            adapter,
            policy,
            clock,
            cancellation,
            observer,
        );
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
    ) -> Result<Result<ExecutionStep, ExecutionError>, GenerationTransactionStoreError>
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

    /// Requests checked cancellation while reporting exact execution boundaries.
    ///
    /// # Errors
    ///
    /// Returns an outer error when terminal-marker publication fails. Checked
    /// cancellation or observer failures remain in the inner result.
    pub fn cancel_admitted_with_observer<Adapter, Policy, Clock, Observer>(
        &mut self,
        admitted: &AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        adapter: &mut Adapter,
        policy: &mut Policy,
        clock: &Clock,
        cancellation: &CancellationToken,
        observer: &mut Observer,
    ) -> Result<Result<ExecutionStep, ExecutionError>, GenerationTransactionStoreError>
    where
        Adapter: TrustedAdapter,
        Policy: TrustedAdmissionPolicy,
        Clock: MonotonicClock,
        Observer: ExecutionBoundaryObserver,
    {
        let result = self.transaction.cancel_admitted_with_observer(
            admitted,
            adapter,
            policy,
            clock,
            cancellation,
            observer,
        );
        self.persist_terminal_marker()?;
        Ok(result)
    }

    /// Persists a fail-closed terminal when checked cancellation is unavailable.
    ///
    /// # Errors
    ///
    /// Returns an outer error when marker publication fails. Checked token or
    /// journal failures remain in the inner result.
    pub fn record_unsupported_cancellation<Request, Handle, Clock>(
        &mut self,
        admitted: &AdmittedOperation<'plan, Request, Handle>,
        clock: &Clock,
    ) -> Result<Result<(), ExecutionError>, GenerationTransactionStoreError>
    where
        Clock: MonotonicClock,
    {
        let result = self
            .transaction
            .record_unsupported_cancellation(admitted, clock);
        self.persist_terminal_marker()?;
        Ok(result)
    }

    /// Persists a fail-closed terminal when checked reconciliation is unavailable.
    ///
    /// # Errors
    ///
    /// Returns an outer error when marker publication fails. Checked token or
    /// journal failures remain in the inner result.
    pub fn record_unsupported_reconciliation<Request, Handle, Clock>(
        &mut self,
        admitted: &AdmittedOperation<'plan, Request, Handle>,
        clock: &Clock,
    ) -> Result<Result<(), ExecutionError>, GenerationTransactionStoreError>
    where
        Clock: MonotonicClock,
    {
        let result = self
            .transaction
            .record_unsupported_reconciliation(admitted, clock);
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
    ) -> Result<(), GenerationTransactionStoreError> {
        self.transaction
            .settle_failure_before_effect(operation, evidence)
            .map_err(GenerationTransactionStoreError::Transaction)?;
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
    ) -> SessionResult<ResourceReleaseResult<'plan, Adapter::Request, Adapter::Handle>>
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
    ) -> SessionResult<ResourceReleaseResult<'plan, Request, Handle>>
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
    ) -> Result<T, SessionPersistenceFailure<T>> {
        match self.persist_terminal_marker() {
            Ok(()) => Ok(outcome),
            Err(marker_error) => Err(SessionPersistenceFailure {
                outcome: Box::new(outcome),
                marker_error: Box::new(marker_error),
            }),
        }
    }

    fn persist_terminal_marker(&self) -> Result<(), GenerationTransactionStoreError> {
        let Some(terminal) = self.transaction.summary().terminal() else {
            return Ok(());
        };
        self.publish_terminal_marker(terminal)
    }

    fn publish_terminal_marker(
        &self,
        terminal: TerminalResult,
    ) -> Result<(), GenerationTransactionStoreError> {
        if !terminal_is_prune_eligible(terminal) {
            return Ok(());
        }
        let marker = TerminalMarker {
            schema: TERMINAL_MARKER_SCHEMA.to_string(),
            transaction: self.transaction.transaction().clone(),
            plan: self.transaction.plan().id(),
            terminal,
        };
        let marker_path = self
            .store
            .transaction_dir(self.transaction.transaction())
            .join(TERMINAL_MARKER_FILE);
        let bytes = aos_contract::canonical::to_vec(&marker).map_err(|source| {
            GenerationTransactionStoreError::Operation(anyhow::anyhow!(
                "encoding terminal marker: {source:#}"
            ))
        })?;
        publish_named_immutable(&marker_path, &bytes)
    }
}

fn require_local_effect_plan(
    plan: &CheckedEffectPlan,
) -> Result<(), GenerationTransactionStoreError> {
    let binding_plan = plan.binding_plan();
    let stage = binding_plan.environment().environment.stage;
    let supported = matches!(
        stage,
        ExecutionStage::Host | ExecutionStage::ApplicationContainer
    );
    if !supported
        || binding_plan.bindings().iter().any(|binding| {
            binding.provider.environment.stage != stage
                || binding.request.consumer.environment.stage != stage
        })
        || plan
            .operations()
            .iter()
            .any(|operation| operation.target.resource.provider.environment.stage != stage)
    {
        return Err(GenerationTransactionStoreError::Conflict(
            "effect plan crosses its host or application-container boundary".to_string(),
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

impl<Verifier> GenerationTransactionStore<Verifier> {
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
    ) -> Result<Self, GenerationTransactionStoreError> {
        let switch_lock = Arc::new(
            acquire_switch_lock_pub(switch_lock.as_ref())
                .map_err(GenerationTransactionStoreError::SwitchLock)?,
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
    ) -> Result<Self, GenerationTransactionStoreError> {
        let switch_lock = Arc::new(
            acquire_switch_lock_pub(switch_lock.as_ref())
                .map_err(GenerationTransactionStoreError::SwitchLock)?,
        );
        Ok(Self::with_bundle_and_lock(
            generation,
            bundle,
            supported_features,
            verifier,
            switch_lock,
        ))
    }

    fn with_bundle_and_lock(
        generation: impl Into<PathBuf>,
        bundle: ReloadablePlanBundle,
        supported_features: BTreeSet<RequiredFeature>,
        verifier: Verifier,
        switch_lock: Arc<SwitchLockGuard>,
    ) -> Self {
        Self {
            generation: generation.into(),
            pending_bundle: Some(bundle),
            supported_features,
            verifier,
            switch_lock,
        }
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
    ) -> Result<CheckedEffectPlan, GenerationTransactionStoreError> {
        let path = self.bundle_path(transaction);
        let bytes = read_file(&path)?;
        ReloadablePlanBundle::decode(&bytes)
            .and_then(|bundle| bundle.revalidate(supported_features))
            .map_err(GenerationTransactionStoreError::Bundle)
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
    ) -> Result<PathBuf, GenerationTransactionStoreError> {
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
    ) -> Result<(ReloadablePlanBundle, Vec<u8>, Sha256Digest), GenerationTransactionStoreError>
    {
        let path = self.bundle_path(transaction);
        let bundle = if path.is_file() {
            ReloadablePlanBundle::decode(&read_file(&path)?)
                .map_err(GenerationTransactionStoreError::Bundle)?
        } else {
            self.pending_bundle.clone().ok_or_else(|| {
                GenerationTransactionStoreError::Conflict(format!(
                    "transaction {:?} has no retained plan bundle",
                    transaction
                ))
            })?
        };
        let revalidated = bundle
            .clone()
            .revalidate(self.supported_features.clone())
            .map_err(GenerationTransactionStoreError::Bundle)?;
        if !checked_plans_match(&revalidated, plan) {
            return Err(GenerationTransactionStoreError::Conflict(format!(
                "transaction {:?} plan bundle does not reconstruct the supplied checked plan",
                transaction
            )));
        }
        let bytes = bundle
            .canonical_bytes()
            .map_err(GenerationTransactionStoreError::Bundle)?;
        let digest = bundle
            .digest()
            .map_err(GenerationTransactionStoreError::Bundle)?;
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

impl<Verifier> TrustedPlanStore for GenerationTransactionStore<Verifier>
where
    Verifier: AbilityArtifactVerifier,
{
    type Error = GenerationTransactionStoreError;

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
        .map_err(GenerationTransactionStoreError::Evidence)?;
        Ok(PlanRetentionReceipt::new(
            transaction.clone(),
            plan.id(),
            bundle_digest,
            evidence,
        ))
    }
}

impl<Verifier> TrustedRootStore for GenerationTransactionStore<Verifier>
where
    Verifier: AbilityArtifactVerifier,
{
    type Error = GenerationTransactionStoreError;

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
                    .map_err(GenerationTransactionStoreError::Roots)
            })
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        paths.dedup();
        let transaction_dir = self.prepare_transaction_dir(transaction)?;

        // Publish roots before inspecting bytes so concurrent GC cannot remove
        // a valid object between verification and durable retention.
        create_config_gc_roots(&transaction_dir, &[], &paths)
            .map_err(GenerationTransactionStoreError::Roots)?;
        sync_directory(&transaction_dir)?;
        for artifact in &canonical {
            self.verifier
                .verify(artifact)
                .map_err(GenerationTransactionStoreError::Artifact)?;
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
        .map_err(GenerationTransactionStoreError::Evidence)?;
        Ok(RootRetentionReceipt::new(
            transaction.clone(),
            roots,
            evidence,
        ))
    }
}

fn canonical_artifacts(
    artifacts: &[ArtifactReference],
) -> Result<Vec<ArtifactReference>, GenerationTransactionStoreError> {
    let mut canonical = Vec::with_capacity(artifacts.len());
    let mut by_content = BTreeMap::new();
    let mut by_store_path = BTreeMap::new();
    for artifact in artifacts {
        super::stock::store_root_and_suffix(Path::new(&artifact.store_path)).map_err(|source| {
            GenerationTransactionStoreError::Conflict(format!(
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
            return Err(GenerationTransactionStoreError::Conflict(
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
) -> Result<(), GenerationTransactionStoreError> {
    let parent = path.parent().ok_or_else(|| {
        GenerationTransactionStoreError::Conflict(format!(
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
            GenerationTransactionStoreError::Conflict(format!(
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

fn compare_existing(path: &Path, expected: &[u8]) -> Result<(), GenerationTransactionStoreError> {
    let existing = read_file(path)?;
    if existing == expected {
        Ok(())
    } else {
        Err(GenerationTransactionStoreError::Conflict(format!(
            "immutable ability file {} conflicts with requested bytes",
            path.display()
        )))
    }
}

fn create_private_directory(path: &Path) -> Result<(), GenerationTransactionStoreError> {
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

fn validate_generation_directory(path: &Path) -> Result<(), GenerationTransactionStoreError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|source| io_error("reading configuration generation", path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(GenerationTransactionStoreError::Conflict(format!(
            "configuration generation {} is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

/// Reports whether a generation contains unfinished ability recovery work.
///
/// # Errors
///
/// Returns an error when the generation name is invalid or when the transaction
/// directory itself cannot be listed.
pub(crate) fn generation_must_be_retained(generation: &Path) -> anyhow::Result<bool> {
    let name = generation
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("generation {} has no UTF-8 name", generation.display()))?;
    validate_generation_name(name).map_err(anyhow::Error::new)?;
    generation_has_unfinished_transactions(generation)
}

fn validate_generation_name(name: &str) -> Result<(), GenerationTransactionStoreError> {
    let Some(number) = name.strip_prefix("gen-") else {
        return Err(GenerationTransactionStoreError::Conflict(format!(
            "generation name {name:?} lacks the gen- prefix"
        )));
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(GenerationTransactionStoreError::Conflict(format!(
            "generation name {name:?} is not canonical"
        )));
    }
    Ok(())
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
            ReloadablePlanBundle::decode(&bytes).map_err(GenerationTransactionStoreError::Bundle)
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

fn read_file(path: &Path) -> Result<Vec<u8>, GenerationTransactionStoreError> {
    read_regular_file(path, PLAN_BUNDLE_MAX_BYTES, "retained plan bundle")
}

fn read_regular_file(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, GenerationTransactionStoreError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("opening retained plan bundle", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspecting retained plan bundle", path, source))?;
    if !metadata.is_file() {
        return Err(GenerationTransactionStoreError::Conflict(format!(
            "{label} {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(GenerationTransactionStoreError::Conflict(format!(
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
        return Err(GenerationTransactionStoreError::Conflict(format!(
            "{label} {} grew beyond the {}-byte limit while reading",
            path.display(),
            max_bytes
        )));
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), GenerationTransactionStoreError> {
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
) -> GenerationTransactionStoreError {
    GenerationTransactionStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_name_is_canonical() {
        validate_generation_name("gen-42").expect("canonical generation name");
        assert!(validate_generation_name("42").is_err());
        assert!(validate_generation_name("gen-").is_err());
        assert!(validate_generation_name("gen-4a").is_err());
    }
}
