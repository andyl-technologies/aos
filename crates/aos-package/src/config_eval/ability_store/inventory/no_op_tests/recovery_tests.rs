//! Integrated journal and durable-owner recovery tests.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;

use aos_ability_model::{AbilityValue, LocalKey, RetryPolicy, VersionedDocument};
use aos_ability_plan::{
    BindingCandidate, CandidateSelection, CompositionContext, CompositionEvaluator,
    CompositionFragment, EvaluationError, PlanningReplayInputs, PlanningSnapshot,
    RecursiveComposer, ResolutionPolicyDocument, TransitionContext, TransitionFragment,
    TransitionInputs, TransitionPlanner, VerifiedPlanningSnapshot, VerifiedTransitionPlan,
};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CancellationToken,
    CatalogReservation, EffectDisposition, InvocationPurpose, MonotonicClock, PlanRetentionReceipt,
    ReconcileDisposition, ReservationContext, ResourceAdmissionEvidence, ResourceHandle,
    RootRetentionReceipt, RuntimeControl, TrustedAdapter, TrustedPlanStore, TrustedResourceCatalog,
    TrustedRootStore,
};
use aos_ability_runtime::bundle::ReloadablePlanBundle;
use aos_ability_runtime::execution::{
    Boundary, ExecutionBoundaryControl, ExecutionBoundaryObservation, ExecutionBoundaryObserver,
    ExecutionError, ExecutionStep, ExecutionTransaction, RecoveryAction, TrustedAdmissionPolicy,
};
use aos_ability_runtime::journal::JournalLimits;
use aos_ability_validate::test_support::stateful_owner_plan_fixture;

use super::*;
use crate::config_eval::ability_store::verification::AbilityArtifactVerifier;
use crate::config_eval::ability_store::{
    EXECUTION_JOURNAL_FILE, GenerationAbilityStore, NATIVE_NO_OP_VERIFICATION_FILE,
    NATIVE_NO_OP_VERIFICATION_SCHEMA, NativeNoOpVerificationMarker, TERMINAL_MARKER_FILE,
    TERMINAL_MARKER_SCHEMA, TRANSACTION_ROOT, TerminalMarker,
};

#[path = "recovery_tests/planner_fixture.rs"]
mod planner_fixture;

use planner_fixture::*;

#[test]
fn real_recovery_fixture_persists_an_exact_replayable_bundle() {
    let fixture = real_recovery_plan("first-incarnation");
    let bundle = fixture.bundle();

    assert_eq!(bundle.plan(), fixture.transition.checked_effect().id());
    assert_eq!(fixture.transition.checked_effect().operations().len(), 1);
}

#[derive(Clone, Debug, Default)]
struct RecoveryArtifactVerifier;

impl AbilityArtifactVerifier for RecoveryArtifactVerifier {
    fn verify(&self, artifact: &aos_ability_model::ArtifactReference) -> anyhow::Result<()> {
        anyhow::ensure!(
            artifact.store_path.starts_with("/nix/store/"),
            "test artifact is outside the store"
        );
        Ok(())
    }
}

struct ReopenStore {
    bundle: aos_contract::Sha256Digest,
}

impl TrustedRootStore for ReopenStore {
    type Error = io::Error;

    fn retain(
        &mut self,
        transaction: &aos_ability_model::TransactionId,
        artifacts: &[aos_ability_model::ArtifactReference],
    ) -> Result<RootRetentionReceipt, Self::Error> {
        let mut roots = artifacts
            .iter()
            .map(|artifact| artifact.closure)
            .collect::<Vec<_>>();
        roots.sort_unstable();
        roots.dedup();

        Ok(RootRetentionReceipt::new(
            transaction.clone(),
            roots,
            bool_value(true),
        ))
    }
}

impl TrustedPlanStore for ReopenStore {
    type Error = io::Error;

    fn retain_plan(
        &mut self,
        transaction: &aos_ability_model::TransactionId,
        plan: &aos_ability_validate::CheckedEffectPlan,
    ) -> Result<PlanRetentionReceipt, Self::Error> {
        Ok(PlanRetentionReceipt::new(
            transaction.clone(),
            plan.id(),
            self.bundle,
            bool_value(true),
        ))
    }
}

struct IntegratedRecoveryFixture {
    _root: Arc<tempfile::TempDir>,
    generation: PathBuf,
    transaction: aos_ability_model::TransactionId,
    plan: aos_ability_validate::CheckedEffectPlan,
    bundle: ReloadablePlanBundle,
    state: Arc<NativeInventoryState>,
    _admission: Arc<()>,
}

pub(super) struct AuthenticatedSourceOwner {
    pub(super) owner: NativeProviderOwner,
    pub(super) assignment: aos_ability_model::ProviderAssignment,
    pub(super) supported_features: BTreeSet<aos_ability_model::RequiredFeature>,
}

pub(super) fn establish_authenticated_source_owner(
    root: Arc<tempfile::TempDir>,
) -> Result<AuthenticatedSourceOwner, Box<dyn std::error::Error>> {
    let fixture =
        IntegratedRecoveryFixture::in_profile(root, "gen-1", "source", "source-incarnation")?;
    let assignment = fixture.checked_assignment()?;

    complete_and_finalize(&fixture)?;
    let ledger = fixture.ledger()?;
    let [owner] = ledger.owners.as_slice() else {
        return Err("authenticated source fixture must retain exactly one owner".into());
    };

    Ok(AuthenticatedSourceOwner {
        owner: owner.clone(),
        assignment,
        supported_features: fixture.state.supported_features.clone(),
    })
}

impl IntegratedRecoveryFixture {
    fn new(incarnation: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::in_profile(
            Arc::new(tempfile::tempdir()?),
            "gen-2",
            "candidate",
            incarnation,
        )
    }

    fn in_profile(
        root: Arc<tempfile::TempDir>,
        generation_name: &str,
        transaction_name: &str,
        incarnation: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_real_in_profile(
            root,
            generation_name,
            transaction_name,
            real_recovery_plan(incarnation),
        )
    }

    fn retrying_new(incarnation: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_real_in_profile(
            Arc::new(tempfile::tempdir()?),
            "gen-2",
            "candidate",
            real_retry_recovery_plan(incarnation),
        )
    }

    fn from_real_in_profile(
        root: Arc<tempfile::TempDir>,
        generation_name: &str,
        transaction_name: &str,
        real: RealRecoveryPlan,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bundle = real.bundle();
        let supported_features = real.supported_features;
        let plan = real.transition.into_checked_effect();
        let generation = root.path().join(generation_name);
        std::fs::create_dir(&generation)?;
        let transaction = aos_ability_model::TransactionId(key(transaction_name));
        let mut store = GenerationAbilityStore::with_bundle_at(
            &generation,
            bundle.clone(),
            supported_features.clone(),
            RecoveryArtifactVerifier,
            root.path().join("switch.lock"),
        )?;
        let state = NativeInventoryState::for_generation(
            &generation,
            &transaction,
            &plan,
            store.pending_bundle.as_ref(),
            supported_features,
            Arc::clone(&store.switch_lock),
        )?;
        store.retain_plan(&transaction, &plan)?;
        let admission = Arc::new(());

        Ok(Self {
            _root: root,
            generation,
            transaction,
            plan,
            bundle,
            state,
            _admission: admission,
        })
    }

    fn operation(&self) -> &aos_ability_model::Operation {
        &self.plan.operations()[0]
    }

    fn operation_id(&self) -> aos_ability_model::OperationId {
        aos_ability_model::OperationId {
            plan: self.plan.id(),
            operation: self.operation().key.clone(),
        }
    }

    fn journal_path(&self) -> PathBuf {
        self.generation
            .join(TRANSACTION_ROOT)
            .join(self.transaction.0.as_str())
            .join(EXECUTION_JOURNAL_FILE)
    }

    fn open(&self) -> Result<ExecutionTransaction<'_>, Box<dyn std::error::Error>> {
        let mut store = ReopenStore {
            bundle: self.bundle.digest()?,
        };
        Ok(ExecutionTransaction::open(
            &self.plan,
            self.transaction.clone(),
            self.journal_path(),
            JournalLimits::default(),
            &mut store,
        )?)
    }

    fn checked_assignment(&self) -> Result<aos_ability_model::ProviderAssignment, &'static str> {
        let binding = self
            .plan
            .binding_plan()
            .binding(&self.operation().binding)
            .ok_or("stateful operation binding is absent")?;
        let provider = self
            .plan
            .binding_plan()
            .environment()
            .providers
            .iter()
            .find(|provider| {
                provider.provider == binding.provider
                    && provider.interface == binding.interface
                    && provider.implementation == binding.implementation
            })
            .ok_or("stateful handler inventory is absent")?;

        Ok(aos_ability_model::ProviderAssignment {
            provider: provider.provider.clone(),
            interface: provider.interface.clone(),
            implementation: provider.implementation.clone(),
            incarnation: provider
                .incarnation
                .clone()
                .ok_or("stateful handler incarnation is absent")?,
        })
    }

    fn qualified(&self) -> Result<NativeQualifiedResource, Box<dyn std::error::Error>> {
        Ok(NativeQualifiedResource::systemd(
            self.operation().target.resource.clone(),
            "/org/freedesktop/systemd1/unit/recovery_2eservice",
        )?)
    }

    fn reserve(
        &self,
        attempt: u32,
    ) -> Result<NativeResourceReservation, Box<dyn std::error::Error>> {
        let attempt = NonZeroU32::new(attempt).ok_or("reservation attempt must be positive")?;
        Ok(self.state.reserve(
            &self.qualified()?,
            ReservationContext {
                transaction: &self.transaction,
                operation: &self.operation_id(),
                attempt,
                expected_provider: Some(&self.checked_assignment()?),
                recovery_remaining_millis: 1_000,
            },
            self.operation(),
            &self.operation().accesses[0],
        )?)
    }

    fn ledger(&self) -> Result<NativeResourceLedger, GenerationAbilityStoreError> {
        load_native_resource_ledger(&self.state.ledger_path)
    }

    fn preflight(
        &self,
        transaction: &ExecutionTransaction<'_>,
        current_contains_resource: bool,
    ) -> Result<(), GenerationAbilityStoreError> {
        self.state
            .preflight_provider_owners_for_recovery_test(transaction, |_| current_contains_resource)
    }

    fn preflight_after_restart(
        &self,
        transaction: &ExecutionTransaction<'_>,
        current_contains_resource: bool,
    ) -> Result<(), GenerationAbilityStoreError> {
        self.state_after_restart()?
            .preflight_provider_owners_for_recovery_test(transaction, |_| current_contains_resource)
    }

    fn state_after_restart(
        &self,
    ) -> Result<Arc<NativeInventoryState>, GenerationAbilityStoreError> {
        NativeInventoryState::for_generation(
            &self.generation,
            &self.transaction,
            &self.plan,
            Some(&self.bundle),
            self.state.supported_features.clone(),
            Arc::clone(&self.state._switch_lock),
        )
    }

    fn write_terminal_marker(
        &self,
        terminal: aos_ability_model::document::TerminalResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let marker = TerminalMarker {
            schema: TERMINAL_MARKER_SCHEMA.to_string(),
            transaction: self.transaction.clone(),
            plan: self.plan.id(),
            terminal,
        };
        std::fs::write(
            self.generation
                .join(TRANSACTION_ROOT)
                .join(self.transaction.0.as_str())
                .join(TERMINAL_MARKER_FILE),
            aos_contract::canonical::to_vec(&marker)?,
        )?;
        Ok(())
    }
}

#[derive(Default)]
struct JournalCatalog;

impl TrustedResourceCatalog for JournalCatalog {
    type Handle = String;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        _operation: &aos_ability_model::Operation,
        access: &aos_ability_model::ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        Ok(CatalogReservation::new(
            access.resource.key.as_str().to_string(),
            ResourceAdmissionEvidence::new(
                access.resource.clone(),
                context
                    .expected_provider
                    .map(|assignment| assignment.incarnation.clone()),
                None,
                bool_value(true),
            ),
        ))
    }

    fn release(
        &mut self,
        _resource: &aos_ability_model::ResourceId,
        _handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct AllowAllPolicy;

impl TrustedAdmissionPolicy for AllowAllPolicy {
    type Error = io::Error;

    fn authorize(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &aos_ability_model::Operation,
        _method: &aos_ability_model::MethodReference,
        _purpose: InvocationPurpose,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn authorize_resources(
        &mut self,
        _plan: &aos_ability_validate::CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &aos_ability_model::Operation,
        _expected_provider: Option<&aos_ability_model::ProviderAssignment>,
        _resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone)]
struct RecoveryRecord {
    evidence: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for RecoveryRecord {
    fn durable(&self) -> &AbilityValue {
        &self.evidence
    }
}

impl AdapterCompletion for RecoveryRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

#[derive(Default)]
struct IndeterminateThenRetryAdapter;

impl TrustedAdapter for IndeterminateThenRetryAdapter {
    type Request = AbilityValue;
    type Completion = RecoveryRecord;
    type Observation = RecoveryRecord;
    type Handle = String;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        _implementation: &aos_ability_model::ProviderImplementationReference,
        _method: &aos_ability_model::MethodReference,
        _purpose: InvocationPurpose,
    ) -> bool {
        true
    }

    fn supports_compensation(&self) -> bool {
        false
    }

    fn prepare_durable(
        &self,
        _operation: &aos_ability_model::Operation,
        inputs: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        Ok(inputs.clone())
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        Ok(durable.clone())
    }

    fn execute(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        EffectDisposition::Indeterminate(recovery_record())
    }

    fn reconcile(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        ReconcileDisposition::SafeToRetry(recovery_record())
    }

    fn cancel(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        CancellationDisposition::Indeterminate(recovery_record())
    }
}

struct CompletedAdapter {
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl CompletedAdapter {
    fn for_fixture(fixture: &IntegratedRecoveryFixture) -> Self {
        Self::for_operation(&fixture.plan, fixture.operation())
    }

    fn for_operation(
        plan: &aos_ability_validate::CheckedEffectPlan,
        operation: &aos_ability_model::Operation,
    ) -> Self {
        let method = plan
            .interfaces()
            .get(&operation.interface)
            .and_then(|interface| interface.interface.methods.get(&operation.method))
            .expect("recovery operation method descriptor");
        Self {
            outputs: method
                .outputs
                .keys()
                .cloned()
                .map(|output| (output, bool_value(true)))
                .collect(),
        }
    }
}

impl TrustedAdapter for CompletedAdapter {
    type Request = AbilityValue;
    type Completion = RecoveryRecord;
    type Observation = RecoveryRecord;
    type Handle = String;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        _implementation: &aos_ability_model::ProviderImplementationReference,
        _method: &aos_ability_model::MethodReference,
        _purpose: InvocationPurpose,
    ) -> bool {
        true
    }

    fn supports_compensation(&self) -> bool {
        false
    }

    fn prepare_durable(
        &self,
        _operation: &aos_ability_model::Operation,
        inputs: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        Ok(inputs.clone())
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        Ok(durable.clone())
    }

    fn execute(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        EffectDisposition::Completed(RecoveryRecord {
            evidence: bool_value(true),
            outputs: self.outputs.clone(),
        })
    }

    fn reconcile(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        ReconcileDisposition::InterventionRequired(recovery_record())
    }

    fn cancel(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        CancellationDisposition::Indeterminate(recovery_record())
    }
}

struct RecoveryClock;

impl MonotonicClock for RecoveryClock {
    fn now_millis(&self) -> u64 {
        0
    }

    fn restart_stable_millis(&self) -> u64 {
        0
    }
}

struct HaltAtIntent;

impl ExecutionBoundaryObserver for HaltAtIntent {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if observation.boundary() == Boundary::EffectIntentDurable {
            Ok(ExecutionBoundaryControl::Halt)
        } else {
            Ok(ExecutionBoundaryControl::Continue)
        }
    }
}

fn recovery_record() -> RecoveryRecord {
    RecoveryRecord {
        evidence: bool_value(true),
        outputs: BTreeMap::new(),
    }
}

fn bool_value(value: bool) -> AbilityValue {
    AbilityValue::new(serde_json::Value::Bool(value)).expect("Boolean ability value")
}

#[path = "recovery_tests/lifecycle_tests.rs"]
mod lifecycle_tests;

fn admission_error<Handle>(
    failure: aos_ability_runtime::execution::AdmissionFailure<Handle>,
) -> io::Error {
    io::Error::other(failure.error().to_string())
}

fn halt_at_effect_intent(
    fixture: &IntegratedRecoveryFixture,
    transaction: &mut ExecutionTransaction<'_>,
    attempt: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let reservation = fixture.reserve(attempt)?;
    let mut catalog = JournalCatalog;
    let mut policy = AllowAllPolicy;
    let mut adapter = IndeterminateThenRetryAdapter;
    let admitted = transaction
        .admit(
            &fixture.operation().key,
            &adapter,
            &mut catalog,
            &mut policy,
            &RecoveryClock,
        )
        .map_err(admission_error)?;
    assert_eq!(admitted.attempt().get(), attempt);
    let error = transaction
        .drive_admitted_with_observer(
            &admitted,
            &mut adapter,
            &mut policy,
            &RecoveryClock,
            &CancellationToken::default(),
            &mut HaltAtIntent,
        )
        .expect_err("fixture must halt at durable effect intent");
    assert!(matches!(
        error,
        ExecutionError::BoundaryHalt(Boundary::EffectIntentDurable)
    ));
    drop(admitted);
    drop(reservation);
    Ok(())
}

fn progress_to_retry_attempt_two(
    fixture: &IntegratedRecoveryFixture,
) -> Result<ExecutionTransaction<'_>, Box<dyn std::error::Error>> {
    let mut transaction = fixture.open()?;
    fixture.preflight(&transaction, false)?;
    let reservation = fixture.reserve(1)?;
    let mut catalog = JournalCatalog;
    let mut policy = AllowAllPolicy;
    let mut adapter = IndeterminateThenRetryAdapter;
    let admitted = transaction
        .admit(
            &fixture.operation().key,
            &adapter,
            &mut catalog,
            &mut policy,
            &RecoveryClock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &RecoveryClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Indeterminate
    );
    drop(admitted);
    drop(reservation);
    drop(transaction);

    let mut transaction = fixture.open()?;
    fixture.preflight_after_restart(&transaction, false)?;
    let recovery = transaction
        .admit(
            &fixture.operation().key,
            &adapter,
            &mut catalog,
            &mut policy,
            &RecoveryClock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &recovery,
            &mut adapter,
            &mut policy,
            &RecoveryClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::SafeToRetry
    );
    transaction
        .release_admitted::<IndeterminateThenRetryAdapter, _, _>(
            recovery,
            &mut catalog,
            &RecoveryClock,
        )
        .map_err(|failure| io::Error::other(failure.error().to_string()))?;
    assert!(matches!(
        transaction.next_action(&fixture.operation().key)?,
        RecoveryAction::Retry { attempt } if attempt.get() == 2
    ));
    Ok(transaction)
}

fn complete_and_finalize(
    fixture: &IntegratedRecoveryFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transaction = fixture.open()?;
    fixture.preflight(&transaction, false)?;
    let reservation = fixture.reserve(1)?;
    let mut catalog = JournalCatalog;
    let mut policy = AllowAllPolicy;
    let mut adapter = CompletedAdapter::for_fixture(fixture);
    let admitted = transaction
        .admit(
            &fixture.operation().key,
            &adapter,
            &mut catalog,
            &mut policy,
            &RecoveryClock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &RecoveryClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Completed
    );
    transaction
        .release_admitted::<CompletedAdapter, _, _>(admitted, &mut catalog, &RecoveryClock)
        .map_err(|failure| io::Error::other(failure.error().to_string()))?;
    drop(reservation);
    assert_eq!(
        transaction.summary().terminal(),
        Some(aos_ability_model::document::TerminalResult::Succeeded)
    );
    fixture.write_terminal_marker(aos_ability_model::document::TerminalResult::Succeeded)?;
    fixture
        .state
        .finalize_existing_terminal_marker(&transaction.summary())?;
    drop(transaction);

    let reopened = fixture.open()?;
    let restarted_state = fixture.state_after_restart()?;
    restarted_state.preflight_provider_owners_for_recovery_test(&reopened, |_| true)?;
    restarted_state.finalize_existing_terminal_marker(&reopened.summary())?;
    Ok(())
}

#[path = "recovery_tests/cases.rs"]
mod cases;

#[path = "recovery_tests/adoption_tests.rs"]
mod adoption_tests;
