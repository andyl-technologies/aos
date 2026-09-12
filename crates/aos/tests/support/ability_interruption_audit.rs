//! Executes the closed native-adapter interruption qualification cohort.
//!
//! The release image runs this binary from the candidate package runtime. Each
//! cell builds a checked plan from the exact published interface descriptor,
//! halts admission before resource acquisition, drops the transaction, and
//! reopens its durable journal. Evidence comes from the journal, a durable
//! reservation ledger, and an independent foreign sentinel. Later boundaries
//! require provider-specific effect oracles and stay outside this cohort.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, ArtifactReference, ControllerAssignment, DependencyEdge,
    ExecutionStage, InterfaceDocument, InterfaceKey, LocalKey, MethodDescriptor, MethodReference,
    Operation, PlanNodeKey, ProviderAssignment, ProviderImplementationReference, ResourceAccess,
    ResourceId, RetryPolicy, StringSyntax, TransactionId, ValueExpression, ValueSchema,
};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CatalogReservation,
    EffectDisposition, InvocationPurpose, MonotonicClock, PlanRetentionReceipt,
    ReconcileDisposition, ReservationContext, ResourceAdmissionEvidence, ResourceHandle,
    RootRetentionReceipt, RuntimeControl, TrustedAdapter, TrustedPlanStore, TrustedResourceCatalog,
    TrustedRootStore,
};
use aos_ability_runtime::execution::{
    AdmissionError, AuthorityRejection, Boundary, CheckedExecutionJournalSnapshot,
    ExecutionBoundaryControl, ExecutionBoundaryObservation, ExecutionBoundaryObserver,
    ExecutionEventKind, ExecutionTransaction, RecoveryAction, RuntimeAuthorityRole,
    TrustedAdmissionPolicy, TrustedAuthoritySnapshot,
};
use aos_ability_runtime::journal::JournalLimits;
use aos_ability_validate::CheckedEffectPlan;
use aos_ability_validate::test_support::{PlanFixture, plan_fixture};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

const OUTPUT_SCHEMA: &str = "aos.qualification.interruption-audit/v1";
const SUBJECT_SCHEMA: &str = "aos.qualification.interruption-subject/v1";
const PLAN_BUNDLE_SCHEMA: &str = "aos.qualification.interruption-plan/v1";
const INTERRUPTION_SCENARIO: &str = "interrupt-before-acquisition";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixSpec {
    schema: String,
    surface: Surface,
    subject: Value,
    cells: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Surface {
    schema: String,
    matrix_schema: String,
    subject_schema: String,
    limits: Value,
    adapters: Vec<Adapter>,
    scenarios: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Adapter {
    adapter: String,
    interface_name: String,
    interface_abi: u32,
    interface_descriptor: String,
    scope: String,
    methods: Vec<MatrixMethod>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixMethod {
    method: String,
    effect_class: String,
    reconcile: Option<String>,
    cancel: Option<String>,
}

#[derive(Serialize)]
struct AuditOutput {
    schema: &'static str,
    matrix_spec_digest: String,
    cells: BTreeMap<String, AuditCell>,
}

#[derive(Serialize)]
struct AuditCell {
    cell_digest: String,
    subject: Value,
    plan_bundle: Value,
    evidence: Value,
}

#[derive(Clone)]
struct AuditRecord {
    evidence: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for AuditRecord {
    fn durable(&self) -> &AbilityValue {
        &self.evidence
    }
}

impl AdapterCompletion for AuditRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

#[derive(Default)]
struct NoDispatchAdapter {
    calls: usize,
}

impl TrustedAdapter for NoDispatchAdapter {
    type Request = AbilityValue;
    type Completion = AuditRecord;
    type Observation = AuditRecord;
    type Handle = String;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        _implementation: &ProviderImplementationReference,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
    ) -> bool {
        true
    }

    fn prepare_durable(
        &self,
        _operation: &Operation,
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
        request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        self.calls += 1;
        EffectDisposition::RejectedBeforeEffect(AuditRecord {
            evidence: request.clone(),
            outputs: BTreeMap::new(),
        })
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        self.calls += 1;
        ReconcileDisposition::StillIndeterminate(AuditRecord {
            evidence: request.clone(),
            outputs: BTreeMap::new(),
        })
    }

    fn cancel(
        &mut self,
        request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        self.calls += 1;
        CancellationDisposition::Indeterminate(AuditRecord {
            evidence: request.clone(),
            outputs: BTreeMap::new(),
        })
    }
}

#[derive(Clone, Copy)]
struct AuditClock;

impl MonotonicClock for AuditClock {
    fn now_millis(&self) -> u64 {
        1
    }

    fn restart_stable_millis(&self) -> u64 {
        1
    }
}

#[derive(Clone, Copy)]
struct AllowPolicy;

impl TrustedAuthoritySnapshot for AllowPolicy {
    type Error = io::Error;

    fn authorize_role(
        &mut self,
        _plan: &CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
        _role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn authorize_resources(
        &mut self,
        _plan: &CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _expected_provider: Option<&ProviderAssignment>,
        _resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl TrustedAdmissionPolicy for AllowPolicy {
    type DispatchFence = Self;

    fn acquire_dispatch_fence(
        &mut self,
        _plan: &CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
    ) -> Result<Self::DispatchFence, AuthorityRejection<Self::Error>> {
        Ok(*self)
    }
}

struct HaltAtBoundary {
    path: PathBuf,
    observed: Option<Boundary>,
}

impl ExecutionBoundaryObserver for HaltAtBoundary {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if observation.boundary() != Boundary::BeforeResourceAcquisition {
            return Ok(ExecutionBoundaryControl::Continue);
        }

        let bytes = canonical_bytes(&json!({
            "schema": "aos.qualification.interruption-boundary/v1",
            "scenario": INTERRUPTION_SCENARIO,
            "transaction": observation.transaction(),
            "operation": observation.operation(),
            "attempt": observation.attempt(),
            "purpose": observation.purpose(),
            "boundary": format!("{:?}", observation.boundary()),
        }))?;
        write_durable(&self.path, &bytes)?;
        self.observed = Some(observation.boundary());
        Ok(ExecutionBoundaryControl::Halt)
    }
}

struct DurableStore {
    directory: PathBuf,
    plan_bundle: Vec<u8>,
    bundle_digest: Option<Sha256Digest>,
}

impl TrustedPlanStore for DurableStore {
    type Error = io::Error;

    fn retain_plan(
        &mut self,
        transaction: &TransactionId,
        plan: &CheckedEffectPlan,
    ) -> Result<PlanRetentionReceipt, Self::Error> {
        let bundle: Value = serde_json::from_slice(&self.plan_bundle).map_err(io::Error::other)?;
        if bundle.get("plan") != Some(&json!(plan.id())) {
            return Err(io::Error::other("retained bundle plan identity differs"));
        }
        write_durable(&self.directory.join("plan-bundle.json"), &self.plan_bundle)?;
        let digest = Sha256Digest::of_bytes(&self.plan_bundle);
        self.bundle_digest = Some(digest);
        Ok(PlanRetentionReceipt::new(
            transaction.clone(),
            plan.id(),
            digest,
            AbilityValue::new(json!({"durable": true})).map_err(io::Error::other)?,
        ))
    }
}

impl TrustedRootStore for DurableStore {
    type Error = io::Error;

    fn retain(
        &mut self,
        transaction: &TransactionId,
        artifacts: &[ArtifactReference],
    ) -> Result<RootRetentionReceipt, Self::Error> {
        let mut roots: Vec<_> = artifacts.iter().map(|artifact| artifact.closure).collect();
        roots.sort_unstable();
        roots.dedup();
        let bytes = canonical_bytes(&json!({
            "transaction": transaction,
            "roots": roots,
        }))
        .map_err(io::Error::other)?;
        write_durable(&self.directory.join("retained-roots.json"), &bytes)?;
        Ok(RootRetentionReceipt::new(
            transaction.clone(),
            roots,
            AbilityValue::new(json!({"durable": true})).map_err(io::Error::other)?,
        ))
    }
}

#[derive(Default)]
struct ReservationState {
    acquire_calls: usize,
    release_calls: usize,
    owners: BTreeSet<String>,
    max_owners: usize,
}

struct DurableCatalog {
    ledger: PathBuf,
    state: ReservationState,
}

impl DurableCatalog {
    fn persist(&self) -> Result<(), io::Error> {
        let bytes = canonical_bytes(&json!({
            "acquire-calls": self.state.acquire_calls,
            "release-calls": self.state.release_calls,
            "owners": self.state.owners,
            "max-owners": self.state.max_owners,
        }))
        .map_err(io::Error::other)?;
        write_durable(&self.ledger, &bytes)
    }
}

impl TrustedResourceCatalog for DurableCatalog {
    type Handle = String;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        _operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        let owner = format!(
            "{:?}/{:?}/{}",
            context.transaction, context.operation.operation.key, context.attempt,
        );
        self.state.acquire_calls += 1;
        self.state.owners.insert(owner.clone());
        self.state.max_owners = self.state.max_owners.max(self.state.owners.len());
        self.persist()?;

        Ok(CatalogReservation::new(
            owner,
            ResourceAdmissionEvidence::new(
                access.resource.clone(),
                context
                    .expected_provider
                    .map(|assignment| assignment.incarnation.clone()),
                None,
                AbilityValue::new(json!({"reserved": true})).map_err(io::Error::other)?,
            ),
        ))
    }

    fn release(
        &mut self,
        _resource: &ResourceId,
        handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        if !self.state.owners.remove(handle) {
            return Err(io::Error::other("reservation owner is absent"));
        }
        self.state.release_calls += 1;
        self.persist()
    }
}

fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let spec_path = PathBuf::from(
        arguments
            .next()
            .context("matrix specification is required")?,
    );
    let output_path = PathBuf::from(arguments.next().context("output path is required")?);
    let interface_roots: Vec<PathBuf> = arguments.map(PathBuf::from).collect();
    ensure!(!interface_roots.is_empty(), "interface roots are required");

    let spec_bytes =
        fs::read(&spec_path).with_context(|| format!("failed to read {}", spec_path.display()))?;
    let spec_value: Value = serde_json::from_slice(&spec_bytes)
        .with_context(|| format!("failed to decode {}", spec_path.display()))?;
    let spec: MatrixSpec = serde_json::from_value(spec_value.clone())
        .with_context(|| format!("failed to decode {}", spec_path.display()))?;
    validate_spec(&spec)?;
    let interfaces = load_interfaces(&interface_roots)?;
    let matrix_cells: BTreeMap<_, _> = spec
        .cells
        .iter()
        .map(|cell| {
            let id = cell
                .get("id")
                .and_then(Value::as_str)
                .context("matrix cell lacks an id")?;
            Ok((id.to_string(), cell))
        })
        .collect::<Result<_>>()?;

    let evidence_root = output_path.with_extension("evidence");
    ensure!(
        !evidence_root.try_exists()?,
        "interruption evidence directory already exists"
    );
    fs::create_dir_all(&evidence_root)?;
    let mut cells = BTreeMap::new();

    for adapter in &spec.surface.adapters {
        let interface_key = InterfaceKey {
            name: adapter.interface_name.parse()?,
            abi: NonZeroU32::new(adapter.interface_abi)
                .context("interface ABI must be non-zero")?,
            descriptor: parse_digest(&adapter.interface_descriptor)?,
        };
        let interface = interfaces
            .get(&interface_key)
            .with_context(|| format!("missing exact interface {}", adapter.interface_descriptor))?;

        for method in &adapter.methods {
            let descriptor = interface
                .interface
                .methods
                .get(&LocalKey::new(&method.method)?)
                .with_context(|| format!("interface lacks method {}", method.method))?;
            for scenario_name in [INTERRUPTION_SCENARIO] {
                let cell_id = format!(
                    "{}/{}/abi-{}/{}/{}",
                    adapter.adapter,
                    adapter.interface_name,
                    adapter.interface_abi,
                    method.method,
                    scenario_name,
                );
                let cell = matrix_cells
                    .get(&cell_id)
                    .with_context(|| format!("matrix lacks interruption cell {cell_id}"))?;
                validate_cell(cell, adapter, method, scenario_name)?;
                let audit = run_cell(
                    &evidence_root,
                    &cell_id,
                    cell,
                    interface,
                    descriptor,
                    method,
                )
                .with_context(|| format!("interruption cell {cell_id} failed"))?;
                ensure!(
                    cells.insert(cell_id, audit).is_none(),
                    "duplicate audit cell"
                );
            }
        }
    }

    ensure!(cells.len() == 50, "expected 50 before-acquisition cells");
    let output = AuditOutput {
        schema: OUTPUT_SCHEMA,
        matrix_spec_digest: digest_value(&spec_value)?,
        cells,
    };
    write_durable(&output_path, &canonical_bytes(&output)?)?;
    Ok(())
}

fn validate_cell(
    cell: &Value,
    adapter: &Adapter,
    method: &MatrixMethod,
    scenario: &str,
) -> Result<()> {
    ensure!(
        cell.get("adapter") == Some(&json!(adapter.adapter)),
        "cell adapter differs"
    );
    ensure!(
        cell.get("interface")
            == Some(&json!({
                "name": adapter.interface_name,
                "abi": adapter.interface_abi,
                "descriptor": adapter.interface_descriptor,
            })),
        "cell interface differs"
    );
    ensure!(
        cell.get("method") == Some(&json!(method.method)),
        "cell method differs"
    );
    ensure!(
        cell.get("effect_class") == Some(&json!(method.effect_class)),
        "cell effect class differs"
    );
    ensure!(
        cell.get("scope") == Some(&json!(adapter.scope)),
        "cell scope differs"
    );
    ensure!(
        cell.get("recovery")
            == Some(&json!({"reconcile": method.reconcile, "cancel": method.cancel})),
        "cell recovery routes differ"
    );
    ensure!(
        cell.get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.ends_with(&format!("/{scenario}"))),
        "cell scenario differs"
    );
    Ok(())
}

fn run_cell(
    evidence_root: &Path,
    cell_id: &str,
    cell: &Value,
    interface: &InterfaceDocument,
    descriptor: &MethodDescriptor,
    matrix_method: &MatrixMethod,
) -> Result<AuditCell> {
    let directory =
        evidence_root.join(digest_bytes(cell_id.as_bytes()).trim_start_matches("sha256:"));
    fs::create_dir_all(&directory)?;
    let journal_path = directory.join("execution.journal");
    let ledger_path = directory.join("reservation-ledger.json");
    let boundary_path = directory.join("interruption-boundary.json");
    let foreign_path = directory.join("foreign-resource");
    write_durable(&foreign_path, b"independent-foreign-resource\n")?;
    let foreign_before = digest_file(&foreign_path)?;

    let (plan, plan_bundle, operation_key, dependent_key) =
        checked_plan(interface, descriptor, matrix_method)?;
    let transaction_id = TransactionId(LocalKey::new(&format!(
        "interrupt-{}",
        &digest_bytes(cell_id.as_bytes())[7..23]
    ))?);
    let mut store = DurableStore {
        directory: directory.clone(),
        plan_bundle,
        bundle_digest: None,
    };
    let mut catalog = DurableCatalog {
        ledger: ledger_path.clone(),
        state: ReservationState::default(),
    };
    catalog.persist()?;
    let adapter = NoDispatchAdapter::default();
    let mut policy = AllowPolicy;
    let mut observer = HaltAtBoundary {
        path: boundary_path.clone(),
        observed: None,
    };

    let mut transaction = ExecutionTransaction::open(
        &plan,
        transaction_id.clone(),
        &journal_path,
        JournalLimits::default(),
        &mut store,
    )?;
    let failure = match transaction.admit_with_observer(
        &operation_key,
        &adapter,
        &mut catalog,
        &mut policy,
        &AuditClock,
        &mut observer,
    ) {
        Ok(_) => bail!("admission continued past the interruption boundary"),
        Err(failure) => failure,
    };
    ensure!(
        matches!(
            failure.error(),
            AdmissionError::BoundaryHalt(Boundary::BeforeResourceAcquisition)
        ),
        "admission stopped with an unexpected error"
    );
    ensure!(
        observer.observed == Some(Boundary::BeforeResourceAcquisition),
        "interruption boundary was not observed"
    );
    drop(transaction);

    let fault_snapshot =
        CheckedExecutionJournalSnapshot::read(&plan, &journal_path, JournalLimits::default())?;
    let fault_journal_digest = digest_file(&journal_path)?;
    let fault_events = event_counts(&fault_snapshot);
    ensure!(
        fault_events == json!({"transaction-planned": 1}),
        "before-acquisition interruption changed durable operation state"
    );

    let mut recovered = ExecutionTransaction::open(
        &plan,
        transaction_id.clone(),
        &journal_path,
        JournalLimits::default(),
        &mut store,
    )?;
    let ready_at_restart = recovered
        .schedule_ready(NonZeroUsize::new(8).context("ready batch size must be non-zero")?)?;
    let primary_ready_at_restart = ready_at_restart.iter().any(|ready| {
        ready.operation() == &operation_key && ready.action() == &RecoveryAction::Admit
    });
    let dependent_ready_at_restart = ready_at_restart
        .iter()
        .any(|ready| ready.operation() == &dependent_key);
    ensure!(
        primary_ready_at_restart,
        "interrupted operation was not recoverable by fresh admission"
    );
    ensure!(
        !dependent_ready_at_restart,
        "required-success dependent became ready after failure"
    );
    drop(recovered);

    let restart_snapshot =
        CheckedExecutionJournalSnapshot::read(&plan, &journal_path, JournalLimits::default())?;
    ensure!(
        event_counts(&restart_snapshot) == json!({"transaction-planned": 1}),
        "journal reopen changed durable operation state"
    );
    ensure!(
        fault_journal_digest == digest_file(&journal_path)?,
        "journal bytes changed while reopening pending work"
    );
    ensure!(
        fault_snapshot.head_digest() == restart_snapshot.head_digest(),
        "journal head changed while reopening pending work"
    );
    ensure!(
        adapter.calls == 0,
        "before-acquisition interruption dispatched an adapter"
    );
    ensure!(
        catalog.state.acquire_calls == 0,
        "before-acquisition interruption acquired a resource"
    );
    ensure!(
        catalog.state.release_calls == 0,
        "before-acquisition interruption released a resource"
    );
    ensure!(
        catalog.state.owners.is_empty() && catalog.state.max_owners == 0,
        "before-acquisition interruption observed a resource owner"
    );
    let foreign_after = digest_file(&foreign_path)?;
    ensure!(foreign_before == foreign_after, "foreign sentinel changed");

    let cell_digest = digest_value(cell)?;
    let bundle_digest = store
        .bundle_digest
        .context("plan bundle was not retained")?;
    let retained_bundle = fs::read(directory.join("plan-bundle.json"))?;
    let subject = json!({
        "schema": SUBJECT_SCHEMA,
        "cell-id": cell_id,
        "cell-digest": cell_digest,
        "interface": interface.interface_key()?,
        "method": matrix_method.method,
        "plan": plan.id(),
        "transaction": transaction_id,
        "operation": operation_key,
        "dependent-operation": dependent_key,
    });
    let evidence = json!({
        "scenario": INTERRUPTION_SCENARIO,
        "runtime-boundary": format!("{:?}", Boundary::BeforeResourceAcquisition),
        "declared-recovery-routes": {
            "reconcile": matrix_method.reconcile,
            "cancel": matrix_method.cancel,
        },
        "fixture-recovery-routes": {
            "reconcile": matrix_method.reconcile.as_ref().map(|_| &matrix_method.method),
            "cancel": Value::Null,
        },
        "boundary-record": {
            "digest": digest_file(&boundary_path)?,
            "bytes": serde_json::from_slice::<Value>(&fs::read(&boundary_path)?)?,
        },
        "journal-at-fault": {
            "digest": fault_journal_digest,
            "head": fault_snapshot.head_digest(),
            "state": "pending",
            "events": fault_events,
        },
        "journal-after-restart": {
            "digest": digest_file(&journal_path)?,
            "head": restart_snapshot.head_digest(),
            "state": "pending",
            "events": event_counts(&restart_snapshot),
        },
        "reservation-ledger": {
            "digest": digest_file(&ledger_path)?,
            "acquire-calls": catalog.state.acquire_calls,
            "release-calls": catalog.state.release_calls,
            "max-owners": catalog.state.max_owners,
            "owners": catalog.state.owners,
        },
        "adapter-calls": {
            "total": adapter.calls,
            "dependent": 0,
        },
        "primary-ready-at-restart": primary_ready_at_restart,
        "dependent-ready-at-restart": dependent_ready_at_restart,
        "foreign-before": foreign_before,
        "foreign-after": foreign_after,
    });

    Ok(AuditCell {
        cell_digest,
        subject,
        plan_bundle: json!({
            "schema": PLAN_BUNDLE_SCHEMA,
            "digest": format!("{bundle_digest}"),
            "bytes-sha256": digest_bytes(&retained_bundle),
        }),
        evidence,
    })
}

fn event_counts(snapshot: &CheckedExecutionJournalSnapshot) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    for record in snapshot.records() {
        let kind = match record.body().body() {
            ExecutionEventKind::TransactionPlanned { .. } => "transaction-planned",
            ExecutionEventKind::OperationAdmitted { .. } => "operation-admitted",
            ExecutionEventKind::EffectIntent { .. } => "effect-intent",
            ExecutionEventKind::EffectCompleted { .. } => "effect-completed",
            ExecutionEventKind::ReconciliationIntent { .. } => "reconciliation-intent",
            ExecutionEventKind::ReconciliationObserved { .. } => "reconciled",
            ExecutionEventKind::ResourcesReleased { .. } => "resources-released",
            ExecutionEventKind::OperationInterventionRequired { .. } => "intervention-required",
            _ => "other",
        };
        *counts.entry(kind.to_string()).or_default() += 1;
    }
    json!(counts)
}

fn checked_plan(
    interface: &InterfaceDocument,
    descriptor: &MethodDescriptor,
    matrix_method: &MatrixMethod,
) -> Result<(
    CheckedEffectPlan,
    Vec<u8>,
    aos_ability_model::ScopedOperationKey,
    aos_ability_model::ScopedOperationKey,
)> {
    let mut fixture: PlanFixture = plan_fixture();
    fixture.interfaces = vec![interface.clone()];
    fixture.refresh_interface_with_features(interface.required_features.iter().cloned().collect());
    if interface.interface.name.as_str() == "aos.foreground-process" {
        retarget_fixture_stage(&mut fixture, ExecutionStage::ApplicationContainer);
    }
    let methods = vec![LocalKey::new(&matrix_method.method)?];

    fixture.binding_inputs.desired_state.child_requests[0].methods = methods.clone();
    fixture.binding_plan.requests[0].methods = methods.clone();
    fixture.binding_plan.bindings[0].caller_grant.methods = methods;
    fixture.binding_plan.bindings[0].caller_grant.resources[0].operations =
        descriptor.permitted_operations.clone();
    let access = if matrix_method.effect_class == "observation" {
        AccessMode::Read
    } else {
        AccessMode::ExclusiveWrite
    };
    fixture.binding_plan.bindings[0].caller_grant.resources[0].access = access;
    let execution_guarantees = match interface.interface.name.as_str() {
        "aos.systemd-manager" | "aos.systemd-service-effects" => Some(vec![
            aos_ability_model::builtin::local_systemd_manager_guarantee()?,
        ]),
        "aos.foreground-process" => Some(vec![
            aos_ability_model::builtin::foreground_process_supervision_guarantee()?,
        ]),
        _ => None,
    };
    if let Some(guarantees) = execution_guarantees {
        fixture.binding_inputs.environment.providers[0].guarantees = guarantees.clone();
        fixture.binding_inputs.desired_state.child_requests[0].guarantees = guarantees.clone();
        fixture.binding_plan.requests[0].guarantees = guarantees.clone();
        fixture.binding_plan.bindings[0].guarantees = guarantees;
    }

    let input = AbilityValue::new(minimal_value(&descriptor.parameters, &fixture)?)?;
    let interface_key = fixture.effect_plan.operations[0].interface.clone();
    let operation = &mut fixture.effect_plan.operations[0];
    operation.key.key = LocalKey::new(&matrix_method.method)?;
    operation.method = LocalKey::new(&matrix_method.method)?;
    operation.family = descriptor.operation_family.clone();
    operation.target.resource.key = LocalKey::new("qualified-resource")?;
    operation.target.operations = descriptor.permitted_operations.clone();
    operation.inputs = ValueExpression::Literal { value: input };
    operation.accesses[0].resource = operation.target.resource.clone();
    operation.accesses[0].mode = access;
    // The interruption precedes dispatch, so restart always returns to
    // admission. A reconcilable contract still requires a type-compatible
    // recovery reference for the checked plan; the audit never invokes it.
    operation.recovery.retry = if matrix_method.reconcile.is_some() {
        RetryPolicy::Bounded {
            max_attempts: NonZeroU32::new(2).context("retry count must be non-zero")?,
            backoff_millis: 0,
        }
    } else {
        RetryPolicy::Disabled
    };
    operation.recovery.reconcile = matrix_method
        .reconcile
        .as_ref()
        .map(|_| {
            Ok::<MethodReference, anyhow::Error>(MethodReference {
                interface: interface_key,
                method: LocalKey::new(&matrix_method.method)?,
            })
        })
        .transpose()?;
    operation.recovery.cancel = None;
    operation.recovery.compensate = None;
    let qualified_resource = operation.target.resource.clone();
    let controller = if matrix_method.effect_class == "mutation" {
        Some(AggregateId {
            provider: qualified_resource.provider.clone(),
            group: LocalKey::new("interruption-audit")?,
        })
    } else {
        None
    };
    operation.controller = controller.clone();
    let operation_key = operation.key.clone();
    let mut dependent = operation.clone();
    dependent.key.key = LocalKey::new("dependent-after-interruption")?;
    let dependent_key = dependent.key.clone();
    fixture.effect_plan.operations.push(dependent);
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| left.key.cmp(&right.key));
    fixture.effect_plan.edges = vec![DependencyEdge {
        from: PlanNodeKey::Operation {
            key: operation_key.clone(),
        },
        to: PlanNodeKey::Operation {
            key: dependent_key.clone(),
        },
        kind: aos_ability_model::DependencyKind::RequiredSuccess,
    }];
    fixture.binding_plan.bindings[0].caller_grant.resources[0].resource =
        qualified_resource.clone();
    fixture.binding_plan.resources[0].resource = qualified_resource.clone();
    fixture.binding_inputs.environment.resources[0].resource = qualified_resource.clone();
    fixture.binding_inputs.desired_state.resources[0].resource = qualified_resource.clone();
    fixture.effect_plan.current_revisions[0].resource = qualified_resource.clone();
    fixture.effect_plan.desired_revisions[0].resource = qualified_resource.clone();
    if let Some(controller) = controller {
        let assignment = ControllerAssignment {
            resource: qualified_resource,
            controller,
        };
        fixture.binding_inputs.environment.controllers = vec![assignment.clone()];
        fixture.binding_inputs.desired_state.controllers = vec![assignment.clone()];
        fixture.effect_plan.controllers = vec![assignment];
    }
    fixture.refresh_commitments();
    let plan = fixture
        .clone()
        .validate()
        .map_err(|errors| anyhow::anyhow!("{errors:?}"))?;
    let plan_bundle = canonical_bytes(&json!({
        "schema": PLAN_BUNDLE_SCHEMA,
        "plan": plan.id(),
        "interfaces": fixture.interfaces,
        "binding-inputs": {
            "environment": fixture.binding_inputs.environment,
            "desired-state": fixture.binding_inputs.desired_state,
            "packages": fixture.binding_inputs.packages,
        },
        "binding-plan": fixture.binding_plan,
        "effect-plan": fixture.effect_plan,
    }))?;

    Ok((plan, plan_bundle, operation_key, dependent_key))
}

fn retarget_fixture_stage(fixture: &mut PlanFixture, stage: ExecutionStage) {
    // Environment stage participates in every provider and resource identity,
    // so the cross-document fixture must move as one unit.
    fixture.binding_inputs.environment.environment.stage = stage;
    for provider in &mut fixture.binding_inputs.environment.providers {
        provider.provider.environment.stage = stage;
    }
    for resource in &mut fixture.binding_inputs.environment.resources {
        resource.resource.provider.environment.stage = stage;
    }
    for controller in &mut fixture.binding_inputs.environment.controllers {
        controller.resource.provider.environment.stage = stage;
        controller.controller.provider.environment.stage = stage;
    }

    for request in &mut fixture.binding_inputs.desired_state.child_requests {
        request.id.consumer.environment.stage = stage;
    }
    for resource in &mut fixture.binding_inputs.desired_state.resources {
        resource.resource.provider.environment.stage = stage;
    }
    for controller in &mut fixture.binding_inputs.desired_state.controllers {
        controller.resource.provider.environment.stage = stage;
        controller.controller.provider.environment.stage = stage;
    }

    for request in &mut fixture.binding_plan.requests {
        request.id.consumer.environment.stage = stage;
    }
    for binding in &mut fixture.binding_plan.bindings {
        binding.request.consumer.environment.stage = stage;
        binding.provider.environment.stage = stage;
        binding.caller_grant.principal.environment.stage = stage;
        binding.provider_grant.principal.environment.stage = stage;
        for permission in &mut binding.caller_grant.resources {
            permission.resource.provider.environment.stage = stage;
        }
        for permission in &mut binding.provider_grant.resources {
            permission.resource.provider.environment.stage = stage;
        }
    }
    for resource in &mut fixture.binding_plan.resources {
        resource.resource.provider.environment.stage = stage;
    }

    for resource in &mut fixture.effect_plan.current_revisions {
        resource.resource.provider.environment.stage = stage;
    }
    for resource in &mut fixture.effect_plan.desired_revisions {
        resource.resource.provider.environment.stage = stage;
    }
    for operation in &mut fixture.effect_plan.operations {
        operation.target.resource.provider.environment.stage = stage;
        for access in &mut operation.accesses {
            access.resource.provider.environment.stage = stage;
        }
    }
    for controller in &mut fixture.effect_plan.controllers {
        controller.resource.provider.environment.stage = stage;
        controller.controller.provider.environment.stage = stage;
    }
}

fn minimal_value(schema: &ValueSchema, fixture: &PlanFixture) -> Result<Value> {
    Ok(match schema {
        ValueSchema::Boolean => Value::Bool(false),
        ValueSchema::Integer { minimum, .. } => json!(minimum),
        ValueSchema::String { max_length, syntax } => {
            let candidate = match syntax {
                Some(StringSyntax::LocalKeyV1) => "x",
                Some(StringSyntax::QualifiedNameV1) => "x.y",
                None => "",
            };
            ensure!(
                candidate.len() as u64 <= *max_length,
                "string schema has no simple inhabitant"
            );
            Value::String(candidate.to_string())
        }
        ValueSchema::StringEnum { values } => {
            Value::String(values.first().context("string enum is empty")?.clone())
        }
        ValueSchema::List { .. } => Value::Array(Vec::new()),
        ValueSchema::Map { .. } => Value::Object(Map::new()),
        ValueSchema::Record {
            fields,
            optional_fields,
        } => {
            let optional: BTreeSet<_> = optional_fields.iter().collect();
            let mut record = Map::new();
            for (key, value) in fields {
                if !optional.contains(key) {
                    record.insert(key.as_str().to_string(), minimal_value(value, fixture)?);
                }
            }
            Value::Object(record)
        }
        ValueSchema::TaggedUnion { tag, variants } => {
            let (variant, schema) = variants.iter().next().context("tagged union is empty")?;
            let Value::Object(mut record) = minimal_value(schema, fixture)? else {
                bail!("tagged union variant is not a record");
            };
            record.insert(
                tag.as_str().to_string(),
                Value::String(variant.as_str().to_string()),
            );
            Value::Object(record)
        }
        ValueSchema::Optional { .. } => Value::Null,
        ValueSchema::ArtifactReference => serde_json::to_value(&fixture.effect_plan.artifacts[0])?,
        ValueSchema::ResourceReference => {
            serde_json::to_value(&fixture.effect_plan.operations[0].target)?
        }
        ValueSchema::ProviderAssignment => serde_json::to_value(
            fixture.binding_inputs.environment.providers[0]
                .incarnation
                .as_ref()
                .map(|incarnation| ProviderAssignment {
                    provider: fixture.binding_inputs.environment.providers[0]
                        .provider
                        .clone(),
                    interface: fixture.binding_inputs.environment.providers[0]
                        .interface
                        .clone(),
                    implementation: fixture.binding_inputs.environment.providers[0]
                        .implementation
                        .clone(),
                    incarnation: incarnation.clone(),
                })
                .context("fixture provider lacks an incarnation")?,
        )?,
        ValueSchema::OperationResultReference => {
            bail!("operation result schema requires a producer")
        }
    })
}

fn validate_spec(spec: &MatrixSpec) -> Result<()> {
    ensure!(
        spec.schema == "aos.qualification.native-adapter-matrix-spec/v1",
        "unsupported matrix schema"
    );
    ensure!(
        spec.surface.schema == "aos.qualification.native-adapter-surface/v1",
        "unsupported surface schema"
    );
    ensure!(
        spec.surface.matrix_schema == "aos.qualification.native-adapter-matrix/v1",
        "unsupported matrix result schema"
    );
    ensure!(
        spec.surface.subject_schema == "aos.qualification.native-adapter-subject/v1",
        "unsupported subject schema"
    );
    ensure!(!spec.surface.limits.is_null(), "matrix limits are absent");
    ensure!(!spec.subject.is_null(), "matrix subject is absent");
    ensure!(
        !spec.surface.scenarios.is_empty(),
        "matrix scenarios are absent"
    );
    ensure!(
        spec.surface
            .adapters
            .iter()
            .all(|adapter| !adapter.scope.is_empty()),
        "matrix adapter scope is absent"
    );
    Ok(())
}

fn load_interfaces(roots: &[PathBuf]) -> Result<BTreeMap<InterfaceKey, InterfaceDocument>> {
    let mut interfaces = BTreeMap::new();
    let systemd_manager = aos_ability_model::builtin::systemd_manager_interface()?;
    interfaces.insert(systemd_manager.interface_key()?, systemd_manager);
    for root in roots {
        let directory = root.join("interfaces");
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("failed to read {}", directory.display()))?
        {
            let candidate = entry?.path();
            if candidate.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let document: InterfaceDocument = serde_json::from_slice(&fs::read(&candidate)?)?;
            let key = document.interface_key()?;
            if let Some(previous) = interfaces.insert(key, document.clone()) {
                ensure!(
                    previous == document,
                    "interface root contains conflicting descriptors"
                );
            }
        }
    }
    Ok(interfaces)
}

fn parse_digest(value: &str) -> Result<Sha256Digest> {
    serde_json::from_value(json!(value)).map_err(Into::into)
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn digest_value(value: &Value) -> Result<String> {
    Ok(digest_bytes(&canonical_bytes(value)?))
}

fn digest_file(path: &Path) -> Result<String> {
    Ok(digest_bytes(&fs::read(path)?))
}

fn digest_bytes(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

fn write_durable(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
