//! Executes the closed native-adapter runtime-control qualification cohort.
//!
//! This binary is installed beside the private package runtime so release
//! qualification executes the candidate's linked ability runtime. It accepts
//! only the immutable matrix specification and realized interface documents,
//! performs no provider effect, and emits evidence derived from durable
//! journals and an independent reservation ledger.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::num::NonZeroU32;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, ArtifactReference, ControllerAssignment, DependencyEdge,
    DependencyKind, IndeterminateSemantics, InterfaceDocument, InterfaceKey, LocalKey,
    MethodDescriptor, MethodReference, Operation, PlanNodeKey, ProviderAssignment,
    ProviderImplementationReference, ResourceAccess, ResourceId, RetryPolicy, StringSyntax,
    TransactionId, ValueExpression, ValueSchema, compare_edges, compare_operation_keys,
};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CancellationToken,
    CatalogReservation, EffectDisposition, InvocationPurpose, MonotonicClock, PlanRetentionReceipt,
    ReconcileDisposition, ReservationContext, ResourceAdmissionEvidence, ResourceHandle,
    RootRetentionReceipt, RuntimeControl, TrustedAdapter, TrustedPlanStore, TrustedResourceCatalog,
    TrustedRootStore,
};
use aos_ability_runtime::execution::{
    AdmissionError, AuthorityCheckBoundary, AuthorityRejection, CheckedExecutionJournalSnapshot,
    ExecutionBoundaryControl, ExecutionBoundaryObservation, ExecutionBoundaryObserver,
    ExecutionError, ExecutionEventKind, ExecutionStep, ExecutionTransaction,
    OperationInterventionReason, RecoveryAction, ResourceReleaseError, RuntimeAuthorityRole,
    TrustedAdmissionPolicy, TrustedAuthoritySnapshot,
};
use aos_ability_runtime::journal::JournalLimits;
use aos_ability_validate::CheckedEffectPlan;
use aos_ability_validate::test_support::{PlanFixture, plan_fixture};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

const OUTPUT_SCHEMA: &str = "aos.qualification.native-adapter-runtime-audit/v1";
const SUBJECT_SCHEMA: &str = "aos.qualification.native-adapter-runtime-subject/v1";
const PLAN_BUNDLE_SCHEMA: &str = "aos.qualification.native-adapter-runtime-plan/v1";
const ROLE_SCENARIOS: [&str; 12] = [
    "revoke-caller-before-acquisition",
    "revoke-caller-after-acquisition",
    "revoke-caller-before-external-effect",
    "revoke-provider-before-acquisition",
    "revoke-provider-after-acquisition",
    "revoke-provider-before-external-effect",
    "revoke-enforcement-before-acquisition",
    "revoke-enforcement-after-acquisition",
    "revoke-enforcement-before-external-effect",
    "revoke-assignment-before-acquisition",
    "revoke-assignment-after-acquisition",
    "revoke-assignment-before-external-effect",
];
const FAILURE_CONTROL_SCENARIOS: [&str; 4] = [
    "cancel-unsettled-attempt",
    "expire-attempt-deadline",
    "fail-cleanup",
    "fail-release",
];

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

#[derive(Clone, Copy)]
struct AuditScenario {
    role: RuntimeAuthorityRole,
    boundary: aos_ability_runtime::execution::Boundary,
    authority_boundary: AuthorityCheckBoundary,
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

struct NoDispatchAdapter {
    observation: AbilityValue,
    execute_calls: usize,
    reconcile_calls: usize,
    cancel_calls: usize,
}

impl NoDispatchAdapter {
    fn new(observation: AbilityValue) -> Self {
        Self {
            observation,
            execute_calls: 0,
            reconcile_calls: 0,
            cancel_calls: 0,
        }
    }

    fn calls(&self) -> usize {
        self.execute_calls + self.reconcile_calls + self.cancel_calls
    }
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
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        self.execute_calls += 1;
        EffectDisposition::RejectedBeforeEffect(AuditRecord {
            evidence: self.observation.clone(),
            outputs: BTreeMap::new(),
        })
    }

    fn reconcile(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        self.reconcile_calls += 1;
        ReconcileDisposition::RejectedBeforeEffect(AuditRecord {
            evidence: self.observation.clone(),
            outputs: BTreeMap::new(),
        })
    }

    fn cancel(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        self.cancel_calls += 1;
        CancellationDisposition::Indeterminate(AuditRecord {
            evidence: self.observation.clone(),
            outputs: BTreeMap::new(),
        })
    }
}

struct AuditClock {
    now: Cell<u64>,
    restart_stable: Cell<u64>,
}

impl AuditClock {
    fn new(now: u64) -> Self {
        Self {
            now: Cell::new(now),
            restart_stable: Cell::new(now),
        }
    }

    fn advance_to(&self, now: u64) {
        self.now.set(now);
        self.restart_stable.set(now);
    }
}

impl MonotonicClock for AuditClock {
    fn now_millis(&self) -> u64 {
        self.now.get()
    }

    fn restart_stable_millis(&self) -> u64 {
        self.restart_stable.get()
    }
}

struct RevocablePolicy {
    revoked: Rc<Cell<Option<RuntimeAuthorityRole>>>,
}

#[derive(Clone, Copy)]
struct AuthorityFence {
    revoked: Option<RuntimeAuthorityRole>,
}

fn authorize_role(
    revoked: Option<RuntimeAuthorityRole>,
    role: RuntimeAuthorityRole,
) -> Result<(), io::Error> {
    if revoked == Some(role) {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "qualification role was revoked",
        ))
    } else {
        Ok(())
    }
}

impl TrustedAuthoritySnapshot for AuthorityFence {
    type Error = io::Error;

    fn authorize_role(
        &mut self,
        _plan: &CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        authorize_role(self.revoked, role)
    }

    fn authorize_resources(
        &mut self,
        _plan: &CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _expected_provider: Option<&ProviderAssignment>,
        _resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        authorize_role(self.revoked, RuntimeAuthorityRole::AssignmentIncarnation)
    }
}

impl TrustedAuthoritySnapshot for RevocablePolicy {
    type Error = io::Error;

    fn authorize_role(
        &mut self,
        _plan: &CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error> {
        authorize_role(self.revoked.get(), role)
    }

    fn authorize_resources(
        &mut self,
        _plan: &CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _expected_provider: Option<&ProviderAssignment>,
        _resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error> {
        authorize_role(
            self.revoked.get(),
            RuntimeAuthorityRole::AssignmentIncarnation,
        )
    }
}

impl TrustedAdmissionPolicy for RevocablePolicy {
    type DispatchFence = AuthorityFence;

    fn acquire_dispatch_fence(
        &mut self,
        _plan: &CheckedEffectPlan,
        _binding: &aos_ability_model::Binding,
        _operation: &Operation,
        _method: &MethodReference,
        _purpose: InvocationPurpose,
    ) -> Result<Self::DispatchFence, AuthorityRejection<Self::Error>> {
        Ok(AuthorityFence {
            revoked: self.revoked.get(),
        })
    }
}

struct RevokeAtBoundary {
    revoked: Rc<Cell<Option<RuntimeAuthorityRole>>>,
    scenario: AuditScenario,
    observed: Option<aos_ability_runtime::execution::Boundary>,
}

impl ExecutionBoundaryObserver for RevokeAtBoundary {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if observation.boundary() == self.scenario.boundary {
            self.revoked.set(Some(self.scenario.role));
            self.observed = Some(observation.boundary());
        }
        Ok(ExecutionBoundaryControl::Continue)
    }
}

struct FailAtBoundary {
    target: aos_ability_runtime::execution::Boundary,
    observed: bool,
}

struct ExpireAtBoundary<'a> {
    clock: &'a AuditClock,
    target: aos_ability_runtime::execution::Boundary,
    advance_by: u64,
    observed: bool,
}

impl ExecutionBoundaryObserver for ExpireAtBoundary<'_> {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if observation.boundary() == self.target {
            self.observed = true;
            self.clock
                .advance_to(self.clock.now_millis().saturating_add(self.advance_by));
        }
        Ok(ExecutionBoundaryControl::Continue)
    }
}

impl ExecutionBoundaryObserver for FailAtBoundary {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if observation.boundary() == self.target {
            self.observed = true;
            bail!("injected qualification boundary failure");
        }
        Ok(ExecutionBoundaryControl::Continue)
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
    release_failures: usize,
    owners: usize,
    max_owners: usize,
}

struct DurableCatalog {
    ledger: PathBuf,
    state: ReservationState,
    fail_releases: usize,
}

impl DurableCatalog {
    fn persist(&self) -> Result<(), io::Error> {
        let bytes = canonical_bytes(&json!({
            "acquire-calls": self.state.acquire_calls,
            "release-calls": self.state.release_calls,
            "release-failures": self.state.release_failures,
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
        self.state.acquire_calls += 1;
        self.state.owners += 1;
        self.state.max_owners = self.state.max_owners.max(self.state.owners);
        self.persist()?;

        Ok(CatalogReservation::new(
            access.resource.key.as_str().to_string(),
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
        _handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        self.state.release_calls += 1;
        if self.fail_releases > 0 {
            self.fail_releases -= 1;
            self.state.release_failures += 1;
            self.persist()?;
            return Err(io::Error::other("injected catalog release failure"));
        }
        self.state.owners = self.state.owners.saturating_sub(1);
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
        "authority evidence directory already exists"
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
            for scenario_name in ROLE_SCENARIOS {
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
                    .with_context(|| format!("matrix lacks role cell {cell_id}"))?;
                validate_cell(cell, adapter, method, scenario_name)?;
                let audit = run_cell(
                    &evidence_root,
                    &cell_id,
                    cell,
                    interface,
                    descriptor,
                    method,
                    parse_scenario(scenario_name)?,
                )
                .with_context(|| format!("authority cell {cell_id} failed"))?;
                ensure!(
                    cells.insert(cell_id, audit).is_none(),
                    "duplicate audit cell"
                );
            }
            for scenario_name in FAILURE_CONTROL_SCENARIOS {
                if scenario_name == "cancel-unsettled-attempt" && method.cancel.is_some() {
                    continue;
                }
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
                    .with_context(|| format!("matrix lacks failure-control cell {cell_id}"))?;
                validate_cell(cell, adapter, method, scenario_name)?;
                let audit = run_failure_control_cell(
                    &evidence_root,
                    &cell_id,
                    cell,
                    interface,
                    descriptor,
                    method,
                    scenario_name,
                )
                .with_context(|| format!("failure-control cell {cell_id} failed"))?;
                ensure!(
                    cells.insert(cell_id, audit).is_none(),
                    "duplicate audit cell"
                );
            }
        }
    }

    ensure!(
        cells.len() == 756,
        "expected 756 role-revocation and shared failure-control cells"
    );
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
    let expected_interface = json!({
        "name": adapter.interface_name,
        "abi": adapter.interface_abi,
        "descriptor": adapter.interface_descriptor,
    });
    let expected_recovery = json!({
        "reconcile": method.reconcile,
        "cancel": method.cancel,
    });
    ensure!(
        cell.get("adapter") == Some(&json!(adapter.adapter)),
        "cell adapter differs"
    );
    ensure!(
        cell.get("interface") == Some(&expected_interface),
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
        cell.get("recovery") == Some(&expected_recovery),
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
    scenario: AuditScenario,
) -> Result<AuditCell> {
    let directory =
        evidence_root.join(digest_bytes(cell_id.as_bytes()).trim_start_matches("sha256:"));
    fs::create_dir_all(&directory)?;
    let journal_path = directory.join("execution.journal");
    let ledger_path = directory.join("reservation-ledger.json");
    let foreign_path = directory.join("foreign-resource");
    write_durable(&foreign_path, b"independent-foreign-resource\n")?;
    let foreign_before = digest_file(&foreign_path)?;

    let (plan, plan_bundle, operation_key, _dependent_key, observation) =
        checked_plan(interface, descriptor, matrix_method)?;
    let transaction_id = TransactionId(LocalKey::new(&format!(
        "authority-{}",
        &digest_bytes(cell_id.as_bytes())[7..23]
    ))?);
    let mut store = DurableStore {
        directory: directory.clone(),
        plan_bundle,
        bundle_digest: None,
    };
    let mut transaction = ExecutionTransaction::open(
        &plan,
        transaction_id.clone(),
        &journal_path,
        JournalLimits::default(),
        &mut store,
    )?;
    let mut catalog = DurableCatalog {
        ledger: ledger_path.clone(),
        state: ReservationState::default(),
        fail_releases: 0,
    };
    catalog.persist()?;
    let revoked = Rc::new(Cell::new(None));
    let mut policy = RevocablePolicy {
        revoked: Rc::clone(&revoked),
    };
    let mut observer = RevokeAtBoundary {
        revoked,
        scenario,
        observed: None,
    };
    let mut adapter = NoDispatchAdapter::new(observation);
    let clock = AuditClock::new(1);

    match scenario.boundary {
        aos_ability_runtime::execution::Boundary::FinalDispatch => {
            let admitted = transaction
                .admit(&operation_key, &adapter, &mut catalog, &mut policy, &clock)
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
            let error = match transaction.drive_admitted_with_observer(
                &admitted,
                &mut adapter,
                &mut policy,
                &clock,
                &CancellationToken::default(),
                &mut observer,
            ) {
                Ok(_) => bail!("final dispatch unexpectedly succeeded"),
                Err(error) => error,
            };
            assert_execution_rejection(&error, scenario)?;
            transaction
                .release_admitted::<NoDispatchAdapter, _, _>(admitted, &mut catalog, &clock)
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
        }
        _ => {
            let failure = match transaction.admit_with_observer(
                &operation_key,
                &adapter,
                &mut catalog,
                &mut policy,
                &clock,
                &mut observer,
            ) {
                Ok(_) => bail!("admission unexpectedly succeeded"),
                Err(failure) => failure,
            };
            assert_admission_rejection(failure.error(), scenario)?;
        }
    }

    ensure!(
        observer.observed == Some(scenario.boundary),
        "revocation boundary was not observed"
    );
    ensure!(
        adapter.calls() == 0,
        "authority fence allowed adapter dispatch"
    );
    ensure!(
        catalog.state.max_owners <= 1,
        "more than one resource owner was observed"
    );
    ensure!(
        catalog.state.owners == 0,
        "resource ownership was not released"
    );
    let expected_acquisitions = usize::from(
        scenario.boundary != aos_ability_runtime::execution::Boundary::BeforeResourceAcquisition,
    );
    ensure!(
        catalog.state.acquire_calls == expected_acquisitions,
        "unexpected acquisition count"
    );
    ensure!(
        catalog.state.release_calls == expected_acquisitions,
        "unexpected release count"
    );

    drop(transaction);
    let snapshot =
        CheckedExecutionJournalSnapshot::read(&plan, &journal_path, JournalLimits::default())?;
    let authority_rejections = snapshot
        .records()
        .iter()
        .filter(|record| {
            matches!(
                record.body().body(),
                ExecutionEventKind::AuthorityRejected { role, boundary, .. }
                    if *role == scenario.role && *boundary == scenario.authority_boundary
            )
        })
        .count();
    let effect_outcomes = snapshot
        .records()
        .iter()
        .filter(|record| {
            matches!(
                record.body().body(),
                ExecutionEventKind::EffectCompleted { .. }
                    | ExecutionEventKind::EffectRejectedBeforeEffect { .. }
                    | ExecutionEventKind::EffectIndeterminate { .. }
            )
        })
        .count();
    ensure!(
        authority_rejections == 1,
        "journal lacks exact authority rejection"
    );
    ensure!(effect_outcomes == 0, "journal reports an adapter outcome");
    let foreign_after = digest_file(&foreign_path)?;
    ensure!(foreign_before == foreign_after, "foreign sentinel changed");

    let cell_digest = digest_value(cell)?;
    let bundle_digest = store
        .bundle_digest
        .context("plan bundle was not retained")?;
    let subject = json!({
        "schema": SUBJECT_SCHEMA,
        "cell-id": cell_id,
        "cell-digest": cell_digest,
        "interface": interface.interface_key()?,
        "method": matrix_method.method,
        "plan": plan.id(),
        "transaction": transaction_id,
    });
    let plan_bundle = fs::read(directory.join("plan-bundle.json"))?;
    let evidence = json!({
        "role": scenario.role,
        "authority-boundary": scenario.authority_boundary,
        "runtime-boundary": format!("{:?}", scenario.boundary),
        "journal": {
            "digest": digest_file(&journal_path)?,
            "head": snapshot.head_digest(),
            "authority-rejections": authority_rejections,
            "effect-outcomes": effect_outcomes,
        },
        "reservation-ledger": {
            "digest": digest_file(&ledger_path)?,
            "acquire-calls": catalog.state.acquire_calls,
            "release-calls": catalog.state.release_calls,
            "max-owners": catalog.state.max_owners,
            "owners": catalog.state.owners,
        },
        "dispatch-calls": adapter.calls(),
        "foreign-before": foreign_before,
        "foreign-after": foreign_after,
    });

    Ok(AuditCell {
        cell_digest,
        subject,
        plan_bundle: json!({
            "schema": PLAN_BUNDLE_SCHEMA,
            "digest": format!("{bundle_digest}"),
            "bytes-sha256": digest_bytes(&plan_bundle),
        }),
        evidence,
    })
}

fn run_failure_control_cell(
    evidence_root: &Path,
    cell_id: &str,
    cell: &Value,
    interface: &InterfaceDocument,
    descriptor: &MethodDescriptor,
    matrix_method: &MatrixMethod,
    scenario: &str,
) -> Result<AuditCell> {
    use aos_ability_runtime::execution::Boundary;

    let directory =
        evidence_root.join(digest_bytes(cell_id.as_bytes()).trim_start_matches("sha256:"));
    fs::create_dir_all(&directory)?;
    let journal_path = directory.join("execution.journal");
    let ledger_path = directory.join("reservation-ledger.json");
    let foreign_path = directory.join("foreign-resource");
    write_durable(&foreign_path, b"independent-foreign-resource\n")?;
    let foreign_before = digest_file(&foreign_path)?;

    let (plan, plan_bundle, operation_key, dependent_key, observation) =
        checked_plan(interface, descriptor, matrix_method)?;
    let transaction_id = TransactionId(LocalKey::new(&format!(
        "control-{}",
        &digest_bytes(cell_id.as_bytes())[7..23]
    ))?);
    let mut store = DurableStore {
        directory: directory.clone(),
        plan_bundle,
        bundle_digest: None,
    };
    let mut transaction = ExecutionTransaction::open(
        &plan,
        transaction_id.clone(),
        &journal_path,
        JournalLimits::default(),
        &mut store,
    )?;
    let mut catalog = DurableCatalog {
        ledger: ledger_path.clone(),
        state: ReservationState::default(),
        fail_releases: 0,
    };
    catalog.persist()?;
    let revoked = Rc::new(Cell::new(None));
    let mut policy = RevocablePolicy { revoked };
    let mut adapter = NoDispatchAdapter::new(observation);
    let clock = AuditClock::new(1);
    let cancellation = CancellationToken::default();
    let classification: String;
    let retained_resources: usize;
    let cleanup_errors: usize;
    let owners_at_failure: usize;

    match scenario {
        "cancel-unsettled-attempt" => {
            let admitted = transaction
                .admit(&operation_key, &adapter, &mut catalog, &mut policy, &clock)
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
            cancellation.cancel();
            ensure!(
                matrix_method.cancel.is_none(),
                "supported cancellation requires a provider-specific oracle"
            );
            transaction.record_unsupported_cancellation(&admitted, &clock)?;
            ensure!(
                adapter.cancel_calls == 0,
                "unsupported cancellation dispatched"
            );
            classification = "cancellation-unsupported-intervention".to_string();
            retained_resources = admitted.resources().count();
            owners_at_failure = catalog.state.owners;
            cleanup_errors = 0;
        }
        "expire-attempt-deadline" => {
            let admitted = transaction
                .admit(&operation_key, &adapter, &mut catalog, &mut policy, &clock)
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
            let mut observer = ExpireAtBoundary {
                clock: &clock,
                target: Boundary::EffectIntentDurable,
                advance_by: admitted.operation().deadline.attempt_timeout_millis.get(),
                observed: false,
            };
            let step = transaction.drive_admitted_with_observer(
                &admitted,
                &mut adapter,
                &mut policy,
                &clock,
                &cancellation,
                &mut observer,
            )?;
            ensure!(
                observer.observed && step == ExecutionStep::RejectedBeforeEffect,
                "trusted clock deadline did not abort the durable intent"
            );
            retained_resources = admitted.resources().count();
            owners_at_failure = catalog.state.owners;
            cleanup_errors = 0;
            classification = "trusted-clock-deadline-expired".to_string();
        }
        "fail-cleanup" => {
            catalog.fail_releases = 1;
            let mut observer = FailAtBoundary {
                target: Boundary::ResourcesAcquired,
                observed: false,
            };
            let failure = transaction
                .admit_with_observer(
                    &operation_key,
                    &adapter,
                    &mut catalog,
                    &mut policy,
                    &clock,
                    &mut observer,
                )
                .expect_err("injected admission cleanup must fail");
            ensure!(
                observer.observed,
                "cleanup failure boundary was not observed"
            );
            retained_resources = failure.retained_resources().count();
            cleanup_errors = failure.cleanup_errors().len();
            owners_at_failure = catalog.state.owners;
            ensure!(
                retained_resources == 1 && cleanup_errors == 1 && owners_at_failure == 1,
                "cleanup failure did not retain its exact ownership token"
            );
            failure.retry_cleanup(&mut catalog).map_err(|failure| {
                anyhow::anyhow!("cleanup retry remained failed: {}", failure.error())
            })?;
            classification = "cleanup-failure-retained-then-released".to_string();
        }
        "fail-release" => {
            let admitted = transaction
                .admit(&operation_key, &adapter, &mut catalog, &mut policy, &clock)
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
            let step = transaction.drive_admitted(
                &admitted,
                &mut adapter,
                &mut policy,
                &clock,
                &cancellation,
            )?;
            ensure!(
                step == ExecutionStep::RejectedBeforeEffect,
                "release setup did not settle before effect"
            );
            catalog.fail_releases = 1;
            let failure = transaction
                .release_admitted::<NoDispatchAdapter, _, _>(admitted, &mut catalog, &clock)
                .expect_err("injected release must fail");
            ensure!(
                matches!(failure.error(), ResourceReleaseError::Catalog { .. }),
                "release injection produced an unexpected error"
            );
            retained_resources = failure.retained_resources().count();
            owners_at_failure = catalog.state.owners;
            cleanup_errors = 0;
            ensure!(
                retained_resources == 1 && owners_at_failure == 1,
                "release failure did not retain its exact ownership token"
            );
            failure
                .retry(&mut transaction, &mut catalog, &clock)
                .map_err(|failure| anyhow::anyhow!("release retry failed: {}", failure.error()))?;
            transaction
                .settle_failure_before_effect(&operation_key, adapter.observation.clone())?;
            classification = "release-failure-retained-then-released".to_string();
        }
        other => bail!("unknown failure-control scenario {other}"),
    }

    ensure!(catalog.state.max_owners == 1, "ownership was not exclusive");
    ensure!(owners_at_failure == 1, "failure did not retain ownership");
    ensure!(
        retained_resources == 1,
        "failure retained an unexpected resource set"
    );
    let ready = transaction.schedule_ready(
        NonZeroUsize::new(plan.operations().len()).context("plan has no operations")?,
    )?;
    let expected_dependent_settlement =
        matches!(scenario, "cancel-unsettled-attempt" | "fail-release");
    let dependent = ready
        .iter()
        .find(|entry| entry.operation() == &dependent_key);
    if expected_dependent_settlement {
        let dependent = dependent.context("required-success dependent was not durably blocked")?;
        ensure!(
            dependent.action() == &RecoveryAction::SettleFailureBeforeEffect,
            "required-success dependent became externally executable"
        );
        transaction.settle_failure_before_effect(&dependent_key, adapter.observation.clone())?;
    } else {
        ensure!(
            dependent.is_none(),
            "unsettled required-success predecessor exposed its dependent"
        );
    }

    drop(transaction);
    let snapshot =
        CheckedExecutionJournalSnapshot::read(&plan, &journal_path, JournalLimits::default())?;
    let dependent_effect_events = snapshot
        .records()
        .iter()
        .filter(|record| {
            matches!(
                record.body().body(),
                ExecutionEventKind::EffectIntent { operation, .. }
                    | ExecutionEventKind::EffectCompleted { operation, .. }
                    | ExecutionEventKind::EffectRejectedBeforeEffect { operation, .. }
                    | ExecutionEventKind::EffectIndeterminate { operation, .. }
                    if operation.operation == dependent_key
            )
        })
        .count();
    let dependent_settlements = count_events(&snapshot, |event| {
        matches!(
            event,
            ExecutionEventKind::OperationSettledFailure { operation, .. }
                if operation.operation == dependent_key
        )
    });
    ensure!(
        dependent_effect_events == 0
            && dependent_settlements == usize::from(expected_dependent_settlement),
        "dependent operation was not blocked before effect"
    );
    let cancellation_requested = count_events(&snapshot, |event| {
        matches!(event, ExecutionEventKind::CancellationRequested { .. })
    });
    let cancellation_observed = count_events(&snapshot, |event| {
        matches!(event, ExecutionEventKind::CancellationObserved { .. })
    });
    let cancellation_interventions = count_events(&snapshot, |event| {
        matches!(
            event,
            ExecutionEventKind::OperationInterventionRequired {
                reason: OperationInterventionReason::CancellationUnsupported,
                ..
            }
        )
    });
    let deadline_aborts = count_events(&snapshot, |event| {
        matches!(
            event,
            ExecutionEventKind::EffectDispatchAborted {
                reason: aos_ability_runtime::execution::DispatchAbortReason::DeadlineExpired,
                ..
            }
        )
    });
    match scenario {
        "cancel-unsettled-attempt" => ensure!(
            cancellation_interventions == 1,
            "unsupported cancellation intervention was not durable"
        ),
        _ => {}
    }
    let foreign_after = digest_file(&foreign_path)?;
    ensure!(foreign_before == foreign_after, "foreign sentinel changed");

    let cell_digest = digest_value(cell)?;
    let bundle_digest = store
        .bundle_digest
        .context("plan bundle was not retained")?;
    let subject = json!({
        "schema": SUBJECT_SCHEMA,
        "cell-id": cell_id,
        "cell-digest": cell_digest,
        "interface": interface.interface_key()?,
        "method": matrix_method.method,
        "plan": plan.id(),
        "transaction": transaction_id,
    });
    let retained_bundle = fs::read(directory.join("plan-bundle.json"))?;
    let evidence = json!({
        "scenario": scenario,
        "classification": classification,
        "recovery-routes": {
            "reconcile": matrix_method.reconcile,
            "cancel": matrix_method.cancel,
        },
        "fixture-recovery-routes": {
            "reconcile": if descriptor.outcome.indeterminate == IndeterminateSemantics::Reconcile {
                Some(matrix_method.method.as_str())
            } else {
                None
            },
            "cancel": Value::Null,
        },
        "journal": {
            "digest": digest_file(&journal_path)?,
            "head": snapshot.head_digest(),
            "cancellation-requested": cancellation_requested,
            "cancellation-observed": cancellation_observed,
            "cancellation-interventions": cancellation_interventions,
            "deadline-aborts": deadline_aborts,
            "dependent-effect-events": dependent_effect_events,
            "dependent-settlements": dependent_settlements,
        },
        "reservation-ledger": {
            "digest": digest_file(&ledger_path)?,
            "acquire-calls": catalog.state.acquire_calls,
            "release-calls": catalog.state.release_calls,
            "release-failures": catalog.state.release_failures,
            "max-owners": catalog.state.max_owners,
            "owners-at-failure": owners_at_failure,
            "owners-final": catalog.state.owners,
            "retained-resources": retained_resources,
            "cleanup-errors": cleanup_errors,
        },
        "adapter": {
            "execute-calls": adapter.execute_calls,
            "reconcile-calls": adapter.reconcile_calls,
            "cancel-calls": adapter.cancel_calls,
        },
        "clock": {
            "now-millis": clock.now_millis(),
            "restart-stable-millis": clock.restart_stable_millis(),
        },
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

fn count_events(
    snapshot: &CheckedExecutionJournalSnapshot,
    predicate: impl Fn(&ExecutionEventKind) -> bool,
) -> usize {
    snapshot
        .records()
        .iter()
        .filter(|record| predicate(record.body().body()))
        .count()
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
    AbilityValue,
)> {
    let mut fixture: PlanFixture = plan_fixture();
    fixture.interfaces = vec![interface.clone()];
    fixture.refresh_interface_with_features(interface.required_features.iter().cloned().collect());
    let methods = vec![LocalKey::new(&matrix_method.method)?];

    fixture.binding_inputs.desired_state.child_requests[0].methods = methods.clone();
    fixture.binding_plan.requests[0].methods = methods.clone();
    fixture.binding_plan.bindings[0].caller_grant.methods = methods.clone();
    fixture.binding_plan.bindings[0].caller_grant.resources[0].operations =
        descriptor.permitted_operations.clone();
    let access = if matrix_method.effect_class == "observation" {
        AccessMode::Read
    } else {
        AccessMode::ExclusiveWrite
    };
    fixture.binding_plan.bindings[0].caller_grant.resources[0].access = access;
    if matches!(
        interface.interface.name.as_str(),
        "aos.systemd-manager" | "aos.systemd-service-effects"
    ) {
        let guarantees = vec![aos_ability_model::builtin::local_systemd_manager_guarantee()?];
        fixture.binding_inputs.environment.providers[0].guarantees = guarantees.clone();
        fixture.binding_inputs.desired_state.child_requests[0].guarantees = guarantees.clone();
        fixture.binding_plan.requests[0].guarantees = guarantees.clone();
        fixture.binding_plan.bindings[0].guarantees = guarantees;
    }

    let input = AbilityValue::new(minimal_value(&descriptor.parameters, &fixture)?)?;
    let interface_key = fixture.effect_plan.operations[0].interface.clone();
    let reconcile = if descriptor.outcome.indeterminate == IndeterminateSemantics::Reconcile {
        Some(MethodReference {
            interface: interface_key.clone(),
            method: LocalKey::new(&matrix_method.method)?,
        })
    } else {
        None
    };
    let operation = &mut fixture.effect_plan.operations[0];
    operation.key.key = LocalKey::new("matrix-primary")?;
    operation.method = LocalKey::new(&matrix_method.method)?;
    operation.family = descriptor.operation_family.clone();
    operation.target.resource.key = LocalKey::new("qualified-resource")?;
    operation.target.operations = descriptor.permitted_operations.clone();
    operation.inputs = ValueExpression::Literal { value: input };
    operation.accesses[0].resource = operation.target.resource.clone();
    operation.accesses[0].mode = access;
    operation.recovery.retry = RetryPolicy::Disabled;
    operation.recovery.reconcile = reconcile;
    operation.recovery.cancel = None;
    operation.recovery.compensate = None;
    let qualified_resource = operation.target.resource.clone();
    let controller = if matrix_method.effect_class == "mutation" {
        Some(AggregateId {
            provider: qualified_resource.provider.clone(),
            group: LocalKey::new("authority-audit")?,
        })
    } else {
        None
    };
    operation.controller = controller.clone();
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
    let operation_key = fixture.effect_plan.operations[0].key.clone();
    let mut dependent = fixture.effect_plan.operations[0].clone();
    dependent.key.key = LocalKey::new("matrix-dependent")?;
    let dependent_key = dependent.key.clone();
    fixture.effect_plan.operations.push(dependent);
    fixture.effect_plan.edges.push(DependencyEdge {
        from: PlanNodeKey::Operation {
            key: operation_key.clone(),
        },
        to: PlanNodeKey::Operation {
            key: dependent_key.clone(),
        },
        kind: DependencyKind::RequiredSuccess,
    });
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.edges.sort_by(compare_edges);
    let observation = AbilityValue::new(minimal_value(
        &descriptor.outcome.observation_evidence,
        &fixture,
    )?)?;
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

    Ok((plan, plan_bundle, operation_key, dependent_key, observation))
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
            bail!("operation result parameters require a producer")
        }
    })
}

fn parse_scenario(name: &str) -> Result<AuditScenario> {
    use aos_ability_runtime::execution::Boundary;
    let role = if name.contains("caller") {
        RuntimeAuthorityRole::CallerBindingGrant
    } else if name.contains("provider") {
        RuntimeAuthorityRole::ProviderMethodImplementation
    } else if name.contains("enforcement") {
        RuntimeAuthorityRole::EnforcementPlatformGuarantee
    } else if name.contains("assignment") {
        RuntimeAuthorityRole::AssignmentIncarnation
    } else {
        bail!("unknown role scenario {name}");
    };
    let (boundary, authority_boundary) = if name.ends_with("before-acquisition") {
        (
            Boundary::BeforeResourceAcquisition,
            AuthorityCheckBoundary::BeforeResourceAcquisition,
        )
    } else if name.ends_with("after-acquisition") {
        (
            Boundary::ResourcesAcquired,
            AuthorityCheckBoundary::AfterResourceAcquisition,
        )
    } else if name.ends_with("before-external-effect") {
        (
            Boundary::FinalDispatch,
            AuthorityCheckBoundary::FinalDispatch,
        )
    } else {
        bail!("unknown authority timing {name}");
    };
    Ok(AuditScenario {
        role,
        boundary,
        authority_boundary,
    })
}

fn assert_execution_rejection(error: &ExecutionError, scenario: AuditScenario) -> Result<()> {
    match error {
        ExecutionError::DispatchAdmission(AdmissionError::FreshAuthorization {
            role,
            boundary,
            ..
        }) if *role == scenario.role && *boundary == scenario.authority_boundary => Ok(()),
        other => bail!("unexpected final dispatch error: {other}"),
    }
}

fn assert_admission_rejection(error: &AdmissionError, scenario: AuditScenario) -> Result<()> {
    match error {
        AdmissionError::FreshAuthorization { role, boundary, .. }
            if *role == scenario.role && *boundary == scenario.authority_boundary =>
        {
            Ok(())
        }
        other => bail!("unexpected admission error: {other}"),
    }
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
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let document: InterfaceDocument = serde_json::from_slice(&fs::read(&path)?)?;
            let key = document.interface_key()?;
            if let Some(existing) = interfaces.insert(key, document.clone()) {
                ensure!(existing == document, "interface key collision");
            }
        }
    }
    Ok(interfaces)
}

fn parse_digest(value: &str) -> Result<Sha256Digest> {
    serde_json::from_value(Value::String(value.to_string())).map_err(Into::into)
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

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
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
