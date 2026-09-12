//! Executes the closed native-adapter role-revocation qualification cohort.
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
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, ArtifactReference, ControllerAssignment,
    IndeterminateSemantics, InterfaceDocument, InterfaceKey, LocalKey, MethodDescriptor,
    MethodReference, Operation, ProviderAssignment, ProviderImplementationReference,
    ResourceAccess, ResourceId, RetryPolicy, StringSyntax, TransactionId, ValueExpression,
    ValueSchema,
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
    ExecutionError, ExecutionEventKind, ExecutionTransaction, RuntimeAuthorityRole,
    TrustedAdmissionPolicy, TrustedAuthoritySnapshot,
};
use aos_ability_runtime::journal::JournalLimits;
use aos_ability_validate::CheckedEffectPlan;
use aos_ability_validate::test_support::{PlanFixture, plan_fixture};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

const OUTPUT_SCHEMA: &str = "aos.qualification.authority-revocation-audit/v1";
const SUBJECT_SCHEMA: &str = "aos.qualification.authority-revocation-subject/v1";
const PLAN_BUNDLE_SCHEMA: &str = "aos.qualification.authority-revocation-plan/v1";
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

#[derive(Default)]
struct NoDispatchAdapter {
    calls: usize,
}

impl NoDispatchAdapter {
    fn record_unexpected_dispatch(&mut self) {
        self.calls += 1;
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
        request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        self.record_unexpected_dispatch();
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
        self.record_unexpected_dispatch();
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
        self.record_unexpected_dispatch();
        CancellationDisposition::Indeterminate(AuditRecord {
            evidence: request.clone(),
            outputs: BTreeMap::new(),
        })
    }
}

struct AuditClock;

impl MonotonicClock for AuditClock {
    fn now_millis(&self) -> u64 {
        1
    }

    fn restart_stable_millis(&self) -> u64 {
        1
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
    owners: usize,
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
        }
    }

    ensure!(cells.len() == 564, "expected 564 role-revocation cells");
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

    let (plan, plan_bundle) = checked_plan(interface, descriptor, matrix_method)?;
    let transaction_id = TransactionId(LocalKey::new(&format!(
        "authority-{}",
        &digest_bytes(cell_id.as_bytes())[7..23]
    ))?);
    let operation_key = plan.operations()[0].key.clone();
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
    let mut adapter = NoDispatchAdapter::default();

    match scenario.boundary {
        aos_ability_runtime::execution::Boundary::FinalDispatch => {
            let admitted = transaction
                .admit(
                    &operation_key,
                    &adapter,
                    &mut catalog,
                    &mut policy,
                    &AuditClock,
                )
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
            let error = match transaction.drive_admitted_with_observer(
                &admitted,
                &mut adapter,
                &mut policy,
                &AuditClock,
                &CancellationToken::default(),
                &mut observer,
            ) {
                Ok(_) => bail!("final dispatch unexpectedly succeeded"),
                Err(error) => error,
            };
            assert_execution_rejection(&error, scenario)?;
            transaction
                .release_admitted::<NoDispatchAdapter, _, _>(admitted, &mut catalog, &AuditClock)
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
        }
        _ => {
            let failure = match transaction.admit_with_observer(
                &operation_key,
                &adapter,
                &mut catalog,
                &mut policy,
                &AuditClock,
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
        adapter.calls == 0,
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
        "dispatch-calls": adapter.calls,
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

fn checked_plan(
    interface: &InterfaceDocument,
    descriptor: &MethodDescriptor,
    matrix_method: &MatrixMethod,
) -> Result<(CheckedEffectPlan, Vec<u8>)> {
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
            interface: interface_key,
            method: LocalKey::new(&matrix_method.method)?,
        })
    } else {
        None
    };
    let operation = &mut fixture.effect_plan.operations[0];
    operation.key.key = LocalKey::new(&matrix_method.method)?;
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

    Ok((plan, plan_bundle))
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
