//! Native systemd resource admission and lifecycle effect execution.
//!
//! The catalog binds checked logical resources to configured unit names and a
//! fresh D-Bus manager owner. The adapter persists that owner with its request
//! and observes it again immediately before every call, so a bus or manager
//! replacement cannot reuse stale admission evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aos_ability_model::{
    AbilityActivationMode, AbilityValue, ExecutionStage, IncarnationId, LocalKey, MethodReference,
    Operation, OperationFamily, ProviderAssignment, ProviderImplementationReference,
    ResourceAccess, ResourceId, ServiceAction,
    builtin::{
        systemd_manager_handler, systemd_manager_handler_key, systemd_manager_interface_key,
        systemd_manager_provider,
    },
};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CatalogReservation,
    EffectDisposition, InvocationPurpose, ReconcileDisposition, ReservationContext,
    ResourceAdmissionEvidence, ResourceHandle, RuntimeControl, TrustedAdapter,
    TrustedResourceCatalog,
};
use aos_systemd::{JobOutcome, PinnedSystemdManager, SystemdManagerConnection, UnitActiveState};
use serde::{Deserialize, Serialize};

use crate::ability_package::VerifiedAbilityPackage;
use crate::config_eval::ability_store::{
    NativeQualifiedResource, NativeResourceInventory, NativeResourceReservation,
};

const REQUEST_SCHEMA: &str = "aos.ability.systemd-request/v1";
const RECORD_SCHEMA: &str = "aos.ability.systemd-observation/v1";
const CATALOG_QUALIFICATION_MILLIS: u64 = 30_000;
const NATIVE_EXECUTOR_SUFFIX: &str = "bin/.aos-package-runtime-unwrapped";

/// Binds one checked logical resource to the only unit it may control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdResourceSpec {
    /// Names the logical resource declared by the checked provider.
    pub resource: ResourceId,
    /// Names the exact systemd unit authorized for that resource.
    pub unit: String,
}

/// A fresh native handle acquired for one checked systemd resource.
pub struct SystemdResourceHandle {
    unit: String,
    unit_identity: String,
    manager: Arc<PinnedSystemdManager>,
    reservation: NativeResourceReservation,
}

impl std::fmt::Debug for SystemdResourceHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SystemdResourceHandle")
            .field("unit", &self.unit)
            .field("unit_identity", &self.unit_identity)
            .field("manager", &self.manager.incarnation())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
struct QualifiedSystemdResource {
    unit: String,
    unit_identity: String,
    qualified: NativeQualifiedResource,
}

/// Resolves checked systemd resources against one exact live assignment.
pub struct SystemdResourceCatalog {
    connection: Arc<SystemdManagerConnection>,
    runtime: tokio::runtime::Handle,
    assignment: ProviderAssignment,
    inventory: NativeResourceInventory,
    resources: BTreeMap<ResourceId, QualifiedSystemdResource>,
}

impl SystemdResourceCatalog {
    /// Constructs a catalog from a scoped manager connection, checked
    /// assignment, and authorized units.
    ///
    /// Every acquisition pins `connection`; the catalog never opens or falls
    /// back to another bus scope. Authorized units must already be loaded by a
    /// preceding provider preparation step so qualification remains read-only.
    ///
    /// # Errors
    ///
    /// Returns an error when no Tokio runtime is active, a unit name is unsafe,
    /// a resource belongs to another provider, a resource is duplicated, or
    /// two logical resources name the same concrete unit, an authorized unit is
    /// not already loaded, or its canonical identity cannot be resolved.
    pub fn new(
        connection: Arc<SystemdManagerConnection>,
        assignment: ProviderAssignment,
        inventory: NativeResourceInventory,
        resources: impl IntoIterator<Item = SystemdResourceSpec>,
    ) -> Result<Self, io::Error> {
        require_host_assignment(&assignment)?;
        require_host_collision_domain()?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            invalid_data(format!("systemd catalog requires a Tokio runtime: {error}"))
        })?;
        require_multi_thread_runtime(&runtime)?;
        let configured = index_resources(&assignment, resources)?;
        let manager = Arc::new(run_async(
            &runtime,
            CATALOG_QUALIFICATION_MILLIS,
            connection.pin(),
        )?);
        require_assignment_incarnation(&assignment, &manager)?;

        let mut unit_identities = BTreeSet::new();
        let mut indexed = BTreeMap::new();
        for (resource, unit) in configured {
            let unit_identity = run_async(
                &runtime,
                CATALOG_QUALIFICATION_MILLIS,
                manager.unit_identity(&unit),
            )?;
            if !unit_identities.insert(unit_identity.clone()) {
                return Err(invalid_data(
                    "distinct systemd resources resolve to the same manager unit",
                ));
            }
            let qualified = NativeQualifiedResource::systemd(resource.clone(), &unit_identity)
                .map_err(|error| invalid_data(error.to_string()))?;
            indexed.insert(
                resource,
                QualifiedSystemdResource {
                    unit,
                    unit_identity,
                    qualified,
                },
            );
        }
        Ok(Self {
            connection,
            runtime,
            assignment,
            inventory,
            resources: indexed,
        })
    }

    /// Returns the exact logical-to-native qualification for a catalog member.
    #[must_use]
    pub fn qualified_resource(&self, resource: &ResourceId) -> Option<NativeQualifiedResource> {
        self.resources
            .get(resource)
            .map(|resource| resource.qualified.clone())
    }
}

fn require_host_collision_domain() -> Result<(), io::Error> {
    let rooted = std::env::var_os("AOS_ROOT").is_some_and(|value| !value.is_empty());
    let custom_lock =
        std::env::var_os("AOS_SWITCH_LOCK_PATH").is_some_and(|value| !value.is_empty());
    let custom_profile = std::env::var_os("AOS_PROFILE_ROOT")
        .is_some_and(|value| !value.is_empty() && value != "/var/lib/profiles");
    if rooted || custom_lock || custom_profile {
        return Err(invalid_data(
            "host systemd abilities require the machine-global profile, ledger, and switch-lock domain",
        ));
    }
    Ok(())
}

fn require_host_assignment(assignment: &ProviderAssignment) -> Result<(), io::Error> {
    if assignment.provider.environment.stage != ExecutionStage::Host {
        return Err(invalid_data(
            "host systemd abilities reject assignments from initrd, user, and container manager scopes",
        ));
    }
    Ok(())
}

fn index_resources(
    assignment: &ProviderAssignment,
    resources: impl IntoIterator<Item = SystemdResourceSpec>,
) -> Result<BTreeMap<ResourceId, String>, io::Error> {
    let mut indexed = BTreeMap::new();
    let mut units = BTreeSet::new();
    for spec in resources {
        if spec.resource.provider != assignment.provider {
            return Err(invalid_data("systemd resource belongs to another provider"));
        }
        validate_unit_name(&spec.unit)?;
        if !units.insert(spec.unit.clone()) {
            return Err(invalid_data(
                "distinct systemd resources target the same concrete unit",
            ));
        }
        if indexed.insert(spec.resource, spec.unit).is_some() {
            return Err(invalid_data(
                "systemd resource catalog contains a duplicate",
            ));
        }
    }
    Ok(indexed)
}

fn require_assignment_incarnation(
    assignment: &ProviderAssignment,
    manager: &PinnedSystemdManager,
) -> Result<(), io::Error> {
    let incarnation = IncarnationId::new(manager.incarnation().token())
        .map_err(|error| invalid_data(format!("invalid systemd manager owner: {error}")))?;
    if incarnation == assignment.incarnation {
        Ok(())
    } else {
        Err(invalid_data(
            "systemd manager incarnation changed before admission",
        ))
    }
}

impl TrustedResourceCatalog for SystemdResourceCatalog {
    type Handle = SystemdResourceHandle;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        if operation.target.resource != access.resource {
            return Err(invalid_data(
                "systemd access does not target the operation resource",
            ));
        }
        if context.expected_provider != Some(&self.assignment) {
            return Err(invalid_data(
                "systemd provider assignment is absent or stale",
            ));
        }
        let resource = self
            .resources
            .get(&access.resource)
            .ok_or_else(|| invalid_data("systemd resource is outside the authorized catalog"))?
            .clone();
        let manager = Arc::new(run_async(
            &self.runtime,
            context.recovery_remaining_millis,
            self.connection.pin(),
        )?);
        require_assignment_incarnation(&self.assignment, &manager)?;
        let unit_identity = run_async(
            &self.runtime,
            context.recovery_remaining_millis,
            manager.unit_identity(&resource.unit),
        )?;
        if unit_identity != resource.unit_identity {
            return Err(invalid_data(
                "systemd unit identity changed before admission",
            ));
        }
        let reservation = self
            .inventory
            .reserve(&resource.qualified, context, operation, access)
            .map_err(|error| invalid_data(error.to_string()))?;
        let observation = record_value(SystemdEvidenceFields {
            state: "admitted",
            unit: &resource.unit,
            unit_identity: Some(&resource.unit_identity),
            manager_bus_id: Some(manager.incarnation().bus_id()),
            manager_owner: Some(manager.incarnation().owner()),
            active_state: None,
            job_result: None,
            job_path: None,
        })?;
        let evidence = ResourceAdmissionEvidence::new(
            access.resource.clone(),
            Some(self.assignment.incarnation.clone()),
            None,
            observation,
        );
        Ok(CatalogReservation::new(
            SystemdResourceHandle {
                unit: resource.unit,
                unit_identity: resource.unit_identity,
                manager,
                reservation,
            },
            evidence,
        ))
    }

    fn release(
        &mut self,
        resource: &ResourceId,
        handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        if handle.reservation.logical() != resource {
            return Err(invalid_data(
                "systemd release resource does not match its native reservation",
            ));
        }
        handle
            .reservation
            .release()
            .map_err(|error| invalid_data(error.to_string()))
    }
}

/// Durable request reconstructed after fresh systemd resource acquisition.
#[derive(Clone)]
pub struct SystemdAbilityRequest {
    durable: SystemdDurableRequest,
    manager: Arc<PinnedSystemdManager>,
}

impl std::fmt::Debug for SystemdAbilityRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SystemdAbilityRequest")
            .field("durable", &self.durable)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SystemdDurableRequest {
    schema: String,
    action: SystemdAbilityAction,
    unit: String,
    unit_identity: String,
    manager_bus_id: String,
    manager_owner: String,
}

struct SystemdObservation {
    active_state: UnitActiveState,
    record: SystemdAbilityRecord,
}

/// Typed systemd completion or reconciliation evidence.
#[derive(Clone, Debug)]
pub struct SystemdAbilityRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for SystemdAbilityRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for SystemdAbilityRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

/// Executes a checked systemd lifecycle method through the typed D-Bus client.
pub struct NativeSystemdAdapter {
    runtime: tokio::runtime::Handle,
    assignment: ProviderAssignment,
    fallback: SystemdAbilityRecord,
}

impl NativeSystemdAdapter {
    /// Constructs an adapter from one authenticated package and exact live assignment.
    ///
    /// # Errors
    ///
    /// Returns an error when the package and assignment do not contain the
    /// exact built-in systemd interface, provider, handler, and artifact
    /// linkage, no Tokio runtime is active, or fallback evidence is invalid.
    pub fn new(
        package: &VerifiedAbilityPackage,
        assignment: ProviderAssignment,
    ) -> Result<Self, io::Error> {
        authenticate_builtin_systemd(package, &assignment)?;
        authenticate_native_executor(&assignment.implementation.artifact)?;
        Self::initialize(assignment)
    }

    fn initialize(assignment: ProviderAssignment) -> Result<Self, io::Error> {
        require_host_assignment(&assignment)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            invalid_data(format!("systemd adapter requires a Tokio runtime: {error}"))
        })?;
        require_multi_thread_runtime(&runtime)?;
        let fallback = SystemdAbilityRecord {
            durable: record_value(SystemdEvidenceFields {
                state: "internal-error",
                unit: "unknown.service",
                unit_identity: None,
                manager_bus_id: None,
                manager_owner: None,
                active_state: None,
                job_result: None,
                job_path: None,
            })?,
            outputs: BTreeMap::new(),
        };
        Ok(Self {
            runtime,
            assignment,
            fallback,
        })
    }

    fn observe(
        &self,
        request: &SystemdAbilityRequest,
        remaining_millis: u64,
    ) -> Result<SystemdObservation, io::Error> {
        let active_state = run_async(
            &self.runtime,
            remaining_millis,
            request
                .manager
                .active_state_exact(&request.durable.unit, &request.durable.unit_identity),
        )?;
        let record = self.record("observed", request, Some(&active_state), None, None);
        Ok(SystemdObservation {
            active_state,
            record,
        })
    }

    fn record(
        &self,
        state: &str,
        request: &SystemdAbilityRequest,
        active_state: Option<&UnitActiveState>,
        job_result: Option<&str>,
        job_path: Option<&str>,
    ) -> SystemdAbilityRecord {
        let durable = record_value(SystemdEvidenceFields {
            state,
            unit: &request.durable.unit,
            unit_identity: Some(&request.durable.unit_identity),
            manager_bus_id: Some(&request.durable.manager_bus_id),
            manager_owner: Some(&request.durable.manager_owner),
            active_state,
            job_result,
            job_path,
        })
        .unwrap_or_else(|_| self.fallback.durable.clone());
        let mut outputs = BTreeMap::new();
        if let Some(active_state) = active_state
            && let (Ok(port), Ok(value)) = (
                LocalKey::new("active"),
                AbilityValue::new(serde_json::Value::Bool(active_state.is_active())),
            )
        {
            outputs.insert(port, value);
        }
        SystemdAbilityRecord { durable, outputs }
    }

    fn stale_record(&self, request: &SystemdAbilityRequest) -> SystemdAbilityRecord {
        self.record("manager-changed", request, None, None, None)
    }
}

fn authenticate_builtin_systemd(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
) -> Result<(), io::Error> {
    if package.activation_mode() != AbilityActivationMode::StructuredEffects {
        return Err(invalid_data(
            "systemd adapter requires a structured-effects package",
        ));
    }

    let interface = systemd_manager_interface_key()
        .map_err(|error| invalid_data(format!("invalid built-in systemd interface: {error:#}")))?;
    let handler_key = systemd_manager_handler_key().map_err(|error| {
        invalid_data(format!("invalid built-in systemd handler key: {error:#}"))
    })?;
    if assignment.interface != interface
        || assignment.implementation.handler.as_ref() != Some(&handler_key)
    {
        return Err(invalid_data(
            "assignment does not select the exact built-in systemd contract",
        ));
    }

    let verified = package
        .resolve_terminal_handler(assignment.implementation.descriptor, &handler_key)
        .ok_or_else(|| {
            invalid_data("authenticated package does not resolve the assigned systemd handler")
        })?;
    let expected_provider = systemd_manager_provider(verified.handler().artifact.clone())
        .map_err(|error| invalid_data(format!("invalid built-in systemd provider: {error:#}")))?;
    let expected_handler = systemd_manager_handler(verified.handler().artifact.clone())
        .map_err(|error| invalid_data(format!("invalid built-in systemd handler: {error:#}")))?;
    if verified.provider() != &expected_provider || verified.handler() != &expected_handler {
        return Err(invalid_data(
            "authenticated provider or handler differs from the built-in systemd contract",
        ));
    }
    if assignment.implementation.artifact != expected_provider.artifact {
        return Err(invalid_data(
            "live systemd assignment uses another authenticated artifact",
        ));
    }
    Ok(())
}

fn authenticate_native_executor(
    artifact: &aos_ability_model::ArtifactReference,
) -> Result<(), io::Error> {
    let executable = std::env::current_exe()
        .map_err(|error| invalid_data(format!("resolving native executor path: {error}")))?;
    authenticate_native_executor_path(artifact, &executable)
}

fn authenticate_native_executor_path(
    artifact: &aos_ability_model::ArtifactReference,
    executable: &Path,
) -> Result<(), io::Error> {
    let (root, suffix) = super::stock::store_root_and_suffix(executable).map_err(|error| {
        invalid_data(format!("native executor is outside the Nix store: {error}"))
    })?;
    if root.as_os_str() != std::ffi::OsStr::new(&artifact.store_path)
        || suffix.as_os_str() != std::ffi::OsStr::new(NATIVE_EXECUTOR_SUFFIX)
    {
        return Err(invalid_data(
            "signed systemd handler artifact does not identify the running package runtime",
        ));
    }
    Ok(())
}

impl TrustedAdapter for NativeSystemdAdapter {
    type Request = SystemdAbilityRequest;
    type Completion = SystemdAbilityRecord;
    type Observation = SystemdAbilityRecord;
    type Handle = SystemdResourceHandle;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        implementation: &ProviderImplementationReference,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> bool {
        if implementation != &self.assignment.implementation
            || method.interface != self.assignment.interface
        {
            return false;
        }
        match purpose {
            InvocationPurpose::Effect => matches!(
                method.method.as_str(),
                "start" | "reload" | "restart" | "stop" | "observe"
            ),
            InvocationPurpose::Reconcile | InvocationPurpose::Cancel => {
                method.method.as_str() == "observe"
            }
            InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => false,
        }
    }

    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        let action = SystemdAbilityAction::from_operation(operation)?;
        if operation.interface != self.assignment.interface {
            return Err(invalid_data("systemd operation uses another interface"));
        }
        let [resource] = resources else {
            return Err(invalid_data(
                "systemd operation requires exactly one resource",
            ));
        };
        if resource.resource() != &operation.target.resource {
            return Err(invalid_data(
                "systemd handle does not match the operation target",
            ));
        }
        let input: UnitInput = serde_json::from_value(inputs.as_json().clone())
            .map_err(|error| invalid_data(format!("invalid systemd input: {error}")))?;
        validate_unit_name(&input.unit)?;
        if input.unit != resource.native().unit {
            return Err(invalid_data(
                "systemd input unit is outside the resource binding",
            ));
        }
        let request = SystemdDurableRequest {
            schema: REQUEST_SCHEMA.to_string(),
            action,
            unit: input.unit,
            unit_identity: resource.native().unit_identity.clone(),
            manager_bus_id: resource.native().manager.incarnation().bus_id().to_string(),
            manager_owner: resource.native().manager.incarnation().owner().to_string(),
        };
        AbilityValue::new(
            serde_json::to_value(request)
                .map_err(|error| invalid_data(format!("encoding systemd request: {error}")))?,
        )
        .map_err(|error| invalid_data(format!("systemd request exceeds limits: {error}")))
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        let request: SystemdDurableRequest = serde_json::from_value(durable.as_json().clone())
            .map_err(|error| invalid_data(format!("invalid durable systemd request: {error}")))?;
        if request.schema != REQUEST_SCHEMA {
            return Err(invalid_data("unsupported durable systemd request schema"));
        }
        let [resource] = resources else {
            return Err(invalid_data(
                "systemd recovery requires exactly one resource",
            ));
        };
        if request.unit != resource.native().unit
            || request.unit_identity != resource.native().unit_identity
            || request.manager_bus_id != resource.native().manager.incarnation().bus_id()
            || request.manager_owner != resource.native().manager.incarnation().owner()
        {
            return Err(invalid_data(
                "durable systemd request disagrees with fresh acquisition",
            ));
        }
        Ok(SystemdAbilityRequest {
            durable: request,
            manager: Arc::clone(&resource.native().manager),
        })
    }

    fn execute(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        if control.is_cancelled() {
            return EffectDisposition::RejectedBeforeEffect(self.record(
                "cancelled-before-dispatch",
                request,
                None,
                None,
                None,
            ));
        }
        if request.durable.action == SystemdAbilityAction::Observe {
            return match self.observe(request, call_remaining_millis(control)) {
                Ok(observation) => EffectDisposition::Completed(observation.record),
                Err(_) => EffectDisposition::Indeterminate(self.record(
                    "observation-failed",
                    request,
                    None,
                    None,
                    None,
                )),
            };
        }
        let outcome = run_job(&self.runtime, control, request);
        let Ok(outcome) = outcome else {
            return EffectDisposition::Indeterminate(self.record(
                "job-indeterminate",
                request,
                None,
                None,
                None,
            ));
        };
        if !outcome.result.is_done() {
            return EffectDisposition::Indeterminate(self.record(
                "job-failed",
                request,
                None,
                Some(outcome.result.label()),
                Some(outcome.job_path.as_str()),
            ));
        }
        match self.observe(request, call_remaining_millis(control)) {
            Ok(observation)
                if request
                    .durable
                    .action
                    .postcondition(&observation.active_state) =>
            {
                EffectDisposition::Completed(self.record(
                    "completed",
                    request,
                    Some(&observation.active_state),
                    Some(outcome.result.label()),
                    Some(outcome.job_path.as_str()),
                ))
            }
            Ok(observation) => EffectDisposition::Indeterminate(observation.record),
            Err(_) => EffectDisposition::Indeterminate(self.record(
                "postcondition-unavailable",
                request,
                None,
                Some(outcome.result.label()),
                Some(outcome.job_path.as_str()),
            )),
        }
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        match self.observe(request, call_remaining_millis(control)) {
            Ok(observation)
                if request
                    .durable
                    .action
                    .recovery_postcondition(&observation.active_state) =>
            {
                ReconcileDisposition::Completed(observation.record)
            }
            Ok(observation) => ReconcileDisposition::StillIndeterminate(observation.record),
            Err(_) => ReconcileDisposition::InterventionRequired(self.stale_record(request)),
        }
    }

    fn cancel(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        match self.observe(request, call_remaining_millis(control)) {
            Ok(observation)
                if request
                    .durable
                    .action
                    .recovery_postcondition(&observation.active_state) =>
            {
                CancellationDisposition::Completed(observation.record)
            }
            Ok(observation) => CancellationDisposition::Indeterminate(observation.record),
            Err(_) => CancellationDisposition::Indeterminate(self.stale_record(request)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SystemdAbilityAction {
    Start,
    Reload,
    Restart,
    Stop,
    Observe,
}

impl SystemdAbilityAction {
    fn from_operation(operation: &Operation) -> Result<Self, io::Error> {
        let action = match operation.family {
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Start,
            } => Self::Start,
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Reload,
            } => Self::Reload,
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Restart,
            } => Self::Restart,
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop,
            } => Self::Stop,
            OperationFamily::ObserveReadiness => Self::Observe,
            _ => return Err(invalid_data("unsupported systemd operation family")),
        };
        if operation.method.as_str() != action.label() {
            return Err(invalid_data(
                "systemd method disagrees with operation family",
            ));
        }
        Ok(action)
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Reload => "reload",
            Self::Restart => "restart",
            Self::Stop => "stop",
            Self::Observe => "observe",
        }
    }

    const fn postcondition(self, active_state: &UnitActiveState) -> bool {
        match self {
            Self::Start | Self::Reload | Self::Restart => active_state.is_active(),
            Self::Stop => matches!(active_state, UnitActiveState::Inactive),
            Self::Observe => true,
        }
    }

    const fn recovery_postcondition(self, active_state: &UnitActiveState) -> bool {
        match self {
            Self::Start => active_state.is_active(),
            Self::Stop => matches!(active_state, UnitActiveState::Inactive),
            Self::Observe => true,
            Self::Reload | Self::Restart => false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitInput {
    unit: String,
}

fn run_job(
    runtime: &tokio::runtime::Handle,
    control: &dyn RuntimeControl,
    request: &SystemdAbilityRequest,
) -> Result<JobOutcome, io::Error> {
    let remaining_millis = call_remaining_millis(control);
    match request.durable.action {
        SystemdAbilityAction::Start => run_async(
            runtime,
            remaining_millis,
            request
                .manager
                .start_unit_exact(&request.durable.unit, &request.durable.unit_identity),
        ),
        SystemdAbilityAction::Reload => run_async(
            runtime,
            remaining_millis,
            request
                .manager
                .reload_unit_exact(&request.durable.unit, &request.durable.unit_identity),
        ),
        SystemdAbilityAction::Restart => run_async(
            runtime,
            remaining_millis,
            request
                .manager
                .restart_unit_exact(&request.durable.unit, &request.durable.unit_identity),
        ),
        SystemdAbilityAction::Stop => run_async(
            runtime,
            remaining_millis,
            request
                .manager
                .stop_unit_exact(&request.durable.unit, &request.durable.unit_identity),
        ),
        SystemdAbilityAction::Observe => Err(invalid_data("observe does not submit a job")),
    }
}

fn call_remaining_millis(control: &dyn RuntimeControl) -> u64 {
    control
        .attempt_remaining_millis()
        .min(control.recovery_remaining_millis())
}

fn run_async<T, F>(
    runtime: &tokio::runtime::Handle,
    remaining_millis: u64,
    future: F,
) -> Result<T, io::Error>
where
    T: Send,
    F: Future<Output = aos_systemd::Result<T>> + Send,
{
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|current| current.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread)
    {
        return Err(invalid_data(
            "systemd synchronous bridge cannot run on a current-thread Tokio runtime",
        ));
    }
    if remaining_millis == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "systemd deadline elapsed",
        ));
    }
    let timeout = Duration::from_millis(remaining_millis);
    tokio::task::block_in_place(|| {
        runtime
            .block_on(async move { tokio::time::timeout(timeout, future).await })
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "systemd call timed out"))?
            .map_err(|error| io::Error::other(error.to_string()))
    })
}

fn require_multi_thread_runtime(runtime: &tokio::runtime::Handle) -> Result<(), io::Error> {
    if runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
        Ok(())
    } else {
        Err(invalid_data(
            "systemd native execution requires a multi-thread Tokio runtime",
        ))
    }
}

struct SystemdEvidenceFields<'a> {
    state: &'a str,
    unit: &'a str,
    unit_identity: Option<&'a str>,
    manager_bus_id: Option<&'a str>,
    manager_owner: Option<&'a str>,
    active_state: Option<&'a UnitActiveState>,
    job_result: Option<&'a str>,
    job_path: Option<&'a str>,
}

fn record_value(fields: SystemdEvidenceFields<'_>) -> Result<AbilityValue, io::Error> {
    AbilityValue::new(serde_json::json!({
        "schema": RECORD_SCHEMA,
        "state": fields.state,
        "unit": fields.unit,
        "unit_identity": fields.unit_identity,
        "manager_bus_id": fields.manager_bus_id,
        "manager_owner": fields.manager_owner,
        "active_state": fields.active_state.map(UnitActiveState::label),
        "active": fields.active_state.map(UnitActiveState::is_active),
        "job_result": fields.job_result,
        "job_path": fields.job_path,
    }))
    .map_err(|error| invalid_data(format!("systemd evidence exceeds limits: {error}")))
}

fn validate_unit_name(unit: &str) -> Result<(), io::Error> {
    if unit.is_empty()
        || unit.len() > 255
        || !unit.ends_with(".service")
        || !unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'@' | b'-' | b'\\')
        })
    {
        return Err(invalid_data("invalid systemd service unit name"));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use aos_ability_validate::test_support::{
        checked_effect_plan, checked_systemd_manager_effect_plan,
    };
    use aos_systemd::JobResult;
    use zbus::object_server::SignalEmitter;
    use zbus::zvariant::OwnedObjectPath;

    use super::*;
    use crate::ability_package::seal_test_package;

    const SYSTEMD_NAME: &str = "org.freedesktop.systemd1";
    const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
    const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/example_2eservice";
    const REBIND_FIRST_PATH: &str = "/org/freedesktop/systemd1/unit/rebind_2dfirst_2eservice";
    const REBIND_SECOND_PATH: &str = "/org/freedesktop/systemd1/unit/rebind_2dsecond_2eservice";

    struct FakeManager {
        units: BTreeMap<String, OwnedObjectPath>,
        sequences: std::sync::Mutex<BTreeMap<String, Vec<OwnedObjectPath>>>,
    }

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl FakeManager {
        async fn subscribe(&self) {}

        async fn get_unit(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
            if let Some(sequence) = self.sequences.lock().unwrap().get_mut(name)
                && !sequence.is_empty()
            {
                return Ok(sequence.remove(0));
            }
            self.units
                .get(name)
                .cloned()
                .ok_or_else(|| zbus::fdo::Error::Failed("unknown test unit".to_string()))
        }

        #[zbus(signal)]
        async fn job_removed(
            emitter: &SignalEmitter<'_>,
            id: u32,
            job: OwnedObjectPath,
            unit: String,
            result: String,
        ) -> zbus::Result<()>;
    }

    struct FakeUnit {
        id: String,
        active_state: Arc<std::sync::Mutex<String>>,
        starts: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
    impl FakeUnit {
        async fn start(
            &self,
            #[zbus(connection)] connection: &zbus::Connection,
            _mode: &str,
        ) -> OwnedObjectPath {
            self.starts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let job = OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/1")
                .expect("fixed test job path is valid");
            let manager = connection
                .object_server()
                .interface::<_, FakeManager>(MANAGER_PATH)
                .await
                .expect("fake manager remains registered");
            manager
                .job_removed(1, job.clone(), self.id.clone(), "done".to_string())
                .await
                .expect("fake job completion signal is emitted");
            job
        }

        async fn stop(
            &self,
            #[zbus(connection)] connection: &zbus::Connection,
            _mode: &str,
        ) -> OwnedObjectPath {
            let job = OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/2")
                .expect("fixed test job path is valid");
            let manager = connection
                .object_server()
                .interface::<_, FakeManager>(MANAGER_PATH)
                .await
                .expect("fake manager remains registered");
            manager
                .job_removed(2, job.clone(), self.id.clone(), "done".to_string())
                .await
                .expect("fake job completion signal is emitted");
            job
        }

        #[zbus(property)]
        fn id(&self) -> &str {
            &self.id
        }

        #[zbus(property)]
        fn active_state(&self) -> String {
            self.active_state.lock().unwrap().clone()
        }
    }

    struct TestControl;

    impl RuntimeControl for TestControl {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn elapsed_millis(&self) -> u64 {
            0
        }

        fn attempt_remaining_millis(&self) -> u64 {
            1_000
        }

        fn recovery_remaining_millis(&self) -> u64 {
            1_000
        }
    }

    #[test]
    fn current_thread_runtime_is_rejected_before_native_execution() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");

        runtime.block_on(async {
            assert!(require_multi_thread_runtime(&tokio::runtime::Handle::current()).is_err());
        });
    }

    #[test]
    fn host_systemd_rejects_every_other_execution_stage() {
        let mut assignment = test_assignment("test-manager".to_string());
        assert!(require_host_assignment(&assignment).is_ok());

        for stage in [
            ExecutionStage::Build,
            ExecutionStage::Initrd,
            ExecutionStage::SystemContainer,
            ExecutionStage::User,
            ExecutionStage::ApplicationContainer,
        ] {
            assignment.provider.environment.stage = stage;
            assert!(require_host_assignment(&assignment).is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_runtime_flavor_is_accepted() {
        assert!(require_multi_thread_runtime(&tokio::runtime::Handle::current()).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_adapter_requires_the_exact_sealed_builtin_handler()
    -> Result<(), Box<dyn std::error::Error>> {
        let checked = checked_systemd_manager_effect_plan();
        let binding = &checked.binding_plan().bindings()[0];
        let assignment = ProviderAssignment {
            provider: binding.provider.clone(),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            incarnation: IncarnationId::new("test-manager")?,
        };
        let artifact = assignment.implementation.artifact.clone();
        let mut package = aos_ability_model::PackageDocument {
            schema:
                <aos_ability_model::PackageDocument as aos_ability_model::VersionedDocument>::SCHEMA
                    .to_string(),
            required_features: Vec::new(),
            activation_mode: AbilityActivationMode::StructuredEffects,
            package: aos_ability_model::document::PackageSubject {
                name: LocalKey::new("native-systemd")?,
                version: "1.0.0".to_string(),
                payload: artifact.clone(),
                source: artifact.clone(),
            },
            artifacts: vec![artifact.clone()],
            exports: Vec::new(),
            requirements: Vec::new(),
            module_entry_points: BTreeMap::new(),
            implementation: aos_ability_model::PackageImplementation {
                providers: vec![systemd_manager_provider(artifact.clone())?],
                handlers: BTreeMap::from([(
                    systemd_manager_handler_key()?,
                    systemd_manager_handler(artifact)?,
                )]),
            },
            ownership: Vec::new(),
        };
        let verified = seal_test_package(package.clone())?;
        let executable =
            Path::new(&assignment.implementation.artifact.store_path).join(NATIVE_EXECUTOR_SUFFIX);

        authenticate_builtin_systemd(&verified, &assignment)?;
        authenticate_native_executor_path(&assignment.implementation.artifact, &executable)?;
        assert!(NativeSystemdAdapter::initialize(assignment.clone()).is_ok());
        assert!(NativeSystemdAdapter::new(&verified, assignment.clone()).is_err());

        package
            .implementation
            .handlers
            .get_mut(&systemd_manager_handler_key()?)
            .expect("test package contains the built-in handler")
            .entry_point = "libexec/forged-systemd-handler".to_string();
        let forged = seal_test_package(package)?;
        assert!(NativeSystemdAdapter::new(&forged, assignment).is_err());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_bridge_constructs_timeout_inside_the_target_runtime() {
        let runtime = tokio::runtime::Handle::current();

        let completed = run_async(&runtime, 100, async { Ok::<_, aos_systemd::Error>(7_u8) })
            .expect("ready future completes through the runtime bridge");
        let timeout = run_async(&runtime, 1, async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok::<_, aos_systemd::Error>(())
        })
        .expect_err("slow future reaches the bridge timeout");

        assert_eq!(completed, 7);
        assert_eq!(timeout.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn runtime_bridge_yields_a_single_runtime_worker() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("single-worker test runtime builds");
            let result = runtime.block_on(async {
                tokio::spawn(async {
                    let runtime = tokio::runtime::Handle::current();
                    run_async(&runtime, 500, async {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Ok::<_, aos_systemd::Error>(11_u8)
                    })
                })
                .await
            });
            sender
                .send(result)
                .expect("watchdog receiver remains available");
        });

        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("single-worker bridge must not deadlock")
            .expect("runtime worker task completes")
            .expect("timer-dependent systemd future completes");

        assert_eq!(result, 11);
    }

    #[test]
    fn runtime_bridge_rejects_a_current_thread_call_context() {
        let production = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("production test runtime builds");
        let production_handle = production.handle().clone();
        let caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread test runtime builds");

        let error = caller
            .block_on(async {
                run_async(&production_handle, 100, async {
                    Ok::<_, aos_systemd::Error>(())
                })
            })
            .expect_err("current-thread callers are rejected before block_in_place");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn distinct_resources_cannot_target_the_same_unit() {
        let checked = checked_effect_plan();
        let binding = &checked.binding_plan().bindings()[0];
        let assignment = ProviderAssignment {
            provider: binding.provider.clone(),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            incarnation: IncarnationId::new("test-manager").unwrap(),
        };
        let first = ResourceId {
            provider: assignment.provider.clone(),
            key: LocalKey::new("primary-unit").unwrap(),
        };
        let second = ResourceId {
            provider: assignment.provider.clone(),
            key: LocalKey::new("alias-unit").unwrap(),
        };

        let result = index_resources(
            &assignment,
            [
                SystemdResourceSpec {
                    resource: first,
                    unit: "example.service".to_string(),
                },
                SystemdResourceSpec {
                    resource: second,
                    unit: "example.service".to_string(),
                },
            ],
        );

        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires the hermetic AOS D-Bus broker"]
    async fn supplied_catalog_dispatches_exact_unit_and_recovers_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory_directory = tempfile::tempdir()?;
        let generation = inventory_directory.path().join("gen-1");
        std::fs::create_dir(&generation)?;
        let inventory_plan = checked_effect_plan();
        let inventory_transaction =
            aos_ability_model::TransactionId(LocalKey::new("systemd-inventory")?);
        let (inventory, _inventory_owner) = NativeResourceInventory::test_for_generation(
            &generation,
            &inventory_transaction,
            &inventory_plan,
        )?;
        let address = std::env::var("AOS_TEST_DBUS_ADDRESS")?;
        let unit_path = OwnedObjectPath::try_from(UNIT_PATH)?;
        let manager = FakeManager {
            units: BTreeMap::from([
                ("example.service".to_string(), unit_path.clone()),
                ("example-alias.service".to_string(), unit_path.clone()),
            ]),
            sequences: std::sync::Mutex::new(BTreeMap::from([(
                "rebind.service".to_string(),
                vec![
                    OwnedObjectPath::try_from(REBIND_FIRST_PATH)?,
                    OwnedObjectPath::try_from(REBIND_SECOND_PATH)?,
                ],
            )])),
        };
        let example_starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let second_starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let example_active_state = Arc::new(std::sync::Mutex::new("active".to_string()));
        let server = zbus::connection::Builder::address(address.as_str())?
            .serve_at(MANAGER_PATH, manager)?
            .serve_at(
                UNIT_PATH,
                FakeUnit {
                    id: "example.service".to_string(),
                    active_state: Arc::clone(&example_active_state),
                    starts: Arc::clone(&example_starts),
                },
            )?
            .serve_at(
                REBIND_FIRST_PATH,
                FakeUnit {
                    id: "rebind.service".to_string(),
                    active_state: Arc::new(std::sync::Mutex::new("active".to_string())),
                    starts: Arc::clone(&first_starts),
                },
            )?
            .serve_at(
                REBIND_SECOND_PATH,
                FakeUnit {
                    id: "rebind.service".to_string(),
                    active_state: Arc::new(std::sync::Mutex::new("inactive".to_string())),
                    starts: Arc::clone(&second_starts),
                },
            )?
            .build()
            .await?;
        server.request_name(SYSTEMD_NAME).await?;
        let client = zbus::connection::Builder::address(address.as_str())?
            .build()
            .await?;
        let connection = Arc::new(SystemdManagerConnection::from_connection(client));
        let manager = Arc::new(connection.pin().await?);
        let outcome = manager
            .start_unit_exact("rebind.service", REBIND_FIRST_PATH)
            .await?;
        assert_eq!(outcome.result, JobResult::Done);
        assert_eq!(first_starts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(second_starts.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            manager.unit_identity("rebind.service").await?,
            REBIND_SECOND_PATH
        );
        let assignment = test_assignment(manager.incarnation().token());
        let first = test_resource(&assignment, "primary-unit");
        let second = test_resource(&assignment, "alias-unit");

        let catalog = SystemdResourceCatalog::new(
            Arc::clone(&connection),
            assignment.clone(),
            inventory.clone(),
            [SystemdResourceSpec {
                resource: first.clone(),
                unit: "example.service".to_string(),
            }],
        )?;
        assert_eq!(catalog.resources[&first].unit_identity, UNIT_PATH);

        let aliases = SystemdResourceCatalog::new(
            connection,
            assignment.clone(),
            inventory,
            [
                SystemdResourceSpec {
                    resource: first,
                    unit: "example.service".to_string(),
                },
                SystemdResourceSpec {
                    resource: second,
                    unit: "example-alias.service".to_string(),
                },
            ],
        );
        assert!(aliases.is_err());

        let start_request = SystemdAbilityRequest {
            durable: SystemdDurableRequest {
                schema: REQUEST_SCHEMA.to_string(),
                action: SystemdAbilityAction::Start,
                unit: "example.service".to_string(),
                unit_identity: UNIT_PATH.to_string(),
                manager_bus_id: manager.incarnation().bus_id().to_string(),
                manager_owner: manager.incarnation().owner().to_string(),
            },
            manager: Arc::clone(&manager),
        };
        let mut adapter = NativeSystemdAdapter::initialize(assignment)?;
        let completed = adapter.execute(&start_request, &TestControl);
        let EffectDisposition::Completed(completed) = completed else {
            panic!("completed start and active postcondition must settle the lifecycle effect");
        };
        let checked = checked_systemd_manager_effect_plan();
        let operation = &checked.operations()[0];
        let active_port = LocalKey::new("active")?;
        checked.validate_operation_output(
            operation,
            &active_port,
            &completed.outputs()[&active_port],
        )?;
        checked.validate_completion_evidence(operation, completed.durable())?;
        assert_eq!(
            completed.outputs()[&active_port].as_json(),
            &serde_json::Value::Bool(true)
        );
        assert_eq!(example_starts.load(std::sync::atomic::Ordering::SeqCst), 1);

        let stop_request = SystemdAbilityRequest {
            durable: SystemdDurableRequest {
                schema: REQUEST_SCHEMA.to_string(),
                action: SystemdAbilityAction::Stop,
                unit: "example.service".to_string(),
                unit_identity: UNIT_PATH.to_string(),
                manager_bus_id: manager.incarnation().bus_id().to_string(),
                manager_owner: manager.incarnation().owner().to_string(),
            },
            manager: Arc::clone(&manager),
        };
        for transient_state in ["activating", "deactivating", "reloading"] {
            *example_active_state.lock().unwrap() = transient_state.to_string();

            let EffectDisposition::Indeterminate(execution_record) =
                adapter.execute(&stop_request, &TestControl)
            else {
                panic!("transient state cannot settle a completed stop job");
            };
            let ReconcileDisposition::StillIndeterminate(reconcile_record) =
                adapter.reconcile(&stop_request, &TestControl)
            else {
                panic!("transient state cannot reconcile a stop");
            };
            let CancellationDisposition::Indeterminate(cancel_record) =
                adapter.cancel(&stop_request, &TestControl)
            else {
                panic!("transient state cannot cancel a stop as completed");
            };
            for record in [execution_record, reconcile_record, cancel_record] {
                checked.validate_observation_evidence(operation, record.durable())?;
                assert_eq!(record.durable().as_json()["active_state"], transient_state);
            }
        }

        *example_active_state.lock().unwrap() = "active".to_string();

        let request = SystemdAbilityRequest {
            durable: SystemdDurableRequest {
                schema: REQUEST_SCHEMA.to_string(),
                action: SystemdAbilityAction::Observe,
                unit: "example.service".to_string(),
                unit_identity: UNIT_PATH.to_string(),
                manager_bus_id: manager.incarnation().bus_id().to_string(),
                manager_owner: manager.incarnation().owner().to_string(),
            },
            manager,
        };
        let reconciled = adapter.reconcile(&request, &TestControl);
        let ReconcileDisposition::Completed(record) = reconciled else {
            panic!("fresh owner-bound observation did not recover the interrupted read");
        };
        checked.validate_completion_evidence(operation, record.durable())?;
        assert_eq!(
            record.outputs()[&LocalKey::new("active")?].as_json(),
            &serde_json::Value::Bool(true)
        );
        Ok(())
    }

    #[test]
    fn reload_and_restart_cannot_be_recovered_from_active_state_alone() {
        assert!(!SystemdAbilityAction::Reload.recovery_postcondition(&UnitActiveState::Active));
        assert!(!SystemdAbilityAction::Restart.recovery_postcondition(&UnitActiveState::Active));
        assert!(SystemdAbilityAction::Start.recovery_postcondition(&UnitActiveState::Active));
        assert!(SystemdAbilityAction::Stop.recovery_postcondition(&UnitActiveState::Inactive));
        assert!(SystemdAbilityAction::Observe.recovery_postcondition(&UnitActiveState::Active));
        assert!(SystemdAbilityAction::Observe.recovery_postcondition(&UnitActiveState::Inactive));
        for unsettled in [
            UnitActiveState::Activating,
            UnitActiveState::Deactivating,
            UnitActiveState::Reloading,
            UnitActiveState::Failed,
            UnitActiveState::Unknown("future".to_string()),
        ] {
            assert!(!SystemdAbilityAction::Stop.postcondition(&unsettled));
            assert!(!SystemdAbilityAction::Stop.recovery_postcondition(&unsettled));
        }
    }

    fn test_assignment(incarnation: String) -> ProviderAssignment {
        let checked = checked_effect_plan();
        let binding = &checked.binding_plan().bindings()[0];
        ProviderAssignment {
            provider: binding.provider.clone(),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            incarnation: IncarnationId::new(incarnation).unwrap(),
        }
    }

    fn test_resource(assignment: &ProviderAssignment, key: &str) -> ResourceId {
        ResourceId {
            provider: assignment.provider.clone(),
            key: LocalKey::new(key).unwrap(),
        }
    }
}
