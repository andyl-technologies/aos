//! Production host-resource adapters for credential, endpoint, storage, policy, and PostgreSQL.
//!
//! The adapters execute only after the ordinary native ability runtime has
//! authenticated the checked plan, selected package, live assignment, current
//! policy, resource access, and durable intent. Physical state lives beneath
//! `/var/lib/aos/ability-runtime` in root-protected directories. PostgreSQL
//! data survives release and stop; credential views, endpoint allocations, and
//! network-policy rules are instance-scoped.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aos_ability_model::builtin::{
    CREDENTIAL_DELIVERY_OBSERVATION_SCHEMA, HOST_NETWORK_POLICY_OBSERVATION_SCHEMA,
    HOST_STORAGE_OBSERVATION_SCHEMA, NETWORK_ENDPOINT_OBSERVATION_SCHEMA,
    POSTGRESQL_OBSERVATION_SCHEMA,
};
use aos_ability_model::{
    AbilityValue, InterfaceKey, LocalKey, MethodReference, Operation, ProviderAssignment,
    ProviderImplementationReference, ResourceAccess, ResourceId, RevisionId, ScopedOperationKey,
};
use aos_ability_plan::{RuntimeResourceHealth, RuntimeResourceState};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CatalogReservation,
    EffectDisposition, InvocationPurpose, ReconcileDisposition, ReservationContext,
    ResourceAdmissionEvidence, ResourceHandle, ResourceRevisionObservation, RuntimeControl,
    TrustedAdapter, TrustedResourceCatalog,
};
use serde::{Deserialize, Serialize};

use super::ability_store::{
    NativeQualifiedResource, NativeResourceInventory, NativeResourceReservation,
};
use super::native_ability_fs::authenticate_native_executor;
use super::native_resource_map::NativeResourceQualification;
use crate::ability_package::VerifiedAbilityPackage;

mod contract;
mod credential;
mod endpoint;
mod execution;
mod platform;
mod policy;
mod postgresql;
mod process;
mod state;
mod storage;
mod validation;

pub(crate) use contract::{NativeHostResourceKind, preflight_native_host_resource};
pub(crate) use credential::{
    CredentialEvidence, authenticate_credential_dependency_view,
    authenticate_credential_view_evidence,
};
use credential::{
    authenticate_credential_dependency, credential_healthy, execute_credential,
    validate_delivery_before_intent,
};
use endpoint::{authenticate_endpoint, endpoint_health, execute_endpoint};
use execution::{
    authenticate_dependency_bindings, execute_request, observe_health, reconcile_request,
    reject_postgresql_identity_change_before_intent, rejection_record, request_is_read_only,
};
use platform::NativePlatformTools;
use policy::execute_policy;
use postgresql::{execute_postgresql, postgresql_health, validate_process_fence_before_intent};
use process::FixedBudgetControl;
use state::{
    CREDENTIAL_ROOT, CREDENTIAL_SOURCE_ROOT, ENDPOINT_ROOT, HostState, MAX_CREDENTIAL_BYTES,
    POLICY_ROOT, POSTGRESQL_GID, POSTGRESQL_ROOT, POSTGRESQL_SLOT_COUNT, STORAGE_ROOT,
    atomic_write_root, ensure_directory, ensure_runtime_roots, is_protected_atomic_temporary,
    new_state, postgresql_broker_principal, postgresql_broker_uid, postgresql_probe_gid,
    postgresql_probe_principal, postgresql_probe_uid, postgresql_slot_principal,
    postgresql_slot_uid, protected_directory, read_protected_file, read_state_optional,
    remove_atomic_temporary_root, remove_regular_optional, require_current_state,
    require_matching_state, require_state, state_matches_spec, write_state,
};
pub(crate) use storage::{HostResourceAllocations, StorageAllocationRequest};
use storage::{StorageBinding, authenticate_storage_dependency, execute_storage, storage_health};
use validation::{
    CredentialInput, CredentialView, EndpointInput, EndpointValue, PolicyInput, PostgresqlInput,
    StorageInput, method_supported, path_text, require_operation_kind, resource_key, storage_path,
    validate_inputs,
};

/// Supplies the static qualification and desired revision for one logical resource.
#[derive(Clone, Debug)]
pub(crate) struct NativeHostResourceSpec {
    pub(crate) resource: ResourceId,
    pub(crate) handler_provider: aos_ability_model::InstanceId,
    pub(crate) revision: RevisionId,
    pub(crate) qualification: NativeResourceQualification,
    pub(crate) retained_qualification: Option<NativeResourceQualification>,
    pub(crate) dependencies: BTreeMap<ScopedOperationKey, Vec<NativeDependencyBinding>>,
    pub(crate) storage_binding: Option<StorageBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeDependencyBinding {
    pub(crate) input: String,
    pub(crate) producer: ScopedOperationKey,
    pub(crate) resource: ResourceId,
    pub(crate) revision: RevisionId,
    pub(crate) qualification: NativeResourceQualification,
    pub(crate) interface: InterfaceKey,
    pub(crate) method: LocalKey,
    pub(crate) output: LocalKey,
}

/// Acquires host-resource reservations through the common native ledger.
pub(crate) struct NativeHostResourceCatalog {
    assignment: ProviderAssignment,
    inventory: NativeResourceInventory,
    kind: NativeHostResourceKind,
    platform: NativePlatformTools,
    resources: BTreeMap<ResourceId, QualifiedHostResource>,
}

#[derive(Clone, Debug)]
struct QualifiedHostResource {
    spec: NativeHostResourceSpec,
    qualified: NativeQualifiedResource,
    state_path: PathBuf,
}

/// Retains one process-local native ledger reservation.
#[derive(Debug)]
pub(crate) struct NativeHostResourceHandle {
    resource: QualifiedHostResource,
    reservation: NativeResourceReservation,
}

impl NativeHostResourceCatalog {
    pub(crate) fn new(
        assignment: ProviderAssignment,
        inventory: NativeResourceInventory,
        kind: NativeHostResourceKind,
        resources: impl IntoIterator<Item = NativeHostResourceSpec>,
    ) -> Result<Self, io::Error> {
        if assignment.provider.environment.stage != aos_ability_model::ExecutionStage::Host {
            return Err(invalid(
                "native host resources require the Host execution stage",
            ));
        }
        super::ability_store::require_machine_global_host_collision_domain()?;
        let platform = NativePlatformTools::authenticate(&assignment.implementation.artifact)?;
        let mut indexed = BTreeMap::new();
        for spec in resources {
            if spec.handler_provider != assignment.provider
                || NativeHostResourceKind::from_qualification(&spec.qualification) != Some(kind)
            {
                return Err(invalid(
                    "host-resource catalog contains a foreign qualification",
                ));
            }
            let (class, object, state_path) = physical_identity(&spec)?;
            let qualified = NativeQualifiedResource::host_resource(
                spec.resource.clone(),
                class,
                "aos-host-runtime",
                &object,
            )
            .map_err(store_error)?;
            let resource = spec.resource.clone();
            if indexed
                .insert(
                    resource,
                    QualifiedHostResource {
                        spec,
                        qualified,
                        state_path,
                    },
                )
                .is_some()
            {
                return Err(invalid(
                    "host-resource catalog contains a duplicate resource",
                ));
            }
        }
        Ok(Self {
            assignment,
            inventory,
            kind,
            platform,
            resources: indexed,
        })
    }

    pub(crate) fn classify_runtime_state(
        &self,
        resource: &ResourceId,
    ) -> Result<(NativeQualifiedResource, RuntimeResourceState), io::Error> {
        let resource = self
            .resources
            .get(resource)
            .ok_or_else(|| invalid("host resource is outside the qualified catalog"))?;
        let state = read_state_optional(&resource.state_path)?;
        let runtime = match state {
            None => RuntimeResourceState::Absent,
            Some(state) if state_matches_spec(&state, &resource.spec) => {
                let control = FixedBudgetControl::new(5_000);
                let health =
                    observe_health(self.kind, &resource.spec, &state, &self.platform, &control)?;
                RuntimeResourceState::Present {
                    revision: state.revision,
                    health,
                }
            }
            Some(_) => {
                return Err(invalid(
                    "host-resource state belongs to another qualification",
                ));
            }
        };
        Ok((resource.qualified.clone(), runtime))
    }
}

impl TrustedResourceCatalog for NativeHostResourceCatalog {
    type Handle = NativeHostResourceHandle;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        if context
            .expected_provider
            .is_some_and(|assignment| assignment != &self.assignment)
            || operation.target.resource != access.resource
        {
            return Err(invalid("host-resource assignment or access is stale"));
        }
        let context = ReservationContext {
            expected_provider: Some(&self.assignment),
            ..context
        };
        require_operation_kind(operation, self.kind)?;
        let resource = self
            .resources
            .get(&access.resource)
            .ok_or_else(|| invalid("host resource is outside the authorized catalog"))?
            .clone();
        let reservation = self
            .inventory
            .reserve(&resource.qualified, context, operation, access)
            .map_err(store_error)?;
        let revision = match read_state_optional(&resource.state_path)? {
            Some(state) if state_matches_spec(&state, &resource.spec) => Some(state.revision),
            Some(_) => {
                return Err(invalid(
                    "host-resource marker belongs to another qualification",
                ));
            }
            None => None,
        };
        let evidence = ResourceAdmissionEvidence::new_with_revision_observation(
            access.resource.clone(),
            Some(self.assignment.incarnation.clone()),
            revision.map_or(
                ResourceRevisionObservation::Absent,
                ResourceRevisionObservation::Present,
            ),
            bool_value(revision.is_some())?,
        );
        Ok(CatalogReservation::new(
            NativeHostResourceHandle {
                resource,
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
            return Err(invalid(
                "host-resource release does not match its reservation",
            ));
        }
        handle.reservation.release().map_err(store_error)
    }
}

/// Executes all five host-resource contracts through one closed typed boundary.
pub(crate) struct NativeHostResourceAdapter {
    assignment: ProviderAssignment,
    kind: NativeHostResourceKind,
    platform: NativePlatformTools,
}

impl NativeHostResourceAdapter {
    pub(crate) fn new(
        package: &VerifiedAbilityPackage,
        assignment: ProviderAssignment,
        qualification: &NativeResourceQualification,
        kind: NativeHostResourceKind,
    ) -> Result<Self, io::Error> {
        preflight_native_host_resource(package, &assignment, qualification, kind)
            .map_err(store_error)?;
        authenticate_native_executor(
            &assignment.implementation.artifact,
            kind.entry_point(),
            kind.label(),
        )?;
        let platform = NativePlatformTools::authenticate(&assignment.implementation.artifact)?;
        Ok(Self {
            assignment,
            kind,
            platform,
        })
    }
}

/// Reconstructs one durable host request with its fresh physical reservation.
#[derive(Clone, Debug)]
pub(crate) struct NativeHostRequest {
    durable: DurableHostRequest,
    resource: QualifiedHostResource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableHostRequest {
    schema: String,
    kind: HostRequestKind,
    method: String,
    operation: ScopedOperationKey,
    resource: ResourceId,
    revision: RevisionId,
    inputs: AbilityValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retained_qualification: Option<NativeResourceQualification>,
    dependencies: Vec<NativeDependencyBinding>,
    platform: NativePlatformTools,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_binding: Option<StorageBinding>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum HostRequestKind {
    Credential,
    Endpoint,
    Storage,
    NetworkPolicy,
    Postgresql,
}

impl From<NativeHostResourceKind> for HostRequestKind {
    fn from(value: NativeHostResourceKind) -> Self {
        match value {
            NativeHostResourceKind::Credential => Self::Credential,
            NativeHostResourceKind::Endpoint => Self::Endpoint,
            NativeHostResourceKind::Storage => Self::Storage,
            NativeHostResourceKind::NetworkPolicy => Self::NetworkPolicy,
            NativeHostResourceKind::Postgresql => Self::Postgresql,
        }
    }
}

/// Carries one exact closed result and its typed output ports.
#[derive(Clone, Debug)]
pub(crate) struct NativeHostRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for NativeHostRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for NativeHostRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

impl TrustedAdapter for NativeHostResourceAdapter {
    type Request = NativeHostRequest;
    type Completion = NativeHostRecord;
    type Observation = NativeHostRecord;
    type Handle = NativeHostResourceHandle;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        implementation: &ProviderImplementationReference,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> bool {
        implementation == &self.assignment.implementation
            && method.interface == self.assignment.interface
            && method_supported(self.kind, method.method.as_str(), purpose)
    }

    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        require_operation_kind(operation, self.kind)?;
        if operation.interface != self.assignment.interface {
            return Err(invalid("host-resource operation uses another interface"));
        }
        let [resource] = resources else {
            return Err(invalid(
                "host-resource operation requires exactly one resource",
            ));
        };
        if resource.resource() != &operation.target.resource
            || NativeHostResourceKind::from_qualification(
                &resource.native().resource.spec.qualification,
            ) != Some(self.kind)
        {
            return Err(invalid(
                "host-resource handle differs from the operation target",
            ));
        }
        validate_inputs(
            self.kind,
            operation.method.as_str(),
            inputs,
            &resource.native().resource.spec.qualification,
            resource.native().resource.spec.revision,
        )?;
        if self.kind == NativeHostResourceKind::Credential && operation.method.as_str() == "deliver"
        {
            let input: CredentialInput = decode_input(inputs, "credential")?;
            validate_delivery_before_intent(&resource.native().resource, &input)?;
        }
        let dependencies = resource
            .native()
            .resource
            .spec
            .dependencies
            .get(&operation.key)
            .cloned()
            .unwrap_or_default();
        let storage_binding = resource.native().resource.spec.storage_binding.clone();
        if matches!(self.kind, NativeHostResourceKind::Storage) && storage_binding.is_none()
            || self.kind == NativeHostResourceKind::Postgresql
                && operation.method.as_str() == "materialize"
                && storage_binding.is_none()
        {
            return Err(invalid(
                "host-resource catalog has no reserved storage slot",
            ));
        }
        if self.kind == NativeHostResourceKind::Postgresql
            && operation.method.as_str() == "materialize"
        {
            reject_postgresql_identity_change_before_intent(
                &resource.native().resource,
                inputs,
                storage_binding.as_ref().ok_or_else(|| {
                    invalid("PostgreSQL materialization has no reserved storage slot")
                })?,
            )?;
        }
        authenticate_dependency_bindings(
            self.kind,
            operation.method.as_str(),
            inputs,
            &dependencies,
            storage_binding.as_ref(),
        )?;
        ability_value(serde_json::to_value(DurableHostRequest {
            schema: "aos.ability.native-host-request/v1".to_string(),
            kind: self.kind.into(),
            method: operation.method.as_str().to_string(),
            operation: operation.key.clone(),
            resource: operation.target.resource.clone(),
            revision: resource.native().resource.spec.revision,
            inputs: inputs.clone(),
            retained_qualification: resource
                .native()
                .resource
                .spec
                .retained_qualification
                .clone(),
            dependencies,
            platform: self.platform.clone(),
            storage_binding,
        })?)
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        let request: DurableHostRequest = serde_json::from_value(durable.as_json().clone())
            .map_err(|error| invalid(format!("invalid durable host-resource request: {error}")))?;
        let [resource] = resources else {
            return Err(invalid(
                "host-resource recovery requires exactly one resource",
            ));
        };
        if request.schema != "aos.ability.native-host-request/v1"
            || request.kind != self.kind.into()
            || request.resource != *resource.resource()
            || request.revision != resource.native().resource.spec.revision
            || request.dependencies
                != resource
                    .native()
                    .resource
                    .spec
                    .dependencies
                    .get(&request.operation)
                    .cloned()
                    .unwrap_or_default()
            || request.retained_qualification
                != resource.native().resource.spec.retained_qualification
            || request.platform != self.platform
        {
            return Err(invalid(
                "durable host-resource request differs from fresh acquisition",
            ));
        }
        validate_inputs(
            self.kind,
            &request.method,
            &request.inputs,
            &resource.native().resource.spec.qualification,
            resource.native().resource.spec.revision,
        )?;
        let expected_storage_binding = resource.native().resource.spec.storage_binding.clone();
        if request.storage_binding != expected_storage_binding {
            return Err(invalid(
                "durable principal-slot binding differs from fresh authority",
            ));
        }
        Ok(NativeHostRequest {
            durable: request,
            resource: resource.native().resource.clone(),
        })
    }

    fn execute(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        if control.is_cancelled() {
            return EffectDisposition::RejectedBeforeEffect(rejection_record(request));
        }
        match execute_request(request, control) {
            Ok(record) => EffectDisposition::Completed(record),
            Err(_) if request_is_read_only(request) => {
                EffectDisposition::RejectedBeforeEffect(rejection_record(request))
            }
            // Request validation is complete before the intent is admitted.
            // Any execution failure may follow a partial external effect.
            Err(_) => EffectDisposition::Indeterminate(rejection_record(request)),
        }
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        match reconcile_request(request, control) {
            Ok(Some(record)) => ReconcileDisposition::Completed(record),
            Ok(None) => ReconcileDisposition::SafeToRetry(rejection_record(request)),
            Err(_) if request_is_read_only(request) => {
                ReconcileDisposition::RejectedBeforeEffect(rejection_record(request))
            }
            Err(_) => ReconcileDisposition::InterventionRequired(rejection_record(request)),
        }
    }

    fn cancel(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        match self.reconcile(request, control) {
            ReconcileDisposition::Completed(record) => CancellationDisposition::Completed(record),
            ReconcileDisposition::SafeToRetry(record)
            | ReconcileDisposition::RejectedBeforeEffect(record) => {
                CancellationDisposition::RejectedBeforeEffect(record)
            }
            ReconcileDisposition::StillIndeterminate(record)
            | ReconcileDisposition::InterventionRequired(record) => {
                CancellationDisposition::Indeterminate(record)
            }
        }
    }
}

fn physical_identity(
    spec: &NativeHostResourceSpec,
) -> Result<(&'static str, String, PathBuf), io::Error> {
    let resource_key = resource_key(&spec.resource)?;
    Ok(match &spec.qualification {
        NativeResourceQualification::CredentialDelivery { .. } => {
            let path = Path::new(CREDENTIAL_ROOT).join(format!("{resource_key}.view"));
            (
                "credential-view",
                path_text(&path)?,
                Path::new(CREDENTIAL_ROOT).join(format!(".{resource_key}.json")),
            )
        }
        NativeResourceQualification::NetworkEndpoint { address, port, .. } => {
            let (class, object) = if *port == 0 {
                ("network-endpoint-allocation", resource_key.clone())
            } else {
                ("network-endpoint", format!("{address}:{port}"))
            };
            (
                class,
                object,
                Path::new(ENDPOINT_ROOT).join(format!("{resource_key}.json")),
            )
        }
        NativeResourceQualification::HostStorage { .. } => {
            let path = storage_path(&spec.resource)?;
            (
                "host-storage",
                path_text(&path)?,
                Path::new(STORAGE_ROOT).join(format!(".{resource_key}.json")),
            )
        }
        NativeResourceQualification::HostNetworkPolicy { policy } => (
            "host-network-policy",
            policy.clone(),
            Path::new(POLICY_ROOT).join(format!("{resource_key}.json")),
        ),
        NativeResourceQualification::Postgresql { .. } => {
            let path = Path::new(POSTGRESQL_ROOT).join(&resource_key);
            (
                "postgresql-cluster",
                path_text(&path)?,
                Path::new(POSTGRESQL_ROOT).join(format!(".{resource_key}.json")),
            )
        }
        _ => return Err(invalid("qualification is not a native host resource")),
    })
}

fn decode_input<T>(value: &AbilityValue, label: &str) -> Result<T, io::Error>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(value.as_json().clone())
        .map_err(|error| invalid(format!("invalid {label} request: {error}")))
}

fn record(
    result: serde_json::Value,
    outputs: BTreeMap<LocalKey, AbilityValue>,
) -> Result<NativeHostRecord, io::Error> {
    Ok(NativeHostRecord {
        durable: ability_value(result)?,
        outputs,
    })
}

fn ability_value(value: serde_json::Value) -> Result<AbilityValue, io::Error> {
    AbilityValue::new(value).map_err(store_error)
}

fn bool_value(value: bool) -> Result<AbilityValue, io::Error> {
    ability_value(serde_json::Value::Bool(value))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn store_error(error: impl std::fmt::Display) -> io::Error {
    invalid(error.to_string())
}
