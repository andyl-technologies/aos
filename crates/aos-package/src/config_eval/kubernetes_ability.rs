//! Trusted Kubernetes object admission and API convergence.
//!
//! Native orchestration supplies canonical object JSON, an exact GVK and
//! object identity, an authenticated kubectl artifact, and a protected
//! kubeconfig. Checked operations carry only the closed Boolean terminal
//! parameter. The adapter invokes kubectl with an empty environment and
//! reconciles every mutation through a fresh API observation.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use aos_ability_model::{
    AbilityActivationMode, AbilityValue, ArtifactReference, ExecutionStage, IncarnationId,
    InterfaceKey, InterfaceName, KubernetesObjectAction, LocalKey, MethodReference, Operation,
    OperationFamily, ProviderAssignment, ProviderImplementationReference, ResourceAccess,
    ResourceId, RevisionId,
};
use aos_ability_plan::{RuntimeResourceHealth, RuntimeResourceState};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CatalogReservation,
    EffectDisposition, InvocationPurpose, ReconcileDisposition, ReservationContext,
    ResourceAdmissionEvidence, ResourceHandle, ResourceRevisionObservation, RuntimeControl,
    TrustedAdapter, TrustedResourceCatalog,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::ability_package::VerifiedAbilityPackage;
use crate::config_eval::ability_store::inventory::require_machine_global_host_collision_domain;
use crate::config_eval::ability_store::{
    GenerationAbilityStoreError, NativeQualifiedResource, NativeResourceInventory,
    NativeResourceReservation,
};
pub(crate) use crate::config_eval::kubernetes_transport::{
    DeferredKubernetesApiCapability, KubernetesApiCapability,
};
#[cfg(test)]
use crate::config_eval::kubernetes_transport::{
    ExecutionDeadline, KUBECONFIG_CAPTURE_ARGUMENTS, KubeconfigSnapshot, child_process_group,
    exchange_kubectl_io, terminate_and_reap, validate_captured_kubeconfig,
};
use crate::config_eval::kubernetes_transport::{FixedBudgetControl, KubernetesInvocation};
use crate::config_eval::native_ability_fs::authenticate_native_executor;
use crate::config_eval::native_resource_map::kubernetes_resource_owner;

const INTERFACE_DESCRIPTOR: &str =
    "sha256:bbced9c501c3c41ab4b5f2a70a2945bde2128ef0a37ad900f6d9f1e2f110963e";
const ENTRY_POINT: &str = "libexec/aos-kubernetes-object-handler-v1";
const REQUEST_SCHEMA: &str = "aos.ability.kubernetes-object-request/v2";
const REQUEST_SCHEMA_V3: &str = "aos.ability.kubernetes-object-request/v3";
const REVISION_ANNOTATION: &str = "aos.andyl.com/object-revision";
const OWNER_ANNOTATION: &str = "aos.andyl.com/resource-owner";

/// Binds one logical resource to an exact Kubernetes API object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesObjectResourceSpec {
    /// Names the provider-owned logical resource.
    pub resource: ResourceId,
    /// Names the terminal handler selected for this logical owner.
    pub handler_provider: aos_ability_model::InstanceId,
    /// Pins the exact authenticated kubectl artifact.
    pub kubectl: ArtifactReference,
    /// Names the protected root-owned kubeconfig.
    pub kubeconfig: PathBuf,
    /// Names the exact Kubernetes API version.
    pub api_version: String,
    /// Names the exact Kubernetes kind.
    pub kind: String,
    /// Names the namespace, or is absent for a cluster-scoped object.
    pub namespace: Option<String>,
    /// Names the exact object within its scope.
    pub name: String,
    /// Carries the canonical integer-only JSON object.
    pub object_json: Vec<u8>,
    /// Gives the revision expected before mutation.
    pub current_revision: Option<RevisionId>,
    /// Carries the exact authenticated current object when one is retained.
    pub current_object_json: Option<Vec<u8>>,
    /// Gives the revision assigned to the desired object.
    pub desired_revision: Option<RevisionId>,
}

#[derive(Clone, Debug)]
struct QualifiedKubernetesObject {
    spec: KubernetesObjectResourceSpec,
    capability: KubernetesApiCapability,
    cluster_incarnation: IncarnationId,
    object_digest: Sha256Digest,
    qualified: NativeQualifiedResource,
}

#[derive(Debug)]
enum KubernetesExecutionError {
    BeforeEffect,
    AfterEffect,
}

/// A fresh lock-bound handle for one Kubernetes object.
#[derive(Debug)]
pub struct KubernetesObjectResourceHandle {
    resource: QualifiedKubernetesObject,
    action: KubernetesObjectAction,
    owned_divergence: bool,
    converged_owned_desired: bool,
    reservation: NativeResourceReservation,
}

/// Resolves logical resources to exact protected Kubernetes capabilities.
pub struct KubernetesObjectResourceCatalog {
    assignment: ProviderAssignment,
    inventory: NativeResourceInventory,
    resources: BTreeMap<ResourceId, QualifiedKubernetesObject>,
}

impl KubernetesObjectResourceCatalog {
    /// Constructs a root-owned host catalog from authenticated object specifications.
    ///
    /// # Errors
    ///
    /// Returns an error for another execution stage or owner, duplicate logical
    /// or physical objects, unsafe kubeconfigs, invalid canonical object JSON,
    /// or kubectl artifacts outside the mapped package.
    pub fn new(
        package: &VerifiedAbilityPackage,
        assignment: ProviderAssignment,
        inventory: NativeResourceInventory,
        trusted_owner: u32,
        resources: impl IntoIterator<Item = KubernetesObjectResourceSpec>,
    ) -> Result<Self, io::Error> {
        if trusted_owner != 0 || assignment.provider.environment.stage != ExecutionStage::Host {
            return Err(invalid_data(
                "Kubernetes object effects support only the root-owned host execution view",
            ));
        }
        require_machine_global_host_collision_domain()?;
        preflight_native_kubernetes(package, &assignment)?;

        let mut physical_objects = BTreeSet::new();
        let mut indexed = BTreeMap::new();
        for spec in resources {
            if spec.handler_provider != assignment.provider {
                return Err(invalid_data(
                    "Kubernetes object resource belongs to another provider",
                ));
            }
            if !package.artifacts().contains(&spec.kubectl) {
                return Err(invalid_data(
                    "kubectl artifact is outside the authenticated owner package",
                ));
            }
            validate_object_spec(&spec)?;
            let capability =
                KubernetesApiCapability::new(package, &spec.kubectl, &spec.kubeconfig)?;
            let identity = format!(
                "cluster={};{}",
                assignment.incarnation.as_str(),
                canonical_identity(&spec)
            );
            if !physical_objects.insert(identity.clone()) {
                return Err(invalid_data(
                    "distinct Kubernetes resources share one API object",
                ));
            }
            let object_digest = Sha256Digest::of_bytes(&spec.object_json);
            let qualified =
                NativeQualifiedResource::kubernetes_object(spec.resource.clone(), &identity)
                    .map_err(store_error)?;
            let resource = spec.resource.clone();
            if indexed
                .insert(
                    resource,
                    QualifiedKubernetesObject {
                        spec,
                        capability,
                        cluster_incarnation: assignment.incarnation.clone(),
                        object_digest,
                        qualified,
                    },
                )
                .is_some()
            {
                return Err(invalid_data(
                    "Kubernetes catalog contains a duplicate logical resource",
                ));
            }
        }
        Ok(Self {
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
            .map(|entry| entry.qualified.clone())
    }

    /// Classifies an owned live object while rejecting unavailable or foreign evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when the resource is absent from the catalog, the
    /// bounded API observation fails, or its ownership evidence is foreign.
    pub(crate) fn classify_runtime_revision(
        &self,
        resource: &ResourceId,
    ) -> Result<(NativeQualifiedResource, RuntimeResourceState), io::Error> {
        let resource = self
            .resources
            .get(resource)
            .ok_or_else(|| invalid_data("Kubernetes runtime resource is not cataloged"))?;
        let control = FixedBudgetControl::new(30_000);
        let observation = observe_object(resource, &control)?;
        let revision = classify_owned_revision(&observation)?;
        Ok((resource.qualified.clone(), revision))
    }
}

impl TrustedResourceCatalog for KubernetesObjectResourceCatalog {
    type Handle = KubernetesObjectResourceHandle;
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
        {
            return Err(invalid_data(
                "Kubernetes provider assignment is absent or stale",
            ));
        }
        if operation.target.resource != access.resource {
            return Err(invalid_data(
                "Kubernetes access does not target the operation resource",
            ));
        }
        let context = ReservationContext {
            expected_provider: Some(&self.assignment),
            ..context
        };
        let resource = self
            .resources
            .get(&access.resource)
            .ok_or_else(|| invalid_data("Kubernetes object is outside the authorized catalog"))?
            .clone();
        let action = action_for(operation)?;
        validate_action_spec(action, &resource.spec)?;
        let reservation = self
            .inventory
            .reserve(&resource.qualified, context, operation, access)
            .map_err(store_error)?;
        let control = FixedBudgetControl::new(context.recovery_remaining_millis);
        let observation = observe_object(&resource, &control)?;
        let state = classify_owned_revision(&observation)?;
        let converged_owned_desired = owned_desired_converged(&resource.spec, &observation);
        let (revision, owned_divergence) = match state {
            RuntimeResourceState::Absent => (ResourceRevisionObservation::Absent, false),
            RuntimeResourceState::Present {
                revision,
                health: RuntimeResourceHealth::Healthy,
            } => (ResourceRevisionObservation::Present(revision), false),
            RuntimeResourceState::Present {
                revision,
                health: RuntimeResourceHealth::Divergent,
            } => {
                if resource.spec.current_revision != Some(revision) {
                    return Err(invalid_data(
                        "owned Kubernetes divergence uses another current revision",
                    ));
                }
                (ResourceRevisionObservation::Unknown, true)
            }
            RuntimeResourceState::Present {
                health: RuntimeResourceHealth::Stopped,
                ..
            } => {
                return Err(invalid_data(
                    "Kubernetes object cannot carry stopped runtime health",
                ));
            }
        };
        let evidence = ResourceAdmissionEvidence::new_with_revision_observation(
            access.resource.clone(),
            Some(self.assignment.incarnation.clone()),
            revision,
            record_value(&observation)?,
        );
        Ok(CatalogReservation::new(
            KubernetesObjectResourceHandle {
                resource,
                action,
                owned_divergence,
                converged_owned_desired,
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
                "Kubernetes release does not match its native reservation",
            ));
        }
        handle.reservation.release().map_err(store_error)
    }
}

/// Durable Kubernetes request reconstructed with a fresh native handle.
#[derive(Clone, Debug)]
pub struct KubernetesObjectRequest {
    durable: KubernetesDurableRequest,
    resource: QualifiedKubernetesObject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct KubernetesDurableRequest {
    schema: String,
    action: KubernetesObjectAction,
    resource: ResourceId,
    api_version: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    object_digest: Sha256Digest,
    current_revision: Option<RevisionId>,
    desired_revision: Option<RevisionId>,
    kubectl: ArtifactReference,
    kubeconfig_source: String,
    kubeconfig_digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "is_false")]
    owned_divergence: bool,
}

const fn is_false(value: &bool) -> bool {
    !*value
}

/// Completion or observation evidence returned from the Kubernetes API.
#[derive(Clone, Debug)]
pub struct KubernetesObjectRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for KubernetesObjectRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for KubernetesObjectRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

/// Executes authenticated Kubernetes object methods through exact kubectl.
pub struct NativeKubernetesObjectAdapter {
    assignment: ProviderAssignment,
}

impl NativeKubernetesObjectAdapter {
    /// Constructs the adapter from one exact built-in terminal assignment.
    ///
    /// # Errors
    ///
    /// Returns an error unless the package and assignment resolve the exact
    /// Kubernetes interface, handler, artifact, and native entry point.
    pub fn new(
        package: &VerifiedAbilityPackage,
        assignment: ProviderAssignment,
    ) -> Result<Self, io::Error> {
        preflight_native_kubernetes(package, &assignment)?;
        authenticate_native_executor(
            &assignment.implementation.artifact,
            ENTRY_POINT,
            "Kubernetes object",
        )?;
        Ok(Self { assignment })
    }
}

impl TrustedAdapter for NativeKubernetesObjectAdapter {
    type Request = KubernetesObjectRequest;
    type Completion = KubernetesObjectRecord;
    type Observation = KubernetesObjectRecord;
    type Handle = KubernetesObjectResourceHandle;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        implementation: &ProviderImplementationReference,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> bool {
        implementation == &self.assignment.implementation
            && method.interface == self.assignment.interface
            && matches!(
                purpose,
                InvocationPurpose::Effect
                    | InvocationPurpose::Reconcile
                    | InvocationPurpose::Cancel
            )
            && matches!(method.method.as_str(), "apply" | "delete" | "observe")
    }

    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        if inputs.as_json() != &serde_json::Value::Bool(true) {
            return Err(invalid_data(
                "Kubernetes terminal method requires the closed Boolean input true",
            ));
        }
        if operation.interface != self.assignment.interface {
            return Err(invalid_data("Kubernetes operation uses another interface"));
        }
        let action = action_for(operation)?;
        let [resource] = resources else {
            return Err(invalid_data(
                "Kubernetes operation requires exactly one resource",
            ));
        };
        if resource.resource() != &operation.target.resource || resource.native().action != action {
            return Err(invalid_data(
                "Kubernetes handle does not match the operation target and family",
            ));
        }
        encode_request(durable_request(
            action,
            &resource.native().resource,
            resource.native().owned_divergence,
        )?)
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        let request: KubernetesDurableRequest = serde_json::from_value(durable.as_json().clone())
            .map_err(|error| {
            invalid_data(format!("invalid durable Kubernetes request: {error}"))
        })?;
        if !matches!(
            (request.schema.as_str(), request.owned_divergence),
            (REQUEST_SCHEMA, false) | (REQUEST_SCHEMA_V3, true)
        ) {
            return Err(invalid_data(
                "unsupported durable Kubernetes request schema",
            ));
        }
        let [resource] = resources else {
            return Err(invalid_data(
                "Kubernetes recovery requires exactly one resource",
            ));
        };
        if !recovery_divergence_matches(
            &request,
            resource.native().owned_divergence,
            resource.native().converged_owned_desired,
        ) {
            return Err(invalid_data(
                "durable Kubernetes divergence differs from fresh ownership evidence",
            ));
        }
        if request
            != durable_request(
                resource.native().action,
                &resource.native().resource,
                request.owned_divergence,
            )?
        {
            return Err(invalid_data(
                "durable Kubernetes request disagrees with fresh acquisition",
            ));
        }
        Ok(KubernetesObjectRequest {
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
            return EffectDisposition::RejectedBeforeEffect(failure_record());
        }
        let result = match request.durable.action {
            KubernetesObjectAction::Apply => mutate_object(
                &request.resource,
                "apply",
                request.durable.owned_divergence,
                control,
            )
            .and_then(|observation| {
                record(&observation)
                    .map(|record| (observation, record))
                    .map_err(|_| KubernetesExecutionError::AfterEffect)
            }),
            KubernetesObjectAction::Delete => mutate_object(
                &request.resource,
                "delete",
                request.durable.owned_divergence,
                control,
            )
            .and_then(|observation| {
                record(&observation)
                    .map(|record| (observation, record))
                    .map_err(|_| KubernetesExecutionError::AfterEffect)
            }),
            KubernetesObjectAction::Observe => observe_object(&request.resource, control)
                .map_err(|_| KubernetesExecutionError::BeforeEffect)
                .and_then(|observation| {
                    record(&observation)
                        .map(|record| (observation, record))
                        .map_err(|_| KubernetesExecutionError::BeforeEffect)
                }),
        };
        match result {
            Ok((observation, record)) if operation_completed(&request.durable, &observation) => {
                EffectDisposition::Completed(record)
            }
            Ok((_, record)) => EffectDisposition::Indeterminate(record),
            Err(KubernetesExecutionError::BeforeEffect) => {
                EffectDisposition::RejectedBeforeEffect(failure_record())
            }
            Err(KubernetesExecutionError::AfterEffect) => {
                EffectDisposition::Indeterminate(failure_record())
            }
        }
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        match observe_object(&request.resource, control) {
            Ok(observation) if operation_completed(&request.durable, &observation) => {
                ReconcileDisposition::Completed(
                    record(&observation).unwrap_or_else(|_| failure_record()),
                )
            }
            Ok(observation) if safe_to_retry(&request.durable, &observation) => {
                ReconcileDisposition::SafeToRetry(
                    record(&observation).unwrap_or_else(|_| failure_record()),
                )
            }
            Ok(observation) => ReconcileDisposition::InterventionRequired(
                record(&observation).unwrap_or_else(|_| failure_record()),
            ),
            Err(_) => ReconcileDisposition::StillIndeterminate(failure_record()),
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

fn recovery_divergence_matches(
    request: &KubernetesDurableRequest,
    acquired_owned_divergence: bool,
    converged_owned_desired: bool,
) -> bool {
    request.owned_divergence == acquired_owned_divergence
        || (request.action == KubernetesObjectAction::Apply
            && request.owned_divergence
            && !acquired_owned_divergence
            && converged_owned_desired)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct KubernetesObservation {
    schema: String,
    available: bool,
    content_matches: bool,
    #[serde(skip)]
    current_content_matches: bool,
    #[serde(skip)]
    live_object: Option<serde_json::Value>,
    exists: bool,
    object_revision: Option<String>,
    owned: bool,
    resource_version: Option<String>,
    uid: Option<String>,
}

fn mutate_object(
    resource: &QualifiedKubernetesObject,
    action: &str,
    owned_divergence: bool,
    control: &dyn RuntimeControl,
) -> Result<KubernetesObservation, KubernetesExecutionError> {
    let invocation = resource
        .capability
        .invocation(&resource.cluster_incarnation, control)
        .map_err(|_| KubernetesExecutionError::BeforeEffect)?;
    let admitted = observe_object_with(resource, &invocation)
        .map_err(|_| KubernetesExecutionError::BeforeEffect)?;
    match action {
        "apply" if resource.spec.current_revision.is_none() => {
            if !admitted.available || admitted.exists {
                return Err(KubernetesExecutionError::BeforeEffect);
            }
            invocation
                .run(
                    &["create".to_string(), "-f".to_string(), "-".to_string()],
                    Some(&resource.spec.object_json),
                )
                .map_err(|_| KubernetesExecutionError::AfterEffect)?;
        }
        "apply" => {
            require_owned_current(resource, &admitted, owned_divergence)
                .map_err(|_| KubernetesExecutionError::BeforeEffect)?;
            let replacement = replacement_object(resource, &admitted)
                .map_err(|_| KubernetesExecutionError::BeforeEffect)?;
            invocation
                .run(
                    &["replace".to_string(), "-f".to_string(), "-".to_string()],
                    Some(&replacement),
                )
                .map_err(|_| KubernetesExecutionError::AfterEffect)?;
        }
        "delete" if !admitted.exists && admitted.available => return Ok(admitted),
        "delete" => {
            require_owned_current(resource, &admitted, owned_divergence)
                .map_err(|_| KubernetesExecutionError::BeforeEffect)?;
            delete_with_preconditions(resource, &admitted, &invocation)?;
        }
        _ => {
            return Err(KubernetesExecutionError::BeforeEffect);
        }
    }
    invocation
        .require_incarnation(&resource.cluster_incarnation)
        .map_err(|_| KubernetesExecutionError::AfterEffect)?;
    let observation = observe_object_with(resource, &invocation)
        .map_err(|_| KubernetesExecutionError::AfterEffect)?;
    invocation
        .require_incarnation(&resource.cluster_incarnation)
        .map_err(|_| KubernetesExecutionError::AfterEffect)?;
    Ok(observation)
}

fn observe_object(
    resource: &QualifiedKubernetesObject,
    control: &dyn RuntimeControl,
) -> Result<KubernetesObservation, io::Error> {
    let invocation = resource
        .capability
        .invocation(&resource.cluster_incarnation, control)?;
    let observation = observe_object_with(resource, &invocation)?;
    invocation.require_incarnation(&resource.cluster_incarnation)?;
    Ok(observation)
}

fn observe_object_with(
    resource: &QualifiedKubernetesObject,
    invocation: &KubernetesInvocation<'_>,
) -> Result<KubernetesObservation, io::Error> {
    let output = invocation.run(
        &[
            "get".to_string(),
            "-f".to_string(),
            "-".to_string(),
            "--ignore-not-found=true".to_string(),
            "-o".to_string(),
            "json".to_string(),
        ],
        Some(&resource.spec.object_json),
    )?;
    if output.is_empty() {
        return Ok(absent_observation());
    }
    let object = aos_contract::canonical::parse_json(&output, "kubectl observation")
        .map_err(|error| invalid_data(error.to_string()))?;
    validate_observed_identity(&object, &resource.spec)?;
    let metadata = object
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_data("kubectl observation has no metadata object"))?;
    let field = |name: &str| {
        metadata
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let object_revision = metadata
        .get("annotations")
        .and_then(serde_json::Value::as_object)
        .and_then(|annotations| annotations.get(REVISION_ANNOTATION))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let expected_owner = kubernetes_resource_owner(&resource.spec.resource)
        .map_err(|error| invalid_data(error.to_string()))?
        .to_string();
    let owned = metadata
        .get("annotations")
        .and_then(serde_json::Value::as_object)
        .and_then(|annotations| annotations.get(OWNER_ANNOTATION))
        .and_then(serde_json::Value::as_str)
        == Some(expected_owner.as_str());
    let desired = aos_contract::canonical::parse_json(
        &resource.spec.object_json,
        "desired Kubernetes object",
    )
    .map_err(|error| invalid_data(error.to_string()))?;
    let current_content_matches = resource
        .spec
        .current_object_json
        .as_deref()
        .map(|current| {
            aos_contract::canonical::parse_json(current, "current Kubernetes object")
                .map(|current| desired_projection_matches(&current, &object))
        })
        .transpose()
        .map_err(|error| invalid_data(error.to_string()))?
        .unwrap_or(false);
    let content_matches = resource
        .spec
        .current_object_json
        .as_deref()
        .map(|current| {
            aos_contract::canonical::parse_json(current, "current Kubernetes object")
                .map(|current| converged_projection_matches(&current, &desired, &object))
        })
        .transpose()
        .map_err(|error| invalid_data(error.to_string()))?
        .unwrap_or_else(|| desired_projection_matches(&desired, &object));
    let resource_version = field("resourceVersion");
    let uid = field("uid");
    Ok(KubernetesObservation {
        schema: aos_ability_model::builtin::KUBERNETES_OBJECT_OBSERVATION_SCHEMA.to_string(),
        available: true,
        content_matches,
        current_content_matches,
        live_object: Some(object),
        exists: true,
        object_revision,
        owned,
        resource_version,
        uid,
    })
}

fn require_owned_current(
    resource: &QualifiedKubernetesObject,
    observation: &KubernetesObservation,
    owned_divergence: bool,
) -> Result<(), io::Error> {
    let expected_revision = resource
        .spec
        .current_revision
        .ok_or_else(|| invalid_data("Kubernetes mutation has no expected current revision"))?
        .0
        .to_string();
    if !observation.available
        || !observation.exists
        || !observation.owned
        || !(observation.current_content_matches || owned_divergence)
        || observation.object_revision.as_deref() != Some(&expected_revision)
        || observation.uid.as_deref().is_none_or(str::is_empty)
        || observation
            .resource_version
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(invalid_data(
            "Kubernetes mutation requires the exact owned current object",
        ));
    }
    Ok(())
}

fn replacement_object(
    resource: &QualifiedKubernetesObject,
    observation: &KubernetesObservation,
) -> Result<Vec<u8>, io::Error> {
    let current = resource
        .spec
        .current_object_json
        .as_deref()
        .ok_or_else(|| invalid_data("Kubernetes replacement has no retained current object"))?;
    let current = aos_contract::canonical::parse_json(current, "current Kubernetes object")
        .map_err(|error| invalid_data(error.to_string()))?;
    let desired = aos_contract::canonical::parse_json(
        &resource.spec.object_json,
        "Kubernetes replacement object",
    )
    .map_err(|error| invalid_data(error.to_string()))?;
    replacement_object_from_live(&current, &desired, observation)
}

fn replacement_object_from_live(
    current: &serde_json::Value,
    desired: &serde_json::Value,
    observation: &KubernetesObservation,
) -> Result<Vec<u8>, io::Error> {
    let mut object = observation
        .live_object
        .clone()
        .ok_or_else(|| invalid_data("Kubernetes replacement has no live object"))?;
    if !desired_projection_matches(current, &object) {
        return Err(invalid_data(
            "live Kubernetes object disagrees with its retained current projection",
        ));
    }
    update_owned_projection(&mut object, current, desired)?;
    object
        .as_object_mut()
        .ok_or_else(|| invalid_data("Kubernetes replacement is not an object"))?
        .remove("status");
    let metadata = object
        .get_mut("metadata")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| invalid_data("Kubernetes replacement has no metadata object"))?;
    metadata.remove("managedFields");
    metadata.insert(
        "resourceVersion".to_string(),
        serde_json::Value::String(
            observation
                .resource_version
                .clone()
                .ok_or_else(|| invalid_data("Kubernetes replacement has no resource version"))?,
        ),
    );
    metadata.insert(
        "uid".to_string(),
        serde_json::Value::String(
            observation
                .uid
                .clone()
                .ok_or_else(|| invalid_data("Kubernetes replacement has no UID"))?,
        ),
    );
    aos_contract::canonical::canonical_json(&object)
        .map_err(|error| invalid_data(error.to_string()))
}

fn update_owned_projection(
    live: &mut serde_json::Value,
    current: &serde_json::Value,
    desired: &serde_json::Value,
) -> Result<(), io::Error> {
    match (live, current, desired) {
        (
            serde_json::Value::Object(live),
            serde_json::Value::Object(current),
            serde_json::Value::Object(desired),
        ) => {
            for removed in current.keys().filter(|key| !desired.contains_key(*key)) {
                if live
                    .get_mut(removed)
                    .is_some_and(|value| remove_owned_projection(value, &current[removed]))
                {
                    live.remove(removed);
                }
            }
            for (key, desired_value) in desired {
                match (live.get_mut(key), current.get(key)) {
                    (Some(live_value), Some(current_value)) => {
                        update_owned_projection(live_value, current_value, desired_value)?;
                    }
                    _ => {
                        live.insert(key.clone(), desired_value.clone());
                    }
                }
            }
            Ok(())
        }
        (
            serde_json::Value::Array(live),
            serde_json::Value::Array(current),
            serde_json::Value::Array(desired),
        ) => update_owned_array(live, current, desired),
        (live, _, desired) => {
            *live = desired.clone();
            Ok(())
        }
    }
}

fn remove_owned_projection(live: &mut serde_json::Value, current: &serde_json::Value) -> bool {
    let (serde_json::Value::Object(live), serde_json::Value::Object(current)) = (live, current)
    else {
        return true;
    };

    for (key, current_value) in current {
        if live
            .get_mut(key)
            .is_some_and(|value| remove_owned_projection(value, current_value))
        {
            live.remove(key);
        }
    }
    live.is_empty()
}

fn update_owned_array(
    live: &mut Vec<serde_json::Value>,
    current: &[serde_json::Value],
    desired: &[serde_json::Value],
) -> Result<(), io::Error> {
    if current == desired {
        return if array_projection_matches(current, live) {
            Ok(())
        } else {
            Err(invalid_data(
                "live Kubernetes atomic list disagrees with its retained projection",
            ))
        };
    }
    if live.as_slice() != current {
        return Err(invalid_data(
            "Kubernetes atomic list contains server-assigned fields and cannot be updated safely",
        ));
    }
    *live = desired.to_vec();
    Ok(())
}

fn delete_with_preconditions(
    resource: &QualifiedKubernetesObject,
    observation: &KubernetesObservation,
    invocation: &KubernetesInvocation<'_>,
) -> Result<(), KubernetesExecutionError> {
    let resource_url = discover_resource_url(resource, invocation)
        .map_err(|_| KubernetesExecutionError::BeforeEffect)?;
    let options =
        delete_options(observation).map_err(|_| KubernetesExecutionError::BeforeEffect)?;
    invocation
        .run(
            &[
                "delete".to_string(),
                "--raw".to_string(),
                resource_url,
                "-f".to_string(),
                "-".to_string(),
            ],
            Some(&options),
        )
        .map_err(|_| KubernetesExecutionError::AfterEffect)?;
    Ok(())
}

fn delete_options(observation: &KubernetesObservation) -> Result<Vec<u8>, io::Error> {
    let uid = observation
        .uid
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_data("Kubernetes delete has no UID precondition"))?;
    let resource_version = observation
        .resource_version
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_data("Kubernetes delete has no resource-version precondition"))?;
    let options = serde_json::json!({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {
            "resourceVersion": resource_version,
            "uid": uid,
        },
        "propagationPolicy": "Foreground",
    });
    aos_contract::canonical::canonical_json(&options)
        .map_err(|error| invalid_data(error.to_string()))
}

fn discover_resource_url(
    resource: &QualifiedKubernetesObject,
    invocation: &KubernetesInvocation<'_>,
) -> Result<String, io::Error> {
    let (discovery_path, expected_group_version) =
        if let Some((group, version)) = resource.spec.api_version.split_once('/') {
            (
                format!("/apis/{group}/{version}"),
                resource.spec.api_version.as_str(),
            )
        } else {
            (
                format!("/api/{}", resource.spec.api_version),
                resource.spec.api_version.as_str(),
            )
        };
    let output = invocation.run(
        &["get".to_string(), "--raw".to_string(), discovery_path],
        None,
    )?;
    let discovery = aos_contract::canonical::parse_json(&output, "Kubernetes API discovery")
        .map_err(|error| invalid_data(error.to_string()))?;
    if discovery
        .get("groupVersion")
        .and_then(serde_json::Value::as_str)
        != Some(expected_group_version)
    {
        return Err(invalid_data(
            "Kubernetes discovery returned another API group version",
        ));
    }
    let resources = discovery
        .get("resources")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid_data("Kubernetes discovery has no resource list"))?;
    let namespaced = resource.spec.namespace.is_some();
    let matches = resources
        .iter()
        .filter(|candidate| {
            candidate.get("kind").and_then(serde_json::Value::as_str)
                == Some(resource.spec.kind.as_str())
                && candidate
                    .get("namespaced")
                    .and_then(serde_json::Value::as_bool)
                    == Some(namespaced)
                && candidate
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| !name.contains('/'))
        })
        .collect::<Vec<_>>();
    let [mapping] = matches.as_slice() else {
        return Err(invalid_data(
            "Kubernetes kind does not resolve to one exact API resource",
        ));
    };
    let plural = mapping
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_data("Kubernetes API resource has no name"))?;
    let prefix = if let Some((group, version)) = resource.spec.api_version.split_once('/') {
        format!("/apis/{group}/{version}")
    } else {
        format!("/api/{}", resource.spec.api_version)
    };
    Ok(match &resource.spec.namespace {
        Some(namespace) => format!(
            "{prefix}/namespaces/{namespace}/{plural}/{}",
            resource.spec.name
        ),
        None => format!("{prefix}/{plural}/{}", resource.spec.name),
    })
}

fn validate_object_spec(spec: &KubernetesObjectResourceSpec) -> Result<(), io::Error> {
    if spec.desired_revision.is_some() && spec.object_json.is_empty() {
        return Err(invalid_data("desired Kubernetes object JSON is empty"));
    }
    let object = aos_contract::canonical::require_canonical(&spec.object_json, "Kubernetes object")
        .map_err(|error| invalid_data(error.to_string()))?;
    validate_observed_identity(&object, spec)?;
    reject_server_managed_fields(&object)?;
    let annotations = object
        .get("metadata")
        .and_then(|metadata| metadata.get("annotations"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_data("Kubernetes object has no metadata annotations"))?;
    let revision = annotations
        .get(REVISION_ANNOTATION)
        .and_then(serde_json::Value::as_str);
    let expected_revision = spec
        .desired_revision
        .or(spec.current_revision)
        .map(|revision| revision.0.to_string());
    if revision != expected_revision.as_deref() {
        return Err(invalid_data(
            "Kubernetes object revision annotation differs from desired revision",
        ));
    }
    let owner = annotations
        .get(OWNER_ANNOTATION)
        .and_then(serde_json::Value::as_str);
    let expected_owner = kubernetes_resource_owner(&spec.resource)
        .map_err(|error| invalid_data(error.to_string()))?
        .to_string();
    if owner != Some(expected_owner.as_str()) {
        return Err(invalid_data(
            "Kubernetes object owner annotation differs from its logical resource",
        ));
    }
    match (&spec.current_revision, &spec.current_object_json) {
        (Some(current_revision), Some(current_object_json)) => {
            let current = aos_contract::canonical::require_canonical(
                current_object_json,
                "retained Kubernetes object",
            )
            .map_err(|error| invalid_data(error.to_string()))?;
            validate_observed_identity(&current, spec)?;
            reject_server_managed_fields(&current)?;
            let annotations = current
                .get("metadata")
                .and_then(|metadata| metadata.get("annotations"))
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| {
                    invalid_data("retained Kubernetes object has no metadata annotations")
                })?;
            if annotations
                .get(REVISION_ANNOTATION)
                .and_then(serde_json::Value::as_str)
                != Some(current_revision.0.to_string().as_str())
                || annotations
                    .get(OWNER_ANNOTATION)
                    .and_then(serde_json::Value::as_str)
                    != Some(expected_owner.as_str())
            {
                return Err(invalid_data(
                    "retained Kubernetes object annotations differ from its revision or owner",
                ));
            }
        }
        (None, None) => {}
        _ => {
            return Err(invalid_data(
                "Kubernetes current revision and retained object must be present together",
            ));
        }
    }
    Ok(())
}

fn reject_server_managed_fields(object: &serde_json::Value) -> Result<(), io::Error> {
    if object.get("status").is_some() {
        return Err(invalid_data(
            "Kubernetes desired object contains the server-managed status field",
        ));
    }
    let metadata = object
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_data("Kubernetes object has no metadata object"))?;
    const SERVER_FIELDS: [&str; 8] = [
        "creationTimestamp",
        "deletionGracePeriodSeconds",
        "deletionTimestamp",
        "generation",
        "managedFields",
        "resourceVersion",
        "selfLink",
        "uid",
    ];
    if SERVER_FIELDS
        .iter()
        .any(|field| metadata.contains_key(*field))
    {
        return Err(invalid_data(
            "Kubernetes desired object contains server-managed metadata",
        ));
    }
    Ok(())
}

fn desired_projection_matches(desired: &serde_json::Value, observed: &serde_json::Value) -> bool {
    match (desired, observed) {
        (serde_json::Value::Object(desired), serde_json::Value::Object(observed)) => {
            desired.iter().all(|(key, value)| {
                observed
                    .get(key)
                    .is_some_and(|live| desired_projection_matches(value, live))
            })
        }
        (serde_json::Value::Array(desired), serde_json::Value::Array(observed)) => {
            array_projection_matches(desired, observed)
        }
        _ => desired == observed,
    }
}

fn converged_projection_matches(
    current: &serde_json::Value,
    desired: &serde_json::Value,
    observed: &serde_json::Value,
) -> bool {
    if let (
        serde_json::Value::Array(current),
        serde_json::Value::Array(desired),
        serde_json::Value::Array(observed),
    ) = (current, desired, observed)
    {
        // Lists are atomic without an authenticated schema. Unchanged lists may
        // retain server fields, while changed lists must converge exactly; a
        // default-extended changed list therefore requires intervention.
        return if current == desired {
            array_projection_matches(desired, observed)
        } else {
            desired == observed
        };
    }

    let (
        serde_json::Value::Object(current),
        serde_json::Value::Object(desired),
        serde_json::Value::Object(observed),
    ) = (current, desired, observed)
    else {
        return desired_projection_matches(desired, observed);
    };

    desired.iter().all(|(key, desired_value)| {
        observed.get(key).is_some_and(|observed_value| {
            current.get(key).map_or_else(
                || desired_projection_matches(desired_value, observed_value),
                |current_value| {
                    converged_projection_matches(current_value, desired_value, observed_value)
                },
            )
        })
    }) && current
        .iter()
        .filter(|(key, _)| !desired.contains_key(*key))
        .all(|(key, current_value)| removed_projection_matches(current_value, observed.get(key)))
}

fn removed_projection_matches(
    current: &serde_json::Value,
    observed: Option<&serde_json::Value>,
) -> bool {
    let Some(observed) = observed else {
        return true;
    };
    let (serde_json::Value::Object(current), serde_json::Value::Object(observed)) =
        (current, observed)
    else {
        return false;
    };

    current
        .iter()
        .all(|(key, current_value)| removed_projection_matches(current_value, observed.get(key)))
}

fn array_projection_matches(desired: &[serde_json::Value], observed: &[serde_json::Value]) -> bool {
    desired.len() == observed.len()
        && desired
            .iter()
            .zip(observed)
            .all(|(desired, observed)| desired_projection_matches(desired, observed))
}

fn validate_observed_identity(
    object: &serde_json::Value,
    spec: &KubernetesObjectResourceSpec,
) -> Result<(), io::Error> {
    let metadata = object
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_data("Kubernetes object has no metadata object"))?;
    if object.get("apiVersion").and_then(serde_json::Value::as_str)
        != Some(spec.api_version.as_str())
        || object.get("kind").and_then(serde_json::Value::as_str) != Some(spec.kind.as_str())
        || metadata.get("name").and_then(serde_json::Value::as_str) != Some(spec.name.as_str())
        || metadata
            .get("namespace")
            .and_then(serde_json::Value::as_str)
            != spec.namespace.as_deref()
        || metadata.get("generateName").is_some()
    {
        return Err(invalid_data(
            "Kubernetes API object identity differs from native qualification",
        ));
    }
    Ok(())
}

fn action_for(operation: &Operation) -> Result<KubernetesObjectAction, io::Error> {
    let OperationFamily::KubernetesObject { action } = operation.family else {
        return Err(invalid_data("unsupported Kubernetes operation family"));
    };
    let expected = match action {
        KubernetesObjectAction::Apply => "apply",
        KubernetesObjectAction::Observe => "observe",
        KubernetesObjectAction::Delete => "delete",
    };
    if operation.method.as_str() != expected {
        return Err(invalid_data(
            "Kubernetes method disagrees with operation family",
        ));
    }
    Ok(action)
}

fn validate_action_spec(
    action: KubernetesObjectAction,
    spec: &KubernetesObjectResourceSpec,
) -> Result<(), io::Error> {
    match action {
        KubernetesObjectAction::Apply | KubernetesObjectAction::Observe
            if spec.desired_revision.is_none() =>
        {
            Err(invalid_data(
                "Kubernetes desired operation has no desired revision",
            ))
        }
        KubernetesObjectAction::Delete if spec.desired_revision.is_some() => Err(invalid_data(
            "Kubernetes delete unexpectedly carries a desired revision",
        )),
        _ => Ok(()),
    }
}

fn durable_request(
    action: KubernetesObjectAction,
    resource: &QualifiedKubernetesObject,
    owned_divergence: bool,
) -> Result<KubernetesDurableRequest, io::Error> {
    validate_action_spec(action, &resource.spec)?;
    Ok(KubernetesDurableRequest {
        schema: if owned_divergence {
            REQUEST_SCHEMA_V3
        } else {
            REQUEST_SCHEMA
        }
        .to_string(),
        action,
        resource: resource.spec.resource.clone(),
        api_version: resource.spec.api_version.clone(),
        kind: resource.spec.kind.clone(),
        namespace: resource.spec.namespace.clone(),
        name: resource.spec.name.clone(),
        object_digest: resource.object_digest,
        current_revision: resource.spec.current_revision,
        desired_revision: resource.spec.desired_revision,
        kubectl: resource.spec.kubectl.clone(),
        kubeconfig_source: path_string(&resource.capability.kubeconfig_source)?,
        kubeconfig_digest: resource.capability.snapshot_digest()?,
        owned_divergence,
    })
}

fn encode_request(request: KubernetesDurableRequest) -> Result<AbilityValue, io::Error> {
    let value = serde_json::to_value(request)
        .map_err(|error| invalid_data(format!("encoding Kubernetes request: {error}")))?;
    AbilityValue::new(value)
        .map_err(|error| invalid_data(format!("Kubernetes request exceeds limits: {error}")))
}

fn operation_completed(
    request: &KubernetesDurableRequest,
    observation: &KubernetesObservation,
) -> bool {
    match request.action {
        KubernetesObjectAction::Apply => {
            observation.available
                && observation.exists
                && observation.owned
                && observation.content_matches
                && observation.object_revision.as_deref()
                    == request
                        .desired_revision
                        .map(|revision| revision.0.to_string())
                        .as_deref()
                && observation.uid.is_some()
                && observation.resource_version.is_some()
        }
        KubernetesObjectAction::Observe => observation.available,
        KubernetesObjectAction::Delete => observation.available && !observation.exists,
    }
}

fn owned_desired_converged(
    spec: &KubernetesObjectResourceSpec,
    observation: &KubernetesObservation,
) -> bool {
    observation.available
        && observation.exists
        && observation.owned
        && observation.content_matches
        && observation.object_revision.as_deref()
            == spec
                .desired_revision
                .map(|revision| revision.0.to_string())
                .as_deref()
        && observation
            .uid
            .as_deref()
            .is_some_and(|uid| !uid.is_empty())
        && observation
            .resource_version
            .as_deref()
            .is_some_and(|version| !version.is_empty())
}

fn safe_to_retry(request: &KubernetesDurableRequest, observation: &KubernetesObservation) -> bool {
    if !observation.available {
        return false;
    }
    if !observation.exists {
        return match request.action {
            KubernetesObjectAction::Apply => request.current_revision.is_none(),
            KubernetesObjectAction::Observe | KubernetesObjectAction::Delete => true,
        };
    }
    observation.owned
        && (observation.current_content_matches || request.owned_divergence)
        && observation.uid.is_some()
        && observation.resource_version.is_some()
        && observation.object_revision.as_deref()
            == request
                .current_revision
                .map(|revision| revision.0.to_string())
                .as_deref()
}

#[cfg(test)]
fn revision_observation(observation: &KubernetesObservation) -> ResourceRevisionObservation {
    if !observation.available {
        return ResourceRevisionObservation::Unknown;
    }
    if !observation.exists {
        return ResourceRevisionObservation::Absent;
    }
    if !observation.owned || !(observation.content_matches || observation.current_content_matches) {
        return ResourceRevisionObservation::Unknown;
    }
    observation
        .object_revision
        .as_deref()
        .and_then(|revision| Sha256Digest::parse(revision).ok())
        .map(|digest| ResourceRevisionObservation::Present(RevisionId(digest)))
        .unwrap_or(ResourceRevisionObservation::Unknown)
}

fn classify_owned_revision(
    observation: &KubernetesObservation,
) -> Result<RuntimeResourceState, io::Error> {
    if !observation.available {
        return Err(invalid_data("Kubernetes observation is unavailable"));
    }
    if !observation.exists {
        return Ok(RuntimeResourceState::Absent);
    }
    if !observation.owned {
        return Err(invalid_data("Kubernetes object ownership is foreign"));
    }
    let revision = observation
        .object_revision
        .as_deref()
        .ok_or_else(|| invalid_data("owned Kubernetes object has no revision annotation"))
        .and_then(|revision| {
            Sha256Digest::parse(revision)
                .map(RevisionId)
                .map_err(|error| invalid_data(error.to_string()))
        })?;
    if observation.content_matches || observation.current_content_matches {
        Ok(RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Healthy,
        })
    } else {
        Ok(RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Divergent,
        })
    }
}

fn record(observation: &KubernetesObservation) -> Result<KubernetesObjectRecord, io::Error> {
    let durable = record_value(observation)?;
    let output = LocalKey::new("observation").map_err(|error| invalid_data(error.to_string()))?;
    Ok(KubernetesObjectRecord {
        durable: durable.clone(),
        outputs: BTreeMap::from([(output, durable)]),
    })
}

fn record_value(observation: &KubernetesObservation) -> Result<AbilityValue, io::Error> {
    let value = serde_json::to_value(observation)
        .map_err(|error| invalid_data(format!("encoding Kubernetes observation: {error}")))?;
    AbilityValue::new(value)
        .map_err(|error| invalid_data(format!("Kubernetes observation exceeds limits: {error}")))
}

fn failure_record() -> KubernetesObjectRecord {
    record(&unavailable_observation()).unwrap_or_else(|_| KubernetesObjectRecord {
        durable: AbilityValue::new(serde_json::Value::Bool(false))
            .unwrap_or_else(|_| unreachable!("Boolean ability values are bounded")),
        outputs: BTreeMap::new(),
    })
}

fn absent_observation() -> KubernetesObservation {
    KubernetesObservation {
        schema: aos_ability_model::builtin::KUBERNETES_OBJECT_OBSERVATION_SCHEMA.to_string(),
        available: true,
        content_matches: false,
        current_content_matches: false,
        live_object: None,
        exists: false,
        object_revision: None,
        owned: false,
        resource_version: None,
        uid: None,
    }
}

fn unavailable_observation() -> KubernetesObservation {
    KubernetesObservation {
        schema: aos_ability_model::builtin::KUBERNETES_OBJECT_OBSERVATION_SCHEMA.to_string(),
        available: false,
        content_matches: false,
        current_content_matches: false,
        live_object: None,
        exists: false,
        object_revision: None,
        owned: false,
        resource_version: None,
        uid: None,
    }
}

fn canonical_identity(spec: &KubernetesObjectResourceSpec) -> String {
    format!(
        "apiVersion={};kind={};namespace={};name={}",
        spec.api_version,
        spec.kind,
        spec.namespace.as_deref().unwrap_or(""),
        spec.name
    )
}

pub(crate) fn preflight_native_kubernetes(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
) -> Result<(), io::Error> {
    if package.activation_mode() != AbilityActivationMode::StructuredEffects
        || assignment.interface != expected_interface()?
    {
        return Err(invalid_data(
            "Kubernetes adapter requires its exact structured-effects interface",
        ));
    }
    let handler_key = aos_ability_model::builtin::kubernetes_object_handler_key()
        .map_err(|error| invalid_data(error.to_string()))?;
    if assignment.implementation.handler.as_ref() != Some(&handler_key) {
        return Err(invalid_data(
            "Kubernetes assignment selects another terminal handler",
        ));
    }
    let verified = package
        .resolve_terminal_handler(assignment.implementation.descriptor, &handler_key)
        .ok_or_else(|| {
            invalid_data("authenticated package does not resolve the Kubernetes handler")
        })?;
    let expected = aos_ability_model::builtin::kubernetes_object_handler(
        assignment.implementation.artifact.clone(),
    )
    .map_err(|error| invalid_data(error.to_string()))?;
    if verified.provider().interface != assignment.interface
        || verified.provider().artifact != assignment.implementation.artifact
        || verified
            .provider()
            .descriptor_digest()
            .map_err(|error| invalid_data(error.to_string()))?
            != assignment.implementation.descriptor
        || verified.handler() != &expected
    {
        return Err(invalid_data(
            "authenticated Kubernetes provider linkage differs from the assignment",
        ));
    }
    Ok(())
}

fn expected_interface() -> Result<InterfaceKey, io::Error> {
    let interface = aos_ability_model::builtin::kubernetes_object_interface_key()
        .map_err(|error| invalid_data(error.to_string()))?;
    let descriptor = Sha256Digest::parse(INTERFACE_DESCRIPTOR)
        .map_err(|error| invalid_data(error.to_string()))?;
    if interface.descriptor != descriptor {
        return Err(invalid_data(
            "compiled Kubernetes interface descriptor changed unexpectedly",
        ));
    }
    Ok(InterfaceKey {
        name: InterfaceName::new(aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME)
            .map_err(|error| invalid_data(error.to_string()))?,
        abi: NonZeroU32::new(1).ok_or_else(|| invalid_data("invalid interface ABI"))?,
        descriptor,
    })
}

fn path_string(path: &Path) -> Result<String, io::Error> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| invalid_data("Kubernetes path is not UTF-8"))
}

fn store_error(error: GenerationAbilityStoreError) -> io::Error {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use aos_ability_model::{EnvironmentId, ExecutionStage, InstanceId};

    use super::*;

    #[test]
    fn desired_projection_detects_owned_field_drift() {
        let spec = test_spec(Some(revision("current")), Some(revision("desired")));
        let desired = parsed(&spec.object_json);
        let mut observed = desired.clone();
        observed["metadata"]["uid"] = serde_json::json!("server-uid");
        observed["metadata"]["resourceVersion"] = serde_json::json!("42");
        observed["status"] = serde_json::json!({"availableReplicas": 2});

        assert!(desired_projection_matches(&desired, &observed));

        observed["spec"]["replicas"] = serde_json::json!(3);
        assert!(!desired_projection_matches(&desired, &observed));
    }

    #[test]
    fn update_preserves_server_assigned_fields_inside_objects_and_lists() {
        let current = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "annotations": {"aos.andyl.com/object-revision": "current"},
                "name": "api",
                "namespace": "default"
            },
            "spec": {
                "ports": [{"name": "https", "port": 443}],
                "selector": {"app": "api"}
            }
        });
        let desired = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "annotations": {"aos.andyl.com/object-revision": "desired"},
                "name": "api",
                "namespace": "default"
            },
            "spec": {
                "ports": [{"name": "https", "port": 443}],
                "selector": {"app": "api-v2"}
            }
        });
        let live = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "annotations": {"aos.andyl.com/object-revision": "current"},
                "creationTimestamp": "2026-09-10T00:00:00Z",
                "managedFields": [{"manager": "kube-controller-manager"}],
                "name": "api",
                "namespace": "default",
                "resourceVersion": "42",
                "uid": "server-uid"
            },
            "spec": {
                "clusterIP": "10.43.0.10",
                "ports": [{
                    "name": "https",
                    "nodePort": 30443,
                    "port": 443,
                    "protocol": "TCP"
                }],
                "selector": {"app": "api"}
            },
            "status": {"loadBalancer": {}}
        });
        let mut observation = present_observation();
        observation.live_object = Some(live);

        let replacement = replacement_object_from_live(&current, &desired, &observation)
            .expect("owned projection overlays the live object");
        let replacement = parsed(&replacement);

        assert_eq!(replacement["spec"]["clusterIP"], "10.43.0.10");
        assert_eq!(replacement["spec"]["ports"][0]["nodePort"], 30443);
        assert_eq!(replacement["spec"]["ports"][0]["port"], 443);
        assert_eq!(replacement["spec"]["selector"]["app"], "api-v2");
        assert!(replacement.get("status").is_none());
        assert!(replacement["metadata"].get("managedFields").is_none());
        assert!(desired_projection_matches(&desired, &replacement));
    }

    #[test]
    fn update_removes_previously_owned_fields_and_preserves_unowned_fields() {
        let current = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "labels": {"keep": "old", "remove": "owned"},
                "name": "settings",
                "namespace": "default"
            },
            "data": {"keep": "old", "remove": "owned"}
        });
        let desired = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "labels": {"keep": "new"},
                "name": "settings",
                "namespace": "default"
            },
            "data": {"keep": "new"}
        });
        let live = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "annotations": {"injected": "preserved"},
                "labels": {
                    "injected": "preserved",
                    "keep": "old",
                    "remove": "owned"
                },
                "name": "settings",
                "namespace": "default",
                "resourceVersion": "42",
                "uid": "server-uid"
            },
            "data": {"injected": "preserved", "keep": "old", "remove": "owned"}
        });
        let mut observation = present_observation();
        observation.live_object = Some(live);

        let replacement = replacement_object_from_live(&current, &desired, &observation)
            .expect("three-way projection update succeeds");
        let replacement = parsed(&replacement);

        assert_eq!(replacement["data"]["keep"], "new");
        assert_eq!(replacement["data"]["injected"], "preserved");
        assert!(replacement["data"].get("remove").is_none());
        assert_eq!(replacement["metadata"]["labels"]["keep"], "new");
        assert_eq!(replacement["metadata"]["labels"]["injected"], "preserved");
        assert!(replacement["metadata"]["labels"].get("remove").is_none());
        assert_eq!(
            replacement["metadata"]["annotations"]["injected"],
            "preserved"
        );
    }

    #[test]
    fn omitted_parent_removes_owned_descendants_and_preserves_live_extensions() {
        let current = serde_json::json!({
            "metadata": {"labels": {"owned": "old"}}
        });
        let desired = serde_json::json!({"metadata": {}});
        let mut live = serde_json::json!({
            "metadata": {"labels": {"injected": "kept", "owned": "old"}}
        });

        update_owned_projection(&mut live, &current, &desired)
            .expect("nested owned projection can be removed");

        assert_eq!(
            live,
            serde_json::json!({"metadata": {"labels": {"injected": "kept"}}})
        );
        assert!(converged_projection_matches(&current, &desired, &live));
    }

    #[test]
    fn desired_revision_does_not_hide_a_restored_removed_field() {
        let current = serde_json::json!({
            "metadata": {
                "annotations": {(REVISION_ANNOTATION): "current"},
                "name": "settings"
            },
            "data": {"obsolete": "owned"}
        });
        let desired = serde_json::json!({
            "metadata": {
                "annotations": {(REVISION_ANNOTATION): "desired"},
                "name": "settings"
            },
            "data": {}
        });
        let restored = serde_json::json!({
            "metadata": {
                "annotations": {(REVISION_ANNOTATION): "desired"},
                "name": "settings",
                "resourceVersion": "43",
                "uid": "server-uid"
            },
            "data": {"obsolete": "owned"}
        });

        assert!(desired_projection_matches(&desired, &restored));
        assert!(!converged_projection_matches(&current, &desired, &restored));
    }

    #[test]
    fn atomic_list_update_keeps_order_significant_during_add_and_remove() {
        let current = serde_json::json!([
            {"name": "http", "port": 80},
            {"name": "obsolete", "port": 81}
        ]);
        let desired = serde_json::json!([
            {"name": "metrics", "port": 9090},
            {"name": "http", "port": 8080}
        ]);
        let mut live = current.clone();

        update_owned_projection(&mut live, &current, &desired)
            .expect("unextended atomic list can be replaced exactly");

        assert_eq!(
            live[0],
            serde_json::json!({"name": "metrics", "port": 9090})
        );
        assert_eq!(live[1], serde_json::json!({"name": "http", "port": 8080}));

        let reordered = serde_json::json!([
            {"name": "obsolete", "port": 81},
            {"name": "http", "port": 80}
        ]);
        assert!(!desired_projection_matches(&current, &reordered));
    }

    #[test]
    fn changed_atomic_list_with_server_fields_is_rejected() {
        let current = serde_json::json!([{"port": 80}]);
        let desired = serde_json::json!([{"port": 8080}]);
        let mut live = serde_json::json!([{"nodePort": 30080, "port": 80}]);

        assert!(update_owned_projection(&mut live, &current, &desired).is_err());
    }

    #[test]
    fn changed_atomic_list_requires_removed_entry_fields_to_stay_absent() {
        let current = serde_json::json!([{"name": "http", "obsolete": true, "port": 80}]);
        let desired = serde_json::json!([{"name": "http", "port": 80}]);
        let restored = serde_json::json!([{"name": "http", "obsolete": true, "port": 80}]);

        assert!(desired_projection_matches(&desired, &restored));
        assert!(!converged_projection_matches(&current, &desired, &restored));
        assert!(converged_projection_matches(&current, &desired, &desired));
    }

    #[test]
    fn cilium_and_longhorn_helm_chart_scalar_updates_preserve_live_extensions() {
        for (name, current_values, desired_values) in [
            (
                "cilium",
                r#"{"kubeProxyReplacement":true,"operator":{"replicas":1}}"#,
                r#"{"kubeProxyReplacement":true,"operator":{"replicas":2}}"#,
            ),
            (
                "longhorn",
                r#"{"defaultSettings":{"defaultReplicaCount":"3"},"persistence":{"defaultClassReplicaCount":3}}"#,
                r#"{"defaultSettings":{"defaultReplicaCount":"2"},"persistence":{"defaultClassReplicaCount":2}}"#,
            ),
        ] {
            let current = helm_chart(name, "current", current_values);
            let desired = helm_chart(name, "desired", desired_values);
            let mut live = current.clone();
            live["metadata"]["resourceVersion"] = serde_json::json!("42");
            live["metadata"]["uid"] = serde_json::json!(format!("{name}-uid"));
            live["spec"]["failurePolicy"] = serde_json::json!("reinstall");
            live["status"] = serde_json::json!({"jobName": format!("helm-install-{name}")});
            let mut observation = present_observation();
            observation.live_object = Some(live);

            let replacement = replacement_object_from_live(&current, &desired, &observation)
                .expect("HelmChart map and scalar update succeeds");
            let replacement = parsed(&replacement);

            assert_eq!(replacement["spec"]["valuesContent"], desired_values);
            assert_eq!(replacement["spec"]["failurePolicy"], "reinstall");
            assert!(replacement.get("status").is_none());
            assert!(desired_projection_matches(&desired, &replacement));
        }
    }

    fn helm_chart(name: &str, revision: &str, values_content: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "helm.cattle.io/v1",
            "kind": "HelmChart",
            "metadata": {
                "annotations": {"aos.andyl.com/object-revision": revision},
                "name": name,
                "namespace": "kube-system"
            },
            "spec": {
                "chart": name,
                "repo": if name == "cilium" {
                    "https://helm.cilium.io/"
                } else {
                    "https://charts.longhorn.io"
                },
                "targetNamespace": if name == "cilium" {
                    "kube-system"
                } else {
                    "longhorn-system"
                },
                "valuesContent": values_content,
                "version": "fixture-version"
            }
        })
    }

    #[test]
    fn retry_requires_the_exact_owned_current_object() {
        let spec = test_spec(Some(revision("current")), Some(revision("desired")));
        let request = test_request(&spec, KubernetesObjectAction::Apply);
        let mut observation = present_observation();
        observation.object_revision = Some(revision("current").0.to_string());
        observation.content_matches = false;
        observation.current_content_matches = true;

        assert!(safe_to_retry(&request, &observation));

        observation.owned = false;
        assert!(!safe_to_retry(&request, &observation));

        observation.owned = true;
        observation.current_content_matches = false;
        assert!(!safe_to_retry(&request, &observation));
    }

    #[test]
    fn divergent_repair_retry_retains_exact_ownership_guards() {
        let spec = test_spec(Some(revision("current")), Some(revision("desired")));
        let mut request = test_request(&spec, KubernetesObjectAction::Apply);
        request.schema = REQUEST_SCHEMA_V3.to_string();
        request.owned_divergence = true;
        let mut observation = present_observation();
        observation.object_revision = Some(revision("current").0.to_string());
        observation.content_matches = false;
        observation.current_content_matches = false;

        assert!(safe_to_retry(&request, &observation));

        observation.owned = false;
        assert!(!safe_to_retry(&request, &observation));

        observation.owned = true;
        observation.object_revision = Some(revision("foreign").0.to_string());
        assert!(!safe_to_retry(&request, &observation));

        observation.object_revision = Some(revision("current").0.to_string());
        observation.uid = None;
        assert!(!safe_to_retry(&request, &observation));
    }

    #[test]
    fn divergent_apply_recovers_after_the_desired_object_is_committed() {
        let spec = test_spec(Some(revision("current")), Some(revision("desired")));
        let mut durable = test_request(&spec, KubernetesObjectAction::Apply);
        durable.schema = REQUEST_SCHEMA_V3.to_string();
        durable.owned_divergence = true;
        let observation = present_observation();

        assert!(operation_completed(&durable, &observation));
        assert!(owned_desired_converged(&spec, &observation));
        assert!(recovery_divergence_matches(
            &durable,
            false,
            owned_desired_converged(&spec, &observation),
        ));
    }

    #[test]
    fn divergent_apply_recovery_rejects_foreign_or_changed_desired_objects() {
        let spec = test_spec(Some(revision("current")), Some(revision("desired")));
        let mut observation = present_observation();

        observation.owned = false;
        assert!(!owned_desired_converged(&spec, &observation));

        observation.owned = true;
        observation.content_matches = false;
        assert!(!owned_desired_converged(&spec, &observation));

        observation.content_matches = true;
        observation.object_revision = Some(revision("foreign").0.to_string());
        assert!(!owned_desired_converged(&spec, &observation));
    }

    #[test]
    fn disappeared_update_requires_intervention_instead_of_retry() {
        let update = test_spec(Some(revision("current")), Some(revision("desired")));
        let update_request = test_request(&update, KubernetesObjectAction::Apply);
        assert!(!safe_to_retry(&update_request, &absent_observation()));

        let create = test_spec(None, Some(revision("desired")));
        let create_request = test_request(&create, KubernetesObjectAction::Apply);
        assert!(safe_to_retry(&create_request, &absent_observation()));

        let observe_request = test_request(&update, KubernetesObjectAction::Observe);
        assert!(safe_to_retry(&observe_request, &absent_observation()));
    }

    #[test]
    fn unavailable_observation_is_not_authoritative_absence() {
        let unavailable = unavailable_observation();
        let absent = absent_observation();

        assert_eq!(
            revision_observation(&unavailable),
            ResourceRevisionObservation::Unknown
        );
        assert_eq!(
            revision_observation(&absent),
            ResourceRevisionObservation::Absent
        );
        assert_eq!(
            failure_record().durable().as_json()["available"],
            serde_json::Value::Bool(false)
        );
        assert!(failure_record().durable().as_json()["content-matches"].is_boolean());
        assert!(
            failure_record()
                .durable()
                .as_json()
                .get("content_matches")
                .is_none()
        );
    }

    #[test]
    fn repair_classification_rejects_foreign_objects_and_keeps_owned_divergence() {
        let mut observation = present_observation();
        observation.content_matches = false;
        observation.current_content_matches = false;
        assert_eq!(
            classify_owned_revision(&observation).expect("owned mismatch is classified"),
            RuntimeResourceState::Present {
                revision: revision("desired"),
                health: RuntimeResourceHealth::Divergent,
            }
        );

        observation.owned = false;
        assert!(
            classify_owned_revision(&observation).is_err(),
            "foreign object must not select a repair action"
        );
        assert!(classify_owned_revision(&unavailable_observation()).is_err());
    }

    #[test]
    fn observe_completes_with_any_authoritative_object_state() {
        let spec = test_spec(Some(revision("current")), Some(revision("desired")));
        let request = test_request(&spec, KubernetesObjectAction::Observe);
        let mut drifted = present_observation();
        drifted.content_matches = false;
        drifted.owned = false;

        assert!(operation_completed(&request, &absent_observation()));
        assert!(operation_completed(&request, &drifted));
        assert!(!operation_completed(&request, &unavailable_observation()));
    }

    #[test]
    fn delete_options_carry_uid_and_resource_version_preconditions() {
        let options = delete_options(&present_observation()).expect("delete options encode");

        assert_eq!(
            parsed(&options),
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {
                    "resourceVersion": "42",
                    "uid": "server-uid"
                },
                "propagationPolicy": "Foreground"
            })
        );

        let mut missing_uid = present_observation();
        missing_uid.uid = None;
        assert!(delete_options(&missing_uid).is_err());
    }

    #[test]
    fn object_spec_authenticates_retained_content_and_rejects_server_fields() {
        let mut spec = test_spec(Some(revision("current")), Some(revision("desired")));
        assert!(validate_object_spec(&spec).is_ok());

        spec.current_object_json = None;
        assert!(validate_object_spec(&spec).is_err());

        let mut spec = test_spec(None, Some(revision("desired")));
        let mut object = parsed(&spec.object_json);
        object["metadata"]["resourceVersion"] = serde_json::json!("42");
        spec.object_json = canonical(&object);
        assert!(validate_object_spec(&spec).is_err());
    }

    #[test]
    fn kubeconfig_snapshot_is_sealed_and_rejects_external_credentials() {
        let valid = kubeconfig_value();
        let validated = validate_captured_kubeconfig(&canonical(&valid))
            .expect("embedded kubeconfig is accepted");
        let snapshot = KubeconfigSnapshot::new(&validated).expect("snapshot is sealed");

        assert_eq!(std::fs::read(snapshot.path()).unwrap(), validated);
        assert_eq!(
            rustix::fs::fcntl_get_seals(&snapshot.file).unwrap(),
            rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::SEAL
        );

        let mut external = valid.clone();
        external["users"][0]["user"]["exec"] = serde_json::json!({
            "apiVersion": "client.authentication.k8s.io/v1",
            "command": "/untrusted/credential-helper"
        });
        assert!(validate_captured_kubeconfig(&canonical(&external)).is_err());

        let mut external_ca = valid;
        external_ca["clusters"][0]["cluster"]["certificate-authority"] =
            serde_json::json!("/mutable/cluster-ca.pem");
        assert!(validate_captured_kubeconfig(&canonical(&external_ca)).is_err());
    }

    #[test]
    fn kubeconfig_capture_rejects_external_references_before_any_flattening() {
        assert_eq!(
            KUBECONFIG_CAPTURE_ARGUMENTS,
            ["config", "view", "--raw", "--minify", "-o", "json"]
        );
        assert!(!KUBECONFIG_CAPTURE_ARGUMENTS.contains(&"--flatten"));
    }

    #[test]
    fn cancellation_postcondition_probe_runs_with_usable_control() {
        let mut command = helper_command("postcondition");
        let mut child = command
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("postcondition helper starts");
        let group = child_process_group(&child).expect("helper process group exists");
        let control = FixedBudgetControl::new(2_000);
        let deadline = ExecutionDeadline::new(&control).expect("cancellation budget is usable");

        let output = exchange_kubectl_io(&mut child, group, None, &control, deadline)
            .expect("Kubernetes postcondition probe completes");

        let marker = b"postcondition-observed";
        assert!(output.windows(marker.len()).any(|window| window == marker));
    }

    #[test]
    fn process_group_cleanup_does_not_wait_for_inherited_output_pipes() {
        let mut command = helper_command("spawn-descendant");
        let mut child = command
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("helper process starts");
        let group = child_process_group(&child).expect("helper process group exists");
        let control = FixedBudgetControl::new(2_000);
        let deadline = ExecutionDeadline::new(&control).expect("test deadline is valid");
        let started = Instant::now();

        exchange_kubectl_io(&mut child, group, None, &control, deadline)
            .expect("successful helper is collected");

        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn stalled_process_io_is_killed_at_the_shared_deadline() {
        let mut command = helper_command("sleep");
        let mut child = command
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("helper process starts");
        let group = child_process_group(&child).expect("helper process group exists");
        let control = FixedBudgetControl::new(50);
        let deadline = ExecutionDeadline::new(&control).expect("test deadline is valid");
        let input = vec![0_u8; 4 * 1024 * 1024];
        let started = Instant::now();

        let error = exchange_kubectl_io(&mut child, group, Some(&input), &control, deadline)
            .expect_err("stalled process must time out");
        terminate_and_reap(&mut child, group);

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn process_group_helper() {
        match std::env::var("AOS_KUBERNETES_PROCESS_HELPER").as_deref() {
            Ok("spawn-descendant") => {
                let _descendant = helper_command("sleep")
                    .spawn()
                    .expect("descendant helper starts");
            }
            Ok("postcondition") => print!("postcondition-observed"),
            Ok("sleep") => std::thread::sleep(Duration::from_secs(60)),
            _ => {}
        }
    }

    fn helper_command(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test executable exists"));
        command
            .env_clear()
            .env("AOS_KUBERNETES_PROCESS_HELPER", mode)
            .args([
                "--exact",
                "config_eval::kubernetes_ability::tests::process_group_helper",
                "--nocapture",
            ]);
        command
    }

    fn kubeconfig_value() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "clusters": [{
                "cluster": {
                    "certificate-authority-data": "Y2E=",
                    "server": "https://127.0.0.1:6443"
                },
                "name": "cluster"
            }],
            "contexts": [{
                "context": {"cluster": "cluster", "user": "admin"},
                "name": "admin@cluster"
            }],
            "current-context": "admin@cluster",
            "kind": "Config",
            "preferences": {},
            "users": [{
                "name": "admin",
                "user": {
                    "client-certificate-data": "Y2VydA==",
                    "client-key-data": "a2V5"
                }
            }]
        })
    }

    fn test_spec(
        current_revision: Option<RevisionId>,
        desired_revision: Option<RevisionId>,
    ) -> KubernetesObjectResourceSpec {
        let resource = test_resource();
        let selected_revision = desired_revision.or(current_revision);
        let object_json = object_bytes(&resource, selected_revision, 2);
        let current_object_json =
            current_revision.map(|revision| object_bytes(&resource, Some(revision), 1));

        KubernetesObjectResourceSpec {
            handler_provider: resource.provider.clone(),
            resource,
            kubectl: test_artifact(),
            kubeconfig: PathBuf::from("/run/aos/kubernetes/admin.kubeconfig"),
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            namespace: Some("default".to_string()),
            name: "example".to_string(),
            object_json,
            current_revision,
            current_object_json,
            desired_revision,
        }
    }

    fn object_bytes(resource: &ResourceId, revision: Option<RevisionId>, replicas: i64) -> Vec<u8> {
        let owner = kubernetes_resource_owner(resource)
            .expect("owner digest encodes")
            .to_string();
        let revision = revision.map(|revision| revision.0.to_string());
        canonical(&serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "annotations": {
                    "aos.andyl.com/resource-owner": owner,
                    "aos.andyl.com/object-revision": revision,
                },
                "name": "example",
                "namespace": "default"
            },
            "spec": {
                "replicas": replicas,
                "selector": {"matchLabels": {"app": "example"}}
            }
        }))
    }

    fn test_request(
        spec: &KubernetesObjectResourceSpec,
        action: KubernetesObjectAction,
    ) -> KubernetesDurableRequest {
        KubernetesDurableRequest {
            schema: REQUEST_SCHEMA.to_string(),
            action,
            resource: spec.resource.clone(),
            api_version: spec.api_version.clone(),
            kind: spec.kind.clone(),
            namespace: spec.namespace.clone(),
            name: spec.name.clone(),
            object_digest: Sha256Digest::of_bytes(&spec.object_json),
            current_revision: spec.current_revision,
            desired_revision: spec.desired_revision,
            owned_divergence: false,
            kubectl: spec.kubectl.clone(),
            kubeconfig_source: spec.kubeconfig.display().to_string(),
            kubeconfig_digest: Sha256Digest::of_bytes("test kubeconfig"),
        }
    }

    fn present_observation() -> KubernetesObservation {
        KubernetesObservation {
            schema: aos_ability_model::builtin::KUBERNETES_OBJECT_OBSERVATION_SCHEMA.to_string(),
            available: true,
            content_matches: true,
            current_content_matches: true,
            live_object: Some(serde_json::json!({})),
            exists: true,
            object_revision: Some(revision("desired").0.to_string()),
            owned: true,
            resource_version: Some("42".to_string()),
            uid: Some("server-uid".to_string()),
        }
    }

    fn test_resource() -> ResourceId {
        ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("test").expect("authority is valid"),
                    key: LocalKey::new("host").expect("environment is valid"),
                    stage: ExecutionStage::Host,
                },
                key: LocalKey::new("kubernetes").expect("instance is valid"),
            },
            key: LocalKey::new("example").expect("resource is valid"),
        }
    }

    fn test_artifact() -> ArtifactReference {
        ArtifactReference {
            content: Sha256Digest::of_bytes("kubectl content"),
            store_path: "/nix/store/test-kubectl".to_string(),
            nar_hash: Sha256Digest::of_bytes("kubectl nar"),
            closure: Sha256Digest::of_bytes("kubectl closure"),
        }
    }

    fn revision(label: &str) -> RevisionId {
        RevisionId(Sha256Digest::of_bytes(label))
    }

    fn canonical(value: &serde_json::Value) -> Vec<u8> {
        aos_contract::canonical::canonical_json(value).expect("test object is canonical")
    }

    fn parsed(bytes: &[u8]) -> serde_json::Value {
        aos_contract::canonical::parse_json(bytes, "test object").expect("test object parses")
    }
}
