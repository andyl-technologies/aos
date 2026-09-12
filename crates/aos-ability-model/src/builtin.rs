//! Portable contracts for native abilities supplied by the AOS platform.
//!
//! These constructors are the single source of truth for interfaces whose
//! terminal adapters are compiled into AOS. Package producers and native
//! adapters compare their documents against these exact contracts.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use anyhow::Result;
use aos_contract::Sha256Digest;

use crate::{
    ArtifactReference, ExecutionStage, GuaranteeKey, HandlerDescriptor, ImplementationKind,
    IndeterminateSemantics, InterfaceDescriptor, InterfaceDocument, InterfaceKey, InterfaceName,
    KubernetesObjectAction, LifecycleSemantics, LocalKey, MethodDescriptor, OperationFamily,
    OutcomeSemantics, OutputDescriptor, ProviderImplementation, ResourceLifetime, ServiceAction,
    StringSyntax, ValuePhase, ValueSchema, ValueVisibility, VersionedDocument,
};

mod resource;
mod rollout;

pub use resource::*;
pub use rollout::*;

/// Names the native systemd manager interface.
pub const SYSTEMD_MANAGER_INTERFACE_NAME: &str = "aos.systemd-manager";

/// Names the native interface used to start and hand off a planned systemd provider.
pub const SYSTEMD_PROVIDER_BOOTSTRAP_INTERFACE_NAME: &str = "aos.systemd-provider-bootstrap";

/// Names the readiness output carrying the planned manager assignment.
pub const SYSTEMD_PROVIDER_BOOTSTRAP_ASSIGNMENT_OUTPUT: &str = "cluster-assignment";

/// Names the terminal handler catalog entry for the native systemd adapter.
pub const SYSTEMD_MANAGER_HANDLER_KEY: &str = "native-systemd-manager-v1";

/// Names the terminal handler entry point retained in package metadata.
pub const SYSTEMD_MANAGER_HANDLER_ENTRY_POINT: &str = "libexec/aos-systemd-manager-handler-v1";

/// Carries the exact durable evidence schema emitted by the systemd adapter.
pub const SYSTEMD_OBSERVATION_SCHEMA: &str = "aos.ability.systemd-observation/v1";

/// Names the guarantee that binds lifecycle effects to the target environment's local manager.
pub const LOCAL_SYSTEMD_MANAGER_GUARANTEE_NAME: &str = "aos.local-systemd-manager";

/// Names the guarantee that authenticates delegated system-container manager control.
pub const SYSTEM_CONTAINER_MANAGER_DELEGATION_GUARANTEE_NAME: &str =
    "aos.system-container-manager-delegation";

/// Names the explicit application-container foreground supervision interface.
pub const FOREGROUND_PROCESS_INTERFACE_NAME: &str = "aos.foreground-process";

/// Names the guarantee that retains and supervises the exact foreground process.
pub const FOREGROUND_PROCESS_SUPERVISION_GUARANTEE_NAME: &str =
    "aos.foreground-process-supervision";

/// Carries the exact observation schema emitted by a foreground-process provider.
pub const FOREGROUND_PROCESS_OBSERVATION_SCHEMA: &str =
    "aos.ability.foreground-process-observation/v1";

/// Names the terminal handler catalog entry for foreground process effects.
pub const FOREGROUND_PROCESS_HANDLER_KEY: &str = "native-foreground-process-v1";

/// Names the inert handler marker retained in application-container metadata.
pub const FOREGROUND_PROCESS_HANDLER_ENTRY_POINT: &str =
    "libexec/aos-foreground-process-handler-v1";

/// Names the native Kubernetes object-effects interface.
pub const KUBERNETES_OBJECT_INTERFACE_NAME: &str = "aos.kubernetes-object-effects";

/// Names the terminal handler catalog entry for Kubernetes object effects.
pub const KUBERNETES_OBJECT_HANDLER_KEY: &str = "native-kubernetes-object-v1";

/// Names the terminal handler entry point retained in package metadata.
pub const KUBERNETES_OBJECT_HANDLER_ENTRY_POINT: &str = "libexec/aos-kubernetes-object-handler-v1";

/// Carries the exact durable evidence schema emitted by the Kubernetes adapter.
pub const KUBERNETES_OBJECT_OBSERVATION_SCHEMA: &str =
    "aos.ability.kubernetes-object-observation/v1";

const SYSTEMD_UNIT_MAX_BYTES: u64 = 256;
const SYSTEMD_IDENTITY_MAX_BYTES: u64 = 1_024;
const SYSTEMD_STATE_MAX_BYTES: u64 = 128;
const SYSTEMD_JOB_PATH_MAX_BYTES: u64 = 4_096;
const KUBERNETES_FIELD_MAX_BYTES: u64 = 4_096;
const FOREGROUND_ENTRY_POINT_MAX_BYTES: u64 = 4_096;
const FOREGROUND_ARGUMENT_MAX_BYTES: u64 = 4_096;
const FOREGROUND_ARGUMENT_MAX_ITEMS: u64 = 128;

/// Selects a lifecycle strategy without treating one manager form as another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionStrategy {
    /// Uses the systemd manager local to the selected execution environment.
    SystemdManager,
    /// Supervises an application container's declared foreground process.
    ForegroundProcess,
}

/// Describes the stages and exact guarantees accepted by one built-in strategy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionStrategyCompatibility {
    /// Identifies the exact interface carrying the lifecycle strategy.
    pub interface: InterfaceKey,
    /// Names the strategy independently from its implementation.
    pub strategy: ExecutionStrategy,
    /// Maps each supported stage to its required exact guarantees.
    pub stages: BTreeMap<ExecutionStage, Vec<GuaranteeKey>>,
}

impl ExecutionStrategyCompatibility {
    /// Returns the guarantees required at `stage`, or `None` when the stage is unsupported.
    #[must_use]
    pub fn required_guarantees(&self, stage: ExecutionStage) -> Option<&[GuaranteeKey]> {
        self.stages.get(&stage).map(Vec::as_slice)
    }
}

/// Builds the guarantee binding systemd calls to the selected environment's local manager.
///
/// # Errors
///
/// Returns an error only if a built-in guarantee name or version is invalid.
pub fn local_systemd_manager_guarantee() -> Result<GuaranteeKey> {
    execution_guarantee(
        LOCAL_SYSTEMD_MANAGER_GUARANTEE_NAME,
        "lifecycle calls use only the authenticated systemd manager transport for the provider environment",
    )
}

/// Builds the guarantee proving system-container manager delegation and containment.
///
/// # Errors
///
/// Returns an error only if a built-in guarantee name or version is invalid.
pub fn system_container_manager_delegation_guarantee() -> Result<GuaranteeKey> {
    execution_guarantee(
        SYSTEM_CONTAINER_MANAGER_DELEGATION_GUARANTEE_NAME,
        "the system-container manager endpoint is broker-authenticated, delegated, and unable to control the host manager",
    )
}

/// Builds the guarantee retaining one exact supervised foreground process.
///
/// # Errors
///
/// Returns an error only if a built-in guarantee name or version is invalid.
pub fn foreground_process_supervision_guarantee() -> Result<GuaranteeKey> {
    execution_guarantee(
        FOREGROUND_PROCESS_SUPERVISION_GUARANTEE_NAME,
        "the application-container executor retains and observes the exact declared foreground process",
    )
}

/// Returns stage compatibility metadata for a recognized execution strategy interface.
///
/// The exact interface descriptor must match. A foreign interface cannot acquire
/// built-in stage semantics by reusing a well-known name.
///
/// # Errors
///
/// Returns an error if a built-in interface or guarantee cannot be constructed.
pub fn execution_strategy_compatibility(
    interface: &InterfaceKey,
) -> Result<Option<ExecutionStrategyCompatibility>> {
    if interface == &systemd_manager_interface_key()? {
        return systemd_execution_compatibility(interface.clone()).map(Some);
    }
    if interface == &foreground_process_interface_key()? {
        return foreground_execution_compatibility(interface.clone()).map(Some);
    }
    Ok(None)
}

/// Returns strategy metadata declared by exact interface guarantees.
///
/// This allows separately versioned provider interfaces to opt into the same
/// execution-stage policy without sharing the built-in interface name. The
/// guarantee descriptor, not its textual name alone, selects the semantics.
///
/// # Errors
///
/// Returns an error if the document declares conflicting strategies or its
/// canonical identity cannot be computed.
pub fn declared_execution_strategy_compatibility(
    interface: &InterfaceDocument,
) -> Result<Option<ExecutionStrategyCompatibility>> {
    let local_systemd = local_systemd_manager_guarantee()?;
    let foreground = foreground_process_supervision_guarantee()?;
    let declares_systemd = interface.interface.guarantees.contains(&local_systemd);
    let declares_foreground = interface.interface.guarantees.contains(&foreground);

    anyhow::ensure!(
        !(declares_systemd && declares_foreground),
        "interface declares conflicting execution strategies"
    );
    let key = interface.interface_key()?;
    if declares_systemd {
        return systemd_execution_compatibility(key).map(Some);
    }
    if declares_foreground {
        return foreground_execution_compatibility(key).map(Some);
    }
    Ok(None)
}

fn systemd_execution_compatibility(
    interface: InterfaceKey,
) -> Result<ExecutionStrategyCompatibility> {
    Ok(ExecutionStrategyCompatibility {
        interface,
        strategy: ExecutionStrategy::SystemdManager,
        stages: BTreeMap::from([
            (
                ExecutionStage::Host,
                vec![local_systemd_manager_guarantee()?],
            ),
            (
                ExecutionStage::SystemContainer,
                vec![
                    local_systemd_manager_guarantee()?,
                    system_container_manager_delegation_guarantee()?,
                ],
            ),
        ]),
    })
}

fn foreground_execution_compatibility(
    interface: InterfaceKey,
) -> Result<ExecutionStrategyCompatibility> {
    Ok(ExecutionStrategyCompatibility {
        interface,
        strategy: ExecutionStrategy::ForegroundProcess,
        stages: BTreeMap::from([(
            ExecutionStage::ApplicationContainer,
            vec![foreground_process_supervision_guarantee()?],
        )]),
    })
}

/// Builds the exact public interface implemented by the Kubernetes object adapter.
///
/// The request identifies an object for planning. Native qualification supplies
/// the authoritative identity, canonical object bytes, executable, and protected
/// kubeconfig, so checked-plan parameters cannot widen runtime authority.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn kubernetes_object_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(KUBERNETES_OBJECT_INTERFACE_NAME)?;
    let observation_output = OutputDescriptor {
        schema: kubernetes_object_observation_schema()?,
        phase: ValuePhase::Observation,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Attempt,
    };
    let methods = [
        ("apply", KubernetesObjectAction::Apply),
        ("delete", KubernetesObjectAction::Delete),
        ("observe", KubernetesObjectAction::Observe),
    ]
    .into_iter()
    .map(|(name, action)| {
        let method = LocalKey::new(name)?;
        let descriptor = MethodDescriptor {
            operation_family: OperationFamily::KubernetesObject { action },
            parameters: ValueSchema::Boolean,
            target_resource: interface_name.clone(),
            outputs: BTreeMap::from([(LocalKey::new("observation")?, observation_output.clone())]),
            permitted_operations: vec![method.clone()],
            guarantees: Vec::new(),
            outcome: OutcomeSemantics {
                completion_evidence: kubernetes_object_observation_schema()?,
                observation_evidence: kubernetes_object_observation_schema()?,
                supports_rejected_before_effect: true,
                indeterminate: IndeterminateSemantics::Reconcile,
            },
        };
        Ok((method, descriptor))
    })
    .collect::<Result<BTreeMap<_, _>>>()?;

    Ok(InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: interface_name,
            abi: NonZeroU32::new(1).ok_or_else(|| anyhow::anyhow!("invalid built-in ABI"))?,
            request: kubernetes_object_identity_schema()?,
            configuration: None,
            outputs: BTreeMap::new(),
            methods,
            lifecycle: LifecycleSemantics {
                stable_resource_identity: true,
                releases_ephemeral_on_disable: false,
                retains_persistent_by_default: true,
                persistent_delete_method: Some(LocalKey::new("delete")?),
            },
            guarantees: Vec::new(),
        },
    })
}

/// Computes the canonical identity of the Kubernetes object-effects interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn kubernetes_object_interface_key() -> Result<InterfaceKey> {
    Ok(kubernetes_object_interface()?.interface_key()?)
}

/// Returns the exact terminal handler key used by the Kubernetes object adapter.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn kubernetes_object_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(KUBERNETES_OBJECT_HANDLER_KEY)?)
}

/// Builds the exact terminal Kubernetes object handler contract for an artifact.
///
/// # Errors
///
/// Returns an error only if a built-in schema identifier violates the identity grammar.
pub fn kubernetes_object_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: KUBERNETES_OBJECT_HANDLER_ENTRY_POINT.to_string(),
        arguments: ValueSchema::Boolean,
        result: kubernetes_object_observation_schema()?,
    })
}

/// Builds the exact terminal Kubernetes object provider for an artifact.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn kubernetes_object_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    let interface = kubernetes_object_interface_key()?;

    Ok(ProviderImplementation {
        interface: interface.clone(),
        artifact,
        requirements: Vec::new(),
        implementation: ImplementationKind::TerminalHandler {
            handler: kubernetes_object_handler_key()?,
        },
        owns_resource_kinds: vec![interface.name],
        state_format: None,
    })
}

fn kubernetes_object_identity_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (LocalKey::new("api-version")?, bounded_string(256)),
            (LocalKey::new("kind")?, bounded_string(256)),
            (LocalKey::new("name")?, bounded_string(253)),
            (
                LocalKey::new("namespace")?,
                ValueSchema::Optional {
                    value: Box::new(bounded_string(253)),
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

fn kubernetes_object_observation_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (LocalKey::new("available")?, ValueSchema::Boolean),
            (LocalKey::new("content-matches")?, ValueSchema::Boolean),
            (LocalKey::new("exists")?, ValueSchema::Boolean),
            (
                LocalKey::new("object-revision")?,
                ValueSchema::Optional {
                    value: Box::new(bounded_string(71)),
                },
            ),
            (LocalKey::new("owned")?, ValueSchema::Boolean),
            (
                LocalKey::new("resource-version")?,
                ValueSchema::Optional {
                    value: Box::new(bounded_string(KUBERNETES_FIELD_MAX_BYTES)),
                },
            ),
            (
                LocalKey::new("schema")?,
                ValueSchema::StringEnum {
                    values: vec![KUBERNETES_OBJECT_OBSERVATION_SCHEMA.to_string()],
                },
            ),
            (
                LocalKey::new("uid")?,
                ValueSchema::Optional {
                    value: Box::new(bounded_string(KUBERNETES_FIELD_MAX_BYTES)),
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

/// Builds the exact public interface implemented by the native systemd manager.
///
/// All methods accept a closed unit record and return an observed active-state
/// port. Lifecycle methods use `observe` to reconcile an indeterminate effect;
/// active state alone does not prove that a reload or restart occurred.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn systemd_manager_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(SYSTEMD_MANAGER_INTERFACE_NAME)?;
    let active_output = OutputDescriptor {
        schema: ValueSchema::Boolean,
        phase: ValuePhase::Observation,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Attempt,
    };
    let methods = [
        ("observe", OperationFamily::ObserveReadiness),
        (
            "reload",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Reload,
            },
        ),
        (
            "restart",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Restart,
            },
        ),
        (
            "start",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Start,
            },
        ),
        (
            "stop",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop,
            },
        ),
    ]
    .into_iter()
    .map(|(name, family)| {
        let method = LocalKey::new(name)?;
        let descriptor = MethodDescriptor {
            operation_family: family,
            parameters: systemd_unit_schema()?,
            target_resource: interface_name.clone(),
            outputs: BTreeMap::from([(LocalKey::new("active")?, active_output.clone())]),
            permitted_operations: vec![method.clone()],
            guarantees: Vec::new(),
            outcome: OutcomeSemantics {
                completion_evidence: systemd_observation_schema()?,
                observation_evidence: systemd_observation_schema()?,
                supports_rejected_before_effect: true,
                indeterminate: IndeterminateSemantics::Reconcile,
            },
        };
        Ok((method, descriptor))
    })
    .collect::<Result<BTreeMap<_, _>>>()?;

    Ok(InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: interface_name,
            abi: NonZeroU32::new(1).ok_or_else(|| anyhow::anyhow!("invalid built-in ABI"))?,
            request: systemd_unit_schema()?,
            configuration: None,
            outputs: BTreeMap::new(),
            methods,
            lifecycle: LifecycleSemantics {
                stable_resource_identity: true,
                releases_ephemeral_on_disable: false,
                retains_persistent_by_default: true,
                persistent_delete_method: None,
            },
            guarantees: vec![
                local_systemd_manager_guarantee()?,
                system_container_manager_delegation_guarantee()?,
            ],
        },
    })
}

/// Computes the canonical identity of the native systemd manager interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn systemd_manager_interface_key() -> Result<InterfaceKey> {
    Ok(systemd_manager_interface()?.interface_key()?)
}

/// Builds the explicit application-container foreground-process interface.
///
/// This contract does not emulate systemd unit behavior. It exposes only
/// foreground start, stop, and observation semantics, and requires an exact
/// supervisor guarantee supplied by the application-container executor.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn foreground_process_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(FOREGROUND_PROCESS_INTERFACE_NAME)?;
    let methods = [
        ("observe", OperationFamily::ObserveReadiness),
        (
            "start",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Start,
            },
        ),
        (
            "stop",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop,
            },
        ),
    ]
    .into_iter()
    .map(|(name, family)| {
        let method = LocalKey::new(name)?;
        Ok((
            method.clone(),
            MethodDescriptor {
                operation_family: family,
                parameters: ValueSchema::Boolean,
                target_resource: interface_name.clone(),
                outputs: BTreeMap::new(),
                permitted_operations: vec![method],
                guarantees: Vec::new(),
                outcome: OutcomeSemantics {
                    completion_evidence: foreground_process_observation_schema()?,
                    observation_evidence: foreground_process_observation_schema()?,
                    supports_rejected_before_effect: true,
                    indeterminate: IndeterminateSemantics::Reconcile,
                },
            },
        ))
    })
    .collect::<Result<BTreeMap<_, _>>>()?;

    Ok(InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: interface_name,
            abi: NonZeroU32::new(1).ok_or_else(|| anyhow::anyhow!("invalid built-in ABI"))?,
            request: foreground_process_request_schema()?,
            configuration: None,
            outputs: BTreeMap::new(),
            methods,
            lifecycle: LifecycleSemantics {
                stable_resource_identity: true,
                releases_ephemeral_on_disable: true,
                retains_persistent_by_default: false,
                persistent_delete_method: None,
            },
            guarantees: vec![foreground_process_supervision_guarantee()?],
        },
    })
}

/// Computes the canonical identity of the foreground-process interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn foreground_process_interface_key() -> Result<InterfaceKey> {
    Ok(foreground_process_interface()?.interface_key()?)
}

/// Returns the exact terminal handler key used by the foreground supervisor.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn foreground_process_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(FOREGROUND_PROCESS_HANDLER_KEY)?)
}

/// Builds the terminal foreground-process handler contract for an artifact.
///
/// The handler entry point is an authenticated metadata marker. The
/// application-container executor invokes the workload entry point carried by
/// the resource request after independently checking that artifact.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates its grammar.
pub fn foreground_process_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: FOREGROUND_PROCESS_HANDLER_ENTRY_POINT.to_string(),
        arguments: foreground_process_request_schema()?,
        result: foreground_process_observation_schema()?,
    })
}

/// Builds the native foreground-process provider implementation.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn foreground_process_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    let interface = foreground_process_interface_key()?;

    Ok(ProviderImplementation {
        interface: interface.clone(),
        artifact,
        requirements: Vec::new(),
        implementation: ImplementationKind::TerminalHandler {
            handler: foreground_process_handler_key()?,
        },
        owns_resource_kinds: vec![interface.name],
        state_format: None,
    })
}

/// Builds the public lifecycle and readiness contract for a planned systemd provider.
///
/// The lifecycle operations control the resource through its bootstrap
/// manager. `observe-manager` publishes the exact assignment that consumers
/// must reacquire through the receiving stage's independently supplied
/// transport.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn systemd_provider_bootstrap_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(SYSTEMD_PROVIDER_BOOTSTRAP_INTERFACE_NAME)?;
    let assignment_output = OutputDescriptor {
        schema: ValueSchema::ProviderAssignment,
        phase: ValuePhase::Observation,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Attempt,
    };
    let method = |name: &str,
                  operation_family: OperationFamily,
                  outputs: BTreeMap<LocalKey, OutputDescriptor>|
     -> Result<(LocalKey, MethodDescriptor)> {
        let method = LocalKey::new(name)?;
        let descriptor = MethodDescriptor {
            operation_family,
            parameters: ValueSchema::Boolean,
            target_resource: interface_name.clone(),
            outputs,
            permitted_operations: vec![method.clone()],
            guarantees: Vec::new(),
            outcome: OutcomeSemantics {
                completion_evidence: ValueSchema::Boolean,
                observation_evidence: ValueSchema::Boolean,
                supports_rejected_before_effect: true,
                indeterminate: IndeterminateSemantics::Reconcile,
            },
        };
        Ok((method, descriptor))
    };
    let methods = [
        method(
            "observe-manager",
            OperationFamily::ObserveReadiness,
            BTreeMap::from([(
                LocalKey::new(SYSTEMD_PROVIDER_BOOTSTRAP_ASSIGNMENT_OUTPUT)?,
                assignment_output,
            )]),
        )?,
        method(
            "start",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Start,
            },
            BTreeMap::new(),
        )?,
        method(
            "stop",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop,
            },
            BTreeMap::new(),
        )?,
    ]
    .into_iter()
    .collect();

    Ok(InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: interface_name,
            abi: NonZeroU32::new(1).ok_or_else(|| anyhow::anyhow!("invalid built-in ABI"))?,
            request: ValueSchema::Boolean,
            configuration: None,
            outputs: BTreeMap::new(),
            methods,
            lifecycle: LifecycleSemantics {
                stable_resource_identity: true,
                releases_ephemeral_on_disable: false,
                retains_persistent_by_default: true,
                persistent_delete_method: None,
            },
            guarantees: Vec::new(),
        },
    })
}

/// Computes the canonical identity of the planned systemd provider interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn systemd_provider_bootstrap_interface_key() -> Result<InterfaceKey> {
    Ok(systemd_provider_bootstrap_interface()?.interface_key()?)
}

/// Returns the exact terminal handler key used by the native systemd adapter.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn systemd_manager_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(SYSTEMD_MANAGER_HANDLER_KEY)?)
}

/// Builds the exact terminal systemd handler contract for an artifact.
///
/// # Errors
///
/// Returns an error only if a built-in schema identifier violates the identity grammar.
pub fn systemd_manager_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: SYSTEMD_MANAGER_HANDLER_ENTRY_POINT.to_string(),
        arguments: systemd_unit_schema()?,
        result: systemd_observation_schema()?,
    })
}

/// Builds the exact terminal provider implementation for an artifact.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn systemd_manager_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    let interface = systemd_manager_interface_key()?;

    Ok(ProviderImplementation {
        interface: interface.clone(),
        artifact,
        requirements: Vec::new(),
        implementation: ImplementationKind::TerminalHandler {
            handler: systemd_manager_handler_key()?,
        },
        owns_resource_kinds: vec![interface.name],
        state_format: None,
    })
}

fn execution_guarantee(name: &str, semantics: &str) -> Result<GuaranteeKey> {
    Ok(GuaranteeKey {
        name: InterfaceName::new(name)?,
        version: NonZeroU32::new(1).ok_or_else(|| anyhow::anyhow!("invalid built-in version"))?,
        descriptor: Sha256Digest::separated("aos.ability.execution-guarantee/v1", semantics),
    })
}

fn foreground_process_request_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("arguments")?,
                ValueSchema::List {
                    element: Box::new(bounded_string(FOREGROUND_ARGUMENT_MAX_BYTES)),
                    max_items: FOREGROUND_ARGUMENT_MAX_ITEMS,
                },
            ),
            (LocalKey::new("artifact")?, ValueSchema::ArtifactReference),
            (
                LocalKey::new("entry_point")?,
                bounded_string(FOREGROUND_ENTRY_POINT_MAX_BYTES),
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

fn foreground_process_observation_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("process_identity")?,
                ValueSchema::Optional {
                    value: Box::new(bounded_string(SYSTEMD_IDENTITY_MAX_BYTES)),
                },
            ),
            (LocalKey::new("running")?, ValueSchema::Boolean),
            (
                LocalKey::new("schema")?,
                ValueSchema::StringEnum {
                    values: vec![FOREGROUND_PROCESS_OBSERVATION_SCHEMA.to_string()],
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

fn systemd_unit_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([(
            LocalKey::new("unit")?,
            bounded_string(SYSTEMD_UNIT_MAX_BYTES),
        )]),
        optional_fields: Vec::new(),
    })
}

fn systemd_observation_schema() -> Result<ValueSchema> {
    let optional_string = |maximum| ValueSchema::Optional {
        value: Box::new(bounded_string(maximum)),
    };

    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("active")?,
                ValueSchema::Optional {
                    value: Box::new(ValueSchema::Boolean),
                },
            ),
            (
                LocalKey::new("active_state")?,
                optional_string(SYSTEMD_STATE_MAX_BYTES),
            ),
            (
                LocalKey::new("job_path")?,
                optional_string(SYSTEMD_JOB_PATH_MAX_BYTES),
            ),
            (
                LocalKey::new("job_result")?,
                optional_string(SYSTEMD_STATE_MAX_BYTES),
            ),
            (
                LocalKey::new("manager_bus_id")?,
                optional_string(SYSTEMD_IDENTITY_MAX_BYTES),
            ),
            (
                LocalKey::new("manager_owner")?,
                optional_string(SYSTEMD_IDENTITY_MAX_BYTES),
            ),
            (
                LocalKey::new("schema")?,
                ValueSchema::StringEnum {
                    values: vec![SYSTEMD_OBSERVATION_SCHEMA.to_string()],
                },
            ),
            (
                LocalKey::new("state")?,
                bounded_string(SYSTEMD_STATE_MAX_BYTES),
            ),
            (
                LocalKey::new("unit")?,
                bounded_string(SYSTEMD_UNIT_MAX_BYTES),
            ),
            (
                LocalKey::new("unit_identity")?,
                optional_string(SYSTEMD_IDENTITY_MAX_BYTES),
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

const fn bounded_string(max_length: u64) -> ValueSchema {
    ValueSchema::String {
        max_length,
        syntax: None::<StringSyntax>,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use aos_contract::Sha256Digest;

    use super::*;

    #[test]
    fn systemd_manager_contract_has_stable_identity_and_valid_methods() {
        let document = systemd_manager_interface().expect("built-in contract must construct");
        let key = document
            .interface_key()
            .expect("built-in contract must have an identity");

        crate::InterfaceName::new(SYSTEMD_MANAGER_INTERFACE_NAME)
            .expect("built-in interface name must remain valid");
        assert_eq!(document.interface.methods.len(), 5);
        assert!(document.interface.methods.contains_key("observe"));
        assert_eq!(key, systemd_manager_interface_key().unwrap());
        assert_eq!(
            key.descriptor,
            Sha256Digest::parse(
                "sha256:ff940aedc92c6492557de96a9d802ad27e8dc945155adc23c7542b0bb5e3bce3"
            )
            .unwrap()
        );
        assert!(
            crate::decode_canonical::<InterfaceDocument>(
                &crate::encode_canonical(&document).unwrap(),
                crate::ABILITY_LIMITS_V1,
                &BTreeSet::new(),
            )
            .is_ok()
        );
    }

    #[test]
    fn execution_strategies_are_stage_specific_and_require_exact_guarantees() {
        let systemd = execution_strategy_compatibility(&systemd_manager_interface_key().unwrap())
            .unwrap()
            .expect("systemd must declare execution compatibility");
        let foreground =
            execution_strategy_compatibility(&foreground_process_interface_key().unwrap())
                .unwrap()
                .expect("foreground process must declare execution compatibility");

        assert_eq!(systemd.strategy, ExecutionStrategy::SystemdManager);
        assert_eq!(
            systemd.required_guarantees(ExecutionStage::Host),
            Some([local_systemd_manager_guarantee().unwrap()].as_slice())
        );
        assert_eq!(
            systemd
                .required_guarantees(ExecutionStage::SystemContainer)
                .expect("system containers are supported")
                .len(),
            2
        );
        assert!(
            systemd
                .required_guarantees(ExecutionStage::ApplicationContainer)
                .is_none()
        );
        assert_eq!(foreground.strategy, ExecutionStrategy::ForegroundProcess);
        assert!(
            foreground
                .required_guarantees(ExecutionStage::ApplicationContainer)
                .is_some()
        );
        assert!(
            foreground
                .required_guarantees(ExecutionStage::Host)
                .is_none()
        );
        assert_eq!(
            local_systemd_manager_guarantee().unwrap().descriptor,
            Sha256Digest::parse(
                "sha256:50995c1c62000543639c8d9f85995c35cc44a9022933ed79e5447654593291d4"
            )
            .unwrap()
        );
        assert_eq!(
            system_container_manager_delegation_guarantee()
                .unwrap()
                .descriptor,
            Sha256Digest::parse(
                "sha256:a811c4d2cc0fd8e09a019ae518bbe95f393ed5bc3265a1b72902adfa7325ceda"
            )
            .unwrap()
        );
        assert_eq!(
            foreground_process_supervision_guarantee()
                .unwrap()
                .descriptor,
            Sha256Digest::parse(
                "sha256:b213e3c6ef28e4930a1091296e28fbfddde9f539d2daeb0287edfe955047311a"
            )
            .unwrap()
        );
    }

    #[test]
    fn foreground_contract_does_not_claim_systemd_reload_semantics() {
        let document = foreground_process_interface().unwrap();
        let methods = document
            .interface
            .methods
            .keys()
            .map(LocalKey::as_str)
            .collect::<Vec<_>>();

        assert_eq!(methods, ["observe", "start", "stop"]);
        assert_eq!(
            document.interface.guarantees,
            [foreground_process_supervision_guarantee().unwrap()]
        );
    }

    #[test]
    fn kubernetes_contract_has_stable_identity_and_valid_methods() {
        let document =
            kubernetes_object_interface().expect("built-in Kubernetes contract must construct");
        let key = document
            .interface_key()
            .expect("built-in Kubernetes contract must have an identity");

        crate::InterfaceName::new(KUBERNETES_OBJECT_INTERFACE_NAME)
            .expect("built-in interface name must remain valid");
        assert_eq!(document.interface.methods.len(), 3);
        assert!(document.interface.methods.contains_key("apply"));
        assert!(document.interface.methods.contains_key("delete"));
        assert!(document.interface.methods.contains_key("observe"));
        assert_eq!(key, kubernetes_object_interface_key().unwrap());
        assert_eq!(
            key.descriptor,
            Sha256Digest::parse(
                "sha256:bbced9c501c3c41ab4b5f2a70a2945bde2128ef0a37ad900f6d9f1e2f110963e"
            )
            .unwrap()
        );
        assert!(
            crate::decode_canonical::<InterfaceDocument>(
                &crate::encode_canonical(&document).unwrap(),
                crate::ABILITY_LIMITS_V1,
                &BTreeSet::new(),
            )
            .is_ok()
        );
    }

    #[test]
    fn systemd_provider_bootstrap_contract_has_typed_readiness() {
        let document = systemd_provider_bootstrap_interface()
            .expect("built-in provider-bootstrap contract must construct");
        let key = document
            .interface_key()
            .expect("built-in provider-bootstrap contract must have an identity");
        let observe = document
            .interface
            .methods
            .get("observe-manager")
            .expect("provider-bootstrap contract must observe its manager");

        assert_eq!(document.interface.methods.len(), 3);
        assert_eq!(document.interface.request, ValueSchema::Boolean);
        assert_eq!(observe.operation_family, OperationFamily::ObserveReadiness);
        let assignment = observe
            .outputs
            .get(SYSTEMD_PROVIDER_BOOTSTRAP_ASSIGNMENT_OUTPUT)
            .expect("manager observation must publish its assignment");
        assert_eq!(assignment.schema, ValueSchema::ProviderAssignment);
        assert_eq!(assignment.phase, ValuePhase::Observation);
        assert_eq!(assignment.visibility, ValueVisibility::Protected);
        assert_eq!(assignment.lifetime, ResourceLifetime::Attempt);
        assert!(document.interface.methods["start"].outputs.is_empty());
        assert!(document.interface.methods["stop"].outputs.is_empty());
        for method in document.interface.methods.values() {
            assert_eq!(method.parameters, ValueSchema::Boolean);
            assert_eq!(method.outcome.completion_evidence, ValueSchema::Boolean);
            assert_eq!(method.outcome.observation_evidence, ValueSchema::Boolean);
            assert!(method.outcome.supports_rejected_before_effect);
            assert_eq!(
                method.outcome.indeterminate,
                IndeterminateSemantics::Reconcile
            );
        }
        assert!(document.interface.configuration.is_none());
        assert!(document.interface.outputs.is_empty());
        assert!(document.interface.guarantees.is_empty());
        assert_eq!(key, systemd_provider_bootstrap_interface_key().unwrap());
        assert_eq!(
            key.descriptor,
            Sha256Digest::parse(
                "sha256:833e92258892d87a1f1cb16f66bfd1629c47a97386a9853cd93ffa30037b82f1"
            )
            .unwrap()
        );
        assert!(
            crate::decode_canonical::<InterfaceDocument>(
                &crate::encode_canonical(&document).unwrap(),
                crate::ABILITY_LIMITS_V1,
                &BTreeSet::new(),
            )
            .is_ok()
        );
    }
}
