//! Focused tests for binding-native handler calls.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use aos_ability_model::{
    AccessMode, AggregationContract, AggregationScope, AuthorityGrant, BindingSource,
    InterfaceDescriptor, InterfaceName, MethodDescriptor, MethodSemantics, OutcomeSemantics,
    ProviderImplementationReference, ResourceId, ResourceLifetime, ResourcePermission, RevisionId,
    ValueSchema,
};
use aos_contract::Sha256Digest;

use super::*;
use crate::config_eval::handler_process::FixedBudgetControl;

struct FakeTransport {
    effect: InvocationDisposition,
    fail_admission: bool,
    fail_effect_io: bool,
}

impl BoundHandlerTransport for FakeTransport {
    fn admit(
        &self,
        _method: &MethodReference,
        target: &ResourceReference,
        _resource_interface: &InterfaceDocument,
        spec: &CommandHandlerResourceSpec,
        _resources: Vec<ResourceContext>,
        _required_purposes: Vec<InvocationPurpose>,
        _remaining_millis: u64,
    ) -> Result<ResourceContext, std::io::Error> {
        if self.fail_admission {
            return Err(std::io::Error::other("admission failed"));
        }
        let provider_context =
            AbilityValue::new(serde_json::json!({"ready": true})).map_err(std::io::Error::other)?;
        let native_context = AbilityValue::new(
            serde_json::to_value(aos_provider_protocol::BoundNativeContext {
                schema: aos_provider_protocol::RESOURCE_CONTEXT_SCHEMA.into(),
                resource_spec: ResourceSpec {
                    resource: spec.resource.clone(),
                    kind: spec.kind.clone(),
                    lifetime: spec.lifetime,
                    value: spec.value.clone(),
                    realization: spec.realization.clone(),
                    revision: spec.revision,
                },
                provider_context,
            })
            .map_err(std::io::Error::other)?,
        )
        .map_err(std::io::Error::other)?;
        Ok(ResourceContext {
            reference: target.clone(),
            assignment: fixture().2,
            revision: spec.revision,
            observation: AbilityValue::new(serde_json::Value::Bool(true))
                .map_err(std::io::Error::other)?,
            native_context_digest: aos_provider_protocol::native_context_digest(&native_context)
                .map_err(std::io::Error::other)?,
            native_context,
        })
    }

    fn durable_request(
        &self,
        method: MethodReference,
        target: ResourceReference,
        inputs: AbilityValue,
        resources: Vec<ResourceContext>,
        recovery: RecoveryMethods,
    ) -> Result<DurableRequest, std::io::Error> {
        Ok(DurableRequest {
            schema: aos_provider_protocol::REQUEST_SCHEMA.into(),
            handler: LocalKey::new("handler").map_err(std::io::Error::other)?,
            method,
            semantics: MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
            recovery,
            target,
            inputs,
            native_context_digest: aos_provider_protocol::resource_set_digest(&resources)
                .map_err(std::io::Error::other)?,
            resources,
        })
    }

    fn invoke(
        &self,
        request: &DurableRequest,
        purpose: InvocationPurpose,
        _control: &dyn RuntimeControl,
        blobs: &TransactionBlobStore,
    ) -> Result<InvocationResult, std::io::Error> {
        if purpose == InvocationPurpose::Effect && self.fail_effect_io {
            return Err(std::io::Error::other("effect transport failed"));
        }
        let disposition = if purpose == InvocationPurpose::Effect {
            self.effect
        } else {
            InvocationDisposition::Completed
        };
        let outputs = if disposition == InvocationDisposition::Completed {
            let output = blobs.publish_bytes(
                &LocalKey::new("result").map_err(std::io::Error::other)?,
                b"binding-native result",
            )?;
            BTreeMap::from([(
                LocalKey::new("result").map_err(std::io::Error::other)?,
                AbilityValue::new(serde_json::to_value(output).map_err(std::io::Error::other)?)
                    .map_err(std::io::Error::other)?,
            )])
        } else {
            BTreeMap::new()
        };
        Ok(InvocationResult {
            schema: aos_provider_protocol::RESULT_SCHEMA.into(),
            disposition,
            evidence: AbilityValue::new(serde_json::Value::Bool(true))
                .map_err(std::io::Error::other)?,
            outputs,
            native_context_digest: request.native_context_digest,
        })
    }
}

fn fixture() -> (
    Binding,
    InterfaceDocument,
    ProviderAssignment,
    BoundHandlerTarget,
) {
    let resource_interface = InterfaceDocument {
        schema: "aos.ability.interface/v1".into(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: InterfaceName::new("aos.test.resource").expect("resource interface"),
            abi: NonZeroU32::MIN,
            description: "Test resource.".into(),
            request: ValueSchema::Boolean,
            configuration: None,
            outputs: BTreeMap::new(),
            methods: BTreeMap::new(),
            lifecycle: aos_ability_model::LifecycleSemantics {
                persistent_delete_method: None,
            },
            aggregation: AggregationContract {
                scope: AggregationScope::ProviderInstance,
                key: LocalKey::new("slot").expect("slot"),
                controller_group: LocalKey::new("test").expect("group"),
                reject_slot_collisions: true,
                merge_contract: None,
            },
            guarantees: Vec::new(),
        },
    };
    let resource_key = resource_interface.interface_key().expect("resource key");
    let method = LocalKey::new("apply").expect("method");
    let handler_interface = InterfaceDocument {
        schema: "aos.ability.interface/v1".into(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: InterfaceName::new("aos.test.handler").expect("handler interface"),
            abi: NonZeroU32::MIN,
            description: "Test handler.".into(),
            request: ValueSchema::Boolean,
            configuration: None,
            outputs: BTreeMap::new(),
            methods: BTreeMap::from([(
                method.clone(),
                MethodDescriptor {
                    description: "Applies the resource.".into(),
                    semantics: MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
                    parameters: ValueSchema::Boolean,
                    target_resource: resource_key.name.clone(),
                    outputs: BTreeMap::new(),
                    permitted_operations: vec![method.clone()],
                    guarantees: Vec::new(),
                    outcome: OutcomeSemantics {
                        completion_evidence: ValueSchema::Boolean,
                        observation_evidence: ValueSchema::Boolean,
                        supports_rejected_before_effect: true,
                        indeterminate: aos_ability_model::IndeterminateSemantics::Reconcile,
                    },
                },
            )]),
            lifecycle: aos_ability_model::LifecycleSemantics {
                persistent_delete_method: None,
            },
            aggregation: AggregationContract {
                scope: AggregationScope::ProviderInstance,
                key: LocalKey::new("slot").expect("slot"),
                controller_group: LocalKey::new("test").expect("group"),
                reject_slot_collisions: true,
                merge_contract: None,
            },
            guarantees: Vec::new(),
        },
    };
    let handler_key = handler_interface.interface_key().expect("handler key");
    let provider: aos_ability_model::InstanceId = serde_json::from_value(serde_json::json!({
        "environment": {"authority":"test","key":"host","stage":"host"},
        "key":"provider"
    }))
    .expect("provider");
    let resource = ResourceId {
        provider: provider.clone(),
        key: LocalKey::new("resource").expect("resource"),
    };
    let artifact = aos_ability_model::ArtifactReference {
        content: Sha256Digest::of_bytes("content"),
        store_path: "/nix/store/00000000000000000000000000000000-handler".into(),
        nar_hash: Sha256Digest::of_bytes("nar"),
        closure: Sha256Digest::of_bytes("closure"),
    };
    let implementation = ProviderImplementationReference {
        descriptor: Sha256Digest::of_bytes("implementation"),
        artifact,
        handler: Some(LocalKey::new("handler").expect("handler")),
    };
    let assignment = ProviderAssignment {
        provider: provider.clone(),
        interface: handler_key.clone(),
        implementation: implementation.clone(),
        incarnation: serde_json::from_value(serde_json::json!("live")).expect("incarnation"),
    };
    let binding = Binding {
        id: BindingId(LocalKey::new("binding").expect("binding")),
        request: serde_json::from_value(serde_json::json!({
            "consumer": provider,
            "scope": [],
            "key": "request"
        }))
        .expect("request"),
        interface: handler_key,
        provider: assignment.provider.clone(),
        provider_package: Some(Sha256Digest::of_bytes("package")),
        implementation,
        source: BindingSource::Explicit,
        caller_grant: AuthorityGrant {
            principal: assignment.provider.clone(),
            methods: vec![method.clone()],
            contributions: Vec::new(),
            resources: vec![ResourcePermission {
                resource: resource.clone(),
                access: AccessMode::ExclusiveWrite,
                operations: vec![method.clone()],
            }],
        },
        provider_grant: AuthorityGrant {
            principal: assignment.provider.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
        },
        guarantees: Vec::new(),
        policy_revision: RevisionId(Sha256Digest::of_bytes("policy")),
        lifetime: ResourceLifetime::Instance,
        mediation_allowed: false,
    };
    let target = BoundHandlerTarget {
        reference: ResourceReference {
            interface: resource_key.clone(),
            resource: resource.clone(),
            operations: vec![method],
            lifetime: ResourceLifetime::Instance,
        },
        interface: resource_interface,
        resource: ResourceSpec {
            resource,
            kind: resource_key.name,
            lifetime: ResourceLifetime::Instance,
            value: AbilityValue::new(serde_json::Value::Bool(true)).expect("value"),
            realization: AbilityValue::new(serde_json::Value::Null).expect("realization"),
            revision: RevisionId(Sha256Digest::of_bytes("revision")),
        },
        resources: Vec::new(),
        recovery: RecoveryMethods {
            reconcile: Some(MethodReference {
                interface: handler_key_for_target(&handler_interface),
                method: LocalKey::new("apply").expect("method"),
            }),
            cancel: None,
            compensate: None,
        },
    };
    (binding, handler_interface, assignment, target)
}

fn handler_key_for_target(interface: &InterfaceDocument) -> aos_ability_model::InterfaceKey {
    interface.interface_key().expect("handler interface key")
}

pub(in crate::config_eval) fn identity_fixture() -> BoundHandlerIdentity {
    let (binding, interface, assignment, target) = fixture();
    let method = MethodReference {
        interface: binding.interface.clone(),
        method: LocalKey::new("apply").expect("method"),
    };

    BoundHandlerIdentity {
        binding_plan: aos_ability_model::PlanId(Sha256Digest::of_bytes("binding plan")),
        binding,
        interface,
        assignment,
        method,
        target,
    }
}

#[test]
fn handler_only_binding_authorizes_without_an_effect_operation() {
    let (binding, interface, assignment, target) = fixture();
    let method = MethodReference {
        interface: binding.interface.clone(),
        method: LocalKey::new("apply").expect("method"),
    };

    validate_template(&binding, &interface, &assignment, &method, &target)
        .expect("binding-native template");
}

#[test]
fn handler_only_binding_invokes_and_cleans_without_an_effect_operation() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let artifact = tempfile::tempdir().expect("handler artifact");
    let (mut binding, interface, mut assignment, target) = fixture();
    binding.implementation.artifact.store_path = artifact.path().display().to_string();
    assignment.implementation = binding.implementation.clone();
    let method = MethodReference {
        interface: binding.interface.clone(),
        method: LocalKey::new("apply").expect("method"),
    };
    let identity = BoundHandlerIdentity {
        binding_plan: aos_ability_model::PlanId(Sha256Digest::of_bytes("binding plan")),
        binding,
        interface,
        assignment,
        method,
        target,
    };
    let client = BoundHandlerClient {
        identity,
        runtime_root: runtime.path().to_path_buf(),
        transport: Box::new(FakeTransport {
            effect: InvocationDisposition::Completed,
            fail_admission: false,
            fail_effect_io: false,
        }),
        budget_millis: DEFAULT_CALL_BUDGET_MILLIS,
    };
    let call = client.begin_call().expect("handler-only call");
    let input_blob = call
        .publish_blob(
            &LocalKey::new("payload").expect("blob slot"),
            b"binding-native payload",
        )
        .expect("input blob");
    let call_directory = runtime
        .path()
        .join("bound-handler-calls")
        .join(call.transaction().0.as_str());

    let result = call
        .invoke(
            AbilityValue::new(serde_json::to_value(input_blob).expect("blob reference"))
                .expect("inputs"),
            &FixedBudgetControl::new(1_000),
        )
        .expect("handler-only invocation");

    assert_eq!(
        result.invocation().disposition,
        InvocationDisposition::Completed
    );
    let output: TransactionBlobReference =
        serde_json::from_value(result.invocation().outputs["result"].as_json().clone())
            .expect("output blob reference");
    assert_eq!(
        result.read_blob(&output).expect("output blob"),
        b"binding-native result"
    );
    assert!(call_directory.exists());
    result.finish().expect("terminal cleanup");
    assert!(!call_directory.exists());
}

#[test]
fn rejected_admission_removes_the_complete_draft_call() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let artifact = tempfile::tempdir().expect("handler artifact");
    let mut identity = identity_fixture();
    identity.binding.implementation.artifact.store_path = artifact.path().display().to_string();
    identity.assignment.implementation = identity.binding.implementation.clone();
    let client = BoundHandlerClient {
        identity,
        runtime_root: runtime.path().to_path_buf(),
        transport: Box::new(FakeTransport {
            effect: InvocationDisposition::Completed,
            fail_admission: true,
            fail_effect_io: false,
        }),
        budget_millis: DEFAULT_CALL_BUDGET_MILLIS,
    };
    let call = client.begin_call().expect("draft call");
    let call_directory = runtime
        .path()
        .join("bound-handler-calls")
        .join(call.transaction().0.as_str());

    let error = match call.invoke(
        AbilityValue::new(serde_json::Value::Bool(true)).expect("inputs"),
        &FixedBudgetControl::new(1_000),
    ) {
        Ok(_) => panic!("failed admission must reject the call"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("admitting bound-handler target"));
    assert_eq!(
        error.state(),
        BoundHandlerFailureState::CleanedBeforePreparation
    );
    assert!(error.recovery_transaction().is_none());
    assert!(!call_directory.exists());
}

#[test]
fn interrupted_handler_call_reconciles_after_reopen() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let artifact = tempfile::tempdir().expect("handler artifact");
    let (mut binding, interface, mut assignment, mut target) = fixture();
    binding.implementation.artifact.store_path = artifact.path().display().to_string();
    assignment.implementation = binding.implementation.clone();
    target.recovery.reconcile = Some(MethodReference {
        interface: binding.interface.clone(),
        method: LocalKey::new("apply").expect("method"),
    });
    let method = MethodReference {
        interface: binding.interface.clone(),
        method: LocalKey::new("apply").expect("method"),
    };
    let identity = BoundHandlerIdentity {
        binding_plan: aos_ability_model::PlanId(Sha256Digest::of_bytes("binding plan")),
        binding,
        interface,
        assignment,
        method,
        target,
    };
    let client = BoundHandlerClient {
        identity,
        runtime_root: runtime.path().to_path_buf(),
        transport: Box::new(FakeTransport {
            effect: InvocationDisposition::Indeterminate,
            fail_admission: false,
            fail_effect_io: false,
        }),
        budget_millis: DEFAULT_CALL_BUDGET_MILLIS,
    };
    let call = client.begin_call().expect("handler-only call");
    let error = match call.invoke(
        AbilityValue::new(serde_json::Value::Bool(true)).expect("inputs"),
        &FixedBudgetControl::new(1_000),
    ) {
        Ok(_) => panic!("indeterminate effect must stay recoverable"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("requires recovery"));
    assert_eq!(error.state(), BoundHandlerFailureState::RetainedForRecovery);
    let transaction = error
        .recovery_transaction()
        .expect("recoverable transaction")
        .clone();

    let result = client
        .recover(&transaction, &FixedBudgetControl::new(1_000))
        .expect("reconciled call");
    assert_eq!(
        result.invocation().disposition,
        InvocationDisposition::Completed
    );
    result.finish().expect("recovery cleanup");
}

#[test]
fn handler_io_and_illegal_disposition_errors_return_recovery_handles() {
    for (effect, fail_effect_io) in [
        (InvocationDisposition::Completed, true),
        (InvocationDisposition::SafeToRetry, false),
    ] {
        let runtime = tempfile::tempdir().expect("runtime root");
        let artifact = tempfile::tempdir().expect("handler artifact");
        let mut identity = identity_fixture();
        identity.binding.implementation.artifact.store_path = artifact.path().display().to_string();
        identity.assignment.implementation = identity.binding.implementation.clone();
        let client = BoundHandlerClient {
            identity,
            runtime_root: runtime.path().to_path_buf(),
            transport: Box::new(FakeTransport {
                effect,
                fail_admission: false,
                fail_effect_io,
            }),
            budget_millis: DEFAULT_CALL_BUDGET_MILLIS,
        };
        let call = client.begin_call().expect("handler call");

        let error = match call.invoke(
            AbilityValue::new(serde_json::Value::Bool(true)).expect("inputs"),
            &FixedBudgetControl::new(1_000),
        ) {
            Ok(_) => panic!("effect failure must retain recovery state"),
            Err(error) => error,
        };
        assert_eq!(error.state(), BoundHandlerFailureState::RetainedForRecovery);
        let transaction = error
            .recovery_transaction()
            .expect("recovery transaction")
            .clone();

        let result = client
            .recover(&transaction, &FixedBudgetControl::new(1_000))
            .expect("recovered call");
        result.finish().expect("recovery cleanup");
    }
}

#[test]
fn wrong_binding_method_and_context_are_rejected() {
    let checked = aos_ability_validate::test_support::stateful_owner_plan_fixture()
        .validate()
        .expect("checked binding fixture");
    let missing = BindingId(LocalKey::new("missing-binding").expect("binding"));
    assert!(selected_binding(checked.binding_plan(), &missing).is_err());

    let (binding, interface, assignment, target) = fixture();
    let method = MethodReference {
        interface: binding.interface.clone(),
        method: LocalKey::new("apply").expect("method"),
    };

    let mut wrong_assignment = assignment.clone();
    wrong_assignment.implementation.descriptor = Sha256Digest::of_bytes("other");
    assert!(validate_template(&binding, &interface, &wrong_assignment, &method, &target).is_err());

    let wrong_method = MethodReference {
        interface: binding.interface.clone(),
        method: LocalKey::new("other").expect("method"),
    };
    assert!(validate_template(&binding, &interface, &assignment, &wrong_method, &target).is_err());

    let mut wrong_target = target;
    wrong_target.resource.revision = RevisionId(Sha256Digest::of_bytes("other"));
    wrong_target.reference.resource.key = LocalKey::new("other").expect("resource");
    assert!(validate_template(&binding, &interface, &assignment, &method, &wrong_target).is_err());
}
