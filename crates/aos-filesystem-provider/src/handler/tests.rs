use std::num::NonZeroU32;

use aos_ability_model::{
    AccessMode, EnvironmentId, ExecutionStage, InstanceId, InterfaceKey, InterfaceName,
    MethodReference, MethodSemantics, ResourceLifetime,
};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, INVOCATION_SCHEMA, InvocationControl, REQUEST_SCHEMA, ResourceSpec,
};
use tempfile::tempdir;

use super::*;

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("test key is valid")
}

fn interface(name: &str) -> InterfaceKey {
    InterfaceKey {
        name: InterfaceName::new(name).expect("test interface is valid"),
        abi: NonZeroU32::MIN,
        descriptor: Sha256Digest::of_bytes(name),
    }
}

fn resource(key_name: &str) -> ResourceId {
    ResourceId {
        provider: InstanceId {
            environment: EnvironmentId {
                authority: key("test"),
                key: key("host"),
                stage: ExecutionStage::Host,
            },
            key: key("filesystem"),
        },
        key: key(key_name),
    }
}

fn provider(temporary: &Path) -> FilesystemProvider {
    let identity_root = temporary.join("etc");
    fs::create_dir_all(&identity_root).expect("identity fixture directory exists");
    fs::write(
        identity_root.join("passwd"),
        format!(
            "service:x:{}:{}:service:/:/sbin/nologin\n",
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw()
        ),
    )
    .expect("principal fixture is written");
    fs::write(
        identity_root.join("group"),
        format!("service:x:{}:\n", rustix::process::getegid().as_raw()),
    )
    .expect("group fixture is written");
    FilesystemProvider {
        state_root: temporary.join("state"),
        instance_root: temporary.join("instance"),
        persistent_root: temporary.join("persistent"),
        identity_root,
        mutable_roots: vec![temporary.join("entries")],
    }
}

fn admission_request(provider: &FilesystemProvider, resource: ResourceId) -> AdmissionRequest {
    let interface = interface(STORAGE_ALLOCATION_INTERFACE);
    let value = ability_value(json!({
        "name": "runtime",
        "purpose": "runtime",
        "mode": "0750",
    }))
    .expect("request value is valid");
    let decoded: StorageAllocationRequest = decode_value(&value).expect("request fixture decodes");
    let path = provider
        .storage_path(STORAGE_ALLOCATION_INTERFACE, &resource, &decoded)
        .expect("planned path computes");
    let target = ResourceReference {
        interface: interface.clone(),
        resource: resource.clone(),
        operations: vec![key("allocate"), key("observe")],
        lifetime: ResourceLifetime::Instance,
    };
    AdmissionRequest {
        schema: ADMISSION_REQUEST_SCHEMA.into(),
        method: MethodReference {
            interface,
            method: key("allocate"),
        },
        semantics: MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        target,
        resource_spec: ResourceSpec {
            resource,
            kind: aos_ability_model::InterfaceName::new(STORAGE_ALLOCATION_INTERFACE)
                .expect("storage resource kind is valid"),
            lifetime: aos_ability_model::ResourceLifetime::Instance,
            value,
            realization: ability_value(json!({
                "schema": REALIZATION_SCHEMA,
                "path": path_string(&path).expect("planned path is UTF-8"),
            }))
            .expect("realization is valid"),
            revision: RevisionId(Sha256Digest::of_bytes(b"desired-storage")),
        },
        resources: Vec::new(),
        control: InvocationControl {
            attempt_remaining_millis: 10_000,
            recovery_remaining_millis: 10_000,
            cancelled: false,
        },
    }
}

fn entry_request(
    provider: &FilesystemProvider,
    resource: ResourceId,
    relative_path: &str,
    entry: serde_json::Value,
    source_path: Option<&Path>,
    prerequisites: Vec<ResourceReference>,
    resources: Vec<ResourceContext>,
) -> AdmissionRequest {
    let interface = interface(FILESYSTEM_ENTRY_INTERFACE);
    let destination = provider.mutable_roots[0].join(relative_path);
    let target = ResourceReference {
        interface: interface.clone(),
        resource: resource.clone(),
        operations: vec![key("materialize"), key("observe"), key("release")],
        lifetime: ResourceLifetime::Instance,
    };
    let value = ability_value(json!({
        "name": resource.key,
        "entry": entry,
        "destination": destination,
        "owner": "service",
        "group": "service",
        "mode": "0750",
        "prerequisites": prerequisites,
    }))
    .expect("filesystem entry request is valid");
    AdmissionRequest {
        schema: ADMISSION_REQUEST_SCHEMA.into(),
        method: MethodReference {
            interface,
            method: key("materialize"),
        },
        semantics: MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        target,
        resource_spec: ResourceSpec {
            resource,
            kind: InterfaceName::new(FILESYSTEM_ENTRY_INTERFACE)
                .expect("filesystem entry kind is valid"),
            lifetime: ResourceLifetime::Instance,
            value,
            realization: ability_value(json!({
                "schema": ENTRY_REALIZATION_SCHEMA,
                "path": destination,
                "source_path": source_path,
            }))
            .expect("filesystem entry realization is valid"),
            revision: RevisionId(Sha256Digest::of_bytes(relative_path)),
        },
        resources,
        control: InvocationControl {
            attempt_remaining_millis: 10_000,
            recovery_remaining_millis: 10_000,
            cancelled: false,
        },
    }
}

fn persistent_request(provider: &FilesystemProvider, resource: ResourceId) -> AdmissionRequest {
    let mut request = admission_request(provider, resource);
    let interface = interface(PERSISTENT_STORAGE_ALLOCATION_INTERFACE);
    request.method.interface = interface.clone();
    request.target.interface = interface;
    request.target.lifetime = ResourceLifetime::Persistent;
    request.resource_spec.kind = InterfaceName::new(PERSISTENT_STORAGE_ALLOCATION_INTERFACE)
        .expect("persistent storage kind is valid");
    request.resource_spec.lifetime = ResourceLifetime::Persistent;
    let input: StorageAllocationRequest =
        decode_value(&request.resource_spec.value).expect("persistent request fixture decodes");
    let path = provider
        .storage_path(
            PERSISTENT_STORAGE_ALLOCATION_INTERFACE,
            &request.resource_spec.resource,
            &input,
        )
        .expect("persistent planned path computes");
    request.resource_spec.realization = ability_value(json!({
        "schema": REALIZATION_SCHEMA,
        "path": path,
    }))
    .expect("persistent realization is valid");
    request
}

fn storage_view_request(
    target_resource: ResourceId,
    source: ResourceReference,
    source_context: ResourceContext,
    path: &Path,
) -> AdmissionRequest {
    let source_provider =
        decode_provider_context(&source_context).expect("source provider context decodes");
    let interface = interface(STORAGE_VIEW_INTERFACE);
    let target = ResourceReference {
        interface: interface.clone(),
        resource: target_resource.clone(),
        operations: vec![key("materialize"), key("observe"), key("release")],
        lifetime: ResourceLifetime::Instance,
    };
    let value = ability_value(json!({
        "name": "socket",
        "source": source,
        "source_path": source_provider.path,
        "access": "read-write",
        "relative_path": "service.sock",
    }))
    .expect("storage-view request is valid");
    AdmissionRequest {
        schema: ADMISSION_REQUEST_SCHEMA.into(),
        method: MethodReference {
            interface,
            method: key("materialize"),
        },
        semantics: MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        target,
        resource_spec: ResourceSpec {
            resource: target_resource,
            kind: InterfaceName::new(STORAGE_VIEW_INTERFACE)
                .expect("storage-view resource kind is valid"),
            lifetime: ResourceLifetime::Instance,
            value,
            realization: ability_value(json!({
                "schema": VIEW_REALIZATION_SCHEMA,
                "source": source_context.reference,
                "relative_path": "service.sock",
                "path": path,
            }))
            .expect("storage-view realization is valid"),
            revision: RevisionId(Sha256Digest::of_bytes(
                path_string(path).expect("path is UTF-8"),
            )),
        },
        resources: vec![source_context],
        control: InvocationControl {
            attempt_remaining_millis: 10_000,
            recovery_remaining_millis: 10_000,
            cancelled: false,
        },
    }
}

fn target_context(request: &AdmissionRequest, admission: &AdmissionResult) -> ResourceContext {
    let bound = ability_value(
        serde_json::to_value(BoundNativeContext {
            schema: aos_provider_protocol::RESOURCE_CONTEXT_SCHEMA.into(),
            resource_spec: request.resource_spec.clone(),
            provider_context: admission.native_context.clone(),
        })
        .expect("bound context serializes"),
    )
    .expect("bound context is canonical");
    let assignment = serde_json::from_value(serde_json::json!({
        "provider": request.target.resource.provider,
        "interface": request.method.interface,
        "implementation": {
            "descriptor": format!("sha256:{}", "4".repeat(64)),
            "artifact": {
                "content": format!("sha256:{}", "5".repeat(64)),
                "store_path": "/nix/store/00000000000000000000000000000000-fixture",
                "nar_hash": format!("sha256:{}", "6".repeat(64)),
                "closure": format!("sha256:{}", "7".repeat(64)),
            },
            "handler": "fixture",
        },
        "incarnation": "fixture-incarnation",
    }))
    .expect("provider assignment fixture is valid");
    ResourceContext {
        reference: request.target.clone(),
        assignment,
        revision: request.resource_spec.revision,
        observation: admission.observation.clone(),
        native_context_digest: aos_provider_protocol::native_context_digest(&bound)
            .expect("context digest computes"),
        native_context: bound,
    }
}

fn invocation(
    purpose: InvocationPurpose,
    request: &AdmissionRequest,
    context: ResourceContext,
) -> Invocation {
    let resources = vec![context];
    let native_context_digest =
        resource_set_digest(&resources).expect("resource set digest computes");
    Invocation {
        schema: INVOCATION_SCHEMA.into(),
        purpose,
        method: request.method.clone(),
        semantics: request.semantics.clone(),
        request: aos_provider_protocol::DurableRequest {
            schema: REQUEST_SCHEMA.into(),
            method: request.method.clone(),
            semantics: request.semantics.clone(),
            recovery: aos_provider_protocol::RecoveryMethods {
                reconcile: Some(request.method.clone()),
                cancel: Some(request.method.clone()),
                compensate: None,
            },
            target: request.target.clone(),
            inputs: request.resource_spec.value.clone(),
            native_context_digest,
            resources,
        },
        control: request.control.clone(),
    }
}

fn invocation_with_dependencies(
    purpose: InvocationPurpose,
    request: &AdmissionRequest,
    target: ResourceContext,
    mut dependencies: Vec<ResourceContext>,
) -> Invocation {
    dependencies.push(target);
    dependencies.sort_by(|left, right| left.reference.resource.cmp(&right.reference.resource));
    let native_context_digest =
        resource_set_digest(&dependencies).expect("resource set digest computes");
    Invocation {
        schema: INVOCATION_SCHEMA.into(),
        purpose,
        method: request.method.clone(),
        semantics: request.semantics.clone(),
        request: aos_provider_protocol::DurableRequest {
            schema: REQUEST_SCHEMA.into(),
            method: request.method.clone(),
            semantics: request.semantics.clone(),
            recovery: aos_provider_protocol::RecoveryMethods {
                reconcile: Some(request.method.clone()),
                cancel: Some(request.method.clone()),
                compensate: None,
            },
            target: request.target.clone(),
            inputs: request.resource_spec.value.clone(),
            native_context_digest,
            resources: dependencies,
        },
        control: request.control.clone(),
    }
}

#[test]
fn allocation_effect_creates_an_owned_exact_directory() {
    let temporary = tempdir().expect("temporary directory exists");
    let provider = provider(temporary.path());
    let request = admission_request(&provider, resource("runtime"));
    let admission = provider
        .admit(request.clone())
        .expect("absent allocation admits");
    assert_eq!(admission.revision, AdmissionRevision::Absent);
    let context = target_context(&request, &admission);

    let result = provider
        .invoke(invocation(InvocationPurpose::Effect, &request, context))
        .expect("allocation effect succeeds");
    assert_eq!(result.disposition, InvocationDisposition::Completed);
    assert!(result.outputs.contains_key(&key("storage-path")));
    assert!(result.outputs.contains_key(&key("retained-resource")));
    assert!(result.outputs.contains_key(&key("observation")));

    let observed = provider
        .admit(request)
        .expect("created allocation observes");
    assert_eq!(
        observed.revision,
        AdmissionRevision::Present {
            revision: RevisionId(Sha256Digest::of_bytes(b"desired-storage")),
        }
    );
}

#[test]
fn allocation_applies_and_observes_resolved_principal_and_group() {
    use std::os::unix::fs::MetadataExt as _;

    let temporary = tempdir().expect("temporary directory exists");
    let provider = provider(temporary.path());
    let mut request = admission_request(&provider, resource("owned"));
    request.resource_spec.value = ability_value(json!({
        "name": "owned",
        "purpose": "state",
        "mode": "0750",
        "owner": "service",
        "group": "service",
    }))
    .expect("owned request is valid");
    let admission = provider
        .admit(request.clone())
        .expect("owned allocation admits");
    let context = target_context(&request, &admission);

    let result = provider
        .invoke(invocation(InvocationPurpose::Effect, &request, context))
        .expect("owned allocation effect succeeds");

    assert_eq!(result.disposition, InvocationDisposition::Completed);
    let provider_context: StorageProviderContext =
        decode_value(&admission.native_context).expect("provider context decodes");
    let metadata = fs::metadata(provider_context.path).expect("storage directory exists");
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.gid(), rustix::process::getegid().as_raw());
    let observed = provider
        .admit(request)
        .expect("owned allocation remains admissible");
    assert_eq!(
        observed.revision,
        AdmissionRevision::Present {
            revision: RevisionId(Sha256Digest::of_bytes(b"desired-storage")),
        }
    );
}

#[test]
fn admission_rejects_a_realization_that_differs_from_the_planned_path() {
    let temporary = tempdir().expect("temporary directory exists");
    let provider = provider(temporary.path());
    let mut request = admission_request(&provider, resource("drifted-realization"));
    request.resource_spec.realization = ability_value(json!({
        "schema": REALIZATION_SCHEMA,
        "path": temporary.path().join("other"),
    }))
    .expect("drifted realization is valid JSON");

    let error = provider
        .admit(request)
        .expect_err("a drifted planned path must be rejected");

    assert!(error.to_string().contains("planned path"), "{error:#}");
}

#[test]
fn cancellation_of_an_absent_allocation_never_creates_it() {
    let temporary = tempdir().expect("temporary directory exists");
    let provider = provider(temporary.path());
    let request = admission_request(&provider, resource("cancelled"));
    let admission = provider
        .admit(request.clone())
        .expect("absent allocation admits");
    let context = target_context(&request, &admission);
    let provider_context: StorageProviderContext =
        decode_value(&admission.native_context).expect("provider context decodes");

    let result = provider
        .invoke(invocation(InvocationPurpose::Cancel, &request, context))
        .expect("cancellation observes absence");
    assert_eq!(
        result.disposition,
        InvocationDisposition::RejectedBeforeEffect
    );
    assert!(!Path::new(&provider_context.path).exists());
}

#[test]
fn release_removes_only_the_exact_claimed_directory_and_reconciles_absence() {
    let temporary = tempdir().expect("temporary directory exists");
    let provider = provider(temporary.path());
    let mut request = admission_request(&provider, resource("released"));
    let allocation = provider.admit(request.clone()).expect("allocation admits");
    let allocation_context = target_context(&request, &allocation);
    provider
        .invoke(invocation(
            InvocationPurpose::Effect,
            &request,
            allocation_context,
        ))
        .expect("allocation effect succeeds");
    let provider_context: StorageProviderContext =
        decode_value(&allocation.native_context).expect("provider context decodes");
    fs::write(
        Path::new(&provider_context.path).join("content"),
        b"retained bytes",
    )
    .expect("fixture content is written");

    request.method.method = key("release");
    request.target.operations.push(key("release"));
    let release = provider
        .admit(request.clone())
        .expect("present allocation admits for release");
    let release_context = target_context(&request, &release);
    let result = provider
        .invoke(invocation(
            InvocationPurpose::Effect,
            &request,
            release_context.clone(),
        ))
        .expect("release effect succeeds");

    assert_eq!(result.disposition, InvocationDisposition::Completed);
    assert_eq!(result.outputs.len(), 1);
    assert!(result.outputs.contains_key(&key("observation")));
    assert!(!Path::new(&provider_context.path).exists());
    assert!(
        provider
            .claim_for(&request.resource_spec.resource)
            .expect("claim lookup succeeds")
            .is_none()
    );

    let reconciled = provider
        .invoke(invocation(
            InvocationPurpose::Reconcile,
            &request,
            release_context,
        ))
        .expect("released absence reconciles");
    assert_eq!(reconciled.disposition, InvocationDisposition::Completed);
    assert_eq!(observation_state(&reconciled.evidence), Some("absent"));
}

#[test]
fn filesystem_entries_enforce_declared_parent_order_and_copy_exact_content() {
    let temporary = tempdir().expect("temporary directory exists");
    let provider = provider(temporary.path());
    fs::create_dir_all(&provider.mutable_roots[0]).expect("mutable fixture root exists");

    let parent_request = entry_request(
        &provider,
        resource("wrapper-root"),
        "wrappers",
        json!({"kind":"directory"}),
        None,
        Vec::new(),
        Vec::new(),
    );
    let parent_admission = provider
        .admit(parent_request.clone())
        .expect("parent directory admits");
    provider
        .invoke(invocation(
            InvocationPurpose::Effect,
            &parent_request,
            target_context(&parent_request, &parent_admission),
        ))
        .expect("parent directory materializes");
    let observed_parent = provider
        .admit(parent_request.clone())
        .expect("parent directory observes");
    let parent_context = target_context(&parent_request, &observed_parent);

    let artifact = temporary.path().join("artifact");
    fs::create_dir(&artifact).expect("artifact root exists");
    fs::write(artifact.join("wrapper"), b"exact wrapper bytes").expect("artifact file exists");
    let source = fs::canonicalize(artifact.join("wrapper")).expect("artifact source canonicalizes");
    let source_value = json!({
        "kind": "artifact-file",
        "reference": {
            "artifact": {
                "content": format!("sha256:{}", "1".repeat(64)),
                "store_path": artifact,
                "nar_hash": format!("sha256:{}", "2".repeat(64)),
                "closure": format!("sha256:{}", "3".repeat(64)),
            },
            "path": "wrapper",
        },
    });
    let child_request = entry_request(
        &provider,
        resource("wrapper-bin"),
        "wrappers/tool",
        json!({
            "kind": "copied-file",
            "source": source_value,
            "maximum_size_bytes": MAX_SAFE_INTEGER,
        }),
        Some(&source),
        vec![parent_request.target.clone()],
        vec![parent_context.clone()],
    );
    let child_admission = provider
        .admit(child_request.clone())
        .expect("child file with an exact parent prerequisite admits");
    let result = provider
        .invoke(invocation_with_dependencies(
            InvocationPurpose::Effect,
            &child_request,
            target_context(&child_request, &child_admission),
            vec![parent_context.clone()],
        ))
        .expect("child file materializes");

    assert_eq!(result.disposition, InvocationDisposition::Completed);
    assert_eq!(
        fs::read(provider.mutable_roots[0].join("wrappers/tool")).expect("copied file is readable"),
        b"exact wrapper bytes"
    );
    assert!(result.outputs.contains_key(&key("execution-path")));

    let bound_error = inspect_regular_file_nofollow(&source, 4)
        .expect_err("copy source larger than the declared bound must fail");
    assert!(bound_error.to_string().contains("byte bound"));
    let range_error = inspect_regular_file_nofollow(&source, MAX_SAFE_INTEGER + 1)
        .expect_err("copy source bound outside canonical JSON range must fail");
    assert!(range_error.to_string().contains("portable integer"));

    let undeclared_child = entry_request(
        &provider,
        resource("undeclared-child"),
        "wrappers/other",
        json!({"kind":"directory"}),
        None,
        Vec::new(),
        Vec::new(),
    );
    let error = provider
        .admit(undeclared_child)
        .expect_err("an undeclared claimed parent must fail admission");
    assert!(error.to_string().contains("parent"), "{error:#}");
}

#[test]
fn storage_view_materialize_and_release_only_its_exact_durable_lease() {
    let temporary = tempdir().expect("temporary directory exists");
    let provider = provider(temporary.path());
    let source_request = admission_request(&provider, resource("source"));
    let source_admission = provider
        .admit(source_request.clone())
        .expect("source allocation admits");
    provider
        .invoke(invocation(
            InvocationPurpose::Effect,
            &source_request,
            target_context(&source_request, &source_admission),
        ))
        .expect("source allocation materializes");
    let source_observation = provider
        .admit(source_request.clone())
        .expect("source allocation observes");
    let source_context = target_context(&source_request, &source_observation);
    let source_root: StorageProviderContext =
        decode_value(&source_observation.native_context).expect("source context decodes");
    let view_path = Path::new(&source_root.path).join("service.sock");
    let mut request = storage_view_request(
        resource("view"),
        source_request.target.clone(),
        source_context.clone(),
        &view_path,
    );
    let mut mismatched = request.clone();
    let mut mismatched_value = mismatched.resource_spec.value.as_json().clone();
    mismatched_value["source_path"] = json!(temporary.path().join("foreign-storage"));
    mismatched.resource_spec.value =
        ability_value(mismatched_value).expect("mismatched view request remains bounded");
    let error = provider
        .admit(mismatched)
        .expect_err("a view cannot pair its source with another planned path");
    assert!(
        error.to_string().contains("planned source path"),
        "{error:#}"
    );

    let admission = provider
        .admit(request.clone())
        .expect("absent storage-view lease admits");
    assert_eq!(admission.revision, AdmissionRevision::Absent);
    let effect = provider
        .invoke(invocation_with_dependencies(
            InvocationPurpose::Effect,
            &request,
            target_context(&request, &admission),
            vec![source_context.clone()],
        ))
        .expect("storage-view lease materializes");
    assert_eq!(effect.disposition, InvocationDisposition::Completed);
    assert_eq!(observation_state(&effect.evidence), Some("ready"));

    request.method.method = key("release");
    let release_admission = provider
        .admit(request.clone())
        .expect("active storage-view lease admits for release");
    let release = provider
        .invoke(invocation_with_dependencies(
            InvocationPurpose::Effect,
            &request,
            target_context(&request, &release_admission),
            vec![source_context],
        ))
        .expect("storage-view lease releases");
    assert_eq!(release.disposition, InvocationDisposition::Completed);
    assert_eq!(observation_state(&release.evidence), Some("absent"));
    assert!(Path::new(&source_root.path).is_dir());
}

#[test]
fn persistent_release_detaches_ownership_without_deleting_retained_data() {
    let temporary = tempdir().expect("temporary directory exists");
    let provider = provider(temporary.path());
    let mut request = persistent_request(&provider, resource("persistent"));
    let admission = provider
        .admit(request.clone())
        .expect("persistent allocation admits");
    provider
        .invoke(invocation(
            InvocationPurpose::Effect,
            &request,
            target_context(&request, &admission),
        ))
        .expect("persistent allocation materializes");
    let context: StorageProviderContext =
        decode_value(&admission.native_context).expect("provider context decodes");
    let retained = Path::new(&context.path).join("retained");
    fs::write(&retained, b"persistent data").expect("persistent fixture is written");

    request.method.method = key("release");
    request.target.operations.push(key("release"));
    let release = provider
        .admit(request.clone())
        .expect("persistent release admits");
    provider
        .invoke(invocation(
            InvocationPurpose::Effect,
            &request,
            target_context(&request, &release),
        ))
        .expect("persistent allocation detaches");

    assert_eq!(
        fs::read(retained).expect("persistent bytes remain"),
        b"persistent data"
    );
    let resource_id = request.resource_spec.resource.clone();
    let detached = provider
        .admit(request)
        .expect("detached persistent allocation remains observable");
    assert!(matches!(
        detached.revision,
        AdmissionRevision::Present { .. }
    ));
    assert_eq!(observation_state(&detached.observation), Some("absent"));
    assert!(
        !provider
            .claim_for(&resource_id)
            .expect("persistent claim is readable")
            .is_some_and(|claim| claim.active)
    );
}

#[test]
fn invocation_rejects_resource_set_drift_before_allocation() {
    let temporary = tempdir().expect("temporary directory exists");
    let provider = provider(temporary.path());
    let request = admission_request(&provider, resource("drifted"));
    let admission = provider
        .admit(request.clone())
        .expect("absent allocation admits");
    let context = target_context(&request, &admission);
    let provider_context: StorageProviderContext =
        decode_value(&admission.native_context).expect("provider context decodes");
    let mut invocation = invocation(InvocationPurpose::Effect, &request, context);
    invocation.request.native_context_digest = Sha256Digest::of_bytes(b"other-resource-set");

    let error = provider
        .invoke(invocation)
        .expect_err("resource-set drift must fail before effect");

    assert!(
        error.to_string().contains("resource-set digest"),
        "{error:#}"
    );
    assert!(!Path::new(&provider_context.path).exists());
}
