//! Shared host-resource request execution and dependency authentication.
//!
//! Adapter methods enter here only after checked resource acquisition and
//! durable-request validation. Each family retains its own effect logic.

use super::*;

pub(super) fn request_is_read_only(request: &NativeHostRequest) -> bool {
    matches!(request.durable.method.as_str(), "acquire" | "observe")
}

pub(super) fn reject_postgresql_identity_change_before_intent(
    resource: &QualifiedHostResource,
    inputs: &AbilityValue,
    storage: &StorageBinding,
) -> Result<(), io::Error> {
    let input: PostgresqlInput = decode_input(inputs, "PostgreSQL")?;
    let NativeResourceQualification::Postgresql {
        database,
        postgresql_major,
        role,
        ..
    } = &resource.spec.qualification
    else {
        return Err(invalid("PostgreSQL request has another qualification"));
    };
    if input.database != *database || input.role != *role {
        return Err(invalid(
            "PostgreSQL database and role are immutable for retained storage",
        ));
    }
    validate_process_fence_before_intent(resource, storage)?;
    if let Some(existing) = read_state_optional(&resource.state_path)? {
        let NativeResourceQualification::Postgresql {
            database: old_database,
            postgresql_major: old_major,
            role: old_role,
            ..
        } = existing.qualification
        else {
            return Err(invalid("PostgreSQL marker has another qualification"));
        };
        if old_database != *database || old_role != *role || old_major != *postgresql_major {
            return Err(invalid(
                "retained PostgreSQL compatibility identity changed",
            ));
        }
    }
    let data = Path::new(&storage.storage_path).join("data");
    match fs::symlink_metadata(&data) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => protected_directory(&data, storage.uid, storage.gid, 0o700)?,
    }
    let version = match read_protected_file(&data.join("PG_VERSION"), 32, storage.uid, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if fs::read_dir(&data)?.next().is_none() {
                return Ok(());
            }
            return Err(invalid(
                "PostgreSQL data directory is nonempty without PG_VERSION",
            ));
        }
        Err(error) => return Err(error),
    };
    if version != format!("{postgresql_major}\n").as_bytes() {
        return Err(invalid(
            "PostgreSQL data major differs from desired compatibility policy",
        ));
    }
    Ok(())
}

pub(super) fn execute_request(
    request: &NativeHostRequest,
    control: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    // Production creates these roots. Every operation authenticates them and
    // never repairs ownership or permissions in place.
    ensure_runtime_roots()?;
    authenticate_dependency_bindings(
        NativeHostResourceKind::from_qualification(&request.resource.spec.qualification)
            .ok_or_else(|| invalid("durable request lost its host-resource qualification"))?,
        &request.durable.method,
        &request.durable.inputs,
        &request.durable.dependencies,
        request.durable.storage_binding.as_ref(),
    )?;
    match NativeHostResourceKind::from_qualification(&request.resource.spec.qualification)
        .ok_or_else(|| invalid("durable request lost its host-resource qualification"))?
    {
        NativeHostResourceKind::Credential => execute_credential(request),
        NativeHostResourceKind::Endpoint => execute_endpoint(request, control),
        NativeHostResourceKind::Storage => execute_storage(request),
        NativeHostResourceKind::NetworkPolicy => execute_policy(request, control),
        NativeHostResourceKind::Postgresql => execute_postgresql(request, control),
    }
}

pub(super) fn authenticate_dependency_bindings(
    kind: NativeHostResourceKind,
    method: &str,
    inputs: &AbilityValue,
    dependencies: &[NativeDependencyBinding],
    storage_binding: Option<&StorageBinding>,
) -> Result<(), io::Error> {
    if kind == NativeHostResourceKind::Postgresql && matches!(method, "materialize" | "observe") {
        let input: PostgresqlInput = decode_input(inputs, "PostgreSQL")?;
        match &input.endpoint {
            Some(endpoint) => {
                let endpoint_binding = require_dependency(dependencies, "endpoint")?;
                authenticate_endpoint(endpoint_binding, endpoint)?;
            }
            None if dependencies
                .iter()
                .all(|binding| binding.input != "endpoint") => {}
            None => {
                return Err(invalid(
                    "null PostgreSQL endpoint carries producer authority",
                ));
            }
        }

        match input.storage_path.as_deref() {
            Some(storage_path) => {
                let storage = storage_binding
                    .ok_or_else(|| invalid("PostgreSQL dependency has no storage binding"))?;
                let storage_dependency = require_dependency(dependencies, "storage_path")?;
                let authenticated_storage = authenticate_storage_dependency(
                    storage_dependency,
                    storage_path,
                    &input.cluster,
                )?;
                if storage != &authenticated_storage || storage_path != storage.storage_path {
                    return Err(invalid(
                        "PostgreSQL storage value differs from its producer authority",
                    ));
                }
            }
            None if dependencies
                .iter()
                .all(|binding| binding.input != "storage_path") => {}
            None => {
                return Err(invalid(
                    "null PostgreSQL storage carries producer authority",
                ));
            }
        }

        match &input.credential_view {
            Some(view) => {
                let credential_binding = require_dependency(dependencies, "credential_view")?;
                authenticate_credential_dependency(
                    credential_binding,
                    Path::new(&view.path),
                    &view.version,
                )?;
            }
            None if dependencies
                .iter()
                .all(|binding| binding.input != "credential_view") => {}
            None => {
                return Err(invalid(
                    "trust-mode PostgreSQL request carries credential authority",
                ));
            }
        }
    } else if kind == NativeHostResourceKind::NetworkPolicy && matches!(method, "apply" | "observe")
    {
        let input: PolicyInput = decode_input(inputs, "host network policy")?;
        let endpoint = input
            .endpoint
            .as_ref()
            .ok_or_else(|| invalid("network policy dependency has no endpoint"))?;
        let endpoint_binding = require_dependency(dependencies, "endpoint")?;
        authenticate_endpoint(endpoint_binding, endpoint)?;
    }
    Ok(())
}

fn require_dependency<'a>(
    dependencies: &'a [NativeDependencyBinding],
    input: &str,
) -> Result<&'a NativeDependencyBinding, io::Error> {
    let mut matches = dependencies.iter().filter(|binding| binding.input == input);
    let binding = matches.next().ok_or_else(|| {
        invalid(format!(
            "host-resource input {input} has no producer authority"
        ))
    })?;
    if matches.next().is_some() {
        return Err(invalid(format!(
            "host-resource input {input} has ambiguous producer authority"
        )));
    }
    Ok(binding)
}

pub(super) fn reconcile_request(
    request: &NativeHostRequest,
    control: &dyn RuntimeControl,
) -> Result<Option<NativeHostRecord>, io::Error> {
    let state = read_state_optional(&request.resource.state_path)?;
    let Some(state) = state else {
        return if matches!(request.durable.method.as_str(), "release" | "remove") {
            execute_request(request, control).map(Some)
        } else if request_is_read_only(request) {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "reconciliation found no host-resource state",
            ))
        } else {
            Ok(None)
        };
    };
    if state.resource != request.durable.resource {
        return Err(invalid("reconciliation found foreign host-resource state"));
    }
    let exact_current = state.revision == request.durable.revision
        && state.qualification == request.resource.spec.qualification;
    let stable_prior = state_matches_spec(&state, &request.resource.spec)
        && prior_revision_reexecution_allowed(request);
    if exact_current || stable_prior {
        execute_request(request, control).map(Some)
    } else {
        Err(invalid("reconciliation found stale host-resource state"))
    }
}

pub(super) fn prior_revision_reexecution_allowed(request: &NativeHostRequest) -> bool {
    let Some(kind) =
        NativeHostResourceKind::from_qualification(&request.resource.spec.qualification)
    else {
        return false;
    };
    matches!(
        (kind, request.durable.method.as_str()),
        (NativeHostResourceKind::Credential, "deliver" | "release")
            | (NativeHostResourceKind::Storage, "ensure" | "release")
            | (NativeHostResourceKind::Endpoint, "materialize" | "release")
            | (NativeHostResourceKind::NetworkPolicy, "apply" | "remove")
            | (NativeHostResourceKind::Postgresql, "materialize" | "stop")
    )
}

pub(super) fn rejection_record(request: &NativeHostRequest) -> NativeHostRecord {
    let result =
        match NativeHostResourceKind::from_qualification(&request.resource.spec.qualification) {
            Some(NativeHostResourceKind::Credential) => {
                let input = decode_input::<CredentialInput>(&request.durable.inputs, "credential");
                input.map(|input| {
                    serde_json::json!({
                        "schema": CREDENTIAL_DELIVERY_OBSERVATION_SCHEMA,
                        "delivered": false,
                        "observed_version": null,
                        "requested_version": input.version,
                        "view": input.view,
                    })
                })
            }
            Some(NativeHostResourceKind::Endpoint) => Ok(serde_json::json!({
                "schema": NETWORK_ENDPOINT_OBSERVATION_SCHEMA,
                "requested_revision": request.durable.revision.0.to_string(),
                "observed_revision": null,
                "endpoint": null,
                "owned": false,
            })),
            Some(NativeHostResourceKind::Storage) => {
                let input = decode_input::<StorageInput>(&request.durable.inputs, "storage");
                input.map(|_| {
                    serde_json::json!({
                        "schema": HOST_STORAGE_OBSERVATION_SCHEMA,
                        "requested_revision": request.durable.revision.0.to_string(),
                        "observed_revision": null,
                        "attached": false,
                        "exists": false,
                        "path": storage_path(&request.durable.resource)
                            .and_then(|path| path_text(&path))
                            .unwrap_or_default(),
                    })
                })
            }
            Some(NativeHostResourceKind::NetworkPolicy) => Ok(serde_json::json!({
                "schema": HOST_NETWORK_POLICY_OBSERVATION_SCHEMA,
                "requested_revision": request.durable.revision.0.to_string(),
                "observed_revision": null,
                "active": false,
                "endpoint": null,
            })),
            Some(NativeHostResourceKind::Postgresql) => {
                let input = decode_input::<PostgresqlInput>(&request.durable.inputs, "PostgreSQL");
                input.map(|input| {
                    serde_json::json!({
                        "schema": POSTGRESQL_OBSERVATION_SCHEMA,
                        "cluster": input.cluster,
                        "database": input.database,
                        "endpoint": null,
                        "observed_revision": null,
                        "production_control_path": "/bin/postgresql-control",
                        "ready": false,
                        "role": input.role,
                        "submitted_revision": input.configuration_revision,
                    })
                })
            }
            None => Err(invalid("request has no host-resource qualification")),
        };
    let durable = result
        .and_then(ability_value)
        .unwrap_or_else(|_| request.durable.inputs.clone());
    NativeHostRecord {
        durable,
        outputs: BTreeMap::new(),
    }
}

pub(super) fn observe_health(
    kind: NativeHostResourceKind,
    spec: &NativeHostResourceSpec,
    state: &HostState,
    platform: &NativePlatformTools,
    control: &dyn RuntimeControl,
) -> Result<RuntimeResourceHealth, io::Error> {
    Ok(match kind {
        NativeHostResourceKind::Credential => {
            if credential_healthy(state)? {
                RuntimeResourceHealth::Healthy
            } else {
                RuntimeResourceHealth::Divergent
            }
        }
        NativeHostResourceKind::Endpoint => {
            if endpoint_health(state)? {
                RuntimeResourceHealth::Healthy
            } else {
                RuntimeResourceHealth::Divergent
            }
        }
        NativeHostResourceKind::Storage => {
            let (exists, attached) = storage_health(state)?;
            if !exists {
                RuntimeResourceHealth::Divergent
            } else if !attached {
                RuntimeResourceHealth::Stopped
            } else {
                RuntimeResourceHealth::Healthy
            }
        }
        NativeHostResourceKind::NetworkPolicy => policy::policy_health(state, platform, control)?,
        NativeHostResourceKind::Postgresql => postgresql_health(spec, state, platform, control)?,
    })
}
