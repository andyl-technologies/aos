//! Durable PostgreSQL state authentication and retained-resource discovery.
//!
//! This module binds serialized lifecycle state to exact logical resources,
//! physical paths, artifacts, and principal slots before callers act on it.

use super::*;

pub(super) fn authenticate_state_authority(
    request: &NativeHostRequest,
    state: &HostState,
) -> Result<(), io::Error> {
    require_matching_state(request, state)?;
    let exact_desired = state.qualification == request.resource.spec.qualification;
    let exact_retained = request
        .durable
        .retained_qualification
        .as_ref()
        .is_some_and(|qualification| qualification == &state.qualification);
    if !exact_desired && !exact_retained {
        return Err(invalid(
            "PostgreSQL state lacks desired or retained authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_details_identity(
    state: &HostState,
    current: &PostgresqlStateDetails,
) -> Result<(), io::Error> {
    let qualified = qualification(&state.qualification)?;
    let digest = resource_key(&state.resource)?;
    let expected_cluster = Path::new(POSTGRESQL_ROOT).join(&digest);
    let expected_state = Path::new(POSTGRESQL_ROOT).join(format!(".{digest}.json"));
    if current.cluster != qualified.cluster
        || current.database != qualified.database
        || current.role != qualified.role
        || current.control != *qualified.control
        || current.postgresql != *qualified.postgresql
        || current.postgresql_major != qualified.postgresql_major
        || current.postgres_executable != artifact_executable(qualified.postgresql, "bin/postgres")?
        || current.cluster_root != path_text(&expected_cluster)?
        || current.state_path != path_text(&expected_state)?
        || current.slot >= super::super::POSTGRESQL_SLOT_COUNT
        || current.uid != postgresql_slot_uid(current.slot)?
        || current.gid != POSTGRESQL_GID
        || current.principal != postgresql_slot_principal(current.slot)?
        || current.probe_uid != postgresql_probe_uid(current.slot)?
        || current.probe_gid != postgresql_probe_gid(current.slot)?
        || current.probe_principal != postgresql_probe_principal(current.slot)?
        || current.run_path != format!("{SOCKET_ROOT}/{:02}", current.slot)
        || current.server_port != 20_000 + u16::from(current.slot)
        || current.storage_path
            != path_text(&super::super::storage_path(
                &current.storage_resource,
                &current.cluster,
                "database",
                crate::config_eval::native_resource_map::HostStorageOwner::PostgresqlSlot,
            )?)?
        || current.data_path != format!("{}/data", current.storage_path)
    {
        return Err(invalid("PostgreSQL state identity is inconsistent"));
    }
    validate_state_paths(current)?;
    Ok(())
}

pub(super) fn validate_state_paths(current: &PostgresqlStateDetails) -> Result<(), io::Error> {
    let root = Path::new(&current.cluster_root);
    let expected = [
        (&current.active_config_path, "postgresql.conf"),
        (&current.active_hba_path, "pg_hba.conf"),
        (&current.active_ident_path, "pg_ident.conf"),
        (&current.final_config_path, "postgresql.final.conf"),
        (&current.final_hba_path, "pg_hba.final.conf"),
        (&current.final_ident_path, "pg_ident.final.conf"),
        (
            &current.quarantine_config_path,
            "postgresql.quarantine.conf",
        ),
        (&current.quarantine_hba_path, "pg_hba.quarantine.conf"),
        (&current.quarantine_ident_path, "pg_ident.quarantine.conf"),
    ];
    if expected
        .iter()
        .any(|(actual, name)| Path::new(actual.as_str()) != root.join(name))
    {
        return Err(invalid(
            "PostgreSQL state contains a noncanonical file path",
        ));
    }
    Ok(())
}

pub(super) fn require_input(
    input: &PostgresqlInput,
    current: &PostgresqlStateDetails,
) -> Result<(), io::Error> {
    if input.cluster != current.cluster
        || input.database != current.database
        || input.role != current.role
        || input.configuration_revision != current.configuration_revision
        || input
            .endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint != &current.endpoint)
        || input
            .storage_path
            .as_deref()
            .is_some_and(|path| path != current.storage_path)
        || input
            .credential_view
            .as_ref()
            .map(|view| (&view.path, &view.version))
            != current
                .credential
                .as_ref()
                .map(|credential| (&credential.view_path, &credential.version))
    {
        return Err(invalid("PostgreSQL request differs from durable state"));
    }
    Ok(())
}

pub(super) fn validate_binding(binding: &StorageBinding) -> Result<(), io::Error> {
    if binding.slot >= super::super::POSTGRESQL_SLOT_COUNT
        || binding.uid != postgresql_slot_uid(binding.slot)?
        || binding.gid != POSTGRESQL_GID
        || binding.principal != postgresql_slot_principal(binding.slot)?
        || binding.purpose != "database"
    {
        return Err(invalid("PostgreSQL storage binding is inconsistent"));
    }
    protected_directory(
        Path::new(&binding.storage_path),
        binding.uid,
        binding.gid,
        0o700,
    )
}

pub(super) fn qualification(
    value: &NativeResourceQualification,
) -> Result<QualificationRef<'_>, io::Error> {
    let NativeResourceQualification::Postgresql {
        cluster,
        control,
        database,
        postgresql,
        postgresql_major,
        role,
    } = value
    else {
        return Err(invalid("resource is not qualified for PostgreSQL"));
    };
    Ok(QualificationRef {
        cluster,
        control,
        database,
        postgresql,
        postgresql_major: *postgresql_major,
        role,
    })
}

pub(super) fn artifact_executable(
    artifact: &ArtifactReference,
    entry: &str,
) -> Result<String, io::Error> {
    let root = Path::new(&artifact.store_path);
    if !root.is_absolute() || !artifact.store_path.starts_with("/nix/store/") {
        return Err(invalid("PostgreSQL artifact path is not canonical"));
    }
    let expected = root.join(entry);
    let canonical = fs::canonicalize(&expected)?;
    let metadata = fs::metadata(&canonical)?;
    if !canonical.starts_with(root) && !canonical.starts_with("/nix/store/")
        || !metadata.file_type().is_file()
        || metadata.mode() & 0o111 == 0
    {
        return Err(invalid("PostgreSQL artifact entry is not executable"));
    }
    canonical
        .into_os_string()
        .into_string()
        .map_err(|_| invalid("PostgreSQL artifact entry is not UTF-8"))
}

pub(super) fn write_details(
    request: &NativeHostRequest,
    current: &PostgresqlStateDetails,
) -> Result<(), io::Error> {
    write_state(
        &request.resource.state_path,
        &state_with_details(request, current)?,
    )
}

pub(super) fn state_with_details(
    request: &NativeHostRequest,
    current: &PostgresqlStateDetails,
) -> Result<HostState, io::Error> {
    Ok(new_state(
        request,
        serde_json::to_value(current).map_err(store_error)?,
    ))
}

pub(super) fn details(state: &HostState) -> Result<PostgresqlStateDetails, io::Error> {
    serde_json::from_value(state.details.clone())
        .map_err(|error| invalid(format!("invalid PostgreSQL state details: {error}")))
}

pub(super) fn synthetic_request(
    spec: &super::super::NativeHostResourceSpec,
    state: &HostState,
    platform: &super::super::platform::NativePlatformTools,
) -> Result<NativeHostRequest, io::Error> {
    let current = details(state)?;
    let input = PostgresqlInput {
        cluster: current.cluster.clone(),
        configuration_revision: current.configuration_revision.clone(),
        database: current.database.clone(),
        credential_view: current.credential.as_ref().map(|credential| {
            super::super::CredentialView {
                path: credential.view_path.clone(),
                version: credential.version.clone(),
            }
        }),
        endpoint: Some(current.endpoint.clone()),
        role: current.role.clone(),
        storage_path: Some(current.storage_path.clone()),
    };
    let (operation, dependencies) = spec
        .dependencies
        .iter()
        .find(|(_, dependencies)| {
            dependencies
                .iter()
                .any(|dependency| dependency.input == "storage_path")
        })
        .or_else(|| spec.dependencies.iter().next())
        .ok_or_else(|| invalid("PostgreSQL state has no checked observation operation"))?;
    Ok(NativeHostRequest {
        durable: super::super::DurableHostRequest {
            schema: "aos.ability.native-host-request/v1".to_string(),
            kind: super::super::HostRequestKind::Postgresql,
            method: "observe".to_string(),
            operation: operation.clone(),
            resource: state.resource.clone(),
            revision: state.revision,
            inputs: ability_value(serde_json::to_value(input).map_err(store_error)?)?,
            retained_qualification: spec.retained_qualification.clone(),
            dependencies: dependencies.clone(),
            platform: platform.clone(),
            storage_binding: spec.storage_binding.clone(),
        },
        resource: super::super::QualifiedHostResource {
            spec: spec.clone(),
            qualified: super::super::NativeQualifiedResource::host_resource(
                spec.resource.clone(),
                "postgresql-cluster",
                "aos-host-runtime",
                &current.cluster_root,
            )
            .map_err(store_error)?,
            state_path: PathBuf::from(&current.state_path),
        },
    })
}

pub(super) fn postgresql_record(
    request: &NativeHostRequest,
    input: &PostgresqlInput,
    current: Option<&PostgresqlStateDetails>,
    ready: bool,
    observed_revision: Option<String>,
) -> Result<NativeHostRecord, io::Error> {
    let submitted = current
        .map(|details| details.configuration_revision.clone())
        .unwrap_or_else(|| input.configuration_revision.clone());
    let result = serde_json::json!({
        "schema": POSTGRESQL_OBSERVATION_SCHEMA,
        "cluster": input.cluster,
        "database": input.database,
        "endpoint": current.map(|details| details.endpoint.clone()),
        "observed_revision": observed_revision,
        "production_control_path": "/bin/postgresql-control",
        "ready": ready,
        "role": input.role,
        "submitted_revision": submitted,
    });
    let outputs = match request.durable.method.as_str() {
        "materialize" => BTreeMap::from([(
            LocalKey::new(POSTGRESQL_CONFIGURATION_REVISION_OUTPUT).map_err(store_error)?,
            ability_value(serde_json::Value::String(submitted))?,
        )]),
        "observe" => BTreeMap::from([
            (
                LocalKey::new(POSTGRESQL_OBSERVED_REVISION_OUTPUT).map_err(store_error)?,
                ability_value(serde_json::to_value(observed_revision).map_err(store_error)?)?,
            ),
            (
                LocalKey::new(POSTGRESQL_READY_OUTPUT).map_err(store_error)?,
                bool_value(ready)?,
            ),
            (
                LocalKey::new(POSTGRESQL_SUBMITTED_REVISION_OUTPUT).map_err(store_error)?,
                ability_value(serde_json::Value::String(
                    input.configuration_revision.clone(),
                ))?,
            ),
        ]),
        _ => BTreeMap::new(),
    };
    record(result, outputs)
}

pub(crate) struct RetainedPostgresqlAssociation {
    pub(crate) storage: StorageBinding,
    pub(crate) endpoint_resource: ResourceId,
}

pub(crate) fn retained_associations()
-> Result<BTreeMap<ResourceId, RetainedPostgresqlAssociation>, io::Error> {
    Ok(scan_postgresql_ledger()?
        .into_iter()
        .map(|(resource, details)| {
            let storage = StorageBinding {
                storage_resource: details.storage_resource,
                storage_path: details.storage_path,
                cluster: details.cluster,
                lifetime: crate::config_eval::native_resource_map::HostStorageLifetime::Persistent,
                owner: crate::config_eval::native_resource_map::HostStorageOwner::PostgresqlSlot,
                purpose: "database".to_string(),
                slot: details.slot,
                uid: details.uid,
                gid: details.gid,
                principal: details.principal,
            };
            (
                resource,
                RetainedPostgresqlAssociation {
                    storage,
                    endpoint_resource: details.endpoint_resource,
                },
            )
        })
        .collect())
}

pub(super) fn scan_postgresql_ledger()
-> Result<BTreeMap<ResourceId, PostgresqlStateDetails>, io::Error> {
    let mut markers = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut storage = BTreeSet::new();
    let mut slots = BTreeSet::new();
    for entry in fs::read_dir(POSTGRESQL_ROOT)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("PostgreSQL ledger contains a non-UTF-8 entry"))?;
        if let Some(digest) = name
            .strip_prefix('.')
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|value| canonical_digest(value))
        {
            let state = read_state_optional(&entry.path())?
                .ok_or_else(|| invalid("PostgreSQL marker disappeared during scan"))?;
            let current = details(&state)?;
            validate_details_identity(&state, &current)?;
            if resource_key(&state.resource)? != digest
                || markers
                    .insert(state.resource.clone(), current.clone())
                    .is_some()
                || !storage.insert(current.storage_resource.clone())
                || !slots.insert(current.slot)
            {
                return Err(invalid("PostgreSQL ledger contains a duplicate binding"));
            }
        } else if super::super::is_protected_atomic_temporary(&entry.path())? {
            continue;
        } else if canonical_digest(&name) && entry.file_type()?.is_dir() {
            directories.insert(name);
        } else {
            return Err(invalid("PostgreSQL root contains an unknown entry"));
        }
    }
    for (resource, current) in &markers {
        let digest = resource_key(resource)?;
        if directories.contains(&digest) {
            protected_directory(
                Path::new(&current.cluster_root),
                current.uid,
                current.gid,
                0o700,
            )?;
        } else if current.phase != PostgresqlPhase::Preparing {
            return Err(invalid("settled PostgreSQL cluster directory is absent"));
        }
    }
    if directories.iter().any(|digest| {
        !markers
            .keys()
            .any(|resource| resource_key(resource).ok().as_deref() == Some(digest))
    }) {
        return Err(invalid("PostgreSQL directory has no ownership marker"));
    }
    Ok(markers)
}

pub(super) fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
