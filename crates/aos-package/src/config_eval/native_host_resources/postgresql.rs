//! Persistent PostgreSQL preparation, lifecycle recovery, and observation.
//!
//! Root-owned Rust records each transition before invoking a signed control
//! under a fixed server or probe identity. The control is the only component
//! that executes PostgreSQL programs. Persistent data and ownership ledgers
//! survive logical teardown.

mod control;
mod process_fence;
mod render;
mod state_authority;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aos_ability_model::builtin::{
    POSTGRESQL_CONFIGURATION_REVISION_OUTPUT, POSTGRESQL_OBSERVATION_SCHEMA,
    POSTGRESQL_OBSERVED_REVISION_OUTPUT, POSTGRESQL_READY_OUTPUT,
    POSTGRESQL_SUBMITTED_REVISION_OUTPUT,
};
use aos_ability_model::{ArtifactReference, LocalKey, ResourceId, RevisionId};
use aos_ability_plan::RuntimeResourceHealth;
use aos_ability_runtime::adapter::RuntimeControl;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use self::control::{
    ApplicationProof, AuthenticationOutcome, ProcessProof, ServerProof, ServerTarget, StopProof,
};
pub(super) use self::process_fence::validate_process_fence_before_intent;
use self::process_fence::{
    authenticate_process_proof, recorded_process_is_absent, require_global_target_authority,
    start_adoption_policy, validate_process_proof_fields,
};
pub(super) use self::state_authority::retained_associations;
use self::state_authority::{
    artifact_executable, authenticate_state_authority, details, postgresql_record, qualification,
    require_input, scan_postgresql_ledger, state_with_details, synthetic_request, validate_binding,
    validate_details_identity, write_details,
};
use super::super::native_resource_map::NativeResourceQualification;
use super::credential::{
    CredentialEvidence, authenticate_credential_marker, authenticate_credential_view,
};
use super::storage::StorageBinding;
use super::{
    HostState, NativeHostRecord, NativeHostRequest, POSTGRESQL_GID, POSTGRESQL_ROOT,
    PostgresqlInput, QualifiedHostResource, ability_value, bool_value, decode_input,
    ensure_directory, invalid, new_state, path_text, postgresql_probe_gid,
    postgresql_probe_principal, postgresql_probe_uid, postgresql_slot_principal,
    postgresql_slot_uid, protected_directory, read_protected_file, read_state_optional, record,
    require_matching_state, require_state, resource_key, store_error, write_state,
};

const ADMIN_ROLE: &str = "aos-ability-postgresql";
const SOCKET_ROOT: &str = "/run/aos-ability-postgresql";
const MAX_POSTGRESQL_FILE_BYTES: u64 = 256 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PostgresqlPhase {
    Preparing,
    Prepared,
    AuthenticatingStop,
    StoppedForTransition,
    RevalidatingCandidates,
    OpeningCredential,
    QuarantineStarting,
    QuarantineActive,
    Repairing,
    Repaired,
    QuarantineStopping,
    QuarantineStopped,
    PublishingFinal,
    FinalPublished,
    FinalStarting,
    FinalStarted,
    Active,
    Stopping,
    Stopped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum PostgresqlAuth {
    Scram,
}

impl PostgresqlAuth {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Scram => "scram",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum TargetProcessPolicy<'a> {
    Absent,
    ConfiguredTargetAbsent,
    Expected(&'a ProcessProof),
    StartAdoption,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordedProcessFence {
    CurrentExpected,
    PriorExpected,
    CurrentAbsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessFenceMatrix {
    recorded: RecordedProcessFence,
    current_target_absent: bool,
    desired_target_absent: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PostgresqlStateDetails {
    phase: PostgresqlPhase,
    auth: PostgresqlAuth,
    slot: u8,
    uid: u32,
    gid: u32,
    principal: String,
    probe_uid: u32,
    probe_gid: u32,
    probe_principal: String,
    cluster: String,
    cluster_root: String,
    state_path: String,
    storage_resource: ResourceId,
    endpoint_resource: ResourceId,
    storage_path: String,
    data_path: String,
    run_path: String,
    active_config_path: String,
    active_hba_path: String,
    active_ident_path: String,
    final_config_path: String,
    final_hba_path: String,
    final_ident_path: String,
    quarantine_config_path: String,
    quarantine_hba_path: String,
    quarantine_ident_path: String,
    configuration_revision: String,
    database: String,
    role: String,
    endpoint: super::EndpointValue,
    server_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential: Option<CredentialEvidence>,
    control: ArtifactReference,
    postgresql: ArtifactReference,
    postgres_executable: String,
    postgresql_major: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pg_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data_system_identifier: Option<String>,
    final_config_digest: Sha256Digest,
    final_hba_digest: Sha256Digest,
    final_ident_digest: Sha256Digest,
    quarantine_config_digest: Sha256Digest,
    quarantine_hba_digest: Sha256Digest,
    quarantine_ident_digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_config_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_hba_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_ident_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_verifier_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process: Option<ProcessProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior_active: Option<PostgresqlActiveSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PostgresqlActiveSnapshot {
    operation_revision: RevisionId,
    qualification: NativeResourceQualification,
    configuration_revision: String,
    resource: ResourceId,
    control: ArtifactReference,
    postgresql: ArtifactReference,
    postgres_executable: String,
    postgresql_major: u16,
    pg_version: String,
    data_system_identifier: String,
    slot: u8,
    uid: u32,
    gid: u32,
    principal: String,
    probe_uid: u32,
    probe_gid: u32,
    probe_principal: String,
    cluster: String,
    cluster_root: String,
    state_path: String,
    storage_resource: ResourceId,
    endpoint_resource: ResourceId,
    storage_path: String,
    data_path: String,
    run_path: String,
    active_config_path: String,
    active_hba_path: String,
    active_ident_path: String,
    endpoint: super::EndpointValue,
    server_port: u16,
    database: String,
    role: String,
    auth: PostgresqlAuth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential: Option<CredentialEvidence>,
    active_config_digest: Sha256Digest,
    active_hba_digest: Sha256Digest,
    active_ident_digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_verifier_digest: Option<Sha256Digest>,
    process: ProcessProof,
}

struct PostgresqlPaths {
    cluster: PathBuf,
    state: PathBuf,
    storage: PathBuf,
    data: PathBuf,
    run: PathBuf,
    active_config: PathBuf,
    active_hba: PathBuf,
    active_ident: PathBuf,
    final_config: PathBuf,
    final_hba: PathBuf,
    final_ident: PathBuf,
    quarantine_config: PathBuf,
    quarantine_hba: PathBuf,
    quarantine_ident: PathBuf,
}

impl PostgresqlPaths {
    fn new(request: &NativeHostRequest, binding: &StorageBinding) -> Result<Self, io::Error> {
        let cluster = Path::new(POSTGRESQL_ROOT).join(resource_key(&request.durable.resource)?);
        protected_directory(Path::new(SOCKET_ROOT), 0, 0, 0o711)?;
        let run = Path::new(SOCKET_ROOT).join(format!("{:02}", binding.slot));
        protected_directory(
            &run,
            binding.uid,
            postgresql_probe_gid(binding.slot)?,
            0o2710,
        )?;
        let storage = PathBuf::from(&binding.storage_path);
        Ok(Self {
            state: request.resource.state_path.clone(),
            data: storage.join("data"),
            active_config: cluster.join("postgresql.conf"),
            active_hba: cluster.join("pg_hba.conf"),
            active_ident: cluster.join("pg_ident.conf"),
            final_config: cluster.join("postgresql.final.conf"),
            final_hba: cluster.join("pg_hba.final.conf"),
            final_ident: cluster.join("pg_ident.final.conf"),
            quarantine_config: cluster.join("postgresql.quarantine.conf"),
            quarantine_hba: cluster.join("pg_hba.quarantine.conf"),
            quarantine_ident: cluster.join("pg_ident.quarantine.conf"),
            cluster,
            storage,
            run,
        })
    }
}

struct QualificationRef<'a> {
    cluster: &'a str,
    control: &'a ArtifactReference,
    database: &'a str,
    postgresql: &'a ArtifactReference,
    postgresql_major: u16,
    role: &'a str,
}

pub(super) fn execute_postgresql(
    request: &NativeHostRequest,
    runtime: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    let input: PostgresqlInput = decode_input(&request.durable.inputs, "PostgreSQL")?;
    match request.durable.method.as_str() {
        "materialize" => materialize(request, &input, runtime),
        "start" | "restart" => activate(request, &input, runtime),
        "stop" => stop(request, &input, runtime),
        "observe" => observe(request, &input, runtime),
        _ => Err(invalid("unsupported PostgreSQL method")),
    }
}

fn materialize(
    request: &NativeHostRequest,
    input: &PostgresqlInput,
    runtime: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    let binding = request
        .durable
        .storage_binding
        .as_ref()
        .ok_or_else(|| invalid("PostgreSQL materialization has no storage slot"))?;
    validate_binding(binding)?;
    scan_postgresql_ledger()?;
    let paths = PostgresqlPaths::new(request, binding)?;

    if let Some(state) = read_state_optional(&request.resource.state_path)? {
        authenticate_state_authority(request, &state)?;
        let existing = details(&state)?;
        validate_details_identity(&state, &existing)?;
        require_input(input, &existing)?;
        if state.revision == request.durable.revision
            && state.qualification == request.resource.spec.qualification
        {
            match existing.phase {
                PostgresqlPhase::Active => {
                    authenticate_candidates(&existing)?;
                    authenticate_active_files(&existing, true)?;
                    authenticate_pg_version(&existing)?;
                    let process = existing
                        .process
                        .as_ref()
                        .ok_or_else(|| invalid("active PostgreSQL has no process proof"))?;
                    match authenticate_process_proof(process, &existing) {
                        Ok(())
                            if authenticate_active(request, &state, &existing, runtime).is_ok() =>
                        {
                            return postgresql_record(
                                request,
                                input,
                                Some(&existing),
                                true,
                                Some(existing.configuration_revision.clone()),
                            );
                        }
                        Ok(()) => {
                            let mut recovering = existing;
                            recovering.phase = PostgresqlPhase::AuthenticatingStop;
                            write_details(request, &recovering)?;
                            return postgresql_record(
                                request,
                                input,
                                Some(&recovering),
                                false,
                                None,
                            );
                        }
                        Err(error) => {
                            if !recorded_process_is_absent(process)? {
                                return Err(error);
                            }
                            require_global_target_authority(
                                &existing.postgres_executable,
                                &existing.data_path,
                                &existing.active_config_path,
                                existing.uid,
                                existing.gid,
                                TargetProcessPolicy::Absent,
                            )?;
                            let mut recovering = existing;
                            recovering.process = None;
                            recovering.phase = PostgresqlPhase::StoppedForTransition;
                            write_details(request, &recovering)?;
                            return postgresql_record(
                                request,
                                input,
                                Some(&recovering),
                                false,
                                None,
                            );
                        }
                    }
                }
                PostgresqlPhase::Prepared => {
                    authenticate_candidates(&existing)?;
                    return postgresql_record(request, input, Some(&existing), false, None);
                }
                PostgresqlPhase::Preparing => {
                    return finish_preparation(request, input, existing, &paths, runtime);
                }
                PostgresqlPhase::Stopped => {
                    authenticate_candidates(&existing)?;
                    authenticate_active_files(&existing, true)?;
                    authenticate_pg_version(&existing)?;
                    let mut recovering = existing;
                    recovering.phase = PostgresqlPhase::StoppedForTransition;
                    write_details(request, &recovering)?;
                    return postgresql_record(request, input, Some(&recovering), false, None);
                }
                _ => {
                    return postgresql_record(request, input, Some(&existing), false, None);
                }
            }
        }
    }

    let prior_active = authenticate_prior(request, input, binding, runtime)?;
    let mut desired = desired_details(request, input, binding, &paths, prior_active)?;
    desired.phase = PostgresqlPhase::Preparing;
    write_details(request, &desired)?;
    finish_preparation(request, input, desired, &paths, runtime)
}

fn finish_preparation(
    request: &NativeHostRequest,
    input: &PostgresqlInput,
    mut desired: PostgresqlStateDetails,
    paths: &PostgresqlPaths,
    runtime: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    require_global_target_authority(
        &desired.postgres_executable,
        &desired.data_path,
        &desired.active_config_path,
        desired.uid,
        desired.gid,
        TargetProcessPolicy::Absent,
    )?;
    ensure_directory(paths.cluster.as_path(), desired.uid, desired.gid, 0o700)?;
    control::prepare(&request.durable.platform, paths, &desired, runtime)?;
    authenticate_candidates(&desired)?;
    authenticate_pg_version(&desired)?;
    desired.phase = PostgresqlPhase::Prepared;
    write_details(request, &desired)?;
    postgresql_record(request, input, Some(&desired), false, None)
}

fn activate(
    request: &NativeHostRequest,
    input: &PostgresqlInput,
    runtime: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    let state = require_state(request)?;
    authenticate_state_authority(request, &state)?;
    if state.revision != request.durable.revision
        || state.qualification != request.resource.spec.qualification
    {
        return Err(invalid(
            "PostgreSQL activation has stale prepared authority",
        ));
    }
    let mut current = details(&state)?;
    validate_details_identity(&state, &current)?;
    require_input(input, &current)?;

    loop {
        match current.phase {
            PostgresqlPhase::Preparing => {
                return Err(invalid("PostgreSQL preparation is incomplete"));
            }
            PostgresqlPhase::Prepared | PostgresqlPhase::AuthenticatingStop => {
                if let Some(prior) = current.prior_active.clone() {
                    current.phase = PostgresqlPhase::AuthenticatingStop;
                    write_details(request, &current)?;
                    authenticate_and_stop_prior(request, &prior, runtime)?;
                } else {
                    authenticate_and_stop_desired(request, &mut current, runtime)?;
                }
                current.phase = PostgresqlPhase::StoppedForTransition;
                write_details(request, &current)?;
            }
            PostgresqlPhase::StoppedForTransition | PostgresqlPhase::RevalidatingCandidates => {
                current.phase = PostgresqlPhase::RevalidatingCandidates;
                write_details(request, &current)?;
                authenticate_and_stop_desired(request, &mut current, runtime)?;
                authenticate_candidates(&current)?;
                current.phase = PostgresqlPhase::OpeningCredential;
                write_details(request, &current)?;
            }
            PostgresqlPhase::OpeningCredential => {
                let _secret = load_secret(&current)?;
                current.process = None;
                current.phase = PostgresqlPhase::QuarantineStarting;
                write_details(request, &current)?;
            }
            PostgresqlPhase::QuarantineStarting => {
                require_global_target_authority(
                    &current.postgres_executable,
                    &current.data_path,
                    &current.active_config_path,
                    current.uid,
                    current.gid,
                    start_adoption_policy(current.phase)?,
                )?;
                let process = control::lifecycle(
                    &request.durable.platform,
                    &current,
                    "quarantine-start",
                    runtime,
                )?
                .ok_or_else(|| invalid("quarantine start returned no process proof"))?;
                authenticate_process_proof(&process, &current)?;
                current.process = Some(process);
                authenticate_active_files(&current, false)?;
                current.phase = PostgresqlPhase::QuarantineActive;
                write_details(request, &current)?;
            }
            PostgresqlPhase::QuarantineActive | PostgresqlPhase::Repairing => {
                current.phase = PostgresqlPhase::Repairing;
                write_details(request, &current)?;
                let secret = load_secret(&current)?;
                let proof = control::repair(
                    &request.durable.platform,
                    &current,
                    secret.as_deref().map(Vec::as_slice),
                    runtime,
                )?;
                validate_repair_proof(&proof, current.auth)?;
                current.role_verifier_digest = proof.role_verifier_digest;
                current.phase = PostgresqlPhase::Repaired;
                write_details(request, &current)?;
            }
            PostgresqlPhase::Repaired | PostgresqlPhase::QuarantineStopping => {
                current.phase = PostgresqlPhase::QuarantineStopping;
                write_details(request, &current)?;
                require_empty_lifecycle(control::lifecycle(
                    &request.durable.platform,
                    &current,
                    "stop",
                    runtime,
                )?)?;
                authenticate_and_stop_desired(request, &mut current, runtime)?;
                current.phase = PostgresqlPhase::QuarantineStopped;
                write_details(request, &current)?;
            }
            PostgresqlPhase::QuarantineStopped | PostgresqlPhase::PublishingFinal => {
                current.phase = PostgresqlPhase::PublishingFinal;
                write_details(request, &current)?;
                authenticate_and_stop_desired(request, &mut current, runtime)?;
                authenticate_candidates(&current)?;
                require_empty_lifecycle(control::lifecycle(
                    &request.durable.platform,
                    &current,
                    "publish-final",
                    runtime,
                )?)?;
                authenticate_active_files(&current, true)?;
                current.phase = PostgresqlPhase::FinalPublished;
                write_details(request, &current)?;
            }
            PostgresqlPhase::FinalPublished | PostgresqlPhase::FinalStarting => {
                if current.phase == PostgresqlPhase::FinalPublished {
                    current.process = None;
                    current.phase = PostgresqlPhase::FinalStarting;
                    write_details(request, &current)?;
                }
                require_global_target_authority(
                    &current.postgres_executable,
                    &current.data_path,
                    &current.active_config_path,
                    current.uid,
                    current.gid,
                    start_adoption_policy(current.phase)?,
                )?;
                let process = control::lifecycle(
                    &request.durable.platform,
                    &current,
                    "start-final",
                    runtime,
                )?
                .ok_or_else(|| invalid("final start returned no process proof"))?;
                authenticate_process_proof(&process, &current)?;
                current.process = Some(process);
                authenticate_active_files(&current, true)?;
                current.phase = PostgresqlPhase::FinalStarted;
                write_details(request, &current)?;
            }
            PostgresqlPhase::FinalStarted => {
                let proof = require_running_authentication(control::authenticate(
                    &request.durable.platform,
                    &ServerTarget::desired(&current),
                    false,
                    runtime,
                )?)?;
                validate_desired_server_proof(&proof, &current, false)?;
                let secret = load_secret(&current)?;
                let application = control::observe(
                    &request.durable.platform,
                    &current,
                    secret.as_deref().map(Vec::as_slice),
                    runtime,
                )?;
                validate_application_proof(&application, &current)?;
                install_active_proof(&mut current, &proof)?;
                current.phase = PostgresqlPhase::Active;
                write_details(request, &current)?;
            }
            PostgresqlPhase::Active => {
                let state = state_with_details(request, &current)?;
                authenticate_active(request, &state, &current, runtime)?;
                return postgresql_record(
                    request,
                    input,
                    Some(&current),
                    true,
                    Some(current.configuration_revision.clone()),
                );
            }
            PostgresqlPhase::Stopping | PostgresqlPhase::Stopped => {
                return Err(invalid(
                    "stopped PostgreSQL must be materialized before activation",
                ));
            }
        }
    }
}

fn stop(
    request: &NativeHostRequest,
    input: &PostgresqlInput,
    runtime: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    let state = require_state(request)?;
    authenticate_state_authority(request, &state)?;
    let mut current = details(&state)?;
    validate_details_identity(&state, &current)?;
    require_input(input, &current)?;
    if current.phase == PostgresqlPhase::Stopped {
        authenticate_and_stop_desired(request, &mut current, runtime)?;
        return postgresql_record(request, input, Some(&current), false, None);
    }
    if current.phase != PostgresqlPhase::Active && current.phase != PostgresqlPhase::Stopping {
        return Err(invalid(
            "PostgreSQL activation must settle before logical stop",
        ));
    }
    current.phase = PostgresqlPhase::Stopping;
    write_details(request, &current)?;
    authenticate_and_stop_desired(request, &mut current, runtime)?;
    current.phase = PostgresqlPhase::Stopped;
    write_details(request, &current)?;
    postgresql_record(request, input, Some(&current), false, None)
}

fn observe(
    request: &NativeHostRequest,
    input: &PostgresqlInput,
    runtime: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    let state = super::require_current_state(request)?;
    authenticate_state_authority(request, &state)?;
    let current = details(&state)?;
    validate_details_identity(&state, &current)?;
    require_input(input, &current)?;
    if current.phase != PostgresqlPhase::Active {
        return Err(invalid("PostgreSQL readiness is not active"));
    }
    authenticate_active(request, &state, &current, runtime)?;
    postgresql_record(
        request,
        input,
        Some(&current),
        true,
        Some(current.configuration_revision.clone()),
    )
}

pub(super) fn postgresql_health(
    spec: &super::NativeHostResourceSpec,
    state: &HostState,
    platform: &super::platform::NativePlatformTools,
    runtime: &dyn RuntimeControl,
) -> Result<RuntimeResourceHealth, io::Error> {
    let current = details(state)?;
    validate_details_identity(state, &current)?;
    match current.phase {
        PostgresqlPhase::Active => {
            let request = synthetic_request(spec, state, platform)?;
            Ok(
                if authenticate_active(&request, state, &current, runtime).is_ok() {
                    RuntimeResourceHealth::Healthy
                } else {
                    RuntimeResourceHealth::Divergent
                },
            )
        }
        PostgresqlPhase::Stopped
            if current.process.is_none()
                && !Path::new(&current.data_path)
                    .join("postmaster.pid")
                    .try_exists()? =>
        {
            Ok(RuntimeResourceHealth::Stopped)
        }
        _ => Ok(RuntimeResourceHealth::Divergent),
    }
}

fn desired_details(
    request: &NativeHostRequest,
    input: &PostgresqlInput,
    binding: &StorageBinding,
    paths: &PostgresqlPaths,
    prior_active: Option<PostgresqlActiveSnapshot>,
) -> Result<PostgresqlStateDetails, io::Error> {
    let qualification = qualification(&request.resource.spec.qualification)?;
    let credential_view = input
        .credential_view
        .as_ref()
        .ok_or_else(|| invalid("PostgreSQL materialization has no credential view"))?;
    let credential = Some(authenticate_credential_marker(
        Path::new(&credential_view.path),
        &credential_view.version,
        None,
    )?);
    let auth = PostgresqlAuth::Scram;
    let candidates = render::candidates(paths, input, binding, auth)?;
    let endpoint_resource = request
        .durable
        .dependencies
        .iter()
        .find(|dependency| dependency.input == "endpoint")
        .map(|dependency| dependency.resource.clone())
        .ok_or_else(|| invalid("PostgreSQL materialization has no endpoint producer"))?;
    Ok(PostgresqlStateDetails {
        phase: PostgresqlPhase::Preparing,
        auth,
        slot: binding.slot,
        uid: binding.uid,
        gid: binding.gid,
        principal: binding.principal.clone(),
        probe_uid: postgresql_probe_uid(binding.slot)?,
        probe_gid: postgresql_probe_gid(binding.slot)?,
        probe_principal: postgresql_probe_principal(binding.slot)?,
        cluster: input.cluster.clone(),
        cluster_root: path_text(&paths.cluster)?,
        state_path: path_text(&paths.state)?,
        storage_resource: binding.storage_resource.clone(),
        endpoint_resource,
        storage_path: path_text(&paths.storage)?,
        data_path: path_text(&paths.data)?,
        run_path: path_text(&paths.run)?,
        active_config_path: path_text(&paths.active_config)?,
        active_hba_path: path_text(&paths.active_hba)?,
        active_ident_path: path_text(&paths.active_ident)?,
        final_config_path: path_text(&paths.final_config)?,
        final_hba_path: path_text(&paths.final_hba)?,
        final_ident_path: path_text(&paths.final_ident)?,
        quarantine_config_path: path_text(&paths.quarantine_config)?,
        quarantine_hba_path: path_text(&paths.quarantine_hba)?,
        quarantine_ident_path: path_text(&paths.quarantine_ident)?,
        configuration_revision: input.configuration_revision.clone(),
        database: input.database.clone(),
        role: input.role.clone(),
        endpoint: input
            .endpoint
            .clone()
            .ok_or_else(|| invalid("PostgreSQL materialization has no endpoint"))?,
        server_port: 20_000_u16
            .checked_add(u16::from(binding.slot))
            .ok_or_else(|| invalid("PostgreSQL internal port overflowed"))?,
        credential,
        control: qualification.control.clone(),
        postgresql: qualification.postgresql.clone(),
        postgres_executable: artifact_executable(qualification.postgresql, "bin/postgres")?,
        postgresql_major: qualification.postgresql_major,
        pg_version: None,
        data_system_identifier: None,
        final_config_digest: Sha256Digest::of_bytes(&candidates.final_config),
        final_hba_digest: Sha256Digest::of_bytes(&candidates.final_hba),
        final_ident_digest: Sha256Digest::of_bytes(&candidates.final_ident),
        quarantine_config_digest: Sha256Digest::of_bytes(&candidates.quarantine_config),
        quarantine_hba_digest: Sha256Digest::of_bytes(&candidates.quarantine_hba),
        quarantine_ident_digest: Sha256Digest::of_bytes(&candidates.quarantine_ident),
        active_config_digest: None,
        active_hba_digest: None,
        active_ident_digest: None,
        role_verifier_digest: None,
        process: None,
        prior_active,
    })
}

fn authenticate_prior(
    request: &NativeHostRequest,
    input: &PostgresqlInput,
    binding: &StorageBinding,
    runtime: &dyn RuntimeControl,
) -> Result<Option<PostgresqlActiveSnapshot>, io::Error> {
    let Some(state) = read_state_optional(&request.resource.state_path)? else {
        let cluster = Path::new(POSTGRESQL_ROOT).join(resource_key(&request.durable.resource)?);
        if fs::symlink_metadata(cluster).is_ok() {
            return Err(invalid(
                "PostgreSQL cluster exists without an ownership marker",
            ));
        }
        return Ok(None);
    };
    authenticate_state_authority(request, &state)?;
    let current = details(&state)?;
    validate_details_identity(&state, &current)?;
    if current.database != input.database
        || current.role != input.role
        || current.storage_resource != binding.storage_resource
        || current.storage_path != binding.storage_path
        || current.slot != binding.slot
    {
        return Err(invalid("retained PostgreSQL stable identity changed"));
    }
    match current.phase {
        PostgresqlPhase::Active => {
            authenticate_candidates(&current)?;
            authenticate_active_files(&current, true)?;
            authenticate_pg_version(&current)?;
            let process = current
                .process
                .as_ref()
                .ok_or_else(|| invalid("active PostgreSQL has no process proof"))?;
            match authenticate_process_proof(process, &current) {
                Ok(()) => Ok(Some(active_snapshot(&state, &current)?)),
                Err(error) => {
                    if !recorded_process_is_absent(process)? {
                        return Err(error);
                    }
                    require_global_target_authority(
                        &current.postgres_executable,
                        &current.data_path,
                        &current.active_config_path,
                        current.uid,
                        current.gid,
                        TargetProcessPolicy::Absent,
                    )?;
                    Ok(None)
                }
            }
        }
        PostgresqlPhase::Stopped => {
            authenticate_and_stop_desired(request, &mut current.clone(), runtime)?;
            Ok(None)
        }
        _ => Err(invalid(
            "retained PostgreSQL transition must settle before a new revision",
        )),
    }
}

fn authenticate_active(
    request: &NativeHostRequest,
    state: &HostState,
    current: &PostgresqlStateDetails,
    runtime: &dyn RuntimeControl,
) -> Result<ServerProof, io::Error> {
    let proof = authenticate_server_active(request, state, current, runtime, false)?;
    let secret = load_secret(current)?;
    let application = control::observe(
        &request.durable.platform,
        current,
        secret.as_deref().map(Vec::as_slice),
        runtime,
    )?;
    validate_application_proof(&application, current)?;
    Ok(proof)
}

fn authenticate_server_active(
    request: &NativeHostRequest,
    state: &HostState,
    current: &PostgresqlStateDetails,
    runtime: &dyn RuntimeControl,
    allow_verifier_drift: bool,
) -> Result<ServerProof, io::Error> {
    validate_details_identity(state, current)?;
    authenticate_candidates(current)?;
    authenticate_active_files(current, true)?;
    require_global_target_authority(
        &current.postgres_executable,
        &current.data_path,
        &current.active_config_path,
        current.uid,
        current.gid,
        current
            .process
            .as_ref()
            .map_or(TargetProcessPolicy::Absent, TargetProcessPolicy::Expected),
    )?;
    let proof = require_running_authentication(control::authenticate(
        &request.durable.platform,
        &ServerTarget::desired(current),
        false,
        runtime,
    )?)?;
    validate_desired_server_proof(&proof, current, allow_verifier_drift)?;
    Ok(proof)
}

fn require_running_authentication(
    outcome: AuthenticationOutcome,
) -> Result<ServerProof, io::Error> {
    match outcome {
        AuthenticationOutcome::Running(proof) => Ok(proof),
        AuthenticationOutcome::RunningStop(_) | AuthenticationOutcome::Stopped => Err(invalid(
            "PostgreSQL control reported a stopped server where running proof was required",
        )),
    }
}

fn require_empty_lifecycle(proof: Option<ProcessProof>) -> Result<(), io::Error> {
    if proof.is_some() {
        return Err(invalid(
            "PostgreSQL non-start lifecycle returned a process proof",
        ));
    }
    Ok(())
}

fn authenticate_and_stop_prior(
    request: &NativeHostRequest,
    prior: &PostgresqlActiveSnapshot,
    runtime: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    require_global_target_authority(
        &prior.postgres_executable,
        &prior.data_path,
        &prior.active_config_path,
        prior.uid,
        prior.gid,
        TargetProcessPolicy::Expected(&prior.process),
    )?;
    let target = ServerTarget::prior(prior);
    match control::authenticate(&request.durable.platform, &target, true, runtime)? {
        AuthenticationOutcome::RunningStop(proof) => {
            validate_prior_stop_proof(&proof, prior)?;
            validate_process_proof_fields(
                &proof.process,
                Some(&prior.process),
                &prior.postgres_executable,
                &prior.data_path,
                &prior.active_config_path,
                prior.uid,
                prior.gid,
            )?;
        }
        AuthenticationOutcome::Running(_) => {
            return Err(invalid("PostgreSQL stop returned an active proof"));
        }
        AuthenticationOutcome::Stopped => {
            return require_global_target_authority(
                &prior.postgres_executable,
                &prior.data_path,
                &prior.active_config_path,
                prior.uid,
                prior.gid,
                TargetProcessPolicy::Absent,
            );
        }
    }
    if !matches!(
        control::authenticate(&request.durable.platform, &target, true, runtime)?,
        AuthenticationOutcome::Stopped
    ) {
        return Err(invalid("retained PostgreSQL server remained after stop"));
    }
    require_global_target_authority(
        &prior.postgres_executable,
        &prior.data_path,
        &prior.active_config_path,
        prior.uid,
        prior.gid,
        TargetProcessPolicy::Absent,
    )
}

fn authenticate_and_stop_desired(
    request: &NativeHostRequest,
    current: &mut PostgresqlStateDetails,
    runtime: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    require_global_target_authority(
        &current.postgres_executable,
        &current.data_path,
        &current.active_config_path,
        current.uid,
        current.gid,
        current
            .process
            .as_ref()
            .map_or(TargetProcessPolicy::Absent, TargetProcessPolicy::Expected),
    )?;
    let outcome = control::authenticate(
        &request.durable.platform,
        &ServerTarget::desired(current),
        true,
        runtime,
    )?;
    let proof = match outcome {
        AuthenticationOutcome::RunningStop(proof) => proof,
        AuthenticationOutcome::Stopped => {
            current.process = None;
            return require_global_target_authority(
                &current.postgres_executable,
                &current.data_path,
                &current.active_config_path,
                current.uid,
                current.gid,
                TargetProcessPolicy::Absent,
            );
        }
        AuthenticationOutcome::Running(_) => {
            return Err(invalid("PostgreSQL stop returned an active proof"));
        }
    };
    if current.process.is_none() {
        return Err(invalid(
            "running PostgreSQL server has no persisted process authority",
        ));
    }
    validate_desired_stop_proof(&proof, current)?;
    validate_process_proof_fields(
        &proof.process,
        current.process.as_ref(),
        &current.postgres_executable,
        &current.data_path,
        &current.active_config_path,
        current.uid,
        current.gid,
    )?;
    current.process = Some(proof.process);
    if !matches!(
        control::authenticate(
            &request.durable.platform,
            &ServerTarget::desired(current),
            true,
            runtime,
        )?,
        AuthenticationOutcome::Stopped
    ) {
        return Err(invalid("PostgreSQL server remained after stop"));
    }
    current.process = None;
    require_global_target_authority(
        &current.postgres_executable,
        &current.data_path,
        &current.active_config_path,
        current.uid,
        current.gid,
        TargetProcessPolicy::Absent,
    )
}

fn active_snapshot(
    state: &HostState,
    current: &PostgresqlStateDetails,
) -> Result<PostgresqlActiveSnapshot, io::Error> {
    let pg_version = current
        .pg_version
        .clone()
        .ok_or_else(|| invalid("active PostgreSQL has no data version"))?;
    let data_system_identifier = current
        .data_system_identifier
        .clone()
        .ok_or_else(|| invalid("active PostgreSQL has no system identifier"))?;
    let process = current
        .process
        .clone()
        .ok_or_else(|| invalid("active PostgreSQL has no process proof"))?;
    Ok(PostgresqlActiveSnapshot {
        operation_revision: state.revision,
        qualification: state.qualification.clone(),
        configuration_revision: current.configuration_revision.clone(),
        resource: state.resource.clone(),
        control: current.control.clone(),
        postgresql: current.postgresql.clone(),
        postgres_executable: current.postgres_executable.clone(),
        postgresql_major: current.postgresql_major,
        pg_version,
        data_system_identifier,
        slot: current.slot,
        uid: current.uid,
        gid: current.gid,
        principal: current.principal.clone(),
        probe_uid: current.probe_uid,
        probe_gid: current.probe_gid,
        probe_principal: current.probe_principal.clone(),
        cluster: current.cluster.clone(),
        cluster_root: current.cluster_root.clone(),
        state_path: current.state_path.clone(),
        storage_resource: current.storage_resource.clone(),
        endpoint_resource: current.endpoint_resource.clone(),
        storage_path: current.storage_path.clone(),
        data_path: current.data_path.clone(),
        run_path: current.run_path.clone(),
        active_config_path: current.active_config_path.clone(),
        active_hba_path: current.active_hba_path.clone(),
        active_ident_path: current.active_ident_path.clone(),
        endpoint: current.endpoint.clone(),
        server_port: current.server_port,
        database: current.database.clone(),
        role: current.role.clone(),
        auth: current.auth,
        credential: current.credential.clone(),
        active_config_digest: digest_file(&current.active_config_path, current.uid)?,
        active_hba_digest: digest_file(&current.active_hba_path, current.uid)?,
        active_ident_digest: digest_file(&current.active_ident_path, current.uid)?,
        role_verifier_digest: current.role_verifier_digest,
        process,
    })
}

fn install_active_proof(
    current: &mut PostgresqlStateDetails,
    proof: &ServerProof,
) -> Result<(), io::Error> {
    current.pg_version = Some(proof.pg_version.clone());
    current.data_system_identifier = Some(proof.data_system_identifier.clone());
    current.active_config_digest = Some(digest_file(&current.active_config_path, current.uid)?);
    current.active_hba_digest = Some(digest_file(&current.active_hba_path, current.uid)?);
    current.active_ident_digest = Some(digest_file(&current.active_ident_path, current.uid)?);
    current.role_verifier_digest = proof.role_verifier_digest;
    current.process = Some(proof.process.clone());
    Ok(())
}

fn validate_desired_server_proof(
    proof: &ServerProof,
    current: &PostgresqlStateDetails,
    allow_verifier_drift: bool,
) -> Result<(), io::Error> {
    validate_server_identity(
        proof,
        &current.configuration_revision,
        &current.role,
        current.postgresql_major,
        &current.postgres_executable,
        current.auth,
    )?;
    if current
        .pg_version
        .as_ref()
        .is_some_and(|version| version != &proof.pg_version)
        || current
            .data_system_identifier
            .as_ref()
            .is_some_and(|identifier| identifier != &proof.data_system_identifier)
        || !allow_verifier_drift
            && current.role_verifier_digest.is_some()
            && current.role_verifier_digest != proof.role_verifier_digest
    {
        return Err(invalid(
            "PostgreSQL server identity changed from durable state",
        ));
    }
    Ok(())
}

fn validate_prior_stop_proof(
    proof: &StopProof,
    prior: &PostgresqlActiveSnapshot,
) -> Result<(), io::Error> {
    validate_stop_proof_core(
        proof,
        &prior.configuration_revision,
        &prior.role,
        &prior.database,
        prior.postgresql_major,
        &prior.postgres_executable,
        &prior.pg_version,
        &prior.data_system_identifier,
    )
}

fn validate_desired_stop_proof(
    proof: &StopProof,
    current: &PostgresqlStateDetails,
) -> Result<(), io::Error> {
    let pg_version = current
        .pg_version
        .as_deref()
        .ok_or_else(|| invalid("PostgreSQL stop has no persisted data version"))?;
    let system_identifier = current
        .data_system_identifier
        .as_deref()
        .ok_or_else(|| invalid("PostgreSQL stop has no persisted system identifier"))?;
    validate_stop_proof_core(
        proof,
        &current.configuration_revision,
        &current.role,
        &current.database,
        current.postgresql_major,
        &current.postgres_executable,
        pg_version,
        system_identifier,
    )
}

fn validate_stop_proof_core(
    proof: &StopProof,
    configuration_revision: &str,
    role: &str,
    database: &str,
    major: u16,
    executable: &str,
    pg_version: &str,
    system_identifier: &str,
) -> Result<(), io::Error> {
    if proof.schema != "aos.postgresql.control-authenticate-stop/v1"
        || proof.configuration_revision != configuration_revision
        || proof.current_user != ADMIN_ROLE
        || proof.requested_role != role
        || proof.requested_database != database
        || proof.postgresql_major != major
        || proof.pg_version != pg_version
        || proof.pg_version != major.to_string()
        || proof.data_system_identifier != system_identifier
        || proof.data_system_identifier.parse::<u64>().is_err()
        || proof.postgres_executable != executable
        || proof.role_exists
            && [
                proof.login,
                proof.inherit,
                proof.superuser,
                proof.createdb,
                proof.createrole,
                proof.replication,
                proof.bypassrls,
            ]
            .iter()
            .any(Option::is_none)
        || !proof.role_exists
            && (proof.login.is_some()
                || proof.inherit.is_some()
                || proof.superuser.is_some()
                || proof.createdb.is_some()
                || proof.createrole.is_some()
                || proof.replication.is_some()
                || proof.bypassrls.is_some()
                || proof.role_verifier_digest.is_some())
        || proof.database_exists != proof.database_owner.is_some()
    {
        return Err(invalid("PostgreSQL stop proof has another server identity"));
    }
    Ok(())
}

fn validate_server_identity(
    proof: &ServerProof,
    configuration_revision: &str,
    role: &str,
    major: u16,
    executable: &str,
    auth: PostgresqlAuth,
) -> Result<(), io::Error> {
    if proof.configuration_revision != configuration_revision
        || proof.current_user != ADMIN_ROLE
        || proof.role != role
        || !proof.login
        || proof.inherit
        || proof.memberships != 0
        || proof.superuser
        || proof.createdb
        || proof.createrole
        || proof.replication
        || proof.bypassrls
        || proof.database_owner != role
        || proof.postgresql_major != major
        || proof.pg_version != major.to_string()
        || proof.data_system_identifier.parse::<u64>().is_err()
        || proof.postgres_executable != executable
        || auth == PostgresqlAuth::Scram && proof.role_verifier_digest.is_none()
    {
        return Err(invalid(
            "PostgreSQL server proof is not the exact desired identity",
        ));
    }
    Ok(())
}

fn validate_repair_proof(
    proof: &control::RepairProof,
    auth: PostgresqlAuth,
) -> Result<(), io::Error> {
    if auth == PostgresqlAuth::Scram && proof.role_verifier_digest.is_none() {
        return Err(invalid(
            "PostgreSQL repair produced the wrong verifier state",
        ));
    }
    Ok(())
}

fn validate_application_proof(
    proof: &ApplicationProof,
    current: &PostgresqlStateDetails,
) -> Result<(), io::Error> {
    if proof.configuration_revision != current.configuration_revision
        || proof.current_user != current.role
        || proof.role != current.role
        || !proof.login
        || proof.inherit
        || proof.memberships != 0
        || proof.superuser
        || proof.createdb
        || proof.createrole
        || proof.replication
        || proof.bypassrls
        || proof.database_owner != current.role
        || proof.role_verifier_digest.is_some()
    {
        return Err(invalid(
            "PostgreSQL application proof is not the desired identity",
        ));
    }
    Ok(())
}

fn authenticate_candidates(current: &PostgresqlStateDetails) -> Result<(), io::Error> {
    require_digest(
        &current.final_config_path,
        current.uid,
        current.final_config_digest,
    )?;
    require_digest(
        &current.final_hba_path,
        current.uid,
        current.final_hba_digest,
    )?;
    require_digest(
        &current.final_ident_path,
        current.uid,
        current.final_ident_digest,
    )?;
    require_digest(
        &current.quarantine_config_path,
        current.uid,
        current.quarantine_config_digest,
    )?;
    require_digest(
        &current.quarantine_hba_path,
        current.uid,
        current.quarantine_hba_digest,
    )?;
    require_digest(
        &current.quarantine_ident_path,
        current.uid,
        current.quarantine_ident_digest,
    )
}

fn authenticate_active_files(
    current: &PostgresqlStateDetails,
    final_set: bool,
) -> Result<(), io::Error> {
    let expected = if final_set {
        (
            current.final_config_digest,
            current.final_hba_digest,
            current.final_ident_digest,
        )
    } else {
        (
            current.quarantine_config_digest,
            current.quarantine_hba_digest,
            current.quarantine_ident_digest,
        )
    };
    require_digest(&current.active_config_path, current.uid, expected.0)?;
    require_digest(&current.active_hba_path, current.uid, expected.1)?;
    require_digest(&current.active_ident_path, current.uid, expected.2)
}

fn authenticate_pg_version(current: &PostgresqlStateDetails) -> Result<(), io::Error> {
    let bytes = read_protected_file(
        &Path::new(&current.data_path).join("PG_VERSION"),
        32,
        current.uid,
        0o600,
    )?;
    if bytes != format!("{}\n", current.postgresql_major).as_bytes() {
        return Err(invalid("PostgreSQL data has another major version"));
    }
    Ok(())
}

fn load_secret(current: &PostgresqlStateDetails) -> Result<Option<Zeroizing<Vec<u8>>>, io::Error> {
    let Some(expected) = &current.credential else {
        return Ok(None);
    };
    let (evidence, secret) =
        authenticate_credential_view(Path::new(&expected.view_path), &expected.version)?;
    if evidence != *expected {
        return Err(invalid("PostgreSQL credential evidence changed"));
    }
    Ok(Some(secret))
}

fn require_digest(path: &str, uid: u32, expected: Sha256Digest) -> Result<(), io::Error> {
    if digest_file(path, uid)? != expected {
        return Err(invalid("PostgreSQL file differs from its durable digest"));
    }
    Ok(())
}

fn digest_file(path: &str, uid: u32) -> Result<Sha256Digest, io::Error> {
    let bytes = read_protected_file(Path::new(path), MAX_POSTGRESQL_FILE_BYTES, uid, 0o600)?;
    Ok(Sha256Digest::of_bytes(bytes))
}
