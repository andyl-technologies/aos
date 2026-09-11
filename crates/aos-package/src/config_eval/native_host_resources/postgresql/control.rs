//! Bounded transport for the signed, permanently unprivileged PostgreSQL control.

use std::io;
use std::path::Path;

use aos_ability_model::ArtifactReference;
use aos_ability_runtime::adapter::RuntimeControl;
use aos_contract::Sha256Digest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::super::process::{DescendantPolicy, run_bounded};
use super::{
    PostgresqlActiveSnapshot, PostgresqlAuth, PostgresqlPaths, PostgresqlStateDetails,
    artifact_executable, invalid, store_error,
};

const MAX_CONTROL_OUTPUT: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerProof {
    pub(super) schema: String,
    pub(super) configuration_revision: String,
    pub(super) current_user: String,
    pub(super) role: String,
    pub(super) login: bool,
    pub(super) inherit: bool,
    pub(super) memberships: u64,
    pub(super) superuser: bool,
    pub(super) createdb: bool,
    pub(super) createrole: bool,
    pub(super) replication: bool,
    pub(super) bypassrls: bool,
    pub(super) database_owner: String,
    pub(super) role_verifier_digest: Option<Sha256Digest>,
    pub(super) postgresql_major: u16,
    pub(super) pg_version: String,
    pub(super) data_system_identifier: String,
    pub(super) postgres_executable: String,
    pub(super) process: ProcessProof,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct StopProof {
    pub(super) schema: String,
    pub(super) configuration_revision: String,
    pub(super) current_user: String,
    pub(super) requested_role: String,
    pub(super) requested_database: String,
    pub(super) role_exists: bool,
    pub(super) database_exists: bool,
    pub(super) login: Option<bool>,
    pub(super) inherit: Option<bool>,
    pub(super) superuser: Option<bool>,
    pub(super) createdb: Option<bool>,
    pub(super) createrole: Option<bool>,
    pub(super) replication: Option<bool>,
    pub(super) bypassrls: Option<bool>,
    pub(super) memberships: u64,
    pub(super) database_owner: Option<String>,
    pub(super) role_verifier_digest: Option<Sha256Digest>,
    pub(super) postgresql_major: u16,
    pub(super) pg_version: String,
    pub(super) data_system_identifier: String,
    pub(super) postgres_executable: String,
    pub(super) process: ProcessProof,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessProof {
    pub(super) schema: String,
    pub(super) boot_id: String,
    pub(super) pid: u32,
    pub(super) process_group: u32,
    pub(super) start_time: u64,
    pub(super) executable: String,
    pub(super) arguments: Vec<String>,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) groups: Vec<u32>,
    pub(super) no_new_privileges: bool,
    pub(super) capabilities: CapabilityProof,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CapabilityProof {
    pub(super) inheritable: String,
    pub(super) permitted: String,
    pub(super) effective: String,
    pub(super) bounding: String,
    pub(super) ambient: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct StoppedProof {
    schema: String,
    running: bool,
}

pub(super) enum AuthenticationOutcome {
    Running(ServerProof),
    RunningStop(StopProof),
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RepairProof {
    pub(super) schema: String,
    pub(super) role_verifier_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationProof {
    pub(super) schema: String,
    pub(super) configuration_revision: String,
    pub(super) current_user: String,
    pub(super) role: String,
    pub(super) login: bool,
    pub(super) inherit: bool,
    pub(super) memberships: u64,
    pub(super) superuser: bool,
    pub(super) createdb: bool,
    pub(super) createrole: bool,
    pub(super) replication: bool,
    pub(super) bypassrls: bool,
    pub(super) database_owner: String,
    pub(super) role_verifier_digest: Option<Sha256Digest>,
}

pub(super) struct ServerTarget<'a> {
    pub(super) control: &'a ArtifactReference,
    pub(super) postgresql: &'a ArtifactReference,
    pub(super) slot: u8,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) data: &'a str,
    pub(super) cluster: &'a str,
    pub(super) run: &'a str,
    pub(super) port: u16,
    pub(super) configuration_revision: &'a str,
    pub(super) database: &'a str,
    pub(super) role: &'a str,
    pub(super) auth: PostgresqlAuth,
    pub(super) expected_process: Option<&'a ProcessProof>,
}

impl<'a> ServerTarget<'a> {
    pub(super) fn desired(details: &'a PostgresqlStateDetails) -> Self {
        Self {
            control: &details.control,
            postgresql: &details.postgresql,
            slot: details.slot,
            uid: details.uid,
            gid: details.gid,
            data: &details.data_path,
            cluster: &details.cluster_root,
            run: &details.run_path,
            port: details.server_port,
            configuration_revision: &details.configuration_revision,
            database: &details.database,
            role: &details.role,
            auth: details.auth,
            expected_process: details.process.as_ref(),
        }
    }

    pub(super) fn prior(snapshot: &'a PostgresqlActiveSnapshot) -> Self {
        Self {
            control: &snapshot.control,
            postgresql: &snapshot.postgresql,
            slot: snapshot.slot,
            uid: snapshot.uid,
            gid: snapshot.gid,
            data: &snapshot.data_path,
            cluster: &snapshot.cluster_root,
            run: &snapshot.run_path,
            port: snapshot.server_port,
            configuration_revision: &snapshot.configuration_revision,
            database: &snapshot.database,
            role: &snapshot.role,
            auth: snapshot.auth,
            expected_process: Some(&snapshot.process),
        }
    }
}

pub(super) fn prepare(
    platform: &super::super::platform::NativePlatformTools,
    paths: &PostgresqlPaths,
    details: &PostgresqlStateDetails,
    control: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    let target = ServerTarget::desired(details);
    let mut command = server_command(platform, &target)?;
    command.arg("prepare");
    append_server_identity(&mut command, &target);
    let output = run_bounded(
        &mut command,
        None,
        MAX_CONTROL_OUTPUT,
        DescendantPolicy::Reap,
        control,
    )?;
    require_empty_success(output.status.success(), &output.stdout)?;
    if paths.cluster.to_str() != Some(target.cluster) {
        return Err(invalid(
            "PostgreSQL control target changed during preparation",
        ));
    }
    Ok(())
}

pub(super) fn authenticate(
    platform: &super::super::platform::NativePlatformTools,
    target: &ServerTarget<'_>,
    stop: bool,
    control: &dyn RuntimeControl,
) -> Result<AuthenticationOutcome, io::Error> {
    let mode = if stop {
        "authenticate-stop"
    } else {
        "authenticate-active"
    };
    let mut command = server_command(platform, target)?;
    command.arg(mode);
    append_server_identity(&mut command, target);
    let output = run_bounded(
        &mut command,
        None,
        MAX_CONTROL_OUTPUT,
        DescendantPolicy::Reap,
        control,
    )?;
    require_success(output.status.success())?;
    let document = aos_contract::canonical::parse_json(&output.stdout, "PostgreSQL server proof")
        .map_err(store_error)?;
    let schema = document
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("PostgreSQL server proof has no schema"))?;
    if stop && schema == "aos.postgresql.control-authenticate-stopped/v1" {
        let proof: StoppedProof = serde_json::from_value(document)
            .map_err(|error| invalid(format!("invalid stopped proof: {error}")))?;
        if proof.running {
            return Err(invalid("stopped PostgreSQL proof reports a running server"));
        }
        return Ok(AuthenticationOutcome::Stopped);
    }
    if stop {
        let proof: StopProof = serde_json::from_value(document)
            .map_err(|error| invalid(format!("invalid PostgreSQL stop proof: {error}")))?;
        if proof.schema != "aos.postgresql.control-authenticate-stop/v1" {
            return Err(invalid("PostgreSQL stop proof has another schema"));
        }
        return Ok(AuthenticationOutcome::RunningStop(proof));
    }
    let proof: ServerProof = serde_json::from_value(document)
        .map_err(|error| invalid(format!("invalid PostgreSQL server proof: {error}")))?;
    if proof.schema != "aos.postgresql.control-authenticate-active/v1" {
        return Err(invalid("PostgreSQL server proof has another schema"));
    }
    Ok(AuthenticationOutcome::Running(proof))
}

pub(super) fn lifecycle(
    platform: &super::super::platform::NativePlatformTools,
    details: &PostgresqlStateDetails,
    mode: &str,
    control: &dyn RuntimeControl,
) -> Result<Option<ProcessProof>, io::Error> {
    if !matches!(
        mode,
        "quarantine-start" | "stop" | "publish-final" | "start-final"
    ) {
        return Err(invalid("unknown PostgreSQL lifecycle control mode"));
    }
    let target = ServerTarget::desired(details);
    let mut command = server_command(platform, &target)?;
    command.arg(mode);
    append_server_identity(&mut command, &target);
    if mode == "quarantine-start" {
        let prior = details.prior_active.as_ref();
        command
            .arg("--prior-config-digest")
            .arg(prior.map_or_else(
                || "absent".to_string(),
                |snapshot| snapshot.active_config_digest.to_string(),
            ))
            .arg("--prior-hba-digest")
            .arg(prior.map_or_else(
                || "absent".to_string(),
                |snapshot| snapshot.active_hba_digest.to_string(),
            ))
            .arg("--prior-ident-digest")
            .arg(prior.map_or_else(
                || "absent".to_string(),
                |snapshot| snapshot.active_ident_digest.to_string(),
            ));
    }
    let descendants = if matches!(mode, "quarantine-start" | "start-final") {
        DescendantPolicy::PreserveOnSuccess
    } else {
        DescendantPolicy::Reap
    };
    let output = run_bounded(&mut command, None, MAX_CONTROL_OUTPUT, descendants, control)?;
    require_success(output.status.success())?;
    if matches!(mode, "quarantine-start" | "start-final") {
        let proof: ProcessProof = decode(&output.stdout, "PostgreSQL process proof")?;
        if proof.schema != "aos.postgresql.control-process/v1" {
            return Err(invalid("PostgreSQL process proof has another schema"));
        }
        Ok(Some(proof))
    } else {
        require_empty_success(true, &output.stdout)?;
        Ok(None)
    }
}

pub(super) fn repair(
    platform: &super::super::platform::NativePlatformTools,
    details: &PostgresqlStateDetails,
    secret: Option<&[u8]>,
    control: &dyn RuntimeControl,
) -> Result<RepairProof, io::Error> {
    let target = ServerTarget::desired(details);
    let mut command = probe_command(platform, details)?;
    command
        .arg("repair")
        .arg("--slot")
        .arg(format!("{:02}", target.slot))
        .arg("--postgresql-artifact")
        .arg(&target.postgresql.store_path)
        .arg("--run-directory")
        .arg(target.run)
        .arg("--port")
        .arg(target.port.to_string())
        .arg("--database")
        .arg(target.database)
        .arg("--role")
        .arg(target.role)
        .arg("--configuration-revision")
        .arg(target.configuration_revision)
        .arg("--auth")
        .arg(details.auth.as_str());
    let output = run_bounded(
        &mut command,
        secret,
        MAX_CONTROL_OUTPUT,
        DescendantPolicy::Reap,
        control,
    )?;
    require_success(output.status.success())?;
    let proof: RepairProof = decode(&output.stdout, "PostgreSQL repair proof")?;
    if proof.schema != "aos.postgresql.control-repair/v1" {
        return Err(invalid("PostgreSQL repair proof has another schema"));
    }
    Ok(proof)
}

pub(super) fn observe(
    platform: &super::super::platform::NativePlatformTools,
    details: &PostgresqlStateDetails,
    secret: Option<&[u8]>,
    control: &dyn RuntimeControl,
) -> Result<ApplicationProof, io::Error> {
    let target = ServerTarget::desired(details);
    let mut command = probe_command(platform, details)?;
    command
        .arg("observe")
        .arg("--slot")
        .arg(format!("{:02}", target.slot))
        .arg("--postgresql-artifact")
        .arg(&target.postgresql.store_path)
        .arg("--address")
        .arg(&details.endpoint.address)
        .arg("--port")
        .arg(details.endpoint.port.to_string())
        .arg("--database")
        .arg(target.database)
        .arg("--role")
        .arg(target.role)
        .arg("--configuration-revision")
        .arg(target.configuration_revision)
        .arg("--auth")
        .arg(details.auth.as_str());
    let output = run_bounded(
        &mut command,
        secret,
        MAX_CONTROL_OUTPUT,
        DescendantPolicy::Reap,
        control,
    )?;
    require_success(output.status.success())?;
    let proof: ApplicationProof = decode(&output.stdout, "PostgreSQL application proof")?;
    if proof.schema != "aos.postgresql.control-observe/v1" {
        return Err(invalid("PostgreSQL application proof has another schema"));
    }
    Ok(proof)
}

fn server_command(
    platform: &super::super::platform::NativePlatformTools,
    target: &ServerTarget<'_>,
) -> Result<std::process::Command, io::Error> {
    let executable = artifact_executable(target.control, "bin/postgresql-control")?;
    Ok(platform.command_as(Path::new(&executable), target.uid, target.gid))
}

fn probe_command(
    platform: &super::super::platform::NativePlatformTools,
    details: &PostgresqlStateDetails,
) -> Result<std::process::Command, io::Error> {
    let executable = artifact_executable(&details.control, "bin/postgresql-control")?;
    Ok(platform.command_as(Path::new(&executable), details.probe_uid, details.probe_gid))
}

fn append_server_identity(command: &mut std::process::Command, target: &ServerTarget<'_>) {
    let expected_boot_id = target
        .expected_process
        .map_or("absent", |process| process.boot_id.as_str());
    let expected_pid = target
        .expected_process
        .map_or_else(|| "absent".to_string(), |process| process.pid.to_string());
    let expected_process_group = target.expected_process.map_or_else(
        || "absent".to_string(),
        |process| process.process_group.to_string(),
    );
    let expected_start_time = target.expected_process.map_or_else(
        || "absent".to_string(),
        |process| process.start_time.to_string(),
    );
    command
        .arg("--slot")
        .arg(format!("{:02}", target.slot))
        .arg("--postgresql-artifact")
        .arg(&target.postgresql.store_path)
        .arg("--data-directory")
        .arg(target.data)
        .arg("--cluster-directory")
        .arg(target.cluster)
        .arg("--run-directory")
        .arg(target.run)
        .arg("--port")
        .arg(target.port.to_string())
        .arg("--configuration-revision")
        .arg(target.configuration_revision)
        .arg("--database")
        .arg(target.database)
        .arg("--role")
        .arg(target.role)
        .arg("--auth")
        .arg(target.auth.as_str())
        .arg("--expected-boot-id")
        .arg(expected_boot_id)
        .arg("--expected-pid")
        .arg(expected_pid)
        .arg("--expected-process-group")
        .arg(expected_process_group)
        .arg("--expected-start-time")
        .arg(expected_start_time);
}

fn decode<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, io::Error> {
    aos_contract::canonical::from_slice(bytes, label).map_err(store_error)
}

fn require_empty_success(success: bool, output: &[u8]) -> Result<(), io::Error> {
    require_success(success)?;
    if !output.is_empty() {
        return Err(invalid("PostgreSQL control emitted unexpected output"));
    }
    Ok(())
}

fn require_success(success: bool) -> Result<(), io::Error> {
    if success {
        Ok(())
    } else {
        Err(io::Error::other("PostgreSQL control failed"))
    }
}
