//! Holder-bound OpenSSH data route for an admitted execution attachment.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use aos_proto::aos::sandbox::v1::{
    ExecutionControlRequest, ExecutionIoMode, ExecutionServiceClient, GetExecutionRequest,
    OpenSshAccessEndpoint,
};
use aos_sandbox::cli_model::CheckedExecutionControlResultV1;
use aos_sandbox::controller_query::CheckedExecutionResourceV1;

use crate::cli::sandbox::SandboxArgs;
use crate::commands::sandbox::SandboxAttachExitCode;

use super::AuthorizedEndpoint;

/// Opens the checked, separately authorized execution stream.
///
/// # Errors
///
/// Rejects missing or expired access, contradictory execution metadata, unsafe
/// credentials, OpenSSH transport failure, or a nonzero remote exit status.
pub(super) async fn attach(
    args: &SandboxArgs,
    endpoint: &AuthorizedEndpoint,
    request: &ExecutionControlRequest,
    result: &CheckedExecutionControlResultV1,
) -> Result<()> {
    let access = result
        .access_endpoint()
        .context("controller admitted attachment without an OpenSSH access route")?;
    validate_access(access)?;

    let response = ExecutionServiceClient::new(endpoint.connection.clone(), endpoint.config()?)
        .get_execution(GetExecutionRequest {
            execution_id: request.execution_id.clone(),
            ..Default::default()
        })
        .await
        .context("controller rejected attached execution lookup")?
        .into_owned();
    let execution = response
        .execution
        .into_option()
        .context("controller omitted the attached execution")?;
    let execution = CheckedExecutionResourceV1::try_from(execution)
        .context("controller returned an invalid attached execution")?;
    let execution = execution.as_proto();
    if execution.execution_id != access.execution_id
        || execution.sandbox_incarnation_id != access.sandbox_incarnation_id
        || execution.audit_id != access.audit_id
    {
        bail!("OpenSSH access route contradicts the attached execution");
    }
    let io_mode = execution
        .command
        .as_option()
        .and_then(|command| command.io_mode.as_known())
        .context("attached execution has no supported I/O mode")?;
    if io_mode == ExecutionIoMode::EXECUTION_IO_MODE_DETACHED_CAPTURE {
        bail!("detached-capture execution has no interactive attachment");
    }

    let credential_path = args
        .public_credentials
        .as_deref()
        .context("--public-api requires --public-credentials")?;
    let private_key = super::super::public_transport::load_execution_private_key(credential_path)?;
    let custody = tempfile::Builder::new()
        .prefix("aos-execution-")
        .tempdir_in("/tmp")
        .context("cannot create private OpenSSH credential custody")?;
    let key_path = custody.path().join("identity");
    let certificate_path = custody.path().join("identity-cert.pub");
    let known_hosts_path = custody.path().join("known_hosts");
    let host_alias = format!("aos-execution-{}", hex::encode(&access.execution_id));

    write_private_file(&key_path, &private_key)?;
    write_private_file(
        &certificate_path,
        canonical_public_line(&access.client_certificate, true)?.as_bytes(),
    )?;
    let host_key = canonical_public_line(&access.host_public_key, false)?;
    write_private_file(
        &known_hosts_path,
        format!("{host_alias} {host_key}").as_bytes(),
    )?;

    let mut command = tokio::process::Command::new("ssh");
    command.kill_on_drop(true);
    command
        .args(["-F", "/dev/null"])
        .arg("-o")
        .arg(format!("HostName={}", access.host))
        .arg("-o")
        .arg(format!("HostKeyAlias={host_alias}"))
        .arg("-p")
        .arg(access.port.to_string())
        .arg("-l")
        .arg(&access.user);

    command
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts_path.display()))
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg("CheckHostIP=no")
        .arg("-o")
        .arg("UpdateHostKeys=no");

    command
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ClearAllForwardings=yes")
        .arg("-o")
        .arg("ForwardAgent=no")
        .arg("-o")
        .arg("PermitLocalCommand=no")
        .arg("-o")
        .arg("ProxyCommand=none")
        .arg("-o")
        .arg("ProxyJump=none")
        .arg("-o")
        .arg("ControlMaster=no");

    command
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("IdentityAgent=none")
        .arg("-i")
        .arg(&key_path)
        .arg("-o")
        .arg(format!("CertificateFile={}", certificate_path.display()))
        .arg(if io_mode == ExecutionIoMode::EXECUTION_IO_MODE_PTY {
            "-tt"
        } else {
            "-T"
        })
        .arg("--")
        .arg(&host_alias)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = command
        .status()
        .await
        .context("cannot launch the OpenSSH execution data route")?;
    custody
        .close()
        .context("cannot remove temporary OpenSSH credential custody")?;
    if status.success() {
        Ok(())
    } else {
        Err(SandboxAttachExitCode(status.code().unwrap_or(1)).into())
    }
}

fn validate_access(access: &OpenSshAccessEndpoint) -> Result<()> {
    let host = access.host.as_str();
    let safe_dns = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && !host.starts_with('-');
    if host.parse::<IpAddr>().is_err() && !safe_dns {
        bail!("OpenSSH access route has an invalid host");
    }
    if access.user.is_empty()
        || access.user.len() > 32
        || !access
            .user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("OpenSSH access route has an invalid user");
    }
    let expiry = access
        .expires_at
        .as_option()
        .context("OpenSSH access route has no expiration")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes the Unix epoch")?;
    let expiry_seconds =
        u64::try_from(expiry.seconds).context("OpenSSH access route has an invalid expiration")?;
    if expiry_seconds < now.as_secs()
        || (expiry_seconds == now.as_secs() && expiry.nanoseconds <= now.subsec_nanos())
    {
        bail!("OpenSSH access route has expired");
    }
    Ok(())
}

fn canonical_public_line(bytes: &[u8], certificate: bool) -> Result<String> {
    let line = std::str::from_utf8(bytes)
        .context("OpenSSH public credential is not UTF-8")?
        .trim_end_matches('\n');
    let mut fields = line.split_ascii_whitespace();
    let algorithm = fields
        .next()
        .context("OpenSSH public credential has no algorithm")?;
    let encoded = fields
        .next()
        .context("OpenSSH public credential has no key")?;
    if fields.next().is_some()
        || !(algorithm.starts_with("ssh-") || algorithm.starts_with("ecdsa-sha2-"))
        || algorithm.contains(|character: char| !character.is_ascii_graphic())
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        || certificate != algorithm.ends_with("-cert-v01@openssh.com")
    {
        bail!("OpenSSH public credential is not a canonical key line");
    }
    Ok(format!("{algorithm} {encoded}\n"))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create private OpenSSH file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("cannot write private OpenSSH file {}", path.display()))
}
