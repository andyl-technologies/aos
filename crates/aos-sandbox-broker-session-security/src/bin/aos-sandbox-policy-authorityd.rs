//! Admits externally signed deployment policy inputs under root-owned custody.
//!
//! This service commits the monotonic deployment input head and serves an
//! authenticated, read-only signed-head receipt to the node controller. It
//! verifies the signed project source but cannot admit it against the
//! controller-owned publisher journal, issue compiler candidate bindings,
//! or authorize Create effects.

use std::{
    error::Error,
    fs::File,
    io::{self, Read as _, Write as _},
    os::unix::{fs::FileTypeExt as _, net::UnixListener},
    path::Path,
    process::ExitCode,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use aos_sandbox::policy_compiler::{
    PolicyDeploymentInputsV1, admit_fixed_policy_deployment_head_v1,
    verify_signed_project_policy_source_v1, with_fixed_current_policy_head_lease_v1,
};
use aos_sandbox_broker_session_security::policy_authority_client::{
    POLICY_AUTHORITY_SOCKET_PATH_V2, POLICY_HEAD_LEASE_ACK_MAGIC_V3,
    POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3, POLICY_HEAD_LEASE_QUERY_MAGIC_V3,
    POLICY_HEAD_QUERY_MAGIC_V2, POLICY_HEAD_RECEIPT_MAGIC_V2,
};
use ed25519_dalek::VerifyingKey;

const CREDENTIAL_ROOT: &str = "/run/credentials/aos-sandbox-policy-authorityd.service";
const REQUEST_BYTES: usize = 32;
const MAXIMUM_RECEIPT_BYTES: usize = 224 + 4 * (4 + 64 * 1024) + 312 + 4 + 3 * 1024 + 24;
const LEASE_ACK_TIMEOUT: Duration = Duration::from_secs(30);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-policy-authorityd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    if rustix::process::geteuid().as_raw() != 0 || rustix::process::getuid().as_raw() != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root required").into());
    }

    let mut arguments = std::env::args();
    let _program = arguments.next();
    let controller_uid: u32 = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller UID required"))?
        .parse()?;
    let controller_gid: u32 = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller GID required"))?
        .parse()?;
    if controller_uid == 0 || controller_gid == 0 || arguments.next().is_some() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "invalid controller identity").into(),
        );
    }

    let root = Path::new(CREDENTIAL_ROOT);
    let key_bytes = read_bounded(&root.join("deployment-public-key"), 32)?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)?;
    let packet = read_bounded(&root.join("deployment-head.packet"), 224)?;
    let node = read_bounded(&root.join("node-policy.json"), 64 * 1024)?;
    let site = read_bounded(&root.join("site-policy.json"), 64 * 1024)?;
    let backend = read_bounded(&root.join("backend-capabilities.json"), 64 * 1024)?;
    let catalogs = read_bounded(&root.join("catalogs.json"), 64 * 1024)?;
    let project_key_bytes = read_bounded(&root.join("project-public-key"), 32)?;
    let project_key_array: [u8; 32] = project_key_bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid project key length"))?;
    let project_key = VerifyingKey::from_bytes(&project_key_array)?;
    let project_packet = read_bounded(&root.join("project-head.packet"), 312)?;
    let project_input = read_bounded(&root.join("project-layer.json"), 3 * 1024)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let now_unix_seconds = i64::try_from(now.as_secs())?;

    let inputs = PolicyDeploymentInputsV1 {
        node: &node,
        site: &site,
        backend: &backend,
        catalogs: &catalogs,
    };
    let deployment =
        admit_fixed_policy_deployment_head_v1(&packet, &inputs, &verifying_key, now_unix_seconds)?;
    let project = verify_signed_project_policy_source_v1(
        &project_packet,
        &project_input,
        &project_key,
        now_unix_seconds,
    )?;
    if project.head().prerequisite_claims()[1] != deployment.packet_digest() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "project deployment head mismatch",
        )
        .into());
    }

    let socket_path = Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2);
    if let Ok(metadata) = socket_path.symlink_metadata() {
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "unsafe authority socket path",
            )
            .into());
        }
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;

    for accepted in listener.incoming() {
        let mut stream = match accepted {
            Ok(stream) => stream,
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = serve_current_head(
            &mut stream,
            controller_uid,
            controller_gid,
            &packet,
            &inputs,
            &verifying_key,
            &project_packet,
            &project_input,
            &project_key,
        ) {
            eprintln!("aos-sandbox-policy-authorityd: rejected head query: {error}");
        }
    }
    Err(io::Error::new(io::ErrorKind::BrokenPipe, "authority listener ended").into())
}

fn serve_current_head(
    stream: &mut std::os::unix::net::UnixStream,
    controller_uid: u32,
    controller_gid: u32,
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    verifying_key: &VerifyingKey,
    project_packet: &[u8],
    project_input: &[u8],
    project_key: &VerifyingKey,
) -> Result<(), Box<dyn Error>> {
    let peer = rustix::net::sockopt::socket_peercred(&*stream)?;
    if peer.uid.as_raw() != controller_uid || peer.gid.as_raw() != controller_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected controller peer",
        )
        .into());
    }
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut request = [0_u8; REQUEST_BYTES];
    stream.read_exact(&mut request)?;
    let lease = match request.get(..8) {
        Some(magic) if magic == POLICY_HEAD_QUERY_MAGIC_V2 => false,
        Some(magic) if magic == POLICY_HEAD_LEASE_QUERY_MAGIC_V3 => true,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid head query").into()),
    };
    if request[24..] != [0; 8] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid head query").into());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let now_unix_seconds = i64::try_from(now.as_secs())?;
    let deployment =
        admit_fixed_policy_deployment_head_v1(packet, inputs, verifying_key, now_unix_seconds)?;
    let project = verify_signed_project_policy_source_v1(
        project_packet,
        project_input,
        project_key,
        now_unix_seconds,
    )?;
    if project.head().prerequisite_claims()[1] != deployment.packet_digest() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "project deployment head mismatch",
        )
        .into());
    }

    let mut receipt = Vec::with_capacity(MAXIMUM_RECEIPT_BYTES);
    receipt.extend_from_slice(POLICY_HEAD_RECEIPT_MAGIC_V2);
    receipt.extend_from_slice(&request[8..24]);
    receipt.extend_from_slice(packet);
    for input in [inputs.node, inputs.site, inputs.backend, inputs.catalogs] {
        let length = u32::try_from(input.len())?;
        receipt.extend_from_slice(&length.to_be_bytes());
        receipt.extend_from_slice(input);
    }
    receipt.extend_from_slice(project_packet);
    receipt.extend_from_slice(&u32::try_from(project_input.len())?.to_be_bytes());
    receipt.extend_from_slice(project_input);
    if lease {
        with_fixed_current_policy_head_lease_v1(packet, || -> io::Result<()> {
            let length = u32::try_from(receipt.len()).map_err(io::Error::other)?;
            stream.write_all(&length.to_be_bytes())?;
            stream.write_all(&receipt)?;
            // This protocol only permits a read-only candidate inspection;
            // it confers no binding or effect authority. A missing ACK must
            // release the root writer instead of pinning it indefinitely.
            stream.set_read_timeout(Some(LEASE_ACK_TIMEOUT))?;

            let mut acknowledgement = [0_u8; 24];
            stream.read_exact(&mut acknowledgement)?;
            validate_lease_ack(&acknowledgement, &request[8..24])?;

            let completed_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?;
            let completed_at = i64::try_from(completed_at.as_secs()).map_err(io::Error::other)?;
            if completed_at >= deployment.expires_at()
                || completed_at >= project.head().expires_at()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expired lease head",
                ));
            }
            Ok(())
        })??;
        stream.write_all(POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3)?;
        stream.write_all(&request[8..24])?;
    } else {
        stream.write_all(&receipt)?;
    }
    Ok(())
}

fn validate_lease_ack(acknowledgement: &[u8; 24], nonce: &[u8]) -> io::Result<()> {
    if &acknowledgement[..8] != POLICY_HEAD_LEASE_ACK_MAGIC_V3 || &acknowledgement[8..] != nonce {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid lease acknowledgement",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_ack_is_nonce_and_version_bound() {
        let mut acknowledgement = [0_u8; 24];
        acknowledgement[..8].copy_from_slice(POLICY_HEAD_LEASE_ACK_MAGIC_V3);
        acknowledgement[8..].copy_from_slice(&[1; 16]);
        assert!(validate_lease_ack(&acknowledgement, &[1; 16]).is_ok());

        assert!(validate_lease_ack(&acknowledgement, &[2; 16]).is_err());
        acknowledgement[0] ^= 1;
        assert!(validate_lease_ack(&acknowledgement, &[1; 16]).is_err());
    }
}

fn read_bounded(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential size",
        ));
    }
    Ok(bytes)
}
