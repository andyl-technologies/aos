//! Admits externally signed deployment policy inputs under root-owned custody.
//!
//! This service commits the monotonic deployment input head and serves an
//! authenticated signed-head receipt to the node controller. Its version-4
//! exchange can retain a closed AOSPCB02 root CAS and handoff epoch. It cannot
//! admit the project source against the controller-owned publisher journal,
//! authorize compiler publication, or authorize Create effects.

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
    CLOSED_POLICY_BINDING_BYTES_V2, ClosedPolicyRootCasBaseV2, ClosedPolicyRootCasObservationV2,
    PolicyDeploymentInputsV1, admit_fixed_policy_deployment_head_v1,
    admit_fixed_policy_signer_pins_v1, decode_policy_deployment_sources_v1,
    verify_policy_deployment_head_v1, verify_signed_project_policy_source_v1,
    with_fixed_closed_policy_binding_session_v2, with_fixed_current_policy_head_lease_v1,
};
use aos_sandbox_broker_session_security::policy_authority_client::{
    POLICY_AUTHORITY_SOCKET_PATH_V2, POLICY_BINDING_ACK_MAGIC_V4, POLICY_BINDING_BASE_MAGIC_V4,
    POLICY_BINDING_COMMITTED_MAGIC_V4, POLICY_BINDING_COMPLETE_MAGIC_V4,
    POLICY_BINDING_QUERY_MAGIC_V4, POLICY_BINDING_SUBMIT_MAGIC_V4, POLICY_HEAD_LEASE_ACK_MAGIC_V3,
    POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3, POLICY_HEAD_LEASE_QUERY_MAGIC_V3,
    POLICY_HEAD_QUERY_MAGIC_V2, POLICY_HEAD_RECEIPT_MAGIC_V2,
};
use aos_sandbox_broker_session_security::policy_signer_credential::{
    PinnedPolicySignerV1, PolicySignerRoleV1,
};
use ed25519_dalek::VerifyingKey;

const CREDENTIAL_ROOT: &str = "/run/credentials/aos-sandbox-policy-authorityd.service";
const REQUEST_BYTES: usize = 32;
const MAXIMUM_RECEIPT_BYTES: usize = 224 + 4 * (4 + 64 * 1024) + 312 + 4 + 3 * 1024 + 24;
const LEASE_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const CLOSED_BINDING_SUBMISSION_BYTES: usize = 8 + 16 + 4 + CLOSED_POLICY_BINDING_BYTES_V2;
const CLOSED_BINDING_ACK_BYTES: usize = 8 + 16 + 32 + 8;

#[derive(Clone, Copy)]
enum HeadRequestMode {
    Query,
    Lease,
    ClosedBinding,
}

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
    let key_bytes = read_bounded(&root.join("deployment-public-key"), 80)?;
    let deployment_signer =
        PinnedPolicySignerV1::decode(PolicySignerRoleV1::Deployment, &key_bytes)?;
    let packet = read_bounded(&root.join("deployment-head.packet"), 224)?;
    let node = read_bounded(&root.join("node-policy.json"), 64 * 1024)?;
    let site = read_bounded(&root.join("site-policy.json"), 64 * 1024)?;
    let backend = read_bounded(&root.join("backend-capabilities.json"), 64 * 1024)?;
    let catalogs = read_bounded(&root.join("catalogs.json"), 64 * 1024)?;
    let project_key_bytes = read_bounded(&root.join("project-public-key"), 80)?;
    let project_signer =
        PinnedPolicySignerV1::decode(PolicySignerRoleV1::Project, &project_key_bytes)?;
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
    let deployment = verify_policy_deployment_head_v1(
        &packet,
        &inputs,
        deployment_signer.verifying_key(),
        now_unix_seconds,
    )?;
    let _typed_sources = decode_policy_deployment_sources_v1(&inputs, deployment)?;
    let project = verify_signed_project_policy_source_v1(
        &project_packet,
        &project_input,
        project_signer.verifying_key(),
        now_unix_seconds,
    )?;
    if project.head().prerequisite_claims()[1] != deployment.packet_digest() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "project deployment head mismatch",
        )
        .into());
    }
    admit_fixed_policy_signer_pins_v1(
        deployment_signer.generation(),
        deployment_signer.verifying_key(),
        project_signer.generation(),
        project_signer.verifying_key(),
    )?;
    admit_fixed_policy_deployment_head_v1(
        &packet,
        &inputs,
        deployment_signer.verifying_key(),
        now_unix_seconds,
    )?;

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
            deployment_signer.verifying_key(),
            deployment_signer.generation(),
            &project_packet,
            &project_input,
            project_signer.verifying_key(),
            project_signer.generation(),
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
    deployment_signer_generation: u64,
    project_packet: &[u8],
    project_input: &[u8],
    project_key: &VerifyingKey,
    project_signer_generation: u64,
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
    let mode = match request.get(..8) {
        Some(magic) if magic == POLICY_HEAD_QUERY_MAGIC_V2 => HeadRequestMode::Query,
        Some(magic) if magic == POLICY_HEAD_LEASE_QUERY_MAGIC_V3 => HeadRequestMode::Lease,
        Some(magic) if magic == POLICY_BINDING_QUERY_MAGIC_V4 => HeadRequestMode::ClosedBinding,
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
    if matches!(mode, HeadRequestMode::ClosedBinding) {
        let committed = with_fixed_closed_policy_binding_session_v2(
            packet,
            deployment_signer_generation,
            verifying_key,
            project.head(),
            project_signer_generation,
            project_key,
            controller_uid,
            controller_gid,
            |session| -> io::Result<ClosedPolicyRootCasObservationV2> {
                let length = u32::try_from(receipt.len()).map_err(io::Error::other)?;
                stream.write_all(&length.to_be_bytes())?;
                stream.write_all(&receipt)?;
                write_closed_binding_base(
                    stream,
                    session.current_base().map_err(io::Error::other)?,
                )?;
                stream.set_read_timeout(Some(LEASE_ACK_TIMEOUT))?;

                let mut submission = [0_u8; CLOSED_BINDING_SUBMISSION_BYTES];
                stream.read_exact(&mut submission)?;
                let binding = decode_closed_binding_submission(&submission, &request[8..24])?;
                let committed = session
                    .commit_closed_binding(binding)
                    .map_err(io::Error::other)?;
                write_closed_binding_frame(
                    stream,
                    POLICY_BINDING_COMMITTED_MAGIC_V4,
                    &request[8..24],
                    committed,
                )?;

                let mut acknowledgement = [0_u8; CLOSED_BINDING_ACK_BYTES];
                stream.read_exact(&mut acknowledgement)?;
                validate_closed_binding_ack(
                    &acknowledgement,
                    &request[8..24],
                    committed.binding().as_bytes(),
                    committed.handoff_epoch(),
                )?;
                check_signed_head_expiration(deployment.expires_at(), project.head().expires_at())?;
                Ok(committed)
            },
        )??;
        // The root journal is unlocked only after the exact postcommit
        // snapshot check. A lost completion leaves an inert durable record.
        // The value returned below is an observation, not an effect token.
        write_closed_binding_frame(
            stream,
            POLICY_BINDING_COMPLETE_MAGIC_V4,
            &request[8..24],
            committed,
        )?;
    } else if matches!(mode, HeadRequestMode::Lease) {
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

            check_signed_head_expiration(deployment.expires_at(), project.head().expires_at())
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

fn decode_closed_binding_submission<'a>(
    submission: &'a [u8; CLOSED_BINDING_SUBMISSION_BYTES],
    nonce: &[u8],
) -> io::Result<&'a [u8]> {
    if &submission[..8] != POLICY_BINDING_SUBMIT_MAGIC_V4
        || &submission[8..24] != nonce
        || submission[24..28]
            != u32::try_from(CLOSED_POLICY_BINDING_BYTES_V2)
                .map_err(io::Error::other)?
                .to_be_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid closed binding submission",
        ));
    }
    Ok(&submission[28..])
}

fn write_closed_binding_frame(
    stream: &mut std::os::unix::net::UnixStream,
    magic: &[u8; 8],
    nonce: &[u8],
    committed: ClosedPolicyRootCasObservationV2,
) -> io::Result<()> {
    stream.write_all(magic)?;
    stream.write_all(nonce)?;
    stream.write_all(committed.binding().as_bytes())?;
    stream.write_all(&committed.handoff_epoch().to_be_bytes())
}

fn write_closed_binding_base(
    stream: &mut std::os::unix::net::UnixStream,
    base: ClosedPolicyRootCasBaseV2,
) -> io::Result<()> {
    stream.write_all(POLICY_BINDING_BASE_MAGIC_V4)?;
    stream.write_all(&base.issuer_owner())?;
    stream.write_all(base.predecessor().as_bytes())?;
    stream.write_all(&base.next_generation().to_be_bytes())?;
    stream.write_all(&base.deployment_signer_generation().to_be_bytes())?;
    stream.write_all(&base.project_signer_generation().to_be_bytes())
}

fn validate_closed_binding_ack(
    acknowledgement: &[u8; CLOSED_BINDING_ACK_BYTES],
    nonce: &[u8],
    binding: &[u8; 32],
    handoff_epoch: u64,
) -> io::Result<()> {
    if &acknowledgement[..8] != POLICY_BINDING_ACK_MAGIC_V4
        || &acknowledgement[8..24] != nonce
        || &acknowledgement[24..56] != binding
        || acknowledgement[56..64] != handoff_epoch.to_be_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid closed binding acknowledgement",
        ));
    }
    Ok(())
}

fn check_signed_head_expiration(deployment_expires: i64, project_expires: i64) -> io::Result<()> {
    let completed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let completed_at = i64::try_from(completed_at.as_secs()).map_err(io::Error::other)?;
    if completed_at >= deployment_expires || completed_at >= project_expires {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expired policy head",
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

    #[test]
    fn closed_binding_frames_reject_nonce_length_head_and_epoch_substitution() {
        let nonce = [1; 16];
        let head = [2; 32];
        let mut submission = [0_u8; CLOSED_BINDING_SUBMISSION_BYTES];
        submission[..8].copy_from_slice(POLICY_BINDING_SUBMIT_MAGIC_V4);
        submission[8..24].copy_from_slice(&nonce);
        submission[24..28].copy_from_slice(
            &u32::try_from(CLOSED_POLICY_BINDING_BYTES_V2)
                .unwrap()
                .to_be_bytes(),
        );
        assert_eq!(
            decode_closed_binding_submission(&submission, &nonce)
                .expect("exact frame")
                .len(),
            CLOSED_POLICY_BINDING_BYTES_V2
        );
        assert!(decode_closed_binding_submission(&submission, &[3; 16]).is_err());
        submission[24] ^= 1;
        assert!(decode_closed_binding_submission(&submission, &nonce).is_err());

        let mut acknowledgement = [0_u8; CLOSED_BINDING_ACK_BYTES];
        acknowledgement[..8].copy_from_slice(POLICY_BINDING_ACK_MAGIC_V4);
        acknowledgement[8..24].copy_from_slice(&nonce);
        acknowledgement[24..56].copy_from_slice(&head);
        acknowledgement[56..64].copy_from_slice(&4_u64.to_be_bytes());
        assert!(validate_closed_binding_ack(&acknowledgement, &nonce, &head, 4).is_ok());
        assert!(validate_closed_binding_ack(&acknowledgement, &[3; 16], &head, 4).is_err());
        assert!(validate_closed_binding_ack(&acknowledgement, &nonce, &[3; 32], 4).is_err());
        assert!(validate_closed_binding_ack(&acknowledgement, &nonce, &head, 5).is_err());
        acknowledgement[0] ^= 1;
        assert!(validate_closed_binding_ack(&acknowledgement, &nonce, &head, 4).is_err());
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
