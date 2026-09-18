//! Conversion of sealed SourceProvider security projections into AOSMSA02.
//!
//! This module copies only authenticated, nonauthorizing facts from the
//! SourceProvider security crate. It never receives private key material and
//! cannot mint request, outcome, process-liveness, or journal authority.

use aos_sandbox_source_provider_protocol::{
    SourceProviderAuthorityTrustStateV1, SourceProviderKeyTrustStateV1, digest_signed_hello,
};
use aos_sandbox_source_provider_security::{
    MountProviderAuthorityTrustProjectionV2, MountProviderRequestProjectionV2,
    MountProviderSessionProjectionV2, MountProviderSignerProjectionV2,
};
use sha2::{Digest as _, Sha256};

use super::format::{session_id, state_error};
use super::model::{
    ActualWriterRootMountSnapshotV2, AuthorityAdmissionStateV2, AuthorityTrustSnapshotV2,
    KeyAdmissionStateV2, NegotiatedCapabilitiesV2, ProviderExecutionSnapshotV2, ProviderScopeV2,
    SignerRoleV2, SignerSnapshotV2, SourceProviderSessionV2, StoredRecordV2,
};
use super::transition::seal;
use crate::Result;

pub(super) fn scope_from_request(projection: &MountProviderRequestProjectionV2) -> ProviderScopeV2 {
    let (route_id, _, _, resource_namespace_digest) = projection.session().route();
    ProviderScopeV2 {
        holder_authority_id: projection.holder().authority_id(),
        provider_authority_id: projection.provider().authority_id(),
        route_id,
        resource_namespace_digest: *resource_namespace_digest.as_bytes(),
    }
}

pub(super) fn session_from_request(
    projection: &MountProviderRequestProjectionV2,
    predecessor_session_id: Option<[u8; 32]>,
) -> Result<SourceProviderSessionV2> {
    let session = session_from_projection(projection.session(), predecessor_session_id)?;
    if session.scope.holder_authority_id != projection.holder().authority_id()
        || session.scope.provider_authority_id != projection.provider().authority_id()
        || session.session_binding != *projection.session_binding().as_bytes()
        || session.signer_set_commitment != *projection.signer_set_commitment().as_bytes()
        || (
            session.trust_generation,
            session.trust_digest,
            session.revocation_generation,
            session.revocation_digest,
        ) != {
            let (trust_generation, trust_digest, revocation_generation, revocation_digest) =
                projection.trust_heads();
            (
                trust_generation,
                *trust_digest.as_bytes(),
                revocation_generation,
                *revocation_digest.as_bytes(),
            )
        }
    {
        return Err(state_error(
            "SourceProvider request and session projections differ",
        ));
    }
    Ok(session)
}

pub(super) fn session_from_projection(
    projected: &MountProviderSessionProjectionV2,
    predecessor_session_id: Option<[u8; 32]>,
) -> Result<SourceProviderSessionV2> {
    let authorities = projected.authority_trust();
    let (route_id, route_generation, route_digest, resource_namespace_digest) = projected.route();
    let scope = ProviderScopeV2 {
        holder_authority_id: authorities[0].authority().authority_id(),
        provider_authority_id: authorities[1].authority().authority_id(),
        route_id,
        resource_namespace_digest: *resource_namespace_digest.as_bytes(),
    };
    let authority_trust = [
        authority_snapshot(&authorities[0])?,
        authority_snapshot(&authorities[1])?,
    ];
    let signers = projected.ordered_signers();
    let signer_snapshots = [
        signer_snapshot(&signers[0], SignerRoleV2::RootMountHello)?,
        signer_snapshot(&signers[1], SignerRoleV2::RootMountRecord)?,
        signer_snapshot(&signers[2], SignerRoleV2::ProviderHello)?,
        signer_snapshot(&signers[3], SignerRoleV2::ProviderOutcome)?,
    ];
    let (root_hello, provider_hello) = projected.signed_hellos();
    let (kernel_boot_id, root_process_instance, provider_process_instance) =
        projected.process_instances();
    let (root_uid, root_gid, root_tgid, root_start, root_cgroup_digest) = projected.root_writer();
    let (
        provider_pid,
        provider_tgid,
        provider_ppid,
        provider_start,
        provider_cgroup_id,
        _provider_cgroup_digest,
        provider_credentials,
        process_execution_digest,
    ) = projected.provider_execution();
    let (proof_classes, supports_recursive, supports_kernel_coupled) = projected.capabilities();
    let (authenticated_at, current_valid_until, clock_digest) = projected.validity();
    let (session_binding, signer_set_commitment) = projected.session_commitments();
    let (trust_generation, trust_digest, revocation_generation, revocation_digest) =
        projected.trust_heads();

    if route_id != scope.route_id
        || *resource_namespace_digest.as_bytes() != scope.resource_namespace_digest
    {
        return Err(state_error(
            "SourceProvider security projection changes stable scope",
        ));
    }

    let mut session = SourceProviderSessionV2 {
        session_id: [0; 32],
        revision: 1,
        predecessor_session_id,
        scope,
        node_id: projected.node_id(),
        kernel_boot_id,
        root_mount_authority_generation: authorities[0].authority().authority_generation(),
        root_mount_authority_digest: *authorities[0].authority().authority_digest().as_bytes(),
        provider_authority_generation: authorities[1].authority().authority_generation(),
        provider_authority_digest: *authorities[1].authority().authority_digest().as_bytes(),
        route_generation,
        route_digest: *route_digest.as_bytes(),
        negotiated_capabilities: NegotiatedCapabilitiesV2 {
            proof_class_capabilities: proof_classes,
            supports_recursive,
            supports_kernel_coupled,
            signed_lease_receipts: true,
            separated_signing_roles: true,
        },
        signed_root_mount_hello: root_hello.to_vec(),
        signed_root_mount_hello_digest: *digest_signed_hello_bytes(root_hello)?.as_bytes(),
        signed_provider_hello: provider_hello.to_vec(),
        signed_provider_hello_digest: *digest_signed_hello_bytes(provider_hello)?.as_bytes(),
        session_binding: *session_binding.as_bytes(),
        signer_set_commitment: *signer_set_commitment.as_bytes(),
        authenticated_at_seconds: authenticated_at,
        current_valid_until_seconds: current_valid_until,
        trusted_clock_evidence_digest: *clock_digest.as_bytes(),
        trust_generation,
        trust_digest: *trust_digest.as_bytes(),
        revocation_generation,
        revocation_digest: *revocation_digest.as_bytes(),
        authority_trust,
        signers: signer_snapshots,
        root_mount_process_instance: root_process_instance,
        actual_writer_root_mount_process: ActualWriterRootMountSnapshotV2 {
            uid: root_uid,
            gid: root_gid,
            tgid: root_tgid,
            start_time_ticks: root_start,
            cgroup_digest: *root_cgroup_digest.as_bytes(),
        },
        provider_process_instance,
        provider_execution: ProviderExecutionSnapshotV2 {
            pid: provider_pid,
            tgid: provider_tgid,
            ppid: provider_ppid,
            start_time_ticks: provider_start,
            cgroup_id: provider_cgroup_id,
            real_uid: provider_credentials[0],
            effective_uid: provider_credentials[1],
            saved_uid: provider_credentials[2],
            filesystem_uid: provider_credentials[3],
            real_gid: provider_credentials[4],
            effective_gid: provider_credentials[5],
            saved_gid: provider_credentials[6],
            filesystem_gid: provider_credentials[7],
            process_execution_digest: *process_execution_digest.as_bytes(),
        },
        record_digest: [0; 32],
    };
    session.session_id = session_id(&session);
    match seal(StoredRecordV2::ProviderSession { value: session })? {
        StoredRecordV2::ProviderSession { value } => Ok(value),
        _ => Err(state_error(
            "sealed SourceProvider session changed record kind",
        )),
    }
}

fn authority_snapshot(
    projection: &MountProviderAuthorityTrustProjectionV2,
) -> Result<AuthorityTrustSnapshotV2> {
    let authority = projection.authority();
    let (valid_from_seconds, valid_until_seconds, state) = projection.admission();
    if state != SourceProviderAuthorityTrustStateV1::Trusted {
        return Err(state_error(
            "SourceProvider authority projection is not currently trusted",
        ));
    }
    Ok(AuthorityTrustSnapshotV2 {
        authority_id: authority.authority_id(),
        authority_generation: authority.authority_generation(),
        authority_digest: *authority.authority_digest().as_bytes(),
        valid_from_seconds,
        valid_until_seconds,
        state: AuthorityAdmissionStateV2::Trusted,
    })
}

fn signer_snapshot(
    projection: &MountProviderSignerProjectionV2,
    role: SignerRoleV2,
) -> Result<SignerSnapshotV2> {
    let (signer, public_key) = projection.identity();
    let (
        authority_valid_from_seconds,
        authority_valid_until_seconds,
        key_valid_from_seconds,
        key_valid_until_seconds,
        authority_state,
        key_state,
        superseded_by_key_generation,
    ) = projection.admission();
    if authority_state != SourceProviderAuthorityTrustStateV1::Trusted
        || key_state != SourceProviderKeyTrustStateV1::Eligible
        || superseded_by_key_generation != 0
    {
        return Err(state_error(
            "SourceProvider signer projection is not currently eligible",
        ));
    }
    Ok(SignerSnapshotV2 {
        role,
        authority_id: signer.authority_id(),
        authority_generation: signer.authority_generation(),
        authority_digest: *signer.authority_digest().as_bytes(),
        key_id: signer.key_id(),
        key_generation: signer.key_generation(),
        public_key: *public_key,
        public_key_fingerprint: Sha256::digest(public_key).into(),
        authority_valid_from_seconds,
        authority_valid_until_seconds,
        key_valid_from_seconds,
        key_valid_until_seconds,
        authority_state: AuthorityAdmissionStateV2::Trusted,
        key_state: KeyAdmissionStateV2::Eligible,
        superseded_by_key_generation,
    })
}

fn digest_signed_hello_bytes(bytes: &[u8]) -> Result<aos_sandbox_core::ObjectDigest> {
    let hello =
        aos_sandbox_source_provider_protocol::SignedSourceProviderHelloV1::from_canonical_bytes(
            bytes,
        )
        .map_err(|_| state_error("SourceProvider security hello projection is invalid"))?;
    Ok(digest_signed_hello(&hello))
}
