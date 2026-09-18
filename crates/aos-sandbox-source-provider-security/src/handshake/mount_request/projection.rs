//! Protected session projection capture and canonical correlation helpers.

use super::*;

pub(super) trait MountSourceAcquisitionJournalViewV2 {
    fn validated_state(
        &self,
    ) -> Result<
        aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
        SourceProviderSecurityError,
    >;

    fn current_value<'view>(
        &'view self,
        key: &[u8],
    ) -> Result<Option<&'view [u8]>, SourceProviderSecurityError>;

    fn validate_current_snapshot(
        &self,
        snapshot: &aos_sandbox::ProtectedJournalSnapshot,
    ) -> Result<(), SourceProviderSecurityError>;
}

impl MountSourceAcquisitionJournalViewV2 for aos_sandbox::ProtectedJournalAuthority<'_> {
    fn validated_state(
        &self,
    ) -> Result<
        aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
        SourceProviderSecurityError,
    > {
        self.validate_mount_source_acquisition_authority()
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
            self.mount_source_acquisition_records()
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
    }

    fn current_value<'view>(
        &'view self,
        key: &[u8],
    ) -> Result<Option<&'view [u8]>, SourceProviderSecurityError> {
        self.get(key)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)
    }

    fn validate_current_snapshot(
        &self,
        snapshot: &aos_sandbox::ProtectedJournalSnapshot,
    ) -> Result<(), SourceProviderSecurityError> {
        self.validate_mount_source_acquisition_snapshot(snapshot)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)
    }
}

impl MountSourceAcquisitionJournalViewV2
    for aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>
{
    fn validated_state(
        &self,
    ) -> Result<
        aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
        SourceProviderSecurityError,
    > {
        aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
            self.records()
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
    }

    fn current_value<'view>(
        &'view self,
        key: &[u8],
    ) -> Result<Option<&'view [u8]>, SourceProviderSecurityError> {
        self.get(key)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)
    }

    fn validate_current_snapshot(
        &self,
        snapshot: &aos_sandbox::ProtectedJournalSnapshot,
    ) -> Result<(), SourceProviderSecurityError> {
        self.validate_snapshot(snapshot)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)
    }
}

pub(super) fn validated_mount_state(
    journal: &impl MountSourceAcquisitionJournalViewV2,
) -> Result<
    aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    SourceProviderSecurityError,
> {
    journal.validated_state()
}

pub(super) fn stored_mount_session_matches_projection(
    stored: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderSessionV2,
    projected: &MountProviderSessionProjectionV2,
) -> bool {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        AuthorityAdmissionStateV2, KeyAdmissionStateV2,
    };

    let authority_matches = stored
        .authority_trust
        .iter()
        .zip(projected.authority_trust.iter())
        .all(|(stored, projected)| {
            stored.authority_id == projected.authority.authority_id()
                && stored.authority_generation == projected.authority.authority_generation()
                && stored.authority_digest == *projected.authority.authority_digest().as_bytes()
                && stored.valid_from_seconds == projected.valid_from_seconds
                && stored.valid_until_seconds == projected.valid_until_seconds
                && stored.state == AuthorityAdmissionStateV2::Trusted
        });
    let signers_match = stored
        .signers
        .iter()
        .zip(projected.ordered_signers.iter())
        .all(|(stored, projected)| {
            stored.authority_id == projected.signer.authority_id()
                && stored.authority_generation == projected.signer.authority_generation()
                && stored.authority_digest == *projected.signer.authority_digest().as_bytes()
                && stored.key_id == projected.signer.key_id()
                && stored.key_generation == projected.signer.key_generation()
                && stored.public_key == projected.public_key
                && stored.public_key_fingerprint == *projected.signer.public_key_digest().as_bytes()
                && stored.authority_valid_from_seconds == projected.authority_valid_from_seconds
                && stored.authority_valid_until_seconds == projected.authority_valid_until_seconds
                && stored.key_valid_from_seconds == projected.key_valid_from_seconds
                && stored.key_valid_until_seconds == projected.key_valid_until_seconds
                && stored.authority_state == AuthorityAdmissionStateV2::Trusted
                && stored.key_state == KeyAdmissionStateV2::Eligible
                && stored.superseded_by_key_generation == projected.superseded_by_key_generation
        });
    let root_authority = &projected.authority_trust[0].authority;
    let provider_authority = &projected.authority_trust[1].authority;
    stored.scope.holder_authority_id == root_authority.authority_id()
        && stored.scope.provider_authority_id == provider_authority.authority_id()
        && stored.scope.route_id == projected.route_id
        && stored.scope.resource_namespace_digest == *projected.resource_namespace_digest.as_bytes()
        && stored.node_id == projected.node_id
        && stored.kernel_boot_id == projected.root_boot_id
        && stored.root_mount_authority_generation == root_authority.authority_generation()
        && stored.root_mount_authority_digest == *root_authority.authority_digest().as_bytes()
        && stored.provider_authority_generation == provider_authority.authority_generation()
        && stored.provider_authority_digest == *provider_authority.authority_digest().as_bytes()
        && stored.route_generation == projected.route_generation
        && stored.route_digest == *projected.route_digest.as_bytes()
        && stored.negotiated_capabilities.proof_class_capabilities
            == projected.proof_class_capabilities
        && stored.negotiated_capabilities.supports_recursive == projected.supports_recursive
        && stored.negotiated_capabilities.supports_kernel_coupled
            == projected.supports_kernel_coupled
        && stored.signed_root_mount_hello == projected.signed_root_mount_hello
        && stored.signed_provider_hello == projected.signed_provider_hello
        && stored.session_binding == *projected.session_binding.as_bytes()
        && stored.signer_set_commitment == *projected.signer_set_commitment.as_bytes()
        && stored.authenticated_at_seconds == projected.authenticated_at_seconds
        && stored.current_valid_until_seconds == projected.current_valid_until_seconds
        && stored.trusted_clock_evidence_digest
            == *projected.trusted_clock_evidence_digest.as_bytes()
        && stored.trust_generation == projected.trust_generation
        && stored.trust_digest == *projected.trust_digest.as_bytes()
        && stored.revocation_generation == projected.revocation_generation
        && stored.revocation_digest == *projected.revocation_digest.as_bytes()
        && stored.root_mount_process_instance == projected.root_process_instance
        && stored.actual_writer_root_mount_process.uid == projected.root_writer_uid
        && stored.actual_writer_root_mount_process.gid == projected.root_writer_gid
        && stored.actual_writer_root_mount_process.tgid == projected.root_writer_tgid
        && stored.actual_writer_root_mount_process.start_time_ticks
            == projected.root_writer_start_time_ticks
        && stored.actual_writer_root_mount_process.cgroup_digest
            == *projected.root_writer_cgroup_digest.as_bytes()
        && stored.provider_process_instance == projected.provider_process_instance
        && stored.provider_execution.pid == projected.provider_pid
        && stored.provider_execution.tgid == projected.provider_tgid
        && stored.provider_execution.ppid == projected.provider_parent_pid
        && stored.provider_execution.start_time_ticks == projected.provider_start_time_ticks
        && stored.provider_execution.cgroup_id == projected.provider_cgroup_id
        && stored.provider_execution.real_uid == projected.provider_credentials[0]
        && stored.provider_execution.effective_uid == projected.provider_credentials[1]
        && stored.provider_execution.saved_uid == projected.provider_credentials[2]
        && stored.provider_execution.filesystem_uid == projected.provider_credentials[3]
        && stored.provider_execution.real_gid == projected.provider_credentials[4]
        && stored.provider_execution.effective_gid == projected.provider_credentials[5]
        && stored.provider_execution.saved_gid == projected.provider_credentials[6]
        && stored.provider_execution.filesystem_gid == projected.provider_credentials[7]
        && stored.provider_execution.process_execution_digest
            == *projected.provider_execution_digest.as_bytes()
        && authority_matches
        && signers_match
}

pub(super) fn capture_session_projection(
    current: &CurrentRootMountSourceProviderSessionV1,
    authenticated_at_seconds: i64,
) -> Result<MountProviderSessionProjectionV2, SourceProviderSecurityError> {
    let root = current.custody.inner().execution().baseline();
    let custody = current.custody.inner();
    let route = custody.route();
    let trust = custody.trust();
    let root_hello = current.session.root_mount_hello();
    let provider_hello = current.session.provider_hello();
    let signer_references = [
        current.session.signed_root_mount_hello().signer(),
        root_hello.traffic_signer(),
        current.session.signed_provider_hello().signer(),
        provider_hello.traffic_signer(),
    ];
    let root_authority = custody.root_authority().authority();
    let provider_authority = custody.provider_authority().authority();
    let authority_records = [
        trust
            .authorities()
            .iter()
            .find(|entry| entry.authority() == root_authority),
        trust
            .authorities()
            .iter()
            .find(|entry| entry.authority() == provider_authority),
    ];
    let [Some(root_authority_trust), Some(provider_authority_trust)] = authority_records else {
        return Err(SourceProviderSecurityError::SessionContinuity);
    };
    if root_authority_trust.state() != SourceProviderAuthorityTrustStateV1::Trusted
        || provider_authority_trust.state() != SourceProviderAuthorityTrustStateV1::Trusted
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let mut signer_records = Vec::with_capacity(4);
    for signer in signer_references {
        let key = trust
            .keys()
            .iter()
            .find(|entry| entry.signer() == signer)
            .filter(|entry| entry.state() == SourceProviderKeyTrustStateV1::Eligible)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let authority = if signer.authority_id() == root_authority.authority_id() {
            root_authority_trust
        } else if signer.authority_id() == provider_authority.authority_id() {
            provider_authority_trust
        } else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        signer_records.push(MountProviderSignerProjectionV2 {
            signer: signer.clone(),
            public_key: *key.public_key(),
            authority_valid_from_seconds: authority.valid_from_seconds(),
            authority_valid_until_seconds: authority.valid_until_seconds(),
            key_valid_from_seconds: key.valid_from_seconds(),
            key_valid_until_seconds: key.valid_until_seconds(),
            authority_state: authority.state(),
            key_state: key.state(),
            superseded_by_key_generation: key.superseded_by_key_generation(),
        });
    }
    let ordered_signers: [MountProviderSignerProjectionV2; 4] = signer_records
        .try_into()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let current_valid_until_seconds = root_authority_trust
        .valid_until_seconds()
        .min(provider_authority_trust.valid_until_seconds())
        .min(
            ordered_signers
                .iter()
                .map(|entry| entry.key_valid_until_seconds)
                .min()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?,
        );
    if authenticated_at_seconds < root_authority_trust.valid_from_seconds()
        || authenticated_at_seconds < provider_authority_trust.valid_from_seconds()
        || authenticated_at_seconds >= current_valid_until_seconds
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let provider_credentials = current.provider_execution.credentials();
    let provider_credential_fields = [
        provider_credentials.real_user_id(),
        provider_credentials.effective_user_id(),
        provider_credentials.saved_user_id(),
        provider_credentials.filesystem_user_id(),
        provider_credentials.real_group_id(),
        provider_credentials.effective_group_id(),
        provider_credentials.saved_group_id(),
        provider_credentials.filesystem_group_id(),
    ];
    let provider_execution_digest = mount_provider_execution_digest(
        current.provider_execution.pid(),
        current.provider_execution.tgid(),
        current.provider_execution.parent_pid(),
        current.provider_execution.start_time_ticks(),
        current.provider_execution.cgroup_id(),
        provider_credential_fields,
    );
    let trusted_clock_evidence_digest = trusted_clock_evidence_digest(
        root.boot_id,
        authenticated_at_seconds,
        current.session.binding(),
        trust.trust_digest(),
        trust.revocation_digest(),
    );
    Ok(MountProviderSessionProjectionV2 {
        signed_root_mount_hello: current
            .session
            .signed_root_mount_hello()
            .to_canonical_bytes(),
        signed_provider_hello: current.session.signed_provider_hello().to_canonical_bytes(),
        ordered_signers,
        authority_trust: [
            MountProviderAuthorityTrustProjectionV2 {
                authority: root_authority.clone(),
                valid_from_seconds: root_authority_trust.valid_from_seconds(),
                valid_until_seconds: root_authority_trust.valid_until_seconds(),
                state: root_authority_trust.state(),
            },
            MountProviderAuthorityTrustProjectionV2 {
                authority: provider_authority.clone(),
                valid_from_seconds: provider_authority_trust.valid_from_seconds(),
                valid_until_seconds: provider_authority_trust.valid_until_seconds(),
                state: provider_authority_trust.state(),
            },
        ],
        session_binding: current.session.binding(),
        signer_set_commitment: current.session.signer_set_commitment(),
        trust_generation: trust.trust_generation(),
        trust_digest: trust.trust_digest(),
        revocation_generation: trust.revocation_generation(),
        revocation_digest: trust.revocation_digest(),
        root_boot_id: root.boot_id,
        node_id: custody.manifest().node_id(),
        root_process_instance: root_hello.process_instance(),
        provider_process_instance: provider_hello.process_instance(),
        root_writer_uid: root.credentials.effective_user_id(),
        root_writer_gid: root.credentials.effective_group_id(),
        root_writer_tgid: root.tgid,
        root_writer_start_time_ticks: root.start_time_ticks,
        root_writer_cgroup_digest: ObjectDigest::from_bytes(root.cgroup_path_digest),
        provider_pid: current.provider_execution.pid(),
        provider_tgid: current.provider_execution.tgid(),
        provider_parent_pid: current.provider_execution.parent_pid(),
        provider_start_time_ticks: current.provider_execution.start_time_ticks(),
        provider_cgroup_id: current.provider_execution.cgroup_id(),
        provider_cgroup_digest: ObjectDigest::from_bytes(
            current.provider_execution.cgroup_path_digest(),
        ),
        provider_credentials: provider_credential_fields,
        provider_execution_digest,
        route_id: route.route_id(),
        route_generation: route.route_generation(),
        route_digest: route.route_digest(),
        resource_namespace_digest: route.resource_namespace_digest(),
        proof_class_capabilities: root_hello.proof_class_capabilities(),
        supports_recursive: root_hello.supports_recursive(),
        supports_kernel_coupled: root_hello.supports_kernel_coupled(),
        authenticated_at_seconds,
        current_valid_until_seconds,
        trusted_clock_evidence_digest,
    })
}

pub(super) fn mount_provider_execution_digest(
    pid: u32,
    tgid: u32,
    parent_pid: u32,
    start_time_ticks: u64,
    cgroup_id: u64,
    credentials: [u32; 8],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount.source-provider-execution.v2\0");
    hasher.update(pid.to_be_bytes());
    hasher.update(tgid.to_be_bytes());
    hasher.update(parent_pid.to_be_bytes());
    hasher.update(start_time_ticks.to_be_bytes());
    hasher.update(cgroup_id.to_be_bytes());
    for credential in credentials {
        hasher.update(credential.to_be_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn trusted_clock_evidence_digest(
    boot_id: [u8; 16],
    authenticated_at_seconds: i64,
    session_binding: ObjectDigest,
    trust_digest: ObjectDigest,
    revocation_digest: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.security.clock-evidence.v1\0");
    hasher.update(boot_id);
    hasher.update(authenticated_at_seconds.to_be_bytes());
    hasher.update(session_binding.as_bytes());
    hasher.update(trust_digest.as_bytes());
    hasher.update(revocation_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn mount_plan_freshness_digest(
    signed_hellos: (&[u8], &[u8]),
    request_sequence: u64,
    response_sequence: u64,
    head_key: &[u8],
    head_record: &[u8],
    predecessor_session: Option<(&[u8], &[u8])>,
    predecessor_death_commitment: Option<ObjectDigest>,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.security.mount-plan.v1\0");
    for bytes in [signed_hellos.0, signed_hellos.1, head_key, head_record] {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.update(request_sequence.to_be_bytes());
    hasher.update(response_sequence.to_be_bytes());
    if let Some((key, record)) = predecessor_session {
        hasher.update((key.len() as u32).to_be_bytes());
        hasher.update(key);
        hasher.update((record.len() as u32).to_be_bytes());
        hasher.update(record);
    } else {
        hasher.update(0_u32.to_be_bytes());
        hasher.update(0_u32.to_be_bytes());
    }
    hasher.update(
        predecessor_death_commitment
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    ObjectDigest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn historical_verification_key<'configuration>(
    configuration: &'configuration crate::RevalidatedProviderConfigurationV1,
    signer: &aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
    authenticated_at_seconds: i64,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
) -> Result<&'configuration [u8; 32], SourceProviderSecurityError> {
    let trusted = configuration
        .historical_public_keys()
        .iter()
        .find(|entry| entry.signer() == signer)
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    if !configuration.authenticates_historical_key_at(
        trusted,
        authenticated_at_seconds,
        trust_generation,
        trust_digest,
        revocation_generation,
        revocation_digest,
    ) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(trusted.public_key())
}

/// Resolves one already-consumed artifact and reports cleanup-only revocation.
///
/// The revoked branch is deliberately unavailable to fresh admission and all
/// other historical helpers. It succeeds only before authenticated earliest
/// deactivation and therefore cannot recreate current use authority.
#[allow(clippy::too_many_arguments)]
pub(super) fn historical_recovery_verification_key<'configuration>(
    configuration: &'configuration crate::RevalidatedProviderConfigurationV1,
    signer: &aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
    verified_at_seconds: i64,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
) -> Result<(&'configuration [u8; 32], bool), SourceProviderSecurityError> {
    let trusted = configuration
        .historical_public_keys()
        .iter()
        .find(|entry| entry.signer() == signer)
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    if configuration.authenticates_historical_key_at(
        trusted,
        verified_at_seconds,
        trust_generation,
        trust_digest,
        revocation_generation,
        revocation_digest,
    ) {
        return Ok((trusted.public_key(), false));
    }
    if configuration.authenticates_revoked_cleanup_key_at(
        trusted,
        verified_at_seconds,
        trust_generation,
        trust_digest,
        revocation_generation,
        revocation_digest,
    ) {
        return Ok((trusted.public_key(), true));
    }
    Err(SourceProviderSecurityError::SessionContinuity)
}
