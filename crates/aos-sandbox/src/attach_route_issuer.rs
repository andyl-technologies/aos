//! Holder-bound OpenSSH certificate issuance for an authorized public attach.
//!
//! The issuer consumes authenticated Host route evidence after public capability
//! authorization. Its output is suitable for the same durable operation plan as
//! the attach mutation. No guest-agent control message can issue this route.

use aos_proto::aos::sandbox::v1::{
    Execution, ExecutionControlRequest, ExecutionIoMode, ExecutionPhase, OpenSshAccessEndpoint,
    Timestamp,
};
use aos_sandbox_core::{OperationId, PrincipalId};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};
use ssh_key::certificate::{Builder, CertType, Certificate};
use ssh_key::{Algorithm, PrivateKey, PublicKey};

use crate::attach_holder_proof::verify_attach_holder_proof_v1;
use crate::{Journal, JournalRecord, RecordNamespace};

const MAXIMUM_CERTIFICATE_SECONDS: i64 = 300;
const NONCE_DOMAIN: &[u8] = b"aos.sandbox.execution.attach-certificate-nonce.v1\0";
const RECORD_MAGIC: &[u8; 8] = b"AOSATR01";
const RECORD_HEADER_BYTES: usize = 8 + 16 + 32 + 4;
const RECORD_DIGEST_BYTES: usize = 32;
const MAXIMUM_ENDPOINT_BYTES: usize = 64 * 1024;

/// Reports invalid route evidence, authority, or attachment binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AttachRouteIssuanceErrorV1 {
    /// The signer is not an unencrypted Ed25519 OpenSSH CA key.
    #[error("execution attachment certificate authority is invalid")]
    InvalidAuthority,
    /// Authenticated Host route evidence has an invalid or stale shape.
    #[error("execution attachment Host route evidence is invalid")]
    InvalidRoute,
    /// The route does not describe the current authorized execution.
    #[error("execution attachment route is not current")]
    StaleExecution,
    /// The request does not prove possession of its exact holder key.
    #[error("execution attachment holder proof is invalid")]
    InvalidHolderProof,
    /// OpenSSH certificate construction or signing failed.
    #[error("execution attachment certificate issuance failed")]
    Certificate,
    /// The exact operation route record is missing or corrupt.
    #[error("execution attachment durable route record is unavailable")]
    DurableRecord,
}

/// Encodes an endpoint as a protected same-operation admission record.
///
/// # Errors
///
/// Rejects an oversized or noncanonical endpoint encoding.
pub(crate) fn public_attach_route_record_v1(
    operation: OperationId,
    request_digest: [u8; 32],
    access: &OpenSshAccessEndpoint,
) -> Result<JournalRecord, AttachRouteIssuanceErrorV1> {
    let payload = access.encode_to_vec();
    let length =
        u32::try_from(payload.len()).map_err(|_| AttachRouteIssuanceErrorV1::DurableRecord)?;
    if payload.is_empty() || payload.len() > MAXIMUM_ENDPOINT_BYTES {
        return Err(AttachRouteIssuanceErrorV1::DurableRecord);
    }
    let mut value = Vec::with_capacity(RECORD_HEADER_BYTES + payload.len() + RECORD_DIGEST_BYTES);
    value.extend_from_slice(RECORD_MAGIC);
    value.extend_from_slice(operation.as_bytes());
    value.extend_from_slice(&request_digest);
    value.extend_from_slice(&length.to_be_bytes());
    value.extend_from_slice(&payload);
    let digest: [u8; 32] = Sha256::digest(&value).into();
    value.extend_from_slice(&digest);
    Ok(JournalRecord::put(
        RecordNamespace::PublicAttachRoute,
        operation.as_bytes().to_vec(),
        value,
    ))
}

/// Loads the exact endpoint retained with an accepted public attach operation.
///
/// # Errors
///
/// Rejects unavailable protected journal custody, missing/corrupt records, or
/// mismatched operation and request identities.
pub(crate) fn load_public_attach_route_v1(
    journal: &Journal,
    operation: OperationId,
    request_digest: [u8; 32],
) -> Result<OpenSshAccessEndpoint, AttachRouteIssuanceErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| AttachRouteIssuanceErrorV1::DurableRecord)?;
    let bytes = journal
        .get(RecordNamespace::PublicAttachRoute, operation.as_bytes())
        .ok_or(AttachRouteIssuanceErrorV1::DurableRecord)?;
    if bytes.len() < RECORD_HEADER_BYTES + RECORD_DIGEST_BYTES
        || bytes.get(..8) != Some(RECORD_MAGIC.as_slice())
        || bytes.get(8..24) != Some(operation.as_bytes().as_slice())
        || bytes.get(24..56) != Some(request_digest.as_slice())
    {
        return Err(AttachRouteIssuanceErrorV1::DurableRecord);
    }
    let length = bytes
        .get(56..60)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(AttachRouteIssuanceErrorV1::DurableRecord)? as usize;
    if length == 0
        || length > MAXIMUM_ENDPOINT_BYTES
        || bytes.len() != RECORD_HEADER_BYTES + length + RECORD_DIGEST_BYTES
    {
        return Err(AttachRouteIssuanceErrorV1::DurableRecord);
    }
    let content_end = RECORD_HEADER_BYTES + length;
    let digest: [u8; 32] = Sha256::digest(&bytes[..content_end]).into();
    if bytes[content_end..] != digest {
        return Err(AttachRouteIssuanceErrorV1::DurableRecord);
    }
    let access = OpenSshAccessEndpoint::decode_from_slice(&bytes[RECORD_HEADER_BYTES..content_end])
        .map_err(|_| AttachRouteIssuanceErrorV1::DurableRecord)?;
    if access.encode_to_vec() != bytes[RECORD_HEADER_BYTES..content_end] {
        return Err(AttachRouteIssuanceErrorV1::DurableRecord);
    }
    Ok(access)
}

/// Carries the exact authenticated Host OpenSSH listener and CA trust state.
///
/// The caller must obtain this evidence from a current authenticated Host
/// owner, bound to the execution incarnation and assignment epoch. This type
/// validates its syntax; construction alone does not authenticate its source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOpenSshRouteV1 {
    /// Exact execution served by the forced-command gate.
    pub execution_id: [u8; 16],
    /// Exact durably reserved attach operation observed by the Host gate.
    pub attach_operation_id: [u8; 16],
    /// Current sandbox incarnation serving this execution.
    pub sandbox_incarnation_id: [u8; 16],
    /// Current assignment epoch for the Host listener.
    pub assignment_epoch: u64,
    /// Authenticated principal named by the forced-command gate.
    pub principal_id: [u8; 16],
    /// Current execution audit identity named by the gate.
    pub audit_id: [u8; 16],
    /// Reachable DNS name or IP address for the listener.
    pub host: String,
    /// Reachable TCP port for the listener.
    pub port: u16,
    /// Fixed guest account restricted by the forced-command gate.
    pub user: String,
    /// Canonical OpenSSH Ed25519 host public key line.
    pub host_public_key: Vec<u8>,
    /// Canonical OpenSSH Ed25519 user CA public key line trusted by the guest.
    pub trusted_user_ca_public_key: Vec<u8>,
    /// Confirms that the gate checks the exact committed attach operation.
    pub forced_command_gate_active: bool,
    /// Digest of the byte-exact protected Host route record.
    pub route_digest: [u8; 32],
    /// Commitment to the fresh authenticated physical gate readback.
    pub gate_observation_commitment: [u8; 32],
    /// Exclusive Unix-second expiry of the authenticated Host route.
    pub expires_at: i64,
}

impl AuthenticatedOpenSshRouteV1 {
    fn validate(&self) -> Result<(), AttachRouteIssuanceErrorV1> {
        if self.execution_id == [0; 16]
            || self.attach_operation_id == [0; 16]
            || self.sandbox_incarnation_id == [0; 16]
            || self.assignment_epoch == 0
            || self.principal_id == [0; 16]
            || self.audit_id == [0; 16]
            || !aos_sandbox_core::public_attach_route::valid_public_attach_host_v1(&self.host)
            || self.port == 0
            || !aos_sandbox_core::public_attach_route::valid_public_attach_user_v1(&self.user)
            || !self.forced_command_gate_active
            || self.route_digest == [0; 32]
            || self.gate_observation_commitment == [0; 32]
            || self.expires_at <= 0
        {
            return Err(AttachRouteIssuanceErrorV1::InvalidRoute);
        }
        canonical_ed25519_key(&self.host_public_key)
            .map_err(|_| AttachRouteIssuanceErrorV1::InvalidRoute)?;
        canonical_ed25519_key(&self.trusted_user_ca_public_key)
            .map_err(|_| AttachRouteIssuanceErrorV1::InvalidRoute)?;
        Ok(())
    }

    fn validate_attach_binding(
        &self,
        request: &ExecutionControlRequest,
        execution: &Execution,
        principal: PrincipalId,
        operation: OperationId,
        request_digest: [u8; 32],
    ) -> Result<(), AttachRouteIssuanceErrorV1> {
        verify_attach_holder_proof_v1(request)
            .map_err(|_| AttachRouteIssuanceErrorV1::InvalidHolderProof)?;
        self.validate()?;
        if operation.as_bytes() == &[0; 16]
            || principal.as_bytes() == &[0; 16]
            || request_digest == [0; 32]
            || self.attach_operation_id != *operation.as_bytes()
            || self.principal_id != *principal.as_bytes()
            || self.audit_id != execution.audit_id.as_slice()
        {
            return Err(AttachRouteIssuanceErrorV1::InvalidRoute);
        }
        Ok(())
    }

    fn matches_current_execution(
        &self,
        request: &ExecutionControlRequest,
        execution: &Execution,
    ) -> bool {
        request.execution_id.as_slice() == self.execution_id
            && request.mutation.as_option().is_some_and(|mutation| {
                mutation.expected_incarnation_id.as_slice() == self.sandbox_incarnation_id
            })
            && execution.execution_id.as_slice() == self.execution_id
            && execution.sandbox_incarnation_id.as_slice() == self.sandbox_incarnation_id
            && execution.assignment_epoch == self.assignment_epoch
            && execution.phase.as_known() == Some(ExecutionPhase::EXECUTION_PHASE_RUNNING)
    }
}

/// Owns one protected OpenSSH user CA key used only for public attach issuance.
pub struct OpenSshAttachRouteIssuerV1 {
    authority: PrivateKey,
}

impl OpenSshAttachRouteIssuerV1 {
    /// Parses an unencrypted Ed25519 OpenSSH user CA key from protected custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed, encrypted, or non-Ed25519 key material.
    pub fn new(authority_key: &[u8]) -> Result<Self, AttachRouteIssuanceErrorV1> {
        let authority = PrivateKey::from_openssh(authority_key)
            .map_err(|_| AttachRouteIssuanceErrorV1::InvalidAuthority)?;
        if authority.is_encrypted() || authority.algorithm() != Algorithm::Ed25519 {
            return Err(AttachRouteIssuanceErrorV1::InvalidAuthority);
        }
        Ok(Self { authority })
    }

    /// Signs one short-lived certificate for a separately authorized attach.
    ///
    /// The caller must retain the returned endpoint with the accepted public
    /// operation. Replays return that retained endpoint after current authority
    /// is rechecked; they must not ask this signer to create another route.
    ///
    /// # Errors
    ///
    /// Rejects invalid holder proof, stale execution or Host route evidence,
    /// mismatched CA trust, expired validity, or signing failure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue(
        &self,
        request: &ExecutionControlRequest,
        execution: &Execution,
        route: &AuthenticatedOpenSshRouteV1,
        principal: PrincipalId,
        operation: OperationId,
        request_digest: [u8; 32],
        now_seconds: i64,
    ) -> Result<OpenSshAccessEndpoint, AttachRouteIssuanceErrorV1> {
        route.validate_attach_binding(request, execution, principal, operation, request_digest)?;

        let authority_key = canonical_ed25519_key(&route.trusted_user_ca_public_key)
            .map_err(|_| AttachRouteIssuanceErrorV1::InvalidRoute)?;
        if authority_key.key_data() != self.authority.public_key().key_data() {
            return Err(AttachRouteIssuanceErrorV1::InvalidAuthority);
        }
        if !route.matches_current_execution(request, execution) {
            return Err(AttachRouteIssuanceErrorV1::StaleExecution);
        }
        let command = execution
            .command
            .as_option()
            .ok_or(AttachRouteIssuanceErrorV1::StaleExecution)?;
        if command.io_mode.as_known() != Some(ExecutionIoMode::EXECUTION_IO_MODE_PTY)
            && command.io_mode.as_known() != Some(ExecutionIoMode::EXECUTION_IO_MODE_STREAM)
        {
            return Err(AttachRouteIssuanceErrorV1::StaleExecution);
        }
        let expires_at = now_seconds
            .checked_add(MAXIMUM_CERTIFICATE_SECONDS)
            .map(|limit| limit.min(route.expires_at))
            .filter(|expiry| now_seconds > 0 && *expiry > now_seconds)
            .ok_or(AttachRouteIssuanceErrorV1::InvalidRoute)?;
        let valid_after =
            u64::try_from(now_seconds).map_err(|_| AttachRouteIssuanceErrorV1::InvalidRoute)?;
        let valid_before =
            u64::try_from(expires_at).map_err(|_| AttachRouteIssuanceErrorV1::InvalidRoute)?;
        let holder = canonical_ed25519_key(&request.client_public_key)
            .map_err(|_| AttachRouteIssuanceErrorV1::InvalidHolderProof)?;

        let nonce = certificate_nonce(operation, request_digest, route, request);
        let serial = u64::from_be_bytes(
            nonce[..8]
                .try_into()
                .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?,
        );

        let forced_command = forced_command(
            operation,
            &route.execution_id,
            &route.sandbox_incarnation_id,
            route.assignment_epoch,
            principal.as_bytes(),
            &execution.audit_id,
        );
        let key_id = certificate_key_id(
            operation,
            &route.execution_id,
            &route.sandbox_incarnation_id,
            principal.as_bytes(),
            &execution.audit_id,
        );
        let mut builder = Builder::new(nonce, holder.key_data().clone(), valid_after, valid_before)
            .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?;
        builder
            .serial(serial)
            .and_then(|builder| builder.cert_type(CertType::User))
            .and_then(|builder| builder.key_id(key_id))
            .and_then(|builder| builder.valid_principal(route.user.clone()))
            .and_then(|builder| builder.critical_option("force-command", forced_command))
            .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?;
        if command.io_mode.as_known() == Some(ExecutionIoMode::EXECUTION_IO_MODE_PTY) {
            builder
                .extension("permit-pty", "")
                .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?;
        }
        let certificate = builder
            .sign(&self.authority)
            .and_then(|certificate| certificate.to_openssh())
            .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?;

        Ok(OpenSshAccessEndpoint {
            host: route.host.clone(),
            port: u32::from(route.port),
            user: route.user.clone(),
            host_public_key: route.host_public_key.clone(),
            client_certificate: certificate.into_bytes(),
            expires_at: Some(Timestamp {
                seconds: expires_at,
                nanoseconds: 0,
                ..Default::default()
            })
            .into(),
            execution_id: route.execution_id.to_vec(),
            sandbox_incarnation_id: route.sandbox_incarnation_id.to_vec(),
            principal_id: principal.as_bytes().to_vec(),
            audit_id: execution.audit_id.clone(),
            stream_features: command.stream_features.clone(),
            ..Default::default()
        })
    }

    /// Validates an exact endpoint retained by an earlier accepted operation.
    ///
    /// Current public authorization and Host route evidence must be checked
    /// before this call. A valid replay never contacts the signer or extends the
    /// original certificate lifetime.
    ///
    /// # Errors
    ///
    /// Rejects expired, rebound, malformed, or improperly signed endpoints.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_recovered(
        &self,
        request: &ExecutionControlRequest,
        execution: &Execution,
        access: &OpenSshAccessEndpoint,
        route: &AuthenticatedOpenSshRouteV1,
        principal: PrincipalId,
        operation: OperationId,
        request_digest: [u8; 32],
        now_seconds: i64,
    ) -> Result<(), AttachRouteIssuanceErrorV1> {
        route.validate_attach_binding(request, execution, principal, operation, request_digest)?;
        let trusted_ca = canonical_ed25519_key(&route.trusted_user_ca_public_key)?;
        if trusted_ca.key_data() != self.authority.public_key().key_data()
            || !route.matches_current_execution(request, execution)
            || access.execution_id.as_slice() != route.execution_id
            || access.sandbox_incarnation_id.as_slice() != route.sandbox_incarnation_id
            || access.principal_id.as_slice() != principal.as_bytes()
            || access.audit_id != execution.audit_id
            || !access.__buffa_unknown_fields.is_empty()
            || access.host != route.host
            || access.port != u32::from(route.port)
            || access.user != route.user
            || access.host_public_key != route.host_public_key
        {
            return Err(AttachRouteIssuanceErrorV1::StaleExecution);
        }
        let command = execution
            .command
            .as_option()
            .ok_or(AttachRouteIssuanceErrorV1::StaleExecution)?;
        if !matches!(
            command.io_mode.as_known(),
            Some(
                ExecutionIoMode::EXECUTION_IO_MODE_PTY | ExecutionIoMode::EXECUTION_IO_MODE_STREAM
            )
        ) || access.stream_features != command.stream_features
        {
            return Err(AttachRouteIssuanceErrorV1::StaleExecution);
        }
        let expiry = access
            .expires_at
            .as_option()
            .ok_or(AttachRouteIssuanceErrorV1::Certificate)?;
        let now =
            u64::try_from(now_seconds).map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?;
        let expiry_seconds =
            u64::try_from(expiry.seconds).map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?;
        if expiry.nanoseconds != 0 || expiry.seconds > route.expires_at || expiry_seconds <= now {
            return Err(AttachRouteIssuanceErrorV1::Certificate);
        }
        let certificate_line = std::str::from_utf8(&access.client_certificate)
            .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?;
        let certificate = Certificate::from_openssh(certificate_line)
            .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?;
        let lifetime = certificate
            .valid_before()
            .checked_sub(certificate.valid_after())
            .ok_or(AttachRouteIssuanceErrorV1::Certificate)?;
        if certificate
            .to_openssh()
            .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?
            .as_bytes()
            != access.client_certificate
            || certificate.cert_type() != CertType::User
            || certificate.valid_before() != expiry_seconds
            || certificate.valid_after() > now
            || lifetime
                > u64::try_from(MAXIMUM_CERTIFICATE_SECONDS)
                    .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?
            || certificate.public_key()
                != canonical_ed25519_key(&request.client_public_key)
                    .map_err(|_| AttachRouteIssuanceErrorV1::InvalidHolderProof)?
                    .key_data()
            || certificate.valid_principals() != [route.user.as_str()]
        {
            return Err(AttachRouteIssuanceErrorV1::Certificate);
        }
        let nonce = certificate_nonce(operation, request_digest, route, request);
        let serial = u64::from_be_bytes(
            nonce[..8]
                .try_into()
                .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)?,
        );
        if certificate.nonce() != nonce
            || certificate.serial() != serial
            || certificate.key_id()
                != certificate_key_id(
                    operation,
                    &route.execution_id,
                    &route.sandbox_incarnation_id,
                    principal.as_bytes(),
                    &execution.audit_id,
                )
            || certificate.critical_options().len() != 1
            || certificate.critical_options().get("force-command")
                != Some(&forced_command(
                    operation,
                    &route.execution_id,
                    &route.sandbox_incarnation_id,
                    route.assignment_epoch,
                    principal.as_bytes(),
                    &execution.audit_id,
                ))
        {
            return Err(AttachRouteIssuanceErrorV1::Certificate);
        }
        let pty = command.io_mode.as_known() == Some(ExecutionIoMode::EXECUTION_IO_MODE_PTY);
        if (pty
            && (certificate.extensions().len() != 1
                || certificate.extensions().get("permit-pty") != Some(&String::new())))
            || (!pty && !certificate.extensions().is_empty())
        {
            return Err(AttachRouteIssuanceErrorV1::Certificate);
        }
        let fingerprint = trusted_ca.fingerprint(Default::default());
        certificate
            .validate_at(now, [&fingerprint])
            .map_err(|_| AttachRouteIssuanceErrorV1::Certificate)
    }
}

fn certificate_nonce(
    operation: OperationId,
    request_digest: [u8; 32],
    route: &AuthenticatedOpenSshRouteV1,
    request: &ExecutionControlRequest,
) -> [u8; 32] {
    let mut nonce_hash = Sha256::new();
    nonce_hash.update(NONCE_DOMAIN);
    nonce_hash.update(operation.as_bytes());
    nonce_hash.update(request_digest);
    nonce_hash.update(route.execution_id);
    nonce_hash.update(route.sandbox_incarnation_id);
    nonce_hash.update(route.assignment_epoch.to_be_bytes());
    nonce_hash.update((route.host.len() as u16).to_be_bytes());
    nonce_hash.update(route.host.as_bytes());
    nonce_hash.update(route.port.to_be_bytes());
    nonce_hash.update((route.user.len() as u16).to_be_bytes());
    nonce_hash.update(route.user.as_bytes());
    nonce_hash.update((route.host_public_key.len() as u16).to_be_bytes());
    nonce_hash.update(&route.host_public_key);
    nonce_hash.update((route.trusted_user_ca_public_key.len() as u16).to_be_bytes());
    nonce_hash.update(&route.trusted_user_ca_public_key);
    nonce_hash.update((request.client_public_key.len() as u16).to_be_bytes());
    nonce_hash.update(&request.client_public_key);
    nonce_hash.finalize().into()
}

fn certificate_key_id(
    operation: OperationId,
    execution: &[u8],
    incarnation: &[u8],
    principal: &[u8],
    audit: &[u8],
) -> String {
    format!(
        "aos-exec:{}:{}:{}:{}:{}",
        hex_id(operation.as_bytes()),
        hex_id(execution),
        hex_id(incarnation),
        hex_id(principal),
        hex_id(audit)
    )
}

fn forced_command(
    operation: OperationId,
    execution: &[u8],
    incarnation: &[u8],
    assignment_epoch: u64,
    principal: &[u8],
    audit: &[u8],
) -> String {
    format!(
        "/usr/libexec/aos-sandbox-exec-gate --operation-id {} --execution-id {} --incarnation-id {} --assignment-epoch {} --principal-id {} --audit-id {}",
        hex_id(operation.as_bytes()),
        hex_id(execution),
        hex_id(incarnation),
        assignment_epoch,
        hex_id(principal),
        hex_id(audit)
    )
}

fn canonical_ed25519_key(bytes: &[u8]) -> Result<PublicKey, AttachRouteIssuanceErrorV1> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(AttachRouteIssuanceErrorV1::InvalidRoute);
    }
    let line = std::str::from_utf8(bytes).map_err(|_| AttachRouteIssuanceErrorV1::InvalidRoute)?;
    let key =
        PublicKey::from_openssh(line).map_err(|_| AttachRouteIssuanceErrorV1::InvalidRoute)?;
    if key.algorithm() != Algorithm::Ed25519
        || key
            .to_openssh()
            .map_err(|_| AttachRouteIssuanceErrorV1::InvalidRoute)?
            .as_bytes()
            != bytes
    {
        return Err(AttachRouteIssuanceErrorV1::InvalidRoute);
    }
    Ok(key)
}

fn hex_id(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}
