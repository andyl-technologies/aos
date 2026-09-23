//! Fixed protected Host ownership of OpenSSH attach-route records.
//!
//! One record per execution lives in the root-owned Host execution journal.
//! The record pins the endpoint, host key, trusted user CA, incarnation,
//! assignment, and expiry. A record alone does not establish that the guest
//! `sshd` and forced-command gate are running with those values. A fresh
//! Host challenge and signed guest physical readback must match the protected
//! route and agent peer. The synchronous route remains unavailable until the
//! protected channel connects that exchange to service dispatch.
//!
//! ```text
//! /var/lib/aos/sandbox-host/openssh-attach-route.journal
//! HostExecution key = "openssh-attach-route-v1/" || execution_id[16]
//! value = canonical JSON RouteRecordV1 with deny_unknown_fields
//! ```
//!
//! The externally supplied systemd trust credential is compact canonical
//! JSON with exactly these static fields; no per-operation config digest or
//! private host key belongs in it:
//!
//! ```text
//! {"magic":"AOSHAT01","host":"guest.example","port":2222,"user":"aos_exec","host_public_key":"ssh-ed25519 ...","trusted_user_ca_public_key":"ssh-ed25519 ..."}
//! ```

use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::time::{SystemTime, UNIX_EPOCH};

use aos_proto::aos::sandbox::local::v1::HostAttachGateEvidenceV1;
use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionOwnerErrorV1, DormantRuntimeExecutionOwnerV1,
};
use aos_sandbox::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_agent::openssh_gate::{
    OpenSshGateBindingV1, OpenSshGateObserveRequestV1, OpenSshGateReadbackErrorV1,
    OpenSshGateReadbackV1, verify_openssh_gate_readback_v1,
};
use aos_sandbox_agent::openssh_gate_linux::expected_openssh_gate_config_v1;
use aos_sandbox_agent::{AgentFrameV1, AgentProtocolError, decode_frame_v1, encode_frame_v1};
use aos_sandbox_core::public_attach_grant::{
    PublicAttachGrantErrorV1, PublicAttachPendingGrantV1, verify_public_attach_pending_grant_v1,
};
use aos_sandbox_core::{ExecutionId, VerifiedOwnershipLease};
use buffa::Message as _;
use ed25519_dalek::VerifyingKey;
use rand::{TryRngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use ssh_key::{Algorithm, PublicKey};

const HOST_STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const ROUTE_JOURNAL_NAME: &str = "openssh-attach-route.journal";
const ROUTE_KEY_PREFIX: &[u8] = b"openssh-attach-route-v1/";
const ROUTE_MAGIC: &str = "AOSHAR01";
const ROUTE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.host.openssh-attach-route.v1\0";
const TRUST_CREDENTIAL_PATH: &str =
    "/run/credentials/aos-sandbox-hostd.service/openssh-attach-trust.json";
const GRANT_KEY_CREDENTIAL_PATH: &str =
    "/run/credentials/aos-sandbox-hostd.service/openssh-attach-grant-public-key";
const TRUST_MAGIC: &str = "AOSHAT01";
const GRANT_RESERVATION_PREFIX: &[u8] = b"openssh-attach-grant-v1/";
const REVOKED_ROUTE_PREFIX: &[u8] = b"openssh-attach-revoked-v1/";
const REVOKED_ROUTE_MAGIC: &[u8; 8] = b"AOSHRV01";
const O_NOFOLLOW: i32 = 0o400_000;
const O_CLOEXEC: i32 = 0o2_000_000;
const MAXIMUM_ROUTE_BYTES: usize = 2048;
const MAXIMUM_HOST_BYTES: usize = 255;
const MAXIMUM_USER_BYTES: usize = 32;
const MAXIMUM_KEY_BYTES: usize = 128;

/// Owns the fixed root-protected OpenSSH route journal.
pub struct HostOpenSshAttachRouteOwnerV1 {
    journal: Journal,
}

/// Exchanges one frame on a retained, authenticated guest-agent session.
///
/// The transport owner must retain the original protected channel, not connect
/// to an operator-selected endpoint. The signed response is checked against
/// protected peer identity independently of transport success.
pub trait OpenSshGateAgentExchangeV1 {
    /// Sends one exact frame and returns one bounded response frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the authenticated channel is no longer available.
    fn exchange(&mut self, request: &[u8]) -> std::io::Result<Vec<u8>>;
}

impl HostOpenSshAttachRouteOwnerV1 {
    /// Verifies the exact pending receipt under the dedicated protected key.
    ///
    /// # Errors
    ///
    /// Rejects an absent or insecure verifier credential, malformed packet,
    /// invalid signature, or sentinel grant field.
    pub fn verify_pending_grant(
        packet: &[u8],
    ) -> Result<PublicAttachPendingGrantV1, HostOpenSshAttachRouteErrorV1> {
        let verifier_bytes = read_fixed_credential(GRANT_KEY_CREDENTIAL_PATH, 32)?;
        let verifier: [u8; 32] = verifier_bytes
            .try_into()
            .map_err(|_| HostOpenSshAttachRouteErrorV1::TrustUnavailable)?;
        let verifier = VerifyingKey::from_bytes(&verifier)
            .map_err(|_| HostOpenSshAttachRouteErrorV1::TrustUnavailable)?;
        verify_public_attach_pending_grant_v1(packet, &verifier).map_err(Into::into)
    }

    /// Opens and exclusively claims the fixed Host route journal.
    ///
    /// # Errors
    ///
    /// Returns an error if protected storage, its lock, or journal replay is
    /// unavailable or if another authority namespace is present.
    pub fn open() -> Result<Self, HostOpenSshAttachRouteErrorV1> {
        let (mut journal, _) = Journal::open_protected_at(
            HOST_STATE_ROOT,
            ROUTE_JOURNAL_NAME,
            JournalLimits::default(),
        )?;
        let authority = journal.claim_protected_authority(RecordNamespace::HostExecution)?;
        drop(authority);
        Ok(Self { journal })
    }

    /// Durably reserves one route from a dedicated-key controller pending grant.
    ///
    /// The caller must supply a freshly verified live ownership lease. This
    /// method independently checks the grant signer, external deployment trust,
    /// current protected Host runtime and admitted execution. Its one-time
    /// grant marker and route record commit atomically. It does not assert that
    /// the guest gate is installed; only live readback can do that.
    ///
    /// # Errors
    ///
    /// Returns an error for missing credentials, invalid grant/lease/currentness,
    /// reused grant, or failed protected journal durability.
    pub fn reserve_from_pending_grant(
        &mut self,
        packet: &[u8],
        lease: &VerifiedOwnershipLease,
    ) -> Result<(), HostOpenSshAttachRouteErrorV1> {
        let grant = Self::verify_pending_grant(packet)?;
        let (trust, trust_digest) = read_deployment_trust()?;
        if grant.trust_digest != trust_digest || grant.expires_at <= current_unix_seconds()? {
            return Err(HostOpenSshAttachRouteErrorV1::TrustMismatch);
        }
        validate_grant_currentness(&grant, lease)?;

        let mut key = ROUTE_KEY_PREFIX.to_vec();
        key.extend_from_slice(&grant.execution_id);
        let mut reservation_key = GRANT_RESERVATION_PREFIX.to_vec();
        reservation_key.extend_from_slice(&grant.operation_id);
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        if authority
            .get(&revoked_route_key(grant.operation_id))?
            .is_some()
        {
            return Err(HostOpenSshAttachRouteErrorV1::Revoked);
        }
        let grant_digest = Sha256::digest(packet);
        if let Some(previous_digest) = authority.get(&reservation_key)? {
            let previous_route = authority
                .get(&key)?
                .ok_or(HostOpenSshAttachRouteErrorV1::Stale)
                .and_then(decode_route_record)?;
            if previous_route.execution_id != grant.execution_id
                || previous_route.attach_operation_id != grant.operation_id
                || previous_route.incarnation_id != grant.incarnation_id
                || previous_route.assignment_epoch != grant.assignment_epoch
                || previous_route.principal_id != grant.principal_id
                || previous_route.audit_id != grant.audit_id
                || !route_matches_trust(&previous_route, &trust)
            {
                return Err(HostOpenSshAttachRouteErrorV1::Stale);
            }
            if previous_digest == grant_digest.as_slice() {
                if previous_route.expires_at != grant.expires_at
                    || previous_route.gate_config_digest != grant.gate_config_digest
                {
                    return Err(HostOpenSshAttachRouteErrorV1::Stale);
                }
                return Ok(());
            }
            // An expired pending reservation can be renewed under the same
            // controller operation, but never while the old grant is live.
            if previous_route.expires_at >= current_unix_seconds()?
                || grant.expires_at <= previous_route.expires_at
            {
                return Err(HostOpenSshAttachRouteErrorV1::GrantReused);
            }
        }
        let route_generation = match authority.get(&key)? {
            Some(previous) => decode_route_record(previous)?
                .route_generation
                .checked_add(1)
                .ok_or(HostOpenSshAttachRouteErrorV1::Stale)?,
            None => 1,
        };
        let route = RouteRecordV1 {
            magic: ROUTE_MAGIC.to_owned(),
            execution_id: grant.execution_id,
            attach_operation_id: grant.operation_id,
            incarnation_id: grant.incarnation_id,
            assignment_epoch: grant.assignment_epoch,
            principal_id: grant.principal_id,
            audit_id: grant.audit_id,
            host: trust.host,
            port: trust.port,
            user: trust.user,
            host_public_key: trust.host_public_key,
            trusted_user_ca_public_key: trust.trusted_user_ca_public_key,
            expires_at: grant.expires_at,
            route_generation,
            gate_config_digest: grant.gate_config_digest,
        };
        let bytes =
            serde_json::to_vec(&route).map_err(|_| HostOpenSshAttachRouteErrorV1::Malformed)?;
        decode_route_record(&bytes)?;
        let transaction_id = route_transaction_id_v1(grant.operation_id, grant_digest.as_slice())?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![
                JournalRecord::put(RecordNamespace::HostExecution, key, bytes),
                JournalRecord::put(
                    RecordNamespace::HostExecution,
                    reservation_key,
                    grant_digest.to_vec(),
                ),
            ],
        )?;
        authority.commit(&transaction)?;
        Ok(())
    }

    /// Permanently tombstones one locally owned attach operation.
    ///
    /// Only the protected Host owner may call this after authenticating a
    /// terminal action. The marker is never removed, including after expiry,
    /// so a renewed pending grant cannot resurrect the same operation.
    /// There is not yet a controller-to-Host revocation relay.
    ///
    /// # Errors
    ///
    /// Returns an error if the route is absent, belongs to another operation,
    /// or protected storage cannot durably record the tombstone.
    pub fn revoke_local_operation(
        &mut self,
        operation_id: [u8; 16],
        execution_id: [u8; 16],
    ) -> Result<(), HostOpenSshAttachRouteErrorV1> {
        if operation_id == [0; 16] || execution_id == [0; 16] {
            return Err(HostOpenSshAttachRouteErrorV1::Malformed);
        }
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        let revocation_key = revoked_route_key(operation_id);
        if let Some(marker) = authority.get(&revocation_key)? {
            return validate_revocation_marker(marker, operation_id, execution_id);
        }

        let mut route_key = ROUTE_KEY_PREFIX.to_vec();
        route_key.extend_from_slice(&execution_id);
        let route = authority
            .get(&route_key)?
            .ok_or(HostOpenSshAttachRouteErrorV1::Missing)
            .and_then(decode_route_record)?;
        if route.attach_operation_id != operation_id || route.execution_id != execution_id {
            return Err(HostOpenSshAttachRouteErrorV1::Stale);
        }

        let marker = revocation_marker(operation_id, execution_id);
        let transaction_id = revocation_transaction_id(operation_id, execution_id)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::HostExecution,
                revocation_key,
                marker,
            )],
        )?;
        authority.commit(&transaction)?;
        Ok(())
    }

    /// Reads one protected route and the live forced-command gate.
    ///
    /// The identity arguments select a record and must equal its protected
    /// identity. They do not supply endpoint or gate authority. A pending
    /// execution effect, stored route, SSH banner, or reachable TCP port is not
    /// evidence that `sshd` enforces the exact CA and forced command.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, stale, expired, or malformed protected
    /// route, or while authenticated physical gate readback is unavailable.
    pub fn observe_active(
        &mut self,
        execution_id: [u8; 16],
        incarnation_id: [u8; 16],
        assignment_epoch: u64,
    ) -> Result<HostOpenSshAttachRouteEvidenceV1, HostOpenSshAttachRouteErrorV1> {
        let _pending = self.begin_observe_active(execution_id, incarnation_id, assignment_epoch)?;
        Err(HostOpenSshAttachRouteErrorV1::LiveGateUnavailable)
    }

    /// Measures an installed gate on an already-authenticated agent session.
    ///
    /// The session binding must be that of `exchange`'s retained handshake;
    /// the guest checks it before any installation. The signed response is
    /// then compared with the protected Host peer and route currentness.
    ///
    /// # Errors
    ///
    /// Returns an error for transport loss, malformed framing, or mismatched
    /// physical readback.
    pub fn observe_active_on_session(
        &mut self,
        execution_id: [u8; 16],
        incarnation_id: [u8; 16],
        assignment_epoch: u64,
        session_binding: [u8; 32],
        exchange: &mut impl OpenSshGateAgentExchangeV1,
    ) -> Result<HostOpenSshAttachRouteEvidenceV1, HostOpenSshAttachRouteErrorV1> {
        let pending = self.begin_observe_active(execution_id, incarnation_id, assignment_epoch)?;
        let request = pending.request_frame(session_binding)?;
        let response = exchange.exchange(&request)?;
        pending.complete_frame(self, &response)
    }

    /// Starts a fresh challenge for a protected guest-agent gate readback.
    ///
    /// The caller must deliver this challenge over the protected guest-agent
    /// channel and return the guest's signed physical readback to `complete`.
    ///
    /// # Errors
    ///
    /// Returns an error if the route is stale or OS entropy is unavailable.
    pub fn begin_observe_active(
        &mut self,
        execution_id: [u8; 16],
        incarnation_id: [u8; 16],
        assignment_epoch: u64,
    ) -> Result<PendingOpenSshGateObservationV1, HostOpenSshAttachRouteErrorV1> {
        let protected = self.read_protected(execution_id, incarnation_id, assignment_epoch)?;
        let mut challenge = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut challenge)
            .map_err(|_| HostOpenSshAttachRouteErrorV1::Entropy)?;
        if challenge == [0; 32] {
            return Err(HostOpenSshAttachRouteErrorV1::Entropy);
        }
        Ok(PendingOpenSshGateObservationV1 {
            protected,
            challenge,
        })
    }

    fn read_protected(
        &mut self,
        execution_id: [u8; 16],
        incarnation_id: [u8; 16],
        assignment_epoch: u64,
    ) -> Result<ProtectedRouteV1, HostOpenSshAttachRouteErrorV1> {
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        let mut key = ROUTE_KEY_PREFIX.to_vec();
        key.extend_from_slice(&execution_id);
        let bytes = authority
            .get(&key)?
            .ok_or(HostOpenSshAttachRouteErrorV1::Missing)?;
        let route = decode_route_record(bytes)?;
        if let Some(marker) = authority.get(&revoked_route_key(route.attach_operation_id))? {
            validate_revocation_marker(marker, route.attach_operation_id, route.execution_id)?;
            return Err(HostOpenSshAttachRouteErrorV1::Revoked);
        }
        if route.execution_id != execution_id
            || route.incarnation_id != incarnation_id
            || route.assignment_epoch != assignment_epoch
        {
            return Err(HostOpenSshAttachRouteErrorV1::Stale);
        }
        validate_current_execution(&route)?;
        validate_deployment_trust(&route)?;
        if route.expires_at <= current_unix_seconds()? {
            return Err(HostOpenSshAttachRouteErrorV1::Expired);
        }

        let mut digest = Sha256::new();
        digest.update(ROUTE_DIGEST_DOMAIN);
        digest.update(bytes);
        Ok(ProtectedRouteV1 {
            record: route,
            route_digest: digest.finalize().into(),
        })
    }
}

fn revoked_route_key(operation_id: [u8; 16]) -> Vec<u8> {
    let mut key = REVOKED_ROUTE_PREFIX.to_vec();
    key.extend_from_slice(&operation_id);
    key
}

fn revocation_marker(operation_id: [u8; 16], execution_id: [u8; 16]) -> Vec<u8> {
    let mut marker = Vec::with_capacity(40);
    marker.extend_from_slice(REVOKED_ROUTE_MAGIC);
    marker.extend_from_slice(&operation_id);
    marker.extend_from_slice(&execution_id);
    marker
}

fn validate_revocation_marker(
    marker: &[u8],
    operation_id: [u8; 16],
    execution_id: [u8; 16],
) -> Result<(), HostOpenSshAttachRouteErrorV1> {
    if marker != revocation_marker(operation_id, execution_id) {
        return Err(HostOpenSshAttachRouteErrorV1::Malformed);
    }
    Ok(())
}

fn revocation_transaction_id(
    operation_id: [u8; 16],
    execution_id: [u8; 16],
) -> Result<[u8; 16], HostOpenSshAttachRouteErrorV1> {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.host.openssh-attach-revocation-transaction.v1\0");
    hash.update(operation_id);
    hash.update(execution_id);
    hash.finalize()[..16]
        .try_into()
        .map_err(|_| HostOpenSshAttachRouteErrorV1::Malformed)
}

fn route_transaction_id_v1(
    operation_id: [u8; 16],
    grant_digest: &[u8],
) -> Result<[u8; 16], HostOpenSshAttachRouteErrorV1> {
    let mut hash = Sha256::new();
    hash.update(b"aos.sandbox.host.openssh-attach-route-transaction.v1\0");
    hash.update(operation_id);
    hash.update(grant_digest);
    let digest = hash.finalize();
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| HostOpenSshAttachRouteErrorV1::Malformed)?;
    if transaction_id == [0; 16] {
        return Err(HostOpenSshAttachRouteErrorV1::Malformed);
    }
    Ok(transaction_id)
}

/// Retains a protected route while its fresh challenge is measured by the guest.
pub struct PendingOpenSshGateObservationV1 {
    protected: ProtectedRouteV1,
    challenge: [u8; 32],
}

impl PendingOpenSshGateObservationV1 {
    /// Returns the nonce the guest must sign after physical readback.
    #[must_use]
    pub const fn challenge(&self) -> [u8; 32] {
        self.challenge
    }

    /// Returns the protected route commitment sent to the guest for readback.
    #[must_use]
    pub const fn route_digest(&self) -> [u8; 32] {
        self.protected.route_digest
    }

    /// Encodes the exact install/readback request for a retained agent session.
    ///
    /// # Errors
    ///
    /// Returns an error if the session or protected route cannot be encoded.
    pub fn request_frame(
        &self,
        session_binding: [u8; 32],
    ) -> Result<Vec<u8>, HostOpenSshAttachRouteErrorV1> {
        let request = OpenSshGateObserveRequestV1 {
            session_binding,
            challenge: self.challenge,
            route_digest: self.protected.route_digest,
            binding: self.protected.gate_binding(),
        };
        request
            .validate()
            .map_err(HostOpenSshAttachRouteErrorV1::Readback)?;
        let bytes =
            serde_json::to_vec(&request).map_err(|_| HostOpenSshAttachRouteErrorV1::Malformed)?;
        if bytes.len() > 4096 {
            return Err(HostOpenSshAttachRouteErrorV1::Malformed);
        }
        Ok(encode_frame_v1(&AgentFrameV1::OpenSshGateObserveRequest(
            bytes,
        )))
    }

    /// Decodes one authenticated channel response and verifies its signed gate.
    ///
    /// # Errors
    ///
    /// Returns an error if framing or physical gate evidence is invalid.
    pub fn complete_frame(
        self,
        owner: &mut HostOpenSshAttachRouteOwnerV1,
        frame: &[u8],
    ) -> Result<HostOpenSshAttachRouteEvidenceV1, HostOpenSshAttachRouteErrorV1> {
        let AgentFrameV1::OpenSshGateReadback(packet) = decode_frame_v1(frame)? else {
            return Err(HostOpenSshAttachRouteErrorV1::GateMismatch);
        };
        self.complete(owner, &packet)
    }

    /// Authenticates one guest packet and rechecks protected currentness.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet signature, physical gate binding,
    /// protected peer, route, or current execution changed during readback.
    pub fn complete(
        self,
        owner: &mut HostOpenSshAttachRouteOwnerV1,
        packet: &[u8],
    ) -> Result<HostOpenSshAttachRouteEvidenceV1, HostOpenSshAttachRouteErrorV1> {
        let mut runtime_owner = DormantRuntimeExecutionOwnerV1::open()?;
        let current = runtime_owner.claim()?;
        let peer = current.agent_peer();
        let runtime = current.currentness().runtime().currentness();
        if runtime.incarnation().as_bytes() != &self.protected.record.incarnation_id
            || runtime.assignment_epoch().get() != self.protected.record.assignment_epoch
        {
            return Err(HostOpenSshAttachRouteErrorV1::Stale);
        }
        let (readback, commitment) = verify_openssh_gate_readback_v1(packet, &peer.public_key())?;
        verify_readback_binding(
            &self.protected,
            self.challenge,
            *peer.channel_binding().as_bytes(),
            &readback,
        )?;
        drop(current);
        drop(runtime_owner);

        let latest = owner.read_protected(
            self.protected.record.execution_id,
            self.protected.record.incarnation_id,
            self.protected.record.assignment_epoch,
        )?;
        if latest.route_digest != self.protected.route_digest {
            return Err(HostOpenSshAttachRouteErrorV1::Stale);
        }
        let route = latest.record;
        Ok(HostOpenSshAttachRouteEvidenceV1 {
            execution_id: route.execution_id,
            attach_operation_id: route.attach_operation_id,
            incarnation_id: route.incarnation_id,
            assignment_epoch: route.assignment_epoch,
            principal_id: route.principal_id,
            audit_id: route.audit_id,
            host: route.host,
            port: route.port,
            user: route.user,
            host_public_key: route.host_public_key,
            trusted_user_ca_public_key: route.trusted_user_ca_public_key,
            expires_at: route.expires_at,
            route_generation: route.route_generation,
            route_digest: latest.route_digest,
            gate_observation_commitment: commitment,
            signed_gate_readback: packet.to_vec(),
            forced_command_gate_active: true,
        })
    }
}

fn verify_readback_binding(
    protected: &ProtectedRouteV1,
    challenge: [u8; 32],
    channel_binding: [u8; 32],
    readback: &OpenSshGateReadbackV1,
) -> Result<(), HostOpenSshAttachRouteErrorV1> {
    if readback.challenge != challenge
        || readback.route_digest != protected.route_digest
        || readback.channel_binding != channel_binding
        || readback.binding != protected.gate_binding()
    {
        return Err(HostOpenSshAttachRouteErrorV1::GateMismatch);
    }
    Ok(())
}

/// Authenticated Host route fields usable only after live gate readback agrees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostOpenSshAttachRouteEvidenceV1 {
    /// Exact execution selected by the protected Host record.
    pub(crate) execution_id: [u8; 16],
    /// Exact durably admitted attach operation named by the forced command.
    pub(crate) attach_operation_id: [u8; 16],
    /// Current sandbox incarnation observed by the gate.
    pub(crate) incarnation_id: [u8; 16],
    /// Current assignment generation observed by the gate.
    pub(crate) assignment_epoch: u64,
    /// Principal named by the admitted forced command.
    pub(crate) principal_id: [u8; 16],
    /// Audit identity named by the admitted forced command.
    pub(crate) audit_id: [u8; 16],
    /// Pinned OpenSSH endpoint host.
    pub(crate) host: String,
    /// Pinned OpenSSH endpoint port.
    pub(crate) port: u16,
    /// Pinned login account.
    pub(crate) user: String,
    /// Canonical Ed25519 server host public key line.
    pub(crate) host_public_key: String,
    /// Canonical Ed25519 user certificate authority public key line.
    pub(crate) trusted_user_ca_public_key: String,
    /// Route expiry as Unix seconds.
    pub(crate) expires_at: i64,
    /// Generation retained by the protected route record.
    pub(crate) route_generation: u64,
    /// Digest of the byte-exact protected route record.
    pub(crate) route_digest: [u8; 32],
    /// Commitment to the signed, fresh physical gate observation.
    pub(crate) gate_observation_commitment: [u8; 32],
    /// Exact signed physical readback packet authenticated on the retained guest session.
    pub(crate) signed_gate_readback: Vec<u8>,
    /// True only when the physical gate readback matched this route.
    pub(crate) forced_command_gate_active: bool,
}

impl HostOpenSshAttachRouteEvidenceV1 {
    /// Checks the exact accepted operation and execution without exposing mutable fields.
    #[must_use]
    pub fn matches_operation_execution(
        &self,
        operation_id: [u8; 16],
        execution_id: [u8; 16],
    ) -> bool {
        self.attach_operation_id == operation_id && self.execution_id == execution_id
    }

    /// Encodes the full authenticated Host broker response for the controller.
    ///
    /// The signed readback remains present so a controller can retain the
    /// precise physical evidence rather than relying on a boolean claim.
    #[must_use]
    pub fn encode_wire(&self) -> Vec<u8> {
        HostAttachGateEvidenceV1 {
            operation_id: self.attach_operation_id.to_vec(),
            execution_id: self.execution_id.to_vec(),
            incarnation_id: self.incarnation_id.to_vec(),
            assignment_epoch: self.assignment_epoch,
            principal_id: self.principal_id.to_vec(),
            audit_id: self.audit_id.to_vec(),
            host: self.host.clone(),
            port: u32::from(self.port),
            user: self.user.clone(),
            host_public_key: self.host_public_key.as_bytes().to_vec(),
            trusted_user_ca_public_key: self.trusted_user_ca_public_key.as_bytes().to_vec(),
            expires_at: self.expires_at,
            route_generation: self.route_generation,
            route_digest: self.route_digest.to_vec(),
            gate_observation_commitment: self.gate_observation_commitment.to_vec(),
            signed_gate_readback: self.signed_gate_readback.clone(),
            ..Default::default()
        }
        .encode_to_vec()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RouteRecordV1 {
    magic: String,
    execution_id: [u8; 16],
    attach_operation_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    principal_id: [u8; 16],
    audit_id: [u8; 16],
    host: String,
    port: u16,
    user: String,
    host_public_key: String,
    trusted_user_ca_public_key: String,
    expires_at: i64,
    route_generation: u64,
    gate_config_digest: [u8; 32],
}

/// Exact externally provisioned systemd credential for one gate route.
///
/// The credential is an independent deployment trust input, not a route
/// assertion or evidence that the guest installed anything. Per-operation
/// configuration is derived from the signed grant and these static pins.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeploymentTrustV1 {
    magic: String,
    host: String,
    port: u16,
    user: String,
    host_public_key: String,
    trusted_user_ca_public_key: String,
}

/// Exposes only canonical public OpenSSH pins from a protected Host credential.
///
/// This value is not live gate evidence. Consumers still verify current Host
/// admission, an exact signed pending grant, and fresh guest readback.
pub struct HostOpenSshStaticTrustV1 {
    host_public_key: String,
    trusted_user_ca_public_key: String,
    credential_digest: [u8; 32],
}

impl HostOpenSshStaticTrustV1 {
    /// Loads the fixed root-owned credential and validates its canonical pins.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential is absent, mutable by untrusted
    /// accounts, malformed, or contains noncanonical OpenSSH keys.
    pub fn load_protected() -> Result<Self, HostOpenSshAttachRouteErrorV1> {
        let (trust, credential_digest) = read_deployment_trust()?;
        Ok(Self {
            host_public_key: trust.host_public_key,
            trusted_user_ca_public_key: trust.trusted_user_ca_public_key,
            credential_digest,
        })
    }

    /// Returns the exact canonical server host public key line.
    #[must_use]
    pub fn host_public_key(&self) -> &str {
        &self.host_public_key
    }

    /// Returns the exact canonical trusted user CA public key line.
    #[must_use]
    pub fn trusted_user_ca_public_key(&self) -> &str {
        &self.trusted_user_ca_public_key
    }

    /// Returns the SHA-256 digest of the canonical credential bytes.
    #[must_use]
    pub const fn credential_digest(&self) -> [u8; 32] {
        self.credential_digest
    }
}

struct ProtectedRouteV1 {
    record: RouteRecordV1,
    route_digest: [u8; 32],
}

impl ProtectedRouteV1 {
    fn gate_binding(&self) -> OpenSshGateBindingV1 {
        OpenSshGateBindingV1 {
            execution_id: self.record.execution_id,
            attach_operation_id: self.record.attach_operation_id,
            incarnation_id: self.record.incarnation_id,
            assignment_epoch: self.record.assignment_epoch,
            principal_id: self.record.principal_id,
            audit_id: self.record.audit_id,
            port: self.record.port,
            user: self.record.user.clone(),
            host_public_key: self.record.host_public_key.clone(),
            trusted_user_ca_public_key: self.record.trusted_user_ca_public_key.clone(),
            expires_at: self.record.expires_at,
            gate_config_digest: self.record.gate_config_digest,
        }
    }
}

fn validate_current_execution(route: &RouteRecordV1) -> Result<(), HostOpenSshAttachRouteErrorV1> {
    let mut runtime_owner = DormantRuntimeExecutionOwnerV1::open()?;
    let current = runtime_owner.claim()?;
    let admission = current
        .load_admission(ExecutionId::from_bytes(route.execution_id))?
        .ok_or(HostOpenSshAttachRouteErrorV1::Stale)?;
    let runtime = current.currentness().runtime().currentness();
    if admission.currentness() != current.currentness()
        || runtime.incarnation().as_bytes() != &route.incarnation_id
        || runtime.assignment_epoch().get() != route.assignment_epoch
    {
        return Err(HostOpenSshAttachRouteErrorV1::Stale);
    }
    Ok(())
}

fn validate_grant_currentness(
    grant: &PublicAttachPendingGrantV1,
    lease: &VerifiedOwnershipLease,
) -> Result<(), HostOpenSshAttachRouteErrorV1> {
    let mut runtime_owner = DormantRuntimeExecutionOwnerV1::open()?;
    let current = runtime_owner.claim()?;
    let runtime = current.currentness().runtime().currentness();
    let admission = current
        .load_admission(ExecutionId::from_bytes(grant.execution_id))?
        .ok_or(HostOpenSshAttachRouteErrorV1::Stale)?;
    let lease_assignment = lease.lease().assignment();
    if admission.currentness() != current.currentness()
        || runtime.sandbox().as_bytes() != &grant.sandbox_id
        || runtime.incarnation().as_bytes() != &grant.incarnation_id
        || runtime.node().as_bytes() != &grant.node_id
        || runtime.assignment_epoch().get() != grant.assignment_epoch
        || runtime.desired_generation().get() != grant.desired_generation
        || runtime.namespace_generation().get() != grant.namespace_generation
        || runtime.assignment_digest().as_bytes() != &grant.assignment_digest
        || lease_assignment.sandbox().as_bytes() != &grant.sandbox_id
        || lease_assignment.incarnation().as_bytes() != &grant.incarnation_id
        || lease_assignment.epoch().get() != grant.assignment_epoch
        || lease_assignment.digest().as_bytes() != &grant.assignment_digest
        || lease.lease().node().as_bytes() != &grant.node_id
        || lease.lease().lease_generation() != grant.lease_generation
        || lease.lease_digest().as_bytes() != &grant.lease_digest
    {
        return Err(HostOpenSshAttachRouteErrorV1::Stale);
    }
    Ok(())
}

fn validate_deployment_trust(route: &RouteRecordV1) -> Result<(), HostOpenSshAttachRouteErrorV1> {
    let (trust, _) = read_deployment_trust()?;
    if !route_matches_trust(route, &trust) {
        return Err(HostOpenSshAttachRouteErrorV1::TrustMismatch);
    }
    Ok(())
}

fn route_matches_trust(route: &RouteRecordV1, trust: &DeploymentTrustV1) -> bool {
    trust.host == route.host
        && trust.port == route.port
        && trust.user == route.user
        && trust.host_public_key == route.host_public_key
        && trust.trusted_user_ca_public_key == route.trusted_user_ca_public_key
}

fn read_deployment_trust() -> Result<(DeploymentTrustV1, [u8; 32]), HostOpenSshAttachRouteErrorV1> {
    let bytes = read_fixed_credential(TRUST_CREDENTIAL_PATH, MAXIMUM_ROUTE_BYTES)?;
    decode_deployment_trust(&bytes)
}

fn decode_deployment_trust(
    bytes: &[u8],
) -> Result<(DeploymentTrustV1, [u8; 32]), HostOpenSshAttachRouteErrorV1> {
    let trust: DeploymentTrustV1 = serde_json::from_slice(bytes)
        .map_err(|_| HostOpenSshAttachRouteErrorV1::TrustUnavailable)?;
    if serde_json::to_vec(&trust).map_err(|_| HostOpenSshAttachRouteErrorV1::TrustUnavailable)?
        != bytes
        || trust.magic != TRUST_MAGIC
        || !valid_host(&trust.host)
        || trust.port == 0
        || !valid_user(&trust.user)
        || !canonical_ed25519_key(&trust.host_public_key)
        || !canonical_ed25519_key(&trust.trusted_user_ca_public_key)
    {
        return Err(HostOpenSshAttachRouteErrorV1::TrustUnavailable);
    }
    let digest = Sha256::digest(bytes).into();
    Ok((trust, digest))
}

fn read_fixed_credential(
    path: &str,
    maximum: usize,
) -> Result<Vec<u8>, HostOpenSshAttachRouteErrorV1> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)
        .map_err(|_| HostOpenSshAttachRouteErrorV1::TrustUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| HostOpenSshAttachRouteErrorV1::TrustUnavailable)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(HostOpenSshAttachRouteErrorV1::TrustUnavailable);
    }
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| HostOpenSshAttachRouteErrorV1::TrustUnavailable)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(HostOpenSshAttachRouteErrorV1::TrustUnavailable);
    }
    Ok(bytes)
}

fn decode_route_record(bytes: &[u8]) -> Result<RouteRecordV1, HostOpenSshAttachRouteErrorV1> {
    if bytes.len() > MAXIMUM_ROUTE_BYTES {
        return Err(HostOpenSshAttachRouteErrorV1::Malformed);
    }
    let record: RouteRecordV1 =
        serde_json::from_slice(bytes).map_err(|_| HostOpenSshAttachRouteErrorV1::Malformed)?;
    let canonical =
        serde_json::to_vec(&record).map_err(|_| HostOpenSshAttachRouteErrorV1::Malformed)?;
    if canonical != bytes
        || record.magic != ROUTE_MAGIC
        || record.execution_id == [0; 16]
        || record.attach_operation_id == [0; 16]
        || record.incarnation_id == [0; 16]
        || record.assignment_epoch == 0
        || record.principal_id == [0; 16]
        || record.audit_id == [0; 16]
        || record.route_generation == 0
        || record.port == 0
        || record.gate_config_digest == [0; 32]
        || !valid_host(&record.host)
        || !valid_user(&record.user)
        || !canonical_ed25519_key(&record.host_public_key)
        || !canonical_ed25519_key(&record.trusted_user_ca_public_key)
    {
        return Err(HostOpenSshAttachRouteErrorV1::Malformed);
    }
    let expected_config = expected_openssh_gate_config_v1(
        &ProtectedRouteV1 {
            record: record.clone(),
            route_digest: [0; 32],
        }
        .gate_binding(),
    )
    .map_err(|_| HostOpenSshAttachRouteErrorV1::Malformed)?;
    if <[u8; 32]>::from(Sha256::digest(expected_config)) != record.gate_config_digest {
        return Err(HostOpenSshAttachRouteErrorV1::Malformed);
    }
    Ok(record)
}

fn canonical_ed25519_key(line: &str) -> bool {
    if line.len() > MAXIMUM_KEY_BYTES {
        return false;
    }
    let Ok(key) = PublicKey::from_openssh(line) else {
        return false;
    };
    key.algorithm() == Algorithm::Ed25519
        && key.comment().is_empty()
        && key.to_openssh().is_ok_and(|value| value == line)
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAXIMUM_HOST_BYTES
        && host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
        && !host.starts_with('-')
}

fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= MAXIMUM_USER_BYTES
        && user.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || byte == b'_' || (index != 0 && byte == b'-')
        })
}

fn current_unix_seconds() -> Result<i64, HostOpenSshAttachRouteErrorV1> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostOpenSshAttachRouteErrorV1::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| HostOpenSshAttachRouteErrorV1::Clock)
}

/// Reports why an OpenSSH attach route cannot be issued from Host evidence.
#[derive(Debug, thiserror::Error)]
pub enum HostOpenSshAttachRouteErrorV1 {
    /// Fixed protected journal opening or replay failed.
    #[error("protected OpenSSH attach-route journal failed: {0}")]
    Journal(#[from] JournalError),
    /// Fixed protected runtime currentness or admission could not be read.
    #[error("protected Host execution currentness failed: {0}")]
    Runtime(#[from] DormantRuntimeExecutionOwnerErrorV1),
    /// No protected record exists for the execution.
    #[error("protected OpenSSH attach-route record is missing")]
    Missing,
    /// The protected record is invalid or noncanonical.
    #[error("protected OpenSSH attach-route record is malformed")]
    Malformed,
    /// The route identity differs from the requested execution currentness.
    #[error("protected OpenSSH attach-route is stale")]
    Stale,
    /// The route expired before it was observed.
    #[error("protected OpenSSH attach-route expired")]
    Expired,
    /// A protected terminal marker forbids this operation permanently.
    #[error("protected OpenSSH attach operation was revoked")]
    Revoked,
    /// The Host wall clock cannot be read as Unix seconds.
    #[error("Host wall clock is unavailable")]
    Clock,
    /// OS entropy could not produce a fresh gate challenge.
    #[error("Host OpenSSH gate challenge entropy is unavailable")]
    Entropy,
    /// Guest readback packet could not be authenticated.
    #[error("guest OpenSSH gate readback failed: {0}")]
    Readback(#[from] OpenSshGateReadbackErrorV1),
    /// The dedicated controller pending grant is malformed or unauthenticated.
    #[error("controller pending attach grant failed: {0}")]
    Grant(#[from] PublicAttachGrantErrorV1),
    /// The externally provisioned systemd trust credential is unavailable.
    #[error("OpenSSH attach deployment trust credential is unavailable")]
    TrustUnavailable,
    /// The protected route differs from externally provisioned trust pins.
    #[error("OpenSSH attach route differs from deployment trust pins")]
    TrustMismatch,
    /// The exact pending grant was already reserved in Host durable state.
    #[error("pending OpenSSH attach grant was already used")]
    GrantReused,
    /// Authenticated agent framing is malformed.
    #[error("guest OpenSSH gate agent frame failed: {0}")]
    Protocol(#[from] AgentProtocolError),
    /// The retained authenticated guest-agent channel failed.
    #[error("guest OpenSSH gate channel failed: {0}")]
    Transport(#[from] std::io::Error),
    /// No authenticated live `sshd` and forced-command gate readback exists.
    #[error("authenticated live OpenSSH forced-command gate readback is unavailable")]
    LiveGateUnavailable,
    /// A live gate readback disagrees with the protected route.
    #[error("live OpenSSH forced-command gate disagrees with the protected route")]
    GateMismatch,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};
    use ssh_key::{PublicKey, public::Ed25519PublicKey};

    use aos_sandbox_agent::openssh_gate::{OpenSshGatePhysicalStateV1, OpenSshGateReadbackV1};
    use aos_sandbox_agent::openssh_gate_linux::expected_openssh_gate_config_v1;

    use super::{
        DeploymentTrustV1, HostOpenSshAttachRouteErrorV1, ProtectedRouteV1, ROUTE_MAGIC,
        RouteRecordV1, TRUST_MAGIC, decode_deployment_trust, decode_route_record,
        revocation_marker, route_matches_trust, validate_revocation_marker,
        verify_readback_binding,
    };

    fn route_record() -> RouteRecordV1 {
        let host_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let ca_key = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let host_public_key = PublicKey::new(Ed25519PublicKey::from(host_key).into(), "")
            .to_openssh()
            .unwrap();
        let trusted_user_ca_public_key = PublicKey::new(Ed25519PublicKey::from(ca_key).into(), "")
            .to_openssh()
            .unwrap();

        let mut record = RouteRecordV1 {
            magic: ROUTE_MAGIC.to_owned(),
            execution_id: [1; 16],
            attach_operation_id: [2; 16],
            incarnation_id: [3; 16],
            assignment_epoch: 4,
            principal_id: [5; 16],
            audit_id: [6; 16],
            host: "sandbox.example.test".to_owned(),
            port: 2222,
            user: "aos_exec".to_owned(),
            host_public_key,
            trusted_user_ca_public_key,
            expires_at: 2_000_000_000,
            route_generation: 1,
            gate_config_digest: [10; 32],
        };
        let binding = ProtectedRouteV1 {
            record: record.clone(),
            route_digest: [0; 32],
        }
        .gate_binding();
        record.gate_config_digest =
            Sha256::digest(expected_openssh_gate_config_v1(&binding).unwrap()).into();
        record
    }

    #[test]
    fn revocation_marker_is_bound_to_exact_operation_and_execution() {
        let marker = revocation_marker([2; 16], [1; 16]);
        assert_eq!(marker.len(), 40);
        assert!(validate_revocation_marker(&marker, [2; 16], [1; 16]).is_ok());
        assert!(validate_revocation_marker(&marker, [3; 16], [1; 16]).is_err());
        assert!(validate_revocation_marker(&marker, [2; 16], [4; 16]).is_err());
    }

    #[test]
    fn protected_route_rejects_noncanonical_or_unbound_records() {
        let record = route_record();
        let canonical = serde_json::to_vec(&record).unwrap();
        assert_eq!(decode_route_record(&canonical).unwrap(), record);

        let mut padded = canonical.clone();
        padded.push(b' ');
        assert!(matches!(
            decode_route_record(&padded),
            Err(HostOpenSshAttachRouteErrorV1::Malformed)
        ));

        let mut missing_operation = record.clone();
        missing_operation.attach_operation_id = [0; 16];
        assert!(matches!(
            decode_route_record(&serde_json::to_vec(&missing_operation).unwrap()),
            Err(HostOpenSshAttachRouteErrorV1::Malformed)
        ));

        let mut untrusted_key = record;
        untrusted_key
            .trusted_user_ca_public_key
            .push_str(" comment");
        assert!(matches!(
            decode_route_record(&serde_json::to_vec(&untrusted_key).unwrap()),
            Err(HostOpenSshAttachRouteErrorV1::Malformed)
        ));
    }

    #[test]
    fn signed_gate_fields_must_match_every_protected_attach_identity() {
        let route = route_record();
        let protected = ProtectedRouteV1 {
            record: route,
            route_digest: [11; 32],
        };
        let mut readback = OpenSshGateReadbackV1 {
            challenge: [12; 32],
            route_digest: [11; 32],
            channel_binding: [13; 32],
            binding: protected.gate_binding(),
            physical: OpenSshGatePhysicalStateV1 {
                sshd_pid: 123,
                sshd_start_ticks: 456,
                sshd_executable_digest: [14; 32],
                gate_executable_digest: [15; 32],
                host_private_key_digest: [16; 32],
            },
        };
        assert!(verify_readback_binding(&protected, [12; 32], [13; 32], &readback).is_ok());

        readback.binding.trusted_user_ca_public_key.push('x');
        assert!(matches!(
            verify_readback_binding(&protected, [12; 32], [13; 32], &readback),
            Err(HostOpenSshAttachRouteErrorV1::GateMismatch)
        ));
        readback.binding = protected.gate_binding();
        readback.challenge = [17; 32];
        assert!(matches!(
            verify_readback_binding(&protected, [12; 32], [13; 32], &readback),
            Err(HostOpenSshAttachRouteErrorV1::GateMismatch)
        ));
    }

    #[test]
    fn static_trust_pins_two_distinct_operation_configurations() {
        let first = route_record();
        let trust = DeploymentTrustV1 {
            magic: TRUST_MAGIC.to_owned(),
            host: first.host.clone(),
            port: first.port,
            user: first.user.clone(),
            host_public_key: first.host_public_key.clone(),
            trusted_user_ca_public_key: first.trusted_user_ca_public_key.clone(),
        };
        let credential = serde_json::to_vec(&trust).unwrap();
        let (_, trust_digest) = decode_deployment_trust(&credential).unwrap();

        let mut second = first.clone();
        second.attach_operation_id = [25; 16];
        second.principal_id = [26; 16];
        second.audit_id = [27; 16];
        let binding = ProtectedRouteV1 {
            record: second.clone(),
            route_digest: [0; 32],
        }
        .gate_binding();
        second.gate_config_digest =
            Sha256::digest(expected_openssh_gate_config_v1(&binding).unwrap()).into();

        assert_ne!(first.gate_config_digest, second.gate_config_digest);
        assert!(route_matches_trust(&first, &trust));
        assert!(route_matches_trust(&second, &trust));
        assert_eq!(
            decode_deployment_trust(&credential).unwrap().1,
            trust_digest
        );
        assert!(decode_route_record(&serde_json::to_vec(&second).unwrap()).is_ok());
    }
}
