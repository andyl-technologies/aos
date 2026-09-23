//! Fixed protected Host ownership of OpenSSH attach-route records.
//!
//! One record per execution lives in the root-owned Host execution journal.
//! The record pins the endpoint, host key, trusted user CA, incarnation,
//! assignment, and expiry. A record alone does not establish that the guest
//! `sshd` and forced-command gate are running with those values. The live gate
//! reader therefore stays unavailable until an authenticated AOSAGE gate
//! observation is implemented and matched against the protected record.
//!
//! ```text
//! /var/lib/aos/sandbox-host/openssh-attach-route.journal
//! HostExecution key = "openssh-attach-route-v1/" || execution_id[16]
//! value = canonical JSON RouteRecordV1 with deny_unknown_fields
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionOwnerErrorV1, DormantRuntimeExecutionOwnerV1,
};
use aos_sandbox::{Journal, JournalError, JournalLimits, RecordNamespace};
use aos_sandbox_core::ExecutionId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use ssh_key::{Algorithm, PublicKey};

const HOST_STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const ROUTE_JOURNAL_NAME: &str = "openssh-attach-route.journal";
const ROUTE_KEY_PREFIX: &[u8] = b"openssh-attach-route-v1/";
const ROUTE_MAGIC: &str = "AOSHAR01";
const ROUTE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.host.openssh-attach-route.v1\0";
const MAXIMUM_ROUTE_BYTES: usize = 2048;
const MAXIMUM_HOST_BYTES: usize = 255;
const MAXIMUM_USER_BYTES: usize = 32;
const MAXIMUM_KEY_BYTES: usize = 128;

/// Owns the fixed root-protected OpenSSH route journal.
pub struct HostOpenSshAttachRouteOwnerV1 {
    journal: Journal,
}

impl HostOpenSshAttachRouteOwnerV1 {
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
        let protected = self.read_protected(execution_id, incarnation_id, assignment_epoch)?;
        let live = self.read_live_forced_command_gate(&protected)?;
        if live.binding != protected.gate_binding() || live.signed_observation_commitment == [0; 32]
        {
            return Err(HostOpenSshAttachRouteErrorV1::GateMismatch);
        }
        validate_current_execution(&protected.record)?;
        if protected.record.expires_at <= current_unix_seconds()? {
            return Err(HostOpenSshAttachRouteErrorV1::Expired);
        }

        Ok(HostOpenSshAttachRouteEvidenceV1 {
            execution_id: protected.record.execution_id,
            attach_operation_id: protected.record.attach_operation_id,
            incarnation_id: protected.record.incarnation_id,
            assignment_epoch: protected.record.assignment_epoch,
            principal_id: protected.record.principal_id,
            audit_id: protected.record.audit_id,
            host: protected.record.host,
            port: protected.record.port,
            user: protected.record.user,
            host_public_key: protected.record.host_public_key,
            trusted_user_ca_public_key: protected.record.trusted_user_ca_public_key,
            expires_at: protected.record.expires_at,
            route_generation: protected.record.route_generation,
            route_digest: protected.route_digest,
            gate_observation_commitment: live.signed_observation_commitment,
            forced_command_gate_active: true,
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
        if route.execution_id != execution_id
            || route.incarnation_id != incarnation_id
            || route.assignment_epoch != assignment_epoch
        {
            return Err(HostOpenSshAttachRouteErrorV1::Stale);
        }
        validate_current_execution(&route)?;
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

    fn read_live_forced_command_gate(
        &self,
        _route: &ProtectedRouteV1,
    ) -> Result<LiveGateReadbackV1, HostOpenSshAttachRouteErrorV1> {
        // The current AOSAGE protocol signs execution outcomes, but has no
        // signed observation of the guest's live sshd and gate configuration.
        // Do not promote a protected route to an attach capability before that
        // independently measured observation exists.
        Err(HostOpenSshAttachRouteErrorV1::LiveGateUnavailable)
    }
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
    /// True only when the physical gate readback matched this route.
    pub(crate) forced_command_gate_active: bool,
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

struct ProtectedRouteV1 {
    record: RouteRecordV1,
    route_digest: [u8; 32],
}

#[derive(Eq, PartialEq)]
struct GateBindingV1 {
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
    gate_config_digest: [u8; 32],
}

struct LiveGateReadbackV1 {
    binding: GateBindingV1,
    signed_observation_commitment: [u8; 32],
}

impl ProtectedRouteV1 {
    fn gate_binding(&self) -> GateBindingV1 {
        GateBindingV1 {
            execution_id: self.record.execution_id,
            attach_operation_id: self.record.attach_operation_id,
            incarnation_id: self.record.incarnation_id,
            assignment_epoch: self.record.assignment_epoch,
            principal_id: self.record.principal_id,
            audit_id: self.record.audit_id,
            host: self.record.host.clone(),
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
    Ok(record)
}

fn canonical_ed25519_key(line: &str) -> bool {
    if line.len() > MAXIMUM_KEY_BYTES {
        return false;
    }
    let Ok(key) = PublicKey::from_openssh(line) else {
        return false;
    };
    key.algorithm() == Algorithm::Ed25519 && key.to_openssh().is_ok_and(|value| value == line)
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
    /// The Host wall clock cannot be read as Unix seconds.
    #[error("Host wall clock is unavailable")]
    Clock,
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
    use ssh_key::{PublicKey, public::Ed25519PublicKey};

    use super::{HostOpenSshAttachRouteErrorV1, ROUTE_MAGIC, RouteRecordV1, decode_route_record};

    fn route_record() -> RouteRecordV1 {
        let host_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let ca_key = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let host_public_key = PublicKey::new(Ed25519PublicKey::from(host_key).into(), "")
            .to_openssh()
            .unwrap();
        let trusted_user_ca_public_key = PublicKey::new(Ed25519PublicKey::from(ca_key).into(), "")
            .to_openssh()
            .unwrap();

        RouteRecordV1 {
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
        }
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
}
