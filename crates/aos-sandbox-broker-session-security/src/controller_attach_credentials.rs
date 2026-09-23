//! Dedicated controller credentials for signed public OpenSSH attachment.
//!
//! The grant seed and user CA key are loaded only from fixed systemd names.
//! The compact Host trust credential is checked byte for byte before its
//! digest enters a grant; no public request supplies route or signing data.
//!
//! ```text
//! openssh-attach-grant-signing-key = 32 raw Ed25519 seed bytes
//! openssh-attach-grant-public-key = 32 raw Ed25519 public key bytes
//! openssh-attach-ca-signing-key = unencrypted Ed25519 OpenSSH private key
//! openssh-attach-trust.json = canonical AOSHAT01 deployment trust JSON
//! ```

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox::attach_route_issuer::OpenSshAttachRouteIssuerV1;
use aos_sandbox::public_attach_pending::PublicAttachPendingV1;
use aos_sandbox_agent::openssh_gate::OpenSshGateBindingV1;
use aos_sandbox_agent::openssh_gate_linux::expected_openssh_gate_config_v1;
use ed25519_dalek::SigningKey;
use rustix::fs::{CWD, Mode, OFlags, openat};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const GRANT_SIGNING_KEY: &str = "openssh-attach-grant-signing-key";
const GRANT_PUBLIC_KEY: &str = "openssh-attach-grant-public-key";
const CA_SIGNING_KEY: &str = "openssh-attach-ca-signing-key";
const TRUST: &str = "openssh-attach-trust.json";
const TRUST_MAGIC: &str = "AOSHAT01";
const MAXIMUM_CA_BYTES: usize = 8 * 1024;
const MAXIMUM_TRUST_BYTES: usize = 2048;

/// Owns the independent signing inputs for one controller worker.
pub(crate) struct ControllerAttachCredentialsV1 {
    grant_seed: Zeroizing<[u8; 32]>,
    issuer: OpenSshAttachRouteIssuerV1,
    trust_digest: [u8; 32],
    trust: DeploymentTrustV1,
}

/// Reports incomplete or unsafe dedicated attach credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ControllerAttachCredentialErrorV1 {
    /// One of the required protected credentials is missing or invalid.
    #[error("controller OpenSSH attach credentials are unavailable or invalid")]
    Invalid,
}

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

impl ControllerAttachCredentialsV1 {
    /// Loads the complete optional credential set from systemd custody.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe directory or any incomplete, malformed, or mismatched
    /// set. An entirely absent set leaves public ATTACH unavailable.
    pub(crate) fn from_process_credentials_optional()
    -> Result<Option<Self>, ControllerAttachCredentialErrorV1> {
        let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
            return Ok(None);
        };
        let directory = Path::new(&directory);
        if !directory.is_absolute() {
            return Err(ControllerAttachCredentialErrorV1::Invalid);
        }
        let Some(grant_seed) = read_credential(directory, GRANT_SIGNING_KEY, 32)? else {
            if read_credential(directory, GRANT_PUBLIC_KEY, 32)?.is_some()
                || read_credential(directory, CA_SIGNING_KEY, MAXIMUM_CA_BYTES)?.is_some()
                || read_credential(directory, TRUST, MAXIMUM_TRUST_BYTES)?.is_some()
            {
                return Err(ControllerAttachCredentialErrorV1::Invalid);
            }
            return Ok(None);
        };
        let grant_seed: [u8; 32] = grant_seed
            .as_slice()
            .try_into()
            .map_err(|_| ControllerAttachCredentialErrorV1::Invalid)?;
        let grant_seed = Zeroizing::new(grant_seed);
        let expected_public: [u8; 32] = read_required(directory, GRANT_PUBLIC_KEY, 32)?
            .as_slice()
            .try_into()
            .map_err(|_| ControllerAttachCredentialErrorV1::Invalid)?;
        if SigningKey::from_bytes(&grant_seed)
            .verifying_key()
            .to_bytes()
            != expected_public
        {
            return Err(ControllerAttachCredentialErrorV1::Invalid);
        }

        let ca_key = Zeroizing::new(read_required(directory, CA_SIGNING_KEY, MAXIMUM_CA_BYTES)?);
        let issuer = OpenSshAttachRouteIssuerV1::new(&ca_key)
            .map_err(|_| ControllerAttachCredentialErrorV1::Invalid)?;
        let trust_bytes = read_required(directory, TRUST, MAXIMUM_TRUST_BYTES)?;
        let trust: DeploymentTrustV1 = serde_json::from_slice(&trust_bytes)
            .map_err(|_| ControllerAttachCredentialErrorV1::Invalid)?;
        if trust.magic != TRUST_MAGIC
            || trust.host.is_empty()
            || serde_json::to_vec(&trust).map_err(|_| ControllerAttachCredentialErrorV1::Invalid)?
                != trust_bytes
        {
            return Err(ControllerAttachCredentialErrorV1::Invalid);
        }
        let trust_digest = Sha256::digest(&trust_bytes).into();

        Ok(Some(Self {
            grant_seed,
            issuer,
            trust_digest,
            trust,
        }))
    }

    /// Returns a short-lived signer value for one protected grant operation.
    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.grant_seed)
    }

    /// Returns the protected CA issuer used only after Host gate readback.
    pub(crate) const fn issuer(&self) -> &OpenSshAttachRouteIssuerV1 {
        &self.issuer
    }

    /// Returns the exact deployed Host trust credential commitment.
    pub(crate) const fn trust_digest(&self) -> [u8; 32] {
        self.trust_digest
    }

    /// Derives the expected gate configuration for this protected operation.
    ///
    /// # Errors
    ///
    /// Rejects a malformed pending binding or static deployment trust value.
    pub(crate) fn gate_config_digest(
        &self,
        pending: &PublicAttachPendingV1,
    ) -> Result<[u8; 32], ControllerAttachCredentialErrorV1> {
        let binding = OpenSshGateBindingV1 {
            attach_operation_id: *pending.operation_id().as_bytes(),
            execution_id: pending.execution_id(),
            incarnation_id: pending.sandbox_incarnation_id(),
            assignment_epoch: pending.assignment_epoch(),
            principal_id: pending.principal_id(),
            audit_id: pending.audit_id(),
            user: self.trust.user.clone(),
            port: self.trust.port,
            host_public_key: self.trust.host_public_key.clone(),
            trusted_user_ca_public_key: self.trust.trusted_user_ca_public_key.clone(),
            expires_at: pending.expires_at(),
            // The generator validates this field but does not include it in
            // the config, so a nonzero sentinel breaks the digest cycle.
            gate_config_digest: [1; 32],
        };
        let configuration = expected_openssh_gate_config_v1(&binding)
            .map_err(|_| ControllerAttachCredentialErrorV1::Invalid)?;
        Ok(Sha256::digest(configuration).into())
    }
}

fn read_required(
    directory: &Path,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, ControllerAttachCredentialErrorV1> {
    read_credential(directory, name, maximum)?.ok_or(ControllerAttachCredentialErrorV1::Invalid)
}

fn read_credential(
    directory: &Path,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, ControllerAttachCredentialErrorV1> {
    let path = directory.join(name);
    let descriptor = match openat(
        CWD,
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(ControllerAttachCredentialErrorV1::Invalid),
    };
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| ControllerAttachCredentialErrorV1::Invalid)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum as u64
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(ControllerAttachCredentialErrorV1::Invalid);
    }
    let mut bytes = Vec::with_capacity(maximum.min(metadata.len() as usize));
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ControllerAttachCredentialErrorV1::Invalid)?;
    if bytes.len() != metadata.len() as usize {
        return Err(ControllerAttachCredentialErrorV1::Invalid);
    }
    Ok(Some(bytes))
}
