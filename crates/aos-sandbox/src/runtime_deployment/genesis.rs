//! Genuine fixed-role admission of the externally signed deployment genesis.
//!
//! The sole wire codec is Protocol's `DeploymentGenesisV1`; this module retains
//! its actual fixed credentials and startup owner. The signed genesis binds a
//! pre-genesis anchor, never its own future complete-map head or NV value. The
//! independent provisioner seeds those afterward. Startup creates no journal,
//! index, checkpoint, deployment identity, or runtime authority.
//!
//! ```text
//! runtime-deployment-genesis-v1 = canonical AOSRDG01:404 || signature:64
//! runtime-deployment-provisioner-pin-v1 = independent Ed25519 public key:32
//! runtime-deployment-signing-seed-v1 = separate private publisher seed:32
//! ```

use std::path::Path;

use aos_sandbox_protocol::runtime_deployment::{
    DEPLOYMENT_GENESIS_BYTES_V1, DeploymentGenesisV1,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::journal::RecordNamespace;
use crate::tpm_nv_custody::credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};
use crate::tpm_nv_custody::{NvCustodyEndpointV1, NvCustodyErrorV1, canonical_nv_name_v1};

use super::{
    HELPER_CONTEXT, OWNER_CONTEXT, ProductionRuntimeDeploymentStartupV1, SOCKET_PATH,
    SOCKET_UNIT, UNIT,
};

pub(super) const SIGNED_GENESIS_BYTES: usize = DEPLOYMENT_GENESIS_BYTES_V1 + 64;
pub(crate) const GENESIS_KEY: &[u8] = b"deployment-genesis-v1";
pub(crate) const NAMESPACE: RecordNamespace = RecordNamespace::HostCatalogReconciliation;
pub(crate) const DIRECTORY: &str = "/var/lib/aos/sandbox/runtime-deployment";
pub(crate) const MAIN_NAME: &str = "preparation.journal";
pub(super) const SIDECAR_NAME: &str = "tpm-floor.journal";

const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-runtime-publisher.service";
const GENESIS_ROLE: &str = "runtime-deployment-genesis-v1";
const PROVISIONER_ROLE: &str = "runtime-deployment-provisioner-pin-v1";
const SIGNER_ROLE: &str = "runtime-deployment-signing-seed-v1";
const AUTH_ROLE: &str = "runtime-deployment-tpm-index-auth-v1";
const MODE_PATH: &str = "/etc/aos/runtime-deployment-tpm-floor/mode";

/// Retains real startup and independent fixed credentials, never a caller DTO.
///
/// This prerequisite is not a current floor or live process-readiness witness.
/// The common physical owner still authenticates the complete main and sidecar
/// against fresh NV; a signed historical phase cannot reconstruct a pidfd.
pub(crate) struct VerifiedDeploymentGenesisV1<'startup> {
    startup: &'startup ProductionRuntimeDeploymentStartupV1,
    exact: Vec<u8>,
    provisioner: VerifyingKey,
    signer: SigningKey,
    genesis: DeploymentGenesisV1,
}

impl<'startup> VerifiedDeploymentGenesisV1<'startup> {
    /// Admits the exact external genesis under original live startup custody.
    ///
    /// # Errors
    ///
    /// Rejects unavailable or substituted credentials, signatures, key roles,
    /// fixed-purpose bindings or actual startup/profile/policy observations.
    pub(crate) fn open(
        startup: &'startup ProductionRuntimeDeploymentStartupV1,
    ) -> Result<Self, NvCustodyErrorV1> {
        startup.recheck().map_err(|_| NvCustodyErrorV1::Provisioning)?;

        let exact = read_role(GENESIS_ROLE, SIGNED_GENESIS_BYTES, false)?;
        let provisioner = read_provisioner()?;
        let signer = read_signer()?;
        let genesis = decode_signed(&exact, &provisioner)?;
        require_bindings(
            &genesis, startup.profile_digest(), startup.canonical_policy_digest(),
        )?;
        if genesis.signer != signer.verifying_key().to_bytes()
            || genesis.signer == provisioner.to_bytes()
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }

        let owner = Self {
            startup,
            exact,
            provisioner,
            signer,
            genesis,
        };
        owner.recheck()?;
        Ok(owner)
    }

    /// Rechecks the same actual startup, independent pin, genesis and signer role.
    ///
    /// # Errors
    ///
    /// Rejects any startup drift or missing/substituted fixed credential.
    pub(crate) fn recheck(&self) -> Result<(), NvCustodyErrorV1> {
        self.startup.recheck().map_err(|_| NvCustodyErrorV1::Provisioning)?;
        if read_role(GENESIS_ROLE, SIGNED_GENESIS_BYTES, false)? != self.exact
            || read_provisioner()?.to_bytes() != self.provisioner.to_bytes()
            || read_signer()?.verifying_key() != self.signer.verifying_key()
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        let observed = decode_signed(&self.exact, &self.provisioner)?;
        require_bindings(
            &observed,
            self.startup.profile_digest(),
            self.startup.canonical_policy_digest(),
        )?;
        if observed != self.genesis {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        self.startup.recheck().map_err(|_| NvCustodyErrorV1::Provisioning)
    }

    pub(crate) fn startup(&self) -> &ProductionRuntimeDeploymentStartupV1 {
        self.startup
    }

    pub(crate) fn claims(&self) -> &DeploymentGenesisV1 {
        &self.genesis
    }

    pub(crate) fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }

    pub(crate) fn publisher_verifier(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    /// Returns the canonical wire genesis commitment, never currentness.
    ///
    /// # Errors
    ///
    /// Rejects invalid canonical genesis fields.
    pub(crate) fn genesis_digest(&self) -> Result<[u8; 32], NvCustodyErrorV1> {
        self.genesis.digest().map_err(|_| NvCustodyErrorV1::Encoding)
    }

    pub(crate) fn exact_genesis_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.exact).into()
    }

    pub(crate) fn scope(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"aos.sandbox.tpm-floor.closed-purpose.scope.v1\0")
            .chain_update(&self.exact)
            .finalize()
            .into()
    }
}

/// Derives the external provisioner's initial native UUID from signed bytes.
///
/// This nonauthorizing DATA derivation runs after signing; its UUID is not a
/// field of the genesis and therefore cannot recurse through the initialized
/// complete-map head. The initial native transaction must use this identity
/// before the independent provisioner computes its checkpoint and NV seed.
///
/// # Errors
///
/// Rejects a noncanonical signed-genesis length. Signature authentication still
/// belongs to the genuine fixed-credential owner, not this derivation.
pub(crate) fn genesis_native_transaction_v1(
    exact_signed_genesis: &[u8],
) -> Result<[u8; 16], NvCustodyErrorV1> {
    if exact_signed_genesis.len() != SIGNED_GENESIS_BYTES {
        return Err(NvCustodyErrorV1::Encoding);
    }

    let digest = Sha256::new()
        .chain_update(b"aos.runtime-deployment.genesis-native-transaction.v1\0")
        .chain_update(exact_signed_genesis)
        .finalize();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    identity[6] = (identity[6] & 0x0f) | 0x80;
    identity[8] = (identity[8] & 0x3f) | 0x80;
    Ok(identity)
}

fn read_role(name: &str, length: usize, private: bool) -> Result<Vec<u8>, NvCustodyErrorV1> {
    read_optional_bounded_role_credential_v1(
        Path::new(CREDENTIAL_DIRECTORY),
        name,
        length,
        length,
        private,
        CredentialOwnerPolicyV1::RootOrCurrent,
    )
    .map_err(|_| NvCustodyErrorV1::Provisioning)?
    .ok_or(NvCustodyErrorV1::Provisioning)
}

fn read_provisioner() -> Result<VerifyingKey, NvCustodyErrorV1> {
    let bytes: [u8; 32] = read_role(PROVISIONER_ROLE, 32, false)?
        .try_into()
        .map_err(|_| NvCustodyErrorV1::Encoding)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| NvCustodyErrorV1::Provisioning)?;
    if key.is_weak() {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    Ok(key)
}

fn read_signer() -> Result<SigningKey, NvCustodyErrorV1> {
    let bytes = Zeroizing::new(read_role(SIGNER_ROLE, 32, true)?);
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&bytes);
    if *seed == [0; 32] {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    Ok(SigningKey::from_bytes(&seed))
}

fn decode_signed(
    bytes: &[u8],
    provisioner: &VerifyingKey,
) -> Result<DeploymentGenesisV1, NvCustodyErrorV1> {
    if bytes.len() != SIGNED_GENESIS_BYTES || provisioner.is_weak() {
        return Err(NvCustodyErrorV1::Encoding);
    }
    let genesis = DeploymentGenesisV1::decode(&bytes[..DEPLOYMENT_GENESIS_BYTES_V1])
        .map_err(|_| NvCustodyErrorV1::Encoding)?;
    let signature = bytes[DEPLOYMENT_GENESIS_BYTES_V1..]
        .try_into()
        .map_err(|_| NvCustodyErrorV1::Encoding)?;
    genesis.verify_signature(provisioner, signature)
        .map_err(|_| NvCustodyErrorV1::Provisioning)?;
    Ok(genesis)
}

fn require_bindings(
    genesis: &DeploymentGenesisV1,
    profile: [u8; 32],
    policy: [u8; 32],
) -> Result<(), NvCustodyErrorV1> {
    if genesis.nv_name != canonical_nv_name_v1(NvCustodyEndpointV1::RuntimeDeployment)
        || genesis.empty_ledger_anchor != empty_ledger_anchor()
        || genesis.publisher_profile != profile
        || genesis.mac_policy != policy
        || genesis.credential_contract != credential_contract()
        || genesis.uid_start < 65_536
        || genesis.uid_count < 65_536
        || genesis.uid_start.checked_add(genesis.uid_count).is_none()
    {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    Ok(())
}

/// Binds only the operation-free pre-genesis namespace and its empty sequence.
pub(super) fn empty_ledger_anchor() -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.runtime-deployment.empty-ledger.v1\0")
        .chain_update(credential_contract())
        .chain_update([NAMESPACE as u8])
        .chain_update(1_u64.to_be_bytes())
        .finalize()
        .into()
}

/// Commits the exact fixed purpose, paths, contexts, original roles and credentials.
pub(super) fn credential_contract() -> [u8; 32] {
    let mut hash = Sha256::new().chain_update(b"aos.runtime-deployment.credential-contract.v1\0");
    for value in [
        UNIT, SOCKET_UNIT, SOCKET_PATH,
        OWNER_CONTEXT, HELPER_CONTEXT,
        DIRECTORY, MAIN_NAME, SIDECAR_NAME,
        CREDENTIAL_DIRECTORY, GENESIS_ROLE, PROVISIONER_ROLE, SIGNER_ROLE,
        AUTH_ROLE, MODE_PATH,
        super::LISTENER_FD_NAME, super::PID1_FD_NAME, super::PROFILE_FD_NAME,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update([NAMESPACE as u8]);
    hash.update(0x0180_a055_u32.to_be_bytes());
    hash.update(0x8100_a055_u32.to_be_bytes());
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;
    use super::*;

    fn fixture() -> (DeploymentGenesisV1, SigningKey) {
        let provisioner = SigningKey::from_bytes(&[1; 32]);
        let mut salt = [3; 34];
        salt[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
        let genesis = DeploymentGenesisV1 {
            node: [4; 16], deployment: [5; 16],
            signer: SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes(),
            nv_name: canonical_nv_name_v1(NvCustodyEndpointV1::RuntimeDeployment),
            salt_name: salt, empty_ledger_anchor: empty_ledger_anchor(),
            publisher_profile: [7; 32], nspawn_digest: [8; 32], root_digest: [9; 32],
            supervisor_filter: [10; 32], payload_filter: [11; 32], mac_policy: [12; 32],
            credential_contract: credential_contract(), uid_start: 65_536, uid_count: 65_536,
        };
        (genesis, provisioner)
    }

    #[test]
    fn unrun_external_signature_and_complete_fixed_contract_are_required() {
        let (genesis, provisioner) = fixture();
        let mut bytes = genesis.encode().unwrap().to_vec();
        let message = [b"aos.runtime-deployment.genesis.v1\0".as_slice(), &bytes].concat();
        bytes.extend_from_slice(&provisioner.sign(&message).to_bytes());

        assert_eq!(decode_signed(&bytes, &provisioner.verifying_key()).unwrap(), genesis);
        assert!(require_bindings(&genesis, [7; 32], [12; 32]).is_ok());
        assert!(decode_signed(&bytes, &SigningKey::from_bytes(&[2; 32]).verifying_key()).is_err());
        bytes[236] ^= 1;
        assert!(decode_signed(&bytes, &provisioner.verifying_key()).is_err());
    }

    #[test]
    fn unrun_anchor_is_not_a_future_head_and_foreign_purpose_refuses() {
        let (genesis, _) = fixture();
        for changed in [
            DeploymentGenesisV1 { nv_name: canonical_nv_name_v1(NvCustodyEndpointV1::RootCreateFailure), ..genesis.clone() },
            DeploymentGenesisV1 { empty_ledger_anchor: [13; 32], ..genesis.clone() },
            DeploymentGenesisV1 { publisher_profile: [14; 32], ..genesis.clone() },
            DeploymentGenesisV1 { credential_contract: [15; 32], ..genesis.clone() },
            DeploymentGenesisV1 { uid_start: 1, ..genesis },
        ] {
            assert!(require_bindings(&changed, [7; 32], [12; 32]).is_err());
        }
    }
}
