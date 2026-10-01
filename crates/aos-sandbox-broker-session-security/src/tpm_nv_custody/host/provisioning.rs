//! Fixed Host mode and auth adapter over the existing shared admission engines.
//!
//! Core's genuine Origins alone authenticates the signed genesis, canonical NV
//! Name, independent provisioner and exact credential contract. This adapter
//! retains its admitted bytes and Names; it neither parses another genesis nor
//! hashes a second public-area Name. Auth is reread from the already contracted
//! systemd role and only its private zeroizing commitment is retained.
//!
//! ```text
//! fixed mode: /etc/aos/runtime-deployment-tpm-floor/mode
//! fixed private role: runtime-deployment-tpm-index-auth-v1 (32 nonzero bytes)
//! signed genesis: admitted AOSRDG01:404 || signature:64
//! ```

use std::path::Path;

use aos_sandbox::RuntimeDeploymentComparisonOriginsV1;
use aos_sandbox_protocol::runtime_deployment::{
    DEPLOYMENT_GENESIS_BYTES_V1, DEPLOYMENT_NV_INDEX_V1, DEPLOYMENT_SALT_HANDLE_V1,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::fixed_role_credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};
use crate::recovery::ModePinV1;
use crate::tpm_nv_custody::{NvCustodyEndpointV1, framing::salt_handle_v1};

use super::HostTpmAdmissionErrorV1;

// These names are already committed by the genuine signed credential contract.
const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-runtime-publisher.service";
const AUTH_ROLE: &str = "runtime-deployment-tpm-index-auth-v1";
const SIGNED_GENESIS_BYTES: usize = DEPLOYMENT_GENESIS_BYTES_V1 + 64;

/// Retains the genuine signed Host purpose and private credential commitment.
pub(super) struct HostProvisioningPinV1<'origin, 'startup> {
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    mode: ModePinV1,
    auth_digest: Zeroizing<[u8; 32]>,
    signed_genesis: [u8; SIGNED_GENESIS_BYTES],
    nv_name: [u8; 34],
    salt_name: [u8; 34],
}

impl<'origin, 'startup> HostProvisioningPinV1<'origin, 'startup> {
    /// Retains only the fixed roles of already-rechecked genuine Origins.
    ///
    /// # Errors
    /// Rejects mode, credential or admitted signed-purpose disagreement.
    pub(super) fn open(
        origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    ) -> Result<Self, HostTpmAdmissionErrorV1> {
        let mode = ModePinV1::open_runtime_deployment()
            .map_err(HostTpmAdmissionErrorV1::Mode)?;
        require_required_mode(mode.is_required())?;
        let auth = read_auth()?;

        // Origins was rechecked by the only admission entry. Its unchanged
        // owner validates signature, canonical NV 055 and the fixed contract;
        // no caller-built Names or genesis bytes can reach this construction.
        require_fixed_host_purpose()?;
        let signed_genesis = origins
            .signed_genesis()
            .try_into()
            .map_err(|_| HostTpmAdmissionErrorV1::ChangedPurpose)?;
        let claims = origins.genesis_claims();
        Ok(Self {
            origins,
            mode,
            auth_digest: Zeroizing::new(Sha256::digest(&auth[..]).into()),
            signed_genesis,
            nv_name: claims.nv_name,
            salt_name: claims.salt_name,
        })
    }

    /// Rereads private auth against the retained, nonexported commitment.
    ///
    /// # Errors
    /// Rejects a missing, unsafe, malformed or changed fixed credential.
    pub(super) fn current_auth(
        &self,
    ) -> Result<Zeroizing<[u8; 32]>, HostTpmAdmissionErrorV1> {
        let auth = read_auth()?;
        require_same_auth(&auth, &self.auth_digest)?;
        Ok(auth)
    }

    /// Rechecks the original immutable mode without accepting legacy closure.
    ///
    /// # Errors
    /// Rejects path, inode, content or decoded-mode drift.
    pub(super) fn recheck_mode(&self) -> Result<(), HostTpmAdmissionErrorV1> {
        self.mode.revalidate().map_err(HostTpmAdmissionErrorV1::Mode)?;
        require_required_mode(self.mode.is_required())
    }

    /// Rechecks genuine Origins and their exact retained signed purpose inputs.
    ///
    /// # Errors
    /// Retains comparison failures and rejects different signed bytes or Names.
    pub(super) fn recheck_origins(&self) -> Result<(), HostTpmAdmissionErrorV1> {
        self.origins.recheck().map_err(HostTpmAdmissionErrorV1::Origins)?;
        require_fixed_host_purpose()?;

        let claims = self.origins.genesis_claims();
        if self.origins.signed_genesis() != self.signed_genesis.as_slice()
            || claims.nv_name != self.nv_name
            || claims.salt_name != self.salt_name
        {
            return Err(HostTpmAdmissionErrorV1::ChangedPurpose);
        }
        Ok(())
    }
}

/// Checks closed compiled-purpose identity; Names remain owned by genuine Core.
fn require_fixed_host_purpose() -> Result<(), HostTpmAdmissionErrorV1> {
    let endpoint = NvCustodyEndpointV1::RuntimeDeployment;
    if endpoint.nv_index() != DEPLOYMENT_NV_INDEX_V1
        || salt_handle_v1(endpoint) != DEPLOYMENT_SALT_HANDLE_V1
    {
        return Err(HostTpmAdmissionErrorV1::ChangedPurpose);
    }
    Ok(())
}

fn require_required_mode(required: bool) -> Result<(), HostTpmAdmissionErrorV1> {
    if !required {
        return Err(HostTpmAdmissionErrorV1::LegacyClosed);
    }
    Ok(())
}

fn read_auth() -> Result<Zeroizing<[u8; 32]>, HostTpmAdmissionErrorV1> {
    let bytes = read_optional_bounded_role_credential_v1(
        Path::new(CREDENTIAL_DIRECTORY),
        AUTH_ROLE,
        32,
        32,
        true,
        CredentialOwnerPolicyV1::RootOrCurrent,
    )
    .map_err(HostTpmAdmissionErrorV1::Credential)?
    .ok_or(HostTpmAdmissionErrorV1::MissingAuth)?;
    decode_auth(Zeroizing::new(bytes))
}

/// Keeps every success and refusal buffer zeroizing, including pure vectors.
fn decode_auth(
    bytes: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<[u8; 32]>, HostTpmAdmissionErrorV1> {
    if bytes.len() != 32 {
        return Err(HostTpmAdmissionErrorV1::InvalidAuth);
    }
    let mut auth = Zeroizing::new([0; 32]);
    auth.copy_from_slice(&bytes);
    if *auth == [0; 32] {
        return Err(HostTpmAdmissionErrorV1::InvalidAuth);
    }
    Ok(auth)
}

fn require_same_auth(
    auth: &[u8; 32],
    expected: &[u8; 32],
) -> Result<(), HostTpmAdmissionErrorV1> {
    let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(auth)));
    if *digest != *expected {
        return Err(HostTpmAdmissionErrorV1::ChangedAuth);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrun_auth_is_exact_nonzero_and_keeps_a_zeroizing_result() {
        let auth: Zeroizing<[u8; 32]> = decode_auth(Zeroizing::new(vec![7; 32])).unwrap();

        assert_eq!(*auth, [7; 32]);
        for bytes in [vec![], vec![7; 31], vec![7; 33], vec![0; 32]] {
            assert!(matches!(
                decode_auth(Zeroizing::new(bytes)),
                Err(HostTpmAdmissionErrorV1::InvalidAuth),
            ));
        }
    }

    #[test]
    fn unrun_auth_commitment_refuses_substitution_without_secret_diagnostics() {
        let digest = Zeroizing::new(<[u8; 32]>::from(Sha256::digest([7; 32])));

        require_same_auth(&[7; 32], &digest).unwrap();
        let error = require_same_auth(&[8; 32], &digest).unwrap_err();

        assert!(matches!(&error, HostTpmAdmissionErrorV1::ChangedAuth));
        assert_eq!(error.to_string(), "Host TPM auth credential changed");
    }

    #[test]
    fn unrun_explicit_legacy_mode_never_admits_host_inputs() {
        require_required_mode(true).unwrap();

        assert!(matches!(
            require_required_mode(false),
            Err(HostTpmAdmissionErrorV1::LegacyClosed),
        ));
    }

    #[test]
    fn unrun_compiled_purpose_and_role_names_remain_the_fixed_host_contract() {
        require_fixed_host_purpose().unwrap();

        assert_eq!(DEPLOYMENT_NV_INDEX_V1, 0x0180_a055);
        assert_eq!(DEPLOYMENT_SALT_HANDLE_V1, 0x8100_a055);
        assert_eq!(SIGNED_GENESIS_BYTES, 468);
        assert_eq!(AUTH_ROLE, "runtime-deployment-tpm-index-auth-v1");
        assert_eq!(
            CREDENTIAL_DIRECTORY,
            "/run/credentials/aos-sandbox-runtime-publisher.service",
        );
    }
}
