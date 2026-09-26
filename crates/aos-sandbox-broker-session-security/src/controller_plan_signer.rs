//! Protected controller signing for prepared broker authorization plans.
//!
//! The key is loaded only from a fixed systemd credential name. This owner
//! signs the exact domain-separated statement prepared by the controller core;
//! completion independently verifies the result against its pinned policy.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox::{BrokerPlanPreparation, ReturnedSignature, SignedBrokerPlan, SigningAuthority};
use aos_sandbox_core::format::{decode_broker_authorization_plan, decode_trust_policy};
use aos_sandbox_core::model::{KeyUsage, SignaturePurpose};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerPlanTrustAnchor, DecodeLimits, MediaType,
    ObjectDigest, PortableMediaType, ProtocolId, RevocationScopeId, descriptor_for_bytes,
    sign_statement,
};
use ed25519_dalek::SigningKey;
use rustix::fs::{CWD, Mode, OFlags, openat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::fixed_role_credential::read_optional_fixed_role_credential_v1;

const CREDENTIAL_NAME: &str = "broker-plan-signing-key";
const POLICY_CREDENTIAL_NAME: &str = "broker-plan-policy.cbor";
const PUBLIC_KEY_CREDENTIAL_NAME: &str = "broker-plan-public-key";
const REVOCATION_SCOPE_CREDENTIAL_NAME: &str = "broker-revocation-scope";
const MOUNT_POLICY_CREDENTIAL_NAME: &str = "mount-broker-plan-policy.cbor";
const MOUNT_PUBLIC_KEY_CREDENTIAL_NAME: &str = "mount-broker-plan-public-key";
const MOUNT_REVOCATION_SCOPE_CREDENTIAL_NAME: &str = "mount-broker-revocation-scope";
const SEED_BYTES: usize = 32;
const MAXIMUM_POLICY_BYTES: usize = 64 * 1024;

pub(crate) struct ControllerBrokerPlanSignerV1 {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    authority: SigningAuthority,
    mount_authority: SigningAuthority,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ControllerBrokerPlanSignerError {
    #[error("controller broker-plan credential is invalid or unreadable")]
    Credential,
    #[error("controller broker-plan signature does not match the prepared statement")]
    Signature,
    #[error("controller broker-plan signature failed policy verification")]
    Completion,
}

impl ControllerBrokerPlanSignerV1 {
    /// Returns the broker-plan public key for separate-purpose key isolation.
    pub(crate) fn verifying_key_bytes(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }

    /// Loads the independent public plan-verification anchor for attachment effects.
    ///
    /// The revocation scope is a separate protected Host authority credential,
    /// not a value copied from the plan or request being verified.
    ///
    /// # Errors
    ///
    /// Rejects missing, unsafe, or inconsistent policy, key, or scope bytes.
    pub(crate) fn trust_anchor_from_process_credentials()
    -> Result<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError> {
        Self::trust_anchor_from_credentials(
            POLICY_CREDENTIAL_NAME,
            PUBLIC_KEY_CREDENTIAL_NAME,
            REVOCATION_SCOPE_CREDENTIAL_NAME,
        )
    }

    /// Loads Mount's independent public policy, key, and revocation scope.
    pub(crate) fn mount_trust_anchor_from_process_credentials()
    -> Result<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError> {
        Self::trust_anchor_from_credentials(
            MOUNT_POLICY_CREDENTIAL_NAME,
            MOUNT_PUBLIC_KEY_CREDENTIAL_NAME,
            MOUNT_REVOCATION_SCOPE_CREDENTIAL_NAME,
        )
    }

    /// Reads Mount's validated revocation scope for typed effect-plan construction.
    pub(crate) fn mount_revocation_scope_from_process_credentials()
    -> Result<RevocationScopeId, ControllerBrokerPlanSignerError> {
        Ok(Self::mount_trust_anchor_from_process_credentials()?.revocation_scope())
    }

    fn trust_anchor_from_credentials(
        policy_name: &str,
        public_key_name: &str,
        revocation_scope_name: &str,
    ) -> Result<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError> {
        let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
            .ok_or(ControllerBrokerPlanSignerError::Credential)?;
        if !Path::new(&directory).is_absolute() {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }
        let directory = Path::new(&directory);
        let public_key: [u8; SEED_BYTES] =
            read_public_credential(directory, public_key_name, SEED_BYTES)?
                .try_into()
                .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        let revocation_scope: [u8; 16] =
            read_public_credential(directory, revocation_scope_name, 16)?
                .try_into()
                .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        let policy_bytes = read_public_credential(directory, policy_name, MAXIMUM_POLICY_BYTES)?;
        let policy = decode_trust_policy(&policy_bytes, DecodeLimits::default())
            .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        if policy.purpose() != SignaturePurpose::BrokerAuthorization {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }
        let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
        let mut matching = policy.allowed_keys().iter().filter(|key| {
            key.usage() == KeyUsage::BrokerAuthorization && key.public_key_sha256() == fingerprint
        });
        let signer = matching
            .next()
            .cloned()
            .ok_or(ControllerBrokerPlanSignerError::Credential)?;
        if matching.next().is_some() {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }
        let media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        let descriptor = descriptor_for_bytes(media_type, &policy_bytes);
        BrokerPlanTrustAnchor::from_trusted_configuration(
            policy_bytes,
            descriptor,
            policy.trust_scope(),
            signer,
            public_key,
            RevocationScopeId::from_bytes(revocation_scope),
            DecodeLimits::default(),
        )
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)
    }

    /// Loads an optional fixed credential without following its leaf symlink.
    pub(crate) fn from_process_credentials_optional()
    -> Result<Option<Self>, ControllerBrokerPlanSignerError> {
        let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
            return Ok(None);
        };
        if !Path::new(&directory).is_absolute() {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }
        let directory = Path::new(&directory);
        let Some(seed_bytes) = read_optional_fixed_role_credential_v1(
            directory,
            CREDENTIAL_NAME,
            SEED_BYTES as u64,
            true,
        )
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)?
        else {
            return Ok(None);
        };
        let seed = Zeroizing::new(
            seed_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ControllerBrokerPlanSignerError::Credential)?,
        );

        let signing_key = SigningKey::from_bytes(&seed);
        let expected_public_key = signing_key.verifying_key().to_bytes();
        let authority = signing_authority_from_credentials(
            directory,
            POLICY_CREDENTIAL_NAME,
            PUBLIC_KEY_CREDENTIAL_NAME,
            expected_public_key,
        )?;
        let mount_authority = signing_authority_from_credentials(
            directory,
            MOUNT_POLICY_CREDENTIAL_NAME,
            MOUNT_PUBLIC_KEY_CREDENTIAL_NAME,
            expected_public_key,
        )?;

        Ok(Some(Self {
            seed,
            authority,
            mount_authority,
        }))
    }

    /// Signs one immutable broker plan and verifies its completed artifact.
    pub(crate) fn sign_plan(
        &self,
        plan: BrokerAuthorizationPlan,
        now_seconds: i64,
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        self.sign_with_authority(plan, now_seconds, &self.authority)
    }

    /// Signs only Mount-scoped plans under Mount's independent policy.
    pub(crate) fn sign_mount_plan(
        &self,
        plan: BrokerAuthorizationPlan,
        now_seconds: i64,
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        if plan.audience() != BrokerAudience::Mount || plan.protocol() != ProtocolId::MountBroker {
            return Err(ControllerBrokerPlanSignerError::Completion);
        }
        self.sign_with_authority(plan, now_seconds, &self.mount_authority)
    }

    /// Verifies the exact original Mount plan retained in a durable attempt.
    ///
    /// Recovery never signs a replacement under the same operation identity.
    /// Current assignment and ownership authority are checked separately when
    /// the recovered plan is rebound to the protected attempt.
    pub(crate) fn recover_mount_plan(
        &self,
        canonical_plan: &[u8],
        canonical_signature: &[u8],
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        let plan = decode_broker_authorization_plan(canonical_plan, DecodeLimits::default())
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)?;
        if plan.audience() != BrokerAudience::Mount || plan.protocol() != ProtocolId::MountBroker {
            return Err(ControllerBrokerPlanSignerError::Completion);
        }
        let issued = plan.issued_seconds();
        let preparation = BrokerPlanPreparation::new(plan, self.mount_authority.clone())
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)?;
        if preparation.canonical_plan() != canonical_plan {
            return Err(ControllerBrokerPlanSignerError::Completion);
        }
        preparation
            .complete(ReturnedSignature::Envelope(canonical_signature), issued)
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)
    }

    fn sign_with_authority(
        &self,
        plan: BrokerAuthorizationPlan,
        now_seconds: i64,
        authority: &SigningAuthority,
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        let preparation = BrokerPlanPreparation::new(plan, authority.clone())
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)?;
        let signing_key = SigningKey::from_bytes(&self.seed);
        let signature = sign_statement(
            preparation.signing_request().statement().clone(),
            &signing_key,
        )
        .map_err(|_| ControllerBrokerPlanSignerError::Signature)?;
        preparation
            .complete(ReturnedSignature::Bytes(signature.signature()), now_seconds)
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)
    }
}

fn signing_authority_from_credentials(
    directory: &Path,
    policy_name: &str,
    public_key_name: &str,
    expected_public_key: [u8; SEED_BYTES],
) -> Result<SigningAuthority, ControllerBrokerPlanSignerError> {
    let public_key: [u8; SEED_BYTES] =
        read_public_credential(directory, public_key_name, SEED_BYTES)?
            .try_into()
            .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
    if public_key != expected_public_key {
        return Err(ControllerBrokerPlanSignerError::Credential);
    }

    let policy_bytes = read_public_credential(directory, policy_name, MAXIMUM_POLICY_BYTES)?;
    let policy = decode_trust_policy(&policy_bytes, DecodeLimits::default())
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
    if policy.purpose() != SignaturePurpose::BrokerAuthorization {
        return Err(ControllerBrokerPlanSignerError::Credential);
    }
    let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
    let mut matches = policy.allowed_keys().iter().filter(|key| {
        key.usage() == KeyUsage::BrokerAuthorization && key.public_key_sha256() == fingerprint
    });
    let signer = matches
        .next()
        .cloned()
        .ok_or(ControllerBrokerPlanSignerError::Credential)?;
    if matches.next().is_some() {
        return Err(ControllerBrokerPlanSignerError::Credential);
    }
    let media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
    let policy_descriptor = descriptor_for_bytes(media_type, &policy_bytes);
    SigningAuthority::new(
        policy_bytes,
        policy_descriptor,
        policy.trust_scope(),
        signer,
        public_key,
        SignaturePurpose::BrokerAuthorization,
        DecodeLimits::default(),
    )
    .map_err(|_| ControllerBrokerPlanSignerError::Credential)
}

fn read_public_credential(
    directory: &Path,
    name: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ControllerBrokerPlanSignerError> {
    let path = directory.join(name);
    let descriptor = openat(
        CWD,
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
    let length = usize::try_from(metadata.len())
        .ok()
        .filter(|length| *length > 0 && *length <= maximum_bytes)
        .ok_or(ControllerBrokerPlanSignerError::Credential)?;
    if !metadata.is_file() {
        return Err(ControllerBrokerPlanSignerError::Credential);
    }

    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
    let mut trailing = [0];
    if file
        .read(&mut trailing)
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)?
        != 0
    {
        return Err(ControllerBrokerPlanSignerError::Credential);
    }
    Ok(bytes)
}
