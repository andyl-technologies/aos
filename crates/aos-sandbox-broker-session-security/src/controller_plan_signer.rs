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
use aos_sandbox_core::format::decode_trust_policy;
use aos_sandbox_core::model::{KeyUsage, SignaturePurpose};
use aos_sandbox_core::{
    BrokerAuthorizationPlan, DecodeLimits, MediaType, ObjectDigest, PortableMediaType,
    descriptor_for_bytes, sign_statement,
};
use ed25519_dalek::SigningKey;
use rustix::fs::{CWD, Mode, OFlags, openat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const CREDENTIAL_NAME: &str = "broker-plan-signing-key";
const POLICY_CREDENTIAL_NAME: &str = "broker-plan-policy.cbor";
const PUBLIC_KEY_CREDENTIAL_NAME: &str = "broker-plan-public-key";
const SEED_BYTES: usize = 32;
const MAXIMUM_POLICY_BYTES: usize = 64 * 1024;

pub(crate) struct ControllerBrokerPlanSignerV1 {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    authority: SigningAuthority,
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
        let path = directory.join(CREDENTIAL_NAME);
        let descriptor = match openat(
            CWD,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(ControllerBrokerPlanSignerError::Credential),
        };
        let mut file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        if !metadata.is_file()
            || metadata.len() != SEED_BYTES as u64
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }

        let mut seed = Zeroizing::new([0; SEED_BYTES]);
        file.read_exact(&mut *seed)
            .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        let mut trailing = [0];
        if file
            .read(&mut trailing)
            .map_err(|_| ControllerBrokerPlanSignerError::Credential)?
            != 0
        {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }

        let public_key = read_public_credential(directory, PUBLIC_KEY_CREDENTIAL_NAME, SEED_BYTES)?;
        let public_key: [u8; SEED_BYTES] = public_key
            .try_into()
            .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key().to_bytes() != public_key {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }

        let policy_bytes =
            read_public_credential(directory, POLICY_CREDENTIAL_NAME, MAXIMUM_POLICY_BYTES)?;
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
        let authority = SigningAuthority::new(
            policy_bytes,
            policy_descriptor,
            policy.trust_scope(),
            signer,
            public_key,
            SignaturePurpose::BrokerAuthorization,
            DecodeLimits::default(),
        )
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;

        Ok(Some(Self { seed, authority }))
    }

    /// Signs one immutable broker plan and verifies its completed artifact.
    pub(crate) fn sign_plan(
        &self,
        plan: BrokerAuthorizationPlan,
        now_seconds: i64,
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        let preparation = BrokerPlanPreparation::new(plan, self.authority.clone())
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
