//! Protected controller signing for prepared broker authorization plans.
//!
//! The key is loaded only from a fixed systemd credential name. This owner
//! signs the exact domain-separated statement prepared by the controller core;
//! completion independently verifies the result against its pinned policy.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use aos_sandbox::{BrokerPlanPreparation, ReturnedSignature, SignedBrokerPlan};
use aos_sandbox_core::sign_statement;
use ed25519_dalek::SigningKey;
use rustix::fs::{CWD, Mode, OFlags, openat};
use zeroize::Zeroizing;

const CREDENTIAL_NAME: &str = "broker-plan-signing-key";
const SEED_BYTES: usize = 32;

pub(crate) struct ControllerBrokerPlanSignerV1 {
    seed: Zeroizing<[u8; SEED_BYTES]>,
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
        let path = Path::new(&directory).join(CREDENTIAL_NAME);
        let descriptor = match openat(
            CWD,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
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
        if !metadata.is_file() || metadata.len() != SEED_BYTES as u64 {
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
        Ok(Some(Self { seed }))
    }

    /// Signs one immutable broker plan and verifies its completed artifact.
    pub(crate) fn sign(
        &self,
        preparation: BrokerPlanPreparation,
        now_seconds: i64,
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
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
