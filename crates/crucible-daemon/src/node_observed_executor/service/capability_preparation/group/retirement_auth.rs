//! Authenticates only the lane's original native cleanup relation across restart.
//!
//! The separate private key does not sign native captures or accept caller
//! bodies as authority. Only this installed owning lane seals its exact held
//! source cleanup relation, after original runtime and native reclamation.

use super::super::{NodeObservationServiceError, refused};
use ed25519_dalek::{Signature, Signer, SigningKey};
use rustix::fs::{Mode, OFlags};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

pub(in crate::node_observed_executor::service::capability_preparation) struct Authenticator {
    key: SigningKey,
}

impl Authenticator {
    pub(in crate::node_observed_executor::service::capability_preparation) fn open(
        directory: &Path,
    ) -> Result<Self, NodeObservationServiceError> {
        let directory = File::from(
            rustix::fs::open(
                directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(refused)?,
        );
        let uid = rustix::process::geteuid().as_raw();
        let metadata = directory.metadata().map_err(refused)?;
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(refused(
                "operational cleanup authentication requires a private owned archive",
            ));
        }
        let name = "capability-native-retirement-key-v1";
        match rustix::fs::openat(
            &directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                // Operational key entropy never enters simulation coordinates,
                // model state, operation IDs or source capability selection.
                let mut key = [0_u8; 32];
                File::open("/dev/urandom")
                    .map_err(refused)?
                    .read_exact(&mut key)
                    .map_err(refused)?;
                let mut file = File::from(fd);
                file.write_all(&key).map_err(refused)?;
                file.sync_all().map_err(refused)?;
                directory.sync_all().map_err(refused)?;
                key.fill(0);
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(refused(error)),
        }
        let mut file = File::from(
            rustix::fs::openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(refused)?,
        );
        let metadata = file.metadata().map_err(refused)?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.len() != 32
        {
            return Err(refused(
                "original cleanup key is not a private single-link 32-byte file",
            ));
        }
        let mut key = [0_u8; 32];
        file.read_exact(&mut key).map_err(refused)?;
        let signing = SigningKey::from_bytes(&key);
        key.fill(0);
        Ok(Self { key: signing })
    }

    pub(in crate::node_observed_executor::service::capability_preparation) fn sign(
        &self,
        body: &[u8],
    ) -> Result<Vec<u8>, NodeObservationServiceError> {
        let message = message(body)?;
        Ok(self.key.sign(&message).to_bytes().to_vec())
    }

    pub(in crate::node_observed_executor::service::capability_preparation) fn verify(
        &self,
        body: &[u8],
        authentication: &[u8],
    ) -> Result<(), NodeObservationServiceError> {
        let signature = Signature::from_slice(authentication).map_err(refused)?;
        self.key
            .verifying_key()
            .verify_strict(&message(body)?, &signature)
            .map_err(refused)
    }
}

fn message(body: &[u8]) -> Result<Vec<u8>, NodeObservationServiceError> {
    if body.len() > 128 * 1024 {
        return Err(refused(
            "original cleanup signing body exceeds finite credit",
        ));
    }
    let mut message = Vec::new();
    let domain = b"crucible.capability-native-retirement.v1\0";
    message
        .try_reserve_exact(domain.len() + 8 + body.len())
        .map_err(refused)?;
    message.extend_from_slice(domain);
    message.extend_from_slice(&(body.len() as u64).to_be_bytes());
    message.extend_from_slice(body);
    Ok(message)
}

#[cfg(test)]
#[path = "retirement_auth_tests.rs"]
mod retirement_auth_tests;
