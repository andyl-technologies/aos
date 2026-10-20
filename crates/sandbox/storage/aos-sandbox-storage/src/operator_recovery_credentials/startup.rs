//! Retains the two independently provisioned initial Storage operator keys.
//!
//! Native input and role-validation results belong to the same prepaid startup
//! attempt. The normal operator owner is moved only after the exact readback.

use ed25519_dalek::{SigningKey, VerifyingKey};

use super::{
    CONTROLLER_BYTES, CONTROLLER_NAME, InitialStorageCredentialBatchV1,
    OWNER_BYTES, OWNER_NAME, StorageOperatorRecoveryCredentialsV1,
    StorageServiceError, decode_controller, decode_owner, invalid,
};

type ParsedController = ([u8; 16], u64, VerifyingKey);
type ParsedOwner = ([u8; 16], u64, SigningKey);

pub(crate) struct StorageOperatorCredentialStartupV1 {
    native: InitialStorageCredentialBatchV1<2>,
    controller: Option<Result<ParsedController, StorageServiceError>>,
    owner: Option<Result<ParsedOwner, StorageServiceError>>,
    binding: Option<Result<(), StorageServiceError>>,
    completed: Option<StorageOperatorRecoveryCredentialsV1>,
    entered: bool,
    taken: bool,
    closed: Option<StorageServiceError>,
}

impl StorageOperatorCredentialStartupV1 {
    pub(crate) fn new() -> Self {
        Self {
            native: InitialStorageCredentialBatchV1::new(),
            controller: None,
            owner: None,
            binding: None,
            completed: None,
            entered: false,
            taken: false,
            closed: None,
        }
    }

    /// Includes the actual inline attempt and dominant fixed input carriers.
    ///
    /// This passive bound supplies no payer or fit. The genuine original must
    /// accept it before construction/capture grows any dynamic representation.
    pub(crate) fn receiving_memory_bytes() -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(2 * (CONTROLLER_BYTES + OWNER_BYTES))?
            .checked_add(2 * "/run/credentials/aos-storaged.service".len())?
            .checked_add(16 * 256)
    }

    /// Returns the reached native descriptor peak, including partial prefixes.
    pub(crate) const fn receiving_open_files() -> usize {
        6
    }

    /// Returns fixed file, buffer, path and native error carrier accounting.
    pub(crate) const fn receiving_metadata_entries() -> usize {
        28
    }

    pub(crate) fn capture_once(&mut self) -> Result<(), ()> {
        if self.entered || self.taken || self.closed.is_some() {
            self.closed.get_or_insert_with(|| invalid("Storage operator startup repeated"));
            return Err(());
        }
        self.entered = true;
        let names = [CONTROLLER_NAME, OWNER_NAME];
        let lengths = [CONTROLLER_BYTES, OWNER_BYTES];
        if self.native.capture_once(&names, &lengths).is_ok() {
            self.controller = Some(self.native.bytes(0)
                .ok_or_else(|| invalid("Storage operator input incomplete"))
                .and_then(decode_controller));
            if matches!(self.controller, Some(Ok(_))) {
                self.owner = Some(self.native.bytes(1)
                    .ok_or_else(|| invalid("Storage operator input incomplete"))
                    .and_then(decode_owner));
                if matches!(self.owner, Some(Ok(_))) {
                    self.binding = Some(self.require_independent_roles());
                }
            }
        }
        // The old load finishes by reopening both exact credential names.
        // This selected post additionally retains original metadata bookends.
        let _ = self.native.post_once(&names, &lengths);
        if self.failure().is_none() && matches!(self.binding, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn require_independent_roles(&self) -> Result<(), StorageServiceError> {
        let controller = self.controller.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("Storage operator input incomplete"))?;
        let owner = self.owner.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("Storage operator input incomplete"))?;
        if controller.2 == owner.2.verifying_key() {
            return Err(invalid("operator role keys are not independent"));
        }
        Ok(())
    }

    pub(crate) fn take_success(&mut self) -> Option<StorageOperatorRecoveryCredentialsV1> {
        if !self.entered || self.taken || self.failure().is_some()
            || !self.native.ready_for_handoff()
            || !matches!(self.binding, Some(Ok(())))
            || !matches!(self.controller, Some(Ok(_)))
            || !matches!(self.owner, Some(Ok(_)))
            || self.native.bytes(0).is_none() || self.native.bytes(1).is_none()
        {
            return None;
        }
        let directory_identity = self.native.directory_identity()?;
        let directory = InitialStorageCredentialBatchV1::<2>::directory_path();
        let controller = self.native.take_pin(0, CONTROLLER_NAME)?;
        let owner = self.native.take_pin(1, OWNER_NAME)?;
        let (_, controller_generation, controller_key) = self.controller.take()?.ok()?;
        let (owner_id, owner_generation, owner_key) = self.owner.take()?.ok()?;
        self.taken = true;
        self.completed = Some(StorageOperatorRecoveryCredentialsV1 {
            directory,
            directory_identity,
            controller,
            owner,
            controller_key,
            controller_generation,
            owner_key,
            owner_id,
            owner_generation,
        });
        if self.native.settle_positive_native_once().is_err() {
            self.closed.get_or_insert_with(|| invalid("Storage operator settlement incomplete"));
            return None;
        }
        self.completed.take()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.capture_failure()
            .or_else(|| self.controller.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.owner.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native.post_failure())
            .or_else(|| self.closed.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}
