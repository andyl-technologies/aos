//! Retains the fixed Storage hold-key startup before its ordinary owner handoff.
//!
//! The enclosing genuine Storage startup pays first and retains this attempt
//! on failure. No key is generated or caller path/role accepted here.

use zeroize::Zeroizing;

use super::{
    CREDENTIAL_NAME, KEY_BYTES, StorageServiceError, StorageZfsHoldKeyCustodyV1,
    StorageZfsHoldKeyV1, StorageZfsHoldSignerV1, StorageZfsHoldVerifierV1,
    decode_key_record, invalid,
};
use crate::operator_recovery_credentials::InitialStorageCredentialBatchV1;

type ParsedKey = (
    StorageZfsHoldSignerV1,
    StorageZfsHoldVerifierV1,
    Zeroizing<[u8; 32]>,
);

pub(crate) struct StorageZfsHoldKeyStartupV1 {
    native: InitialStorageCredentialBatchV1<1>,
    parsed: Option<Result<ParsedKey, StorageServiceError>>,
    parsed_post: Option<Result<ParsedKey, StorageServiceError>>,
    semantic_post: Option<Result<(), StorageServiceError>>,
    completed: Option<StorageZfsHoldKeyV1>,
    entered: bool,
    taken: bool,
    closed: Option<StorageServiceError>,
}

impl StorageZfsHoldKeyStartupV1 {
    pub(crate) fn new() -> Self {
        Self {
            native: InitialStorageCredentialBatchV1::new(),
            parsed: None,
            parsed_post: None,
            semantic_post: None,
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
        std::mem::size_of::<Self>().checked_add(2 * KEY_BYTES)?
            .checked_add(2 * "/run/credentials/aos-storaged.service".len())?
            .checked_add(16 * 256)
    }

    /// Returns the reached native descriptor peak, including partial prefixes.
    pub(crate) const fn receiving_open_files() -> usize {
        4
    }

    /// Returns fixed file, buffer, path and native error carrier accounting.
    pub(crate) const fn receiving_metadata_entries() -> usize {
        24
    }

    pub(crate) fn capture_once(&mut self) -> Result<(), ()> {
        if self.entered || self.taken || self.closed.is_some() {
            self.closed.get_or_insert_with(|| invalid("Storage hold-key startup repeated"));
            return Err(());
        }
        self.entered = true;
        if self.native.capture_once(&[CREDENTIAL_NAME], &[KEY_BYTES]).is_ok() {
            self.parsed = Some(self.native.bytes(0)
                .ok_or_else(|| invalid("Storage hold-key input incomplete"))
                .and_then(decode_key_record));
        }
        let posted = self.native.post_once(&[CREDENTIAL_NAME], &[KEY_BYTES]);
        if posted.is_ok() && matches!(self.parsed, Some(Ok(_))) {
            // The old load ends in recheck, including this second role decode.
            self.parsed_post = Some(self.native.post_bytes(0)
                .ok_or_else(|| invalid("Storage hold-key input incomplete"))
                .and_then(decode_key_record));
            self.semantic_post = Some(self.recheck_semantic());
        }
        if self.failure().is_none() && matches!(self.semantic_post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn recheck_semantic(&self) -> Result<(), StorageServiceError> {
        let expected = self.parsed.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("Storage hold-key input incomplete"))?;
        // Native posts already proved exact named bytes, including identity.
        // Keep the whole second decode beside the original through comparison.
        let current = self.parsed_post.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| invalid("Storage hold-key post decode failed"))?;
        if current.0 != expected.0 || current.1 != expected.1 || current.2 != expected.2 {
            return Err(invalid("Storage ZFS hold credential changed"));
        }
        Ok(())
    }

    pub(crate) fn take_success(&mut self) -> Option<StorageZfsHoldKeyV1> {
        if !self.entered || self.taken || self.failure().is_some()
            || !self.native.ready_for_handoff()
            || !matches!(self.semantic_post, Some(Ok(())))
            || !matches!(self.parsed, Some(Ok(_)))
            || self.native.bytes(0).is_none()
        {
            return None;
        }
        let directory_identity = self.native.directory_identity()?;
        let directory = InitialStorageCredentialBatchV1::<1>::directory_path();
        let key = self.native.take_pin(0, CREDENTIAL_NAME)?;
        let (signer, verifier, seed) = self.parsed.take()?.ok()?;
        self.taken = true;
        self.completed = Some(StorageZfsHoldKeyV1 {
            custody: StorageZfsHoldKeyCustodyV1::Protected {
                directory,
                directory_identity,
                key,
            },
            signer,
            verifier,
            seed,
        });
        if self.native.settle_positive_native_once().is_err() {
            self.closed.get_or_insert_with(|| invalid("Storage hold-key settlement incomplete"));
            return None;
        }
        self.completed.take()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.capture_failure()
            .or_else(|| self.parsed.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native.post_failure())
            .or_else(|| self.parsed_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.semantic_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.closed.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}
