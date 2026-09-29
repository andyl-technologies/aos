//! Original five-known-field and full native correlation scopes.
//!
//! ```text
//! scope[224] = flight[32] | original_session[32] | mount_attempt[32] |
//! provider_attempt[32] | provider_acquisition[32] | original_root_request[32] |
//! original_native_request[32]
//! ```

use aos_sandbox_core::ObjectDigest;

use super::Result;
use super::codec::{Reader, digest, invalid, nonzero};

const FLIGHT_DOMAIN: &[u8] = b"aos.sandbox.native-held-completion.flight.v1\0";

/// Retains original correlation claims; it never constructs a current owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHeldScopeV1 {
    /// Commits Root request, Mount attempt and original Source session.
    pub flight: ObjectDigest,
    /// Retains the original Acquire session binding, never a recovery session.
    pub original_source_session: ObjectDigest,
    /// Names the actual original Mount ProviderQueryAttemptV2 attempt ID.
    pub mount_attempt: ObjectDigest,
    /// Names Source's original attempt digest; unknown in RootPrepared only.
    pub provider_attempt: ObjectDigest,
    /// Names the original provider acquisition from Acquire.
    pub provider_acquisition: ObjectDigest,
    /// Uses the existing digest_signed_request of the original signed Acquire.
    pub original_root_request: ObjectDigest,
    /// Uses the exact original signed native request digest; unknown at Root1.
    pub original_native_request: ObjectDigest,
}

impl NativeHeldScopeV1 {
    /// Checks the five known fields and the two immutable Root-only zero fields.
    ///
    /// # Errors
    ///
    /// Rejects sentinels, a wrong flight digest or any nonzero unknown field.
    pub fn validate_root_only(&self) -> Result<()> {
        self.validate_known()?;
        if nonzero(self.provider_attempt) || nonzero(self.original_native_request) {
            return Err(invalid("Root-only scope"));
        }
        Ok(())
    }

    /// Checks every original native field without granting dispatch permission.
    ///
    /// # Errors
    ///
    /// Rejects sentinels, a wrong flight digest or either unbound native field.
    pub fn validate_full(&self) -> Result<()> {
        self.validate_known()?;
        if !nonzero(self.provider_attempt) || !nonzero(self.original_native_request) {
            return Err(invalid("full native scope"));
        }
        Ok(())
    }

    /// Reports the canonical Root-only shape, not absence of Source dispatch.
    #[must_use]
    pub fn is_root_only(&self) -> bool {
        !nonzero(self.provider_attempt) && !nonzero(self.original_native_request)
    }

    /// Joins a full scope to the unchanged original Root five-known-field prefix.
    ///
    /// # Errors
    ///
    /// Rejects malformed scopes or any changed known original field.
    pub fn require_root_prefix(&self, original: &Self) -> Result<()> {
        self.validate_full()?;
        original.validate_root_only()?;
        if self.flight != original.flight
            || self.original_source_session != original.original_source_session
            || self.mount_attempt != original.mount_attempt
            || self.provider_acquisition != original.provider_acquisition
            || self.original_root_request != original.original_root_request
        {
            return Err(invalid("original Root prefix join"));
        }
        Ok(())
    }

    /// Encodes all seven exact correlation fields in their canonical order.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; 224] {
        let mut bytes = [0; 224];
        for (index, value) in self.fields().iter().enumerate() {
            bytes[index * 32..(index + 1) * 32].copy_from_slice(value.as_bytes());
        }
        bytes
    }

    pub(super) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            flight: reader.digest()?,
            original_source_session: reader.digest()?,
            mount_attempt: reader.digest()?,
            provider_attempt: reader.digest()?,
            provider_acquisition: reader.digest()?,
            original_root_request: reader.digest()?,
            original_native_request: reader.digest()?,
        })
    }

    fn fields(&self) -> [ObjectDigest; 7] {
        [
            self.flight,
            self.original_source_session,
            self.mount_attempt,
            self.provider_attempt,
            self.provider_acquisition,
            self.original_root_request,
            self.original_native_request,
        ]
    }

    fn validate_known(&self) -> Result<()> {
        if !nonzero(self.original_source_session)
            || !nonzero(self.mount_attempt)
            || !nonzero(self.provider_acquisition)
            || !nonzero(self.original_root_request)
            || self.flight
                != native_held_flight_digest_v1(
                    self.original_root_request,
                    self.mount_attempt,
                    self.original_source_session,
                )
        {
            return Err(invalid("known original scope"));
        }
        Ok(())
    }
}

/// Computes only a flight correlation digest, never a protected owner identity.
#[must_use]
pub fn native_held_flight_digest_v1(
    original_root_request: ObjectDigest,
    mount_attempt: ObjectDigest,
    original_source_session: ObjectDigest,
) -> ObjectDigest {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(original_root_request.as_bytes());
    bytes.extend_from_slice(mount_attempt.as_bytes());
    bytes.extend_from_slice(original_source_session.as_bytes());
    digest(FLIGHT_DOMAIN, &bytes)
}
