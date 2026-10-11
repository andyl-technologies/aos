//! Compact active-copy ownership in the existing permanent physical-key head.
//!
//! Full immutable sessions and positive receipts live in separately addressed
//! records. A pending provider turn never expires, and another workflow cannot
//! use the key while this pointer remains. Positive closure and clearing the
//! exact owner share the same checked storage transaction.
//!
//! ```text
//! owner = {copy_id, original_digest, configuration}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::external_object::copy::ExternalCopyOriginal;
use serde::{Deserialize, Serialize};

use super::super::protocol::digest_string;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Owner {
    pub copy_id: String,
    pub original_digest: String,
    pub configuration: String,
}

impl Owner {
    /// Retains only immutable commitments; no time or provider permission.
    ///
    /// # Errors
    /// Refuses an invalid original or malformed independently installed profile.
    pub(super) fn new(original: &ExternalCopyOriginal, configuration: String) -> Result<Self> {
        let value = Self {
            copy_id: original.copy_id()?,
            original_digest: original.fingerprint()?,
            configuration,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks compact retained commitments before any workflow shares the key.
    ///
    /// # Errors
    /// Refuses a malformed owner rather than treating it as a settled session.
    pub(in crate::external_object) fn validate(&self) -> Result<()> {
        ensure!(
            digest_string(&self.copy_id)
                && digest_string(&self.original_digest)
                && digest_string(&self.configuration),
            "corrupt retained copy owner"
        );
        Ok(())
    }

    /// Compares the full original to the durable compact owner.
    ///
    /// # Errors
    /// Refuses changed selectors, incarnation or independently configured profile.
    pub(super) fn matches(&self, original: &ExternalCopyOriginal) -> Result<()> {
        self.validate()?;
        ensure!(
            *self == Self::new(original, original.profile_digest.clone())?,
            "retained copy owner differs"
        );
        Ok(())
    }
}
