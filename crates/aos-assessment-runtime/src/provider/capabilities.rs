//! Authenticated fresh capability negotiation independent of unrelated Hub delivery.

use anyhow::{Result, bail};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::{ProviderLimits, ProviderOperation};
use crate::validation::{encoded, sorted, text};

/// Challenges one installed executor without granting provider or storage effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapabilityChallenge {
    /// Exact capability challenge discriminator.
    pub schema: String,
    /// Installed deployment identity.
    pub deployment_id: String,
    /// Installed coordinator identity.
    pub issuer: String,
    /// Installed executor identity.
    pub audience: String,
    /// Unique unpredictable challenge nonce.
    pub nonce: String,
    /// Explicit issuance time.
    pub issued_at: Timestamp,
    /// Exclusive deadline, within sixty seconds of issuance.
    pub expires_at: Timestamp,
}

impl CapabilityChallenge {
    /// Checks bounded challenge identity and a short current validity window.
    ///
    /// # Errors
    /// Returns an error for incompatible schema, invalid nonce or expiry.
    pub fn validate_at(&self, now: &Timestamp) -> Result<()> {
        for value in [
            &self.deployment_id,
            &self.issuer,
            &self.audience,
            &self.nonce,
        ] {
            text(value, 128, "capability challenge identity")?;
        }
        if self.schema != "aos.provider-capability-challenge/v1"
            || self.nonce.len() < 32
            || &self.issued_at > now
            || now >= &self.expires_at
            || self.expires_at.elapsed_since(&self.issued_at)? > 60
        {
            bail!("provider capability challenge is invalid or expired");
        }
        encoded(self)?;
        Ok(())
    }

    /// Computes an exact nonce/time/service-bound challenge identity.
    ///
    /// # Errors
    /// Returns an error for envelope limits or canonical serialization.
    pub fn digest(&self) -> Result<Sha256Digest> {
        encoded(self)?;
        Sha256Digest::of_canonical("aos.provider-capability-challenge/v1", self)
    }
}

/// Advertises exact installed parser profiles and tightenable effect ceilings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderCapabilitiesV1 {
    /// Exact closed capability response discriminator.
    pub schema: String,
    /// Exact authenticated fresh challenge, including deployment and nonce.
    pub challenge: CapabilityChallenge,
    /// Actual installed executor build identity.
    pub executor_build: String,
    /// Exact installed adapter versions, sorted and unique.
    pub adapters: Vec<String>,
    /// Actual effective independent invocation ceilings.
    pub limits: ProviderLimits,
}

impl ProviderCapabilitiesV1 {
    /// Checks the fresh paired response before coordinator work issuance.
    ///
    /// # Errors
    /// Returns an error for wrong challenge/schema, expiry, adapter or limit bounds.
    pub fn validate_for(&self, challenge: &CapabilityChallenge, now: &Timestamp) -> Result<()> {
        challenge.validate_at(now)?;
        text(&self.executor_build, 128, "capability executor build")?;
        self.limits.validate()?;
        if self.schema != "aos.provider-capabilities/v1"
            || &self.challenge != challenge
            || self.adapters.len() > 16
        {
            bail!("provider capability response differs from its fresh challenge");
        }
        sorted(&self.adapters, "provider adapter capabilities")?;
        for adapter in &self.adapters {
            text(adapter, 128, "provider adapter capability")?;
        }
        encoded(self)?;
        Ok(())
    }

    /// Checks whether an exact operation/profile is installed and negotiated.
    ///
    /// # Errors
    /// Returns an error for invalid typed source configuration or absent adapter.
    pub fn require(&self, operation: &ProviderOperation) -> Result<()> {
        operation.validate()?;
        if self
            .adapters
            .binary_search_by(|adapter| adapter.as_str().cmp(operation.adapter_version()))
            .is_err()
        {
            bail!("required provider profile is unavailable on the paired executor");
        }
        Ok(())
    }
}
