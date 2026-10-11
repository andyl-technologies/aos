//! Separate plan/result authentication before decoding or resolving credentials.

use anyhow::{Result, bail};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    CapabilityChallenge, PROVIDER_CAPABILITIES_PATH, PROVIDER_WORK_PATH, ProviderCapabilitiesV1,
    ProviderWorkPlanV1, ProviderWorkResultV1,
};
use crate::validation::{decode, encoded, text};

/// Signs and verifies provider work in a domain separate from ingress/storage.
pub struct ProviderWorkAuth {
    secret: Zeroizing<Vec<u8>>,
    deployment: String,
    issuer: String,
    audience: String,
}

impl ProviderWorkAuth {
    /// Creates one installed paired-service signer/verifier with a strong secret.
    ///
    /// # Errors
    /// Returns an error for a secret shorter than thirty-two bytes or invalid identities.
    pub fn new(
        secret: Vec<u8>,
        deployment: String,
        issuer: String,
        audience: String,
    ) -> Result<Self> {
        if secret.len() < 32 {
            bail!("provider work requires a separate strong shared secret");
        }
        for value in [&deployment, &issuer, &audience] {
            text(value, 128, "installed provider service identity")?;
        }
        Ok(Self {
            secret: Zeroizing::new(secret),
            deployment,
            issuer,
            audience,
        })
    }

    fn mac(&self, domain: &[u8], route: &str, body: &[u8]) -> Result<Hmac<Sha256>> {
        if body.len() > 256 * 1024 {
            bail!("provider authentication body exceeds route limit");
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .map_err(|_| anyhow::anyhow!("invalid provider authentication key"))?;
        for value in [
            domain,
            b"POST",
            route.as_bytes(),
            self.deployment.as_bytes(),
            self.issuer.as_bytes(),
            self.audience.as_bytes(),
        ] {
            mac.update(&(value.len() as u64).to_be_bytes());
            mac.update(value);
        }
        mac.update(Sha256Digest::of_bytes(body).to_string().as_bytes());
        Ok(mac)
    }

    /// Authenticates exact request bytes after validating scope and validity.
    ///
    /// # Errors
    /// Returns an error for invalid scope/time, envelope bounds or serialization.
    pub fn sign_plan(
        &self,
        plan: &ProviderWorkPlanV1,
        now: &Timestamp,
    ) -> Result<(Vec<u8>, String)> {
        self.check_identity(plan)?;
        plan.validate_at(now)?;
        let body = encoded(plan)?;
        let signature = hex::encode(
            self.mac(b"aos-provider-plan-v1", PROVIDER_WORK_PATH, &body)?
                .finalize()
                .into_bytes(),
        );
        Ok((body, signature))
    }

    /// Verifies authentication before decoding a current exact bounded work plan.
    ///
    /// # Errors
    /// Returns an error for invalid signature, duplicate fields, wrong deployment,
    /// expiry or unsupported scope; callers must verify before credentials/effects.
    pub fn verify_plan(
        &self,
        body: &[u8],
        signature: &str,
        now: &Timestamp,
    ) -> Result<ProviderWorkPlanV1> {
        self.verify(b"aos-provider-plan-v1", PROVIDER_WORK_PATH, body, signature)?;
        let plan = ProviderWorkPlanV1::from_slice(body, now)?;
        self.check_identity(&plan)?;
        plan.validate_at(now)?;
        Ok(plan)
    }

    /// Authenticates one compact result in the independent provider-result domain.
    ///
    /// # Errors
    /// Returns an error for invalid result/plan association or envelope bounds.
    pub fn sign_result(
        &self,
        result: &ProviderWorkResultV1,
        plan: &ProviderWorkPlanV1,
        now: &Timestamp,
    ) -> Result<(Vec<u8>, String)> {
        self.check_identity(plan)?;
        result.validate_for(plan, now)?;
        let body = encoded(result)?;
        let signature = hex::encode(
            self.mac(b"aos-provider-result-v1", PROVIDER_WORK_PATH, &body)?
                .finalize()
                .into_bytes(),
        );
        Ok((body, signature))
    }

    /// Verifies a result before admitting its normalized objects to the journal.
    ///
    /// # Errors
    /// Returns an error for invalid signature, changed scope/hash, expiry or limits.
    pub fn verify_result(
        &self,
        body: &[u8],
        signature: &str,
        plan: &ProviderWorkPlanV1,
        now: &Timestamp,
    ) -> Result<ProviderWorkResultV1> {
        self.check_identity(plan)?;
        self.verify(
            b"aos-provider-result-v1",
            PROVIDER_WORK_PATH,
            body,
            signature,
        )?;
        let result: ProviderWorkResultV1 = decode(body, "provider work result")?;
        result.validate_for(plan, now)?;
        Ok(result)
    }

    fn check_identity(&self, plan: &ProviderWorkPlanV1) -> Result<()> {
        if plan.deployment_id != self.deployment
            || plan.issuer != self.issuer
            || plan.audience != self.audience
        {
            bail!("provider work deployment, issuer or audience differs from installed pairing");
        }
        Ok(())
    }

    fn check_challenge(&self, challenge: &CapabilityChallenge, now: &Timestamp) -> Result<()> {
        challenge.validate_at(now)?;
        if challenge.deployment_id != self.deployment
            || challenge.issuer != self.issuer
            || challenge.audience != self.audience
        {
            bail!("capability challenge differs from the installed service pairing");
        }
        Ok(())
    }

    /// Authenticates a fresh bounded capability challenge in its own route/domain.
    ///
    /// # Errors
    /// Returns an error for invalid pairing, expiry or canonical bounds.
    pub fn sign_challenge(
        &self,
        challenge: &CapabilityChallenge,
        now: &Timestamp,
    ) -> Result<(Vec<u8>, String)> {
        self.check_challenge(challenge, now)?;
        let body = encoded(challenge)?;
        let signature = hex::encode(
            self.mac(
                b"aos-provider-capability-request-v1",
                PROVIDER_CAPABILITIES_PATH,
                &body,
            )?
            .finalize()
            .into_bytes(),
        );
        Ok((body, signature))
    }

    /// Verifies a capability challenge before returning installed service information.
    ///
    /// # Errors
    /// Returns an error for invalid signature, wrong pairing, ambiguity or expiry.
    pub fn verify_challenge(
        &self,
        body: &[u8],
        signature: &str,
        now: &Timestamp,
    ) -> Result<CapabilityChallenge> {
        self.verify(
            b"aos-provider-capability-request-v1",
            PROVIDER_CAPABILITIES_PATH,
            body,
            signature,
        )?;
        let challenge = decode(body, "provider capability challenge")?;
        self.check_challenge(&challenge, now)?;
        Ok(challenge)
    }

    /// Authenticates an exact challenge-bound installed capability response.
    ///
    /// # Errors
    /// Returns an error for invalid response/pairing, expiry or canonical bounds.
    pub fn sign_capabilities(
        &self,
        capabilities: &ProviderCapabilitiesV1,
        now: &Timestamp,
    ) -> Result<(Vec<u8>, String)> {
        self.check_challenge(&capabilities.challenge, now)?;
        capabilities.validate_for(&capabilities.challenge, now)?;
        let body = encoded(capabilities)?;
        let signature = hex::encode(
            self.mac(
                b"aos-provider-capability-result-v1",
                PROVIDER_CAPABILITIES_PATH,
                &body,
            )?
            .finalize()
            .into_bytes(),
        );
        Ok((body, signature))
    }

    /// Verifies current capability authority before issuing an exact provider plan.
    ///
    /// # Errors
    /// Returns an error for wrong signature/challenge, expiry or profile limits.
    pub fn verify_capabilities(
        &self,
        body: &[u8],
        signature: &str,
        challenge: &CapabilityChallenge,
        now: &Timestamp,
    ) -> Result<ProviderCapabilitiesV1> {
        self.check_challenge(challenge, now)?;
        self.verify(
            b"aos-provider-capability-result-v1",
            PROVIDER_CAPABILITIES_PATH,
            body,
            signature,
        )?;
        let capabilities: ProviderCapabilitiesV1 = decode(body, "provider capabilities")?;
        capabilities.validate_for(challenge, now)?;
        Ok(capabilities)
    }

    fn verify(&self, domain: &[u8], route: &str, body: &[u8], signature: &str) -> Result<()> {
        if signature.len() != 64 {
            bail!("invalid provider work signature");
        }
        let signature = hex::decode(signature)
            .map_err(|_| anyhow::anyhow!("invalid provider work signature"))?;
        self.mac(domain, route, body)?
            .verify_slice(&signature)
            .map_err(|_| anyhow::anyhow!("invalid provider work signature"))
    }
}
