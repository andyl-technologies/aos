//! Fresh signed direct profile discovery on the existing storage-capabilities route.
//!
//! ```json
//! {"version":2,"deploymentId":"deployment","executorPublicOrigin":"https://executor.example","requestNonce":"<64 lowercase hex>","issuedAt":"100","expiresAt":"130","managed":true,"externalSelectors":[]}
//! ```
//!
//! The old literal readiness challenge retains its legacy response. These fresh
//! envelopes use separate domains, full exact request correlation and a 64 KiB
//! bound. No returned profile alone establishes private-policy qualification.

use std::{collections::BTreeSet, io};

use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::storage_work::StorageWorkKey;

use super::*;

/// Maximum complete protected direct capability request or reply bytes.
pub const MAX_DIRECT_CAPABILITY_BYTES: usize = 64 * 1024;

const REQUEST_DOMAIN: &[u8] = b"aos.direct-upload.storage-capabilities-request.v2\0";
const REPLY_DOMAIN: &[u8] = b"aos.direct-upload.storage-capabilities-reply.v2\0";

/// Fresh server-resolved profile challenge sent only to the fixed internal route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectStorageCapabilitiesRequest {
    /// Closed fresh challenge version, currently two.
    pub version: u32,
    /// Independently configured immutable Hub deployment.
    pub deployment_id: String,
    /// Independently pinned canonical public executor HTTPS origin.
    pub executor_public_origin: String,
    /// Fresh random request correlation, exactly 64 lowercase hex characters.
    pub request_nonce: String,
    /// Earliest declared request issue timestamp, in exact seconds.
    pub issued_at: WireInteger,
    /// Exclusive short request deadline, never a settlement fence.
    pub expires_at: WireInteger,
    /// Requests the actual protected managed profile/policy pair.
    pub managed: bool,
    /// Only requested current external bindings, resolved by the Native owner.
    pub external_selectors: Vec<DirectExternalProfileSelector>,
}

impl DirectStorageCapabilitiesRequest {
    /// Checks audience, bounded selectors and an exclusive conservative deadline.
    ///
    /// `latest_now` must come from an independently qualified caller clock; this
    /// helper does not establish clock freshness, rollback protection or trust.
    ///
    /// # Errors
    /// Returns an error for foreign audience, invalid or duplicate selectors,
    /// excessive encoding, invalid lifetime or expired/future request.
    pub fn validate(&self, deployment: &str, executor_origin: &str, latest_now: u64) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            self.deployment_id == deployment
                && self.executor_public_origin == executor_origin
                && self.issued_at.get() <= latest_now
                && latest_now < self.expires_at.get(),
            "direct capability request audience or deadline mismatch"
        );
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        ensure!(
            self.version == 2
                && valid_direct_identity(&self.deployment_id)
                && valid_direct_digest(&self.request_nonce)
                && self
                    .expires_at
                    .get()
                    .checked_sub(self.issued_at.get())
                    .is_some_and(|ttl| ttl > 0 && ttl <= 30)
                && self.external_selectors.len() <= MAX_DIRECT_PLACEMENTS
                && (self.managed || !self.external_selectors.is_empty()),
            "invalid direct capability challenge"
        );
        let origin = url::Url::parse(&self.executor_public_origin)
            .map_err(|_| anyhow::anyhow!("invalid direct capability executor origin"))?;
        ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/"
                && origin.origin().ascii_serialization() == self.executor_public_origin,
            "invalid direct capability executor origin"
        );
        let mut identities = BTreeSet::new();
        for selector in &self.external_selectors {
            selector.validate()?;
            // A binding may not be challenged twice with changed purpose facts.
            ensure!(
                identities.insert((
                    selector.physical_authority_id.clone(),
                    selector.association.association_id.clone()
                )),
                "duplicate direct capability selector"
            );
        }
        encode_capability(self)?;
        Ok(())
    }
}

/// Exact fresh challenge-correlated profile readback, authenticated before decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectStorageCapabilitiesReply {
    /// Exact complete request, including all selectors, nonce and deadlines.
    pub request: DirectStorageCapabilitiesRequest,
    /// Only requested actual protected profiles and private policy projections.
    pub capabilities: DirectStorageCapabilities,
}

impl DirectStorageCapabilitiesReply {
    /// Correlates the complete response to the exact requested profile set.
    ///
    /// Independently reviewed profile pin equality and current publication
    /// admission remain Native caller requirements after this validation.
    ///
    /// # Errors
    /// Returns an error for unsolicited/missing profiles or changed selectors.
    pub fn validate_for(&self, request: &DirectStorageCapabilitiesRequest) -> Result<()> {
        request.validate_shape()?;
        ensure!(
            &self.request == request,
            "direct capability reply request changed"
        );
        self.capabilities.validate(&request.deployment_id)?;
        ensure!(
            self.capabilities.profile.is_some() == request.managed
                && self.capabilities.external_profiles.len() == request.external_selectors.len(),
            "direct capability requested profile set mismatch"
        );
        for (profile, selector) in self
            .capabilities
            .external_profiles
            .iter()
            .zip(&request.external_selectors)
        {
            ensure!(
                &profile.profile.selector == selector,
                "direct capability selector response mismatch"
            );
        }
        encode_capability(self)?;
        Ok(())
    }
}

/// Signs a bounded closed fresh request with its dedicated domain.
///
/// # Errors
/// Returns a value-free error for invalid shape, excessive encoding or signing.
pub fn sign_direct_storage_capabilities_request(
    key: &StorageWorkKey,
    request: &DirectStorageCapabilitiesRequest,
) -> Result<SignedDirectControl> {
    request.validate_shape()?;
    sign(key, REQUEST_DOMAIN, request)
}

/// Authenticates raw bytes before closed decoding, then checks audience and time.
///
/// # Errors
/// Returns an error for bad signature/domain, noncanonical/unknown/duplicate
/// fields, excessive bytes, changed audience or an expired conservative deadline.
pub fn verify_direct_storage_capabilities_request(
    key: &StorageWorkKey,
    signature: &str,
    bytes: &[u8],
    deployment: &str,
    executor_origin: &str,
    latest_now: u64,
) -> Result<DirectStorageCapabilitiesRequest> {
    let request: DirectStorageCapabilitiesRequest = verify(key, REQUEST_DOMAIN, signature, bytes)?;
    request.validate(deployment, executor_origin, latest_now)?;
    Ok(request)
}

/// Signs an exact fresh reply without exposing protected credential material.
///
/// # Errors
/// Returns an error for changed/missing profile projections, bounds or signing.
pub fn sign_direct_storage_capabilities_reply(
    key: &StorageWorkKey,
    reply: &DirectStorageCapabilitiesReply,
) -> Result<SignedDirectControl> {
    reply.validate_for(&reply.request)?;
    sign(key, REPLY_DOMAIN, reply)
}

/// Authenticates a fresh reply and validates its full request correlation/deadline.
///
/// # Errors
/// Returns an error for authentication, nonclosed/canonical wire, bounds,
/// changed request/profile set or expired conservative caller time.
pub fn verify_direct_storage_capabilities_reply(
    key: &StorageWorkKey,
    signature: &str,
    bytes: &[u8],
    request: &DirectStorageCapabilitiesRequest,
    latest_now: u64,
) -> Result<DirectStorageCapabilitiesReply> {
    let reply: DirectStorageCapabilitiesReply = verify(key, REPLY_DOMAIN, signature, bytes)?;
    request.validate(
        &request.deployment_id,
        &request.executor_public_origin,
        latest_now,
    )?;
    reply.validate_for(request)?;
    Ok(reply)
}

fn sign<T: Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    value: &T,
) -> Result<SignedDirectControl> {
    let body = encode_capability(value)?;
    let signature = key
        .sign_body(&domain_bytes(domain, &body))
        .map_err(|_| anyhow::anyhow!("direct capability signing failed"))?;
    Ok(SignedDirectControl { body, signature })
}

fn verify<T: DeserializeOwned + Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    signature: &str,
    bytes: &[u8],
) -> Result<T> {
    ensure!(
        bytes.len() <= MAX_DIRECT_CAPABILITY_BYTES,
        "direct capability control exceeds limit"
    );
    key.verify_body(signature, &domain_bytes(domain, bytes))
        .map_err(|_| anyhow::anyhow!("direct capability authentication failed"))?;
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid direct capability control"))?;
    ensure!(
        encode_capability(&value)? == bytes,
        "noncanonical direct capability control"
    );
    Ok(value)
}

fn domain_bytes(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(domain.len() + bytes.len());
    result.extend_from_slice(domain);
    result.extend_from_slice(bytes);
    result
}

fn encode_capability<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut writer = CapabilityWriter(Vec::new());
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| anyhow::anyhow!("invalid or excessive direct capability encoding"))?;
    Ok(writer.0)
}

struct CapabilityWriter(Vec<u8>);

impl io::Write for CapabilityWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_DIRECT_CAPABILITY_BYTES)
        {
            return Err(io::Error::other("direct capability control exceeds limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
