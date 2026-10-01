//! Fresh metadata challenges for Worker-held external credential custody.
//!
//! Operator staging carries one resolved material. Native probe and adoption
//! controls carry only exact original metadata. Replies never return material;
//! each MAC binds canonical bytes, purpose, fresh nonce, and complete context.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    StorageBindingPublication, StorageBindingSnapshot, StorageCredentialMaterial, StorageWorkError,
    StorageWorkKey,
};
use crate::topology_probe::StorageCredentialProbeEvidence;

/// Protected operator endpoint for one original queued credential material.
pub const STORAGE_CREDENTIAL_CUSTODY_PATH: &str = "/_internal/storage/v1/credential-custody";
/// Metadata-only Native endpoint for an exact retained credential probe.
pub const STORAGE_CREDENTIAL_CUSTODY_PROBE_PATH: &str =
    "/_internal/storage/v1/credential-custody/probe";
/// Metadata-only Native endpoint for current binding adoption or renewal.
pub const STORAGE_BINDING_ADOPTION_PATH: &str = "/_internal/storage/v1/binding-adoption";
/// Maximum canonical control or reply size.
pub const MAX_BINDING_CUSTODY_BYTES: usize = 64 * 1024;
/// Maximum explicit material retention horizon; it grants no provider permission.
pub const MAX_CREDENTIAL_CUSTODY_SECONDS: i64 = 24 * 60 * 60;

const STAGE_REQUEST: &[u8] = b"aos.storage-credential-custody.stage-request.v1\0";
const STAGE_REPLY: &[u8] = b"aos.storage-credential-custody.stage-reply.v1\0";
const PROBE_REQUEST: &[u8] = b"aos.storage-credential-custody.probe-request.v1\0";
const PROBE_REPLY: &[u8] = b"aos.storage-credential-custody.probe-reply.v1\0";
const ADOPT_REQUEST: &[u8] = b"aos.storage-binding-custody.adopt-request.v1\0";
const ADOPT_REPLY: &[u8] = b"aos.storage-binding-custody.adopt-reply.v1\0";

/// Exact queued probe and current SQL credential identity, without secret bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCredentialCustodyProbe {
    /// Protocol version, currently one.
    pub version: u8,
    /// Fresh 256-bit challenge nonce.
    pub nonce: String,
    /// Request issue time in Unix seconds.
    pub issued_at: i64,
    /// Exclusive request deadline, no more than thirty seconds after issue.
    pub expires_at: i64,
    /// Original queued topology operation identity.
    pub operation_id: String,
    /// Original server-owned probe object token.
    pub probe_token: String,
    /// Exact current-generation credential head CAS.
    pub head_resource_version: i64,
    /// Fresh complete binding coordinates and one exact credential reference.
    pub snapshot: StorageBindingSnapshot,
}

impl StorageCredentialCustodyProbe {
    /// Validates the fresh original challenge before material lookup or dispatch.
    ///
    /// # Errors
    /// Returns an error for invalid originals, another deployment, or expiry.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<(), StorageWorkError> {
        fresh(
            self.version,
            &self.nonce,
            self.issued_at,
            self.expires_at,
            now,
        )?;
        self.snapshot.validate(deployment, now)?;
        if self.operation_id.is_empty()
            || self.operation_id.len() > 128
            || self.operation_id.chars().any(char::is_control)
            || !digest(&self.probe_token)
            || self.head_resource_version <= 0
            || self.snapshot.access_mode != "private"
            || self.snapshot.credentials.len() != 1
            || self.snapshot.issued_at > now
            || self.snapshot.expires_at <= now
            || self.snapshot.expires_at > self.expires_at
            || self.snapshot.expires_at - self.snapshot.issued_at > 30
        {
            return Err(StorageWorkError::InvalidSnapshot);
        }
        Ok(())
    }

    /// Compares immutable queued originals while allowing fresh challenge times.
    ///
    /// # Errors
    /// Returns an error when an original task, head, binding, or reference changed.
    pub fn matches_original(&self, original: &Self) -> Result<(), StorageWorkError> {
        let mut expected = original.clone();
        expected.nonce = self.nonce.clone();
        expected.issued_at = self.issued_at;
        expected.expires_at = self.expires_at;
        expected.snapshot.issued_at = self.snapshot.issued_at;
        expected.snapshot.expires_at = self.snapshot.expires_at;
        if *self != expected {
            return Err(StorageWorkError::InvalidSnapshot);
        }
        Ok(())
    }
}

/// Protected staging of one material under its exact queued metadata original.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCredentialCustodyStage {
    /// Fresh queued original that controls this staging invocation.
    pub request: StorageCredentialCustodyProbe,
    /// Exact purpose-local provider material; retained only by Worker custody.
    pub material: StorageCredentialMaterial,
    /// Exclusive independent custody expiry, bounded to twenty-four hours.
    pub material_not_after: i64,
}

impl StorageCredentialCustodyStage {
    /// Validates exact material fingerprint and its explicit retention horizon.
    ///
    /// # Errors
    /// Returns an error for stale metadata, mismatched material, or excessive life.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<(), StorageWorkError> {
        self.request.validate(deployment, now)?;
        if self.material_not_after <= now
            || self.material_not_after <= self.request.issued_at
            || self
                .material_not_after
                .saturating_sub(self.request.issued_at)
                > MAX_CREDENTIAL_CUSTODY_SECONDS
        {
            return Err(StorageWorkError::InvalidTime);
        }
        // Material validation borrows the exact staged reference; no secret
        // is returned to a Native probe or adoption consumer.
        let encoded = zeroize::Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| StorageWorkError::InvalidSnapshot)?,
        );
        let duplicate: Self =
            serde_json::from_slice(&encoded).map_err(|_| StorageWorkError::InvalidSnapshot)?;
        StorageBindingPublication {
            snapshot: duplicate.request.snapshot,
            materials: vec![duplicate.material],
        }
        .validate(deployment, now)
    }
}

/// Nonsecret acknowledgement of the exact protected staging control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCredentialCustodyStageReply {
    /// Complete metadata original; material is deliberately absent.
    pub request: StorageCredentialCustodyProbe,
    /// Exact independent custody horizon accepted by Worker.
    pub material_not_after: i64,
    /// SHA-256 of the complete canonical staged control.
    pub stage_body_sha256: String,
}

/// Actual provider probe result authenticated against a fresh complete original.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCredentialCustodyProbeReply {
    /// Exact fresh original, including current SQL head and task pins.
    pub request: StorageCredentialCustodyProbe,
    /// Actual bounded provider measurements, never operator readiness input.
    pub evidence: StorageCredentialProbeEvidence,
    /// Fresh authenticated readback time of the retained actual measurements.
    pub observed_at: i64,
}

/// Fresh metadata-only request to adopt a complete current SQL binding snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBindingAdoptionRequest {
    /// Protocol version, currently one.
    pub version: u8,
    /// Fresh 256-bit challenge nonce.
    pub nonce: String,
    /// Request issue time in Unix seconds.
    pub issued_at: i64,
    /// Exclusive request deadline, no more than thirty seconds after issue.
    pub expires_at: i64,
    /// Complete fresh SQL-built snapshot, without credential material.
    pub expected: StorageBindingSnapshot,
}

impl StorageBindingAdoptionRequest {
    /// Validates current binding identity and independent request freshness.
    ///
    /// # Errors
    /// Returns an error for malformed, expired, or foreign snapshot authority.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<(), StorageWorkError> {
        self.validate_context(deployment, Some(now))
    }

    /// Checks retained adoption metadata without asserting current eligibility.
    ///
    /// The complete snapshot, audience, nonce and intrinsic thirty-second request
    /// lifetime remain validated. This observation-only check authenticates no
    /// capture and grants no permission; execution uses [`Self::validate`].
    ///
    /// # Errors
    /// Returns an error for malformed identity, audience, snapshot, lifetime or size.
    pub fn validate_observation_shape(&self, deployment: &str) -> Result<(), StorageWorkError> {
        self.validate_context(deployment, None)?;
        encode(self)?;
        Ok(())
    }

    fn validate_context(&self, deployment: &str, now: Option<i64>) -> Result<(), StorageWorkError> {
        fresh_context(
            self.version,
            &self.nonce,
            self.issued_at,
            self.expires_at,
            now,
        )?;
        match now {
            Some(now) => self.expected.validate(deployment, now)?,
            None => self.expected.validate_observation_shape(deployment)?,
        }
        if now.is_some_and(|now| self.expected.issued_at > now || self.expected.expires_at <= now) {
            return Err(StorageWorkError::InvalidTime);
        }
        Ok(())
    }
}

/// Exact adopted snapshot authenticated to the original fresh Native challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBindingAdoptionReply {
    /// Complete fresh metadata request.
    pub request: StorageBindingAdoptionRequest,
    /// Exact durable snapshot acknowledged by Worker custody.
    pub acknowledged: StorageBindingSnapshot,
}

impl StorageBindingAdoptionReply {
    /// Correlates retained adoption metadata with an independently selected original.
    ///
    /// Only the acknowledged snapshot's issue and expiry times may differ from
    /// the original snapshot. Both intrinsic lifetimes remain bounded. This
    /// observation-only check proves neither authentication nor live adoption.
    ///
    /// # Errors
    /// Returns an error for malformed snapshots, changed originals or oversized encoding.
    pub fn validate_observation_for(
        &self,
        request: &StorageBindingAdoptionRequest,
    ) -> Result<(), StorageWorkError> {
        request.validate_observation_shape(&request.expected.deployment_id)?;
        self.validate_original(request, None)?;
        encode(self)?;
        Ok(())
    }

    fn validate_original(
        &self,
        request: &StorageBindingAdoptionRequest,
        now: Option<i64>,
    ) -> Result<(), StorageWorkError> {
        match now {
            Some(now) => self
                .acknowledged
                .validate(&request.expected.deployment_id, now)?,
            None => self
                .acknowledged
                .validate_observation_shape(&request.expected.deployment_id)?,
        }

        let mut expected = request.expected.clone();
        expected.issued_at = self.acknowledged.issued_at;
        expected.expires_at = self.acknowledged.expires_at;
        if self.request != *request
            || self.acknowledged != expected
            || now.is_some_and(|now| {
                self.acknowledged.issued_at > now || self.acknowledged.expires_at <= now
            })
        {
            return Err(StorageWorkError::InvalidSnapshot);
        }
        Ok(())
    }
}

/// Bounded canonical bytes and their purpose-separated MAC.
pub struct SignedStorageCustodyControl {
    /// Exact canonical request or reply bytes.
    pub body: Vec<u8>,
    /// MAC header over the exact purpose domain and body.
    pub signature: String,
}

fn fresh(
    version: u8,
    nonce: &str,
    issued: i64,
    expires: i64,
    now: i64,
) -> Result<(), StorageWorkError> {
    fresh_context(version, nonce, issued, expires, Some(now))
}

fn fresh_context(
    version: u8,
    nonce: &str,
    issued: i64,
    expires: i64,
    now: Option<i64>,
) -> Result<(), StorageWorkError> {
    if version != 1
        || !digest(nonce)
        || issued <= 0
        || now.is_some_and(|now| issued > now || now >= expires)
        || expires <= issued
        || expires.saturating_sub(issued) > 30
    {
        return Err(StorageWorkError::InvalidTime);
    }
    Ok(())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sign<T: Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    value: &T,
) -> Result<SignedStorageCustodyControl, StorageWorkError> {
    let body = encode(value)?;
    let signature = key.sign_body(&[domain, &body].concat())?;
    Ok(SignedStorageCustodyControl { body, signature })
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageWorkError> {
    let body = serde_json::to_vec(value).map_err(|_| StorageWorkError::InvalidSnapshot)?;
    if body.len() > MAX_BINDING_CUSTODY_BYTES {
        return Err(StorageWorkError::InvalidSnapshot);
    }
    Ok(body)
}

fn verify<T: DeserializeOwned + Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    signature: &str,
    body: &[u8],
) -> Result<T, StorageWorkError> {
    if body.len() > MAX_BINDING_CUSTODY_BYTES {
        return Err(StorageWorkError::InvalidSnapshot);
    }
    key.verify_body(signature, &[domain, body].concat())?;
    let value = serde_json::from_slice(body).map_err(|_| StorageWorkError::InvalidSnapshot)?;
    if serde_json::to_vec(&value).map_err(|_| StorageWorkError::InvalidSnapshot)? != body {
        return Err(StorageWorkError::InvalidSnapshot);
    }
    Ok(value)
}

macro_rules! requests {
    ($sign:ident, $verify:ident, $type:ty, $domain:ident) => {
        /// Signs the canonical control in its dedicated request domain.
        ///
        /// # Errors
        /// Returns an error for oversized encoding or invalid signing material.
        pub fn $sign(
            key: &StorageWorkKey,
            request: &$type,
        ) -> Result<SignedStorageCustodyControl, StorageWorkError> {
            sign(key, $domain, request)
        }

        /// Authenticates canonical bytes and validates fresh deployment authority.
        ///
        /// # Errors
        /// Returns an error for changed bytes, wrong purpose, invalid originals, or expiry.
        pub fn $verify(
            key: &StorageWorkKey,
            signature: &str,
            body: &[u8],
            deployment: &str,
            now: i64,
        ) -> Result<$type, StorageWorkError> {
            let request: $type = verify(key, $domain, signature, body)?;
            request.validate(deployment, now)?;
            Ok(request)
        }
    };
}

requests!(
    sign_storage_credential_custody_stage,
    verify_storage_credential_custody_stage,
    StorageCredentialCustodyStage,
    STAGE_REQUEST
);
requests!(
    sign_storage_credential_custody_probe,
    verify_storage_credential_custody_probe,
    StorageCredentialCustodyProbe,
    PROBE_REQUEST
);
requests!(
    sign_storage_binding_adoption,
    verify_storage_binding_adoption,
    StorageBindingAdoptionRequest,
    ADOPT_REQUEST
);

mod frozen;
pub use frozen::*;

/// Signs a nonsecret protected-stage acknowledgement.
///
/// # Errors
/// Returns an error for oversized encoding or invalid signing material.
pub fn sign_storage_credential_custody_stage_reply(
    key: &StorageWorkKey,
    reply: &StorageCredentialCustodyStageReply,
) -> Result<SignedStorageCustodyControl, StorageWorkError> {
    sign(key, STAGE_REPLY, reply)
}

/// Verifies the exact original stage without returning its secret material.
///
/// # Errors
/// Returns an error for another original, MAC, purpose, body, or expiry.
pub fn verify_storage_credential_custody_stage_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    request: &StorageCredentialCustodyStage,
    now: i64,
) -> Result<StorageCredentialCustodyStageReply, StorageWorkError> {
    request.validate(&request.request.snapshot.deployment_id, now)?;
    let reply: StorageCredentialCustodyStageReply = verify(key, STAGE_REPLY, signature, body)?;
    let original = serde_json::to_vec(request).map_err(|_| StorageWorkError::InvalidSnapshot)?;
    if reply.request != request.request
        || reply.material_not_after != request.material_not_after
        || reply.stage_body_sha256 != hex::encode(Sha256::digest(original))
    {
        return Err(StorageWorkError::InvalidSnapshot);
    }
    Ok(reply)
}

/// Signs actual provider measurements bound to their exact fresh probe.
///
/// # Errors
/// Returns an error for oversized encoding or invalid signing material.
pub fn sign_storage_credential_custody_probe_reply(
    key: &StorageWorkKey,
    reply: &StorageCredentialCustodyProbeReply,
) -> Result<SignedStorageCustodyControl, StorageWorkError> {
    sign(key, PROBE_REPLY, reply)
}

/// Verifies fresh measurements against the complete original probe challenge.
///
/// # Errors
/// Returns an error for another challenge, invalid MAC, or expired observations.
pub fn verify_storage_credential_custody_probe_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    request: &StorageCredentialCustodyProbe,
    now: i64,
) -> Result<StorageCredentialCustodyProbeReply, StorageWorkError> {
    request.validate(&request.snapshot.deployment_id, now)?;
    let reply: StorageCredentialCustodyProbeReply = verify(key, PROBE_REPLY, signature, body)?;
    if reply.request != *request
        || reply.observed_at < request.issued_at
        || reply.observed_at > now
        || reply.observed_at >= request.expires_at
    {
        return Err(StorageWorkError::InvalidSnapshot);
    }
    Ok(reply)
}

/// Signs acknowledgement of an exact durable metadata-only binding adoption.
///
/// # Errors
/// Returns an error for oversized encoding or invalid signing material.
pub fn sign_storage_binding_adoption_reply(
    key: &StorageWorkKey,
    reply: &StorageBindingAdoptionReply,
) -> Result<SignedStorageCustodyControl, StorageWorkError> {
    sign(key, ADOPT_REPLY, reply)
}

/// Verifies fresh custody acknowledgement of the exact current SQL snapshot.
///
/// # Errors
/// Returns an error for another snapshot, challenge, purpose, MAC, or expiry.
pub fn verify_storage_binding_adoption_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    request: &StorageBindingAdoptionRequest,
    now: i64,
) -> Result<StorageBindingAdoptionReply, StorageWorkError> {
    request.validate(&request.expected.deployment_id, now)?;
    let reply: StorageBindingAdoptionReply = verify(key, ADOPT_REPLY, signature, body)?;
    reply.validate_original(request, Some(now))?;
    Ok(reply)
}

#[cfg(test)]
mod tests;

mod deletion;
pub use deletion::*;
