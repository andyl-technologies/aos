//! Fresh guard-role observation of the reviewed emulator SDK anchor.
//!
//! ```text
//! request = installed issuer/profile + exact SDK anchor + nonce + <=30s
//! reply = exact request + conditional full-read identity/hash + observation
//! ```
//!
//! This read-only control cannot create an anchor or admit a business object.

use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    direct_upload::{direct_worker_emulated_script_id, valid_direct_digest},
    mirror_guard::MirrorGuardIssuer,
    storage_work::StorageWorkKey,
};

use super::{valid_identity, OciSdkObjectObservation};

/// Identifies a guard-authenticated, read-only OCI emulator anchor lookup.
pub const OCI_SDK_ANCHOR_PATH: &str = "/_internal/storage/oci-sdk-anchor";
/// Identifies the existing guard role's purpose-separated MAC header.
pub const OCI_SDK_ANCHOR_SIGNATURE_HEADER: &str = "x-aos-oci-sdk-anchor-signature";
/// Bounds the closed anchor control before decoding.
pub const MAX_OCI_SDK_ANCHOR_CONTROL_BYTES: usize = 8 * 1024;

/// Challenges the exact independently reviewed SDK anchor and installation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkAnchorLookup {
    /// Closed control version, currently one.
    pub version: u32,
    /// Exact protected deployment.
    pub deployment_id: String,
    /// OCI-only accepted profile, never a Direct or mirror profile.
    pub profile_digest: String,
    /// Exact compiled source and source-derived emulator script.
    pub issuer: MirrorGuardIssuer,
    /// Installed conservative UTC uncertainty.
    pub clock_uncertainty_seconds: u64,
    /// Exact reviewed conditional-read SDK identity and full SHA-256.
    pub anchor: OciSdkObjectObservation,
    /// Fresh 32-byte random challenge encoded as lowercase hexadecimal.
    pub nonce: String,
    /// Original UTC issue time.
    pub issued_at: u64,
    /// Original exclusive deadline, no more than thirty seconds later.
    pub expires_at: u64,
}

impl OciSdkAnchorLookup {
    /// Checks the closed read-only challenge and original freshness.
    ///
    /// # Errors
    /// Rejects foreign/malformed identities, nonisolated anchors or stale windows.
    pub fn validate(&self, deployment: &str, latest_now: u64) -> Result<()> {
        ensure!(
            self.version == 1
                && self.deployment_id == deployment
                && valid_identity(deployment)
                && valid_direct_digest(&self.profile_digest)
                && valid_direct_digest(&self.issuer.source_digest)
                && self.issuer.script_version
                    == direct_worker_emulated_script_id(&self.issuer.source_digest)?
                && (1..30).contains(&self.clock_uncertainty_seconds)
                && valid_direct_digest(&self.nonce)
                && self.issued_at <= latest_now
                && latest_now < self.expires_at
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|ttl| (1..=30).contains(&ttl)),
            "OCI SDK anchor challenge is invalid or stale"
        );
        self.anchor.validate()?;
        let parts: Vec<_> = self.anchor.object.key.split('/').collect();
        ensure!(
            self.anchor.object.size <= 1024
                && parts.len() == 3
                && parts[0] == ".aos-oci-sdk-qualification"
                && parts[1].len() == 32
                && parts[1]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                && parts[2] == "anchor",
            "OCI SDK anchor is outside its isolated bound"
        );
        bounded(self)?;
        Ok(())
    }
}

/// Retains the actual conditional full read correlated to a fresh challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkAnchorReply {
    /// Exact request including nonce, original cutoff and reviewed anchor.
    pub request: OciSdkAnchorLookup,
    /// Actual returned SDK version, ETag, size and full-byte SHA-256.
    pub observed: OciSdkObjectObservation,
    /// Conservative UTC time after the actual body reached EOF.
    pub observed_at: u64,
}

/// Contains canonical bounded control bytes and a guard-role signature.
pub struct SignedOciSdkAnchorControl {
    /// Exact canonical JSON bytes.
    pub body: Vec<u8>,
    /// Existing guard key's purpose-separated envelope commitment MAC.
    pub signature: String,
}

/// Signs a fresh read-only lookup under the independent guard role.
///
/// # Errors
/// Rejects invalid challenges or serialization failure.
pub fn sign_oci_sdk_anchor_lookup(
    key: &StorageWorkKey,
    lookup: &OciSdkAnchorLookup,
) -> Result<SignedOciSdkAnchorControl> {
    lookup.validate(&lookup.deployment_id, lookup.issued_at)?;
    sign(key, b"aos.hub.oci-sdk-anchor-request.v1\0", lookup)
}

/// Authenticates a fresh read-only lookup before SDK observation.
///
/// # Errors
/// Rejects invalid MAC/canonical form, foreign audiences or expired originals.
pub fn verify_oci_sdk_anchor_lookup(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    latest_now: u64,
) -> Result<OciSdkAnchorLookup> {
    let lookup: OciSdkAnchorLookup =
        verify(key, b"aos.hub.oci-sdk-anchor-request.v1\0", signature, body)?;
    lookup.validate(deployment, latest_now)?;
    Ok(lookup)
}

/// Signs an actual conditional full read after checking exact identity.
///
/// # Errors
/// Rejects mismatched versions/hash/size or an expired observation.
pub fn sign_oci_sdk_anchor_reply(
    key: &StorageWorkKey,
    reply: &OciSdkAnchorReply,
) -> Result<SignedOciSdkAnchorControl> {
    validate_reply(reply, &reply.request, reply.observed_at)?;
    sign(key, b"aos.hub.oci-sdk-anchor-reply.v1\0", reply)
}

/// Authenticates the exact current SDK anchor observation.
///
/// # Errors
/// Rejects invalid MAC/canonical form, changed request/identity or expiry.
pub fn verify_oci_sdk_anchor_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    lookup: &OciSdkAnchorLookup,
    latest_now: u64,
) -> Result<()> {
    let reply: OciSdkAnchorReply =
        verify(key, b"aos.hub.oci-sdk-anchor-reply.v1\0", signature, body)?;
    validate_reply(&reply, lookup, latest_now)
}

fn validate_reply(
    reply: &OciSdkAnchorReply,
    lookup: &OciSdkAnchorLookup,
    latest_now: u64,
) -> Result<()> {
    lookup.validate(&lookup.deployment_id, latest_now)?;
    reply.observed.validate()?;
    ensure!(
        reply.request == *lookup
            && reply.observed == lookup.anchor
            && lookup.issued_at <= reply.observed_at
            && reply.observed_at <= latest_now
            && reply.observed_at < lookup.expires_at,
        "OCI SDK anchor observation differs from its exact challenge"
    );
    bounded(reply)?;
    Ok(())
}

fn bounded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(value)?;
    ensure!(
        body.len() <= MAX_OCI_SDK_ANCHOR_CONTROL_BYTES,
        "OCI SDK anchor control exceeds bound"
    );
    Ok(body)
}

fn commitment(domain: &[u8], body: &[u8]) -> Vec<u8> {
    [domain, Sha256::digest(body).as_slice()].concat()
}

fn sign<T: Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    value: &T,
) -> Result<SignedOciSdkAnchorControl> {
    let body = bounded(value)?;
    let signature = key.sign_body(&commitment(domain, &body))?;
    Ok(SignedOciSdkAnchorControl { body, signature })
}

fn verify<T: Serialize + DeserializeOwned>(
    key: &StorageWorkKey,
    domain: &[u8],
    signature: &str,
    body: &[u8],
) -> Result<T> {
    ensure!(
        body.len() <= MAX_OCI_SDK_ANCHOR_CONTROL_BYTES,
        "OCI SDK anchor control exceeds bound"
    );
    key.verify_body(signature, &commitment(domain, body))?;
    let value: T = serde_json::from_slice(body)
        .map_err(|_| anyhow::anyhow!("OCI SDK anchor control is malformed"))?;
    ensure!(
        bounded(&value)? == body,
        "OCI SDK anchor control is not canonical"
    );
    Ok(value)
}
