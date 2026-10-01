//! Fresh independent storage-side OCI parsing under an exact guarded key.
//!
//! ```text
//! request = issuer + exact key/descriptor/admission + nonce + deadline
//! reply   = exact request + observed incarnation + parsed metadata
//! ```
//!
//! The existing guard role authenticates a purpose-separated SHA-256 commitment
//! of each bounded canonical envelope. This accommodates the existing 4 MiB OCI
//! metadata limit without enlarging generic storage-work plan limits.

use anyhow::{ensure, Result};
use aos_oci_types::Descriptor;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{OciDocumentProjection, MAX_OCI_PROJECTION_BYTES};
use crate::{
    hybrid_ingress::HybridOciManifestAdmission,
    mirror_guard::MirrorGuardIssuer,
    storage_work::{StorageObjectIdentity, StorageWorkKey},
};

/// Identifies the independent OCI metadata readback route.
pub const OCI_PROJECTION_PATH: &str = "/_internal/storage/oci-document-projection";
/// Authenticates this control under the independently installed guard role.
pub const OCI_PROJECTION_SIGNATURE_HEADER: &str = "x-aos-oci-projection-signature";
/// Bounds the small lookup before any document is read.
pub const MAX_OCI_PROJECTION_LOOKUP_BYTES: usize = 16 * 1024;

/// Challenges one exact stored OCI document without requesting its body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciProjectionLookup {
    /// Closed wire version.
    pub version: u32,
    /// Exact Native and Worker deployment.
    pub deployment_id: String,
    /// Exact independently accepted provider/runtime/policy commitment.
    pub protected_profile_digest: String,
    /// Independently selected implementation identity.
    pub issuer: MirrorGuardIssuer,
    /// Independently selected conservative UTC uncertainty.
    pub clock_uncertainty_seconds: u64,
    /// Full guarded provider key, including the selected placement prefix.
    pub key: String,
    /// Expected exact original bytes and document kind.
    pub descriptor: Descriptor,
    /// Original Native reservation for a root manifest; configs have no upload.
    pub admission: Option<HybridOciManifestAdmission>,
    /// Fresh random 32-byte challenge encoded in lowercase hexadecimal.
    pub nonce: String,
    /// Original issue time in UTC seconds.
    pub issued_at: u64,
    /// Original exclusive deadline, no more than 30 seconds after issue.
    pub expires_at: u64,
}

impl OciProjectionLookup {
    /// Validates the exact closed lookup and conservative freshness.
    ///
    /// # Errors
    /// Returns an error for malformed identity, unsupported media, an oversized
    /// original, mismatched staging address or a foreign/stale challenge.
    pub fn validate(&self, deployment: &str, latest_now: u64) -> Result<()> {
        ensure!(
            self.version == 1
                && self.deployment_id == deployment
                && !deployment.is_empty()
                && deployment.len() <= 256
                && !deployment.chars().any(char::is_control)
                && crate::direct_upload::valid_direct_digest(&self.protected_profile_digest)
                && crate::direct_upload::valid_direct_digest(&self.issuer.source_digest)
                && !self.issuer.script_version.is_empty()
                && self.issuer.script_version.len() <= 256
                && !self.issuer.script_version.chars().any(char::is_control)
                && (1..30).contains(&self.clock_uncertainty_seconds)
                && crate::direct_upload::valid_direct_digest(&self.nonce)
                && self.issued_at <= latest_now
                && latest_now < self.expires_at
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|ttl| (1..=30).contains(&ttl)),
            "OCI projection challenge is invalid or stale"
        );
        ensure!(
            !self.key.is_empty()
                && self.key.len() <= 2048
                && !self.key.starts_with('/')
                && !self.key.chars().any(char::is_control)
                && self
                    .key
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."),
            "OCI projection key is invalid"
        );
        self.descriptor.validate()?;
        ensure!(
            self.descriptor.size > 0
                && self.descriptor.size <= aos_oci_types::limits::MAX_JSON_BYTES as u64
                && (self.descriptor.media_type.is_image_manifest()
                    || self.descriptor.media_type.is_image_index()
                    || self.descriptor.media_type.is_image_config()),
            "OCI projection descriptor is invalid"
        );
        if let Some(admission) = &self.admission {
            ensure!(
                (crate::keymap::r2_key(&admission.placement_prefix, &admission.staging_object_key)
                    == self.key
                    || crate::keymap::r2_key(
                        &admission.placement_prefix,
                        &crate::db::oci_blob_object_key(self.descriptor.digest)
                    ) == self.key)
                    && admission.byte_size == self.descriptor.size
                    && admission.sha256 == self.descriptor.digest.encoded()
                    && admission.upload_id.len() == 32
                    && admission
                        .upload_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    && crate::direct_upload::valid_direct_digest(&admission.original_digest),
                "OCI projection changed the retained staging original"
            );
        }
        bounded(self, MAX_OCI_PROJECTION_LOOKUP_BYTES)?;
        Ok(())
    }
}

/// Carries the actual conditional read and semantic parser result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciProjectionReply {
    /// Exact original challenge, including admission, issuer and nonce.
    pub request: OciProjectionLookup,
    /// Incarnation observed on the same immutable read as the parsed bytes.
    pub object: StorageObjectIdentity,
    /// Metadata parsed from actual stored bytes after exact SHA/size validation.
    pub projection: OciDocumentProjection,
    /// Conservative completion time after the read and parser.
    pub observed_at: u64,
}

/// Holds an independently authenticated exact OCI readback.
#[derive(Clone, Debug)]
pub struct VerifiedOciProjection(OciProjectionReply);

impl VerifiedOciProjection {
    /// Rechecks the exact byte descriptor and original guard deadline.
    ///
    /// # Errors
    /// Returns an error for changed descriptor identity, a clock conversion or
    /// an expired proof. Reuse never extends the original challenge window.
    pub fn check(&self, descriptor: &Descriptor, raw_now: i64) -> Result<&OciDocumentProjection> {
        ensure!(
            self.0.request.descriptor.media_type == descriptor.media_type
                && self.0.request.descriptor.digest == descriptor.digest
                && self.0.request.descriptor.size == descriptor.size,
            "OCI readback differs from the authoritative descriptor"
        );
        let latest_now = u64::try_from(raw_now)?
            .checked_add(self.0.request.clock_uncertainty_seconds)
            .ok_or_else(|| anyhow::anyhow!("OCI projection clock overflow"))?;
        validate_reply(&self.0, &self.0.request, latest_now)?;
        Ok(&self.0.projection)
    }

    /// Returns the raw-clock deadline clipped by the original clock policy.
    #[must_use]
    pub fn deadline(&self) -> i64 {
        i64::try_from(
            self.0
                .request
                .expires_at
                .saturating_sub(self.0.request.clock_uncertainty_seconds),
        )
        .unwrap_or(i64::MIN)
    }

    /// Returns the actual conditional-read incarnation bound to this proof.
    #[must_use]
    pub fn object(&self) -> &StorageObjectIdentity {
        &self.0.object
    }

    /// Returns the exact guarded storage key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.0.request.key
    }

    /// Returns the exact root upload original bound into the challenge.
    #[must_use]
    pub fn admission(&self) -> Option<&HybridOciManifestAdmission> {
        self.0.request.admission.as_ref()
    }

    /// Returns the independently parsed document metadata.
    #[must_use]
    pub fn into_projection(self) -> OciDocumentProjection {
        self.0.projection
    }
}

/// Contains exact canonical control bytes and their guard-role signature.
pub struct SignedOciProjectionControl {
    /// Canonical bounded JSON body.
    pub body: Vec<u8>,
    /// Purpose-separated authentication of the whole envelope commitment.
    pub signature: String,
}

/// Signs an original fresh lookup under the existing independent guard key.
///
/// # Errors
/// Returns an error for invalid lookup metadata or serialization failure.
pub fn sign_oci_projection_lookup(
    key: &StorageWorkKey,
    request: &OciProjectionLookup,
) -> Result<SignedOciProjectionControl> {
    request.validate(&request.deployment_id, request.issued_at)?;
    sign(
        key,
        b"aos.hub.oci-projection-request.v1\0",
        request,
        MAX_OCI_PROJECTION_LOOKUP_BYTES,
    )
}

/// Authenticates a fresh lookup before storage-side work.
///
/// # Errors
/// Returns an error for invalid MAC, canonical shape, audience or freshness.
pub fn verify_oci_projection_lookup(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    latest_now: u64,
) -> Result<OciProjectionLookup> {
    let request: OciProjectionLookup = verify(
        key,
        b"aos.hub.oci-projection-request.v1\0",
        signature,
        body,
        MAX_OCI_PROJECTION_LOOKUP_BYTES,
    )?;
    request.validate(deployment, latest_now)?;
    Ok(request)
}

/// Signs metadata derived from the actual stored original under the guard gate.
///
/// # Errors
/// Returns an error for mismatched identity, projection or observation window.
pub fn sign_oci_projection_reply(
    key: &StorageWorkKey,
    reply: &OciProjectionReply,
) -> Result<SignedOciProjectionControl> {
    validate_reply(reply, &reply.request, reply.observed_at)?;
    sign(
        key,
        b"aos.hub.oci-projection-reply.v1\0",
        reply,
        MAX_OCI_PROJECTION_BYTES,
    )
}

/// Authenticates the complete exact readback before exposing its metadata.
///
/// # Errors
/// Returns an error for changed challenge/body/incarnation, malformed metadata,
/// a foreign guard role or an expired observation.
pub fn verify_oci_projection_reply(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    original: &OciProjectionLookup,
    latest_now: u64,
) -> Result<VerifiedOciProjection> {
    let reply = verify(
        key,
        b"aos.hub.oci-projection-reply.v1\0",
        signature,
        body,
        MAX_OCI_PROJECTION_BYTES,
    )?;
    validate_reply(&reply, original, latest_now)?;
    Ok(VerifiedOciProjection(reply))
}

fn validate_reply(
    reply: &OciProjectionReply,
    original: &OciProjectionLookup,
    latest_now: u64,
) -> Result<()> {
    original.validate(&original.deployment_id, latest_now)?;
    ensure!(
        reply.request == *original
            && reply.object.key == original.key
            && reply.object.size == original.descriptor.size
            && reply
                .object
                .provider_version
                .as_deref()
                .is_some_and(crate::storage_work::valid_provider_version)
            && crate::surface_write::strong_if_match_etag(&reply.object.etag)? == reply.object.etag
            && original.issued_at <= reply.observed_at
            && reply.observed_at <= latest_now
            && reply.observed_at < original.expires_at,
        "OCI projection reply differs from its exact original"
    );
    reply.projection.validate(original.descriptor.media_type)?;
    bounded(reply, MAX_OCI_PROJECTION_BYTES)?;
    Ok(())
}

fn bounded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(value)?;
    ensure!(
        body.len() <= limit,
        "OCI projection control exceeds its explicit bound"
    );
    Ok(body)
}

fn commitment(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut value = domain.to_vec();
    value.extend_from_slice(&Sha256::digest(body));
    value
}

fn sign<T: Serialize>(
    key: &StorageWorkKey,
    domain: &[u8],
    value: &T,
    limit: usize,
) -> Result<SignedOciProjectionControl> {
    let body = bounded(value, limit)?;
    let signature = key.sign_body(&commitment(domain, &body))?;
    Ok(SignedOciProjectionControl { body, signature })
}

fn verify<T: Serialize + DeserializeOwned>(
    key: &StorageWorkKey,
    domain: &[u8],
    signature: &str,
    body: &[u8],
    limit: usize,
) -> Result<T> {
    ensure!(
        body.len() <= limit,
        "OCI projection control exceeds its explicit bound"
    );
    key.verify_body(signature, &commitment(domain, body))?;
    let value: T = serde_json::from_slice(body)?;
    ensure!(
        bounded(&value, limit)? == body,
        "OCI projection control is not canonical"
    );
    Ok(value)
}
