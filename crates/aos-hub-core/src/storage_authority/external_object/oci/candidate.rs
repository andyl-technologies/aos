//! Test-only authorization of one reserved External OCI controlled fixture.
//!
//! This schema exists only with test support. It contains no measurements or
//! reviewer acceptance and cannot activate an ordinary producer. The fixture
//! uses actual SQL OCI originals, separately installed cohorts and independent
//! issuer/guard roles; this control restricts that execution to one reserved
//! placement under the exact compiled emulator identity and immutable cutoff.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{qualification::ExternalOciProfile, digest_string};
use crate::storage_work::StorageWorkKey;

const DOMAIN: &[u8] = b"aos.test-only-external-oci-candidate.v1\0";
/// Maximum serialized test-only control before decoding.
pub const MAX_OCI_CANDIDATE_BYTES: usize = 4096;

/// Pins one actual controlled fixture, never a hosted acceptance artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOciCandidate {
    /// Closed test-only schema version.
    pub version: u8,
    /// Actual installed controlled deployment.
    pub deployment_id: String,
    /// Exact source-built Worker source identity.
    pub source_digest: String,
    /// Exact source-derived emulator script identity.
    pub script_version: String,
    /// Full actually installed OCI profile commitment.
    pub profile_digest: String,
    /// One reserved fixture placement prefix; public paths deny its segment.
    pub placement_prefix: String,
    /// Immutable first authorization time, never renewed by configuration.
    pub issued_at: i64,
    /// Immutable fixture cutoff, at most fifteen minutes later.
    pub expires_at: i64,
}

impl ExternalOciCandidate {
    /// Checks actual profile, source and reserved placement without accepting
    /// provider capability or constructing an acceptance artifact.
    ///
    /// # Errors
    /// Refuses wrong identity, nonreserved placement, changed profile or cutoff.
    pub fn validate(&self, deployment: &str, source: &str, script: &str,
        profile: &ExternalOciProfile, placement: &str, latest: i64) -> Result<()> {
        profile.validate()?;
        ensure!(self.version == 1 && self.deployment_id == deployment
            && self.source_digest == source && digest_string(source)
            && self.script_version == script
            && script == crate::direct_upload::direct_worker_emulated_script_id(source)?
            && self.profile_digest == profile.digest()?
            && self.placement_prefix == placement
            && crate::storage_work::valid_relative_path(placement, false)
            && placement.starts_with(".aos-direct-qualification/")
            && placement.len() <= 512 && self.issued_at > 0
            && self.issued_at <= latest && latest < self.expires_at
            && self.expires_at.checked_sub(self.issued_at).is_some_and(|age| age > 0 && age <= 900),
            "controlled OCI fixture identity, namespace or immutable cutoff differs");
        ensure!(serde_json::to_vec(self)?.len() <= MAX_OCI_CANDIDATE_BYTES,
            "controlled OCI fixture control oversized");
        Ok(())
    }

    /// Authenticates exact canonical fixture bytes under its independent key.
    ///
    /// # Errors
    /// Refuses oversized or noncanonical control bytes and a bad purpose MAC.
    pub fn authenticate(key: &StorageWorkKey, signature: &str, bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_OCI_CANDIDATE_BYTES, "controlled OCI control oversized");
        key.verify_body(signature, &[DOMAIN, bytes].concat())?;
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(serde_json::to_vec(&value)? == bytes, "controlled OCI control noncanonical");
        Ok(value)
    }

    /// Signs only this test-only original-bound control, never evidence.
    ///
    /// # Errors
    /// Refuses oversized controls or signing failure.
    pub fn sign(&self, key: &StorageWorkKey) -> Result<(Vec<u8>, String)> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= MAX_OCI_CANDIDATE_BYTES, "controlled OCI control oversized");
        let signature = key.sign_body(&[DOMAIN, &bytes].concat())?;
        Ok((bytes, signature))
    }
}
