//! Complete offline verification over captured release bytes.
//!
//! Filesystem capture is intentionally outside this crate. Native and Worker
//! callers must first capture a no-follow, regular-file-only tree, then pass
//! the immutable bytes here so all runtimes share semantic verification.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use serde::Serialize;

use crate::artifact::BundlePath;
use crate::canonical;
use crate::digest::Sha256Digest;
use crate::manifest::{MANIFEST_DOMAIN, MANIFEST_ENVELOPE_V1, ManifestEnvelopeV1};
use crate::plan::ReleasePlan;
use crate::signing::{SignerRole, TrustedEd25519Key, verify_ed25519_response};
use crate::state::{JournalEntry, JournalSummary};

/// Exact captured regular file supplied to the pure verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedFile {
    /// Normalized path below the bundle root.
    pub path: BundlePath,
    /// Exact captured byte length.
    pub size_bytes: u64,
    /// SHA-256 computed while streaming the captured regular file.
    pub sha256: Sha256Digest,
}

/// Successful verification counts for stable machine output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSummary {
    /// Stable verifier result schema.
    pub schema_version: &'static str,
    /// Immutable release identity.
    pub release_id: String,
    /// Exact calendar version.
    pub version: String,
    /// Frozen plan digest.
    pub plan_digest: Sha256Digest,
    /// Final manifest payload digest.
    pub manifest_digest: Sha256Digest,
    /// Number of exact payload files verified.
    pub artifact_count: usize,
    /// Number of public evidence records verified.
    pub evidence_count: usize,
    /// Number of distinct manifest signatures verified.
    pub signatures_verified: usize,
}

#[derive(Serialize)]
struct BundleDigestInput<'a> {
    manifest_envelope_digest: Sha256Digest,
    files: Vec<BundleDigestFile<'a>>,
}

#[derive(Serialize)]
struct BundleDigestFile<'a> {
    path: &'a str,
    size_bytes: u64,
    sha256: Sha256Digest,
}

/// Computes the identity of exact manifest-envelope and captured payload bytes.
///
/// # Errors
///
/// Returns an error when captured paths are duplicated or the closed digest
/// input cannot be represented as canonical JSON.
pub fn bundle_digest(
    manifest_envelope_bytes: &[u8],
    files: &[CapturedFile],
) -> Result<Sha256Digest> {
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|file| file.path.as_str());
    if ordered.windows(2).any(|pair| pair[0].path == pair[1].path) {
        bail!("captured bundle contains a duplicate path");
    }
    let input = BundleDigestInput {
        manifest_envelope_digest: Sha256Digest::of_bytes(manifest_envelope_bytes),
        files: ordered
            .into_iter()
            .map(|file| BundleDigestFile {
                path: file.path.as_str(),
                size_bytes: file.size_bytes,
                sha256: file.sha256,
            })
            .collect(),
    };
    Sha256Digest::of_canonical("aos.release.bundle/v1", &input)
}

/// Verifies canonical plan/envelope bytes, signatures, schema semantics, and
/// exact captured bundle closure.
///
/// `files` contains every regular file below the bundle root except the root
/// `release-manifest.json` envelope itself. It therefore includes the exact
/// `release-plan.json` bytes.
///
/// # Errors
///
/// Returns an error for noncanonical or ambiguous JSON, schema or policy
/// failure, identity drift, invalid/insufficient signatures, duplicate or
/// untrusted signer keys, missing/extra/aliased paths, or content mismatch.
pub fn verify_release(
    plan_bytes: &[u8],
    manifest_envelope_bytes: &[u8],
    files: &[CapturedFile],
    trusted_keys: &[TrustedEd25519Key],
) -> Result<VerificationSummary> {
    canonical::require_canonical(plan_bytes, "release plan")?;
    let plan: ReleasePlan = canonical::from_slice(plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(plan_bytes);

    canonical::require_canonical(manifest_envelope_bytes, "release manifest envelope")?;
    let envelope: ManifestEnvelopeV1 =
        canonical::from_slice(manifest_envelope_bytes, "release manifest envelope")?;
    if envelope.schema_version != MANIFEST_ENVELOPE_V1 {
        bail!("unsupported release manifest envelope schema");
    }
    let manifest_digest = Sha256Digest::of_canonical(MANIFEST_DOMAIN, &envelope.payload)?;
    if envelope.payload_digest != manifest_digest || envelope.payload.plan_digest != plan_digest {
        bail!("release manifest or plan digest mismatch");
    }
    envelope.payload.validate(&plan)?;
    let signatures_verified = verify_manifest_signatures(&plan, &envelope, trusted_keys)?;
    verify_file_closure(&envelope, files)?;

    Ok(VerificationSummary {
        schema_version: "aos.release.verification-result/v1",
        release_id: plan.release_id,
        version: plan.version,
        plan_digest,
        manifest_digest,
        artifact_count: envelope.payload.artifacts.len(),
        evidence_count: envelope.payload.evidence.len(),
        signatures_verified,
    })
}

/// Verifies an append-only journal captured by the caller and replays its state.
///
/// The journal replays one global lifecycle plus one lifecycle per destination
/// (see [`crate::state`]).
///
/// # Errors
///
/// Returns an error for an empty journal, an invalid entry, a discontinuous
/// sequence, a digest or plan mismatch, a prior state that differs from the
/// replayed state, an illegal transition, a production destination published
/// before any staging destination, or manifest identity drift.
pub fn verify_journal(entries: &[JournalEntry]) -> Result<JournalSummary> {
    let first = entries
        .first()
        .ok_or_else(|| anyhow::anyhow!("release journal is empty"))?;
    first.validate()?;
    let plan_digest = first.plan_digest;
    let mut summary = JournalSummary::start(first);
    let mut expected_manifest = first.manifest_digest;
    let mut previous_digest = first.digest()?;

    for (index, entry) in entries.iter().enumerate().skip(1) {
        entry.validate()?;
        let expected_sequence = u64::try_from(index)
            .context("journal entry index exceeds u64")?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("journal sequence overflow"))?;
        if entry.sequence != expected_sequence
            || entry.plan_digest != plan_digest
            || entry.previous_entry_digest != Some(previous_digest)
            || entry.prior_state != Some(summary.expected_prior(entry))
        {
            bail!(
                "release journal continuity mismatch at sequence {}",
                entry.sequence
            );
        }
        summary.apply(entry)?;
        if let Some(manifest) = entry.manifest_digest {
            if expected_manifest.is_some_and(|expected| expected != manifest) {
                bail!("release journal manifest identity changed");
            }
            expected_manifest = Some(manifest);
        }
        previous_digest = entry.digest()?;
    }
    Ok(summary)
}

/// Verifies a journal and requires every destination entry to be planned.
///
/// In addition to [`verify_journal`], every recorded destination must exist
/// in `plan`, and every first publication must have followed the `after`
/// surface roles of its contract cell.
///
/// # Errors
///
/// Returns an error for any [`verify_journal`] failure, a journal whose plan
/// digest differs from `plan`, or an unplanned or out-of-order destination.
pub fn verify_journal_for_plan(
    plan: &ReleasePlan,
    entries: &[JournalEntry],
) -> Result<JournalSummary> {
    let summary = verify_journal(entries)?;
    let Some((first, rest)) = entries.split_first() else {
        bail!("release journal is empty");
    };
    if first.plan_digest != Sha256Digest::of_bytes(canonical::to_vec(plan)?) {
        bail!("release journal names a different plan");
    }

    // Replay publications in order so each `after` check sees only the
    // destinations published before it.
    let mut replay = JournalSummary::start(first);
    for entry in rest {
        if let Some(destination) = &entry.destination
            && entry.new_state == crate::state::ReleaseState::Published
        {
            replay.can_publish(plan, destination)?;
        }
        replay.apply(entry)?;
    }
    Ok(summary)
}

fn verify_manifest_signatures(
    plan: &ReleasePlan,
    envelope: &ManifestEnvelopeV1,
    trusted_keys: &[TrustedEd25519Key],
) -> Result<usize> {
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
        .ok_or_else(|| anyhow::anyhow!("release evidence signer policy is absent"))?;
    let trusted: BTreeMap<_, _> = trusted_keys
        .iter()
        .map(|key| (key.key_id.as_str(), key))
        .collect();
    if trusted.len() != trusted_keys.len() {
        bail!("trusted key input contains duplicate key ids");
    }

    let mut verified = BTreeSet::new();
    for signature in &envelope.signatures {
        let request = &signature.request;
        if request.role != SignerRole::ReleaseEvidence
            || request.registry != plan.registry
            || request.release_id != plan.release_id
            || request.plan_digest != envelope.payload.plan_digest
            || request.manifest_digest != Some(envelope.payload_digest)
            || request.payload_digest != envelope.payload_digest
            || request.provider_revision != requirement.provider_revision
            || !requirement.key_ids.contains(&request.key_id)
        {
            bail!("manifest signature request is outside the frozen signer policy");
        }
        if !verified.insert(request.key_id.as_str()) {
            bail!("manifest envelope repeats a signer key");
        }
        let key = trusted
            .get(request.key_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("trusted key absent for {}", request.key_id))?;
        verify_ed25519_response(request, &signature.response, key)?;
    }
    if verified.len() < usize::from(requirement.threshold) {
        bail!("manifest signature threshold is not satisfied");
    }
    Ok(verified.len())
}

fn verify_file_closure(envelope: &ManifestEnvelopeV1, files: &[CapturedFile]) -> Result<()> {
    let expected: BTreeMap<_, _> = envelope
        .payload
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect();
    let mut seen = BTreeSet::new();
    for file in files {
        if !seen.insert(file.path.as_str()) {
            bail!("captured bundle contains duplicate path {}", file.path);
        }
        let artifact = expected
            .get(file.path.as_str())
            .ok_or_else(|| anyhow::anyhow!("extra bundle file {}", file.path))?;
        if artifact.size_bytes != file.size_bytes || artifact.sha256 != file.sha256 {
            bail!("bundle file identity mismatch: {}", file.path);
        }
    }
    if seen.len() != expected.len() {
        let missing = expected
            .keys()
            .find(|path| !seen.contains(**path))
            .copied()
            .unwrap_or("unknown");
        bail!("bundle file is missing: {missing}");
    }
    Ok(())
}

#[cfg(test)]
#[path = "verify_tests.rs"]
pub(crate) mod tests;
