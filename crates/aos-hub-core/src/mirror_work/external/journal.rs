//! Positive-only mirror transitions beneath one permanent External key owner.
//!
//! The adapter commits this session and its lease floor atomically before each
//! effect. Pending never clears on expiry, provider HEAD, error or caller drop.
//! Positive completion precedes content verification; a failed verification
//! retains the actual physical receipt and cannot cause another Complete.
//!
//! ```text
//! session = {original, destination, configuration, acceptance, progress,
//!            pending, closed, acknowledged_commit}
//! receipt = {original_digest, pending, positive}
//! ```

use anyhow::{Context as _, Result, ensure};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{
    direct_upload::valid_direct_digest,
    storage_authority::{StorageGuardStamp, control::StorageAuthorityObjectScope},
    storage_work::StorageObjectIdentity,
};

use super::{MirrorExternalClosure, MirrorStageRetention};
use crate::mirror_work::{MirrorOriginal, MirrorPart, MirrorProgress, MirrorVerifiedObject, digest};

/// Retains one exact signed mirror artifact and its original exclusive cutoff.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorExternalAcceptance {
    /// Commitment to the actual verified mirror artifact bytes.
    pub artifact_digest: String,
    /// Original artifact observation timestamp.
    pub issued_at: u64,
    /// Exclusive cutoff, clipped to the independently accepted prerequisite.
    pub expires_at: u64,
}

/// Identifies one never-reissued provider mutation from retained progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MirrorExternalEffect {
    /// Creates the original nonempty multipart upload.
    Create,
    /// Writes an actually empty representation without a fictitious upload ID.
    EmptyPut,
    /// Uploads the exact next part, with its source SHA and MD5 transport checksum.
    Part {
        /// Actual bytes read and hashed before dispatch; ETag is empty until receipt.
        part: MirrorPart,
        /// Base64 encoded MD5 of those exact bytes, required in the signed PUT.
        checksum_md5: String,
    },
    /// Closes the exact retained upload and ordered positive part manifest.
    Complete {
        /// Actual Create acknowledgement, not a recomputed provider identity.
        upload_id: String,
        /// Commitment to the complete ordered positive part records.
        parts_digest: String,
    },
}

/// Retains the original effect and dispatch nonce before a provider invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorExternalPending {
    /// Exact never-reissued provider action.
    pub effect: MirrorExternalEffect,
    /// Commitment to original, destination and exact action.
    pub effect_digest: String,
    /// Fresh randomness minted only before the first dispatch.
    pub dispatch_nonce: String,
}

/// Retains only an observed successful provider response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MirrorExternalPositive {
    /// Retains the actual multipart Create acknowledgement.
    Created {
        /// Actual provider upload ID.
        upload_id: String,
    },
    /// Retains the actual signed part's strong ETag.
    Part {
        /// Actual successful part ETag.
        etag: String,
    },
    /// Retains actual final provider identity beneath a separately issued stamp.
    Completed {
        /// Physical object returned by the successful Complete or empty PUT.
        object: StorageObjectIdentity,
        /// Permanent key incarnation selected from the prior guard counter.
        guard_stamp: StorageGuardStamp,
    },
}

/// Couples an exact pending effect to one positive response without recursion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorExternalReceipt {
    /// Commitment to the complete original selected before the first effect.
    pub original_digest: String,
    /// Exact retained pending record.
    pub pending: MirrorExternalPending,
    /// Actual positive provider observation.
    pub positive: MirrorExternalPositive,
}

/// Retains one full immutable original, its unknown action and positive progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorExternalSession {
    /// Full independently selected SQL and physical original.
    pub original: MirrorOriginal,
    /// Selects the stage or final physical key; never changes after admission.
    pub destination: bool,
    /// Commitment to the independently installed mirror transport domain.
    pub configuration: String,
    /// First accepted artifact window; loading a new artifact cannot renew it.
    pub acceptance: MirrorExternalAcceptance,
    /// Bounded positive source, part and final verification records.
    pub progress: MirrorProgress,
    /// Permanently retained unknown action, cleared only by its exact receipt.
    pub pending: Option<MirrorExternalPending>,
    /// Actual provider completion, retained before final content verification.
    pub closed: Option<MirrorExternalClosure>,
    /// Exact Native commit acknowledged before logical ownership is released.
    pub acknowledged_commit: Option<String>,
}

impl MirrorExternalSession {
    /// Declares one original under its exact independently observed prerequisite.
    ///
    /// # Errors
    /// Refuses malformed pins, a managed original or an unverified source seed.
    pub fn declare(
        original: MirrorOriginal,
        destination: bool,
        configuration: String,
        acceptance: MirrorExternalAcceptance,
        source: Option<MirrorProgress>,
    ) -> Result<Self> {
        let progress = match (destination, source) {
            (false, None) => MirrorProgress {
                original_digest: digest(&original)?,
                ..Default::default()
            },
            (true, Some(progress)) => {
                ensure!(
                    progress.verified.is_some()
                        && progress.destination_upload_id.is_none()
                        && progress.destination.is_none(),
                    "mirror promotion lacks its exact verified source"
                );
                progress
            }
            _ => anyhow::bail!("mirror session source seed differs from physical role"),
        };
        let session = Self {
            original,
            destination,
            configuration,
            acceptance,
            progress,
            pending: None,
            closed: None,
            acknowledged_commit: None,
        };
        session.validate()?;
        Ok(session)
    }

    /// Checks retained state without interpreting expiry as provider settlement.
    ///
    /// # Errors
    /// Refuses changed originals, malformed pending records or forked receipts.
    pub fn validate(&self) -> Result<()> {
        self.original.validate()?;
        let selected = self
            .original
            .external_destination
            .as_ref()
            .context("External mirror session has a managed original")?;
        ensure!(
            valid_direct_digest(&self.configuration)
                && valid_direct_digest(&self.acceptance.artifact_digest)
                && self.acceptance.issued_at < self.acceptance.expires_at
                && self.acceptance.expires_at <= selected.expires_at,
            "mirror retained acceptance or configuration differs"
        );
        self.progress.validate(&self.original)?;
        if let Some(pending) = &self.pending {
            ensure!(
                pending.effect_digest == self.effect_digest(&pending.effect)?
                    && valid_direct_digest(&pending.dispatch_nonce)
                    && self.closed.is_none()
                    && self.acknowledged_commit.is_none(),
                "mirror pending effect changed its original"
            );
            self.validate_effect(&pending.effect)?;
        }
        if let Some(closed) = &self.closed {
            closed.validate_for(&self.original, self.destination)?;
            if !self.destination {
                ensure!(
                    self.progress.stage_closure.as_ref() == Some(closed),
                    "mirror stage lost its actual completion receipt"
                );
            }
        }
        if let Some(commit) = &self.acknowledged_commit {
            ensure!(
                self.pending.is_none() && self.progress.commit_digest(&self.original)? == *commit,
                "mirror acknowledgement differs from its terminal original"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 256 * 1024,
            "mirror physical session exceeds its closed control bound"
        );
        Ok(())
    }

    /// Retains a first provider intent; an unknown original never issues a retry.
    ///
    /// # Errors
    /// Refuses pending, closed or acknowledged state and changed part geometry.
    pub fn begin(&self, effect: MirrorExternalEffect, nonce: String) -> Result<Self> {
        self.validate()?;
        ensure!(
            self.pending.is_none()
                && self.closed.is_none()
                && self.acknowledged_commit.is_none()
                && valid_direct_digest(&nonce),
            "mirror physical effect remains unknown or terminal"
        );
        self.validate_effect(&effect)?;
        let mut next = self.clone();
        next.pending = Some(MirrorExternalPending {
            effect_digest: self.effect_digest(&effect)?,
            effect,
            dispatch_nonce: nonce,
        });
        next.validate()?;
        Ok(next)
    }

    /// Advances only an exact positive provider response to the retained intent.
    ///
    /// # Errors
    /// Refuses absent pending state, another response, key, size or receipt.
    pub fn acknowledge(&self, receipt: &MirrorExternalReceipt) -> Result<Self> {
        self.validate()?;
        ensure!(
            receipt.original_digest == digest(&self.original)?
                && self.pending.as_ref() == Some(&receipt.pending),
            "mirror positive receipt differs from pending"
        );
        let mut next = self.clone();
        match (&receipt.pending.effect, &receipt.positive) {
            (MirrorExternalEffect::Create, MirrorExternalPositive::Created { upload_id }) => {
                ensure!(
                    !upload_id.is_empty()
                        && upload_id.len() <= 2048
                        && !upload_id.chars().any(char::is_control),
                    "mirror provider upload ID invalid"
                );
                if self.destination {
                    next.progress.destination_upload_id = Some(upload_id.clone());
                } else {
                    next.progress.stage_upload_id = Some(upload_id.clone());
                }
            }
            (MirrorExternalEffect::Part { part, .. }, MirrorExternalPositive::Part { etag }) => {
                let mut part = part.clone();
                crate::surface_write::strong_if_match_etag(etag)?;
                part.etag = etag.clone();
                if self.destination {
                    next.progress.destination_parts.push(part);
                } else {
                    next.progress.stage_parts.push(part);
                }
            }
            (
                MirrorExternalEffect::Complete { .. } | MirrorExternalEffect::EmptyPut,
                MirrorExternalPositive::Completed {
                    object,
                    guard_stamp,
                },
            ) => {
                // The receipt digest excludes the derived closure, avoiding a
                // self-referential progress commitment or manufactured version.
                let authority = &self
                    .original
                    .external_destination
                    .as_ref()
                    .context("mirror External prerequisite absent")?
                    .protected_profile
                    .profile
                    .write_cohort
                    .authority;
                let closed = MirrorExternalClosure {
                    scope: StorageAuthorityObjectScope {
                        guard_namespace_id: authority.guard_namespace_id.clone(),
                        physical_authority_id: authority.authority_id.clone(),
                        full_key: self.key(),
                    },
                    guard_stamp: guard_stamp.clone(),
                    object: object.clone(),
                    receipt_digest: digest(receipt)?,
                };
                closed.validate_for(&self.original, self.destination)?;
                if !self.destination {
                    next.progress.stage_object = Some(object.clone());
                    next.progress.stage_closure = Some(closed.clone());
                    next.progress.stage_retention =
                        Some(MirrorStageRetention::RetainedForQualifiedCleanup);
                }
                next.closed = Some(closed);
            }
            _ => anyhow::bail!("mirror provider acknowledgement changed action"),
        }
        next.pending = None;
        next.validate()?;
        Ok(next)
    }

    /// Retains actual full-stream verification without dispatching a mutation.
    ///
    /// # Errors
    /// Refuses another closed identity or a changed encoded or plain proof.
    pub fn verified(&self, verified: MirrorVerifiedObject) -> Result<Self> {
        self.validate()?;
        ensure!(
            self.pending.is_none()
                && self
                    .closed
                    .as_ref()
                    .is_some_and(|closed| closed.object == verified.object),
            "mirror verification differs from retained positive completion"
        );
        let mut next = self.clone();
        if self.destination {
            let source = self
                .progress
                .verified
                .as_ref()
                .context("mirror source verification absent")?;
            ensure!(
                source.sha256 == verified.sha256
                    && source.nar_sha256 == verified.nar_sha256
                    && source.nar_size == verified.nar_size,
                "mirror final bytes differ from verified source"
            );
            next.progress.destination = Some(verified);
            next.progress.destination_closure = self.closed.clone();
        } else {
            next.progress.verified = Some(verified);
        }
        next.validate()?;
        Ok(next)
    }

    /// Returns the original physical full key without selecting a new prefix.
    pub fn key(&self) -> String {
        if self.destination {
            self.original.destination_key()
        } else {
            self.original.stage_key()
        }
    }

    /// Archives only the exact already committed final progress, without Delete.
    ///
    /// # Errors
    /// Refuses unknown effects, absent final bytes, changed source or commit.
    pub fn acknowledge_commit(&self, progress: &MirrorProgress, commit: &str) -> Result<Self> {
        self.validate()?;
        ensure!(
            self.pending.is_none()
                && progress.commit_digest(&self.original)? == commit
                && self.progress.stage_closure == progress.stage_closure
                && self.progress.stage_parts == progress.stage_parts
                && self.progress.verified == progress.verified,
            "mirror ACK changed the retained source or committed final proof"
        );
        if self.destination || self.acknowledged_commit.is_some() {
            ensure!(
                self.progress == *progress,
                "mirror terminal ACK replaced its exact positive progress"
            );
        }
        ensure!(
            self.acknowledged_commit
                .as_deref()
                .is_none_or(|prior| prior == commit),
            "mirror ACK replaced its terminal commit"
        );
        let mut next = self.clone();
        next.progress = progress.clone();
        next.acknowledged_commit = Some(commit.into());
        next.validate()?;
        Ok(next)
    }

    fn effect_digest(&self, effect: &MirrorExternalEffect) -> Result<String> {
        digest(&(
            "aos.external-mirror-effect.v1",
            &self.original,
            self.destination,
            effect,
        ))
    }

    fn validate_effect(&self, effect: &MirrorExternalEffect) -> Result<()> {
        let (upload, parts) = if self.destination {
            (
                &self.progress.destination_upload_id,
                &self.progress.destination_parts,
            )
        } else {
            (&self.progress.stage_upload_id, &self.progress.stage_parts)
        };
        let total = self.original.verification.size();
        match effect {
            MirrorExternalEffect::Create | MirrorExternalEffect::EmptyPut => {
                ensure!(
                    upload.is_none()
                        && parts.is_empty()
                        && ((total == 0) == matches!(effect, MirrorExternalEffect::EmptyPut)),
                    "mirror Create changed original geometry or positive state"
                );
            }
            MirrorExternalEffect::Part { part, checksum_md5 } => {
                let checksum = base64::engine::general_purpose::STANDARD.decode(checksum_md5)?;
                let offset = parts.len() as u64 * crate::mirror_work::MIRROR_PART_BYTES;
                ensure!(
                    upload.is_some()
                        && part.part_number as usize == parts.len() + 1
                        && part.size > 0
                        && part.size
                            == total
                                .checked_sub(offset)
                                .context("mirror part exceeds source")?
                                .min(crate::mirror_work::MIRROR_PART_BYTES)
                        && part.etag.is_empty()
                        && valid_direct_digest(&part.sha256)
                        && checksum.len() == 16
                        && base64::engine::general_purpose::STANDARD.encode(checksum)
                            == *checksum_md5,
                    "mirror Part changed its contiguous source or transport checksum"
                );
                if self.destination {
                    let source = self
                        .progress
                        .stage_parts
                        .get(parts.len())
                        .context("mirror copied part has no verified source receipt")?;
                    ensure!(
                        source.part_number == part.part_number
                            && source.size == part.size
                            && source.sha256 == part.sha256,
                        "mirror copy bytes changed verified source part"
                    );
                }
            }
            MirrorExternalEffect::Complete {
                upload_id,
                parts_digest,
            } => {
                ensure!(
                    upload.as_ref() == Some(upload_id)
                        && !parts.is_empty()
                        && parts.iter().map(|part| part.size).sum::<u64>() == total
                        && digest(parts)? == *parts_digest,
                    "mirror Complete changed its positive manifest"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
