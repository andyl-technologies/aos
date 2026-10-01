//! Compact permanent ownership for a streaming same-binding copy.
//!
//! The physical guard persists a pending turn before dispatch and an immutable
//! receipt before advancing this state. Parts live in separately addressed KV
//! records; this head retains their ordered digest and the portable source hash
//! continuation. No deadline, HEAD result or repeated request clears a pending
//! turn. Provider authentication and epoch-lease admission remain separate.
//!
//! ```text
//! creating -> active -> closed
//!                 \-> aborted
//! pending = {copy_id, original_digest, action_id, action, dispatch_nonce}
//! receipt = {turn, outcome}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::db::OciSha256State;
use crate::storage_authority::canonical_digest;

use super::{digest_string, CopySourceObject, ExternalCopyOriginal};

mod progress;

/// Names one closed provider mutation retained before its dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CopyAction {
    /// Creates one private multipart upload for a nonempty object.
    Create,
    /// Writes the verified empty object using explicitly admitted PUT authority.
    EmptyPut,
    /// Reads one exact source range and uploads it as a destination part.
    Part {
        /// Positive provider upload identity from the retained Create receipt.
        upload_id: String,
        /// Exact one-based part position.
        number: u32,
        /// Exact immutable source offset.
        offset: u64,
        /// Known source range and outgoing part length.
        bytes: u64,
        /// Exact portable whole-source continuation before this range.
        source_state_digest: String,
    },
    /// Closes the ordered manifest after every source byte was consumed.
    Complete {
        /// Positive provider upload identity from the retained Create receipt.
        upload_id: String,
        /// Actual full source SHA-256 calculated beside storage.
        sha256: String,
        /// Ordered positive part-receipt commitment retained by the guard.
        parts_digest: String,
    },
    /// Removes a known incomplete multipart upload after all earlier effects settle.
    Abort {
        /// Positive original upload identity; a guessed upload ID is forbidden.
        upload_id: String,
    },
}

impl CopyAction {
    /// Derives one action identity without fresh request time or randomness.
    ///
    /// # Errors
    /// Returns an error for an invalid original or failed serialization.
    pub fn operation_id(&self, original: &ExternalCopyOriginal) -> Result<String> {
        let (phase, number) = match self {
            Self::Create => ("create", 0),
            Self::EmptyPut => ("empty_put", 0),
            Self::Part { number, .. } => ("part", *number),
            Self::Complete { .. } => ("complete", 0),
            Self::Abort { .. } => ("abort", 0),
        };
        canonical_digest(&(
            "aos.external-placement-copy-effect.v1",
            original.copy_id()?,
            phase,
            number,
        ))
    }
}

/// Retains one exact dispatch turn, including its unique provider-attempt nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyTurn {
    /// Stable retained copy identity, independent of fresh permission envelopes.
    pub copy_id: String,
    /// Full immutable original fingerprint.
    pub original_digest: String,
    /// Stable original-derived action identity.
    pub action_id: String,
    /// Exact provider selector and continuation commitment.
    pub action: CopyAction,
    /// Guard-generated nonce for this one dispatch, retained before invocation.
    pub dispatch_nonce: String,
}

/// Records a positive provider acknowledgement after its source checks finish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CopyOutcome {
    /// Retains the actual provider upload identity.
    Created {
        /// Positive provider Create result.
        upload_id: String,
    },
    /// Retains a positive part acknowledgement and actual conditional-read hash.
    Part {
        /// Actual provider part ETag, preserved without substituting a checksum.
        etag: String,
        /// Actual SHA-256 of this exact range, calculated at the executor.
        sha256: String,
        /// Portable whole-source state after exact EOF for the selected range.
        source_state: OciSha256State,
    },
    /// Retains the positively closed destination's exact physical incarnation.
    Closed {
        /// Actual version, strong tag and full known destination length.
        destination: CopySourceObject,
        /// Actual full source SHA-256, calculated without sending bytes to Native.
        sha256: String,
    },
    /// Retains positive provider removal of the exact incomplete upload.
    Aborted,
}

/// Binds a positive provider result to the already retained exact turn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyReceipt {
    /// Exact original turn, including its retained dispatch nonce.
    pub turn: CopyTurn,
    /// Positive producer result; transport failure is never a receipt.
    pub outcome: CopyOutcome,
}

/// Tracks the compact lifecycle of one retained multipart copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyPhase {
    /// No positive provider Create or empty PUT receipt exists yet.
    Creating,
    /// Positive Create exists; ordered parts or exact Abort may be admitted.
    Active,
    /// Positive versioned destination closure exists.
    Closed,
    /// Positive incomplete-upload removal exists.
    Aborted,
}

/// Holds compact state in the existing permanent physical-object guard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopySession {
    original: ExternalCopyOriginal,
    phase: CopyPhase,
    upload_id: Option<String>,
    next_part: u32,
    source_state: OciSha256State,
    parts_digest: String,
    pending: Option<CopyTurn>,
    last_receipt: Option<String>,
    destination: Option<CopySourceObject>,
}

impl CopySession {
    /// Creates a compact original owner before any provider invocation.
    ///
    /// # Errors
    /// Returns an error for an invalid immutable original.
    pub fn initialize(original: ExternalCopyOriginal) -> Result<Self> {
        original.validate()?;
        Ok(Self {
            original,
            phase: CopyPhase::Creating,
            upload_id: None,
            next_part: 1,
            source_state: OciSha256State::initial(),
            parts_digest: canonical_digest(&"aos.external-placement-copy-parts.v1")?,
            pending: None,
            last_receipt: None,
            destination: None,
        })
    }

    /// Returns the retained immutable original.
    pub fn original(&self) -> &ExternalCopyOriginal {
        &self.original
    }

    /// Returns the durable phase without treating pending effects as settled.
    pub fn phase(&self) -> CopyPhase {
        self.phase
    }

    /// Returns an unresolved provider turn, if one was persisted.
    pub fn pending(&self) -> Option<&CopyTurn> {
        self.pending.as_ref()
    }

    /// Returns the actual positive destination identity after full closure.
    pub fn destination(&self) -> Option<&CopySourceObject> {
        self.destination.as_ref()
    }

    /// Checks durable state before a guard exposes or changes it.
    ///
    /// # Errors
    /// Returns an error for changed originals, invalid progress or malformed turns.
    pub fn validate(&self, original: &ExternalCopyOriginal) -> Result<()> {
        original.validate()?;
        ensure!(&self.original == original, "retained copy original differs");
        self.source_state.validate()?;
        let count = original.part_count()?;
        ensure!(
            (1..=count + 1).contains(&self.next_part)
                && self.source_state.total_bytes
                    == (u64::from(self.next_part - 1) * original.part_bytes.get() as u64)
                        .min(original.source_object.bytes.get() as u64)
                && digest_string(&self.parts_digest)
                && self
                    .last_receipt
                    .as_ref()
                    .is_none_or(|value| digest_string(value)),
            "retained copy progress invalid"
        );
        if let Some(upload_id) = &self.upload_id {
            provider_id(upload_id)?;
        }
        if self.next_part == 1 {
            ensure!(
                self.source_state == OciSha256State::initial(),
                "copy initial source continuation differs"
            );
        }
        ensure!(
            match self.phase {
                CopyPhase::Creating =>
                    self.upload_id.is_none()
                        && self.next_part == 1
                        && self.last_receipt.is_none()
                        && self.destination.is_none(),
                CopyPhase::Active =>
                    self.upload_id.is_some()
                        && original.source_object.bytes.get() > 0
                        && self.last_receipt.is_some()
                        && self.destination.is_none(),
                CopyPhase::Closed =>
                    self.destination.is_some()
                        && (self.upload_id.is_some() == (original.source_object.bytes.get() > 0))
                        && self.last_receipt.is_some()
                        && self.next_part == count + 1
                        && self.pending.is_none(),
                CopyPhase::Aborted =>
                    self.upload_id.is_some()
                        && original.source_object.bytes.get() > 0
                        && self.last_receipt.is_some()
                        && self.destination.is_none()
                        && self.pending.is_none(),
            },
            "retained copy phase invalid"
        );
        if let Some(destination) = &self.destination {
            destination.validate()?;
            ensure!(
                destination.bytes == original.source_object.bytes,
                "retained destination length differs"
            );
            self.check_source_hash()?;
        }
        if let Some(turn) = &self.pending {
            self.validate_turn(turn)?;
        }
        Ok(())
    }

    /// Selects the only next ordered copy action without dispatching it.
    ///
    /// # Errors
    /// Returns an error for an unknown prior effect or a terminal copy.
    pub fn next_action(&self) -> Result<CopyAction> {
        self.validate(&self.original)?;
        ensure!(
            self.pending.is_none(),
            "copy provider effect remains unknown"
        );
        self.planned_action()
    }

    /// Retains a single attempt before invoking a provider.
    ///
    /// The storage adapter must commit this state before returning the turn.
    /// This method grants neither an epoch lease nor current SQL permission.
    ///
    /// # Errors
    /// Returns an error for changed originals, malformed nonce, another action
    /// or any pending earlier attempt, including an exact repeated request.
    pub fn begin(
        &mut self,
        original: &ExternalCopyOriginal,
        action: CopyAction,
        dispatch_nonce: String,
    ) -> Result<CopyTurn> {
        self.validate(original)?;
        ensure!(
            self.pending.is_none(),
            "copy provider effect remains unknown"
        );
        self.check_action(&action)?;
        let turn = CopyTurn {
            copy_id: original.copy_id()?,
            original_digest: original.fingerprint()?,
            action_id: action.operation_id(original)?,
            action,
            dispatch_nonce,
        };
        self.validate_turn(&turn)?;
        self.pending = Some(turn.clone());
        Ok(turn)
    }

    /// Advances only after a positive receipt for the exact pending attempt.
    ///
    /// The producer supplies a source continuation only after a versioned
    /// conditional range read reached exact EOF and UploadPart acknowledged.
    /// Its authenticated receipt and the separately retained immutable part
    /// record establish that fact; continuation words alone prove no bytes.
    /// The storage adapter atomically retains the receipt and this postimage.
    ///
    /// # Errors
    /// Returns an error for a different attempt, malformed positive evidence,
    /// incomplete source coverage or a hash different from the original.
    pub fn acknowledge(&mut self, receipt: &CopyReceipt) -> Result<()> {
        self.validate(&self.original)?;
        ensure!(
            self.pending.as_ref() == Some(&receipt.turn),
            "copy receipt differs from exact pending turn"
        );
        let mut next = self.clone();
        match (&receipt.turn.action, &receipt.outcome) {
            (CopyAction::Create, CopyOutcome::Created { upload_id }) => {
                provider_id(upload_id)?;
                next.upload_id = Some(upload_id.clone());
                next.phase = CopyPhase::Active;
            }
            (
                CopyAction::Part { offset, bytes, .. },
                CopyOutcome::Part {
                    etag,
                    sha256,
                    source_state,
                },
            ) => {
                provider_id(etag)?;
                ensure!(digest_string(sha256), "copy part SHA-256 invalid");
                source_state.validate()?;
                ensure!(
                    source_state.total_bytes == offset + bytes,
                    "copy receipt did not cover exact source range"
                );
                next.source_state = source_state.clone();
                next.parts_digest = canonical_digest(&(
                    "aos.external-placement-copy-part-chain.v1",
                    &self.parts_digest,
                    canonical_digest(receipt)?,
                ))?;
                next.next_part += 1;
            }
            (
                CopyAction::EmptyPut | CopyAction::Complete { .. },
                CopyOutcome::Closed {
                    destination,
                    sha256,
                },
            ) => {
                destination.validate()?;
                ensure!(
                    destination.bytes == self.original.source_object.bytes
                        && sha256 == &self.source_hash()?,
                    "copy destination receipt differs from verified source"
                );
                self.check_source_hash()?;
                next.destination = Some(destination.clone());
                next.phase = CopyPhase::Closed;
            }
            (CopyAction::Abort { .. }, CopyOutcome::Aborted) => {
                next.phase = CopyPhase::Aborted;
            }
            _ => anyhow::bail!("copy receipt does not match provider action"),
        }
        next.pending = None;
        next.last_receipt = Some(canonical_digest(receipt)?);
        next.validate(&self.original)?;
        *self = next;
        Ok(())
    }

    fn planned_action(&self) -> Result<CopyAction> {
        if self.phase == CopyPhase::Creating {
            return Ok(if self.original.source_object.bytes.get() == 0 {
                CopyAction::EmptyPut
            } else {
                CopyAction::Create
            });
        }
        ensure!(self.phase == CopyPhase::Active, "copy already terminal");
        let upload_id = self
            .upload_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("copy upload identity absent"))?;
        if self.next_part <= self.original.part_count()? {
            let (offset, bytes) = self.original.part_range(self.next_part)?;
            return Ok(CopyAction::Part {
                upload_id,
                number: self.next_part,
                offset,
                bytes,
                source_state_digest: canonical_digest(&self.source_state)?,
            });
        }
        self.check_source_hash()?;
        Ok(CopyAction::Complete {
            upload_id,
            sha256: self.source_hash()?,
            parts_digest: self.parts_digest.clone(),
        })
    }

    fn check_action(&self, action: &CopyAction) -> Result<()> {
        if let CopyAction::Abort { upload_id } = action {
            ensure!(
                self.phase == CopyPhase::Active && self.upload_id.as_ref() == Some(upload_id),
                "copy Abort requires original positive upload identity"
            );
        } else {
            ensure!(
                *action == self.planned_action()?,
                "copy action differs from retained progress"
            );
        }
        Ok(())
    }

    fn validate_turn(&self, turn: &CopyTurn) -> Result<()> {
        self.check_action(&turn.action)?;
        ensure!(
            turn.copy_id == self.original.copy_id()?
                && turn.original_digest == self.original.fingerprint()?
                && turn.action_id == turn.action.operation_id(&self.original)?
                && digest_string(&turn.dispatch_nonce),
            "copy turn differs from retained original"
        );
        Ok(())
    }

    fn source_hash(&self) -> Result<String> {
        Ok(self.source_state.final_digest()?.encoded())
    }

    fn check_source_hash(&self) -> Result<()> {
        let hash = self.source_hash()?;
        ensure!(
            self.source_state.total_bytes == self.original.source_object.bytes.get() as u64
                && self
                    .original
                    .expected_sha256
                    .as_ref()
                    .is_none_or(|expected| expected == &hash),
            "source bytes or SHA-256 differ from retained original"
        );
        Ok(())
    }
}

fn provider_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control),
        "invalid copy provider receipt identity"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
