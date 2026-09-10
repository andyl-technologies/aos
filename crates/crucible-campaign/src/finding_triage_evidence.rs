//! Durable replay inputs for reconstructing one observed finding signature.
//!
//! The record is transport-neutral: campaign storage authenticates the exact
//! reproduction and observed campaign signature while retaining an opaque,
//! versioned execution-model payload. A consumer with the matching execution
//! model decodes that payload against the referenced reproduction and
//! reconstructs its full native failure signature.
//!
//! ```text
//! u32 schema-version = 1
//! ReproductionArtifactId reproduction
//! FindingSignature observed-signature
//! u32 payload-schema
//! bytes payload
//! ```

use crucible_cas::content_store::ContentId;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    CampaignCodecError, CampaignRecordKind, FindingSignature, FindingTriageReplayEvidenceId,
    ObjectEnvelope, ReproductionArtifactId,
};

const RECORD_SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: usize = 52 * 1024 * 1024;

/// Maximum opaque execution-model payload retained by one replay record.
pub const MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES: usize = 48 * 1024 * 1024;

/// One exact replay and the complete campaign signature it observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingTriageReplayEvidence {
    schema_version: u32,
    reproduction: ReproductionArtifactId,
    observed_signature: FindingSignature,
    payload_schema: u32,
    payload: Vec<u8>,
}

impl FindingTriageReplayEvidence {
    /// Builds one bounded replay-evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the payload schema is zero, the
    /// payload is empty or exceeds 48 MiB, or the complete record exceeds its
    /// canonical size bound.
    pub fn new(
        reproduction: ReproductionArtifactId,
        observed_signature: FindingSignature,
        payload_schema: u32,
        payload: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        if payload_schema == 0 || payload.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding triage replay payload is empty or has no schema",
            });
        }
        if payload.len() > MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-payload-bytes",
            });
        }
        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            reproduction,
            observed_signature,
            payload_schema,
            payload,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_RECORD_BYTES,
            "finding-triage-replay-evidence-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the exact reproduction executed by this replay.
    #[must_use]
    pub const fn reproduction(&self) -> ReproductionArtifactId {
        self.reproduction
    }

    /// Returns the complete campaign finding signature observed by the replay.
    #[must_use]
    pub const fn observed_signature(&self) -> &FindingSignature {
        &self.observed_signature
    }

    /// Returns the execution-model payload schema.
    #[must_use]
    pub const fn payload_schema(&self) -> u32 {
        self.payload_schema
    }

    /// Returns the opaque execution-model replay payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns strict canonical record-body bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical record-body bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "finding-triage-replay-evidence-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the exact stored replay-evidence identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<FindingTriageReplayEvidenceId, CampaignCodecError> {
        FindingTriageReplayEvidenceId::from_content_id(
            ObjectEnvelope::for_record(
                CampaignRecordKind::FindingTriageReplayEvidence,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![("reproduction".to_owned(), self.reproduction.content_id())];
        children.extend(crate::finding_candidate::signature_children(
            "observed-signature",
            &self.observed_signature,
        ));
        children
    }
}

impl Canonical for FindingTriageReplayEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.reproduction.encode(encoder);
        self.observed_signature.encode(encoder);
        self.payload_schema.encode(encoder);
        self.payload.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != RECORD_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported finding triage replay evidence schema version",
            });
        }
        Self::new(
            ReproductionArtifactId::decode(decoder)?,
            FindingSignature::decode(decoder)?,
            u32::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES,
                "finding-triage-replay-payload-bytes",
                u8::decode,
            )?,
        )
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;
    use crate::{CampaignHash, FindingKind};

    fn fixture() -> (ReproductionArtifactId, FindingSignature) {
        let reproduction = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            1,
            b"triage-replay-reproduction",
        ))
        .expect("reproduction ID");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            CampaignHash::derive("test", b"triage-replay-fingerprint"),
            None,
            String::from("qemu.replay-divergence"),
            None,
            BTreeSet::new(),
        )
        .expect("finding signature");

        (reproduction, signature)
    }

    #[test]
    fn replay_evidence_round_trip_preserves_exact_native_payload() {
        let (reproduction, signature) = fixture();
        let evidence = FindingTriageReplayEvidence::new(
            reproduction,
            signature,
            7,
            b"versioned native replay payload".to_vec(),
        )
        .expect("triage replay evidence");

        let decoded =
            FindingTriageReplayEvidence::from_canonical_bytes(&evidence.canonical_bytes())
                .expect("decode triage replay evidence");
        assert_eq!(decoded, evidence);
        assert_eq!(decoded.payload_schema(), 7);
        assert_eq!(decoded.payload(), b"versioned native replay payload");
        assert_eq!(decoded.content_children().len(), 1);
    }

    #[test]
    fn replay_evidence_rejects_empty_unversioned_and_oversized_payloads() {
        let (reproduction, signature) = fixture();
        assert!(
            FindingTriageReplayEvidence::new(
                reproduction,
                signature.clone(),
                0,
                b"payload".to_vec(),
            )
            .is_err()
        );
        assert!(
            FindingTriageReplayEvidence::new(reproduction, signature.clone(), 1, Vec::new())
                .is_err()
        );
        assert!(
            FindingTriageReplayEvidence::new(
                reproduction,
                signature,
                1,
                vec![0; MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES + 1],
            )
            .is_err()
        );
    }
}
