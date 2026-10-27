//! Defines the canonical publication schema over Protocol record DATA.

use super::*;
#[cfg(all(feature = "native-journal", target_os = "linux"))]
use crate::native::publication::PolicyPublicationVerifierV1;

/// Selects one closed policy-publication record family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PolicyCompilerJournalRecordKindV1 {
    /// Stores complete portable policy outputs and their normalized input digest.
    Candidate = 1,
    /// Stores complete canonical compiler diagnostics.
    Diagnostics = 2,
    /// Stores a prepared downstream policy-installation effect.
    Effect = 3,
    /// Publishes the exact immediate-successor policy head.
    Current = 4,
    /// Publishes a replay join without granting compaction authority.
    Checkpoint = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum PolicyEffectStateV1 {
    Prepared = 1,
    Observed = 2,
}

/// Defines the policy-compiler protected-journal schema.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PolicyCompilerJournalSchemaV1;

/// Carries authenticated prerequisite evidence used during durable replay.
#[derive(Clone, Debug)]
pub struct PolicyCompilerReplayValidatorV1 {
    pub(crate) authenticated_prerequisites: BTreeMap<ObjectDigest, PolicyPublicationPrerequisitesV1>,
}

impl PolicyCompilerReplayValidatorV1 {
    /// Authenticates the complete bounded prerequisite set before journal claim.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1::UnauthenticatedCandidate`] when
    /// any prerequisite tuple lacks durable provenance evidence, is duplicated,
    /// or would exceed the fixed replay bound.
    #[cfg(all(feature = "native-journal", target_os = "linux"))]
    pub(crate) fn authenticate(
        prerequisites: impl IntoIterator<Item = PolicyPublicationPrerequisitesV1>,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        let mut authenticated_prerequisites = BTreeMap::new();
        for prerequisite in prerequisites {
            if authenticated_prerequisites.len() >= MAXIMUM_AUTHENTICATED_REPLAY_PREREQUISITES
                || !verifier.prerequisite_evidence_is_authentic(&prerequisite)
                || authenticated_prerequisites
                    .insert(prerequisite.digest(), prerequisite)
                    .is_some()
            {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
        }
        Ok(Self {
            authenticated_prerequisites,
        })
    }

    pub(crate) fn contains(&self, prerequisites: &PolicyPublicationPrerequisitesV1) -> bool {
        self.authenticated_prerequisites
            .get(&prerequisites.digest())
            == Some(prerequisites)
    }
}

impl ProtectedDomainSchemaV1 for PolicyCompilerJournalSchemaV1 {
    type Kind = PolicyCompilerJournalRecordKindV1;
    type ReplayValidator = PolicyCompilerReplayValidatorV1;

    const MAGIC: [u8; 8] = *b"AOSPCJ01";
    const HASH_DOMAIN: &'static [u8] = b"aos.sandbox.policy-compiler.journal.v1\0";
    const KEY_PREFIX: &'static [u8] = b"\0aos-policy-compiler-v1\0";
    const MAXIMUM_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

    fn kind_code(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn kind_from_code(code: u8) -> Option<Self::Kind> {
        match code {
            1 => Some(Self::Kind::Candidate),
            2 => Some(Self::Kind::Diagnostics),
            3 => Some(Self::Kind::Effect),
            4 => Some(Self::Kind::Current),
            5 => Some(Self::Kind::Checkpoint),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::Candidate | Self::Kind::Diagnostics => RecordNamespace::PublisherPolicy,
            Self::Kind::Effect => RecordNamespace::Effect,
            Self::Kind::Current => RecordNamespace::AuthorityPublication,
            Self::Kind::Checkpoint => RecordNamespace::RuntimeGeneration,
        }
    }

    fn order(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::Candidate | Self::Kind::Diagnostics => ProtectedRecordRoleV1::State,
            Self::Kind::Effect => ProtectedRecordRoleV1::Effect,
            Self::Kind::Current | Self::Kind::Checkpoint => ProtectedRecordRoleV1::Publication,
        }
    }

    fn is_checkpoint(kind: Self::Kind) -> bool {
        matches!(kind, Self::Kind::Checkpoint)
    }

    fn family(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn decode_reducer_phase(
        validator: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        match kind {
            Self::Kind::Candidate => {
                let candidate = validate_candidate_payload(body).ok()?;
                (identity.len() == 64
                    && body.get(10..42) == identity.get(..32)
                    && identity[32..] == *candidate.candidate.as_bytes()
                    && validator.contains(&candidate.prerequisite_tuple))
                .then_some(ProtectedReducerPhaseV1::Terminal)
            }
            Self::Kind::Diagnostics => (body.get(10..74) == Some(identity))
                .then(|| decode_diagnostics_payload(body).ok())
                .flatten()
                .map(|_| ProtectedReducerPhaseV1::Terminal),
            Self::Kind::Effect => {
                let effect = decode_effect_header(body).ok()?;
                (body.get(10..58) == Some(identity)
                    && validator.contains(&effect.prerequisite_tuple))
                .then_some(match effect.state {
                    PolicyEffectStateV1::Prepared => ProtectedReducerPhaseV1::Prepared,
                    PolicyEffectStateV1::Observed => ProtectedReducerPhaseV1::Observed,
                })
            }
            Self::Kind::Current => {
                let current = decode_current_payload(body).ok()?;
                (body.get(10..42) == Some(identity)
                    && validator.contains(&current.prerequisite_tuple))
                .then_some(ProtectedReducerPhaseV1::Terminal)
            }
            Self::Kind::Checkpoint => None,
        }
    }

    fn validates_identity(kind: Self::Kind, identity: &[u8]) -> bool {
        match kind {
            Self::Kind::Candidate | Self::Kind::Diagnostics => {
                identity.len() == 64
                    && identity[..16] != [0; 16]
                    && identity[16..32] != [0; 16]
                    && identity[32..] != [0; 32]
            }
            Self::Kind::Effect => {
                identity.len() == 48
                    && identity[..16] != [0; 16]
                    && identity[16..32] != [0; 16]
                    && identity[32..] != [0; 16]
            }
            Self::Kind::Current => {
                identity.len() == 32 && identity[..16] != [0; 16] && identity[16..] != [0; 16]
            }
            Self::Kind::Checkpoint => identity.len() == 32 && identity != [0; 32],
        }
    }

    fn semantic_tuple(kind: Self::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]> {
        if body.len() < 8 || identity.len() < 32 {
            return None;
        }
        if kind == Self::Kind::Checkpoint {
            return None;
        }
        Some(
            Sha256::new()
                .chain_update(b"aos.sandbox.policy-compiler.semantic-tuple.v1\0")
                .chain_update(&identity[..32])
                .finalize()
                .into(),
        )
    }
}
