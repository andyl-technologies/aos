//! Coupled-world replay admission and versioned materialization capabilities.

use super::*;

/// Declares the selected execution guarantee independently of capture fidelity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeExecutionGuarantee {
    /// Repeats under the admitted complete model and controlled input sequence.
    Repeatable,
    /// Records an independent observed execution without byte-equivalence claims.
    Nondeterministic,
    /// Makes no qualified repeatability claim and cannot admit deterministic work.
    Unqualified,
    /// Replays a retained transcript under authenticated request preconditions.
    ConditionalTranscript {
        /// Identity of the complete retained boundary-input/output transcript.
        transcript: CampaignHash,
        /// Identity of the retained qualification proof for this realization.
        qualification: CampaignHash,
        /// Identity of the complete request/context/boundary preconditions.
        preconditions: CampaignHash,
    },
}

impl Canonical for NodeExecutionGuarantee {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Repeatable => encoder.u8(0),
            Self::Nondeterministic => encoder.u8(1),
            Self::Unqualified => encoder.u8(3),
            Self::ConditionalTranscript {
                transcript,
                qualification,
                preconditions,
            } => {
                encoder.u8(2);
                transcript.encode(encoder);
                qualification.encode(encoder);
                preconditions.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Repeatable),
            1 => Ok(Self::Nondeterministic),
            3 => Ok(Self::Unqualified),
            2 => Ok(Self::ConditionalTranscript {
                transcript: CampaignHash::decode(decoder)?,
                qualification: CampaignHash::decode(decoder)?,
                preconditions: CampaignHash::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "node-execution-guarantee",
                tag,
            }),
        }
    }
}

/// Names an operation that requires admitted repeatable execution evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeterministicExecutionOperation {
    /// Reuses a deterministic result or native-state cache entry.
    CacheReuse,
    /// Reconstructs state by deterministic thin replay.
    ThinReplay,
    /// Executes counterfactual branches while minimizing a finding.
    Minimization,
    /// Asserts byte or state/event trajectory equivalence between executions.
    Equivalence,
}

/// Binds the actual requested replay or counterfactual to its complete inputs.
///
/// These identities refer to authenticated request and input artifacts, not
/// caller-supplied labels. The input artifact includes faults, clock policy,
/// boundary ordering, and relevant external context as well as payload bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeterministicExecutionContext {
    /// Identity of the actual requested operation or counterfactual branch.
    pub request: CampaignHash,
    /// Identity of the complete input/precondition context for this operation.
    pub inputs: CampaignHash,
}

/// Groups the retained transcript, qualification, and required precondition identities.
///
/// These references identify evidence to be authenticated. Constructing this
/// value neither verifies its content nor grants deterministic execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConditionalTranscriptEvidence {
    /// Identifies the retained complete original boundary transcript.
    pub transcript: CampaignHash,
    /// Identifies the independent transcript qualification evidence.
    pub qualification: CampaignHash,
    /// Identifies the preconditions under which that evidence is valid.
    pub preconditions: CampaignHash,
}

/// Authenticates conditional replay evidence for a complete coupled-world roster.
///
/// Implementations must read and verify the retained transcript bytes, complete
/// sequence coverage, realization binding, and operation-specific request/input
/// preconditions. Comparing the three hashes alone is insufficient. In
/// particular, minimization requires proof for the changed counterfactual;
/// a transcript of the original branch cannot authorize that operation.
pub trait TranscriptQualificationVerifier {
    /// Validates one owner's transcript against the complete operation context.
    ///
    /// # Errors
    ///
    /// Returns an error when evidence is missing, incomplete, incompatible,
    /// divergent, or insufficient for the requested operation.
    fn verify(
        &self,
        roster: &ExecutorNodeRoster,
        owner: &str,
        evidence: ConditionalTranscriptEvidence,
        operation: DeterministicExecutionOperation,
        context: &DeterministicExecutionContext,
    ) -> Result<(), CampaignCodecError>;
}

impl ExecutorNodeRoster {
    /// Admits deterministic work only after checking every coupled owner.
    ///
    /// Conditional replay is admitted only through the supplied authenticated
    /// verifier. Unrecorded live nondeterministic execution always refuses.
    ///
    /// # Errors
    ///
    /// Returns an error for any nondeterministic owner or a failed conditional
    /// transcript qualification, including a counterfactual not covered by it.
    pub fn admit_deterministic_operation(
        &self,
        operation: DeterministicExecutionOperation,
        context: &DeterministicExecutionContext,
        verifier: &impl TranscriptQualificationVerifier,
    ) -> Result<(), CampaignCodecError> {
        for (owner, binding) in self.owners() {
            match binding.guarantee() {
                NodeExecutionGuarantee::Repeatable => {}
                NodeExecutionGuarantee::Nondeterministic | NodeExecutionGuarantee::Unqualified => {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "coupled nondeterministic owner forbids deterministic execution",
                    });
                }
                NodeExecutionGuarantee::ConditionalTranscript {
                    transcript,
                    qualification,
                    preconditions,
                } => verifier.verify(
                    self,
                    owner,
                    ConditionalTranscriptEvidence {
                        transcript: *transcript,
                        qualification: *qualification,
                        preconditions: *preconditions,
                    },
                    operation,
                    context,
                )?,
            }
        }
        Ok(())
    }
}

/// Names a realization-qualified reconstruction or starting strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeMaterializationStrategy {
    /// Starts an independent execution from verified immutable world inputs.
    FreshExecution,
    /// Reconstructs a repeatable model by replaying the authenticated prefix.
    ThinReplay,
    /// Restores a complete qualified native continuation closure.
    ExactRestore,
    /// Branches an admitted live retained execution source.
    LiveFork,
    /// Replays a transcript after verifying each boundary request precondition.
    ConditionalTranscriptReplay,
}

impl Canonical for NodeMaterializationStrategy {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::FreshExecution => 0,
            Self::ThinReplay => 1,
            Self::ExactRestore => 2,
            Self::LiveFork => 3,
            Self::ConditionalTranscriptReplay => 4,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::FreshExecution),
            1 => Ok(Self::ThinReplay),
            2 => Ok(Self::ExactRestore),
            3 => Ok(Self::LiveFork),
            4 => Ok(Self::ConditionalTranscriptReplay),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "node-materialization-strategy",
                tag,
            }),
        }
    }
}

/// Carries version-two realization-aware executor materialization capabilities.
///
/// Unlike the legacy capability schema, this schema can describe an executor
/// that has no thin-replay correctness fallback. It does not change the
/// requirements or canonical bytes of the legacy schema. Capture and live-fork
/// claims require independent owner qualification at admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorNodeCapabilities {
    roster: ExecutorNodeRoster,
    materialization: BTreeSet<NodeMaterializationStrategy>,
}

impl ExecutorNodeCapabilities {
    /// Builds a version-two capability set for one admitted realization.
    ///
    /// This construction checks the claim's shape; it does not qualify native
    /// state capture or supply conditional transcript evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when a nonrepeatable roster advertises unqualified
    /// thin replay, no materialization strategy is supplied, or the encoded
    /// capability record exceeds its bound.
    pub fn new(
        roster: ExecutorNodeRoster,
        materialization: BTreeSet<NodeMaterializationStrategy>,
    ) -> Result<Self, CampaignCodecError> {
        if materialization.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "executor node capabilities contain no materialization strategy",
            });
        }
        if !roster.is_repeatable()
            && materialization.contains(&NodeMaterializationStrategy::ThinReplay)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "nonrepeatable executor cannot advertise unconditional thin replay",
            });
        }

        let capabilities = Self {
            roster,
            materialization,
        };
        codec::ensure_encoded_size(
            &capabilities,
            MAX_ROSTER_BYTES,
            "executor-node-capability-bytes",
        )?;
        Ok(capabilities)
    }

    /// Returns the complete realized owner compatibility roster.
    #[must_use]
    pub const fn roster(&self) -> &ExecutorNodeRoster {
        &self.roster
    }

    /// Returns independently declared materialization strategies.
    #[must_use]
    pub const fn materialization(&self) -> &BTreeSet<NodeMaterializationStrategy> {
        &self.materialization
    }

    /// Returns the version-two capability identity.
    #[must_use]
    pub fn digest(&self) -> CampaignHash {
        CampaignHash::derive(
            "crucible.executor-node-capabilities.v2",
            &self.canonical_bytes(),
        )
    }

    /// Returns strict canonical version-two bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes the version-two schema without accepting legacy capability bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown versions, malformed/noncanonical records,
    /// unsupported claims, or an oversized record.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode_bounded(bytes, MAX_ROSTER_BYTES, "executor-node-capability-bytes")
    }
}

impl Canonical for ExecutorNodeCapabilities {
    fn encode(&self, encoder: &mut Encoder) {
        NODE_CAPABILITY_SCHEMA_VERSION.encode(encoder);
        self.roster.encode(encoder);
        self.materialization.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_version(u32::decode(decoder)?, NODE_CAPABILITY_SCHEMA_VERSION)?;
        Self::new(
            ExecutorNodeRoster::decode(decoder)?,
            decoder.set_bounded(5, "executor-node-materialization-count")?,
        )
    }
}
