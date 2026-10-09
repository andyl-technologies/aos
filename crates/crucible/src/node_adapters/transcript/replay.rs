//! Installed conditional replay qualification and fail-closed original cursors.

use crucible_node_contract::{ContentRef, HashRef, NodeBinding, U64, canonical};
use serde::{Deserialize, Serialize};

use crate::{
    node_admission::AdmittedGraph, node_contract::NodeRoute, node_scheduling::InputPayload,
};

use super::{
    archive::AuthenticatedTranscript,
    codec::{TranscriptError, context_commitment, encode, invalid},
    types::*,
};

/// Reports an installed policy's explicit source-to-fresh-replay association.
///
/// This data cannot qualify a replay by itself. The trusted installed policy is
/// invoked against actual authenticated source bytes and the sealed target graph.
pub struct ReplayQualification {
    /// Retains readable installed provenance and exact applicability evidence.
    pub proof: InputPayload,
    /// Binds complete original source attempt, owners and materialized context.
    pub source_context: ContentRef,
    /// Binds the actual complete fresh replay graph, including peer nodes.
    pub target_world: HashRef,
    /// Binds the actual selected conditional backend and complete configuration.
    pub target_binding: ContentRef,
    /// Binds only the explicit fresh operational node/owner association.
    pub target_route: NodeRoute,
}

/// Authenticates installed source provenance and exact replay applicability.
///
/// Implementations are trusted host installation procedures. They must check
/// actual signed source graph, code and recorded context against readable target
/// context and permit only the declared replay backend/owner substitution.
/// Changed input, clock, fault, horizon or peer realization is a counterfactual,
/// even when a caller supplies newly matching content hashes or public claims.
pub trait InstalledReplayPolicy {
    /// Verifies the actual source and complete target before any response is used.
    ///
    /// # Errors
    /// Refuses missing installed code/source qualifications, omitted raw context,
    /// changed semantics, uncertain source provenance or unsupported substitution.
    fn qualify(
        &self,
        source: &AuthenticatedTranscript,
        target: &AdmittedGraph,
        route: &NodeRoute,
        target_context: &[InputPayload],
    ) -> Result<ReplayQualification, TranscriptError>;
}

/// Retains complete cursor state without serializing replay or native authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCursorSnapshot {
    /// Selects the closed cursor format edition.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Binds the actual independently authenticated complete original transcript.
    pub transcript: ContentRef,
    /// Binds original source attempt, owner lineage and complete applicability.
    pub source_context: ContentRef,
    /// Identifies the first unconsumed original boundary interaction.
    pub next_record: U64,
    /// Retains sticky divergence; a failed branch cannot resume or resample.
    pub diverged: bool,
}

pub(super) struct ReplayCursor {
    pub(super) source: AuthenticatedTranscript,
    pub(super) qualification: ReplayQualification,
    pub(super) next: usize,
    pub(super) diverged: bool,
}

impl ReplayCursor {
    pub(super) fn prepare(
        source: AuthenticatedTranscript,
        target: &AdmittedGraph,
        route: NodeRoute,
        target_context: &[InputPayload],
        policy: &dyn InstalledReplayPolicy,
    ) -> Result<Self, TranscriptError> {
        let binding = target
            .binding(&route.node)
            .ok_or_else(|| TranscriptError::Unqualified("replay node absent".into()))?;
        let guarantees = target
            .guarantees(&route.node)
            .ok_or_else(|| TranscriptError::Unqualified("replay guarantees absent".into()))?;
        if !guarantees.conditional_replay
            || guarantees.repeatability != source.data.origin.repeatability
        {
            return Err(TranscriptError::Unqualified(
                "conditional replay cannot promote original nondeterminism or uncertainty".into(),
            ));
        }
        let original: NodeBinding = serde_json::from_slice(
            &source
                .data
                .origin
                .context
                .iter()
                .find(|object| object.reference == source.data.origin.source_binding)
                .ok_or_else(|| {
                    TranscriptError::Unqualified("original binding bytes absent".into())
                })?
                .bytes,
        )
        .map_err(invalid)?;
        if original.compatibility.implementation.implementation_id
            == binding.compatibility.implementation.implementation_id
        {
            return Err(TranscriptError::Unqualified(
                "replay requires a distinct implementation identity".into(),
            ));
        }
        for owner in &route.owners {
            let admitted = target
                .owner(&owner.owner)
                .ok_or_else(|| TranscriptError::Unqualified("replay owner absent".into()))?;
            if !admitted.owner.participant_ids.contains(&route.node)
                || binding.authority.incarnation_id != owner.incarnation
                || binding.authority.owner_generation != owner.generation
            {
                return Err(TranscriptError::Unqualified(
                    "replay operational owner differs".into(),
                ));
            }
        }
        for object in target_context {
            object.reference.verify(&object.bytes).map_err(invalid)?;
        }
        let qualification = policy.qualify(&source, target, &route, target_context)?;
        qualification
            .proof
            .reference
            .verify(&qualification.proof.bytes)
            .map_err(invalid)?;
        let target_binding =
            canonical::content_ref(&encode(binding)?, "application/json").map_err(invalid)?;
        if qualification.source_context != context_commitment(&source.data.origin)?
            || qualification.target_world != *target.world_binding_hash()
            || qualification.target_binding != target_binding
            || qualification.target_route != route
            || route.node != source.data.origin.route.node
            || route.owners.is_empty()
            || source.data.records.is_empty()
        {
            return Err(TranscriptError::Unqualified(
                "installed replay scope differs from actual complete source/target".into(),
            ));
        }
        Ok(Self {
            source,
            qualification,
            next: 0,
            diverged: false,
        })
    }

    pub(super) fn peek(&self) -> Option<&TranscriptRecord> {
        self.source.data.records.get(self.next)
    }

    pub(super) fn replay(
        &mut self,
        request: &TranscriptRequest,
    ) -> Result<TranscriptRecord, TranscriptError> {
        if self.diverged {
            return Err(self.divergence("branch already diverged"));
        }
        let Some(record) = self.source.data.records.get(self.next) else {
            self.diverged = true;
            return Err(self.divergence("unrecorded request after original prefix"));
        };
        if &record.request != request {
            self.diverged = true;
            return Err(self.divergence("changed, reordered or counterfactual request/context"));
        }
        let record = record.clone();
        self.next = self
            .next
            .checked_add(1)
            .ok_or(TranscriptError::CaptureLimit)?;
        Ok(record)
    }

    pub(super) fn fail(&mut self, reason: &str) -> TranscriptError {
        self.diverged = true;
        self.divergence(reason)
    }

    pub(super) fn snapshot(&self) -> ReplayCursorSnapshot {
        ReplayCursorSnapshot {
            schema_version: 1,
            transcript: self.source.reference.clone(),
            source_context: self.qualification.source_context.clone(),
            next_record: U64::new(self.next as u64),
            diverged: self.diverged,
        }
    }

    fn divergence(&self, reason: &str) -> TranscriptError {
        TranscriptError::Divergence {
            record: U64::new(self.next as u64),
            reason: reason.into(),
        }
    }
}
