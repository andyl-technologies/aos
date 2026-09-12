//! Typed finite-search choices, overrides, and canonical identifier parsing.

use std::collections::BTreeSet;

use super::{ContentHash, FaultObjectId, MappedEffectParameter};
use crate::{ChoiceTag, OverrideDecision, SchedulingPoint};

/// One finite search decision exposed by binding evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingSearchChoice {
    /// Stable decision identity.
    pub id: SearchChoiceId,
    /// Exact candidate-set identity.
    pub candidates_digest: ContentHash,
    /// Number of finite candidates.
    pub candidate_count: u32,
    /// Typed meaning of the finite candidate sequence.
    pub candidate_semantics: BindingSearchCandidateSemantics,
    /// Chosen zero-based candidate index, or `None` for the unmodified model result.
    pub selected_index: Option<u32>,
    /// Whether a replay/explorer override selected the result.
    pub overridden: bool,
}

/// Typed meaning retained for one RFC-0014 finite search candidate sequence.
///
/// Candidate identities are ordered exactly like the binding policy's
/// canonical candidate vector. They let the campaign boundary expose Boolean
/// outcomes and stable discrete transition or parameter alternatives while the
/// effect adapter continues to consume the original typed RFC-0014 values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingSearchCandidateSemantics {
    /// False/true effect outcome candidates, in that order.
    Outcome,
    /// Stable identities for typed state-transition candidates.
    Transition(Vec<ContentHash>),
    /// Stable identities for candidates of one typed effect parameter.
    Parameter {
        /// Effect parameter changed by the finite search policy.
        parameter: MappedEffectParameter,
        /// Stable identities in canonical candidate order.
        candidates: Vec<ContentHash>,
    },
}

impl BindingSearchCandidateSemantics {
    /// Returns the exact typed candidate at one zero-based finite-search index.
    #[must_use]
    pub fn candidate(&self, candidate_index: u32) -> Option<BindingSearchCandidate> {
        let index = usize::try_from(candidate_index).ok()?;
        match self {
            Self::Outcome if candidate_index < 2 => {
                Some(BindingSearchCandidate::Outcome(candidate_index == 1))
            }
            Self::Transition(candidates) => candidates
                .get(index)
                .copied()
                .map(BindingSearchCandidate::Transition),
            Self::Parameter {
                parameter,
                candidates,
            } => candidates
                .get(index)
                .copied()
                .map(|identity| BindingSearchCandidate::Parameter {
                    parameter: *parameter,
                    identity,
                }),
            Self::Outcome => None,
        }
    }

    /// Returns whether the semantic candidate sequence has the expected size.
    #[must_use]
    pub fn is_valid_for_count(&self, candidate_count: u32) -> bool {
        match self {
            Self::Outcome => candidate_count == 2,
            Self::Transition(candidates) | Self::Parameter { candidates, .. } => {
                usize::try_from(candidate_count).ok() == Some(candidates.len())
                    && !candidates.is_empty()
                    && candidates.iter().collect::<BTreeSet<_>>().len() == candidates.len()
            }
        }
    }
}

/// Exact typed meaning of one selected RFC-0014 finite-search candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BindingSearchCandidate {
    /// Whether the typed effect applies.
    Outcome(bool),
    /// Stable identity of the selected state transition.
    Transition(ContentHash),
    /// Stable identity of the selected value for one typed effect parameter.
    Parameter {
        /// Effect parameter changed by the candidate.
        parameter: MappedEffectParameter,
        /// Stable identity of the selected typed value.
        identity: ContentHash,
    },
}

impl BindingSearchCandidate {
    fn tag(self) -> String {
        match self {
            Self::Outcome(value) => format!("outcome/{value}"),
            Self::Transition(identity) => format!("transition/{}", identity.to_hex()),
            Self::Parameter {
                parameter,
                identity,
            } => format!("parameter/{}/{}", parameter.as_str(), identity.to_hex()),
        }
    }
}

impl BindingSearchChoice {
    /// Materializes every finite candidate as a canonical explorer decision.
    #[must_use]
    pub fn override_decisions(&self, parent_branch: ContentHash) -> Vec<OverrideDecision> {
        if !self
            .candidate_semantics
            .is_valid_for_count(self.candidate_count)
        {
            return Vec::new();
        }
        (0..self.candidate_count)
            .filter_map(|candidate_index| {
                let semantic_tag = self.candidate_semantics.candidate(candidate_index)?.tag();
                Some(OverrideDecision {
                    point: SchedulingPoint {
                        key: format!(
                            "signal-fault/{}/{}/{}",
                            parent_branch.to_hex(),
                            self.id.content_hash().to_hex(),
                            self.candidates_digest.to_hex()
                        ),
                    },
                    choice: ChoiceTag {
                        name: format!("candidate/{candidate_index}/{semantic_tag}"),
                    },
                })
            })
            .collect()
    }
}

/// Identity of one finite search decision.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct SearchChoiceId(ContentHash);

impl SearchChoiceId {
    /// Builds the decision-domain-separated identity required for replay.
    #[must_use]
    pub fn new(
        program: ContentHash,
        binding: &FaultObjectId,
        opportunity: Option<ContentHash>,
        sample: ContentHash,
        candidates: ContentHash,
    ) -> Self {
        let material = format!(
            "program={};binding={};opportunity={};sample={};candidates={};",
            program.to_hex(),
            binding.as_str(),
            opportunity.map_or_else(|| String::from("none"), |value| value.to_hex()),
            sample.to_hex(),
            candidates.to_hex()
        );
        Self(ContentHash::from_canonical_material(
            "crucible.search-choice.v1",
            &material,
        ))
    }

    /// Returns the underlying content identity.
    #[must_use]
    pub const fn content_hash(self) -> ContentHash {
        self.0
    }

    /// Restores an identity from its authenticated content hash.
    #[must_use]
    pub const fn from_content_hash(hash: ContentHash) -> Self {
        Self(hash)
    }
}

/// Concrete explorer result retained for ordinary locked replay.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchOverride {
    /// Chosen zero-based candidate index.
    pub candidate_index: u32,
    /// Digest of the exact finite candidate set.
    pub candidates_digest: ContentHash,
    /// Typed candidate identity authenticated by the live binding policy.
    pub candidate: BindingSearchCandidate,
    /// Parent branch, if this choice forked an earlier search branch.
    pub parent_branch: Option<ContentHash>,
}

impl SearchOverride {
    /// Decodes one canonical signal-fault explorer decision.
    #[must_use]
    pub fn from_override_decision(decision: &OverrideDecision) -> Option<(SearchChoiceId, Self)> {
        let encoded = decision.point.key.strip_prefix("signal-fault/")?;
        let (encoded_parent, encoded) = encoded.split_once('/')?;
        let (choice_id, candidates_digest) = encoded.split_once('/')?;
        if candidates_digest.contains('/') {
            return None;
        }
        let parent_branch = parse_search_content_hash(encoded_parent)?;
        let encoded_candidate = decision.choice.name.strip_prefix("candidate/")?;
        let (candidate_index, typed_semantics) = encoded_candidate.split_once('/')?;
        let candidate = parse_typed_search_candidate(typed_semantics)?;
        let candidate_index = parse_canonical_candidate_index(candidate_index)?;
        Some((
            SearchChoiceId::from_content_hash(parse_search_content_hash(choice_id)?),
            Self {
                candidate_index,
                candidates_digest: parse_search_content_hash(candidates_digest)?,
                candidate,
                parent_branch: Some(parent_branch),
            },
        ))
    }
}

fn parse_typed_search_candidate(candidate: &str) -> Option<BindingSearchCandidate> {
    let mut parts = candidate.split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("outcome"), Some("false"), None, None) => {
            Some(BindingSearchCandidate::Outcome(false))
        }
        (Some("outcome"), Some("true"), None, None) => Some(BindingSearchCandidate::Outcome(true)),
        (Some("transition"), Some(identity), None, None) => {
            parse_search_content_hash(identity).map(BindingSearchCandidate::Transition)
        }
        (Some("parameter"), Some(parameter), Some(identity), None) => {
            Some(BindingSearchCandidate::Parameter {
                parameter: MappedEffectParameter::from_key(parameter)?,
                identity: parse_search_content_hash(identity)?,
            })
        }
        _ => None,
    }
}

/// Parses one canonical unsigned decimal candidate index.
pub(crate) fn parse_canonical_candidate_index(encoded: &str) -> Option<u32> {
    let value = encoded.parse::<u32>().ok()?;
    (value.to_string() == encoded).then_some(value)
}

pub(super) fn parse_search_content_hash(encoded: &str) -> Option<ContentHash> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(ContentHash { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_candidate_rejects_unknown_fields() {
        let candidate = BindingSearchCandidate::Parameter {
            parameter: MappedEffectParameter::DurationNanos,
            identity: ContentHash::from_bytes(b"typed-candidate"),
        };
        let mut encoded = serde_json::to_value(candidate)
            .unwrap_or_else(|error| panic!("candidate should encode: {error}"));
        let Some(fields) = encoded
            .get_mut("Parameter")
            .and_then(serde_json::Value::as_object_mut)
        else {
            panic!("parameter candidate must use the tagged object shape");
        };
        fields.insert(String::from("unknown"), serde_json::Value::Bool(true));

        assert!(serde_json::from_value::<BindingSearchCandidate>(encoded).is_err());
    }
}
