//! Typed campaign domains for RFC-0014 signal-fault search choices.
//!
//! This module owns the lossless conversion between runtime candidate tags and
//! campaign Boolean or discrete values. Index-only candidate tags have no
//! reconstructable RFC-0014 meaning and are rejected at this boundary.

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::{
    AlternativeId, BooleanDomain, CampaignCodecError, CampaignHash, ChoiceDomain, ChoiceValue,
    DiscreteAlternative, DiscreteDomain,
};

use super::SignalFaultSelectableError;
use crate::model::{
    BindingSearchCandidateSemantics, MappedEffectParameter, parse_canonical_candidate_index,
};

const SIGNAL_FAULT_DOMAIN_VERSION: u32 = 1;
const SIGNAL_FAULT_OUTCOME_DECLARATION: &str = "signal-fault-event-outcome";
const SIGNAL_FAULT_TRANSITION_DECLARATION: &str = "signal-fault-event-transition";
const SIGNAL_FAULT_PARAMETER_DECLARATION: &str = "signal-fault-event-parameter";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SignalFaultChoiceSemantics {
    Outcome,
    Transition(Vec<CampaignHash>),
    Parameter {
        parameter: MappedEffectParameter,
        candidates: Vec<CampaignHash>,
    },
}

pub(super) enum ParsedCandidateSemantics {
    Outcome(bool),
    Transition(CampaignHash),
    Parameter(MappedEffectParameter, CampaignHash),
}

pub(super) fn semantics_from_runtime(
    semantics: &BindingSearchCandidateSemantics,
) -> SignalFaultChoiceSemantics {
    match semantics {
        BindingSearchCandidateSemantics::Outcome => SignalFaultChoiceSemantics::Outcome,
        BindingSearchCandidateSemantics::Transition(candidates) => {
            SignalFaultChoiceSemantics::Transition(
                candidates
                    .iter()
                    .map(|candidate| CampaignHash::from_bytes(candidate.bytes))
                    .collect(),
            )
        }
        BindingSearchCandidateSemantics::Parameter {
            parameter,
            candidates,
        } => SignalFaultChoiceSemantics::Parameter {
            parameter: *parameter,
            candidates: candidates
                .iter()
                .map(|candidate| CampaignHash::from_bytes(candidate.bytes))
                .collect(),
        },
    }
}

impl SignalFaultChoiceSemantics {
    pub(super) fn declaration_name(&self) -> &'static str {
        match self {
            Self::Outcome => SIGNAL_FAULT_OUTCOME_DECLARATION,
            Self::Transition(_) => SIGNAL_FAULT_TRANSITION_DECLARATION,
            Self::Parameter { .. } => SIGNAL_FAULT_PARAMETER_DECLARATION,
        }
    }

    pub(super) fn semantic_tags(&self) -> BTreeSet<String> {
        let mut tags = BTreeSet::from([String::from("hierarchical-promotion"), self.tag()]);
        if let Self::Parameter { parameter, .. } = self {
            tags.insert(format!("parameter-{}", parameter.as_str()));
        }
        tags
    }

    pub(super) fn candidate_count(&self) -> Result<u32, SignalFaultSelectableError> {
        let count = match self {
            Self::Outcome => 2,
            Self::Transition(candidates) | Self::Parameter { candidates, .. } => candidates.len(),
        };
        u32::try_from(count).map_err(|_| SignalFaultSelectableError::CandidateLimitExceeded)
    }

    pub(super) fn validate_count(
        &self,
        candidate_count: u32,
    ) -> Result<(), SignalFaultSelectableError> {
        if self.candidate_count()? != candidate_count {
            return Err(SignalFaultSelectableError::MixedCandidateSemantics);
        }
        if let Self::Transition(candidates) | Self::Parameter { candidates, .. } = self
            && (candidates.iter().collect::<BTreeSet<_>>().len() != candidates.len()
                || candidates.iter().any(|candidate| {
                    AlternativeId::from_hash(*candidate) == unmodified_alternative()
                }))
        {
            return Err(SignalFaultSelectableError::MixedCandidateSemantics);
        }
        Ok(())
    }

    pub(super) fn domain(&self) -> Result<ChoiceDomain, CampaignCodecError> {
        match self {
            Self::Outcome => Ok(ChoiceDomain::Boolean(BooleanDomain::new(
                SIGNAL_FAULT_DOMAIN_VERSION,
            )?)),
            Self::Transition(candidates) | Self::Parameter { candidates, .. } => {
                let mut alternatives = BTreeMap::new();
                for (index, candidate) in candidates.iter().enumerate() {
                    let id = AlternativeId::from_hash(*candidate);
                    alternatives.insert(
                        id,
                        DiscreteAlternative::new(id, format!("candidate-{index:08x}"), None)?,
                    );
                }
                let unmodified = unmodified_alternative();
                alternatives.insert(
                    unmodified,
                    DiscreteAlternative::new(unmodified, "unmodified", None)?,
                );
                Ok(ChoiceDomain::Discrete(DiscreteDomain::new(
                    SIGNAL_FAULT_DOMAIN_VERSION,
                    alternatives,
                )?))
            }
        }
    }

    pub(super) fn default_value(&self) -> ChoiceValue {
        match self {
            Self::Outcome => ChoiceValue::Boolean(false),
            Self::Transition(_) | Self::Parameter { .. } => {
                ChoiceValue::Discrete(unmodified_alternative())
            }
        }
    }

    pub(super) fn choice_value(
        &self,
        candidate_index: u32,
    ) -> Result<ChoiceValue, SignalFaultSelectableError> {
        let index = usize::try_from(candidate_index)
            .map_err(|_| SignalFaultSelectableError::CandidateOutsideDomain)?;
        match self {
            Self::Outcome if candidate_index < 2 => Ok(ChoiceValue::Boolean(candidate_index == 1)),
            Self::Transition(candidates) | Self::Parameter { candidates, .. } => {
                let id = if index == candidates.len() {
                    unmodified_alternative()
                } else {
                    candidates
                        .get(index)
                        .copied()
                        .map(AlternativeId::from_hash)
                        .ok_or(SignalFaultSelectableError::CandidateOutsideDomain)?
                };
                Ok(ChoiceValue::Discrete(id))
            }
            Self::Outcome => Err(SignalFaultSelectableError::CandidateOutsideDomain),
        }
    }

    pub(super) fn candidate_index(
        &self,
        value: &ChoiceValue,
    ) -> Result<u32, SignalFaultSelectableError> {
        match (self, value) {
            (Self::Outcome, ChoiceValue::Boolean(value)) => Ok(u32::from(*value)),
            (
                Self::Transition(candidates) | Self::Parameter { candidates, .. },
                ChoiceValue::Discrete(id),
            ) if *id == unmodified_alternative() => self.candidate_count(),
            (
                Self::Transition(candidates) | Self::Parameter { candidates, .. },
                ChoiceValue::Discrete(id),
            ) => candidates
                .iter()
                .position(|candidate| AlternativeId::from_hash(*candidate) == *id)
                .and_then(|index| u32::try_from(index).ok())
                .ok_or(SignalFaultSelectableError::CandidateOutsideDomain),
            _ => Err(SignalFaultSelectableError::CandidateOutsideDomain),
        }
    }

    pub(super) fn runtime_semantics(&self) -> BindingSearchCandidateSemantics {
        match self {
            Self::Outcome => BindingSearchCandidateSemantics::Outcome,
            Self::Transition(candidates) => BindingSearchCandidateSemantics::Transition(
                candidates.iter().copied().map(content_hash).collect(),
            ),
            Self::Parameter {
                parameter,
                candidates,
            } => BindingSearchCandidateSemantics::Parameter {
                parameter: *parameter,
                candidates: candidates.iter().copied().map(content_hash).collect(),
            },
        }
    }

    fn tag(&self) -> String {
        match self {
            Self::Outcome => String::from("event-outcome"),
            Self::Transition(_) => String::from("event-transition"),
            Self::Parameter { .. } => String::from("event-parameter"),
        }
    }
}

pub(super) fn parse_candidate_semantics(
    choice_name: &str,
    expected_index: usize,
) -> Result<ParsedCandidateSemantics, SignalFaultSelectableError> {
    let mut parts = choice_name.split('/');
    if parts.next() != Some("candidate")
        || parts.next().and_then(parse_canonical_candidate_index)
            != u32::try_from(expected_index).ok()
    {
        return Err(SignalFaultSelectableError::NonDenseCandidates);
    }
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("outcome"), Some("false"), None, None) => {
            Ok(ParsedCandidateSemantics::Outcome(false))
        }
        (Some("outcome"), Some("true"), None, None) => Ok(ParsedCandidateSemantics::Outcome(true)),
        (Some("transition"), Some(identity), None, None) => Ok(
            ParsedCandidateSemantics::Transition(CampaignHash::parse(identity)?),
        ),
        (Some("parameter"), Some(parameter), Some(identity), None) => {
            Ok(ParsedCandidateSemantics::Parameter(
                parse_parameter(parameter)?,
                CampaignHash::parse(identity)?,
            ))
        }
        _ => Err(SignalFaultSelectableError::UntypedCandidate),
    }
}

pub(super) fn collect_candidate_semantics(
    candidates: Vec<ParsedCandidateSemantics>,
) -> Result<SignalFaultChoiceSemantics, SignalFaultSelectableError> {
    match candidates.as_slice() {
        [ParsedCandidateSemantics::Outcome(false), ParsedCandidateSemantics::Outcome(true)] => {
            Ok(SignalFaultChoiceSemantics::Outcome)
        }
        _ if candidates
            .iter()
            .all(|candidate| matches!(candidate, ParsedCandidateSemantics::Transition(_))) => {
            Ok(SignalFaultChoiceSemantics::Transition(
                candidates
                    .into_iter()
                    .filter_map(|candidate| match candidate {
                        ParsedCandidateSemantics::Transition(identity) => Some(identity),
                        _ => None,
                    })
                    .collect(),
            ))
        }
        [ParsedCandidateSemantics::Parameter(parameter, _), ..]
            if candidates.iter().all(|candidate| {
                matches!(candidate, ParsedCandidateSemantics::Parameter(other, _) if other == parameter)
            }) =>
        {
            Ok(SignalFaultChoiceSemantics::Parameter {
                parameter: *parameter,
                candidates: candidates
                    .into_iter()
                    .filter_map(|candidate| match candidate {
                        ParsedCandidateSemantics::Parameter(_, identity) => Some(identity),
                        _ => None,
                    })
                    .collect(),
            })
        }
        _ => Err(SignalFaultSelectableError::MixedCandidateSemantics),
    }
}

pub(super) fn semantics_from_records(
    declaration_name: &str,
    semantic_tags: &BTreeSet<String>,
    domain: &ChoiceDomain,
) -> Result<SignalFaultChoiceSemantics, SignalFaultSelectableError> {
    match (declaration_name, domain) {
        (SIGNAL_FAULT_OUTCOME_DECLARATION, ChoiceDomain::Boolean(boolean))
            if boolean.semantic_version() == SIGNAL_FAULT_DOMAIN_VERSION =>
        {
            Ok(SignalFaultChoiceSemantics::Outcome)
        }
        (name, ChoiceDomain::Discrete(discrete))
            if name == SIGNAL_FAULT_TRANSITION_DECLARATION
                || name == SIGNAL_FAULT_PARAMETER_DECLARATION =>
        {
            if discrete.semantic_version() != SIGNAL_FAULT_DOMAIN_VERSION {
                return Err(SignalFaultSelectableError::ProducerContractMismatch);
            }
            let candidates = discrete_candidates(discrete)?;
            if name == SIGNAL_FAULT_TRANSITION_DECLARATION {
                Ok(SignalFaultChoiceSemantics::Transition(candidates))
            } else {
                let parameters = semantic_tags
                    .iter()
                    .filter_map(|tag| tag.strip_prefix("parameter-"))
                    .map(parse_parameter)
                    .collect::<Result<Vec<_>, _>>()?;
                let [parameter] = parameters.as_slice() else {
                    return Err(SignalFaultSelectableError::ProducerContractMismatch);
                };
                Ok(SignalFaultChoiceSemantics::Parameter {
                    parameter: *parameter,
                    candidates,
                })
            }
        }
        _ => Err(SignalFaultSelectableError::ProducerContractMismatch),
    }
}

fn discrete_candidates(
    domain: &DiscreteDomain,
) -> Result<Vec<CampaignHash>, SignalFaultSelectableError> {
    let mut indexed = Vec::new();
    let mut saw_unmodified = false;
    for alternative in domain.alternatives().values() {
        if alternative.id() == unmodified_alternative() && alternative.label() == "unmodified" {
            saw_unmodified = true;
            continue;
        }
        let encoded = alternative
            .label()
            .strip_prefix("candidate-")
            .ok_or(SignalFaultSelectableError::ProducerContractMismatch)?;
        let index = usize::from_str_radix(encoded, 16)
            .map_err(|_| SignalFaultSelectableError::ProducerContractMismatch)?;
        indexed.push((index, alternative.id().as_hash()));
    }
    indexed.sort_by_key(|(index, _)| *index);
    if !saw_unmodified
        || indexed.is_empty()
        || indexed
            .iter()
            .enumerate()
            .any(|(expected, (actual, _))| expected != *actual)
    {
        return Err(SignalFaultSelectableError::ProducerContractMismatch);
    }
    Ok(indexed.into_iter().map(|(_, identity)| identity).collect())
}

fn unmodified_alternative() -> AlternativeId {
    AlternativeId::from_hash(CampaignHash::derive(
        "crucible.signal-fault-unmodified.v1",
        b"unmodified",
    ))
}

fn content_hash(hash: CampaignHash) -> crate::ContentHash {
    crate::ContentHash {
        bytes: hash.as_bytes(),
    }
}

fn parse_parameter(value: &str) -> Result<MappedEffectParameter, SignalFaultSelectableError> {
    MappedEffectParameter::from_key(value)
        .ok_or(SignalFaultSelectableError::ProducerContractMismatch)
}
