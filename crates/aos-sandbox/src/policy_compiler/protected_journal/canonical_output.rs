//! Strict data-only decoding of the compiler's existing JSON output profiles.
//!
//! The producer serializes constructor-normalized structs in declaration
//! order, not lexical map-key order. Private wire claims preserve that order
//! and reject unknown/duplicate fields before exact bounded reserialization.
//! They never deserialize authenticated compiler inputs or mint policy proof.
//!
//! ```text
//! u64be(domain-length) || existing-domain || u64be(JSON-length) || typed-JSON
//! ```

use aos_sandbox_core::{
    AttachmentSlotId, MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, RelativePath,
    ResourceId, ResourceKind, Selector, format::descriptor_for_bytes, model::ViewMutation,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{DIAGNOSTICS_DOMAIN, PolicyCompilerJournalErrorV1};
use crate::policy_compiler::{
    advisory::{
        AdvisoryActionV1, AdvisoryDegradationV1, AdvisoryKindV1, AdvisoryStatusV1,
        canonicalize_advisory_actions,
    },
    model::{
        ExplanationDecisionV1, ExplanationReasonV1, ExplanationStageV1, InputSourceV1,
        MAXIMUM_ADVISORY_RULES_PER_LAYER, MAXIMUM_CANONICAL_OBJECT_BYTES,
        MAXIMUM_EXPLANATION_ENTRIES_PER_STAGE, MAXIMUM_NAMESPACE_RULES_PER_LAYER,
        MAXIMUM_POLICY_ANCESTORS, canonical_bytes, digest,
    },
    namespace::{
        LogicalSourceV1, NamespaceCompositionV1, NamespaceExecutionClassV1, NamespaceGraphSchemaV1,
        NamespacePresentationFeatureV1, NamespaceRuleV1, NamespaceSourceClassV1, ViewExecutionV1,
        validate_portable_namespace_rule_order,
    },
};

const NAMESPACE_DOMAIN: &[u8] = b"aos.sandbox.portable-namespace-graph.v1";
const ADVISORY_DOMAIN: &[u8] = b"aos.sandbox.portable-advisory-program.v1";

#[cfg(test)]
#[path = "canonical_output_tests.rs"]
mod tests;

fn invalid() -> PolicyCompilerJournalErrorV1 {
    PolicyCompilerJournalErrorV1::NonCanonicalPublication
}

fn decode_exact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    domain: &'static [u8],
) -> Result<T, PolicyCompilerJournalErrorV1> {
    if bytes.len() < 16 || bytes.len() > MAXIMUM_CANONICAL_OBJECT_BYTES {
        return Err(invalid());
    }
    let domain_length = usize::try_from(u64::from_be_bytes(
        bytes[..8].try_into().map_err(|_| invalid())?,
    ))
    .map_err(|_| invalid())?;
    let domain_end = 8_usize.checked_add(domain_length).ok_or_else(invalid)?;
    let length_end = domain_end.checked_add(8).ok_or_else(invalid)?;
    if bytes.get(8..domain_end) != Some(domain) || length_end > bytes.len() {
        return Err(invalid());
    }
    let length = usize::try_from(u64::from_be_bytes(
        bytes[domain_end..length_end]
            .try_into()
            .map_err(|_| invalid())?,
    ))
    .map_err(|_| invalid())?;
    if length == 0 || length_end.checked_add(length) != Some(bytes.len()) {
        return Err(invalid());
    }

    let claims: T = serde_json::from_slice(&bytes[length_end..]).map_err(|_| invalid())?;
    if canonical_bytes(domain, &claims)? != bytes {
        return Err(invalid());
    }
    Ok(claims)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutableSourceClaims {
    handle: ResourceId,
    selector: Selector,
    descriptor: ObjectDescriptor,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LogicalSourceClaims {
    handle: ResourceId,
    resource_kind: ResourceKind,
    selector: Selector,
    class: NamespaceSourceClassV1,
    execution_class: NamespaceExecutionClassV1,
    executable_source: Option<ExecutableSourceClaims>,
}

impl LogicalSourceClaims {
    // This nonexecuting declaration exists only to reuse pure DAG ordering.
    // Claimed executable evidence never becomes AuthenticatedExecutableSource.
    fn ordering_declaration(&self) -> Result<LogicalSourceV1, PolicyCompilerJournalErrorV1> {
        let declaration = LogicalSourceV1::new(
            self.handle,
            self.resource_kind,
            self.selector.clone(),
            self.class,
            None,
        )
        .map_err(|_| invalid())?;
        match (&self.executable_source, self.execution_class) {
            (None, NamespaceExecutionClassV1::DataOnly) => {}
            (Some(evidence), NamespaceExecutionClassV1::VerifiedPackageOrTool) => {
                if self.class != NamespaceSourceClassV1::Immutable
                    || !matches!(&self.selector, Selector::Tree { .. })
                    || evidence.handle != self.handle
                    || evidence.selector != self.selector
                {
                    return Err(invalid());
                }
                let classification = canonical_bytes(
                    b"aos.sandbox.executable-source-classification.v1",
                    &(self.handle, &self.selector, self.execution_class),
                )?;
                let media =
                    MediaType::new(PortableMediaType::Content.as_str()).map_err(|_| invalid())?;
                if evidence.descriptor != descriptor_for_bytes(media, &classification) {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        Ok(declaration)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompositionClaims {
    output: ResourceId,
    inputs: Vec<ResourceId>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
enum NamespaceRuleClaims {
    Source(LogicalSourceClaims),
    Compose(CompositionClaims),
    Include {
        source: ResourceId,
        prefix: RelativePath,
        execution: ViewExecutionV1,
    },
    Exclude {
        prefix: RelativePath,
    },
    Attach {
        source: ResourceId,
        destination: AttachmentSlotId,
        mode: ViewMutation,
        execution: ViewExecutionV1,
    },
    Present {
        prefix: RelativePath,
        presentation: NamespacePresentationFeatureV1,
    },
}

impl NamespaceRuleClaims {
    fn ordering_rule(&self) -> Result<NamespaceRuleV1, PolicyCompilerJournalErrorV1> {
        Ok(match self {
            Self::Source(source) => NamespaceRuleV1::Source(source.ordering_declaration()?),
            Self::Compose(node) => NamespaceRuleV1::Compose(
                NamespaceCompositionV1::new(node.output, node.inputs.clone())
                    .map_err(|_| invalid())?,
            ),
            Self::Include {
                source,
                prefix,
                execution,
            } => NamespaceRuleV1::Include {
                source: *source,
                prefix: prefix.clone(),
                execution: *execution,
            },
            Self::Exclude { prefix } => NamespaceRuleV1::Exclude {
                prefix: prefix.clone(),
            },
            Self::Attach {
                source,
                destination,
                mode,
                execution,
            } => NamespaceRuleV1::Attach {
                source: *source,
                destination: *destination,
                mode: *mode,
                execution: *execution,
            },
            Self::Present {
                prefix,
                presentation,
            } => NamespaceRuleV1::Present {
                prefix: prefix.clone(),
                presentation: *presentation,
            },
        })
    }
}

/// Checks the exact portable graph shape and pure canonical rule ordering.
///
/// # Errors
/// Rejects malformed framing/fields, contradictory source claims or rule order.
pub(super) fn validate_namespace(bytes: &[u8]) -> Result<(), PolicyCompilerJournalErrorV1> {
    let (_, claims): (NamespaceGraphSchemaV1, Vec<NamespaceRuleClaims>) =
        decode_exact(bytes, NAMESPACE_DOMAIN)?;
    if claims.len() > MAXIMUM_NAMESPACE_RULES_PER_LAYER {
        return Err(invalid());
    }
    let ordering_rules = claims
        .iter()
        .map(NamespaceRuleClaims::ordering_rule)
        .collect::<Result<Vec<_>, _>>()?;
    validate_portable_namespace_rule_order(&ordering_rules).map_err(|_| invalid())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdvisoryActionClaims {
    kind: AdvisoryKindV1,
    source: ResourceId,
    resource_kind: ResourceKind,
    target: Selector,
    bounded_value: u64,
    priority: u16,
    degradation: AdvisoryDegradationV1,
}

impl AdvisoryActionClaims {
    fn action(&self) -> AdvisoryActionV1 {
        AdvisoryActionV1::new(
            self.kind,
            self.source,
            self.resource_kind,
            self.target.clone(),
            self.bounded_value,
            self.priority,
            self.degradation,
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdvisoryDecisionClaims {
    action: AdvisoryActionClaims,
    status: AdvisoryStatusV1,
    effective_value: Option<u64>,
}

/// Checks the exact decision shape and existing specificity/priority ordering.
///
/// # Errors
/// Rejects malformed framing/fields, contradictory decisions or action order.
pub(super) fn validate_advisory(bytes: &[u8]) -> Result<(), PolicyCompilerJournalErrorV1> {
    let claims: Vec<AdvisoryDecisionClaims> = decode_exact(bytes, ADVISORY_DOMAIN)?;
    if claims.len() > MAXIMUM_ADVISORY_RULES_PER_LAYER {
        return Err(invalid());
    }
    for decision in &claims {
        if decision.action.source.as_bytes() == &[0; 16]
            || match (decision.status, decision.effective_value) {
                (AdvisoryStatusV1::Active, Some(value)) => value > decision.action.bounded_value,
                (AdvisoryStatusV1::Active, None) => true,
                (_, value) => value.is_some(),
            }
        {
            return Err(invalid());
        }
    }
    let actions: Vec<_> = claims
        .iter()
        .map(|decision| decision.action.action())
        .collect();
    if canonicalize_advisory_actions(actions.clone())? != actions {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExplanationEntryClaims {
    stage: ExplanationStageV1,
    decision: ExplanationDecisionV1,
    reason: ExplanationReasonV1,
    source: InputSourceV1,
    subject: ObjectDigest,
    causes: Vec<InputSourceV1>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExplanationStageClaims {
    stage: ExplanationStageV1,
    entries: Vec<ExplanationEntryClaims>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExplanationClaims {
    commitment: ObjectDigest,
    stages: Vec<ExplanationStageClaims>,
}

/// Reproduces the complete seven-stage explanation's existing commitment.
///
/// # Errors
/// Rejects malformed framing/fields, stage/bound violations or commitment mismatch.
pub(super) fn validate_diagnostics(bytes: &[u8]) -> Result<(), PolicyCompilerJournalErrorV1> {
    let claims: ExplanationClaims = decode_exact(bytes, DIAGNOSTICS_DOMAIN)?;
    if claims.stages.len() != 7
        || !claims
            .stages
            .windows(2)
            .all(|pair| pair[0].stage < pair[1].stage)
        || claims.stages.iter().any(|stage| {
            stage.entries.len() > MAXIMUM_EXPLANATION_ENTRIES_PER_STAGE
                || stage.entries.iter().any(|entry| {
                    entry.stage != stage.stage
                        || !valid_input_source(entry.source)
                        || entry.causes.iter().any(|cause| !valid_input_source(*cause))
                })
        })
        || digest(b"aos.sandbox.policy-explanation.v2", &claims.stages)? != claims.commitment
    {
        return Err(invalid());
    }
    Ok(())
}

fn valid_input_source(source: InputSourceV1) -> bool {
    !matches!(source, InputSourceV1::Ancestor { ordinal }
        if usize::from(ordinal) >= MAXIMUM_POLICY_ANCESTORS)
}
