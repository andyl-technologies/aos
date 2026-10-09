//! Fixes the exact RFC-0025 obligation inventory independently of claim authors.

use crucible_node_contract::{ContentRef, canonical};

use super::schema::QualificationError;

const REQUIREMENTS: &str = include_str!("requirements.txt");

const SPECIFICATION: [(&str, &str); 12] = [
    (
        "00-conventions-and-model.md",
        include_str!(
            "../../../../docs/rfcs/0025-crucible-node-contract/00-conventions-and-model.md"
        ),
    ),
    (
        "01-node-contract.md",
        include_str!("../../../../docs/rfcs/0025-crucible-node-contract/01-node-contract.md"),
    ),
    (
        "02-ports-capabilities-and-admission.md",
        include_str!(
            "../../../../docs/rfcs/0025-crucible-node-contract/02-ports-capabilities-and-admission.md"
        ),
    ),
    (
        "03-time-and-scheduling.md",
        include_str!("../../../../docs/rfcs/0025-crucible-node-contract/03-time-and-scheduling.md"),
    ),
    (
        "04-quantized-and-physical-nodes.md",
        include_str!(
            "../../../../docs/rfcs/0025-crucible-node-contract/04-quantized-and-physical-nodes.md"
        ),
    ),
    (
        "05-state-and-replay.md",
        include_str!("../../../../docs/rfcs/0025-crucible-node-contract/05-state-and-replay.md"),
    ),
    (
        "06-provider-protocol-and-security.md",
        include_str!(
            "../../../../docs/rfcs/0025-crucible-node-contract/06-provider-protocol-and-security.md"
        ),
    ),
    (
        "07-reference-profiles-and-examples.md",
        include_str!(
            "../../../../docs/rfcs/0025-crucible-node-contract/07-reference-profiles-and-examples.md"
        ),
    ),
    (
        "08-conformance.md",
        include_str!("../../../../docs/rfcs/0025-crucible-node-contract/08-conformance.md"),
    ),
    (
        "09-decisions-and-extensions.md",
        include_str!(
            "../../../../docs/rfcs/0025-crucible-node-contract/09-decisions-and-extensions.md"
        ),
    ),
    (
        "reference/cnp-v1-core-types.md",
        include_str!(
            "../../../../docs/rfcs/0025-crucible-node-contract/reference/cnp-v1-core-types.md"
        ),
    ),
    (
        "reference/cnp-v1-vectors.json",
        include_str!(
            "../../../../docs/rfcs/0025-crucible-node-contract/reference/cnp-v1-vectors.json"
        ),
    ),
];

/// Returns the exact compiled normative source bytes and their content identity.
///
/// # Errors
/// Returns an error when the bounded canonical source inventory cannot encode.
pub fn normative_specification() -> Result<(ContentRef, Vec<u8>), QualificationError> {
    let value = serde_json::json!({
        "schema": "crucible.rfc0025.normative-source.v1",
        "sources": SPECIFICATION,
    });
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > 1024 * 1024 {
        return Err(QualificationError::Refused(
            "compiled normative source budget",
        ));
    }
    let reference = canonical::content_ref(&bytes, "application/json")?;
    Ok((reference, bytes))
}

/// Returns the source-owned requirement inventory and its content identity.
///
/// # Errors
/// Returns an error if the compiled catalog violates its fixed sorted bounds.
pub fn requirement_catalog() -> Result<(ContentRef, Vec<&'static str>), QualificationError> {
    let ids: Vec<_> = REQUIREMENTS.lines().collect();
    if ids.is_empty()
        || ids.len() > 4096
        || ids.windows(2).any(|pair| pair[0] >= pair[1])
        || ids.iter().any(|id| {
            id.len() > 64
                || !id.starts_with("CN-")
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(QualificationError::Refused(
            "invalid compiled requirement catalog",
        ));
    }
    let reference = canonical::content_ref(REQUIREMENTS.as_bytes(), "text/plain")?;
    Ok((reference, ids))
}

#[cfg(test)]
pub(super) fn normative_ids() -> Vec<&'static str> {
    let mut ids: Vec<_> = SPECIFICATION
        .iter()
        .flat_map(|(_, source)| {
            source.split("**[").skip(1).filter_map(|suffix| {
                let (id, _) = suffix.split_once("]**")?;
                id.starts_with("CN-").then_some(id)
            })
        })
        .collect();
    ids.sort_unstable();
    ids
}
