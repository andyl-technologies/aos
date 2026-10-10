//! Fixes the exact RFC-0025 obligation inventory independently of claim authors.

use crucible_node_contract::{ContentRef, canonical};

use super::schema::QualificationError;

const SOURCE_PINS: [(&str, &str); 12] = [
    (
        "00-conventions-and-model.md",
        "8194d29e631be07db32e6d196a28b12efe888ac106b92fa7fe0780d58051b5ae",
    ),
    (
        "01-node-contract.md",
        "7bacc549418c1de3ecd69294288a0714c64c275a9df35a1c154dff7a8a6f41df",
    ),
    (
        "02-ports-capabilities-and-admission.md",
        "4f1ae550f82b120fdb928932d28e279b99d4e5f491ed19dd4c6443a5596b064c",
    ),
    (
        "03-time-and-scheduling.md",
        "d32bdf36c174d81bc4054ffa2b6485773f9a3fb0db7e8706edf4638e32e799fa",
    ),
    (
        "04-quantized-and-physical-nodes.md",
        "e191d66acd126cd3b4303d13c28cf3773e4d981e04ee35598352527cbfb2c9e8",
    ),
    (
        "05-state-and-replay.md",
        "82c34d24ce55f5fc02dfcba40ec4973ce54cbd36b397241a5db91fd80b607b0a",
    ),
    (
        "06-provider-protocol-and-security.md",
        "5a977af6c0fa05b89eabd2f8876c2d6035571860590213529efc6e17b0a5739c",
    ),
    (
        "07-reference-profiles-and-examples.md",
        "2d6fa8402e0fd88a45a44e7325540307935dc5f710068c4f114521060534d149",
    ),
    (
        "08-conformance.md",
        "7ee8c6f5d676620cd483e29ad0d274c8d76bf241f9cf68ff5bdf92cb50fc0344",
    ),
    (
        "09-decisions-and-extensions.md",
        "70d0f4b34fef626605ae5a2c61a6dca78e68c44d6a7f4650f50721802a7bc511",
    ),
    (
        "reference/cnp-v1-core-types.md",
        "d9662b24b5a93e440f19c381f4e745fd0620c2932bea54a4c7d4d12e6df0277d",
    ),
    (
        "reference/cnp-v1-vectors.json",
        "50d98981e57f9b468720a4208ca86a8af79fb88411ea169a7e67997524c6581c",
    ),
];

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
    verify_original_sources()?;
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
    verify_original_sources()?;
    let ids: Vec<_> = REQUIREMENTS.lines().collect();
    if ids != normative_ids()
        || ids.is_empty()
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

fn verify_original_sources() -> Result<(), QualificationError> {
    use sha2::{Digest, Sha256};

    // These literal pins fix the original normative corpus independently of
    // provider claims, the generated requirement list and report authors.
    for ((name, source), (pinned_name, digest)) in SPECIFICATION.iter().zip(SOURCE_PINS) {
        if *name != pinned_name || format!("{:x}", Sha256::digest(source.as_bytes())) != digest {
            return Err(QualificationError::Refused(
                "changed original normative source",
            ));
        }
    }
    Ok(())
}
