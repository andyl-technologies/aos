//! Bounded local evidence closure, ordered dependencies before referring records.

use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, Validate, canonical};
use serde_json::{Map, Value};

use crate::ProviderError;

use super::Resources;

pub(super) fn control_closure(
    resources: &Resources,
    result: &Map<String, Value>,
) -> Result<Vec<ContentRef>, ProviderError> {
    let mut output = Vec::new();
    let mut visited = BTreeMap::new();
    visit(
        &Value::Object(result.clone()),
        &mut visited,
        &mut output,
        0,
        &|reference| {
            if resources.profile.content(reference).is_ok()
                || resources
                    .bootstrap
                    .installed_content
                    .iter()
                    .any(|installed| installed.reference == *reference)
            {
                // The admitting controller already owns these exact bytes:
                // they came from its independently measured profile or private
                // bootstrap. Only newly produced native control evidence is
                // promised after the corresponding response.
                return Ok(None);
            }
            if resources
                .profile
                .implementation
                .artifacts
                .iter()
                .any(|artifact| artifact.content == *reference)
            {
                // Executable artifacts are measured independently at launch;
                // the service never claims to ship its own executable image.
                return Ok(None);
            }
            Ok(Some(resources.content(reference)?.to_vec()))
        },
    )?;
    Ok(output)
}

fn visit(
    value: &Value,
    visited: &mut BTreeMap<String, ContentRef>,
    output: &mut Vec<ContentRef>,
    depth: usize,
    resolve: &impl Fn(&ContentRef) -> Result<Option<Vec<u8>>, ProviderError>,
) -> Result<(), ProviderError> {
    if depth > 64 {
        return Err(ProviderError::ResourceExhausted(
            "control evidence dependency depth",
        ));
    }
    match value {
        Value::Object(object)
            if object.contains_key("hash")
                && object.contains_key("length")
                && object.contains_key("media_type") =>
        {
            let reference: ContentRef = serde_json::from_value(value.clone())
                .map_err(crucible_node_contract::ContractError::from)?;
            reference.validate()?;
            if let Some(original) = visited.get(&reference.hash.digest) {
                if original != &reference {
                    return Err(ProviderError::Conflict(
                        "evidence reference changed metadata",
                    ));
                }
                return Ok(());
            }
            if visited.len() >= 4096 {
                return Err(ProviderError::ResourceExhausted(
                    "control evidence object count",
                ));
            }
            visited.insert(reference.hash.digest.clone(), reference.clone());
            let Some(bytes) = resolve(&reference)? else {
                return Ok(());
            };
            reference.verify(&bytes)?;
            if reference.media_type == "application/json" {
                let record = canonical::parse_json(&bytes, 16 * 1024 * 1024)?;
                visit(&record, visited, output, depth + 1, resolve)?;
            }
            output.push(reference);
        }
        Value::Object(object) => {
            for child in object.values() {
                visit(child, visited, output, depth, resolve)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                visit(child, visited, output, depth, resolve)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- invalid content closure fixtures must fail assertions.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dependencies_precede_receipts_and_shared_objects_are_sent_once() {
        let leaf_bytes = b"native parked evidence".to_vec();
        let leaf = canonical::content_ref(&leaf_bytes, "text/plain").unwrap();
        let record_bytes = canonical::canonical_json(&json!({"evidence":leaf})).unwrap();
        let record = canonical::content_ref(&record_bytes, "application/json").unwrap();
        let mut output = Vec::new();
        let mut visited = BTreeMap::new();

        visit(
            &json!({"record":record,"shared":leaf}),
            &mut visited,
            &mut output,
            0,
            &|reference| {
                Ok(Some(if reference == &leaf {
                    leaf_bytes.clone()
                } else if reference == &record {
                    record_bytes.clone()
                } else {
                    return Err(ProviderError::Correlation("missing evidence"));
                }))
            },
        )
        .unwrap();

        assert_eq!(output, vec![leaf, record]);
    }

    #[test]
    fn missing_or_changed_evidence_refuses_before_transfer() {
        let reference = canonical::content_ref(b"original", "text/plain").unwrap();
        let value = json!({"receipt":reference});
        let mut output = Vec::new();
        assert!(
            visit(&value, &mut BTreeMap::new(), &mut output, 0, &|_| Ok(Some(
                b"replacement".to_vec()
            )))
            .is_err()
        );
        assert!(output.is_empty());
        assert!(
            visit(&value, &mut BTreeMap::new(), &mut output, 0, &|_| Err(
                ProviderError::Correlation("missing evidence")
            ))
            .is_err()
        );
    }
}
