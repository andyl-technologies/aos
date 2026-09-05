//! Validates versioned pin-resolution documents supplied with reviewed mutations.
//!
//! The JSON document carries a `schemaVersion` and a list of `resolutions`:
//!
//! ```json
//! {"schemaVersion":"aos.hub.pin-resolutions.v1","resolutions":[]}
//! ```

use crate::cli::HubMutationArgs;
use anyhow::{Context as _, Result};
use aos_remote::hub_types;
use serde::Deserialize;

const PIN_RESOLUTION_DOCUMENT_SCHEMA: &str = "aos.hub.pin-resolutions.v1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PinResolutionDocument {
    schema_version: String,
    resolutions: Vec<hub_types::PinResolution>,
}

/// Reads and validates the optional versioned pin-resolution document.
///
/// # Errors
///
/// Returns an error if the file cannot be read or fails schema and reference validation.
pub(super) fn read_pin_resolutions(
    mutation: &HubMutationArgs,
) -> Result<Vec<hub_types::PinResolution>> {
    let Some(path) = mutation.pin_resolution_file.as_deref() else {
        return Ok(Vec::new());
    };
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading pin resolutions from {}", path.display()))?;
    parse_pin_resolution_document(&bytes)
        .with_context(|| format!("decoding pin resolutions from {}", path.display()))
}

fn parse_pin_resolution_document(bytes: &[u8]) -> Result<Vec<hub_types::PinResolution>> {
    let document: PinResolutionDocument = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        document.schema_version == PIN_RESOLUTION_DOCUMENT_SCHEMA,
        "unsupported pin-resolution schemaVersion '{}'",
        document.schema_version
    );
    let mut pin_ids = std::collections::BTreeSet::new();
    for resolution in &document.resolutions {
        anyhow::ensure!(!resolution.pin_id.is_empty(), "pinId must not be empty");
        anyhow::ensure!(
            pin_ids.insert(resolution.pin_id.as_str()),
            "duplicate pin resolution for '{}'",
            resolution.pin_id
        );
        let source_version = match resolution.resolution.as_ref() {
            Some(hub_types::pin_resolution::Resolution::MoveEndpoint(action)) => {
                let target = action
                    .replacement_endpoint
                    .as_ref()
                    .context("moveEndpoint.replacementEndpoint is required")?;
                validate_cli_pin_target(target)?;
                action.expected_source_resource_version.as_str()
            }
            Some(hub_types::pin_resolution::Resolution::ReplaceRoute(action)) => {
                let target = action
                    .replacement_route
                    .as_ref()
                    .context("replaceRoute.replacementRoute is required")?;
                validate_cli_pin_target(target)?;
                action.expected_source_resource_version.as_str()
            }
            Some(hub_types::pin_resolution::Resolution::Release(action)) => {
                action.expected_source_resource_version.as_str()
            }
            None => anyhow::bail!("pin '{}' has no resolution action", resolution.pin_id),
        };
        anyhow::ensure!(
            source_version
                .parse::<u64>()
                .is_ok_and(|version| version > 0),
            "pin '{}' requires a positive expectedSourceResourceVersion",
            resolution.pin_id
        );
    }
    Ok(document.resolutions)
}

fn validate_cli_pin_target(target: &hub_types::PinResolutionTarget) -> Result<()> {
    anyhow::ensure!(
        !target.resource_kind.is_empty()
            && !target.resource_stable_id.is_empty()
            && target.resource_generation > 0
            && !target.configuration_digest.is_empty()
            && target
                .expected_resource_version
                .parse::<u64>()
                .is_ok_and(|version| version > 0),
        "replacement target requires kind, stable id, generation, digest, and positive resource version"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_resolution_document_is_versioned_and_strict() {
        let valid = br#"{
          "schemaVersion":"aos.hub.pin-resolutions.v1",
          "resolutions":[{
            "pinId":"pin:one",
            "release":{"expectedSourceResourceVersion":"7"}
          }]
        }"#;
        assert_eq!(parse_pin_resolution_document(valid).unwrap().len(), 1);
        assert!(
            parse_pin_resolution_document(
                br#"{"schemaVersion":"aos.hub.pin-resolutions.v2","resolutions":[]}"#
            )
            .is_err()
        );
        assert!(
            parse_pin_resolution_document(
                br#"{"schemaVersion":"aos.hub.pin-resolutions.v1","resolutions":[],"extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn pin_resolution_document_rejects_malformed_duplicate_and_unsealed_actions() {
        assert!(parse_pin_resolution_document(b"not-json").is_err());
        assert!(
            parse_pin_resolution_document(
                br#"{
              "schemaVersion":"aos.hub.pin-resolutions.v1",
              "resolutions":[
                {"pinId":"pin:one","release":{"expectedSourceResourceVersion":"7"}},
                {"pinId":"pin:one","release":{"expectedSourceResourceVersion":"8"}}
              ]
            }"#
            )
            .is_err()
        );
        assert!(
            parse_pin_resolution_document(
                br#"{
              "schemaVersion":"aos.hub.pin-resolutions.v1",
              "resolutions":[{
                "pinId":"pin:one",
                "release":{"expectedSourceResourceVersion":"0"}
              }]
            }"#
            )
            .is_err()
        );
    }
}
