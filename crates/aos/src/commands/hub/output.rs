//! Formats stable versioned JSON envelopes and readable topology responses.
//!
//! Machine output uses the following envelope shape:
//!
//! ```json
//! {"schema_version":"aos.hub.cli/v1","kind":"example","data":{}}
//! ```

use anyhow::Result;
use aos_core::output::Printer;
use serde::Serialize;

/// Version of the stable JSON envelope emitted by every `aos hub` command.
const HUB_CLI_JSON_SCHEMA: &str = "aos.hub.cli/v1";

/// Converts canonical Connect-JSON lowerCamelCase keys to the CLI's stable
/// snake_case machine-output convention.
fn snake_case_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) => serde_json::Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let mut converted = String::with_capacity(key.len());
                    for character in key.chars() {
                        if character.is_ascii_uppercase() {
                            converted.push('_');
                            converted.push(character.to_ascii_lowercase());
                        } else {
                            converted.push(character);
                        }
                    }
                    (converted, snake_case_json(value))
                })
                .collect(),
        ),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(snake_case_json).collect())
        }
        scalar => scalar,
    }
}

/// Wraps Hub machine output in the stable, explicitly versioned CLI schema.
fn hub_json_envelope(kind: &str, data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema_version": HUB_CLI_JSON_SCHEMA,
        "kind": kind,
        "data": snake_case_json(data),
    })
}

/// Prints one Hub JSON envelope when machine output is active.
pub(super) fn print_hub_json(printer: &Printer, kind: &str, data: serde_json::Value) -> bool {
    printer.json_if_active(&hub_json_envelope(kind, data))
}

/// Derives the stable CLI message kind from a response type name.
pub(super) fn topology_message_kind<T>() -> String {
    let name = std::any::type_name::<T>()
        .rsplit("::")
        .next()
        .unwrap_or("hub_response");
    let mut result = String::with_capacity(name.len());
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() && index != 0 {
            result.push('_');
        }
        result.push(character.to_ascii_lowercase());
    }
    result
}

/// Prints one generated Connect response in stable CLI form.
///
/// # Errors
///
/// Returns an error if the response cannot be serialized as JSON.
pub(in crate::commands) fn print_topology_message<T: Serialize>(
    printer: &Printer,
    message: &T,
) -> Result<()> {
    let value = snake_case_json(serde_json::to_value(message)?);
    if print_hub_json(printer, &topology_message_kind::<T>(), value.clone()) {
        return Ok(());
    }
    printer.plain(&serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_remote::hub_types;

    #[test]
    fn hub_json_envelope_has_a_stable_versioned_shape() {
        assert_eq!(
            hub_json_envelope(
                "placement_list",
                serde_json::json!({
                    "nextPageToken": "next",
                    "items": [{ "resourceVersion": "7" }],
                })
            ),
            serde_json::json!({
                "schema_version": "aos.hub.cli/v1",
                "kind": "placement_list",
                "data": {
                    "next_page_token": "next",
                    "items": [{ "resource_version": "7" }],
                },
            })
        );
    }

    #[test]
    fn hub_json_envelope_discriminates_retained_and_topology_families() {
        assert_eq!(
            hub_json_envelope(
                "login",
                serde_json::json!({
                    "accessToken": "secret",
                    "tokenType": "Bearer",
                    "expiresIn": 300,
                }),
            ),
            serde_json::json!({
                "schema_version": "aos.hub.cli/v1",
                "kind": "login",
                "data": {
                    "access_token": "secret",
                    "token_type": "Bearer",
                    "expires_in": 300,
                },
            }),
        );
        assert_eq!(
            topology_message_kind::<hub_types::ListOrganizationsResponse>(),
            "list_organizations_response",
        );
        assert_eq!(
            topology_message_kind::<hub_types::TopologyPlanResponse>(),
            "topology_plan_response",
        );
    }

    #[test]
    fn connect_json_is_recursively_normalized_for_cli_output() {
        assert_eq!(
            snake_case_json(serde_json::json!({
                "nextPageToken": "next",
                "bindings": [{ "resourceVersion": "7" }],
            })),
            serde_json::json!({
                "next_page_token": "next",
                "bindings": [{ "resource_version": "7" }],
            })
        );
    }
}
