//! Semantic early-network values derived from the canonical ability schema.
//!
//! The signed `aos.network.configuration` interface remains the sole wire
//! contract. This module converts a value that the ability runtime already
//! checked against that interface into the small semantic form used by
//! authorization and backend code. It deliberately defines no parallel serde
//! document, defaults, method set, or schema validation policy.

use anyhow::{Context, Result, bail};
use aos_ability_model::AbilityValue;
use serde_json::{Map, Value};

/// Selects the exact link authorized for early network bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BootstrapLinkSelector {
    /// Selects one link by stable interface name.
    Name(String),
    /// Selects one link by stable MAC address.
    Mac(String),
}

/// Carries normalized early-network facts between checked ability operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapNetwork {
    /// Selects the exact early-boot link.
    pub selector: BootstrapLinkSelector,
    /// Lists canonical static addresses in CIDR notation.
    pub addresses: Vec<String>,
    /// Selects the optional default gateway.
    pub gateway: Option<String>,
    /// Lists canonical DNS servers.
    pub dns: Vec<String>,
}

impl BootstrapNetwork {
    /// Converts a runtime-validated bootstrap value into its semantic form.
    ///
    /// The caller must first validate `value` against
    /// `networkConfiguration.interface.types.bootstrap`, obtained from the
    /// signed interface document. This conversion checks only the structural
    /// assumptions needed by Rust code and does not restate the schema.
    ///
    /// # Errors
    ///
    /// Returns an error if a supposedly validated value cannot be projected
    /// into the semantic bootstrap form.
    pub fn from_validated(value: &AbilityValue) -> Result<Self> {
        let document = value
            .as_json()
            .as_object()
            .context("validated network bootstrap is not an object")?;
        let selector = document
            .get("selector")
            .and_then(Value::as_object)
            .context("validated network bootstrap has no selector")?;
        let selector_value = selector
            .get("value")
            .and_then(Value::as_str)
            .context("validated network bootstrap selector has no value")?
            .to_string();
        let selector = match selector.get("kind").and_then(Value::as_str) {
            Some("name") => BootstrapLinkSelector::Name(selector_value),
            Some("mac") => BootstrapLinkSelector::Mac(selector_value),
            _ => bail!("validated network bootstrap has a non-exact selector"),
        };

        Ok(Self {
            selector,
            addresses: string_list(document, "addresses")?,
            gateway: optional_string(document, "gateway")?,
            dns: string_list(document, "dns")?,
        })
    }

    /// Encodes the semantic value for validation against the signed interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the constructed value exceeds canonical ability
    /// value limits. The ability runtime remains responsible for validating
    /// the result against the signed bootstrap schema.
    pub fn into_ability_value(self) -> Result<AbilityValue> {
        AbilityValue::new(self.into_json()).context("encoding semantic network bootstrap")
    }

    /// Projects the semantic value into canonical JSON for a larger checked value.
    #[must_use]
    pub fn into_json(self) -> Value {
        let mut selector = Map::new();
        match self.selector {
            BootstrapLinkSelector::Name(value) => {
                selector.insert("kind".to_string(), Value::String("name".to_string()));
                selector.insert("value".to_string(), Value::String(value));
            }
            BootstrapLinkSelector::Mac(value) => {
                selector.insert("kind".to_string(), Value::String("mac".to_string()));
                selector.insert("value".to_string(), Value::String(value));
            }
        }

        let mut document = Map::new();
        document.insert("selector".to_string(), Value::Object(selector));
        document.insert(
            "addresses".to_string(),
            Value::Array(self.addresses.into_iter().map(Value::String).collect()),
        );
        if let Some(gateway) = self.gateway {
            document.insert("gateway".to_string(), Value::String(gateway));
        }
        document.insert(
            "dns".to_string(),
            Value::Array(self.dns.into_iter().map(Value::String).collect()),
        );
        Value::Object(document)
    }
}

fn string_list(document: &Map<String, Value>, field: &str) -> Result<Vec<String>> {
    document
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("validated network bootstrap has no {field} list"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .with_context(|| format!("validated network bootstrap {field} item is not text"))
        })
        .collect()
}

fn optional_string(document: &Map<String, Value>, field: &str) -> Result<Option<String>> {
    document
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .with_context(|| format!("validated network bootstrap {field} is not text"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use aos_ability_model::AbilityValue;

    use super::{BootstrapLinkSelector, BootstrapNetwork};

    #[test]
    fn checked_bootstrap_round_trips_through_the_semantic_boundary() {
        let bootstrap = BootstrapNetwork {
            selector: BootstrapLinkSelector::Mac("02:00:00:00:00:01".to_string()),
            addresses: vec!["192.0.2.10/24".to_string()],
            gateway: Some("192.0.2.1".to_string()),
            dns: vec!["192.0.2.53".to_string()],
        };
        let value = bootstrap
            .clone()
            .into_ability_value()
            .expect("canonical value");

        assert_eq!(
            BootstrapNetwork::from_validated(&value).expect("semantic conversion"),
            bootstrap
        );
    }

    #[test]
    fn non_exact_selector_cannot_cross_the_semantic_boundary() {
        let value = AbilityValue::new(serde_json::json!({
            "selector": {"kind": "ethernet", "value": "ignored"},
            "addresses": ["192.0.2.10/24"],
            "dns": []
        }))
        .expect("canonical value");

        assert!(BootstrapNetwork::from_validated(&value).is_err());
    }
}
