//! Loads role and store-expression syntax without opening backends.
//!
//! The T0 loader accepts the TOML exposure vocabulary from specification 26,
//! but rejects every exposure with a named unavailable surface. Capability,
//! token, schema, and backend checks require the later repository milestones.
//! A syntax check therefore grants no authority and starts no service.
//!
//! ```toml
//! role = "serve"
//! store = "guard(policy=warehouse)(bucket(file:///var/lib/terrane))"
//! ```

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

use crate::role::Role;

pub mod expression;

/// Holds parsed foundation configuration without backend credentials or I/O.
#[derive(Debug)]
pub struct Config {
    role: Role,
    store: expression::StoreExpression,
}

impl Config {
    /// Parses the specification's TOML vocabulary and store-expression syntax.
    ///
    /// No surfaces have been implemented in this build. Naming one returns an
    /// error rather than claiming it has passed token or schema validation.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed TOML, unknown keys or roles, invalid
    /// store syntax, or any exposure naming a missing surface.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input).map_err(ConfigError::Toml)?;
        let store = expression::StoreExpression::parse(&raw.store)
            .map_err(ConfigError::Store)?;

        if let Some(exposure) = raw.expose.first() {
            return Err(ConfigError::UnavailableSurface(exposure.surface.clone()));
        }

        Ok(Self { role: raw.role, store })
    }

    /// Returns the sole process role selected by this invocation.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns the immutable, parsed store-expression tree (ARCH-6).
    pub fn store(&self) -> &expression::StoreExpression {
        &self.store
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    role: Role,
    store: String,
    #[serde(default)]
    expose: Vec<RawExposure>,
}

// These fields accept the spec vocabulary for configuration loading only. An
// exposure is refused before any token is read or endpoint is opened in T0.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExposure {
    #[serde(rename = "id")]
    _id: String,
    #[serde(rename = "view")]
    _view: String,
    surface: String,
    #[serde(rename = "at")]
    _at: String,
    #[serde(rename = "token")]
    _token: String,
    #[serde(default, rename = "mode")]
    _mode: BTreeMap<String, toml::Value>,
    #[serde(default, rename = "options")]
    _options: BTreeMap<String, toml::Value>,
}

/// Describes failures to load the entire foundation configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// Preserves TOML diagnostics, including unknown keys and role names.
    Toml(toml::de::Error),
    /// Preserves store-expression syntax diagnostics.
    Store(expression::ExpressionError),
    /// Names a surface that this build cannot serve (ARCH-10, SURF-9).
    UnavailableSurface(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(error) => write!(formatter, "invalid configuration: {error}"),
            Self::Store(error) => write!(formatter, "invalid store expression: {error}"),
            Self::UnavailableSurface(surface) => {
                write!(formatter, "surface {surface:?} is unavailable in this build")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Toml(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::UnavailableSurface(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_role_loads_through_the_same_vocabulary() {
        for role in Role::ALL {
            let text = format!("role = '{role}'\nstore = 'bucket(file:///tmp/store)'\n");
            assert_eq!(Config::parse(&text).expect("valid syntax").role(), role);
        }
    }

    #[test]
    fn rejects_unknown_keys_and_unavailable_surfaces() {
        assert!(Config::parse("role = 'serve'\nstore = 'disk(/tmp)'\nsecret = 'x'").is_err());

        let input = "role = 'realize'\nstore = 'disk(/tmp)'\n[[expose]]\nid = 'root'\nview = 'refs/heads/main'\nsurface = 'fuse'\nat = '/tmp/view'\ntoken = 'file:/tmp/token'";
        assert!(matches!(Config::parse(input), Err(ConfigError::UnavailableSurface(name)) if name == "fuse"));
    }
}
