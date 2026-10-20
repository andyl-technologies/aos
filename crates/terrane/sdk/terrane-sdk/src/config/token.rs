//! Validates credential references without loading or retaining secret bytes.
//!
//! ```toml
//! [tokens]
//! issuer_public_keys = ["file:/etc/terrane/issuer.pub"]
//! host_token = "file:/etc/terrane/host.token"
//! ```

use serde::Deserialize;

use super::ConfigError;

/// Holds credential locators used by the selected process role.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tokens {
    /// Absolute file references to trusted issuer public keys.
    #[serde(default)]
    pub issuer_public_keys: Vec<String>,
    /// Optional capability reference; never an inline token.
    pub host_token: Option<String>,
}

impl Tokens {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        for key in &self.issuer_public_keys {
            if !key.strip_prefix("file:").is_some_and(super::absolute_path) {
                return Err(ConfigError::Invalid(
                    "issuer keys require absolute file references",
                ));
            }
        }
        if let Some(token) = &self.host_token {
            validate_reference(token)?;
        }
        Ok(())
    }
}

/// Checks that a locator is a file, secret-store reference, or anonymous grant.
///
/// # Errors
/// Rejects inline credentials, empty locators, and malformed anonymous grants.
pub fn validate_reference(reference: &str) -> Result<(), ConfigError> {
    let valid = if super::absolute_path(reference) {
        true
    } else if let Some(path) = reference.strip_prefix("file:") {
        super::absolute_path(path)
    } else if let Some(locator) = reference.strip_prefix("secret:") {
        !locator.is_empty()
            && !locator
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
    } else if let Some(grant) = reference.strip_prefix("anonymous:") {
        grant.rsplit_once(':').is_some_and(|(target, verbs)| {
            use terrane_format::auth::{Grant, Verb, Verbs};
            let mut mask = 0;
            for verb in verbs.split(',') {
                mask |= match verb {
                    "read" => Verb::Read as u8,
                    "fork" => Verb::Fork as u8,
                    "commit" => Verb::Commit as u8,
                    "tag" => Verb::Tag as u8,
                    "admin" => Verb::Admin as u8,
                    _ => return false,
                };
            }
            Verbs::new(mask)
                .and_then(|verbs| Grant::new(target.to_owned(), verbs))
                .is_ok()
        })
    } else {
        false
    };
    if valid {
        Ok(())
    } else {
        Err(ConfigError::Invalid("invalid token reference"))
    }
}
