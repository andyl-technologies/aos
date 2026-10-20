//! Parses the specification's exposure tables as a whole, without starting them.
//!
//! ```toml
//! [[expose]]
//! id = "snapshot"
//! view = "refs/heads/main"
//! surface = "sdk"
//! at = "/var/lib/terrane/snapshot"
//! token = "file:/etc/terrane/token"
//! mode = { reader = "pinned" }
//! ```

use super::{ConfigError, absolute_path, token};
use crate::surface::{self, Endpoint, Exposure, ReaderMode, View, ViewTarget, WriterMode};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Holds an exposure with its surface-specific TOML options intact.
pub type ConfiguredExposure = Exposure<BTreeMap<String, toml::Value>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawExposure {
    id: String,
    view: String,
    surface: String,
    at: String,
    token: String,
    #[serde(default)]
    mode: RawMode,
    #[serde(default)]
    options: BTreeMap<String, toml::Value>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMode {
    reader: Option<String>,
    writer: Option<String>,
}

pub(super) fn parse(raw: Vec<RawExposure>) -> Result<Vec<ConfiguredExposure>, ConfigError> {
    let mut identifiers = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    let mut output = Vec::new();
    for raw in raw {
        if raw.id.is_empty() || !identifiers.insert(raw.id.clone()) {
            return Err(ConfigError::Invalid("empty or duplicate exposure id"));
        }
        let view = View::parse(&raw.view).map_err(ConfigError::View)?;
        let registered = surface::registration(&raw.surface)
            .ok_or_else(|| ConfigError::UnavailableSurface(raw.surface.clone()))?;
        token::validate_reference(&raw.token)?;
        // T2 compiles only SDK checkout. Future surfaces add their own endpoint
        // parser together with their implementation rather than accepting guesses.
        if raw.surface != "sdk" || !absolute_path(&raw.at) {
            return Err(ConfigError::Invalid(
                "SDK endpoint requires an absolute directory path",
            ));
        }
        if !endpoints.insert(raw.at.clone()) {
            return Err(ConfigError::Invalid("duplicate exposure endpoint"));
        }
        let reader = match raw.mode.reader.as_deref() {
            Some("pinned") => ReaderMode::Pinned,
            Some("follow") => ReaderMode::Follow,
            Some(_) => return Err(ConfigError::Invalid("unknown reader mode")),
            None => match view.target {
                ViewTarget::Commit(_) => ReaderMode::Pinned,
                ViewTarget::Ref(_) => ReaderMode::Follow,
            },
        };
        if raw.surface == "sdk" && raw.mode.reader.as_deref() != Some("pinned") {
            return Err(ConfigError::Invalid(
                "SDK checkout requires explicit reader = pinned",
            ));
        }
        let writer = match raw.mode.writer.as_deref() {
            Some("manual") => Some(WriterMode::Manual),
            Some("periodic") => Some(WriterMode::Periodic),
            Some("sync") => Some(WriterMode::Sync),
            Some(_) => return Err(ConfigError::Invalid("unknown writer mode")),
            None if registered.writable => Some(WriterMode::Manual),
            None => None,
        };
        if !registered.writable && writer.is_some() {
            return Err(ConfigError::Invalid(
                "read-only surface cannot select writer mode",
            ));
        }
        if !raw.options.is_empty() {
            return Err(ConfigError::Invalid("SDK checkout has no surface options"));
        }
        output.push(Exposure {
            id: raw.id,
            view,
            surface: raw.surface,
            endpoint: Endpoint {
                kind: registered.endpoints[0],
                address: raw.at,
            },
            token: raw.token,
            reader,
            writer,
            options: raw.options,
        });
    }
    Ok(output)
}
