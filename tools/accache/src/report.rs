//! Immutable per-invocation events and comparisons with the previous action.
//!
//! Events retain argument vectors and input names, but environment values are
//! digested before publication. Concurrent writers never share an append file.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    backend::{Backend, atomic},
    model::Identity,
};

/// Records one compiler invocation, including bypasses without an action key.
#[derive(Deserialize, Serialize)]
pub struct Event {
    /// Event format version.
    pub schema: u32,
    /// Start time in milliseconds since the Unix epoch.
    pub timestamp_ms: u128,
    /// Total wrapper duration, including discovery and cache access.
    pub duration_ms: u128,
    /// Machine-readable outcome, such as hit, miss, or bypass.
    pub outcome: String,
    /// Explanation of the lookup or bypass decision.
    pub reason: String,
    /// Action digest when dependency discovery completed successfully.
    pub action: Option<String>,
    /// Optional caller-supplied derivation path, excluded from the key.
    pub derivation: Option<String>,
    /// Nix build output path, when provided by the builder environment.
    pub output: Option<String>,
    /// Full action inventory, absent for discovery bypasses.
    pub identity: Option<Identity>,
    /// Differences from the last invocation targeting the same outputs.
    pub changes: Vec<String>,
    /// Actual files published or restored by this action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
    /// Original wrapper arguments, also retained when discovery bypasses.
    #[serde(default)]
    pub command: Vec<String>,
    /// Invocation directory; bypasses have no complete action identity.
    #[serde(default)]
    pub working_directory: Option<String>,
}

impl Event {
    /// Captures invocation provenance before recording its eventual outcome.
    pub fn new(outcome: &str, reason: String) -> Self {
        Self {
            schema: 1,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            duration_ms: 0,
            outcome: outcome.into(),
            reason,
            action: None,
            derivation: std::env::var("ACCACHE_DERIVATION").ok(),
            output: std::env::var("out").ok(),
            identity: None,
            changes: Vec::new(),
            artifacts: Vec::new(),
            command: std::env::args_os()
                .skip(1)
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect(),
            working_directory: std::env::current_dir()
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
        }
    }
}

/// Publishes an immutable event and updates its output-slot comparison record.
///
/// # Errors
/// Returns an error for serialization or filesystem failures.
pub fn record(backend: &Backend, event: &Event) -> Result<()> {
    let mut temporary = tempfile::Builder::new()
        .prefix("event-")
        .suffix(".pending")
        .permissions(fs::Permissions::from_mode(0o666))
        .tempfile_in(backend.state.join("events"))?;
    temporary.write_all(&serde_json::to_vec(event)?)?;
    let destination = temporary.path().with_extension("json");
    temporary.persist(destination)?;
    if let Some(identity) = &event.identity {
        atomic(
            &backend.state.join("latest").join(identity.slot()?),
            &serde_json::to_vec(identity)?,
        )?;
    }
    Ok(())
}

/// Compares an action with the last recorded invocation for its output slot.
///
/// # Errors
/// Returns an error for unreadable or malformed prior identity records.
pub fn changes(backend: &Backend, identity: &Identity) -> Result<Vec<String>> {
    let path = backend.state.join("latest").join(identity.slot()?);
    match fs::read(path) {
        Ok(bytes) => Ok(identity.differences(&serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(vec!["first observed invocation for this output set".into()])
        }
        Err(error) => Err(error.into()),
    }
}

/// Prints statistics, a detailed explanation, or provenance as JSON.
///
/// # Errors
/// Returns an error for inaccessible storage, serialization failures, or an
/// explanation request with no matching event.
pub fn inspect(backend: &Backend, operation: &str, key: Option<&str>) -> Result<()> {
    let mut events = Vec::new();
    for entry in fs::read_dir(backend.state.join("events"))? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(path)?;
        // Invalid or newer-schema records must not break aggregate inspection.
        if let Ok(event) = serde_json::from_slice::<Event>(&bytes) {
            events.push(event);
        }
    }
    events.sort_by_key(|event| event.timestamp_ms);
    if operation == "stats" {
        let mut counts = BTreeMap::new();
        for event in &events {
            *counts.entry(&event.outcome).or_insert(0_u64) += 1;
        }
        println!("{}", serde_json::to_string_pretty(&counts)?);
    } else if operation == "explain" {
        let event = events
            .iter()
            .rev()
            .find(|event| key.is_none() || event.action.as_deref() == key)
            .ok_or_else(|| anyhow::anyhow!("no matching action event"))?;
        let mut document = serde_json::to_value(event)?;
        if let Some(identity) = &event.identity {
            let policy_path = backend.path("cas", &identity.policy)?;
            if let Ok(bytes) = fs::read(policy_path)
                && crate::model::hash(&bytes) == identity.policy
            {
                document["manifest"] = serde_json::from_slice(&bytes)?;
            }
        }
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else {
        for event in events
            .iter()
            .filter(|event| key.is_none() || event.action.as_deref() == key)
        {
            println!("{}", serde_json::to_string(event)?);
        }
    }
    Ok(())
}
