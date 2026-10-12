//! Literal complete independent models transcribed from published witnesses.
//! No owning encoder constructs malformed inputs; all fields remain inert.

use super::support::Value;

/// Carries one complete independent wire model and its declared interpretation.
pub(crate) struct Case {
    /// Unique published case heading.
    pub name: &'static str,
    /// Published fixture family used to select its owning assertions.
    pub family: &'static str,
    /// Whether the declared format or interpretation accepts the wire.
    pub positive: bool,
    /// Complete independent primitive fields or deliberately malformed raw input.
    pub model: Value,
    /// Literal expanded keys and complete Entry fields for positive Nodes.
    pub full_entries: Vec<(Vec<u8>, Value)>,
    /// Declared physical Ordinary or Index TreeUse.
    pub usage: &'static str,
    /// Whether the physical Node occupies a root position.
    pub is_root: bool,
    /// Explicit contextual role or positive role claim.
    pub role: &'static str,
    /// Declared refusal owner for a negative input.
    pub scope: &'static str,
    /// Published immutable digest, or an empty string for non-immutables.
    pub identity: &'static str,
    /// Explicit namespace owner R for contextual controls.
    pub source: &'static str,
    /// Inclusive lower equality key for a positive opaque value.
    pub lower: &'static str,
    /// Inclusive upper equality key for a positive opaque value.
    pub upper: &'static str,
}

#[path = "models_bindings.rs"]
mod bindings;
#[path = "models_controls.rs"]
mod controls;
#[path = "models_historical.rs"]
mod historical;
#[path = "models_keys.rs"]
mod keys;
#[path = "models_long_roots.rs"]
mod long_roots;
#[path = "models_long_routes.rs"]
mod long_routes;
#[path = "models_long_sources.rs"]
mod long_sources;
#[path = "models_roots.rs"]
mod roots;
#[path = "models_routes.rs"]
mod routes;
#[path = "models_sources.rs"]
mod sources;

/// Returns the complete literal published case models.
///
/// # Panics
/// Panics if a literal fixture contains malformed hexadecimal data.
pub(crate) fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    cases.extend(bindings::cases());
    cases.extend(keys::cases());
    cases.extend(historical::cases());
    cases.extend(sources::cases());
    cases.extend(roots::cases());
    cases.extend(routes::cases());
    cases.extend(long_routes::cases());
    cases.extend(long_roots::cases());
    cases.extend(long_sources::cases());
    cases.extend(controls::cases());
    cases
}
