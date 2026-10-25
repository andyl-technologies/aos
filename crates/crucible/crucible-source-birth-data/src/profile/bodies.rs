//! Retains the actual portable requests and shared closed-field checks.

use crucible_node_format::*;
use serde::{Deserialize, Serialize};

/// Constructs a local portable-field refusal without accepting its input.
pub fn invalid(field: &'static str, reason: &'static str) -> ContractError {
    ContractError::Invalid {
        field,
        reason: reason.to_owned(),
    }
}

/// Checks the unchanged hard portable-array bound.
///
/// # Errors
/// Refuses a sequence above the baseline element ceiling.
pub fn count<T>(values: &[T], field: &'static str) -> Result<(), ContractError> {
    if values.len() > MAX_ARRAY_ELEMENTS {
        return Err(invalid(field, "array exceeds 65536 elements"));
    }
    Ok(())
}

/// Checks strict portable set order and its original element bound.
///
/// # Errors
/// Refuses oversized, duplicate or nonascending keys.
pub fn sorted<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    field: &'static str,
) -> Result<(), ContractError> {
    count(values, field)?;
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(invalid(
            field,
            "set must be strictly sorted without duplicates",
        ));
    }
    Ok(())
}

/// Checks strict canonical order of portable identifier sets.
///
/// # Errors
/// Refuses oversized, duplicate or nonascending identifiers.
pub fn ids(values: &[Id], field: &'static str) -> Result<(), ContractError> {
    sorted(values, Clone::clone, field)
}

/// Checks a validated hash against its defining identity domain.
///
/// # Errors
/// Refuses invalid hash data or a different identity domain.
pub fn domain(hash: &HashRef, expected: &'static str) -> Result<(), ContractError> {
    hash.validate()?;
    if hash.domain != expected {
        return Err(invalid("hash.domain", "incorrect typed identity domain"));
    }
    Ok(())
}

/// Represents the baseline `RealizeRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealizeRequest {
    /// Carries the normative `realization_id` contract field.
    pub realization_id: Id,
    /// Carries the normative `configuration` contract field.
    pub configuration: ContentRef,
    /// Carries the normative `requested_node_ids` contract field.
    pub requested_node_ids: IdSet,
    /// Carries the normative `resource_limits` contract field.
    pub resource_limits: ResourceLimits,
    /// Carries explicitly negotiated method extensions.
    #[serde(deserialize_with = "crucible_node_format::literal_json::deserialize_extensions")]
    pub extensions: Extensions,
}

impl Validate for RealizeRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.configuration.validate()?;
        ids(&self.requested_node_ids, "requested_node_ids")?;
        self.resource_limits.validate()?;
        Ok(())
    }
}

/// Represents the baseline `ActivateRequest` wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateRequest {
    /// Carries the normative `admission_id` contract field.
    pub admission_id: Id,
    /// Identifies the admitted activation.
    pub activation_id: Id,
    /// Identifies the admitted world generation.
    pub world_generation: U64,
    /// Carries the normative `prepared_token` contract field.
    pub prepared_token: Id,
    /// Commits to complete world compatibility.
    pub world_binding_hash: HashRef,
    /// Carries the normative `gate_id` contract field.
    pub gate_id: Id,
    /// Carries explicitly negotiated method extensions.
    #[serde(deserialize_with = "crucible_node_format::literal_json::deserialize_extensions")]
    pub extensions: Extensions,
}

impl Validate for ActivateRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.world_binding_hash.validate()?;
        domain(&self.world_binding_hash, "cnp.world-binding.v1")?;
        Ok(())
    }
}
