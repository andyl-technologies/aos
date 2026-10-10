//! Owns the closed policy JSON DTOs and their diagnostic label roster.
//!
//! Validation and runtime effects stay in the consuming service. Field names,
//! borrowing and Serde type names retain the existing wire contract.

use serde::Deserialize;

/// Deserializes the closed Projection wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Projection<'input> {
    /// Declares the schema.
    #[serde(borrow)]
    pub schema: &'input str,
    /// Declares the original toml blake3.
    #[serde(borrow)]
    pub original_toml_blake3: &'input str,
    /// Declares the document.
    #[serde(borrow)]
    pub document: Document<'input>,
}

/// Deserializes the closed Document wire object.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document<'input> {
    /// Declares the schema.
    #[serde(borrow)]
    pub schema: &'input str,
    /// Declares the version.
    pub version: u32,
    /// Declares the bindings.
    #[serde(borrow)]
    pub bindings: Vec<Binding<'input>>,
    /// Declares the grants.
    #[serde(borrow)]
    pub grants: Vec<Grant<'input>>,
}

/// Deserializes the closed Binding wire object.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding<'input> {
    /// Declares the user id.
    pub user_id: u32,
    /// Declares the group id.
    pub group_id: u32,
    /// Declares the principal.
    #[serde(borrow)]
    pub principal: &'input str,
}

/// Deserializes the closed Grant wire object.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant<'input> {
    /// Declares the principal.
    #[serde(borrow)]
    pub principal: &'input str,
    /// Declares the operation.
    #[serde(borrow)]
    pub operation: &'input str,
    /// Declares the campaign.
    #[serde(borrow)]
    pub campaign: &'input str,
}

impl<'input> super::sealed::Sealed for Projection<'input> {}

impl<'input> super::ClosedJsonProfile<'input> for Projection<'input> {
    const DIAGNOSTIC_LABELS: &'static [&'static str] = &[
        "struct Projection",
        "schema",
        "originalTomlBlake3",
        "document",
        "struct Document",
        "schema",
        "version",
        "bindings",
        "grants",
        "struct Binding",
        "user_id",
        "group_id",
        "principal",
        "struct Grant",
        "principal",
        "operation",
        "campaign",
    ];
}
