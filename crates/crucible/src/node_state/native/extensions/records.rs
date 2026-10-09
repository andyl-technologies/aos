//! Defines bounded source-semantic records for the extension-aware archive edition.

use crucible_node_contract::{ContentRef, HashRef};
use serde::{Deserialize, Serialize};

/// Retains a complete codec-authenticated dependency row for an original body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExtensionDependencyRecord {
    /// Binds complete original octets and media type.
    pub reference: ContentRef,
    /// Names all direct dependencies in strict canonical order.
    pub dependencies: Vec<ContentRef>,
}

/// Binds exact original applications and selected bodies to an installed codec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExtensionInventory {
    /// Selects this closed semantic inventory schema, independently of Index2.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Binds the complete original durable world.
    pub world_binding_hash: HashRef,
    /// Binds original application scopes, parameters, handlers and declarations.
    pub selection_identity: HashRef,
    /// Binds independently installed native preservation/dependency policy bytes.
    pub policy: ContentRef,
    /// Binds actual canonical application bodies in deterministic admission order.
    pub applications: Vec<ContentRef>,
    /// Binds each independent direct or prerequisite frozen interpretation.
    pub definitions: Vec<ContentRef>,
    /// Retains one complete row for every selected body, including the policy.
    pub dependencies: Vec<ExtensionDependencyRecord>,
}
