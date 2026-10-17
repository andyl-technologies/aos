//! Separates namespace installation, semantic interpretation, and qualification.
//!
//! Every interface here belongs to configured host trust. Provider declarations,
//! handler names, matching schema hashes, and successful parsing cannot satisfy
//! these interfaces by themselves. No callback receives an execution grant.

use std::collections::BTreeSet;

use crucible_node_contract::{
    ContentRef, ExtensionDeclaration, ExtensionSelection, ExtensionUse, Id, OperatingMode,
};

use crate::node_admission::EvidenceError;

use super::context::{ExtensionApplication, ExtensionRecordKind};

/// Distinguishes registered interpretation from permission to change behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionImpact {
    /// Defines checked metadata without additional execution or state semantics.
    Metadata,
    /// Defines additional behavior bound to durable execution compatibility.
    Behavior,
}

/// Binds the implemented semantic axes to complete published contract identities.
///
/// This record describes installed code; it does not add capabilities to a node.
/// The actual selected node, port, operating policy, ownership, and qualification
/// must independently support each application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionSemanticContract {
    /// Names the exact source-owned role/class interpretation contract.
    pub class_contract: ContentRef,
    /// Names the implemented operation-facet interpretation contract.
    pub facet_contract: ContentRef,
    /// Names the implemented allowed operating-mode interpretation contract.
    pub mode_contract: ContentRef,
    /// Names the implemented port/lane interpretation contract.
    pub port_contract: ContentRef,
    /// Names the exact implemented boundaries and timing obligations.
    pub timing_contract: ContentRef,
    /// Names complete future-state, ownership, and compatibility obligations.
    pub state_contract: ContentRef,
    /// Names actual refusal, uncertainty, retry, and containment semantics.
    pub error_contract: ContentRef,
    /// Names required executable qualification cases and known exclusions.
    pub qualification_contract: ContentRef,
    /// Enumerates containing locations with installed semantic handlers.
    pub locations: BTreeSet<ExtensionRecordKind>,
    /// Restricts actual selected roles when the application is node scoped.
    pub roles: BTreeSet<Id>,
    /// Restricts actual selected operation facets for this interpretation.
    pub facets: BTreeSet<Id>,
    /// Restricts actual operating modes without synthesizing any mode support.
    pub modes: Vec<OperatingMode>,
    /// Restricts actual port interface identities for port/lane applications.
    pub interfaces: BTreeSet<Id>,
    /// Defines whether use must appear in durable execution identity.
    pub impact: ExtensionImpact,
}

/// Authenticates a configured installation before any provider can select it.
///
/// Implementations must consult actual configured namespace authority and source
/// installation facts. They must not trust an owner string, provider-supplied
/// hash, dynamically selected handler name, or self-issued publication receipt.
pub trait ExtensionInstallationAuthority {
    /// Reads an immutable definition under a ceiling enforced before allocation.
    ///
    /// # Errors
    /// Refuses missing, untrusted, or oversized publication content.
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError>;

    /// Authenticates owner-controlled publication and reserved-name restrictions.
    ///
    /// # Errors
    /// Refuses unauthorized namespaces, forged origins, vendor redefinitions of
    /// core identifiers, changed published versions, and missing trust policy.
    fn authenticate_namespace(
        &self,
        declaration: &ExtensionDeclaration,
        selection: &ExtensionSelection,
    ) -> Result<(), EvidenceError>;

    /// Authenticates an exact published core prerequisite independently of a vendor.
    ///
    /// # Errors
    /// Refuses unknown editions, altered core definitions, and a prerequisite
    /// whose installed interpretation has not been established.
    fn authenticate_core_contract(
        &self,
        identifier: &Id,
        version: u16,
        definition: &ContentRef,
    ) -> Result<(), EvidenceError>;

    /// Authenticates the complete schema and its actual installed bounded validator.
    ///
    /// # Errors
    /// Refuses unknown or unresolved schemas and validators lacking the declared
    /// finite bounds. Successful content verification alone is insufficient.
    fn authenticate_schema(
        &self,
        schema: &crucible_node_contract::SchemaRef,
    ) -> Result<(), EvidenceError>;

    /// Authenticates actual installed semantic code against the complete definition.
    ///
    /// # Errors
    /// Refuses unknown or mismatched source/code identities, omitted semantic
    /// axes, unavailable validators, and inconsistent publication contracts.
    fn authenticate_handler(
        &self,
        declaration: &ExtensionDeclaration,
        handler_identity: &ContentRef,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError>;
}

/// Implements the schema and semantic validator for one exact installed definition.
///
/// The registry independently authenticates this code identity. Validation is
/// read only: it cannot realize a resource, execute a reaction, activate a node,
/// publish externally, or modify a prior admission selection.
pub trait ExtensionSemanticHandler {
    /// Borrows the independently measured installed semantic implementation.
    fn identity(&self) -> &ContentRef;

    /// Borrows the exact implemented scope and semantic contract inventory.
    fn semantics(&self) -> &ExtensionSemanticContract;

    /// Validates the selected schema, parameters, and exact containing record.
    ///
    /// # Errors
    /// Refuses unsupported parameter schema, context, class/facet/mode/port
    /// combinations, semantic constraints, and finite-resource bounds.
    fn validate_application(
        &self,
        application: &ExtensionApplication<'_>,
        declaration: &ExtensionDeclaration,
        selected: &ExtensionUse,
    ) -> Result<(), EvidenceError>;
}

/// Applies independent qualification policy to an exact selected application.
///
/// This authority must authenticate executable evidence applicable to the
/// actual selected implementation/configuration and every required feature.
/// Registry presence, a schema validator, and unrelated successful operations
/// cannot establish support. Missing policy has no successful default.
pub trait ExtensionQualificationAuthority {
    /// Resolves the complete actually available prerequisite feature set for this scope.
    ///
    /// The result must come from authenticated installation, realization, or
    /// negotiated session facts. Offered strings and a provider's declaration
    /// cannot establish that a feature was selected or implemented. The ceiling
    /// must be enforced before allocating the returned inventory.
    ///
    /// # Errors
    /// Refuses unavailable or unauthenticated feature inventory and inventories
    /// exceeding the supplied finite feature count.
    fn actual_features(
        &self,
        application: &ExtensionApplication<'_>,
        maximum_features: usize,
    ) -> Result<crucible_node_contract::IdSet, EvidenceError>;

    /// Qualifies an imported prerequisite under its original root application.
    ///
    /// This does not apply the prerequisite's direct-use parameter schema to
    /// another extension's parameters. Policy must establish that its actual
    /// installed semantics implement the dependency required by the exact
    /// dependent declaration and selected root, including scope restrictions.
    ///
    /// # Errors
    /// Refuses unsupported dependency interpretation, unavailable qualification,
    /// incompatible root/dependent context, and missing required native evidence.
    fn qualify_dependency(
        &self,
        application: &ExtensionApplication<'_>,
        selected_root: &ExtensionUse,
        dependent: &ExtensionDeclaration,
        prerequisite: &ExtensionDeclaration,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError>;

    /// Accepts the exact selected extension under available installed evidence.
    ///
    /// # Errors
    /// Refuses absent, fixture-only, unrelated, stale, weakened, or incomplete
    /// qualification, unsupported required features, and mismatched scopes.
    fn qualify_application(
        &self,
        application: &ExtensionApplication<'_>,
        declaration: &ExtensionDeclaration,
        selected: &ExtensionUse,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError>;
}
