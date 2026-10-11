//! Admits exact registered extension semantics without granting native authority.
//!
//! Portable declarations identify content. Configured namespace policy,
//! independently authenticated installed handlers, and application-specific
//! qualification jointly decide whether that content has implemented meaning.
//! The empty registry preserves refusal of every nonempty extension map.

mod admission;
mod authority;
mod context;
mod frozen;
mod negotiation;
mod registry;
mod selected;

#[cfg(test)]
mod tests;

pub use authority::{
    ExtensionImpact, ExtensionInstallationAuthority, ExtensionQualificationAuthority,
    ExtensionSemanticContract, ExtensionSemanticHandler,
};
pub use context::{
    ExtensionApplication, ExtensionApplicationScope, ExtensionRecordKind, ExtensionRecordPath,
};
pub use frozen::AdmittedExtensionDefinition;
pub use negotiation::InstalledExtensionPeerPolicy;
pub use registry::{ExtensionRegistration, ExtensionRegistryLimits, InstalledExtensionRegistry};
pub use selected::{AdmittedExtensionApplication, AdmittedExtensionSet};

pub(super) use admission::ExtensionAdmission;
pub(super) use context::RecordPlacement;

#[cfg(test)]
pub(super) fn test_model_graph_with_extension() -> crate::node_admission::AdmittedGraph {
    tests::model_graph_with_extension()
}
