//! Measures the distinct typed reader package without behavioral admission.
//!
//! The package loader authenticates exact source, semantic and executable bodies.
//! It cannot construct a runtime node, issue Ready, or install class acceptance.
//! Ordinary selection additionally requires an independently installed owning
//! qualification policy and remains unavailable until that policy is qualified.

mod catalog;
mod definition;
mod graphs;
mod metadata;
mod package;

pub use catalog::{
    InstalledTypedReaderCatalog, InstalledTypedReaderCatalogPolicy,
    InstalledTypedReaderConfiguration, InstalledTypedReaderPreparation,
    InstalledTypedReaderPreparedParts,
};
pub use package::InstalledTypedReaderPackage;

#[cfg(test)]
// Inert contract controls intentionally panic on invalid metadata acceptance.
mod tests;
