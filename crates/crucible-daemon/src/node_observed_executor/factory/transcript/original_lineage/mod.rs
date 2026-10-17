//! Owns source-qualified original-lineage preparation behind two host authorities.
//!
//! Inactive preparation is distinct from common Ready and world publication.
//! The original signed sources and installed policy remain owned through every
//! callback refusal, unwind and runtime custody transfer.

mod policy;
mod preparation;
pub(in crate::node_observed_executor::factory) mod selection;

pub use policy::{InstalledOriginalLineagePlan, InstalledOriginalLineageSourcePolicy};
pub use preparation::InstalledOriginalLineagePreparation;
pub use selection::InstalledOriginalLineageAuthority;

#[cfg(test)]
mod tests;
