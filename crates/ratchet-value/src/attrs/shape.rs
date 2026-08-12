//! Attribute-set shape descriptors for future hidden-class fast paths.
//!
//! A shape captures the key layout shared by attrset instances: the internal
//! symbol-sorted key vector used for binary-search lookup, the construction
//! order permutation, the observable raw-byte lexicographic iteration
//! permutation, the inverse lexicographic rank per symbol slot, and an
//! in-process xxh3 fingerprint of the key vector. The process-local
//! [`ShapeTable`] interns descriptors and caches transition edges for future
//! runtime integration. It does not install a global/shared shape table, inline
//! cache, HAMT representation, or runtime fast path.

mod descriptor;
mod ids;
mod instance;
mod plans;
mod table;

pub use descriptor::{AttrShape, ShapeError, ShapeOrderKeys, ShapeTransition};
pub use ids::{ShapeFingerprint, ShapeId, ShapedAttrsFingerprint};
pub use instance::{
    ShapedAttrConsError, ShapedAttrConsTable, ShapedAttrEntries, ShapedAttrEntry, ShapedAttrs,
    ShapedAttrsError,
};
pub use plans::{
    ShapedUpdateError, ShapedUpdateOperand, ShapedUpdatePlan, StaticShapePlan, StaticShapePlanError,
};
pub use table::{ShapeHandle, ShapeTable, ShapeTableTransition};

#[cfg(test)]
mod order_tests;
#[cfg(test)]
mod tests;
