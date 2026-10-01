//! Owns current-policy repository authorization from specification 22.

// Collection verifies historical inputs through the same genuine Guard.
#[cfg(feature = "std")]
#[path = "gc/authority.rs"]
pub(crate) mod collection_authority;
