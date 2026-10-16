//! Lists compiled surfaces and their normative presentation constraints.

use super::{EndpointKind, TreeSchema};

/// Describes a compiled surface without opening an endpoint or repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceRegistration {
    /// Registered specification name.
    pub name: &'static str,
    /// Accepted presentation addresses.
    pub endpoints: &'static [EndpointKind],
    /// Whether the implementation accepts mutations.
    pub writable: bool,
    /// Metadata-only schema equivalent to the normative registry.
    pub schema: TreeSchema,
}

/// Returns the compiled registration, or absence for an unavailable surface.
///
/// Names are fixed in the executable. Configuration never loads surface code.
pub fn registration(name: &str) -> Option<SurfaceRegistration> {
    match name {
        #[cfg(all(feature = "surface-sdk", unix))]
        "sdk" => Some(SurfaceRegistration {
            name: "sdk",
            endpoints: &[EndpointKind::Directory],
            writable: false,
            schema: TreeSchema::default(),
        }),
        _ => None,
    }
}
