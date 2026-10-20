//! Owns the closed surface registry and SDK checkout through repository reads.
//!
//! `Surface` maps a view to a presentation endpoint; content access remains
//! exclusively in the repository (SURF-1 to SURF-3). The SDK surface produces
//! a durable pinned directory snapshot and owns no backend credentials.

pub use terrane_format::surface::{
    Endpoint, EndpointKind, Exposure, ReaderMode, SchemaEntryKind, TreeSchema, View, ViewError,
    ViewTarget, WriterMode,
};

#[cfg(feature = "std")]
mod exposure;
#[cfg(feature = "std")]
pub use exposure::{PreparedExposures, TokenResolver};

#[cfg(feature = "std")]
pub use crate::repository::schema::{ViewMetadata, validate_schema};

mod registry;
pub use registry::{SurfaceRegistration, registration};

#[cfg(feature = "std")]
mod native;
#[cfg(feature = "std")]
pub use native::*;

#[cfg(all(feature = "surface-sdk", unix))]
mod sdk;
