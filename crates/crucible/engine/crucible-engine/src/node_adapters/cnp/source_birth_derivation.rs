//! Provides SourceBirth worker codecs and the installed-mechanism prerequisite.
//!
//! The codecs produce ordinary data, never accepted Source banks, Birth, Initial,
//! Recipe or native authority. The sealed installation owner checks the selected
//! package under actual shared-process containment; original Source association
//! and result acceptance remain separate responsibilities.

pub mod literal_value;

/// Pure serializers shared by ordinary Source construction and worker data.
pub mod views;

/// Runs the contained child's pure SourceBirth data derivation.
pub mod derive;

/// Verifies the worker result envelope as ordinary data.
pub mod result_wire;

/// Streams the closed secret-free worker request and executes its contained child path.
pub mod request_wire;

/// Verifies the compiled installation under original process containment.
pub mod installation;
