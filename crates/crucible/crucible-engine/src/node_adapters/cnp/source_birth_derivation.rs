//! Provides SourceBirth worker codecs and the installed-mechanism prerequisite.
//!
//! The codecs produce ordinary data, never accepted Source banks, Birth, Initial,
//! Recipe or native authority. The sealed installation owner checks the selected
//! package under actual shared-process containment; original Source association
//! and result acceptance remain separate responsibilities.

pub use crucible_source_birth_data::source_birth::literal_value;

/// Pure serializers shared by ordinary Source construction and worker data.
pub use crucible_source_birth_data::source_birth::views;

/// Runs the contained child's pure SourceBirth data derivation.
pub use crucible_source_birth_data::source_birth::derive;

/// Verifies the worker result envelope as ordinary data.
pub use crucible_source_birth_data::source_birth::result_wire;

/// Streams the closed secret-free worker request and executes its contained child path.
pub use crucible_source_birth_data::source_birth::request_wire;

/// Verifies the compiled installation under original process containment.
pub mod installation;

/// Describes known Source storage and its original external deployment read.
pub mod deployment;

/// Retains one original supervised occurrence through same-Source acceptance.
pub mod job;

/// Retains the immutable original launch occurrence through fresh job retirement.
pub mod original_launch;
