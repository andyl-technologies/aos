//! Provides pure data codecs for the private SourceBirth derivation worker.
//!
//! These operations produce ordinary data, never accepted Source banks, Birth,
//! Initial, Recipe or native authority. Production worker containment and the
//! parent association/acceptance protocol are independent responsibilities.

pub mod literal_value;

/// Pure serializers shared by ordinary Source construction and worker data.
pub mod views;

/// Runs the contained child's pure SourceBirth data derivation.
pub mod derive;

/// Verifies the worker result envelope as ordinary data.
pub mod result_wire;

/// Streams the closed secret-free worker request and executes its contained child path.
pub mod request_wire;
