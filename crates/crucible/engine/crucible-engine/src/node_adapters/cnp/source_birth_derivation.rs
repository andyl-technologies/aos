//! Provides pure data codecs for the private SourceBirth derivation worker.
//!
//! These operations produce ordinary data, never accepted Source banks, Birth,
//! Initial, Recipe or native authority. Production worker containment and the
//! parent association/acceptance protocol are independent responsibilities.

pub mod literal_value;

/// Pure serializers shared by ordinary Source construction and worker data.
pub mod views;
