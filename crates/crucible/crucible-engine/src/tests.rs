//! Crate-level model, scenario, and world-validation tests.

use super::*;

#[path = "tests/content_hash.rs"]
mod content_hash;
#[path = "tests/model_core.rs"]
mod model_core;
#[path = "tests/spatial_components.rs"]
mod spatial_components;
#[path = "tests/world_validation.rs"]
mod world_validation;

use world_validation::*;
