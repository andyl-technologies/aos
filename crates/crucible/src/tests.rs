//! Crate-level model, scenario, and world-validation tests.

use super::*;

#[path = "tests/model_core.rs"]
mod model_core;
#[path = "tests/world_validation.rs"]
mod world_validation;

use world_validation::*;
