//! Crate-level model, scenario, and world-validation tests.

use super::*;

fn valid_step(configuration: &Configuration, decision: Decision) -> Configuration {
    try_step(configuration, decision).expect("test configuration step")
}

#[path = "tests/content_hash.rs"]
mod content_hash;
#[path = "tests/model_core.rs"]
mod model_core;
#[path = "tests/world_validation.rs"]
mod world_validation;

use world_validation::*;
