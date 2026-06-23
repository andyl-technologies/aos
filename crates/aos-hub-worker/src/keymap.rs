//! The R2 machine-path facade classification — re-exported from the shared core.
//!
//! RFC-0004 Phase 5 made [`aos_hub_core::keymap`] the single,
//! runtime-neutral source of truth for machine-path classification
//! (`is_machine_path`, `cache_control`, `content_type`) and R2 key mapping
//! (`r2_key`). The native hub and this Worker both re-export it, so the facade's
//! byte-faithful serving contract cannot drift between deployments. This module
//! is now a thin re-export to keep the worker's `crate::keymap::…` paths stable.

pub use aos_hub_core::keymap::{
    cache_control, content_type, is_machine_path, r2_key, relative_key, IMMUTABLE_CACHE_CONTROL,
    MUTABLE_CACHE_CONTROL,
};
