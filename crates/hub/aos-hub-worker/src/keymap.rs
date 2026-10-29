//! The R2 machine-path facade classification — re-exported from the shared core.
//!
//! RFC-0004 Phase 5 made [`aos_hub_model::keymap`] the single,
//! runtime-neutral source of truth for machine-path classification
//! (`is_machine_path`, `cache_control`, `content_type`) and R2 key mapping
//! (`r2_key`). The native hub and this Worker both re-export it, so the facade's
//! byte-faithful serving contract cannot drift between deployments. This module
//! is now a thin re-export to keep the worker's `crate::keymap::…` paths stable.

pub use aos_hub_model::keymap::cache_control;
pub use aos_hub_model::keymap::content_type;
pub use aos_hub_model::keymap::is_machine_path;
pub use aos_hub_model::keymap::r2_key;
pub use aos_hub_model::keymap::relative_key;
pub use aos_hub_model::keymap::IMMUTABLE_CACHE_CONTROL;
pub use aos_hub_model::keymap::MUTABLE_CACHE_CONTROL;
