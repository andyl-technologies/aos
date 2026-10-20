//! Shares the existing semantic replay families around actual native stages.
//!
//! Ordinary replay and genuine selected writers call these same hooks at the
//! existing COMMIT, materialization, per-record and final-prefix frontiers.
//! The borrowed state contains no native handle, original, payer or completion
//! capability. Native structural validation and all protected ownership stay
//! with their actual parser/writer. No callback or success DATA creates a cut.

use super::*;
use super::source_history as source_original_native;

aos_sandbox_ledger_replay::define_semantic_replay_data_recipe_v1!();
