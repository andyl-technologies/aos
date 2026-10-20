//! Owns the shared historical Source, Root and capacity replay graph.
//!
//! The modules hold the sole saved-state models, codecs and complete replay
//! comparisons used by real native Source and independent Cache readers. The
//! semantic recipes preserve every raw COMMIT and final-prefix check around
//! the same actual canonical parser. These DATA engines issue no live writer,
//! currentness proof, signing purpose, admission, phase or mutation grant.
//!
//! Native roles retain their own fixed construction, financial originals,
//! physical custody and independent posts. Private paid-stage bindings admit
//! actual model growth; the public cold driver is comparison DATA only.

/// Checks the sole canonical Source successor approval and intent grammar.
pub mod successor;

/// Shares fixed Source codec support without native custody or authority.
#[doc(hidden)]
pub mod data;

/// Owns canonical project ancestry and operation history models.
pub mod hierarchy;

/// Owns the immutable Source genesis receipt grammar and returned DATA owner.
pub mod genesis;

/// Owns the canonical saved-state validation engines used by Source replay.
pub mod replay;

/// Shares the original semantic sequence with private native stage bindings.
pub mod semantic_recipe;

/// Shares the original pure Delete COMMIT guards with native adapters.
pub mod delete_recipe;

/// Drives the actual indexed cursor through the fixed no-history DATA recipe.
pub mod cold;

/// Binds the same cold recipe inside each concrete private receiving owner.
pub mod cold_binding;
mod source_no_history;

/// Prices actual reached semantic families before their original allocations.
pub mod geometry;
/// Encodes the historical fixed Source-writer challenge as comparison DATA.
pub mod source_domain_challenge;

/// Shares the canonical saved Source hold and pending-marker comparison fold.
pub mod source_policy_hold;

/// Shares canonical saved Source project-admission row lookups and joins.
pub mod source_project_readback;

/// Shares saved ancestry field and genesis member comparisons without authority.
pub mod source_readback_queries;

/// Shares Source signer comparison codecs without live role authority.
pub mod source_signer_data;

/// Reconstructs complete Cache family DATA for independent native role readers.
pub mod cache_current;

/// Compares canonical pending native cuts without role or financial authority.
pub mod delete_pending;

/// Shares complete logical Delete graph DATA without any native authority.
pub mod delete_graph;

/// Shares canonical Git-prefix hash and fixed-catalog comparison DATA only.
pub mod git_coverage_prefix;
pub mod ordinary_mutation;

/// Shares historical Host fence codecs and deny-only ordinary predicates.
pub mod host_fence;

/// Shares Controller policy-hold/V8/Q04 history without native authority.
pub mod controller_policy_hold;

/// Shares fixed ordinary comparison recipes without native or role authority.
#[doc(hidden)]
pub mod provider_ordinary_recipe;

/// Shares complete Q04 physical-history comparisons without native authority.
pub mod q04_native_history;
