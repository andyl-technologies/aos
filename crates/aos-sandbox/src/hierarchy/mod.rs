//! Pure sandbox hierarchy and filesystem-view planning models.
//!
//! The protected-journal adapter durably binds the bounded reducers while
//! retaining exact postcommit facts. The module owns no broker, descriptor,
//! service activation, or runtime-effect implementation.

pub mod accounting;
pub mod artifact_codec;
pub mod codec;
pub mod evidence;
pub mod exports;
pub mod graph;
pub mod history;
pub mod inspection;
pub mod model;
pub mod placement;
mod protected_evidence;
pub mod protected_journal;
pub mod realizer;
pub mod recovery;
pub mod source_seed;
pub mod state;
mod tree_lineage;
