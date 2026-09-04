//! Backend-neutral compilation of immutable filesystem views.
//!
//! This crate validates hostile portable tree graphs, translates portable
//! identities for one presentation connection, and builds a replaceable
//! architecture-neutral structural index. It owns no mount, network, cache,
//! or publication authority. Callers supply exact objects and a private
//! staging writer; privileged publication and FUSE realization remain separate.

mod graph;
mod index;
mod limits;
mod presentation;
mod source;

pub use graph::{CompileError, CompileSummary, TreeCompiler};
pub use index::{
    INDEX_MEDIA_TYPE, IndexCrosslinks, IndexError, IndexExpectation, IndexStaging, IndexSummary,
    StagedIndex, ValidatedIndex, validate_index,
};
pub use limits::TreeCompileLimits;
pub use presentation::{
    AclCapability, IdMapExtent, IdentityMap, IdentityMapError, PresentationPlan, PresentedMetadata,
};
pub use source::{ExactObject, ObjectSource, SourceError, load_exact};
