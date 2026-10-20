//! Owns the fixed Native Source journal and original paid/Q04 custody.
//!
//! The private fixed-writer child retains the live Source writer, paid opening
//! originals and Q04 loans used by Controller and Runtime callers. Fixed names
//! and limits belong to this owner; Lifecycle retains its schemas and recovery.

mod fixed_writer;

#[cfg(target_os = "linux")]
pub use fixed_writer::ControllerSourceJournalConstructionV1;
#[cfg(target_os = "linux")]
pub(crate) use fixed_writer::OriginalQ04SourceOwnerCutV1;
pub use fixed_writer::ProtectedSourceDomainJournalOwnerV1;

pub(crate) use aos_sandbox_broker::source_receiving::{
    SOURCE_DOMAIN_DIRECTORY_V1 as PROTECTED_SOURCE_DOMAIN_ROOT,
    SOURCE_DOMAIN_JOURNAL_V1 as PROTECTED_SOURCE_DOMAIN_JOURNAL,
    source_journal_limits_v1 as source_domain_journal_limits,
};
