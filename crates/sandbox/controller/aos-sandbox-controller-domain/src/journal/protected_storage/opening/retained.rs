//! Retains actual common acquisitions beside their upper role semantics.
//!
//! The writable and readonly children keep first causes, original native
//! custody, semantic work and independently owed name observations together.
//! Native opening, parser, index and tail bodies live only in their canonical
//! lower owners; these wrappers retain the real role lenders and their gates.

mod captured_preparation;
mod captured_readonly;
mod readonly;
mod writable;

pub(crate) use readonly::ReadOnlyJournalOpenOriginalsV1;
pub(crate) use writable::ProtectedWriterOpenOriginalsV1;

use std::path::Path;

#[cfg(target_os = "linux")]
use super::super::super::runtime_deployment_history;
use super::super::super::{JournalAuthorityInstance, RecoveryReport, validate_limits};
use super::super::{
    Journal, JournalError, JournalLimits, ReadOnlyJournalNameWitness, ReadOnlyProtectedJournal,
};

#[derive(Debug, thiserror::Error)]
#[error("read-only original opening is closed")]
pub(in crate::journal) struct ReadOnlyOpenClosedV1;

static READ_ONLY_OPEN_CLOSED: ReadOnlyOpenClosedV1 = ReadOnlyOpenClosedV1;
