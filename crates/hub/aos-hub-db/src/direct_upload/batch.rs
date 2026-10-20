//! Internal broker reply projections consumed before Native visibility commits.

use super::{DirectCompletionEvidence, DirectItemError, DirectPartGrant, DirectSessionStatus};
use serde::{Deserialize, Serialize};

/// Bounded response collections; aggregate bytes include every URL and header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectUploadReply {
    /// Echo of the originating immutable batch operation, when present.
    pub operation_id: String,
    /// Independent logical admission/status/completion projections.
    pub sessions: Vec<DirectSessionStatus>,
    /// Exact delegated capabilities, bounded after destination fanout.
    pub grants: Vec<DirectPartGrant>,
    /// Verified broker evidence; logical visibility still needs Native commit.
    pub completions: Vec<DirectCompletionEvidence>,
    /// Per-item refusals correlated independently of successful items.
    pub errors: Vec<DirectItemError>,
}
