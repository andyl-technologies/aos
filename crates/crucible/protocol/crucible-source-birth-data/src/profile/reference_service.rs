//! Retains installed byte/reference pairs without opening paths or issuing custody.

use crucible_node_format::{Bytes, ContentRef};
use serde::{Deserialize, Serialize};

/// Supplies exact privately installed content without interpreting references as paths.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledContent {
    /// Commits to the complete installed bytes.
    pub reference: ContentRef,
    /// Supplies complete content through the launcher's private channel.
    pub bytes: Bytes,
}
