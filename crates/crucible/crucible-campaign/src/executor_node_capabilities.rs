//! Versioned realized-owner identities and execution guarantees.
//!
//! The roster binds the whole coupled world, including non-compute owners.
//! Its identity is separate from legacy QEMU campaign lineage and capability
//! formats. No legacy state is relabeled by constructing these records.
//!
//! ```text
//! ExecutorNodeRosterV1 = version | scenario | configuration | graph | owners
//! ExecutorNodeCapabilitiesV2 = version | roster | materialization
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{CampaignCodecError, CampaignHash, ConfigurationArtifactId, ScenarioArtifactId};

mod guarantee;
mod roster;

pub use guarantee::{
    ConditionalTranscriptEvidence, DeterministicExecutionContext, DeterministicExecutionOperation,
    ExecutorNodeCapabilities, NodeExecutionGuarantee, NodeMaterializationStrategy,
    TranscriptQualificationVerifier,
};
pub use roster::{ExecutorNodeRoster, ExecutorOwnerRole, OwnerImplementationBinding};

/// Maximum execution owners retained in one coupled-world roster.
pub const MAX_EXECUTOR_NODE_OWNERS: usize = 4096;

/// Maximum logical node views assigned to one execution owner.
pub const MAX_EXECUTOR_OWNER_NODES: usize = 4096;

const MAX_ROSTER_BYTES: usize = 16 * 1024 * 1024;
const ROSTER_SCHEMA_VERSION: u32 = 1;
const NODE_CAPABILITY_SCHEMA_VERSION: u32 = 2;

fn require_version(actual: u32, expected: u32) -> Result<(), CampaignCodecError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported executor node record schema version",
        })
    }
}

#[cfg(test)]
mod tests;
