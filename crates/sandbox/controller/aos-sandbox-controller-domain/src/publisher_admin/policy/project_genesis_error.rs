//! Publisher-local failures while joining fixed administrative seed inputs.
//!
//! These errors preserve the existing observation classes and native causes.
//! Source/Root orchestration maps them to its own boundary; Publisher never
//! constructs a Source owner or depends on Source journal/hierarchy custody.

use aos_sandbox_protocol::controller_source_seed::ControllerSourceTreeSeedErrorV1;
use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceDataErrorV1;
use aos_sandbox_protocol::source_project_authorization::ProjectAuthorizationSourceDataErrorV2;

use super::{ProjectAuthorizationSourceErrorV2, PublisherPolicyError};

/// Reports a failed Publisher-side join of the actual administrative inputs.
#[derive(Debug, thiserror::Error)]
pub enum PublisherProjectGenesisErrorV1 {
    /// Framing, sentinels, or exact signed-input joins are invalid.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// The fixed issuer or actual retained Publisher head changed.
    #[error("Source genesis owner or credential is not current")]
    Stale,
    /// Protected Publisher row decoding or historical cross-link replay failed.
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
    /// The independently pinned seed body or signature is invalid.
    #[error(transparent)]
    Seed(#[from] ControllerSourceTreeSeedErrorV1),
    /// The separate authorization or protected Publisher current state failed.
    #[error(transparent)]
    Authorization(#[from] ProjectAuthorizationSourceErrorV2),
}

impl From<ProjectAuthorizationSourceDataErrorV2> for PublisherProjectGenesisErrorV1 {
    fn from(error: ProjectAuthorizationSourceDataErrorV2) -> Self {
        Self::Authorization(error.into())
    }
}

impl From<ControllerSourceGenesisAcceptanceDataErrorV1> for PublisherProjectGenesisErrorV1 {
    fn from(error: ControllerSourceGenesisAcceptanceDataErrorV1) -> Self {
        match error {
            ControllerSourceGenesisAcceptanceDataErrorV1::NonCanonical => Self::NonCanonical,
            ControllerSourceGenesisAcceptanceDataErrorV1::Seed(error) => Self::Seed(error),
            ControllerSourceGenesisAcceptanceDataErrorV1::Authorization(error) => {
                Self::Authorization(error.into())
            }
        }
    }
}
