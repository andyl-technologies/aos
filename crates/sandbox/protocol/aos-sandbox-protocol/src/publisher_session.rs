//! Shares nonauthorizing Publisher session scope DATA across protected owners.
//!
//! The four identities describe trusted configuration. Their nonzero shape
//! proves no process identity, live session, current policy or resource payment.

use aos_sandbox_model::{NodeId, PrincipalId, ProjectId, ResourceId};

/// Describes the Publisher service selected by trusted administration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherSessionScope {
    /// Protected service principal, never inferred from Unix credentials.
    pub principal: PrincipalId,
    /// Node whose Publisher execution is registered.
    pub node: NodeId,
    /// Project served by this execution.
    pub project: ProjectId,
    /// Logical cache resource selected by protected configuration.
    pub cache_resource: ResourceId,
}

/// Reports a reserved zero identity in plain Publisher session scope DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("publisher session scope contains an unspecified binding")]
pub struct InvalidPublisherSessionScopeV1;

impl PublisherSessionScope {
    /// Checks the existing four nonzero identity constraints without authority.
    ///
    /// # Errors
    /// Returns an error if any of the principal, node, project or cache resource
    /// identities is the reserved all-zero value.
    pub fn validate_v1(self) -> Result<(), InvalidPublisherSessionScopeV1> {
        if [
            self.principal.as_bytes(),
            self.node.as_bytes(),
            self.project.as_bytes(),
            self.cache_resource.as_bytes(),
        ]
        .iter()
        .any(|id| **id == [0; 16])
        {
            return Err(InvalidPublisherSessionScopeV1);
        }
        Ok(())
    }
}
