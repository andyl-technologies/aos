//! Separates actual known Source storage from an original deployment obligation.
//!
//! A whole-holder observer counts the known Source components and authenticates
//! their external reads against its retained original process reservation. The
//! reservation is an operational envelope; it is never added as allocator demand.

use crate::node_contract::RuntimeError;
use crucible_host_resources::{DeploymentResourceLease, DeploymentResourceReadContext};

/// Borrows a Source-produced known component row and its unresolved deployment.
///
/// There is no public numeric constructor. The Source's actual visitor produces
/// this row while retaining its original private installed-mechanism lease.
/// Reading its numeric component cannot complete a deployment or Source admission.
pub struct SourceDeploymentStorageRead<'a> {
    known_requested_bytes: usize,
    deployment: &'a DeploymentResourceLease,
}

impl<'a> SourceDeploymentStorageRead<'a> {
    pub(in crate::node_adapters::cnp) fn from_original(
        known_requested_bytes: usize,
        deployment: &'a DeploymentResourceLease,
    ) -> Self {
        Self {
            known_requested_bytes,
            deployment,
        }
    }

    /// Reports only the actual known Source component requested-byte sum.
    ///
    /// This excludes the externally reserved process runtime. It is not a
    /// complete byte total, resource reservation or Source execution grant.
    pub fn known_requested_bytes_data(&self) -> usize {
        self.known_requested_bytes
    }

    /// Authenticates this Source's read against the whole-holder's same original.
    ///
    /// The enclosing observer must still walk every other actual owner, account
    /// the original reservation once and check the known peak within its policy.
    ///
    /// # Errors
    /// Refuses a foreign, revoked, incomplete or changed process reservation.
    pub fn authenticate_original(
        &self,
        context: &DeploymentResourceReadContext<'_>,
    ) -> Result<(), RuntimeError> {
        self.deployment
            .authenticate_in(context)
            .map_err(|_| RuntimeError::ForeignAuthority)
    }
}
