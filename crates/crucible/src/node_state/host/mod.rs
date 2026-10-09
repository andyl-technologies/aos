//! Authenticated durable host-model archives and inactive native reconstruction.
//!
//! Archive authentication establishes original host provenance; installed model
//! qualification separately establishes support for the selected native codec.
//! Neither a provider label nor a public content digest issues either authority.

mod archive;
mod capture;
mod driver;

#[cfg(test)]
mod tests;

use crucible_node_contract::{Id, SchemaRef};

use crate::node_adapters::{HostModelNode, HostModelResources};
use crate::node_admission::AdmittedGraph;
use crate::node_contract::{ActivationRecord, RuntimeSnapshot};

use super::{StateError, VerifiedStateContent};

pub use archive::{HostArchive, HostArchiveRecord};
pub use driver::HostWorldRestoreDriver;

/// Authenticates the installed native host model and constructs isolated owners.
///
/// Implementations belong to the trusted local installation. They measure the
/// actual executable and immutable model inputs, including block bases or served
/// trees. They refuse unsupported state editions and source inventories. A
/// public provider descriptor or a matching profile name cannot implement this
/// qualification by itself.
pub trait HostWorldFactory {
    /// Reports an enforced peak native reservation before constructing this owner.
    ///
    /// # Errors
    /// Refuses unavailable accounting or resources beyond installed finite limits.
    fn reservation(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        native: &[u8],
        limits: HostModelResources,
    ) -> Result<super::RestoreReservations, StateError>;

    /// Selects the installed complete continuation codec for this node.
    ///
    /// # Errors
    /// Refuses unsupported implementations, profiles or codecs.
    fn state_schema(&self, graph: &AdmittedGraph, node: &Id) -> Result<SchemaRef, StateError>;

    /// Authenticates complete host coordinator and connection-domain ownership.
    ///
    /// The installed procedure verifies that scheduler/runtime data covers every
    /// future-affecting coordinator object and connection FIFO/credit/custody
    /// domain. Native endpoint codecs alone cannot qualify shared connection or
    /// coordinator state. Unsupported assertion, fault or external-controller
    /// state must be refused rather than replaced with empty initial state.
    ///
    /// # Errors
    /// Refuses missing domain coverage, unsupported coordinator state editions,
    /// incomplete cross-owner custody or unavailable installed procedure evidence.
    fn authenticate_coordinator(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &crate::node_scheduling::SchedulingSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError>;

    /// Authenticates the captured native model and complete immutable source.
    ///
    /// This method has no modeled effects. It positively checks the actual
    /// installed artifact, model definition, selected codec and all immutable
    /// native inputs. The source content has already satisfied cryptographic
    /// identity and finite closure bounds; it is not a qualification claim.
    ///
    /// # Errors
    /// Refuses unavailable installed evidence, changed base/tree/model or an
    /// unsupported original operation, queue or fault inventory.
    fn authenticate_source(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        native: &[u8],
        source: &RuntimeSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError>;

    /// Constructs one exclusively owned, nonautonomous inactive native host node.
    ///
    /// Only local host models with synchronous allocation-failure destruction
    /// belong to this factory. Autonomous resources need a different provider
    /// whose reservation is owned before the external allocation starts. The
    /// returned node must have called its installed model qualification and
    /// actual `prepare_continuation`, retaining the exact original custody.
    ///
    /// # Errors
    /// Refuses unsupported fresh bindings, resource excess, failed installed
    /// qualification or unavailable authenticated native reconstruction.
    fn prepare_node(
        &self,
        graph: &AdmittedGraph,
        node: &Id,
        source: &AuthenticatedHostSource<'_>,
        target: &ActivationRecord,
        limits: HostModelResources,
    ) -> Result<
        (
            HostModelNode,
            crate::node_contract::NativeRuntimeContinuationEvidence,
        ),
        StateError,
    >;
}

/// Borrows original source data authenticated by the local persistent archive.
///
/// Construction is private to the archive driver. An installed model qualifier
/// can require this seal before accepting source lineage during native prepare;
/// public raw bytes and hashes cannot construct one.
pub struct AuthenticatedHostSource<'a> {
    pub(super) node: &'a Id,
    pub(super) native: &'a [u8],
    pub(super) runtime: &'a RuntimeSnapshot,
    pub(super) content: &'a VerifiedStateContent,
}

impl AuthenticatedHostSource<'_> {
    /// Identifies the originally captured component.
    pub fn node(&self) -> &Id {
        self.node
    }

    /// Borrows the complete selected native codec bytes.
    pub fn native(&self) -> &[u8] {
        self.native
    }

    /// Borrows the complete original runtime custody ledger.
    pub fn runtime(&self) -> &RuntimeSnapshot {
        self.runtime
    }

    /// Borrows the authenticated immutable source closure.
    pub fn content(&self) -> &VerifiedStateContent {
        self.content
    }
}

fn native_failure(error: crate::node_contract::OperationFailure) -> StateError {
    StateError::new(
        super::StateErrorCode::NativeEvidence,
        "host native",
        error.reason,
    )
}
