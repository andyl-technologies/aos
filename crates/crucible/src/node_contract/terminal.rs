//! Original terminal-assertion custody under an authenticated live world fence.
//!
//! Native inventories are claims until their actual owning adapter validates
//! them. The opaque barrier is minted only from complete live coordinator and
//! native scope. Its serialized checkpoint retains facts, never live authority.

use std::rc::Rc;

use crucible_node_contract::{Bytes, ContentRef, Id, Position};
use serde::{Deserialize, Serialize};

use super::{OwnerIdentity, WorldActivation};

/// Selects an authenticated complete native future-work disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeTerminalDisposition {
    /// Complete native evidence excludes future work independently of input.
    Unconditional,
    /// Native work is drained, but every admitted input producer must be closed.
    InputsDrained,
}

/// Describes complete original native terminal scope without issuing authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTerminalInventory {
    /// Names the authentic logical participant.
    pub node: Id,
    /// Retains the complete current native owner incarnations.
    pub owners: Vec<OwnerIdentity>,
    /// Retains its actual stopped local cut, never a requested later horizon.
    pub boundary: Position,
    /// States the authenticated complete future-work condition.
    pub disposition: NativeTerminalDisposition,
    /// Retains genuine original native inventory bytes and their selected codec.
    pub receipt: crate::node_scheduling::InputPayload,
}

/// Retains original barrier facts without reconstructing process-local authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldTerminalRecord {
    /// Selects the closed terminal record edition, one.
    pub version: u16,
    /// Names the original terminal operation without replacing it on retry.
    pub operation: Id,
    /// Names the only participant permitted to finalize assertions.
    pub node: Id,
    /// Retains the complete original committed activation and owner roster.
    pub source: super::SavedRuntimeActivation,
    /// Retains the maximum authentic local cut rather than a caller's horizon.
    pub cut: Position,
    /// Binds the complete unchanged live scheduler snapshot bytes.
    pub scheduler: Bytes,
    /// Retains native original proofs in increasing logical node order.
    pub native: Vec<NativeTerminalInventory>,
}

/// Carries live original terminal authority issued only by its owning runtime.
///
/// This type has no public constructor, clone or deserializer. Dropping it does
/// not remove the retained runtime fence or authorize a replacement operation.
pub struct AuthenticatedWorldTerminal {
    pub(super) authority: Rc<()>,
    pub(super) activation: WorldActivation,
    pub(super) record: WorldTerminalRecord,
    pub(super) reference: ContentRef,
}

impl AuthenticatedWorldTerminal {
    /// Returns original immutable barrier facts without transferring authority.
    pub fn record(&self) -> &WorldTerminalRecord {
        &self.record
    }

    /// Returns the original barrier receipt retained through finalization.
    pub fn receipt(&self) -> &ContentRef {
        &self.reference
    }
}

impl std::fmt::Debug for AuthenticatedWorldTerminal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedWorldTerminal")
            .field("operation", &self.record.operation)
            .field("node", &self.record.node)
            .field("cut", &self.record.cut)
            .finish_non_exhaustive()
    }
}

/// Retains a terminal fence and original native result stages for selected codecs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedWorldTerminal {
    /// Retains the original complete barrier context and immutable source proofs.
    pub record: WorldTerminalRecord,
    /// Binds exact original canonical record bytes.
    pub reference: ContentRef,
    /// Marks original native finalization submission, never reset by token drop.
    pub submitted: bool,
    /// Retains the actual original native report, including after output ACK.
    pub report: Option<crate::node_scheduling::InputPayload>,
    /// Retains publication knowledge; uncertainty never authorizes native ACK.
    pub publication: Option<TerminalPublicationState>,
    /// Retains an original acknowledged terminal result, when available.
    pub acknowledged: bool,
}

pub(super) struct TerminalState {
    pub(super) saved: SavedWorldTerminal,
}

/// Retains actual publication knowledge for the original terminal report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalPublicationState {
    /// The original complete report is durably recoverable.
    Committed,
    /// The publisher positively establishes that no report was committed.
    NotCommitted,
    /// The original attempt may have committed and must be reconciled.
    Unknown,
}

/// Publishes exact original terminal facts and actual native assertion bytes.
///
/// Implementations form a trusted storage boundary. A committed result means
/// both supplied objects are durable under their exact content identities;
/// transport acknowledgement or a caller-provided report hash is insufficient.
pub trait TerminalResultPublisher {
    /// Attempts publication of these exact original immutable objects.
    fn publish(
        &mut self,
        barrier: &crate::node_scheduling::InputPayload,
        report: &crate::node_scheduling::InputPayload,
    ) -> super::PublicationStatus;

    /// Reconciles the same original attempt without dispatching native work.
    fn reconcile(
        &mut self,
        barrier: &crate::node_scheduling::InputPayload,
        report: &crate::node_scheduling::InputPayload,
    ) -> super::PublicationStatus;
}

/// Authorizes acknowledgement of an original durably committed terminal result.
///
/// This process-local value has no public constructor or deserializer. Its
/// immutable references remain bound to the same live runtime and operation.
pub struct TerminalResultCommit {
    pub(super) authority: Rc<()>,
    pub(super) operation: Id,
    pub(super) node: Id,
    pub(super) barrier: ContentRef,
    pub(super) report: ContentRef,
}

impl TerminalResultCommit {
    /// Returns the original terminal report identity without transferring authority.
    pub fn report(&self) -> &ContentRef {
        &self.report
    }
}

impl std::fmt::Debug for TerminalResultCommit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TerminalResultCommit")
            .field("operation", &self.operation)
            .field("node", &self.node)
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}
