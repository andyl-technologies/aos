//! Atomic admission of a complete retained-template QEMU child world.
//!
//! Per-node hot-fork launch owns useful process and channel authority, but a
//! campaign branch is not executable until every retained source is paired
//! with the same process-neutral world continuation. This module keeps those
//! children inaccessible during assembly, exact-binds each one to its installed
//! node/source process/configuration/event prefix and assembly incarnation, and
//! publishes one opaque complete-world capability only after every retained
//! source is present, including paused powered-off nodes. Dropping an
//! incomplete assembly transfers every admitted child to its existing
//! fail-closed quarantine path.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crucible::{ContentHash, EventLogOffset, NodeId};
// crucible-lint: allow host-nondeterminism-state -- assembly authenticates an unchanged captured world against its exact child roster; host timing cannot edit the continuation.
use crucible_api::vm_lifecycle::{
    ProductionVmHotForkNodeServiceState, ProductionVmHotForkWorldContinuation,
};
use crucible_qemu::QemuProcessIdentity;

use crate::{
    LinuxQemuHotForkReconciliationBackend, QemuAttemptResourceGuard,
    QemuHotForkAttemptReconciliation, QemuHotForkWorldChildSourceBasis,
};

/// Unforgeable process-local identity of one atomic world assembly attempt.
///
/// Only [`QemuHotForkWorldAssembly::child_launch_token`] can clone this token.
/// A per-node launcher retains that clone in the resulting reconciliation
/// owner, preventing children from another retry or concurrent assembly from
/// being mixed into this world even when all semantic source fields match.
#[derive(Clone)]
pub struct QemuHotForkWorldAssemblyToken {
    identity: Arc<()>,
}

impl QemuHotForkWorldAssemblyToken {
    fn new() -> Self {
        Self {
            identity: Arc::new(()),
        }
    }

    fn same_assembly(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

impl fmt::Debug for QemuHotForkWorldAssemblyToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuHotForkWorldAssemblyToken")
            .finish_non_exhaustive()
    }
}

mod sealed {
    pub trait QemuHotForkWorldChild {}
}

/// One authenticated live child that can participate in atomic world assembly.
///
/// The trait is sealed because installed-node, source-process, configuration,
/// event-prefix, and assembly-incarnation claims must come from the concrete
/// reconciliation owner rather than from a caller-provided implementation.
pub trait QemuHotForkWorldChild: sealed::QemuHotForkWorldChild {
    /// Typed child inspection failure.
    type Error: Error;

    /// Returns the exact retained source basis after node installation.
    ///
    /// # Errors
    ///
    /// Returns the reconciliation failure when the child has not completed
    /// private-channel admission and process-neutral scheduler installation.
    fn source_basis(&self) -> Result<QemuHotForkWorldChildSourceBasis, Self::Error>;

    /// Returns the exact world assembly for which this child was launched.
    #[must_use]
    fn world_assembly_token(&self) -> Option<&QemuHotForkWorldAssemblyToken>;

    /// Transfers every incomplete child authority to fail-closed quarantine.
    fn quarantine(&mut self);
}

impl<G> sealed::QemuHotForkWorldChild
    for QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>
where
    G: QemuAttemptResourceGuard,
{
}

impl<G> QemuHotForkWorldChild
    for QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>
where
    G: QemuAttemptResourceGuard,
{
    type Error = Box<
        crate::QemuHotForkAttemptReconciliationError<crate::LinuxQemuHotForkReconciliationError>,
    >;

    fn source_basis(&self) -> Result<QemuHotForkWorldChildSourceBasis, Self::Error> {
        self.world_child_source_basis()
    }

    fn world_assembly_token(&self) -> Option<&QemuHotForkWorldAssemblyToken> {
        QemuHotForkAttemptReconciliation::world_assembly_token(self)
    }

    fn quarantine(&mut self) {
        QemuHotForkAttemptReconciliation::quarantine(self);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExpectedWorldSource {
    process: QemuProcessIdentity,
}

/// Reason one child was refused before it could enter a world transaction.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QemuHotForkWorldChildAdmissionFailure {
    /// The continuation does not retain a source QEMU for this node.
    #[error("hot-fork child node is not a retained source member of the captured world")]
    UnexpectedNode,
    /// Another child already occupies the exact node coordinate.
    #[error("hot-fork world already contains a child for this node")]
    DuplicateNode,
    /// The child has not completed private-channel and scheduler-node admission.
    #[error("hot-fork child is not ready for world admission: {message}")]
    ChildNotReady {
        /// Bounded diagnostic from the retained child owner.
        message: String,
    },
    /// The child was forked from another modeled configuration.
    #[error("hot-fork child source configuration differs from the world continuation")]
    ConfigurationMismatch,
    /// The installed scheduler node differs from the assembly coordinate.
    #[error("hot-fork child scheduler node differs from the world coordinate")]
    NodeMismatch,
    /// The child's cloned event prefix differs from the world continuation.
    #[error("hot-fork child event prefix differs from the world continuation")]
    EventLogMismatch,
    /// The child belongs to another source-QEMU process incarnation.
    #[error("hot-fork child source process differs from the world continuation")]
    SourceProcessMismatch,
    /// The child was launched for another world transaction or for the legacy
    /// single-node execution path.
    #[error("hot-fork child belongs to another world assembly")]
    WorldAssemblyMismatch,
}

/// Rejected child admission retaining the exact child authority.
#[must_use = "quarantine, retry, or otherwise retain the rejected child authority"]
pub struct QemuHotForkWorldChildAdmissionError<C> {
    node: NodeId,
    child: C,
    failure: QemuHotForkWorldChildAdmissionFailure,
}

impl<C> QemuHotForkWorldChildAdmissionError<C> {
    /// Consumes the error into its node, unchanged child, and typed failure.
    pub fn into_parts(self) -> (NodeId, C, QemuHotForkWorldChildAdmissionFailure) {
        (self.node, self.child, self.failure)
    }
}

impl<C> fmt::Debug for QemuHotForkWorldChildAdmissionError<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuHotForkWorldChildAdmissionError")
            .field("node", &self.node)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl<C> fmt::Display for QemuHotForkWorldChildAdmissionError<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "admit hot-fork child `{}` into world: {}",
            self.node.name, self.failure
        )
    }
}

impl<C> Error for QemuHotForkWorldChildAdmissionError<C> where C: 'static {}

/// Incomplete world publication retaining every already-admitted child.
#[must_use = "complete the world or transfer the retained assembly to quarantine"]
pub struct QemuHotForkWorldIncomplete<C>
where
    C: QemuHotForkWorldChild,
{
    assembly: Box<QemuHotForkWorldAssembly<C>>,
    missing: Vec<NodeId>,
}

impl<C> QemuHotForkWorldIncomplete<C>
where
    C: QemuHotForkWorldChild,
{
    /// Returns the canonically ordered retained source nodes missing a child.
    #[must_use]
    pub fn missing_nodes(&self) -> &[NodeId] {
        &self.missing
    }

    /// Recovers the unchanged assembly for additional admission attempts.
    pub fn into_assembly(self) -> QemuHotForkWorldAssembly<C> {
        *self.assembly
    }
}

impl<C> fmt::Debug for QemuHotForkWorldIncomplete<C>
where
    C: QemuHotForkWorldChild,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuHotForkWorldIncomplete")
            .field("missing", &self.missing)
            .finish_non_exhaustive()
    }
}

impl<C> fmt::Display for QemuHotForkWorldIncomplete<C>
where
    C: QemuHotForkWorldChild,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "hot-fork world is missing {} retained source children",
            self.missing.len()
        )
    }
}

impl<C> Error for QemuHotForkWorldIncomplete<C> where C: QemuHotForkWorldChild + 'static {}

/// Linear all-or-nothing assembly transaction for one child world.
#[must_use = "publish a complete child world or retain it for fail-closed cleanup"]
pub struct QemuHotForkWorldAssembly<C>
where
    C: QemuHotForkWorldChild,
{
    continuation: Option<ProductionVmHotForkWorldContinuation>,
    token: QemuHotForkWorldAssemblyToken,
    configuration: ContentHash,
    event_log_offset: EventLogOffset,
    expected: BTreeMap<NodeId, ExpectedWorldSource>,
    children: BTreeMap<NodeId, C>,
    published: bool,
}

impl<C> QemuHotForkWorldAssembly<C>
where
    C: QemuHotForkWorldChild,
{
    /// Starts one assembly from an opaque, completely captured continuation.
    pub fn new(continuation: ProductionVmHotForkWorldContinuation) -> Self {
        let configuration = continuation.configuration().id();
        let event_log_offset = continuation.event_log_offset();
        let expected = continuation
            .nodes()
            .iter()
            .filter_map(|boundary| match boundary.service_state() {
                ProductionVmHotForkNodeServiceState::Running
                | ProductionVmHotForkNodeServiceState::PoweredOff => boundary
                    .process()
                    .cloned()
                    .map(|process| (boundary.node().clone(), ExpectedWorldSource { process })),
                ProductionVmHotForkNodeServiceState::PermanentlyFailed => None,
            })
            .collect();
        Self {
            continuation: Some(continuation),
            token: QemuHotForkWorldAssemblyToken::new(),
            configuration,
            event_log_offset,
            expected,
            children: BTreeMap::new(),
            published: false,
        }
    }

    /// Returns the number of retained source nodes required by this world.
    #[must_use]
    pub fn expected_child_count(&self) -> usize {
        self.expected.len()
    }

    /// Returns the number of exact children admitted so far.
    #[must_use]
    pub fn admitted_child_count(&self) -> usize {
        self.children.len()
    }

    /// Clones the unforgeable identity required by every per-node launch.
    #[must_use]
    pub fn child_launch_token(&self) -> QemuHotForkWorldAssemblyToken {
        self.token.clone()
    }

    /// Exact-binds one installed child without exposing it to modeled code.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkWorldChildAdmissionError`] with the unchanged child
    /// when the node is unexpected or duplicate, the child is not fully
    /// installed, or any source configuration, event prefix, or process
    /// incarnation differs from the captured world.
    pub fn admit_child(
        &mut self,
        node: NodeId,
        child: C,
    ) -> Result<(), QemuHotForkWorldChildAdmissionError<C>> {
        let result = match self.expected.get(&node) {
            None => Err(QemuHotForkWorldChildAdmissionFailure::UnexpectedNode),
            Some(_) if self.children.contains_key(&node) => {
                Err(QemuHotForkWorldChildAdmissionFailure::DuplicateNode)
            }
            Some(expected) => match child.world_assembly_token() {
                Some(token) if token.same_assembly(&self.token) => child
                    .source_basis()
                    .map_err(
                        |error| QemuHotForkWorldChildAdmissionFailure::ChildNotReady {
                            message: error.to_string().chars().take(512).collect(),
                        },
                    )
                    .and_then(|basis| {
                        validate_world_child_basis(
                            &node,
                            self.configuration,
                            self.event_log_offset,
                            &expected.process,
                            &basis,
                        )
                    }),
                Some(_) | None => Err(QemuHotForkWorldChildAdmissionFailure::WorldAssemblyMismatch),
            },
        };
        if let Err(failure) = result {
            return Err(QemuHotForkWorldChildAdmissionError {
                node,
                child,
                failure,
            });
        }
        self.children.insert(node, child);
        Ok(())
    }

    /// Publishes one capability only when every retained source node is present.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkWorldIncomplete`] with the unchanged assembly and
    /// canonically ordered missing-node set when any retained source is absent.
    pub fn publish(
        mut self,
    ) -> Result<QemuHotForkCompleteWorldAssembly<C>, QemuHotForkWorldIncomplete<C>> {
        let missing = self
            .expected
            .keys()
            .filter(|node| !self.children.contains_key(*node))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(QemuHotForkWorldIncomplete {
                assembly: Box::new(self),
                missing,
            });
        }
        let Some(continuation) = self.continuation.take() else {
            return Err(QemuHotForkWorldIncomplete {
                assembly: Box::new(self),
                missing: Vec::new(),
            });
        };
        let children = std::mem::take(&mut self.children);
        self.published = true;
        Ok(QemuHotForkCompleteWorldAssembly {
            continuation,
            children,
        })
    }
}

impl<C> Drop for QemuHotForkWorldAssembly<C>
where
    C: QemuHotForkWorldChild,
{
    fn drop(&mut self) {
        if self.published {
            return;
        }
        for child in self.children.values_mut() {
            child.quarantine();
        }
    }
}

/// Complete child set awaiting authoritative scheduler-lifecycle installation.
///
/// The type exposes no individual child. A later world installer must consume
/// the whole value, install the one unified event log and host continuation,
/// and only then lend modeled execution capability.
#[must_use = "install the complete child set or retain it for fail-closed cleanup"]
pub struct QemuHotForkCompleteWorldAssembly<C>
where
    C: QemuHotForkWorldChild,
{
    continuation: ProductionVmHotForkWorldContinuation,
    children: BTreeMap<NodeId, C>,
}

impl<C> QemuHotForkCompleteWorldAssembly<C>
where
    C: QemuHotForkWorldChild,
{
    /// Returns the exact process-neutral host continuation for this world.
    pub const fn continuation(&self) -> &ProductionVmHotForkWorldContinuation {
        &self.continuation
    }

    /// Returns the number of installed running QEMU children.
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.children.len()
    }
}

fn validate_world_child_basis(
    node: &NodeId,
    configuration: ContentHash,
    event_log_offset: EventLogOffset,
    process: &QemuProcessIdentity,
    basis: &QemuHotForkWorldChildSourceBasis,
) -> Result<(), QemuHotForkWorldChildAdmissionFailure> {
    if basis.node() != node {
        return Err(QemuHotForkWorldChildAdmissionFailure::NodeMismatch);
    }
    if basis.configuration() != configuration {
        return Err(QemuHotForkWorldChildAdmissionFailure::ConfigurationMismatch);
    }
    if basis.event_log_offset() != event_log_offset {
        return Err(QemuHotForkWorldChildAdmissionFailure::EventLogMismatch);
    }
    if basis.process() != process {
        return Err(QemuHotForkWorldChildAdmissionFailure::SourceProcessMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Clone, Debug, thiserror::Error)]
    #[error("injected child inspection failure")]
    struct FakeChildError;

    struct FakeChild {
        basis: Result<QemuHotForkWorldChildSourceBasis, FakeChildError>,
        token: Option<QemuHotForkWorldAssemblyToken>,
        quarantined: Arc<AtomicUsize>,
    }

    impl sealed::QemuHotForkWorldChild for FakeChild {}

    impl QemuHotForkWorldChild for FakeChild {
        type Error = FakeChildError;

        fn source_basis(&self) -> Result<QemuHotForkWorldChildSourceBasis, Self::Error> {
            self.basis.clone()
        }

        fn world_assembly_token(&self) -> Option<&QemuHotForkWorldAssemblyToken> {
            self.token.as_ref()
        }

        fn quarantine(&mut self) {
            self.quarantined.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn process(process_id: u32) -> QemuProcessIdentity {
        QemuProcessIdentity {
            process_id,
            start_time_ticks: u64::from(process_id) + 100,
            executable: PathBuf::from("/aos/qemu-system-test"),
        }
    }

    fn basis(
        node: NodeId,
        configuration: ContentHash,
        event_log_offset: EventLogOffset,
        process: QemuProcessIdentity,
    ) -> QemuHotForkWorldChildSourceBasis {
        QemuHotForkWorldChildSourceBasis::for_test(node, configuration, event_log_offset, process)
    }

    #[test]
    fn child_basis_requires_exact_node_configuration_log_and_source_process() {
        let configuration = ContentHash::from_bytes(b"world-configuration");
        let event_log_offset = EventLogOffset::new(ContentHash::from_bytes(b"event-prefix"), 17, 2);
        let expected_process = process(41);
        let expected_node = NodeId {
            name: String::from("vm-a"),
        };

        assert_eq!(
            validate_world_child_basis(
                &expected_node,
                configuration,
                event_log_offset,
                &expected_process,
                &basis(
                    expected_node.clone(),
                    configuration,
                    event_log_offset,
                    expected_process.clone(),
                ),
            ),
            Ok(())
        );
        assert_eq!(
            validate_world_child_basis(
                &expected_node,
                configuration,
                event_log_offset,
                &expected_process,
                &basis(
                    NodeId {
                        name: String::from("vm-b"),
                    },
                    configuration,
                    event_log_offset,
                    expected_process.clone(),
                ),
            ),
            Err(QemuHotForkWorldChildAdmissionFailure::NodeMismatch)
        );
        assert_eq!(
            validate_world_child_basis(
                &expected_node,
                configuration,
                event_log_offset,
                &expected_process,
                &basis(
                    expected_node.clone(),
                    ContentHash::from_bytes(b"foreign-configuration"),
                    event_log_offset,
                    expected_process.clone(),
                ),
            ),
            Err(QemuHotForkWorldChildAdmissionFailure::ConfigurationMismatch)
        );
        assert_eq!(
            validate_world_child_basis(
                &expected_node,
                configuration,
                event_log_offset,
                &expected_process,
                &basis(
                    expected_node.clone(),
                    configuration,
                    EventLogOffset::new(ContentHash::from_bytes(b"foreign-prefix"), 18, 2),
                    expected_process.clone(),
                ),
            ),
            Err(QemuHotForkWorldChildAdmissionFailure::EventLogMismatch)
        );
        assert_eq!(
            validate_world_child_basis(
                &expected_node,
                configuration,
                event_log_offset,
                &expected_process,
                &basis(
                    expected_node.clone(),
                    configuration,
                    event_log_offset,
                    process(42),
                ),
            ),
            Err(QemuHotForkWorldChildAdmissionFailure::SourceProcessMismatch)
        );
    }

    #[test]
    fn partial_multi_node_assembly_never_publishes_and_quarantines_admitted_children() {
        let configuration = ContentHash::from_bytes(b"world-configuration");
        let event_log_offset = EventLogOffset::new(ContentHash::from_bytes(b"event-prefix"), 17, 2);
        let first = NodeId {
            name: String::from("vm-a"),
        };
        let second = NodeId {
            name: String::from("vm-b"),
        };
        let first_process = process(41);
        let second_process = process(42);
        let quarantined = Arc::new(AtomicUsize::new(0));
        let token = QemuHotForkWorldAssemblyToken::new();
        let mut assembly = QemuHotForkWorldAssembly {
            continuation: None,
            token: token.clone(),
            configuration,
            event_log_offset,
            expected: BTreeMap::from([
                (
                    first.clone(),
                    ExpectedWorldSource {
                        process: first_process.clone(),
                    },
                ),
                (
                    second.clone(),
                    ExpectedWorldSource {
                        process: second_process.clone(),
                    },
                ),
            ]),
            children: BTreeMap::new(),
            published: false,
        };
        assembly
            .admit_child(
                first.clone(),
                FakeChild {
                    basis: Ok(basis(first, configuration, event_log_offset, first_process)),
                    token: Some(token.clone()),
                    quarantined: Arc::clone(&quarantined),
                },
            )
            .unwrap_or_else(|error| panic!("first exact child should be admitted: {error}"));

        let rejected = assembly
            .admit_child(
                second.clone(),
                FakeChild {
                    basis: Ok(basis(
                        second.clone(),
                        configuration,
                        event_log_offset,
                        second_process.clone(),
                    )),
                    token: Some(QemuHotForkWorldAssemblyToken::new()),
                    quarantined: Arc::clone(&quarantined),
                },
            )
            .err()
            .unwrap_or_else(|| panic!("foreign world token should fail closed"));
        let (_node, mut rejected_child, failure) = rejected.into_parts();
        assert_eq!(
            failure,
            QemuHotForkWorldChildAdmissionFailure::WorldAssemblyMismatch
        );
        rejected_child.quarantine();

        let rejected = assembly
            .admit_child(
                second.clone(),
                FakeChild {
                    basis: Ok(basis(
                        second.clone(),
                        ContentHash::from_bytes(b"foreign-configuration"),
                        event_log_offset,
                        second_process,
                    )),
                    token: Some(token),
                    quarantined: Arc::clone(&quarantined),
                },
            )
            .err()
            .unwrap_or_else(|| panic!("cross-configuration child should fail closed"));
        let (_node, mut rejected_child, failure) = rejected.into_parts();
        assert_eq!(
            failure,
            QemuHotForkWorldChildAdmissionFailure::ConfigurationMismatch
        );
        rejected_child.quarantine();

        let incomplete = assembly
            .publish()
            .err()
            .unwrap_or_else(|| panic!("partial child world must not publish"));
        assert_eq!(incomplete.missing_nodes(), &[second]);
        drop(incomplete);
        assert_eq!(quarantined.load(Ordering::Acquire), 3);
    }
}
