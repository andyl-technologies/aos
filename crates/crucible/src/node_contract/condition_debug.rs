//! Original event-condition stop, report and resume custody.
//!
//! Native inventory records may retain future events. They do not establish
//! EOF or terminal assertion closure. Only the owning runtime can mint a live
//! effect fence after checking unchanged native and coordinator state.
//!
//! ```text
//! {"version":1,"operation":"original-stop","node":"observer",
//!  "source":{...},"cut":{...},"hit":{...},"scheduler":[...],"native":[...]}
//! ```

use std::rc::Rc;

use crucible_node_contract::{Bytes, ContentRef, Id, Position};
use serde::{Deserialize, Serialize};

use super::{OwnerIdentity, SavedRuntimeActivation, WorldActivation};
use crate::{node_adapters::ConditionHitCandidate, node_scheduling::InputPayload};

/// Retains complete stopped native custody without excluding future work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConditionStopInventory {
    /// Names the actual logical participant.
    pub node: Id,
    /// Retains every current execution and capture owner incarnation.
    pub owners: Vec<OwnerIdentity>,
    /// Retains the actual native cut at which physical progress is withheld.
    pub boundary: Position,
    /// Retains the selected complete native state and original custody ledgers.
    #[serde(with = "reference_only")]
    pub receipt: InputPayload,
    /// Retains actual native dependencies outside the immutable record index.
    ///
    /// Serialization cannot reconstruct or authorize these bodies. Only the
    /// selected complete DAG reader may reopen their original byte closure.
    #[serde(skip)]
    pub proof_objects: Vec<InputPayload>,
}

/// Retains a complete next autonomous event frontier without claiming EOF.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConditionEventFrontier {
    /// Names the actual native participant.
    pub node: Id,
    /// Retains every actual current owner incarnation.
    pub owners: Vec<OwnerIdentity>,
    /// Retains the native boundary at which the next event was observed.
    pub boundary: Position,
    /// Retains the next original autonomous reaction, when one is present.
    ///
    /// Absence means only that this closed native inventory contains no local
    /// event; it excludes neither future admitted input nor whole-world work.
    pub next: Option<Position>,
    /// Retains complete original native evidence and immutable frontier policy.
    #[serde(with = "body")]
    pub receipt: InputPayload,
}

/// Retains the original actual stopped world and triggering native input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionStopRecord {
    /// Selects the independent closed condition-stop grammar, one.
    pub version: u16,
    /// Names the original stop operation, never a replacement run.
    pub operation: Id,
    /// Names the only installed condition observer authorized to report the hit.
    pub node: Id,
    /// Retains the complete original committed activation.
    pub source: SavedRuntimeActivation,
    /// Retains the authentic common cut, independently of hit evaluation time.
    pub cut: Position,
    /// Retains the original evaluated input and immutable outcome.
    pub hit: ConditionHitCandidate,
    /// Retains the complete coordinator state, including future FIFO obligations.
    pub scheduler: Bytes,
    /// Retains native inventories in increasing logical participant order.
    pub native: Vec<NativeConditionStopInventory>,
}

impl ConditionStopRecord {
    /// Verifies complete original index dependencies and byte/object ceilings.
    ///
    /// This data check creates no native or control authority. In particular,
    /// callers must still authenticate the original producer and world scope.
    ///
    /// # Errors
    /// Refuses absent, conflicting, unbound or malformed dependency objects,
    /// changed source body hashes, cycles or exhausted finite closure credit.
    pub fn verify_dependency_closure(
        &self,
        objects: &[&InputPayload],
        maximum_objects: usize,
        maximum_bytes: usize,
    ) -> Result<(), super::OperationFailure> {
        if self.version != 1 || self.native.is_empty() || objects.len() > maximum_objects {
            return Err(super::OperationFailure {
                effects: super::EffectKnowledge::None,
                reason: "condition original dependency inventory refused".into(),
            });
        }
        crate::node_adapters::verify_condition_dependency_closure(
            self.native
                .iter()
                .map(|inventory| inventory.receipt.reference.clone())
                .collect(),
            objects,
            maximum_objects,
            maximum_bytes,
        )
    }

    /// Borrows actual native dependency bodies retained behind this record index.
    ///
    /// Parsed indexes contain no such bodies until the selected source reader
    /// reopens the complete DAG. This iterator grants no live authority.
    pub fn dependency_objects(&self) -> impl Iterator<Item = &InputPayload> {
        self.native.iter().flat_map(|inventory| {
            std::iter::once(&inventory.receipt).chain(&inventory.proof_objects)
        })
    }
}

/// Carries an actual live stop fence issued only by the owning runtime.
///
/// There is no public constructor, clone or decoder. Dropping this value keeps
/// the original runtime fenced; serialized stop records create no authority.
pub struct AuthenticatedConditionStop {
    pub(super) authority: Rc<()>,
    pub(super) activation: WorldActivation,
    pub(super) record: ConditionStopRecord,
    pub(super) reference: ContentRef,
    // Original whole-closure credit is independent of the compact index size.
    pub(super) maximum_bytes: usize,
}

impl AuthenticatedConditionStop {
    /// Returns original stop facts without transferring control authority.
    pub fn record(&self) -> &ConditionStopRecord {
        &self.record
    }

    /// Returns the exact original immutable barrier receipt.
    pub fn receipt(&self) -> &ContentRef {
        &self.reference
    }
}

impl std::fmt::Debug for AuthenticatedConditionStop {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedConditionStop")
            .field("operation", &self.record.operation)
            .field("cut", &self.record.cut)
            .finish_non_exhaustive()
    }
}

/// Selects explicit original control under a separately admitted debug facet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ConditionControlRequest {
    /// Reports the native condition at the actual common stopped cut.
    Stop {
        /// Retains complete original live-scope facts.
        barrier: Box<ConditionStopRecord>,
        /// Binds the exact original canonical barrier bytes.
        receipt: ContentRef,
    },
    /// Releases the original fence after authentic durable report acknowledgement.
    Resume {
        /// Names the original stop, independently of this original resume operation.
        stop_operation: Id,
        /// Binds the original stopped-world record.
        barrier: ContentRef,
        /// Binds the original native diagnostic report.
        report: ContentRef,
    },
}

/// Retains historical report and control facts for the selected debug codec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedConditionStop {
    /// Retains unchanged original stopped-world context.
    pub record: ConditionStopRecord,
    /// Binds exact original canonical barrier bytes.
    pub reference: ContentRef,
    /// Retains original native stop submission, including uncertain outcomes.
    pub submitted: bool,
    /// Retains original native report bodies even after acknowledgement.
    pub report: Option<InputPayload>,
    /// Retains historical successful or uncertain publication knowledge.
    pub publication: Option<ConditionPublicationState>,
    /// Retains original native report acknowledgement, never reset by restore.
    pub acknowledged: bool,
    /// Retains original resume identity before the first native control effect.
    pub resume_operation: Option<Id>,
    /// Retains actual original native resume receipt and once-only control history.
    pub resume_receipt: Option<InputPayload>,
    /// Retains original resume-root publication knowledge.
    pub resume_publication: Option<ConditionPublicationState>,
    /// Retains authentic original resume acknowledgement.
    pub resumed: bool,
}

/// Retains historical publication knowledge without attesting a fresh store.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionPublicationState {
    /// The original immutable barrier and report were durably recoverable.
    Committed,
    /// The trusted publisher positively establishes no original publication.
    NotCommitted,
    /// The original attempt may have committed and requires reconciliation.
    Unknown,
}

pub(super) struct ConditionStopState {
    pub(super) saved: SavedConditionStop,
    // This is a process-local trusted-store check, never a serialized marker.
    pub(super) publication_verified_for: Option<Id>,
}

// The stop index commits bodies without recursively embedding their complete
// prior inventories. Decoding leaves their bodies absent until a selected
// source-qualified DAG reader reopens the full closure.
mod reference_only {
    use super::*;

    pub(super) fn serialize<S: serde::Serializer>(
        value: &InputPayload,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.reference.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<InputPayload, D::Error> {
        Ok(InputPayload {
            reference: ContentRef::deserialize(deserializer)?,
            bytes: Vec::new(),
        })
    }
}

// The independent condition grammar uses opaque octets rather than numeric
// JSON arrays. Large original native records remain bounded byte values, not
// arrays that exceed the common contract's element ceiling.
mod body {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        reference: ContentRef,
        bytes: Bytes,
    }

    pub(super) fn serialize<S: serde::Serializer>(
        value: &InputPayload,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Wire {
            reference: value.reference.clone(),
            bytes: Bytes::new(value.bytes.clone()),
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<InputPayload, D::Error> {
        let value = Wire::deserialize(deserializer)?;
        Ok(InputPayload {
            reference: value.reference,
            bytes: value.bytes.into_vec(),
        })
    }
}

/// Publishes or reconciles these exact original diagnostic roots.
///
/// A positive result attests complete current durability, never merely content
/// syntax, a historical marker, transport acknowledgement or a fresh label.
pub trait ConditionResultPublisher {
    /// Publishes exact original immutable barrier and native report bytes.
    fn publish(
        &mut self,
        barrier: &InputPayload,
        report: &InputPayload,
    ) -> super::PublicationStatus;

    /// Reconciles the same immutable original roots in the current trusted store.
    fn reconcile(
        &mut self,
        barrier: &InputPayload,
        report: &InputPayload,
    ) -> super::PublicationStatus;

    /// Publishes the exact roots and their complete source-owned dependency bodies.
    ///
    /// The default refuses: committing root bytes alone cannot prove durable
    /// native history behind the selected DAG index.
    fn publish_complete(
        &mut self,
        _barrier: &InputPayload,
        _report: &InputPayload,
        _dependencies: &[&InputPayload],
    ) -> super::PublicationStatus {
        super::PublicationStatus::NotCommitted
    }

    /// Reopens every original dependency in the current trusted durable store.
    fn reconcile_complete(
        &mut self,
        _barrier: &InputPayload,
        _report: &InputPayload,
        _dependencies: &[&InputPayload],
    ) -> super::PublicationStatus {
        super::PublicationStatus::NotCommitted
    }

    /// Publishes original stop dependencies and the actual resume receipt.
    fn publish_resume_complete(
        &mut self,
        _barrier: &InputPayload,
        _report: &InputPayload,
        _resume: &InputPayload,
        _dependencies: &[&InputPayload],
    ) -> super::PublicationStatus {
        super::PublicationStatus::NotCommitted
    }

    /// Rechecks all original roots and dependencies before resume acknowledgement.
    fn reconcile_resume_complete(
        &mut self,
        _barrier: &InputPayload,
        _report: &InputPayload,
        _resume: &InputPayload,
        _dependencies: &[&InputPayload],
    ) -> super::PublicationStatus {
        super::PublicationStatus::NotCommitted
    }

    /// Publishes the same roots and original native resume-control receipt.
    ///
    /// The default refuses rather than discarding an unpersisted control decision.
    fn publish_resume(
        &mut self,
        _barrier: &InputPayload,
        _report: &InputPayload,
        _resume: &InputPayload,
    ) -> super::PublicationStatus {
        super::PublicationStatus::NotCommitted
    }

    /// Reconciles all original resume roots in the current trusted store.
    ///
    /// The default refuses without issuing fresh control acknowledgement authority.
    fn reconcile_resume(
        &mut self,
        _barrier: &InputPayload,
        _report: &InputPayload,
        _resume: &InputPayload,
    ) -> super::PublicationStatus {
        super::PublicationStatus::NotCommitted
    }
}

/// Carries fresh current-store proof for acknowledgement of the original report.
///
/// This process-local value has no public constructor or decoder. It never
/// changes the historical source context after native continuation.
pub struct ConditionResultCommit {
    pub(super) authority: Rc<()>,
    pub(super) operation: Id,
    pub(super) barrier: ContentRef,
    pub(super) report: ContentRef,
    pub(super) resume: Option<ContentRef>,
}

impl ConditionResultCommit {
    /// Returns the original diagnostic report identity.
    pub fn report(&self) -> &ContentRef {
        &self.report
    }
}

impl std::fmt::Debug for ConditionResultCommit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConditionResultCommit")
            .field("operation", &self.operation)
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "condition_debug_tests.rs"]
mod tests;
