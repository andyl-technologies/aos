//! Enrolls complete staging oracles from original source callbacks before reports.
//!
//! The fixed programme supplies semantic expectations. Unpredictable world and
//! native ACK fields are enrolled only from opaque runtime/source custody; a
//! common completion or serialized Passed report cannot supply these holders.

use std::cell::{Ref, RefCell};

use crucible::{
    node_adapters::cnp::OriginalRuntimeLineage,
    node_contract::{
        InputProvenanceClosure, OriginalInputLineage, OriginalPublicationClaim, WorldActivation,
    },
    node_scheduling::RuntimeInputBatch,
};
use crucible_node_contract::{ContentRef, Id, U64, canonical};
use crucible_node_provider::ProviderError;
use serde::Serialize;
use serde_json::Value;

use super::super::TypedReaderProgramme;
use super::{InstalledTypedReaderSourceFixture, invalid, launch};

#[path = "staging_inventory.rs"]
mod inventory;

const MAXIMUM_BYTES: usize = 16 * 1024 * 1024;

struct Pending {
    stage: Id,
    input: Value,
    provenance: Value,
    publications: Value,
    claims: Vec<OriginalPublicationClaim>,
}

struct Complete {
    case: String,
    input: ContentRef,
    staging: ContentRef,
    bytes: Vec<u8>,
}

pub(super) struct StageOracles {
    pending: RefCell<Vec<Pending>>,
    complete: RefCell<Vec<Complete>>,
}

impl StageOracles {
    pub(super) fn new() -> Result<Self, ProviderError> {
        let mut pending = Vec::new();
        let mut complete = Vec::new();
        pending.try_reserve_exact(9).map_err(|_| invalid())?;
        complete.try_reserve_exact(9).map_err(|_| invalid())?;
        Ok(Self {
            pending: RefCell::new(pending),
            complete: RefCell::new(complete),
        })
    }

    pub(super) fn retain_inputs(
        &self,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<(), ProviderError> {
        if batch.deliveries().is_empty()
            || batch.deliveries().len() > 2
            || lineage.publications().len() != batch.deliveries().len()
        {
            return Err(invalid());
        }
        // Count the entire borrowed tuple before reconstructing any body value.
        let input = InputView::from(batch);
        let provenance_view = ProvenanceView {
            version: provenance.version(),
            activation: activation(provenance.activation()),
            node: provenance.node(),
            stage: provenance.stage_operation(),
            batch: provenance.batch(),
            inventory: provenance.inventory(),
            roots: provenance.roots(),
            objects: provenance.objects(),
        };
        let claims = Claims(lineage.publications());
        super::super::programme::count(&(&input, &provenance_view, &claims), MAXIMUM_BYTES)?;
        let input = value(&input)?;
        let provenance_view = value(&provenance_view)?;
        let publications = value(&claims)?;
        let mut pending = self.pending.try_borrow_mut().map_err(|_| invalid())?;
        if let Some(old) = pending
            .iter()
            .find(|old| &old.stage == batch.stage_operation())
        {
            return if old.input == input
                && old.provenance == provenance_view
                && old.publications == publications
                && old.claims == lineage.publications()
            {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if pending.len() >= 9 {
            return Err(invalid());
        }
        pending.push(Pending {
            stage: batch.stage_operation().clone(),
            input,
            provenance: provenance_view,
            publications,
            claims: lineage.publications().to_vec(),
        });
        Ok(())
    }

    pub(super) fn enroll_window(
        &self,
        programme: &TypedReaderProgramme,
        original: &OriginalRuntimeLineage<'_>,
    ) -> Result<(), ProviderError> {
        let batch = original.input();
        let source = original.source();
        let planned = programme.window(batch.node(), source.native_stage().grant.quantum)?;
        if planned.stage != *batch.stage_operation() || planned.batch != *batch.batch() {
            return Err(invalid());
        }
        let input = value(&InputView::from(batch))?;
        let pending = self.pending.try_borrow().map_err(|_| invalid())?;
        let retained = pending.iter().find(|old| old.stage == planned.stage);
        if retained.is_some_and(|old| old.input != input)
            || (retained.is_none() && !batch.deliveries().is_empty())
        {
            return Err(invalid());
        }
        let claims = retained.map(|old| old.claims.as_slice()).unwrap_or(&[]);
        let native = inventory::native_input(original, claims)?;
        // This selected adapter requires provenance/lineage exactly for
        // nonempty batches. An empty stage cannot inherit an earlier proof.
        // implementation.rs/delegate.rs enforce that source-owned contract;
        // a changed adapter is outside this independently measured fixture.
        if batch.deliveries().is_empty() && retained.is_some() {
            return Err(invalid());
        }
        let acknowledgement = AcknowledgementView {
            stage_operation: batch.stage_operation(),
            batch: batch.batch(),
            node: batch.node(),
            owners: batch.owners(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory(),
            proof_ref: &source.stop().input_custody,
        };
        let commit = CommitView {
            activation: activation(batch.activation()),
            node: batch.node(),
            stage: batch.stage_operation(),
            batch: batch.batch(),
            inventory: batch.inventory(),
            cutoff: batch.cutoff(),
        };
        let staging = StagedView {
            schema: "crucible.original-staged-input-witness.v1",
            input: &input,
            provenance: retained.map(|old| &old.provenance),
            publications: retained.map(|old| &old.publications),
            acknowledgement,
            native_evidence: &native,
            coordinator_commit: Some(commit),
            committed: true,
        };
        // The complete borrowed envelope is charged before canonical Value or
        // final bytes are allocated. Native/publication bodies stay original.
        let bytes = launch::encode(&staging, MAXIMUM_BYTES)?;
        let input_ref =
            canonical::content_ref(&launch::encode(&input, MAXIMUM_BYTES)?, "application/json")?;
        let staging_ref = canonical::content_ref(&bytes, "application/json")?;
        let mut complete = self.complete.try_borrow_mut().map_err(|_| invalid())?;
        if let Some(old) = complete.iter().find(|old| old.case == planned.case) {
            return if old.input == input_ref && old.staging == staging_ref && old.bytes == bytes {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if complete.len() >= 9 {
            return Err(invalid());
        }
        complete.push(Complete {
            case: planned.case.clone(),
            input: input_ref,
            staging: staging_ref,
            bytes,
        });
        Ok(())
    }
}

impl InstalledTypedReaderSourceFixture {
    /// Borrows the complete original staging body under current source custody.
    ///
    /// This data-only view retains the existing source-enrolled body without
    /// copies or mutable enrollment access. It does not authorize Stage or ACK.
    /// The caller must drop the borrow before any effect-capable source callback.
    ///
    /// # Errors
    /// Refuses an unplanned or unenrolled case, a held mutable staging borrow,
    /// changed complete staging bytes or revoked original source/kernel scope.
    pub(in super::super) fn original_staging_bytes(
        &self,
        case: &str,
    ) -> Result<Ref<'_, [u8]>, ProviderError> {
        let planned = self
            .programme
            .windows()
            .iter()
            .find(|planned| planned.case == case)
            .ok_or_else(invalid)?;
        self.current(&planned.node)?;
        let complete = self.staging.complete.try_borrow().map_err(|_| invalid())?;
        let original = complete
            .iter()
            .find(|original| original.case == case)
            .ok_or_else(invalid)?;
        original.staging.verify(&original.bytes)?;
        self.current(&planned.node)?;
        Ref::filter_map(complete, |entries| {
            entries
                .iter()
                .find(|original| original.case == case)
                .map(|original| original.bytes.as_slice())
        })
        .map_err(|_| invalid())
    }

    /// Borrows source-enrolled input and complete staging identities for one planned case.
    ///
    /// These identities were derived in an original native callback, before any
    /// common completion report. The returned data cannot authorize a Stage.
    ///
    /// # Errors
    /// Refuses an unenrolled case or changed actual source/kernel authority.
    pub fn completion_input_oracles(
        &self,
        case: &str,
    ) -> Result<(ContentRef, ContentRef), ProviderError> {
        let planned = self
            .programme
            .windows()
            .iter()
            .find(|planned| planned.case == case)
            .ok_or_else(invalid)?;
        self.current(&planned.node)?;
        let complete = self.staging.complete.try_borrow().map_err(|_| invalid())?;
        let original = complete
            .iter()
            .find(|original| original.case == case)
            .ok_or_else(invalid)?;
        original.staging.verify(&original.bytes)?;
        Ok((original.input.clone(), original.staging.clone()))
    }
}

#[derive(Serialize)]
struct InputView<'a> {
    node: &'a Id,
    stage: &'a Id,
    batch: &'a Id,
    owners: &'a [crucible::node_contract::OwnerIdentity],
    cutoff: crucible_node_contract::Position,
    inventory: &'a ContentRef,
    deliveries: &'a [crucible::node_scheduling::event::Delivery],
    payloads: &'a [crucible::node_scheduling::InputPayload],
}
impl<'a> From<&'a RuntimeInputBatch> for InputView<'a> {
    fn from(batch: &'a RuntimeInputBatch) -> Self {
        Self {
            node: batch.node(),
            stage: batch.stage_operation(),
            batch: batch.batch(),
            owners: batch.owners(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory(),
            deliveries: batch.deliveries(),
            payloads: batch.payloads(),
        }
    }
}
#[derive(Serialize)]
struct Claims<'a>(#[serde(serialize_with = "serialize_claims")] &'a [OriginalPublicationClaim]);
fn serialize_claims<S: serde::Serializer>(
    claims: &[OriginalPublicationClaim],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut sequence = serializer.serialize_seq(Some(claims.len()))?;
    for claim in claims {
        sequence.serialize_element(&(
            &claim.event,
            &claim.origin,
            &claim.published,
            &claim.objects,
            &claim.rows,
        ))?;
    }
    sequence.end()
}
fn activation(
    activation: &WorldActivation,
) -> (
    U64,
    &Id,
    &crucible_node_contract::HashRef,
    &[crucible::node_contract::OwnerIdentity],
    crucible_node_contract::Position,
) {
    let record = activation.record();
    (
        record.generation,
        &record.activation_id,
        &record.world_binding_hash,
        &record.owners,
        record.boundary,
    )
}
fn value(value: &impl Serialize) -> Result<Value, ProviderError> {
    super::super::programme::count(value, MAXIMUM_BYTES)?;
    serde_json::to_value(value)
        .map_err(crucible_node_contract::ContractError::from)
        .map_err(Into::into)
}

#[derive(Serialize)]
struct ProvenanceView<'a> {
    version: u16,
    activation: (
        U64,
        &'a Id,
        &'a crucible_node_contract::HashRef,
        &'a [crucible::node_contract::OwnerIdentity],
        crucible_node_contract::Position,
    ),
    node: &'a Id,
    stage: &'a Id,
    batch: &'a Id,
    inventory: &'a ContentRef,
    roots: &'a [ContentRef],
    objects: &'a [crucible::node_scheduling::InputPayload],
}

#[derive(Serialize)]
struct AcknowledgementView<'a> {
    stage_operation: &'a Id,
    batch: &'a Id,
    node: &'a Id,
    owners: &'a [crucible::node_contract::OwnerIdentity],
    cutoff: crucible_node_contract::Position,
    inventory: &'a ContentRef,
    proof_ref: &'a ContentRef,
}

#[derive(Serialize)]
struct CommitView<'a> {
    activation: (
        U64,
        &'a Id,
        &'a crucible_node_contract::HashRef,
        &'a [crucible::node_contract::OwnerIdentity],
        crucible_node_contract::Position,
    ),
    node: &'a Id,
    stage: &'a Id,
    batch: &'a Id,
    inventory: &'a ContentRef,
    cutoff: crucible_node_contract::Position,
}

#[derive(Serialize)]
struct StagedView<'a> {
    schema: &'static str,
    input: &'a Value,
    provenance: Option<&'a Value>,
    publications: Option<&'a Value>,
    acknowledgement: AcknowledgementView<'a>,
    native_evidence: &'a crucible::node_contract::OriginalInputEvidence,
    coordinator_commit: Option<CommitView<'a>>,
    committed: bool,
}

#[cfg(test)]
// Synthetic encoding controls exercise full borrowed aggregate credit only.
#[path = "staging_tests.rs"]
mod tests;
