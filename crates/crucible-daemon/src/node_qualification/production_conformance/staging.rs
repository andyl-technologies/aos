//! Serializes complete borrowed producer and native input custody without cloning.

use crucible::node_contract::{
    InputProvenanceClosure, OriginalInputEvidence, OriginalPublicationClaim, OriginalStagedInput,
    OwnerIdentity, WorldActivation,
};
use crucible::node_scheduling::{InputCustodyCommit, InputPayload, NativeInputAcknowledgement};
use crucible_node_contract::{ContentRef, HashRef, Id, Position, U64};
use serde::{Serialize, Serializer, ser::SerializeSeq};

use super::exact::InputView;

type ActivationView<'a> = (U64, &'a Id, &'a HashRef, &'a [OwnerIdentity], Position);

pub(super) fn activation_view(activation: &WorldActivation) -> ActivationView<'_> {
    let record = activation.record();
    (
        record.generation,
        &record.activation_id,
        &record.world_binding_hash,
        &record.owners,
        record.boundary,
    )
}

#[derive(Serialize)]
struct ProvenanceView<'a> {
    version: u16,
    activation: ActivationView<'a>,
    node: &'a Id,
    stage: &'a Id,
    batch: &'a Id,
    inventory: &'a ContentRef,
    roots: &'a [ContentRef],
    objects: &'a [InputPayload],
}

impl<'a> From<&'a InputProvenanceClosure> for ProvenanceView<'a> {
    fn from(provenance: &'a InputProvenanceClosure) -> Self {
        Self {
            version: provenance.version(),
            activation: activation_view(provenance.activation()),
            node: provenance.node(),
            stage: provenance.stage_operation(),
            batch: provenance.batch(),
            inventory: provenance.inventory(),
            roots: provenance.roots(),
            objects: provenance.objects(),
        }
    }
}

#[derive(Serialize)]
struct CommitView<'a> {
    activation: ActivationView<'a>,
    node: &'a Id,
    stage: &'a Id,
    batch: &'a Id,
    inventory: &'a ContentRef,
    cutoff: Position,
}

impl<'a> From<&'a InputCustodyCommit> for CommitView<'a> {
    fn from(commit: &'a InputCustodyCommit) -> Self {
        Self {
            activation: activation_view(commit.activation()),
            node: commit.node(),
            stage: commit.stage_operation(),
            batch: commit.batch(),
            inventory: commit.inventory(),
            cutoff: commit.cutoff(),
        }
    }
}

struct Claims<'a>(&'a [OriginalPublicationClaim]);

impl Serialize for Claims<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for claim in self.0 {
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
}

/// Complete borrowed staging state, including source-native receipt bodies.
#[derive(Serialize)]
pub(super) struct StagedView<'a> {
    schema: &'static str,
    input: InputView<'a>,
    provenance: Option<ProvenanceView<'a>>,
    publications: Option<Claims<'a>>,
    acknowledgement: &'a NativeInputAcknowledgement,
    native_evidence: &'a OriginalInputEvidence,
    coordinator_commit: Option<CommitView<'a>>,
    committed: bool,
}

impl<'a> StagedView<'a> {
    pub(super) fn new(
        staged: &'a OriginalStagedInput<'_>,
        evidence: &'a OriginalInputEvidence,
    ) -> Self {
        Self {
            schema: "crucible.original-staged-input-witness.v1",
            input: staged.batch().into(),
            provenance: staged.provenance().map(Into::into),
            publications: staged
                .lineage()
                .map(|lineage| Claims(lineage.publications())),
            acknowledgement: staged.acknowledgement(),
            native_evidence: evidence,
            coordinator_commit: staged.coordinator_commit().map(Into::into),
            committed: staged.committed(),
        }
    }
}
