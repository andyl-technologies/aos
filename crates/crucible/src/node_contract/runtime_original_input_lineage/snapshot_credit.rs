//! Counts the complete Runtime7 wire before allocating owned metadata copies.
//!
//! Borrowed wire views preserve the saved field order and tagged result grammar.
//! Their traversal allocates neither body arrays nor intermediate metadata DTOs.

use super::*;
use serde::ser::{Serialize, SerializeStruct, Serializer};

pub(in crate::node_contract::runtime) struct SnapshotView<'a> {
    pub runtime: &'a NodeRuntime,
    pub cut: Position,
    pub ordinal: U64,
}

impl Serialize for SnapshotView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("OriginalLineageRuntimeRecord", 7)?;
        record.serialize_field("schema_version", &7u16)?;
        record.serialize_field(
            "source_activation",
            &ActivationView(self.runtime.barrier.record()),
        )?;
        record.serialize_field("capture_cut", &self.cut)?;
        record.serialize_field("capture_ordinal", &self.ordinal)?;
        record.serialize_field(
            "owners",
            &Sequence(self.runtime.owners.values().map(OwnerView)),
        )?;
        record.serialize_field(
            "operations",
            &Sequence(self.runtime.operations.values().map(OperationView)),
        )?;
        record.serialize_field(
            "inputs",
            &Sequence(self.runtime.input_batches.values().map(InputView)),
        )?;
        record.end()
    }
}

struct Sequence<I>(I);

impl<I> Serialize for Sequence<I>
where
    I: Iterator + Clone,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.clone())
    }
}

struct ActivationView<'a>(&'a ActivationRecord);

impl Serialize for ActivationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("SavedRuntimeActivation", 5)?;
        record.serialize_field("generation", &self.0.generation)?;
        record.serialize_field("activation_id", &self.0.activation_id)?;
        record.serialize_field("world_binding_hash", &self.0.world_binding_hash)?;
        record.serialize_field("owners", &self.0.owners)?;
        record.serialize_field("boundary", &self.0.boundary)?;
        record.end()
    }
}

struct OwnerView<'a>(&'a super::super::OwnerCustody);

impl Serialize for OwnerView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("SavedRuntimeOwner", 4)?;
        record.serialize_field("identity", &self.0.identity)?;
        record.serialize_field("lifecycle", &self.0.lifecycle)?;
        record.serialize_field("operation", &self.0.operation)?;
        record.serialize_field("domains", &Sequence(self.0.domains.iter()))?;
        record.end()
    }
}

struct OperationView<'a>(&'a super::super::RetainedOperation);

impl Serialize for OperationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let operation = self.0;
        let mut record = serializer.serialize_struct("SavedRuntimeOperation", 8)?;
        record.serialize_field("operation", &operation.admission.token.operation)?;
        record.serialize_field("route", &operation.admission.token.route)?;
        record.serialize_field("request", &operation.admission.request)?;
        record.serialize_field(
            "input_batch",
            &operation
                .admission
                .inputs
                .as_ref()
                .map(|batch| batch.batch()),
        )?;
        record.serialize_field("result", &ResultView(&operation.result))?;
        record.serialize_field("close_submission", &operation.close_submission)?;
        record.serialize_field("submission_effects", &operation.submission_effects)?;
        record.serialize_field(
            "scheduling_commit",
            &operation.scheduling_commit.as_ref().map(CommitView),
        )?;
        record.end()
    }
}

struct ResultView<'a>(&'a RetainedResult);

impl Serialize for ResultView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct(
            "SavedRuntimeResult",
            if matches!(self.0, RetainedResult::Pending) {
                1
            } else {
                2
            },
        )?;
        match self.0 {
            RetainedResult::Pending => record.serialize_field("kind", "pending")?,
            RetainedResult::Complete(outcome) => {
                record.serialize_field("kind", "complete")?;
                record.serialize_field("value", outcome)?;
            }
            RetainedResult::Failed(failure) => {
                record.serialize_field("kind", "failed")?;
                record.serialize_field("value", failure)?;
            }
            RetainedResult::Acknowledged(outcome) => {
                record.serialize_field("kind", "acknowledged")?;
                record.serialize_field("value", outcome)?;
            }
        }
        record.end()
    }
}

struct CommitView<'a>(&'a crate::node_scheduling::SchedulingCommit);

impl Serialize for CommitView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("SavedSchedulingCommit", 3)?;
        record.serialize_field("node", self.0.node())?;
        record.serialize_field("operation", self.0.operation())?;
        record.serialize_field("retained_outputs", self.0.retained_outputs())?;
        record.end()
    }
}

struct InputView<'a>(&'a super::super::inputs::RetainedInput);

impl Serialize for InputView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let input = self.0;
        let batch = &input.batch;
        let mut record = serializer.serialize_struct("OriginalLineageInputRecord", 14)?;
        record.serialize_field("node", batch.node())?;
        record.serialize_field("stage_operation", batch.stage_operation())?;
        record.serialize_field("batch", batch.batch())?;
        record.serialize_field("owners", batch.owners())?;
        record.serialize_field("cutoff", &batch.cutoff())?;
        record.serialize_field("inventory", batch.inventory())?;
        record.serialize_field("deliveries", batch.deliveries())?;
        record.serialize_field(
            "payloads",
            &Sequence(batch.payloads().iter().map(|object| &object.reference)),
        )?;
        record.serialize_field(
            "provenance",
            &input
                .provenance
                .as_ref()
                .map(|proof| ProvenanceView(proof.saved())),
        )?;
        record.serialize_field("lineage", &input.lineage.as_ref().map(LineageView))?;
        record.serialize_field("acknowledgement", &input.acknowledgement)?;
        record.serialize_field("failure", &input.failure)?;
        record.serialize_field("committed", &input.committed)?;
        record.serialize_field("coordinator_committed", &input.commit.is_some())?;
        record.end()
    }
}

struct ProvenanceView<'a>(&'a super::super::SavedInputProvenance);

impl Serialize for ProvenanceView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("OriginalLineageProvenanceRecord", 7)?;
        record.serialize_field("schema_version", &self.0.schema_version)?;
        record.serialize_field("node", &self.0.node)?;
        record.serialize_field("stage_operation", &self.0.stage_operation)?;
        record.serialize_field("batch", &self.0.batch)?;
        record.serialize_field("inventory", &self.0.inventory)?;
        record.serialize_field("roots", &self.0.roots)?;
        record.serialize_field(
            "objects",
            &Sequence(self.0.objects.iter().map(|object| &object.reference)),
        )?;
        record.end()
    }
}

struct LineageView<'a>(&'a OriginalInputLineage);

impl Serialize for LineageView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("SavedOriginalInputLineage", 3)?;
        record.serialize_field("schema_version", &1u16)?;
        record.serialize_field("source", self.0.source_scope())?;
        record.serialize_field(
            "publications",
            &Sequence(self.0.publications().iter().map(PublicationView)),
        )?;
        record.end()
    }
}

struct PublicationView<'a>(&'a OriginalPublicationClaim);

impl Serialize for PublicationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_struct("SavedOriginalPublication", 4)?;
        record.serialize_field("origin", &self.0.origin)?;
        record.serialize_field("published", &self.0.published)?;
        record.serialize_field(
            "objects",
            &Sequence(self.0.objects.iter().map(|object| &object.reference)),
        )?;
        record.serialize_field("rows", &self.0.rows)?;
        record.end()
    }
}

#[cfg(test)]
thread_local! {
    static METADATA_COPY_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(in crate::node_contract::runtime) fn note_metadata_copy_attempt() {
    METADATA_COPY_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
}

#[cfg(test)]
pub(in crate::node_contract::runtime) fn metadata_copy_attempts() -> usize {
    METADATA_COPY_ATTEMPTS.with(std::cell::Cell::get)
}
