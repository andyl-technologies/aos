//! Streams the source-retained first-sealed input and producer ancestry.
//!
//! Every original scope, ordered delivery, payload byte object and direct row is
//! preserved. This local byte view cannot recreate an opaque input permission or
//! authorize capture or fresh restoration.

use super::*;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

struct PublicationView<'a>(&'a OriginalPublicationClaim);

impl Serialize for PublicationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let original = self.0;
        let mut row = serializer.serialize_struct("OriginalPublication", 5)?;
        row.serialize_field("event", &original.event)?;
        row.serialize_field("origin", &original.origin)?;
        row.serialize_field("published", &original.published)?;
        row.serialize_field("objects", &original.objects)?;
        row.serialize_field("rows", &original.rows)?;
        row.end()
    }
}

struct Publications<'a>(&'a [OriginalPublicationClaim]);

impl Serialize for Publications<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for original in self.0 {
            rows.serialize_element(&PublicationView(original))?;
        }
        rows.end()
    }
}

struct LineageView<'a>(&'a OriginalInputLineage);

impl Serialize for LineageView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut row = serializer.serialize_struct("OriginalInputLineage", 3)?;
        row.serialize_field("source_scope", self.0.source_scope())?;
        row.serialize_field(
            "original",
            &super::super::semantic_snapshot::BatchView(self.0.original()),
        )?;
        row.serialize_field("publications", &Publications(self.0.publications()))?;
        row.end()
    }
}

struct Lineages<'a>(&'a [OriginalInputLineage]);

impl Serialize for Lineages<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for original in self.0 {
            rows.serialize_element(&LineageView(original))?;
        }
        rows.end()
    }
}

#[derive(Serialize)]
struct AncestryView<'a> {
    schema: &'static str,
    lineages: Lineages<'a>,
}

impl PacketConnectedSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_original_ancestry_size(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.guard(scope)?;
        let originals = self
            .input_lineage
            .try_borrow()
            .map_err(|_| refused("original source ancestry is busy"))?;
        let view = AncestryView {
            schema: "source-owned.packet-original-ancestry/5",
            lineages: Lineages(&originals),
        };
        let size = super::super::budget::serialized_size(&view, maximum)?;
        self.guard(scope)?;
        Ok(size)
    }

    pub(in crate::node_adapters::cnp::semantic) fn authenticate_complete_original_ancestry(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &InputPayload,
    ) -> Result<(), OperationFailure> {
        self.guard(scope)?;
        let originals = self
            .input_lineage
            .try_borrow()
            .map_err(|_| refused("original source ancestry is busy"))?;
        let view = AncestryView {
            schema: "source-owned.packet-original-ancestry/5",
            lineages: Lineages(&originals),
        };
        super::super::semantic_snapshot::authenticate_component(original, &view)?;
        self.guard(scope)
    }

    pub(in crate::node_adapters::cnp::semantic) fn record_complete_original_ancestry(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        reservation: &mut Option<super::super::semantic_snapshot::CnpSemanticSnapshotReservation>,
    ) -> Result<(), OperationFailure> {
        self.guard(scope)?;
        let originals = self
            .input_lineage
            .try_borrow()
            .map_err(|_| refused("original source ancestry is busy"))?;
        let view = AncestryView {
            schema: "source-owned.packet-original-ancestry/5",
            lineages: Lineages(&originals),
        };
        super::super::semantic_snapshot::record_component(reservation, &view)?;
        self.guard(scope)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
