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

// The complete owning route stores every referenced body separately in the
// authenticated Core closure. Only reference occurrences are serialized here;
// first-sealed scopes, order, native origins and direct rows remain unchanged.
struct ReferencePublicationView<'a>(&'a OriginalPublicationClaim);

struct ObjectReferences<'a>(&'a [InputPayload]);

impl Serialize for ObjectReferences<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for object in self.0 {
            sequence.serialize_element(&object.reference)?;
        }
        sequence.end()
    }
}

impl Serialize for ReferencePublicationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let original = self.0;
        let mut row = serializer.serialize_struct("ReferenceOriginalPublication", 5)?;
        row.serialize_field("event", &original.event)?;
        row.serialize_field("origin", &original.origin)?;
        row.serialize_field("published", &original.published)?;
        row.serialize_field("objects", &ObjectReferences(&original.objects))?;
        row.serialize_field("rows", &original.rows)?;
        row.end()
    }
}

struct ReferencePublications<'a>(&'a [OriginalPublicationClaim]);

impl Serialize for ReferencePublications<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for original in self.0 {
            rows.serialize_element(&ReferencePublicationView(original))?;
        }
        rows.end()
    }
}

struct ReferenceLineageView<'a>(&'a OriginalInputLineage);

impl Serialize for ReferenceLineageView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut row = serializer.serialize_struct("ReferenceOriginalInputLineage", 3)?;
        row.serialize_field("source_scope", self.0.source_scope())?;
        row.serialize_field(
            "original",
            &super::super::semantic_snapshot::BatchView(self.0.original()),
        )?;
        row.serialize_field(
            "publications",
            &ReferencePublications(self.0.publications()),
        )?;
        row.end()
    }
}

struct ReferenceLineages<'a>(&'a [OriginalInputLineage]);

impl Serialize for ReferenceLineages<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for original in self.0 {
            rows.serialize_element(&ReferenceLineageView(original))?;
        }
        rows.end()
    }
}

#[derive(Serialize)]
struct ReferenceAncestryView<'a> {
    schema: &'static str,
    lineages: ReferenceLineages<'a>,
}

fn reference_view(originals: &[OriginalInputLineage]) -> ReferenceAncestryView<'_> {
    ReferenceAncestryView {
        schema: "source-owned.packet-original-ancestry/12",
        lineages: ReferenceLineages(originals),
    }
}

impl PacketConnectedSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_original_reference_ancestry_size(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.guard(scope)?;
        let originals = self
            .input_lineage
            .try_borrow()
            .map_err(|_| refused("reference ancestry busy"))?;
        let bytes = super::super::budget::serialized_size(&reference_view(&originals), maximum)?;
        self.guard(scope)?;
        Ok(bytes)
    }

    pub(in crate::node_adapters::cnp::semantic) fn authenticate_complete_original_reference_ancestry(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &InputPayload,
    ) -> Result<(), OperationFailure> {
        self.guard(scope)?;
        let originals = self
            .input_lineage
            .try_borrow()
            .map_err(|_| refused("reference ancestry busy"))?;
        super::super::semantic_snapshot::authenticate_component(
            original,
            &reference_view(&originals),
        )?;
        self.guard(scope)
    }

    pub(in crate::node_adapters::cnp::semantic) fn record_complete_original_reference_ancestry(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        reservation: &mut Option<super::super::semantic_snapshot::CnpSemanticSnapshotReservation>,
    ) -> Result<(), OperationFailure> {
        self.guard(scope)?;
        let originals = self
            .input_lineage
            .try_borrow()
            .map_err(|_| refused("reference ancestry busy"))?;
        super::super::semantic_snapshot::record_component(
            reservation,
            &reference_view(&originals),
        )?;
        self.guard(scope)
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete_original_reference_lineages(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<std::cell::Ref<'_, [OriginalInputLineage]>, OperationFailure> {
        self.guard(scope)?;
        let originals = self
            .input_lineage
            .try_borrow()
            .map_err(|_| refused("reference ancestry bodies busy"))?;
        Ok(std::cell::Ref::map(originals, |rows| rows.as_slice()))
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Format controls panic on inconsistent data fixtures.
#[allow(clippy::unwrap_used)]
mod reference_tests {
    use super::*;

    #[test]
    fn reference_objects_preserve_full_identity_without_reencoding_binary_bodies() {
        let body = vec![255u8; 4096];
        let reference = canonical::content_ref(&body, "application/octet-stream").unwrap();
        let objects = vec![InputPayload {
            reference: reference.clone(),
            bytes: body,
        }];
        let encoded = serde_json::to_value(ObjectReferences(&objects)).unwrap();

        assert_eq!(encoded, serde_json::json!([reference]));
        let bytes = canonical::canonical_json(&encoded).unwrap();
        assert!(bytes.len() < objects[0].bytes.len());
        assert_eq!(objects[0].bytes.len(), 4096);
        objects[0].reference.verify(&objects[0].bytes).unwrap();
    }
}
