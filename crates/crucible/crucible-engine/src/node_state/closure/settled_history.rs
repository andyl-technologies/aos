//! Borrows every verified content owner with its independent backing capacities.
//!
//! Both the actual digest-keyed map and typed-reference set remain represented.
//! Byte contents use the ordinary Bytes encoding through a borrowed view; no
//! content file, mutable path or reference-only fallback replaces retained data.

use super::*;
use crate::node_contract::RuntimeError;
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityRow, OriginalRestoredOwnerCapacityRows,
    OriginalRestoredOwnerCapacitySink, OriginalRestoredOwnerCapacityWalk,
};
use crucible_node_format::Bytes;
use serde::{
    Serializer,
    ser::{SerializeSeq, SerializeStruct, SerializeTuple},
};

pub(crate) struct ContentHistory<'a>(&'a VerifiedStateContent);

impl VerifiedStateContent {
    pub(crate) fn borrowed_settled_history_data(&self) -> ContentHistory<'_> {
        ContentHistory(self)
    }
}

impl ContentHistory<'_> {
    pub(crate) fn metadata_demand_data(&self) -> Result<(usize, usize), RuntimeError> {
        OriginalRestoredOwnerCapacityRows(self.0).metadata_demand_data()
    }

    pub(crate) fn base64_temporary_bytes_data(&self) -> Result<usize, RuntimeError> {
        self.0
            .objects
            .values()
            .try_fold(0usize, |maximum, (_, bytes)| {
                let requested = Bytes::borrowed_serialization_temporary_bytes_data(bytes)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
                Ok(maximum.max(requested))
            })
    }
}

impl Serialize for ContentHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let VerifiedStateContent {
            objects,
            total_bytes,
            references,
            edition,
        } = self.0;
        self.metadata_demand_data().map_err(S::Error::custom)?;
        let edition = match edition {
            ContentInventoryEdition::Legacy => "legacy",
            ContentInventoryEdition::Typed => "typed",
        };

        let mut value = serializer.serialize_struct("VerifiedStateContentHistory", 6)?;
        value.serialize_field("schema", "source-private.verified-state-content-history/1")?;
        value.serialize_field("edition", edition)?;
        value.serialize_field("total_bytes", total_bytes)?;
        value.serialize_field("objects", &Objects(objects))?;
        value.serialize_field("references", references)?;
        value.serialize_field("capacities", &OriginalRestoredOwnerCapacityRows(self.0))?;
        value.end()
    }
}

struct Objects<'a>(&'a BTreeMap<HashRef, (ContentRef, Vec<u8>)>);

impl Serialize for Objects<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = serializer.serialize_seq(Some(self.0.len()))?;
        for (digest, (reference, bytes)) in self.0 {
            values.serialize_element(&ContentObject {
                digest,
                reference,
                bytes,
            })?;
        }
        values.end()
    }
}

struct ContentObject<'a> {
    digest: &'a HashRef,
    reference: &'a ContentRef,
    bytes: &'a [u8],
}

impl Serialize for ContentObject<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_tuple(3)?;
        value.serialize_element(self.digest)?;
        value.serialize_element(self.reference)?;
        value.serialize_element(&Bytes::borrowed_serialization_data(self.bytes))?;
        value.end()
    }
}

impl OriginalRestoredOwnerCapacityWalk for VerifiedStateContent {
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        let Self {
            objects,
            total_bytes: _,
            references,
            edition: _,
        } = self;
        sink.capacity_row(OriginalRestoredOwnerCapacityRow::tree_population_data::<
            HashRef,
            (ContentRef, Vec<u8>),
        >(objects.len()))?;
        for (digest, (reference, bytes)) in objects {
            digest.capacities(depth, sink)?;
            reference.capacities(depth, sink)?;
            bytes.capacities(depth, sink)?;
        }
        references.capacities(depth, sink)
    }
}

impl VerifiedStateContent {
    /// Names direct historical views; output and serializer work stay separate.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        let terms = [
            Bytes::borrowed_serialization_counter_scratch_data(),
            std::mem::size_of::<ContentHistory<'static>>(),
            std::mem::size_of::<Objects<'static>>(),
            std::mem::size_of::<ContentObject<'static>>(),
            std::mem::size_of::<&VerifiedStateContent>(),
            std::mem::size_of::<&BTreeMap<HashRef, (ContentRef, Vec<u8>)>>(),
            std::mem::size_of::<&std::collections::BTreeSet<ContentRef>>(),
            std::mem::size_of::<(
                &BTreeMap<HashRef, (ContentRef, Vec<u8>)>,
                &usize,
                &std::collections::BTreeSet<ContentRef>,
                &ContentInventoryEdition,
            )>(),
            std::mem::size_of::<
                std::collections::btree_map::Iter<'static, HashRef, (ContentRef, Vec<u8>)>,
            >(),
            std::mem::size_of::<
                std::collections::btree_map::Values<'static, HashRef, (ContentRef, Vec<u8>)>,
            >(),
            std::mem::size_of::<std::collections::btree_set::Iter<'static, ContentRef>>(),
            std::mem::size_of::<(&HashRef, &(ContentRef, Vec<u8>))>(),
            std::mem::size_of::<(&ContentRef, &Vec<u8>)>(),
            std::mem::size_of::<(&HashRef, &ContentRef)>(),
            std::mem::size_of::<Result<(usize, usize), RuntimeError>>(),
            std::mem::size_of::<Result<usize, RuntimeError>>(),
            std::mem::size_of::<Result<(), RuntimeError>>(),
            std::mem::size_of::<&mut dyn OriginalRestoredOwnerCapacitySink>(),
        ];
        let array_bytes = std::mem::size_of_val(&terms);
        let mut iterator = terms.into_iter();
        let iterator_bytes = std::mem::size_of_val(&iterator);
        array_bytes
            .checked_add(iterator_bytes)
            .and_then(|initial| iterator.try_fold(initial, usize::checked_add))
            .unwrap_or(usize::MAX)
    }
}
