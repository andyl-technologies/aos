//! Preserves every independent partial Fresh publication field as inert DATA.
//!
//! ```text
//! {schema,data,proof,report,raw,reference,inventory_raw,inventory_hash,result,
//!  receipt,reply,completed_response,completed_record}
//! ```
//!
//! Presence is historical fact only. Inconsistent and unfinished typed/raw/cache
//! combinations remain representable; this reader never mints completed currency.

use super::*;
use crate::connection::settled17::{
    BorrowedByteBank17, BorrowedDigest17, HistoricalByteBank17, HistoricalDigest17,
};
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, historical_struct, invalid,
};
use crate::retained_metadata::records::MetadataRecordKind;
use crucible_node_format::{Bytes, HashRef};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::mem::{align_of, size_of};

impl NativeFreshReportPublication {
    /// Borrows every actual typed owner, byte bank and partial completion stamp.
    pub(crate) fn borrowed_settled17_data(&self) -> impl Serialize + '_ {
        Publication17(self)
    }
}

struct Publication17<'a>(&'a NativeFreshReportPublication);

impl Serialize for Publication17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeFreshReportPublication {
            schema,
            data,
            proof,
            report,
            raw,
            reference,
            inventory_raw,
            inventory_hash,
            result,
            receipt,
            reply,
            completed_response,
            completed_record,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeFreshReportPublication17", 13)?;
        fields.serialize_field("schema", schema)?;
        fields.serialize_field("data", data)?;
        fields.serialize_field("proof", proof)?;
        fields.serialize_field("report", report)?;
        fields.serialize_field("raw", &BorrowedByteBank17(raw))?;
        fields.serialize_field("reference", reference)?;
        fields.serialize_field("inventory_raw", &BorrowedByteBank17(inventory_raw))?;
        fields.serialize_field("inventory_hash", inventory_hash)?;
        fields.serialize_field("result", result)?;
        fields.serialize_field("receipt", receipt)?;
        fields.serialize_field("reply", &reply.as_ref().map(Reply17))?;
        fields.serialize_field(
            "completed_response",
            &completed_response.as_ref().map(BorrowedDigest17),
        )?;
        fields.serialize_field("completed_record", completed_record)?;
        fields.end()
    }
}

struct Reply17<'a>(&'a super::super::super::control::PacketControlReply);

impl Serialize for Reply17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let super::super::super::control::PacketControlReply { body, evidence } = self.0;
        let mut fields = serializer.serialize_struct("FreshReply17", 2)?;
        fields.serialize_field("body", body)?;
        fields.serialize_field("evidence", &Evidence17(evidence))?;
        fields.end()
    }
}

struct Evidence17<'a>(&'a Vec<(ContentRef, Vec<u8>)>);

impl Serialize for Evidence17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (reference, bytes) in self.0 {
            sequence.serialize_element(&(reference, BorrowedByteBank17(bytes)))?;
        }
        sequence.end()
    }
}

/// Retains actual Fresh publication fields without native completion methods.
pub(crate) struct HistoricalFreshReportPublication17 {
    pub(crate) schema: Option<String>,
    pub(crate) data: Option<PacketNativeFreshRestoreAllocationData>,
    pub(crate) proof: Option<PacketNativeFreshRestoreAllocationProof>,
    pub(crate) report: Option<PacketNativeFreshRestoreAllocationReport>,
    pub(crate) raw: HistoricalByteBank17,
    pub(crate) reference: Option<ContentRef>,
    pub(crate) inventory_raw: HistoricalByteBank17,
    pub(crate) inventory_hash: Option<crucible_node_format::HashRef>,
    pub(crate) result: Option<ObserveResult>,
    pub(crate) receipt: Option<PacketNativeFreshRestoreAllocationReceipt>,
    pub(crate) reply: Option<HistoricalFreshReply17>,
    pub(crate) completed_response: Option<HistoricalDigest17>,
    pub(crate) completed_record: Option<usize>,
}

historical_struct!(HistoricalFreshReportPublication17 {
    schema: Option<String>,
    data: Option<PacketNativeFreshRestoreAllocationData>,
    proof: Option<PacketNativeFreshRestoreAllocationProof>,
    report: Option<PacketNativeFreshRestoreAllocationReport>,
    raw: HistoricalByteBank17,
    reference: Option<ContentRef>,
    inventory_raw: HistoricalByteBank17,
    inventory_hash: Option<crucible_node_format::HashRef>,
    result: Option<ObserveResult>,
    receipt: Option<PacketNativeFreshRestoreAllocationReceipt>,
    reply: Option<HistoricalFreshReply17>,
    completed_response: Option<HistoricalDigest17>,
    completed_record: Option<usize>,
});

/// Retains independent reply DOM and evidence DATA without a publication route.
pub(crate) struct HistoricalFreshReply17 {
    pub(crate) body: serde_json::Map<String, serde_json::Value>,
    pub(crate) evidence: Vec<(ContentRef, Vec<u8>)>,
}

impl HistoricalType for HistoricalFreshReply17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let body = ledger
            .read::<serde_json::Map<String, serde_json::Value>>(fields.named("body")?, build)?;
        let capacity = ledger.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<(ContentRef, Vec<u8>)>(),
            align_of::<(ContentRef, Vec<u8>)>(),
        )?;
        let mut sequence = Fields::array(fields.named("evidence")?)?;
        ledger.native17_target_vector_data::<(ContentRef, Vec<u8>)>(capacity)?;
        let mut evidence = Vec::new();
        if build {
            evidence
                .try_reserve_exact(capacity)
                .map_err(|_| exhausted())?;
            if evidence.capacity() != capacity {
                return Err(exhausted());
            }
        }
        let mut count = 0usize;
        while let Some(raw) = sequence.next_value()? {
            count = count
                .checked_add(1)
                .filter(|count| *count <= capacity)
                .ok_or_else(invalid)?;
            let mut pair = Fields::array(raw)?;
            let reference =
                ledger.read::<ContentRef>(pair.next_value()?.ok_or_else(invalid)?, build)?;
            let bytes = ledger
                .read::<HistoricalByteBank17>(pair.next_value()?.ok_or_else(invalid)?, build)?;
            pair.finish()?;
            if build {
                evidence.push((reference.ok_or_else(invalid)?, bytes.ok_or_else(invalid)?.0));
            }
        }
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            body: body.ok_or_else(invalid)?,
            evidence,
        }))
    }
}

historical_struct!(PacketNativeFreshRestoreAllocationScope {
    native_pid: U64,
    session: Id,
    incarnation: Id,
    node: Id,
    owner: Id,
    owner_generation: U64,
    owner_binding: HashRef,
    world: HashRef,
    prepared_token: Id,
    admission: Id,
    closed_gate_receipt: ContentRef,
    nonce: Bytes,
    assigned_query: Bytes,
    completed_admit_request: Bytes,
    completed_admit_response: Bytes,
    ack_context: Bytes,
});

historical_struct!(PacketNativeFreshRestoreAllocationStorage {
    current_retained_bytes: U64,
    query_retained_growth_bytes: U64,
    prepare_retained_growth_bytes: U64,
    query_transient_bytes: U64,
    prepare_transient_bytes: U64,
    declared_counter_scratch_bytes: U64,
});

historical_struct!(PacketNativeFreshRestoreAllocationData {
    scope: PacketNativeFreshRestoreAllocationScope,
    storage: PacketNativeFreshRestoreAllocationStorage,
});

historical_struct!(PacketNativeFreshRestoreAllocationProof {
    schema: String,
    algorithm: String,
    context_digest: Bytes,
    mac: Bytes,
});

historical_struct!(PacketNativeFreshRestoreAllocationReport {
    schema: String,
    data: PacketNativeFreshRestoreAllocationData,
    proof: PacketNativeFreshRestoreAllocationProof,
});

historical_struct!(PacketNativeFreshRestoreAllocationReceipt {
    schema: String,
    allocation: ContentRef,
});

#[cfg(test)]
mod tests;

// Whole17 decoding keeps all allocating children in the outer typed attempt.
mod retained;
