//! Supplies the concrete retained companion of the exact Fresh17 field roster.

use super::*;
use crate::protocol_snapshot::owned11::typed::{Native17Build, native17_build::native17_struct};
use crate::retained_metadata::MetadataObserver;
native17_struct!(HistoricalFreshReportPublication17 {
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

native17_struct!(PacketNativeFreshRestoreAllocationScope {
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

native17_struct!(PacketNativeFreshRestoreAllocationStorage {
    current_retained_bytes: U64,
    query_retained_growth_bytes: U64,
    prepare_retained_growth_bytes: U64,
    query_transient_bytes: U64,
    prepare_transient_bytes: U64,
    declared_counter_scratch_bytes: U64,
});

native17_struct!(PacketNativeFreshRestoreAllocationData {
    scope: PacketNativeFreshRestoreAllocationScope,
    storage: PacketNativeFreshRestoreAllocationStorage,
});

native17_struct!(PacketNativeFreshRestoreAllocationProof {
    schema: String,
    algorithm: String,
    context_digest: Bytes,
    mac: Bytes,
});

native17_struct!(PacketNativeFreshRestoreAllocationReport {
    schema: String,
    data: PacketNativeFreshRestoreAllocationData,
    proof: PacketNativeFreshRestoreAllocationProof,
});

native17_struct!(PacketNativeFreshRestoreAllocationReceipt {
    schema: String,
    allocation: ContentRef,
});

mod reply;
