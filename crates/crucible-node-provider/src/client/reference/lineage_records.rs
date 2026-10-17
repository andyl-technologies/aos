//! Closed selected source evidence codecs; decoding supplies no source authority.
//!
//! The measurement requires an explicit nullable preceding publication. A
//! subsequent window retains the exact original five typed references:
//!
//! ```text
//! {"schema":"crucible.reference.lineage-measurement.v1",
//!  "native":{...},"consumption_relation":{...},
//!  "accepted_input_custody":{...},"previous_publication":null|{
//!    "measurement":{...},"stop_receipt":{...},"observation_batch":{...},
//!    "publication_consumption":{...},"committed_observation":{...}}}
//! ```

use crate::reference_device::DeviceReceipt;
use crucible_node_contract::{ContentRef, Endpoint, Id, U64};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Measurement {
    pub schema: String,
    pub native: DeviceReceipt,
    pub consumption_relation: ContentRef,
    pub accepted_input_custody: ContentRef,
    #[serde(deserialize_with = "required_nullable")]
    pub previous_publication: Option<Predecessor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Predecessor {
    pub measurement: ContentRef,
    pub stop_receipt: ContentRef,
    pub observation_batch: ContentRef,
    pub publication_consumption: ContentRef,
    pub committed_observation: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Relation {
    pub schema: String,
    pub owner: Id,
    pub incarnation: Id,
    pub owner_generation: U64,
    pub original_kernel_pid: U64,
    pub original_kernel_start_ticks: U64,
    pub native_window: Id,
    pub input_batch: ContentRef,
    pub native_stage: ContentRef,
    pub native_receipt: ContentRef,
    pub initialize_request: ContentRef,
    pub initialize_response_wire: ContentRef,
    pub close_request: ContentRef,
    pub close_response_wire: ContentRef,
    #[serde(deserialize_with = "required_nullable")]
    pub previous_closed: Option<ContentRef>,
    pub preceding_publication_acknowledged: bool,
    pub complete_consumed_prefix: U64,
    pub measured_host_ns: U64,
    pub entries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub original_index: U64,
    pub original_event: ContentRef,
    pub producer: Endpoint,
    pub event_id: Id,
    pub native_sequence: U64,
    pub byte_start: U64,
    pub byte_end: U64,
    pub checksum_after: U64,
    pub zero_byte_consumed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Origin {
    pub schema: String,
    pub child_pid: U64,
    pub original_kernel_start_ticks: U64,
    pub owner: Id,
    pub incarnation: Id,
    pub owner_generation: U64,
    pub dialect: String,
    pub application_status: String,
    pub native_executable: ContentRef,
    pub physical_pause: String,
    pub initialize_request: ContentRef,
    pub initialize_response_wire: ContentRef,
}

fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}
