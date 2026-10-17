//! Selected original consumption evidence and authenticated public predecessor chain.
//!
//! ```json
//! {"schema":"crucible.reference.lineage-measurement.v1","native":{},
//!  "consumption_relation":{},"accepted_input_custody":{},"previous_publication":null}
//! ```
//!
//! Decoding these records grants no source adoption or publication authority.
//! Only the owning source creates them from actual accepted input, native Close
//! and a separately authenticated original public consumption acknowledgement.

use crucible_node_contract::ContentRef;
use serde::{Deserialize, Serialize};

use crate::reference_device::DeviceReceipt;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LineagePublicPredecessor {
    pub(super) measurement: ContentRef,
    pub(super) stop_receipt: ContentRef,
    pub(super) observation_batch: ContentRef,
    pub(super) publication_consumption: ContentRef,
    pub(super) committed_observation: ContentRef,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LineageMeasurement {
    pub(super) schema: String,
    pub(super) native: DeviceReceipt,
    pub(super) consumption_relation: ContentRef,
    pub(super) accepted_input_custody: ContentRef,
    #[serde(deserialize_with = "required_nullable")]
    pub(super) previous_publication: Option<LineagePublicPredecessor>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
