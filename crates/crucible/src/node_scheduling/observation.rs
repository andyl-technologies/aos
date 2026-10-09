//! Native scheduling claims authenticated by the retaining runtime adapter.

use crucible_node_contract::{ContentRef, Endpoint, Id, Position, U64};

use serde::{Deserialize, Serialize};

use crate::node_contract::{OwnerIdentity, WorldActivation};

/// States a complete all-output-lane lower bound without inferring queue absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NativeOutputBound {
    /// Makes no positive lookahead claim.
    Unknown,
    /// Permits an unseen publication at equality.
    At(Position),
    /// Closes every phase and microstep at and before this physical instant.
    AfterInstant(U64),
}

/// Retains a qualified complete output bound for one public producer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProducerBound {
    /// Names the producer whose entire admitted output inventory is covered.
    pub producer: Id,
    /// States the exact timestamp equality convention.
    pub bound: NativeOutputBound,
    /// Binds native evidence for all output paths, generation and closure prefix.
    pub proof_ref: ContentRef,
}

/// Retains one original native output without assigning host completion order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePublication {
    /// Names the original retained publication acknowledged exactly once.
    pub publication_id: Id,
    /// Names the actual producer output lane in the admitted graph.
    pub endpoint: Endpoint,
    /// Retains the native FIFO identity independently of public fanout sequences.
    pub native_sequence: U64,
    /// Gives the original qualified phase-one publication position.
    pub publication: Position,
    /// Gives exact semantic evaluation, or null for an authenticated coarse/native observation.
    #[serde(deserialize_with = "required_nullable")]
    pub evaluation: Option<Position>,
    /// Retains all same-time causal parents required for microstep validation.
    pub causal_parents: Vec<Position>,
    /// Retains immutable bytes under native custody until publication acknowledgement.
    pub payload: ContentRef,
    /// Transfers verified payload bytes into coordinator custody before native acknowledgement.
    pub payload_bytes: Vec<u8>,
}

/// Identifies one original public delivery independently of transport incarnation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputIdentity {
    /// Names the original public producer.
    pub producer: Id,
    /// Names its unchanged node-wide fanout sequence.
    pub source_sequence: U64,
}

/// Reports authentic semantic consumption of the original frozen input prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInputProgress {
    /// Names the previously staged immutable batch.
    pub batch: Id,
    /// Enumerates the cumulative consumed prefix in original canonical delivery order.
    pub consumed: Vec<InputIdentity>,
    /// Binds native evidence of actual exactly-once semantic consumption.
    pub proof_ref: ContentRef,
}

/// Retains one original external root input without modeling its consumption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExternalInput {
    /// Names the original retained external arrival.
    pub event_id: Id,
    /// Preserves the original input-lane native FIFO identity.
    pub native_sequence: U64,
    /// Gives the qualified root publication coordinate with zero microstep.
    pub publication: Position,
    /// Binds the complete immutable payload.
    pub payload: ContentRef,
    /// Transfers readable bytes before any original native storage is released.
    pub payload_bytes: Vec<u8>,
    /// Binds exact capture, sampling or recorded-source provenance of this arrival.
    pub provenance_ref: ContentRef,
}

/// Authenticates a complete external input prefix and retained native arrivals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExternalInputInventory {
    /// Names the declared external root-input lane.
    pub endpoint: Endpoint,
    /// Excludes unseen converted input deliveries strictly before this position.
    pub closed_before: Position,
    /// Retains original native inputs in authentic FIFO order, without consuming them.
    pub inputs: Vec<NativeExternalInput>,
    /// Binds actual source buffers, timing translation and complete prefix closure.
    pub proof_ref: ContentRef,
}

/// Reports current complete native producer closure and retained original outputs.
///
/// Constructing this record supplies claims only. The runtime checks immutable
/// graph routes and its original operation, then requires the trusted adapter to
/// authenticate native evidence before minting a validated observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSchedulingObservation {
    /// Names the node through which the authoritative owner was observed.
    pub node: Id,
    /// Retains the complete current owner incarnation roster.
    pub owners: Vec<OwnerIdentity>,
    /// Gives the actual native reached position independently of production closure.
    pub reached: Position,
    /// Gives the authenticated closed production prefix.
    pub closed_prefix: Position,
    /// Enumerates complete public-producer bounds in canonical node order.
    pub bounds: Vec<NativeProducerBound>,
    /// Retains original outputs in native FIFO order, never host collection order.
    pub publications: Vec<NativePublication>,
    /// Reports actual semantic input consumption, distinct from buffer staging.
    #[serde(deserialize_with = "required_nullable")]
    pub input_progress: Option<NativeInputProgress>,
    /// Reports authentic declared external root-input inventories and closure.
    pub external_inputs: Vec<NativeExternalInputInventory>,
    /// Binds native original custody, clocks and full output inventory evidence.
    pub proof_ref: ContentRef,
}

/// Carries a runtime-authenticated complete boundary observation.
#[derive(Debug)]
pub struct ValidatedSchedulingObservation {
    pub(crate) activation: WorldActivation,
    pub(crate) observation: NativeSchedulingObservation,
}

impl ValidatedSchedulingObservation {
    pub(crate) fn new(
        activation: WorldActivation,
        observation: NativeSchedulingObservation,
    ) -> Self {
        Self {
            activation,
            observation,
        }
    }

    /// Returns the native reached coordinate without converting it to input closure.
    pub fn reached(&self) -> Position {
        self.observation.reached
    }
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
