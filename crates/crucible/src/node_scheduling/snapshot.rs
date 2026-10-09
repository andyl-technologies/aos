//! Bounded coordinator continuation records without live execution authority.
//!
//! ```json
//! { "schema_version": 1, "ordering_profile": "superdense-v1" }
//! ```

use crucible_node_contract::{ContentRef, Endpoint, HashRef, Id, Position, U64};
use serde::{Deserialize, Serialize};

use super::event::Delivery;
use super::{InputIdentity, InputPayload, NativeInputAcknowledgement};

/// Retains a saved owner incarnation without granting access to native state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedOwner {
    /// Names the immutable owner roster member.
    pub owner: Id,
    /// Identifies the source realization, never reused by a restored process.
    pub incarnation: Id,
    /// Identifies the source live owner generation.
    pub generation: U64,
}

/// Retains the full authenticated output-closure strength of one producer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedBound {
    /// Does not authorize lookahead from absence of queued output.
    Unknown,
    /// Permits a not-yet-published event at this publication coordinate.
    At {
        /// Gives the inclusive earliest publication position.
        position: Position,
    },
    /// Excludes every publication at and before this physical instant.
    AfterInstant {
        /// Retains complete same-time closure, including all microsteps.
        time_ps: U64,
    },
}

/// Preserves one producer's closure and unique node-wide sequence continuation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedProducer {
    /// Names the logical producer independently of host transport epochs.
    pub node: Id,
    /// Retains the current complete all-output-lane lower bound.
    pub bound: SavedBound,
    /// Retains the authenticated closed production prefix separately from progress.
    pub closed_prefix: Position,
    /// Retains the next sequence, or explicit null for permanent exhaustion.
    #[serde(deserialize_with = "required_nullable")]
    pub next_sequence: Option<U64>,
}

/// Preserves authentic external-source delivery-prefix closure independently of outputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedExternalPrefix {
    /// Names the declared external root-input lane.
    pub endpoint: Endpoint,
    /// Excludes unseen converted input deliveries strictly before this cut.
    pub closed_before: Position,
}

/// Retains native FIFO provenance independently of coordinator public sequences.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedNativeSequence {
    /// Names the admitted original output lane.
    pub endpoint: Endpoint,
    /// Gives the last observed native FIFO identity, never renumbered on restore.
    pub last_sequence: U64,
}

/// Preserves immutable payload bytes retained by the coordinator after native acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedPayload {
    /// Binds the exact bytes in the baseline content domain.
    pub reference: ContentRef,
    /// Retains the actual readable bytes required by pending input custody.
    pub bytes: Vec<u8>,
}

/// Preserves an execution owner's public phase and exact closure prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedPosition {
    /// Names the indivisible execution owner.
    pub owner: Id,
    /// Retains the reached position without assuming global instant closure.
    pub position: Position,
}

/// Preserves the original permission of an unresolved native operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedPermission {
    /// Retains the original half-open physical execution window.
    ExactRun {
        /// Gives its authentic start coordinate.
        start: Position,
        /// Gives its exclusive physical ceiling.
        limit: Position,
        /// Retains qualified input-blocked parking permission.
        input_blocked_park: bool,
    },
    /// Retains a finite same-instant causal settlement range.
    BoundarySettle {
        /// Gives its authentic first superdense position.
        start: Position,
        /// Gives its exclusive same-instant position.
        limit: Position,
    },
    /// Retains the original fixed input cut and unpublished output window.
    Quantum {
        /// Names the original window without reconstructing a replacement run.
        window: Id,
        /// Gives its original start boundary.
        start: Position,
        /// Gives the earliest output publication boundary.
        end: Position,
        /// Names its immutable staged input batch.
        input_batch: Id,
        /// Retains the original operational budget in nanoseconds.
        host_budget_ns: U64,
    },
}

/// Retains unresolved grant custody without reconstructing a native token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedReservation {
    /// Names the original operation identity, retained across retries.
    pub operation: Id,
    /// Names the original logical node receiving the permission.
    pub node: Id,
    /// Names its indivisible execution owner.
    pub owner: Id,
    /// Retains the original permission without widening it.
    pub permission: SavedPermission,
    /// Retains the unchanged frozen staged cut bound to this original operation.
    #[serde(deserialize_with = "required_nullable")]
    pub input_batch: Option<Id>,
}

/// Preserves the immutable staged input cut and its authentic native custody state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedInputBatch {
    /// Names the indivisible execution owner.
    pub owner: Id,
    /// Names the logical node under which the original native cut was staged.
    pub node: Id,
    /// Names the distinct original staging operation, never repeated on restore.
    pub stage_operation: Id,
    /// Names the original immutable cut.
    pub batch: Id,
    /// Retains the original source native owner roster.
    pub owners: Vec<crate::node_contract::OwnerIdentity>,
    /// Retains the complete exclusive delivery cut.
    pub cutoff: Position,
    /// Binds the original canonical complete delivery inventory.
    pub inventory: ContentRef,
    /// Retains original deliveries, including already consumed prefix identities.
    pub deliveries: Vec<Delivery>,
    /// Preserves original readable bytes without native pointers.
    pub payloads: Vec<InputPayload>,
    /// Retains original native staging evidence, or explicit null before staging.
    #[serde(deserialize_with = "required_nullable")]
    pub acknowledgement: Option<NativeInputAcknowledgement>,
    /// Retains the original unresolved activation, or explicit null between runs.
    #[serde(deserialize_with = "required_nullable")]
    pub activated_by: Option<Id>,
    /// Retains exactly the already consumed original canonical prefix.
    pub consumed: Vec<InputIdentity>,
}

/// Preserves all currently represented coordinator continuation state.
///
/// This record contains no process-local authority. Complete world verification
/// must bind it to native owner state before reconstruction can activate. An
/// unresolved reservation is preserved for diagnosis and custody accounting;
/// reconstruction refuses it until native original-token reminting qualifies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulingSnapshot {
    /// Selects the sole supported snapshot schema edition.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Names the exact retained superdense event-order profile.
    pub ordering_profile: String,
    /// Binds the unchanged complete durable world compatibility identity.
    pub world_binding_hash: HashRef,
    /// Names the original committed source activation.
    pub source_activation_id: Id,
    /// Names the source world generation, never reused on restore.
    pub source_generation: U64,
    /// Retains the source activation cut independently of later owner progress.
    pub source_boundary: Position,
    /// Retains the coordinator's explicit consistent cut without closing later work.
    pub capture_cut: Position,
    /// Binds the capture ordinal without renumbering producer event sequences.
    pub capture_ordinal: U64,
    /// Enumerates the complete source execution and capture owner roster.
    pub source_owners: Vec<SavedOwner>,
    /// Retains the finite same-time closure count from the admitted coordinator.
    pub maximum_microsteps: U64,
    /// Enumerates every execution owner's reached phase and closure prefix.
    pub positions: Vec<SavedPosition>,
    /// Enumerates every public producer, including unknown bounds and exhaustion.
    pub producers: Vec<SavedProducer>,
    /// Retains every observed native output-lane sequence without conflating fanout.
    pub native_sequences: Vec<SavedNativeSequence>,
    /// Retains known external-input prefix claims; omitted declared lanes remain unknown.
    pub external_closed_prefixes: Vec<SavedExternalPrefix>,
    /// Retains readable immutable payload objects for all pending deliveries.
    pub payload_objects: Vec<SavedPayload>,
    /// Retains ordered pending deliveries and their original publication lineage.
    pub pending_deliveries: Vec<Delivery>,
    /// Retains every allocated original operation identity, including completed.
    pub used_operations: Vec<Id>,
    /// Retains every unresolved original reservation without claiming pause.
    pub reservations: Vec<SavedReservation>,
    /// Preserves prepared, staged, or partially consumed immutable native input cuts.
    pub input_batches: Vec<SavedInputBatch>,
    /// Retains all previously minted immutable batch identities to prevent replay.
    pub used_input_batches: Vec<Id>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
