//! Closed private native frames without public CNP execution authority.
//!
//! ```text
//! frame = uint32_be(json_byte_length) || utf8_json
//! integer = canonical decimal string representing an unsigned 64-bit value
//! ```

use crucible_node_contract::{Id, Phase, Position, U64};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Bounds private native frames independently of public CNP receiving credit.
pub const GEM5_NATIVE_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Identifies the versioned private owner controller.
pub const GEM5_NATIVE_PROTOCOL: &str = "crucible.gem5.native/2";

/// Supplies private original launch identity and explicitly selected resources.
#[derive(Clone, Serialize)]
pub(crate) struct Bootstrap {
    pub schema: &'static str,
    pub owner: Id,
    pub incarnation: Id,
    pub generation: U64,
    pub controller_uid: U64,
    pub guest_isa: String,
    pub executable: String,
    pub resource_root: String,
    pub control_socket: String,
}

/// Preserves native event order independently of public superdense phases.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5Boundary {
    /// Records the actual native clock; an idle grant does not move it.
    pub tick: U64,
    /// Records the retained coordinator cursor independently of idle native time.
    pub logical_position: Position,
    /// Counts every serviced native event without wrapping or normalizing ties.
    pub ordinal: U64,
    /// Counts serviced native events at this tick without wrapping same-time ties.
    pub tick_ordinal: U64,
    /// Reports actual pending queue membership.
    pub has_next_event: bool,
    /// Records the next queued event's tick, or zero when no event is queued.
    pub next_tick: U64,
    /// Records its actual native priority independently of public phase order.
    pub next_priority: i32,
    /// Retains the native modeled-state observer's complete original response.
    pub inventory: Value,
}

impl Gem5Boundary {
    /// Requires the native observer to cover every modeled state domain.
    ///
    /// This checks coverage shape only. Installed qualification must separately
    /// authenticate the actual observer, source/model identity and complete data.
    pub fn has_complete_inventory(&self) -> bool {
        self.inventory.get("schema").and_then(Value::as_str)
            == Some("crucible.gem5.modeled-state.v1")
            && self.inventory.get("complete") == Some(&Value::Bool(true))
            && self.inventory.get("native_tick").and_then(Value::as_str)
                == Some(self.tick.get().to_string().as_str())
            && self
                .inventory
                .get("unsupported_domains")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
    }
}

/// Defines a checked half-open superdense range for a closed native profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5ExactRange {
    /// Includes native reactions at this original stopped coordinator cursor.
    pub start: Position,
    /// Excludes every reaction at or beyond this full coordinate.
    pub limit: Position,
    /// Bounds same-time reaction and publication coordinates without wrapping.
    pub maximum_microsteps: U64,
}

impl Gem5Boundary {
    /// Maps the next native callback to its distinct superdense reaction slot.
    ///
    /// This mechanical mapping conveys no native profile or input-closure proof.
    ///
    /// # Errors
    /// Rejects exhausted native tie counters or a reaction beyond the finite cap.
    pub fn next_reaction(
        &self,
        maximum_microsteps: U64,
    ) -> Result<Option<Position>, crate::ProviderError> {
        if !self.has_next_event {
            return Ok(None);
        }
        let microstep = if self.next_tick == self.tick {
            self.tick_ordinal.get().checked_mul(2)
        } else {
            Some(0)
        }
        .ok_or(crate::ProviderError::ResourceExhausted(
            "gem5 reaction microstep",
        ))?;
        if microstep
            .checked_add(1)
            .is_none_or(|publication| publication >= maximum_microsteps.get())
        {
            return Err(crate::ProviderError::ResourceExhausted(
                "gem5 same-time closure",
            ));
        }
        Ok(Some(Position::new(
            self.next_tick,
            U64::new(microstep),
            Phase::Reaction,
        )))
    }
}

/// Retains the exact original private native event prefix request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5Run {
    /// Must identify the private native run operation.
    pub kind: String,
    /// Names the controller's original operation without a replacement attempt.
    pub operation: Id,
    /// Excludes native events at and beyond this physical tick.
    pub exclusive_tick: U64,
    /// Bounds native events between controller polls independently of sim time.
    pub maximum_events: U64,
    /// Selects full-position mediation, or required null for mechanical diagnostics.
    #[serde(deserialize_with = "required_nullable")]
    pub exact_range: Option<Gem5ExactRange>,
}

/// Retains an authentic completed native event prefix and its unread output.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5Completion {
    /// Must identify a completed private native prefix.
    pub kind: String,
    /// Names the original operation whose resource custody remains retained.
    pub operation: Id,
    /// Retains exact request material instead of a caller-created receipt scope.
    pub original: Gem5Run,
    /// Retains native state before servicing the original event prefix.
    pub before: Gem5Boundary,
    /// Retains native state after servicing that prefix.
    pub after: Gem5Boundary,
    /// Gives actual native event progress, independently of elapsed host time.
    pub processed_events: U64,
    /// Classifies horizon, idle, event budget, output or actual guest exit.
    pub reason: String,
    /// Retains complete actual guest syscall output before native release.
    pub output: Vec<u8>,
    /// Retains native guest-write births; an empty vector cannot prove file-polled output timing.
    pub publications: Vec<Gem5ConsolePublication>,
    /// Retains the actual native guest exit diagnostic, or required null.
    #[serde(deserialize_with = "required_nullable")]
    pub exit_cause: Option<String>,
    /// Retains the actual native guest exit code, or required null.
    #[serde(deserialize_with = "required_nullable")]
    pub exit_code: Option<i32>,
}

/// Preserves an original native console write captured inside its event callback.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5ConsolePublication {
    /// Identifies the native output FIFO entry, starting at one without reuse.
    pub output_id: U64,
    /// Records the actual physical tick of the guest write.
    pub tick: U64,
    /// Identifies the serviced native event that produced the write.
    pub event_ordinal: U64,
    /// Records its checked event order at this physical instant.
    pub tick_ordinal: U64,
    /// Identifies the explicitly configured modeled guest process.
    pub guest_pid: U64,
    /// Identifies the modeled CPU context that performed the write.
    pub context_id: U64,
    /// Records the modeled file descriptor; this facet supports stdout only.
    pub guest_fd: i32,
    /// Retains the original sealed input parent, or zero for a root computation.
    pub causal_parent: U64,
    /// Retains immutable original output octets until publication acknowledgment.
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ready {
    pub kind: String,
    pub schema: String,
    pub owner: Id,
    pub incarnation: Id,
    pub generation: U64,
    pub continuation: String,
    pub boundary: Gem5Boundary,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
