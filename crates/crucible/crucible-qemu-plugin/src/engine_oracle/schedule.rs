//! SPDX-License-Identifier: GPL-2.0-only
//! Portable schedule values produced by the GPL plugin's own execution path.
//!
//! These values implement the test-oracle v2 comparison schema. They do not
//! represent engine objects or contain any engine implementation state.

use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Icount {
    pub(crate) retired: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdvanceOutcome {
    ReachedHorizon,
    Paused { at: Icount },
}

impl AdvanceOutcome {
    pub(crate) fn projection(self) -> Value {
        match self {
            Self::ReachedHorizon => json!({"kind": "reached-horizon"}),
            Self::Paused { at } => json!({"kind": "paused", "at": at.retired}),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ScheduleEvent {
    HorizonAdvance {
        from_icount: u64,
        requested_icount: u64,
        reached_icount: u64,
        outcome: AdvanceOutcome,
    },
    FrameDelivery {
        src_slot: u32,
        sequence: u32,
        delivery_icount: u64,
        payload: Vec<u8>,
    },
    FrameEmission {
        dst_slot: u32,
        sequence: u32,
        delivery_icount: u64,
        payload: Vec<u8>,
    },
}

impl ScheduleEvent {
    pub(crate) fn projection(&self) -> Value {
        match self {
            Self::HorizonAdvance {
                from_icount,
                requested_icount,
                reached_icount,
                outcome,
            } => json!({"kind": "horizon", "from": from_icount, "requested": requested_icount,
                       "reached": reached_icount, "outcome": outcome.projection()}),
            Self::FrameDelivery {
                src_slot,
                sequence,
                delivery_icount,
                payload,
            } => json!({"kind": "delivery", "source": src_slot, "sequence": sequence,
                       "icount": delivery_icount, "payload": payload}),
            Self::FrameEmission {
                dst_slot,
                sequence,
                delivery_icount,
                payload,
            } => json!({"kind": "emission", "destination": dst_slot, "sequence": sequence,
                       "icount": delivery_icount, "payload": payload}),
        }
    }
}
