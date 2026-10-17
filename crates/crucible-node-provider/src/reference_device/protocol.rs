//! Private reference-device frames and immutable quantized window identity.
//!
//! This bounded subprotocol carries native device evidence. It is not CNP/1
//! authorization, and its receipts require the enclosing provider's custody.

use crucible_node_contract::{Id, Phase, Position, U64};
use serde::{Deserialize, Serialize};

use crate::ProviderError;

/// Limits the reference device's admitted input bytes per window.
pub const MAX_INPUT_BYTES: usize = 4096;

/// Limits each private device frame independently of CNP/1 transport ceilings.
pub const DEVICE_FRAME_BYTES: usize = 65_536;

/// Binds one immutable input cut to its native owner and publication boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceGrant {
    /// Identifies the currently realized execution owner.
    pub owner_id: Id,
    /// Identifies this child process realization.
    pub incarnation_id: Id,
    /// Fences earlier realizations of the same owner.
    pub generation: U64,
    /// Identifies the original quantized operation.
    pub window_id: Id,
    /// Names the immutable authorized input batch.
    pub input_batch_id: Id,
    /// Orders successive windows without wrapping.
    pub quantum: U64,
    /// Locates the input sampling boundary after host causal authorization.
    pub start: Position,
    /// Locates root output publication at the next declared boundary.
    pub publication: Position,
    /// Limits elapsed host activation time, including transport and scheduling.
    pub host_budget_ns: U64,
}

impl DeviceGrant {
    pub(super) fn validate(&self) -> Result<(), ProviderError> {
        if self.generation.get() == 0
            || self.host_budget_ns.get() == 0
            || self.start.time_ps >= self.publication.time_ps
            || self.publication.microstep.get() != 0
            || self.publication.phase != Phase::Publication
        {
            return Err(ProviderError::Correlation("invalid reference-device grant"));
        }
        Ok(())
    }
}

/// Records the stateful checksum device's complete output for one window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceOutput {
    /// Counts bytes consumed from this window's immutable input batch.
    pub bytes_processed: U64,
    /// Commits the device's cumulative rolling checksum after this batch.
    pub checksum: U64,
}

/// Preserves authenticated local window evidence until publication is acknowledged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReceipt {
    /// Retains the original owner, interval and immutable batch identity.
    pub grant: DeviceGrant,
    /// Retains the original complete output, even for repeated close requests.
    pub output: DeviceOutput,
    /// Measures elapsed activation time independently of modeled picoseconds.
    pub measured_host_ns: U64,
    /// Confirms the controlled device loop acknowledged application-level park.
    ///
    /// This does not claim OS thread suspension or pause of physical hardware.
    pub application_parked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Initialize {
        owner: Id,
        incarnation: Id,
        generation: U64,
    },
    Stage {
        grant: DeviceGrant,
        input: Vec<u8>,
    },
    Activate {
        window: Id,
    },
    Close {
        window: Id,
    },
    Acknowledge {
        window: Id,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Response {
    Ready {
        owner: Id,
        incarnation: Id,
        generation: U64,
        child_pid: U64,
    },
    Staged {
        grant: DeviceGrant,
    },
    Completed {
        window: Id,
        output: DeviceOutput,
    },
    Closed {
        grant: DeviceGrant,
        output: DeviceOutput,
        application_parked: bool,
    },
    Acknowledged {
        window: Id,
    },
}
