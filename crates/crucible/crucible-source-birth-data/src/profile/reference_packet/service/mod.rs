//! Selects immutable private launch/profile DATA, never a service or Source.

use super::{PacketProgramDefinition, connected::PacketConnectedDefinition};
use serde::{Deserialize, Serialize};

/// Selects one original interpreter without changing existing output-only profiles.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PacketConnectedSourceProgram {
    /// Retains the independently configured source-2 output producer.
    Producer {
        /// Retains its complete unchanged two-event program.
        program: PacketProgramDefinition,
    },
    /// Installs the distinct source-4 relay or sink.
    Reactive {
        /// Retains every declared original input connection and output lane.
        program: PacketConnectedDefinition,
    },
}

pub mod ack_emitter;
pub mod capture_allocation;
pub mod complete_restore;
pub mod confirmation;
pub mod fresh_restore_allocation;
mod native5;
mod protocol_metadata;
pub use ack_emitter::PacketNative5AckEmitterSelection;
pub use confirmation::PacketNative5ConfirmationSelection;
pub use native5::{
    PacketNative5CaptureProfile, PacketNative5LaunchValidationFields,
    PacketNative5LaunchValidationProjection, PacketNative5PathSerializationData,
    PacketNative5SourceLaunch, PacketNative5StorageLimits,
};
pub use protocol_metadata::PacketNative5ProtocolMetadataLimits;

/// Shares the actual borrowed static contract serializer.
pub mod native_startup;

/// Defines the sole immutable Native5 policy payload and static constructors.
pub mod native5_policy;

/// Defines the sole immutable original report publication DATA grammar.
pub mod report_startup;
