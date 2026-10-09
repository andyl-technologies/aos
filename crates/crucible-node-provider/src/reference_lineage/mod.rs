//! Source-owned checksum input boundaries and retained native consumption.
//!
//! This successor dialect is distinct from the legacy reference device. Its
//! frames carry data only; an enclosing installed provider must authenticate
//! each original batch, child identity and output before claiming lineage.

mod association;
mod child;
mod custody;
mod driver;
mod execution;
mod journal;
mod kernel;
mod physical_observation;
mod protocol;
mod relation;
mod source_custody;
pub(crate) mod transport;

pub use association::{NativeConsumedBatch, NativeLineageOrigin};
pub use child::serve;
pub use custody::{LineageCustodyQueue, LineageCustodyStatus};
pub use driver::{LineageDeviceStatus, NativeLineageDevice, NativeLineageWindow};
pub use journal::{
    MAX_NATIVE_COMMANDS, MAX_NATIVE_JOURNAL_BYTES, NativeCommandKnowledge, NativeCommandRecord,
};
pub use protocol::{
    DIALECT, LineageConsumedEntry, LineageStage, NativeLineageReceipt, StagedLineageEntry,
};
pub use source_custody::{
    LineageSourceCustody, LineageSourceCustodySlot, LineageSourceFailure, LineageSourceGuard,
};

pub use relation::{ConsumptionEvidence, ConsumptionRelationCredit, NativeConsumptionRelation};

#[cfg(test)]
mod tests;
