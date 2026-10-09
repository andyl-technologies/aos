//! Versioned native owner commands carried on an independently negotiated channel.
//!
//! These records complement the existing ControlV3 setup and shared-memory
//! protocols. Decoding a command authenticates no authority: a native provider
//! must match its retained preparation, activation, complete staged input cut
//! and original request journal before exposing it to its execution engine.
//! Legacy endpoints never interpret these bytes or acquire strict timing claims.
//!
//! ```text
//! offset  bytes  field
//! 0       8      "CNQEMU01"
//! 8       2      extension version, big endian
//! 10      2      command kind, big endian
//! 12      4      body byte length, big endian
//! 16      N      closed command body, no pointers or native enum layouts
//! ```

#[cfg(test)]
mod administrative_frame_tests;
mod administrative_preparation;
mod administrative_role;
mod channel;
mod codec;
mod edition;
mod facts;
mod fixed_microvm;
mod fixed_microvm_frames;
mod frame;
mod initialization;
mod initialization_command;
mod initialization_cut;
mod journal;
mod phase;
mod phase_timer_frames;
mod phase_timers;
mod preparation_successor;
mod preparation_successor_frames;
mod preparation_successor_object;
mod source_fault;
mod timers;
mod types;
mod writer_frames;
mod writers;

pub use administrative_preparation::NativeAdministrativePreparation;
pub use administrative_role::NativeAdministrativeFacts;
pub use fixed_microvm::{
    NATIVE_FIXED_MICROVM_CONTROLLER_EDITION, NATIVE_FIXED_MICROVM_EARLY_PIN_BYTES,
    NATIVE_FIXED_MICROVM_POLICY_BYTES, NativeFixedMicrovmMapping, NativeFixedMicrovmPreparation,
};

#[cfg(unix)]
pub use channel::NativeChannel;
pub use channel::NativeChannelError;
pub use codec::{decode_command, encode_command};
pub use edition::{NativeControlEdition, decode_frame_for_edition, encode_frame_for_edition};
pub use facts::{
    NativeCpuParkFacts, NativeFrame, NativePreparation, NativeStopFacts, NativeStopKind,
    ReceiptAcknowledgement,
};
pub use frame::{decode_frame, encode_frame};
pub use initialization::{NATIVE_INITIALIZATION_MAX_CALLBACKS, NativeInitializationPreparation};
pub use initialization_command::{
    NativeInitializationAcknowledgement, NativeInitializationCommand, NativeInitializationQuery,
    NativeInitializationReceipt, NativeInitializationStatus,
};
pub use initialization_cut::{
    NativeInitializationClass, NativeInitializationCut, NativeInitializationRow,
};
pub use journal::{
    CommandJournal, CommandJournalDisposition, CommandJournalSnapshot,
    NATIVE_COMMAND_JOURNAL_MAX_BYTES, NATIVE_COMMAND_JOURNAL_MAX_ENTRIES,
};
pub use preparation_successor::{
    NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES, NativePreparationSuccessorFacts,
};
pub use preparation_successor_frames::{
    NATIVE_PREPARATION_SUCCESSOR_CHUNK_BYTES, NativePreparationSuccessorChunk,
    NativePreparationSuccessorQuery,
};
pub use preparation_successor_object::NativePreparationSuccessorObservation;
pub use source_fault::{SOURCE_FAULT_BYTES, SourceFaultFacts};
pub use types::{
    BoundaryPolicy, ExecutionCommand, ExecutionKind, NODE_CONTROL_HEADER_BYTES,
    NODE_CONTROL_MAX_BODY_BYTES, NODE_CONTROL_VERSION, NativeCommandError, OwnerScope,
};

pub use timers::{
    NATIVE_TIMER_CHUNK_BYTES, NATIVE_TIMER_OBJECT_MAX_BYTES, NativeTimerArm, NativeTimerChunk,
    NativeTimerList, NativeTimerObservation, NativeTimerQuery,
};
pub use writer_frames::{NATIVE_WRITER_CHUNK_BYTES, NativeWriterChunk, NativeWriterQuery};
pub use writers::{
    NATIVE_WRITER_OBJECT_MAX_BYTES, NativeWriterAio, NativeWriterBh, NativeWriterCpu,
    NativeWriterHandler, NativeWriterObservation, NativeWriterWork,
};

pub use phase::{
    NATIVE_PHASE_EARLY_PIN_BYTES, NATIVE_PHASE_MAX_MICROSTEP, NATIVE_PHASE_POLICY_BYTES,
    NativePhaseMapping, NativePhasePolicy, NativePhasePreparation,
};
pub use phase_timer_frames::{
    NATIVE_PHASE_TIMER_CHUNK_BYTES, NativePhaseTimerChunk, NativePhaseTimerQuery,
};
pub use phase_timers::{
    NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES, NATIVE_PHASE_TIMER_ROW_BYTES,
    NATIVE_PHASE_TIMER_SUMMARY_BYTES, NativePhaseTimerArm, NativePhaseTimerObservation,
    NativeTimerBirth, NativeTimerParent,
};
