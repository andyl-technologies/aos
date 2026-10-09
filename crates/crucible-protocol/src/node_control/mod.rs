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

mod channel;
mod codec;
mod edition;
mod facts;
mod frame;
mod journal;
mod timers;
mod types;
mod writer_frames;
mod writers;

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
pub use journal::{
    CommandJournal, CommandJournalDisposition, CommandJournalSnapshot,
    NATIVE_COMMAND_JOURNAL_MAX_BYTES, NATIVE_COMMAND_JOURNAL_MAX_ENTRIES,
};
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
