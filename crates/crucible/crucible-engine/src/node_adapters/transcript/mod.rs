//! Authenticated conditional boundary transcripts and explicit replay participants.
//!
//! A live [`RecordingNode`] reserves capture before native requests, validates
//! actual source responses and retains their raw data before acknowledgement.
//! [`TranscriptArchive`] authenticates that private capture independently of
//! public content hashes. [`TranscriptReplayNode`] additionally requires trusted
//! installed applicability qualification and refuses any changed or unrecorded
//! branch before releasing output. Original nondeterminism and physical timing
//! uncertainty remain distinct from reproducible recorded boundary responses.

mod archive;
mod byte_wire;
mod capture;
mod codec;
mod control;
mod input_custody_references;
mod model_capture_view;
mod node;
mod proof;
mod recording;
mod replay;
mod tape2;
mod tape2_continuation;
mod types;

#[cfg(test)]
mod tests;

pub use archive::{AuthenticatedTranscript, TranscriptArchive};
pub use capture::CapturedTranscript;
pub use codec::{TranscriptError, context_commitment};
pub use input_custody_references::{ReplayInputCustodyReferences, replay_input_custody_references};
pub use model_capture_view::{OriginalLineageModelCapture, decode_original_lineage_model_capture};
pub use node::{
    AuthenticatedReplayContinuation, TRANSCRIPT_REPLAY_PRESERVATION_PROFILE,
    TRANSCRIPT_REPLAY_PROFILE, Tape2PreparationFailure, TranscriptReplayNode,
    authenticate_replay_continuation, transcript_replay_continuation_definition,
    transcript_replay_continuation_schema,
};
pub use recording::{RecordingHandle, RecordingNode, RecordingPreparationFailure};
pub use replay::{InstalledReplayPolicy, ReplayCursorSnapshot, ReplayQualification};
pub use tape2::{OriginalLineageTapePrefix, TRANSCRIPT_ORIGINAL_LINEAGE_PROFILE};
pub use types::{
    BoundaryTranscript, PhysicalTimingUncertainty, ReplayRequestMetadata, TranscriptAction,
    TranscriptLimits, TranscriptOrigin, TranscriptRecord, TranscriptRequest,
};

pub use tape2_continuation::{
    AuthenticatedTape2Continuation, PinnedTape2Continuation,
    TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE, authenticate_pinned_tape2_continuation,
    authenticate_tape2_continuation, original_lineage_continuation_definition,
    original_lineage_continuation_schema,
};
