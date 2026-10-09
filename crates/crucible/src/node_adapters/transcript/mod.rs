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
mod capture;
mod codec;
mod control;
mod node;
mod proof;
mod recording;
mod replay;
mod types;

#[cfg(test)]
mod tests;

pub use archive::{AuthenticatedTranscript, TranscriptArchive};
pub use capture::CapturedTranscript;
pub use codec::{TranscriptError, context_commitment};
pub use node::{
    AuthenticatedReplayContinuation, TRANSCRIPT_REPLAY_PRESERVATION_PROFILE,
    TRANSCRIPT_REPLAY_PROFILE, TranscriptReplayNode, authenticate_replay_continuation,
    transcript_replay_continuation_definition, transcript_replay_continuation_schema,
};
pub use recording::{RecordingHandle, RecordingNode, RecordingPreparationFailure};
pub use replay::{InstalledReplayPolicy, ReplayCursorSnapshot, ReplayQualification};
pub use types::{
    BoundaryTranscript, PhysicalTimingUncertainty, ReplayRequestMetadata, TranscriptAction,
    TranscriptLimits, TranscriptOrigin, TranscriptRecord, TranscriptRequest,
};
