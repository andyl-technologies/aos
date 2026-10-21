//! Kernel-subject evidence and retained receive custody for connected streams.
//!
//! Endpoint and connection-peer mechanics are owned by aos-linux-descriptors.
//! This module owns the actual cmsg/EOF receive algorithms and their sealed
//! subject construction, never a second stream or application-role authority.

use aos_linux_descriptors::unix_stream::RetainedUnixStream;
mod subject;
mod eof;
mod listener;
mod read_buffer;
pub use subject::{SubjectStreamReceiveGeometryV1, UnixStreamSubjectChunk,
    try_receive_subject_chunk, try_receive_subject_chunk_retaining,
    try_receive_subject_chunk_with_geometry_retaining};
pub use eof::{UnixStreamSubjectEofReadbackV1, try_receive_subject_eof_with_geometry_retaining};
pub use listener::RetainedSubjectStreamListenerReadbackV1;
pub use read_buffer::{RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1};
/// Owns a failed strict stream receive and its actual partial native custody.
pub type RetainedUnixStreamSubjectReceiveErrorV1 = crate::seqpacket::RetainedSeqpacketReceiveErrorV1;
