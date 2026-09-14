//! Pure bounded client-side state reducers for the public sandbox API.
//!
//! [`pagination`] pins list pages to one immutable revision, [`operation_wait`]
//! observes durable operations without conflating an RPC deadline with
//! cancellation, and [`watch`] implements explicit bootstrap/resume semantics
//! with fail-closed cursor-gap handling.

pub mod checkpoint;
pub mod operation_wait;
pub mod pagination;
pub mod watch;

pub use checkpoint::{InvalidWatchCheckpoint, WatchCheckpointV1, MAXIMUM_WATCH_CHECKPOINT_BYTES};
pub use operation_wait::{
    OperationWaitApplyOutcomeV1, OperationWaitError, OperationWaitPolicyV1, OperationWaitReducerV1,
    OperationWaitTerminationV1, MAXIMUM_WAIT_NANOSECONDS, MAXIMUM_WAIT_OBSERVATIONS,
    MAXIMUM_WAIT_VERSION_BYTES,
};
pub use pagination::{
    ImmutableListPageV1, ImmutableListRevisionV1, PageApplyOutcomeV1, PageRequestV1, PageTokenV1,
    PaginationError, PaginationReducerV1, MAXIMUM_COLLECTED_BYTES, MAXIMUM_COLLECTED_ITEMS,
    MAXIMUM_LIST_PAGES, MAXIMUM_PAGE_BYTES, MAXIMUM_PAGE_ITEMS,
};
pub use watch::{
    CompletedWatchBootstrapV1, ServerResyncReasonV1, StreamSequenceContractV1, WatchApplyOutcomeV1,
    WatchError, WatchInputV1, WatchReducerV1, WatchRelistReasonV1, WatchResumePointV1,
    WatchSnapshotChunkV1, WatchTerminationV1, MAXIMUM_RETAINED_WATCH_BYTES,
    MAXIMUM_RETAINED_WATCH_EVENTS, MAXIMUM_WATCH_BOOTSTRAP_BYTES, MAXIMUM_WATCH_BOOTSTRAP_ITEMS,
    MAXIMUM_WATCH_CHUNK_BYTES, MAXIMUM_WATCH_CHUNK_ITEMS,
};
