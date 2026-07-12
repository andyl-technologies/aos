//! Error types for the persistent eval-cache stores.
//!
//! Models the failure modes of packfile decoding, index reads and writes,
//! blob-pack I/O, file-artifact hydration, and schema management.

use super::*;

mod format_errors;
mod index_errors;
mod indexed_errors;
mod storage_errors;

pub use format_errors::{
    PersistBlobPackError, PersistNodeTraceLogError, PersistNodeTraceLogFormatError,
    PersistNodeTracePayloadError, PersistPackFormatError,
};
pub use index_errors::{
    PersistBlobIndexError, PersistFileArtifactIndexError, PersistNodeMetadataIndexError,
    PersistParseArtifactIndexError, PersistRootRecordIndexError,
};
pub use indexed_errors::{
    PersistBlobIndexedReadError, PersistBlobIndexedWriteError,
    PersistCachedExpressionNodeValueIndexedLoadError,
    PersistCachedExpressionNodeValueIndexedWriteError,
    PersistCachedExpressionNodeValueTraceLoadError, PersistCachedExpressionValueIndexedLoadError,
    PersistCachedExpressionValueIndexedWriteError, PersistError, PersistFileArtifactFlushError,
    PersistFileArtifactHydrationError,
    PersistFileArtifactIndexedHydrationError, PersistFileArtifactIndexedWriteError,
    PersistParseArtifactHydrationError, PersistParseArtifactIndexedHydrationError,
    PersistParseArtifactIndexedWriteError, PersistParseArtifactMaterializationError,
    PersistParseBytesIndexedLoadError, PersistParseFileIndexedHydrationError,
    PersistParseFileIndexedLoadError, PersistParseSourceIndexedLoadError, PersistRootRecordError,
};
pub use storage_errors::{
    PersistBlobIndexRebuildError, PersistBlobIndexRebuildPlanError, PersistBlobIndexesRebuildError,
    PersistBlobLiveRootError, PersistBlobPackLivenessPlanError, PersistBlobPackRepackPlanError,
    PersistBlobPackTrimError, PersistBlobPacksRepackError, PersistCompactionError,
    PersistFileBlobPackRepackError, PersistFileBlobReachabilityPlanError,
    PersistNodeValueRootPlanError, PersistStorageAutoMaintenanceError,
    PersistStorageMaintenanceError, PersistStorageMaintenancePlanError, PersistStorageRepackError,
    PersistValueBlobPackRepackError, PersistValueBlobReachabilityPlanError,
};
