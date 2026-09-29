//! Native access to the concrete audited SQLite-to-encrypted-record pipeline.
//!
//! Callers open the source through the no-create read adapter and supply private
//! sinks and explicit archive key custody. Failure may leave incomplete sink
//! bytes. Successful capture grants no serving or recovery authority.

pub use aos_hub_core::snapshot::archive::records::{
    capture_sqlite, CaptureKeyCustody, DatabaseCaptureOutput, SqliteCaptureOptions,
};
