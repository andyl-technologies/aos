//! Native access to audited SQLite/PostgreSQL encrypted-record pipelines.
//!
//! Callers open the source through the no-create read adapter and supply private
//! sinks and explicit archive key custody. Failure may leave incomplete sink
//! bytes. Successful capture grants no serving or recovery authority.

pub use aos_hub_db::snapshot::archive::records::capture_sqlite;
pub use aos_hub_db::snapshot::archive::records::CaptureKeyCustody;
pub use aos_hub_db::snapshot::archive::records::DatabaseCaptureOutput;
pub use aos_hub_db::snapshot::archive::records::SqliteCaptureOptions;

#[cfg(feature = "postgres")]
pub use aos_hub_db::snapshot::archive::records::capture_postgres;
#[cfg(feature = "postgres")]
pub use aos_hub_db::snapshot::archive::records::PostgresCaptureOptions;
