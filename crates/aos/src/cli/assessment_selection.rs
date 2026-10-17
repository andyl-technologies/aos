//! Shared-profile Hub scan selection resolved against admitted package status.
//!
//! Exact submission files remain available for pinned automation. Interactive
//! selectors first enumerate a bounded inventory and then submit its complete
//! immutable selection, so a missing package never becomes a partial scan.

use super::{AssessmentFreshnessArg, AssessmentProfileArg};

#[derive(clap::Args)]
pub struct HubAssessmentScanSelectionArgs {
    /// Select independent profiles or the explicit supported profile set
    #[arg(
        long = "profile",
        value_enum,
        value_delimiter = ',',
        required_unless_present = "request"
    )]
    pub profiles: Vec<AssessmentProfileArg>,

    /// Select these exact coordinates from the Hub's admitted inventory
    #[arg(long = "package", value_name = "COORDINATE", requires = "profiles")]
    pub packages: Vec<String>,

    /// Select source acquisition intent; defaults to refresh-stale
    #[arg(long, value_enum, requires = "profiles")]
    pub freshness: Option<AssessmentFreshnessArg>,

    /// Preserve this exact actor-scoped request identity through retries
    #[arg(long, required_unless_present = "request")]
    pub idempotency_key: Option<String>,
}
