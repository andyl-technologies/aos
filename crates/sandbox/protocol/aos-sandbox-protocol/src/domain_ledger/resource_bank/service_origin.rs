//! Defines passive byte widths for the fixed service-origin flight.
//!
//! ```text
//! Budget = AOSSFB01 prefix192 + ceiling22xBEu64
//! Final  = AOSRSO01 prefix128 + persistent_usage22xBEu64 (Source/Ownership/Cache/Mount)
//! Network Final = AOSRSO02 prefix128 + persistent_usage22xBEu64
//! ```
//!
//! These widths describe the unpublished complete transfer. They provide no
//! decoder, inherited descriptor, resource account or executable provenance.
//! Native recipients must authenticate the same original PID1 flight and retain
//! every persistent usage dimension before admitting subsequent work.

use aos_sandbox_model::ResourceDimension;

/// Counts bytes in a fixed service-origin record's common fixed header.
pub const FIXED_SERVICE_ORIGIN_HEADER_BYTES: usize = 128;

/// Counts bytes in the complete canonical resource vector, ordered by dimension.
pub const FIXED_SERVICE_USAGE_BYTES: usize = ResourceDimension::COUNT * 8;

/// Counts bytes in the complete fixed-service budget flight, including its ceiling.
pub const FIXED_SERVICE_BUDGET_BYTES: usize = 192 + FIXED_SERVICE_USAGE_BYTES;

/// Counts bytes in the final fixed-service transfer, including all persistent usage.
///
/// There is no shorter compatibility form for this unpublished transfer. Its
/// usage is comparison DATA until the actual original flight is authenticated.
pub const FIXED_SERVICE_FINAL_TRANSFER_BYTES: usize =
    FIXED_SERVICE_ORIGIN_HEADER_BYTES + FIXED_SERVICE_USAGE_BYTES;
