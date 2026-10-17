//! Early refusal of unsupported condition-runtime archives without expanding indexes.
//!
//! These callers already hold bounded authenticated archive bytes. The probe
//! scans their runtime version while serde skips other values with IgnoredAny;
//! it never constructs RuntimeSnapshot input indexes or proof-body vectors.
//! Supported legacy bytes still pass through their original typed serde decoder.

use serde::{Deserialize, de::DeserializeOwned};

use super::super::{StateError, schema};
use super::archive::refusal;

// Unknown fields are deliberately skipped only during this header probe. The
// original closed typed decoder remains responsible for the complete grammar.
#[derive(Deserialize)]
struct CoordinatorHeader {
    runtime: RuntimeHeader,
}

#[derive(Deserialize)]
struct RuntimeHeader {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
}

/// Decodes an already-bounded archive record after checking its runtime edition.
///
/// The archive loader and verified content closure retain their installed
/// object and aggregate byte ceilings; source activation reads additionally
/// enforce the caller's record ceiling. The legacy decoder preserves numeric byte
/// arrays above the portable parser's per-array limit. This probe introduces no
/// new cap on accepted legacy records and grants no preservation authority.
///
/// # Errors
/// Refuses malformed headers, unsupported condition runtime six, or any record
/// rejected by the original closed typed decoder.
pub(super) fn decode_supported_coordinator<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, StateError> {
    let header: CoordinatorHeader = serde_json::from_slice(bytes).map_err(schema)?;
    if header.runtime.schema_version == 6 {
        return Err(refusal(
            "condition runtime six is unsupported by the installed host archive codec",
        ));
    }

    serde_json::from_slice(bytes).map_err(schema)
}

#[cfg(test)]
#[path = "runtime_header_tests.rs"]
mod tests;
