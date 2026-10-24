//! Reads the explicit native policy17 wrapper without changing earlier leaves.
//!
//! ```json
//! ["source-private.native5-policy-owned-capture-allocation/17",
//!  "original_observe12", ["report ContentRef", "record ContentRef"],
//!  ["the complete preceding policy13, 14, 15 or 16 leaf"]]
//! ```
//!
//! Both complete definition objects retain their exact recorded capacities.
//! The wrapper is historical data. It cannot issue a native quote, authenticate
//! an original Observe response or complete the new endpoint/service class.

use super::*;
use crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection;

pub(super) const CAPTURE_POLICY_FORMAT: &str =
    "source-private.native5-policy-owned-capture-allocation/17";

pub(super) fn read_selected(
    mut fields: Fields<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    allow_transfer: bool,
) -> Result<Option<HistoricalNativePolicy>, ProviderError> {
    if allow_transfer {
        return Err(invalid());
    }
    let selection = capture_selection(next(&mut fields)?)?;
    let raw_definitions = next(&mut fields)?;
    let base = next(&mut fields)?;
    fields.finish()?;

    // The original encoder wraps the FULL previous InputOwnedPolicyView. It
    // never nests a second Capture wrapper or inserts a newly defaulted base.
    let mut header = Fields::array(base)?;
    let base_tag = super::super::super::typed::plain_string(next(&mut header)?)?;
    if !matches!(
        base_tag,
        "source-private.native5-policy-owned-selected/13"
            | "source-private.native5-policy-owned-complete-restore/14"
            | "source-private.native5-policy-owned-restore-transfer/15"
            | "source-private.native5-policy-owned-restore-input-emitter/16"
    ) {
        return Err(invalid());
    }
    let mut definitions = Fields::array(raw_definitions)?;
    let report = next(&mut definitions)?;
    let record = next(&mut definitions)?;
    definitions.finish()?;

    // Capacity records follow the actual ordinary observer: every old plain
    // field first, then the two newly retained ContentRefs. Wire wrapper order
    // must not reorder the typed record walk. Validation builds neither object.
    let policy = HistoricalNativePolicy::read_selected(base, ledger, build, false)?;
    let report = ledger.read::<ContentRef>(report, build)?;
    let record = ledger.read::<ContentRef>(record, build)?;
    let Some(mut policy) = policy else {
        return Ok(None);
    };
    if policy.capture_allocation_selection.is_some()
        || policy.capture_allocation_definitions.is_some()
        || policy.protocol_metadata_limits.is_none()
        || !matches!(
            policy.capture_profile,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        )
    {
        return Err(invalid());
    }
    policy.capture_allocation_selection = Some(selection);
    policy.capture_allocation_definitions =
        Some([report.ok_or_else(invalid)?, record.ok_or_else(invalid)?]);
    Ok(Some(policy))
}

fn capture_selection(
    input: &[u8],
) -> Result<PacketNative5CaptureAllocationSelection, ProviderError> {
    match super::super::super::typed::plain_string(input)? {
        "original_observe12" => Ok(PacketNative5CaptureAllocationSelection::OriginalObserve12),
        _ => Err(invalid()),
    }
}

// crucible-lint: allow panic-shortcut -- actual enum serialization must agree with its historical reader.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "the regression compares the real contract serializer with the borrowed historical selection parser"
)]
mod tests {
    use super::*;

    #[test]
    fn capture_selection_reader_matches_actual_snake_case_contract_encoding() {
        let original = PacketNative5CaptureAllocationSelection::OriginalObserve12;
        let encoded = serde_json::to_vec(&original).unwrap();

        assert_eq!(encoded, br#""original_observe12""#);
        assert_eq!(capture_selection(&encoded).unwrap(), original);
        assert!(capture_selection(br#""OriginalObserve12""#).is_err());
        assert!(capture_selection(br#""other_observe12""#).is_err());
        assert!(capture_selection(b"null").is_err());
    }
}
