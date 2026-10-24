//! Reads the full fresh policy18 wrapper as inert historical data.
//!
//! ```json
//! ["source-private.native5-policy-owned-fresh-restore-allocation/18",
//!  "completed_admit13", ["Query", "Report", "Proof", "Receipt", "PrepareBinding"],
//!  ["FULL previous policy16 or capture-policy17"]]
//! ```
//!
//! The actual observer walks all preceding fields before the five new full
//! references. Neither this descriptor nor its selection recreates the live
//! completed query, startup action, native issuer or restoration authority.

use super::*;
use crate::reference_packet::service::fresh_restore_allocation::{
    PACKET_FRESH_RESTORE_ALLOCATION_FEATURE, PacketNative5FreshRestoreAllocationSelection,
    PacketNativeFreshRestoreAllocationSchema,
};

pub(super) const FRESH_POLICY_FORMAT: &str =
    "source-private.native5-policy-owned-fresh-restore-allocation/18";

pub(super) fn read_selected(
    mut fields: Fields<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    allow_transfer: bool,
) -> Result<Option<HistoricalNativePolicy>, ProviderError> {
    if allow_transfer {
        return Err(invalid());
    }
    let selection = fresh_selection(next(&mut fields)?)?;
    let raw_definitions = next(&mut fields)?;
    let base = next(&mut fields)?;
    fields.finish()?;
    validate_base_header(base)?;

    let mut definitions = Fields::array(raw_definitions)?;
    let mut raw = [&[][..]; 5];
    for reference in &mut raw {
        *reference = next(&mut definitions)?;
    }
    definitions.finish()?;

    // Preserve the real old-first ordinary observer order. Every independent
    // definition String capacity is consumed from its actual recorded row;
    // the selection is a closed inline enum with no child allocation.
    let policy = HistoricalNativePolicy::read_selected(base, ledger, build, false)?;
    let mut owners: [Option<ContentRef>; 5] = std::array::from_fn(|_| None);
    for (owner, input) in owners.iter_mut().zip(raw) {
        *owner = ledger.read::<ContentRef>(input, build)?;
    }
    let Some(mut policy) = policy else {
        return Ok(None);
    };
    if policy.fresh_restore_allocation_selection.is_some()
        || policy.fresh_restore_allocation_definitions.is_some()
        || policy.protocol_metadata_limits.is_none()
        || !matches!(policy.capture_profile, PacketNative5CaptureProfile::OwnedProtocol11 { .. })
        || policy.complete_restore_selection != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || policy.restore_input_emitter_selection != Some(crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
    {
        return Err(invalid());
    }
    let [query, report, proof, receipt, prepare] = owners;
    let definitions = [
        query.ok_or_else(invalid)?,
        report.ok_or_else(invalid)?,
        proof.ok_or_else(invalid)?,
        receipt.ok_or_else(invalid)?,
        prepare.ok_or_else(invalid)?,
    ];
    authenticate_declared_definitions(&policy.selection, &definitions)?;
    policy.fresh_restore_allocation_selection = Some(selection);
    policy.fresh_restore_allocation_definitions = Some(definitions);
    Ok(Some(policy))
}

fn fresh_selection(
    input: &[u8],
) -> Result<PacketNative5FreshRestoreAllocationSelection, ProviderError> {
    match super::super::super::typed::plain_string(input)? {
        "completed_admit13" => Ok(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13),
        _ => Err(invalid()),
    }
}

// Fresh construction always requires the canonical input writer. Optional
// capture17 may wrap that full16 leaf, but cannot substitute an older base or
// nest another Fresh wrapper. This check runs during the allocation-free pass.
fn validate_base_header(base: &[u8]) -> Result<(), ProviderError> {
    let mut fields = Fields::array(base)?;
    match super::super::super::typed::plain_string(next(&mut fields)?)? {
        "source-private.native5-policy-owned-restore-input-emitter/16" => Ok(()),
        capture::CAPTURE_POLICY_FORMAT => {
            if super::super::super::typed::plain_string(next(&mut fields)?)? != "original_observe12"
            {
                return Err(invalid());
            }
            next(&mut fields)?;
            let base = next(&mut fields)?;
            fields.finish()?;
            let mut base = Fields::array(base)?;
            if super::super::super::typed::plain_string(next(&mut base)?)?
                != "source-private.native5-policy-owned-restore-input-emitter/16"
            {
                return Err(invalid());
            }
            Ok(())
        }
        _ => Err(invalid()),
    }
}

// Match full retained declarations without constructing schema DOMs while the
// cold decoder owns its admitted banks. Actual fixed contract generation and
// source-installed validation belong to the separately authenticated installer.
fn authenticate_declared_definitions(
    selection: &PacketControlSelection,
    definitions: &[ContentRef; 5],
) -> Result<(), ProviderError> {
    if !selection
        .provider
        .extensions_supported
        .iter()
        .any(|feature| feature.as_str() == PACKET_FRESH_RESTORE_ALLOCATION_FEATURE)
    {
        return Err(invalid());
    }
    use PacketNativeFreshRestoreAllocationSchema as S;
    for (schema, definition) in [S::Query, S::Report, S::Proof, S::Receipt, S::PrepareBinding]
        .into_iter()
        .zip(definitions)
    {
        let matches = |declared: &crucible_node_format::SchemaRef| {
            declared.id.as_str() == schema.id()
                && declared.version == 13
                && declared.extensions.is_empty()
                && &declared.definition == definition
        };
        if !selection
            .provider
            .implementation
            .formats
            .iter()
            .any(matches)
            || selection.realization.bindings.iter().any(|binding| {
                !binding
                    .compatibility
                    .implementation
                    .formats
                    .iter()
                    .any(matches)
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_policy_selection_matches_actual_contract_and_refuses_other_spellings()
    -> Result<(), Box<dyn std::error::Error>> {
        let selected = PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13;
        let actual = serde_json::to_vec(&selected)?;

        assert_eq!(fresh_selection(&actual)?, selected);
        for input in [
            b"null".as_slice(),
            br#""CompletedAdmit13""#,
            br#""other13""#,
        ] {
            assert!(fresh_selection(input).is_err());
        }
        Ok(())
    }

    #[test]
    fn fresh_policy_base_header_keeps_full_canonical_writer_and_optional_capture() {
        let input16 = br#"["source-private.native5-policy-owned-restore-input-emitter/16"]"#;
        let input17 = br#"["source-private.native5-policy-owned-capture-allocation/17","original_observe12",[],["source-private.native5-policy-owned-restore-input-emitter/16"]]"#;
        // Header acceptance is deliberately not complete policy acceptance;
        // the real reader still consumes every field and all capacity rows.
        assert!(validate_base_header(input16).is_ok());
        assert!(validate_base_header(input17).is_ok());
        for input in [
            br#"["source-private.native5-policy-owned/11"]"#.as_slice(),
            br#"["source-private.native5-policy-owned-selected/13"]"#,
            br#"["source-private.native5-policy-owned-restore-transfer/15"]"#,
            br#"["source-private.native5-policy-owned-fresh-restore-allocation/18"]"#,
            br#"["source-private.native5-policy-owned-capture-allocation/17","original_observe12",[],["source-private.native5-policy-owned-selected/13"]]"#,
        ] {
            assert!(validate_base_header(input).is_err());
        }
    }
}
