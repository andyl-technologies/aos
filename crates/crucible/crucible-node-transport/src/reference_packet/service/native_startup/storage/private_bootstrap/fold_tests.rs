//! Compares the actual shared private calculation with the complete old body.

use super::super::fold_original;
use super::*;
use crate::reference_packet::service::ack_emitter::native_boot::original_native_startup_attempt_transient_data;

fn outcome(value: Result<PrivateBootstrapStorage, ProviderError>) -> Result<[usize; 6], String> {
    value
        .map(|data| {
            [
                data.retained,
                data.transient,
                data.maximum_boot_bytes,
                data.maximum_source_bytes,
                data.source_requested_bytes,
                data.source_value_backing_bytes,
            ]
        })
        .map_err(|error| format!("{error:?};{error}"))
}

// Keep the complete saved schedule and all old terms, then add only the
// newly retained attempt's defining transient headers.
fn original_with_attempt_headers(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
    source_project: fn(&[u8], usize) -> Result<source_binding::SourceBindingStorage, ProviderError>,
    preflight: bool,
) -> Result<PrivateBootstrapStorage, ProviderError> {
    let mut data = fold_original::project_with_source(input, maximum, source_project, preflight)?;
    data.transient = sum(
        &[
            data.transient,
            original_native_startup_attempt_transient_data(),
        ],
        maximum,
    )?;
    Ok(data)
}

fn source(invocation: bool) -> Vec<u8> {
    let mut value = json!({
        "selection":null,"program":null,"coordinator":null,"limits":null,
        "storage":null,"capture_profile":null,"confirmation_selection":null,
        "ack_emitter_selection":null,"codec_metadata_extent":null
    });
    if invocation {
        value["schema"] = json!("source-owned.packet-canonical-ack-source-binding/15");
        for key in [
            "native_codec_metadata_extent",
            "protocol_metadata_limits",
            "complete_restore_selection",
            "restore_input_emitter_selection",
            "capture_allocation_selection",
            "fresh_restore_allocation_selection",
            "report_startup_allocation",
            "native_startup_allocation",
            "invocation",
        ] {
            value[key] = serde_json::Value::Null;
        }
    }
    // This is a raw geometry fixture, not an authenticated Source bank.
    value.to_string().into_bytes()
}

#[test]
fn shared_private_fold_preserves_complete_original_rows_and_first_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let launch = launch()?;
    let private = crucible_node_format::Id::new("original-private-fold")?;
    let encoded = crucible_node_format::canonical::canonical_json(&serde_json::to_value(&launch)?)?;

    for (invocation, preflight) in [(false, false), (true, false), (false, true)] {
        let source = source(invocation);
        let input = PacketNativeBirthStartupInputs {
            launch: &launch,
            private_launch: &private,
            encoded_launch: &encoded,
            source_birth: &source,
            host_registration: b"{}",
        };
        let source_project = if invocation {
            source_binding::project_invocation
        } else {
            source_binding::project
        };
        let original = outcome(original_with_attempt_headers(
            &input,
            usize::MAX,
            source_project,
            preflight,
        ));
        let actual = outcome(project_with_source(
            &input,
            usize::MAX,
            source_project,
            preflight,
        ));
        assert_eq!(actual, original);
        assert!(actual.is_ok(), "raw geometry setup failed: {actual:?}");

        for maximum in [0, 1, 256, 65_536, 2_097_152] {
            assert_eq!(
                outcome(project_with_source(
                    &input,
                    maximum,
                    source_project,
                    preflight
                )),
                outcome(original_with_attempt_headers(
                    &input,
                    maximum,
                    source_project,
                    preflight
                )),
            );
        }
    }
    Ok(())
}

#[test]
fn shared_private_fold_keeps_malformed_source_and_registration_refusals()
-> Result<(), Box<dyn std::error::Error>> {
    let launch = launch()?;
    let private = crucible_node_format::Id::new("original-private-fold-refusal")?;
    let encoded = crucible_node_format::canonical::canonical_json(&serde_json::to_value(&launch)?)?;
    let source = source(false);

    for (source, registration) in [
        (b"{".as_slice(), b"{}".as_slice()),
        (source.as_slice(), b"{".as_slice()),
    ] {
        let input = PacketNativeBirthStartupInputs {
            launch: &launch,
            private_launch: &private,
            encoded_launch: &encoded,
            source_birth: source,
            host_registration: registration,
        };
        let actual = outcome(project_with_source(
            &input,
            usize::MAX,
            source_binding::project,
            false,
        ));
        let original = outcome(original_with_attempt_headers(
            &input,
            usize::MAX,
            source_binding::project,
            false,
        ));
        assert!(actual.is_err());
        assert_eq!(actual, original);
    }
    Ok(())
}
