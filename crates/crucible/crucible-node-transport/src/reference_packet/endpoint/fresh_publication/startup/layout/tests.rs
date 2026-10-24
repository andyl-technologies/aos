//! Checks actual Fresh layout facts and the independent old quoter.

use super::super::*;
use super::{counter_scratch_data, original};
use crucible_node_format::Bytes;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

type TestResult = Result<(), TestError>;

fn geometry_launch() -> Result<PacketNative5SourceLaunch, serde_json::Error> {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // Only the existing geometry APIs consume this immutable DTO. Empty events
    // are not a valid native launch or evidence of Source, ACK or Fresh admission.
    serde_json::from_value(json!({
        "schema_version": 5,
        "selection": selection,
        "program": {
            "kind": "producer",
            "program": {"schema": "source-owned.packet-program.v1", "events": []}
        },
        "controller_pid": "1",
        "controller_uid": "0",
        "controller_executable": coordinator.reference,
        "admission_token": Bytes::new(vec![7; 32]),
        "initial_coordinator": coordinator,
        "limits": {
            "frame_bytes": "65536",
            "nesting": "64",
            "requests": "256",
            "journal_entries": "1024",
            "blob_chunk_bytes": "4096"
        },
        "storage": {
            "snapshot_bytes": "16384",
            "control_snapshot_bytes": "8192",
            "protocol_snapshot_bytes": "65536",
            "frame_bank_bytes": "65536",
            "frames_per_direction": "256",
            "hello_bytes": "131080",
            "settlement_bytes": "65536"
        },
        "effects": "/not-opened-by-fresh-layout-controls"
    }))
}

#[test]
fn supplied_fresh_headers_are_the_actual_upper_types_and_queries() {
    let fixed = layout::project();
    assert_eq!(fixed.received_frame_bytes, size_of::<ReceivedFrame>());
    assert_eq!(fixed.request_body_bytes, size_of::<RequestBody>());
    assert_eq!(fixed.observe_result_bytes, size_of::<ObserveResult>());
    assert_eq!(
        fixed.control_reply_bytes,
        size_of::<crate::reference_packet::control::PacketControlReply>()
    );
    assert_eq!(fixed.content_slot_bytes, size_of::<(ContentRef, Vec<u8>)>());
    assert_eq!(
        layout::owner_bytes_data(),
        crate::reference_packet::endpoint::fresh_restore::original_fresh_report_owner_layout_data()
    );
    assert_eq!(
        layout::counter_output_data(),
        original_fresh_report_startup_publication_counter_scratch_data()
    );
}

#[test]
fn fresh_quote_keeps_original_retained_components_and_prices_only_new_headers() -> TestResult {
    let launch = geometry_launch()?;
    let maximum = 512 * 1024 * 1024;
    let old = original::quote(&launch, maximum)?;
    let actual = original_fresh_report_startup_publication_data(&launch, maximum)?;
    let extra = sum(&[counter_scratch_data(), size_of::<usize>()])?;

    assert_eq!(actual.retained_growth_bytes, old.retained_growth_bytes);
    assert_eq!(
        actual.declared_counter_scratch_bytes,
        sum(&[old.declared_counter_scratch_bytes, extra])?
    );
    // The new counter is in the encoding phase. The unchanged earlier receive
    // may dominate both; max(receive, encoding + extra) stays in this interval.
    assert!(
        actual.maximum_simultaneous_transient_bytes >= old.maximum_simultaneous_transient_bytes
    );
    assert!(
        actual.maximum_simultaneous_transient_bytes
            <= sum(&[old.maximum_simultaneous_transient_bytes, extra])?
    );
    assert_eq!(
        layout::counter_output_data(),
        sum(&[original::counter_scratch_data(), extra])?
    );
    Ok(())
}

#[test]
fn fresh_quote_accepts_its_exact_demand_and_refuses_one_short_and_bad_original_inputs() -> TestResult
{
    let mut launch = geometry_launch()?;
    let maximum = 512 * 1024 * 1024;
    let actual = original_fresh_report_startup_publication_data(&launch, maximum)?;
    let exact = sum(&[
        actual.retained_growth_bytes,
        actual.maximum_simultaneous_transient_bytes,
        actual.declared_counter_scratch_bytes,
    ])?;
    let admitted = original_fresh_report_startup_publication_data(&launch, exact)?;
    assert_eq!(admitted.retained_growth_bytes, actual.retained_growth_bytes);
    assert_eq!(
        admitted.maximum_simultaneous_transient_bytes,
        actual.maximum_simultaneous_transient_bytes
    );
    assert_eq!(
        admitted.declared_counter_scratch_bytes,
        actual.declared_counter_scratch_bytes
    );
    assert!(original_fresh_report_startup_publication_data(&launch, exact - 1).is_err());

    for bound in [0, 1] {
        assert!(original::quote(&launch, bound).is_err());
        assert_eq!(
            original::quote(&launch, bound)
                .err()
                .map(|error| error.to_string()),
            original_fresh_report_startup_publication_data(&launch, bound)
                .err()
                .map(|error| error.to_string())
        );
    }
    launch.limits.frame_bytes = U64::new(0);
    assert!(original::quote(&launch, maximum).is_err());
    assert_eq!(
        original::quote(&launch, maximum)
            .err()
            .map(|error| error.to_string()),
        original_fresh_report_startup_publication_data(&launch, maximum)
            .err()
            .map(|error| error.to_string())
    );
    Ok(())
}
