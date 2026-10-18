//! Native byte conditions keep logical origin and node-wide byte order.

use super::*;

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error(transparent)]
    Origin(#[from] crate::NativeConsoleOriginError),
    #[error(transparent)]
    Readiness(#[from] ReadyPointResolutionError),
}

fn event(sequence: u64, byte: u8) -> Result<ObservableEvent, crate::NativeConsoleOriginError> {
    ObservableEvent::native_console_byte(
        VirtualTime { ticks: 100 },
        NodeId {
            name: "guest".into(),
        },
        crate::NativeConsoleByteOrigin {
            device: ContentHash { bytes: [9; 32] },
            stream: 7,
            logical_generation: 3,
            node_sequence: sequence,
            stream_sequence: sequence,
            emitted_ps: 50,
            raw_prefix: 1,
            vcpu: 0,
            byte,
        },
    )
}

#[test]
fn native_console_ready_marker_uses_sequence_not_equal_time_byte_sort() -> Result<(), FixtureError>
{
    let observations = vec![event(2, b'A')?, event(1, b'Z')?];
    let guest = NodeId {
        name: "guest".into(),
    };
    let at = resolve_console_marker_ready_point(
        &guest,
        "ZA",
        VirtualTime { ticks: 100 },
        &observations,
    )?;
    assert_eq!(at.ticks, 100);
    assert!(
        resolve_console_marker_ready_point(&guest, "AZ", VirtualTime { ticks: 100 }, &observations)
            .is_err()
    );
    assert!(
        resolve_console_marker_ready_point(
            &NodeId {
                name: "foreign".into()
            },
            "ZA",
            VirtualTime { ticks: 100 },
            &observations
        )
        .is_err()
    );
    assert!(
        resolve_console_marker_ready_point(&guest, "ZA", VirtualTime { ticks: 99 }, &observations)
            .is_err()
    );
    Ok(())
}

#[test]
fn native_console_event_keeps_explicit_evaluation_time_without_poll_restamp()
-> Result<(), FixtureError> {
    let original = event(1, 0xff)?;
    let normalized = original
        .clone()
        .normalize_backend_poll_boundary(VirtualTime { ticks: 200 });
    assert_eq!(normalized, original);
    assert_eq!(
        normalized.console_bytes().map(|(_, bytes)| bytes),
        Some([0xff].as_slice())
    );
    let ObservableEventPayload::NativeConsoleByte { origin, .. } = normalized.payload() else {
        panic!("missing native origin");
    };
    assert_eq!(origin.emitted_ps, 50);
    assert_eq!(origin.raw_prefix, 1);
    assert_eq!(normalized.at().ticks, 100);
    Ok(())
}
