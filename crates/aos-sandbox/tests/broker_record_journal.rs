//! Checks journal framing for the authenticated online Nix broker record widths.

use aos_sandbox::journal::encoded_transaction_append_bytes;
use aos_sandbox::{JournalRecord, JournalTransaction};
use aos_sandbox_core::RecordNamespace;

#[test]
fn online_nix_transaction_width_preserves_authenticated_payload_sizes() {
    // Broker encoder tests independently pin these maximum fence/pending widths.
    // Journal framing remains downstream and treats authenticated values as opaque.
    let transaction = JournalTransaction::new(
        [85; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                vec![86; 1],
                vec![87; 16],
            ),
            JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                vec![81; 24],
                vec![0; 741],
            ),
            JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                vec![82; 24],
                vec![0; 617],
            ),
        ],
    )
    .unwrap();

    // Three payloads plus BEGIN4/COMMIT36 and five HEADER72 frames.
    assert_eq!(
        encoded_transaction_append_bytes(&transaction).unwrap(),
        (7 + 1 + 16) + (7 + 24 + 741) + (7 + 24 + 617) + 400,
    );
}
