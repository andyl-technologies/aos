//! Checks original body retention and finite admission without native authority.
#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These journal controls deliberately panic on invalid fixtures or failed retained-byte invariants.
#![allow(clippy::unwrap_used)]

use super::*;

fn request() -> Envelope {
    let mut request = crate::envelope::tests::request();
    request.method = crate::envelope::Method::Hello;
    request
}

#[test]
fn original_response_bytes_survive_failed_envelope_interpretation() {
    let request = request();
    let mut journal = OriginalHelloJournal::reserve(&request, 2048, 16).unwrap();
    journal.begin(&request, 2048, 16).unwrap();
    let response = b" { \"not_an_envelope\" : [1, 2] } ";
    let stream = [
        u32::try_from(response.len())
            .unwrap()
            .to_be_bytes()
            .as_slice(),
        response.as_slice(),
    ]
    .concat();
    let mut reader =
        crate::transport::FrameReader::with_limits(std::io::Cursor::new(stream), 2048, 16).unwrap();

    let frame = reader.read_retained().unwrap().unwrap();
    let capacity = journal.response.capacity();
    journal.retain_response(&frame.bytes).unwrap();

    assert_eq!(journal.response(), Some(response.as_slice()));
    assert_eq!(journal.response.capacity(), capacity);
    assert!(Envelope::decode(journal.response().unwrap(), 2048).is_err());
    assert!(journal.retain_response(&frame.bytes).is_err());
}

#[test]
fn whole_request_credit_refuses_before_retention_and_exact_limit_accepts() {
    let request = request();
    let extent = serde_json::to_vec(&request).unwrap().len();

    assert!(OriginalHelloJournal::reserve(&request, extent - 1, 16).is_err());
    let journal = OriginalHelloJournal::reserve(&request, extent, 16).unwrap();

    assert_eq!(journal.request(), &request);
    assert!(!journal.attempted());
    assert!(journal.response().is_none());
    assert!(OriginalHelloJournal::reserve(&request, MAXIMUM_BYTES + 1, 16).is_err());
}

#[test]
fn original_attempt_refuses_changed_request_or_limits_and_cannot_begin_again() {
    let request = request();
    let mut journal = OriginalHelloJournal::reserve(&request, 2048, 16).unwrap();
    let mut changed = request.clone();
    changed.sequence = crucible_node_contract::U64::new(2);

    assert!(journal.begin(&changed, 2048, 16).is_err());
    assert!(journal.begin(&request, 2048, 15).is_err());
    assert!(!journal.attempted());
    journal.begin(&request, 2048, 16).unwrap();

    assert!(journal.attempted());
    assert!(journal.begin(&request, 2048, 16).is_err());
    assert!(journal.retain_response(&vec![b' '; 2049]).is_err());
    assert!(journal.response().is_none());
}
