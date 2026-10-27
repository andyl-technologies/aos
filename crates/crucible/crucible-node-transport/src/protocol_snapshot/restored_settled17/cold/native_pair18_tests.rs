//! Exercises real retained native decoder prefixes and once-only refusal.

use super::*;
use crate::protocol_snapshot::{compact_bytes::BorrowedCompactBytes, native_wholegraph17};
use crucible_node_format::canonical;
use std::cell::Cell;

fn roles_with_partial_before() -> [(ContentRef, Vec<u8>); 5] {
    let mut roles = super::super::tests::roles();
    let mut roots = vec![serde_json::Value::Null; 16];
    roots[0] = serde_json::json!(native_wholegraph17::CURRENT_GRAPH17_FORMAT);
    // These banks have a real closed wire shape but deliberately invalid roots.
    // The owning reader must retain its allocations before semantic refusal.
    let before = canonical::canonical_json(&serde_json::json!([
        native_wholegraph17::CURRENT_PROTOCOL17_FORMAT,
        roots,
        [["string", 0, 1, 1]],
        [null]
    ]))
    .unwrap();
    let reference = canonical::content_ref(&before, "application/json").unwrap();
    let mut snapshot: serde_json::Value = serde_json::from_slice(&roles[0].1).unwrap();
    snapshot["protocol"] = serde_json::json!([
        "source-private.native-before-protocol/17",
        reference,
        before.capacity(),
        BorrowedCompactBytes::new(&before)
    ]);
    roles[0].1 = canonical::canonical_json(&snapshot).unwrap();
    roles[0].0 = canonical::content_ref(&roles[0].1, "application/json").unwrap();

    let mut journal: serde_json::Value = serde_json::from_slice(&roles[4].1).unwrap();
    journal["objects"]["before"] = serde_json::json!(reference);
    journal["objects"]["snapshot"] = serde_json::json!(roles[0].0);
    roles[4].1 = canonical::canonical_json(&journal).unwrap();
    roles[4].0 = canonical::content_ref(&roles[4].1, "application/json").unwrap();
    roles
}

struct Admission {
    stop: usize,
    calls: Cell<usize>,
}

impl Admission {
    fn step(&self) -> Result<(), ProviderError> {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        if call == self.stop {
            Err(invalid())
        } else {
            Ok(())
        }
    }
}

impl NativeCold17Admission for Admission {
    fn begin_data(&self, row: NativeCold17PrewalkData) -> Result<(), ProviderError> {
        assert!(matches!(
            row.work_data(),
            NativeCold17Work::RawInputs
                | NativeCold17Work::BeforeGraphBanks
                | NativeCold17Work::BeforeGraphTargets
        ));
        assert_eq!(row.quote_transient_bytes_data(), 0);
        self.step()
    }

    fn construct_data(&self, row: NativeCold17ConstructionData) -> Result<(), ProviderError> {
        assert!(matches!(
            row.work_data(),
            NativeCold17Work::RawInputs | NativeCold17Work::BeforeGraphBanks
        ));
        assert!(row.maximum_new_retained_bytes_data() > 0);
        assert_eq!(row.constructor_transient_bytes_data(), 0);
        self.step()
    }

    fn finish_data(&self, work: NativeCold17Work, actual: usize) -> Result<(), ProviderError> {
        assert!(matches!(
            work,
            NativeCold17Work::RawInputs | NativeCold17Work::BeforeGraphBanks
        ));
        assert!(actual > 0);
        self.step()
    }
}

#[test]
fn native18_local_graphs_retain_actual_banks_at_every_reached_refusal() {
    let roles = roles_with_partial_before();
    let input = super::super::tests::input(&roles);
    // The owning graph header has its own substantial typed layout. Framing's
    // small fixture ceiling does not fund that actual decoder allocation.
    let limits = RestoredSettledNative17Limits::new(
        std::array::from_fn(|index| roles[index].1.len()),
        1,
        1,
        1,
        4096,
        1_048_576,
    )
    .unwrap();
    let plan = RestoredSettledNative17Plan::validate_data(&input, &limits).unwrap();

    for stop in 1..=8 {
        let admission = Admission {
            stop,
            calls: Cell::new(0),
        };
        let mut destination = None;
        let attempt =
            RestoredSettledNative18GraphAttempt::begin_into_data(&mut destination).unwrap();
        let outcome = attempt.read_framed_with_admission_data(&plan, 1_048_576, &admission);
        assert!(outcome.is_err());
        assert!(attempt.finish_original_guards_data(outcome).is_err());
        assert!(!attempt.graphs_decoded_data());
        assert_eq!(admission.calls.get(), stop.min(7));

        let retained = attempt.retained_requested_storage_data(1_048_576).unwrap();
        if stop <= 2 {
            assert!(attempt.decoded.is_none());
            assert_eq!(retained, 0);
        } else {
            let decoded = attempt.decoded.as_ref().unwrap();
            assert!(!decoded.is_validated_data());
            for (index, (_, body)) in roles.iter().enumerate() {
                assert_eq!(&decoded.raw[index], body);
            }
            assert!(!decoded.before_encoded.is_empty());
            assert!(decoded.native_graph.as_ref().is_none());
            let before = decoded.before_native_graph.as_ref();
            assert_eq!(before.is_some(), stop >= 6);
            if let Some(before) = before {
                assert!(before.completed_data().is_none());
                assert!(before.retained_requested_storage_data(1_048_576).unwrap() > 0);
            }
        }

        // Occupied destinations and spent read attempts cannot reparse, erase
        // failed banks or reset an earlier admission refusal.
        assert!(
            attempt
                .read_framed_with_admission_data(&plan, 1_048_576, &admission)
                .is_err()
        );
        assert!(attempt.finish_original_guards_data(Ok(())).is_err());
        assert_eq!(
            attempt.retained_requested_storage_data(1_048_576).unwrap(),
            retained
        );
        assert!(RestoredSettledNative18GraphAttempt::begin_into_data(&mut destination).is_err());
        assert_eq!(admission.calls.get(), stop.min(7));
    }
}

#[test]
fn native18_local_graphs_original_guard_refusal_spends_empty_attempt() {
    let mut destination = None;
    let attempt = RestoredSettledNative18GraphAttempt::begin_into_data(&mut destination).unwrap();
    assert!(attempt.finish_original_guards_data(Err(invalid())).is_err());
    assert!(!attempt.graphs_decoded_data());
    assert_eq!(attempt.retained_requested_storage_data(0).unwrap(), 0);
    assert!(RestoredSettledNative18GraphAttempt::begin_into_data(&mut destination).is_err());
}
