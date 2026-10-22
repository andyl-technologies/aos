//! Exercises actual first-request correlation without authenticating its proof.

use super::*;
use std::cell::Cell;

const PREFIX: &str = "initial_policy_kernel_normalizations_host_correlation_";

struct Model<'a> {
    suffix: &'a str,
    retained: [usize; 5],
    calls: Cell<usize>,
}

impl Model<'_> {
    fn census(&self, inputs: Inputs<'_>) {
        assert_eq!(
            [
                inputs.original.retained_requested_bytes().unwrap(),
                inputs
                    .normalizations
                    .retained_requested_bytes_data(inputs.original)
                    .unwrap(),
                inputs
                    .literal
                    .retained_requested_bytes_data(inputs.original)
                    .unwrap(),
                inputs
                    .parsed
                    .retained_requested_bytes_data(inputs.original)
                    .unwrap(),
                inputs
                    .codec
                    .retained_requested_bytes_data(inputs.original)
                    .unwrap(),
            ],
            self.retained
        );
    }

    fn action(&self, inputs: Inputs<'_>, label: &str) -> Result<(), ProviderError> {
        if self.suffix == format!("expire_{label}") {
            std::thread::sleep(Duration::from_secs(5));
        }
        if self.suffix == format!("revoke_{label}") {
            inputs
                .original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        if self.suffix == format!("reject_{label}") {
            return Err(ProviderError::Conflict("SDK correlation admission model"));
        }
        Ok(())
    }
}

impl Admission for Model<'_> {
    fn construct_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        self.census(inputs);
        assert!(inputs.original.bootstrap_correlation_started && attempt.started);
        assert_eq!(attempt.row, Some(row));
        assert!(attempt.guard.is_none());
        assert_eq!(
            attempt
                .retained_requested_bytes_data(inputs.original)
                .unwrap(),
            size_of::<Attempt>()
        );
        self.action(inputs, "construction")
    }

    fn receive_data(&self, inputs: Inputs<'_>, attempt: &Attempt) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(3), 2);
        self.census(inputs);
        let guard = attempt.guard.as_ref().unwrap();
        assert!(guard.incoming_requests().next().is_none());
        assert!(guard.pending_requests().next().is_none());
        self.action(inputs, "receive")
    }

    fn observe_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
        actual: usize,
    ) -> Result<(), ProviderError> {
        self.census(inputs);
        assert_eq!(
            actual,
            attempt
                .retained_requested_bytes_data(inputs.original)
                .unwrap()
        );
        assert!(actual <= attempt.row.unwrap()[0]);
        let guard = attempt.guard.as_ref().unwrap();
        let label = match step {
            Step::Construct => {
                assert_eq!(self.calls.replace(2), 1);
                assert!(guard.incoming_requests().next().is_none());
                "constructed"
            }
            Step::Receive => {
                assert_eq!(self.calls.replace(4), 3);
                let mut incoming = guard.incoming_requests();
                let original = incoming.next().unwrap();
                assert_eq!(
                    original.method,
                    crate::envelope::Method::NativeImport18Bootstrap
                );
                assert_eq!(original.sequence.get(), 2);
                assert!(incoming.next().is_none());
                "received"
            }
        };
        self.action(inputs, label)
    }
}

/// Keeps all actual predecessors and accepted SDK records through every refusal.
pub(in super::super::super) fn assert_child(
    case: &str,
    original: &mut OriginalImport18RawBootstrap,
) {
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let (normalizations, literal, parsed, codec) = if suffix == "missing_codec" {
        let (normalizations, literal, parsed) =
            super::super::bootstrap_value::tests::complete_for_codec(original);
        (normalizations, literal, parsed, Codec::empty_data())
    } else {
        super::super::bootstrap_codec::tests::complete_for_correlation(original)
    };
    let mut attempt = Attempt::empty_data();
    let inputs = Inputs {
        original,
        normalizations: &normalizations,
        literal: &literal,
        parsed: &parsed,
        codec: &codec,
    };
    let model = Model {
        suffix,
        calls: Cell::new(0),
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
            parsed.retained_requested_bytes_data(original).unwrap(),
            codec.retained_requested_bytes_data(original).unwrap(),
        ],
    };
    model.census(inputs);
    let raw = original.bodies.each_ref().map(Vec::as_ptr);
    let launch = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let cut = original.cut;
    if suffix == "changed_cut" {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    let outcome = original.retain_bootstrap_correlation_data(
        &normalizations,
        &literal,
        &parsed,
        &codec,
        &mut attempt,
        &model,
    );
    let success = matches!(
        suffix,
        "complete" | "reactive" | "callback_refused" | "loan_expired"
    );
    assert_eq!(
        outcome.is_ok(),
        success,
        "{case}: {outcome:?}; expired={}",
        original.cut.is_expired()
    );
    assert!(original.bootstrap_correlation_started && attempt.started);
    assert_eq!(attempt.complete, success);
    assert_eq!(attempt.failed, !success);
    let inputs = Inputs {
        original,
        normalizations: &normalizations,
        literal: &literal,
        parsed: &parsed,
        codec: &codec,
    };
    model.census(inputs);
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), raw);
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch
    );
    let calls = match suffix {
        "changed_cut" | "missing_codec" => 0,
        "reject_construction" | "expire_construction" | "revoke_construction" => 1,
        "reject_constructed" | "expire_constructed" | "revoke_constructed" => 2,
        "reject_receive" | "expire_receive" | "revoke_receive" => 3,
        _ => 4,
    };
    assert_eq!(model.calls.get(), calls);
    assert_eq!(attempt.guard.is_some(), calls >= 2);
    if let Some(guard) = &attempt.guard {
        assert_eq!(guard.incoming_requests().count(), usize::from(calls >= 4));
    }
    if success {
        let entered = Cell::new(false);
        let loan = attempt.with_received_data(inputs, |guard, envelope| {
            entered.set(true);
            assert!(std::ptr::eq(
                guard.incoming_requests().next().unwrap(),
                envelope
            ));
            if suffix == "loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            if suffix == "callback_refused" {
                return Err(ProviderError::Conflict("correlation loan model"));
            }
            Ok(())
        });
        assert!(entered.get());
        assert_eq!(loan.is_ok(), matches!(suffix, "complete" | "reactive"));
    } else {
        assert!(
            attempt
                .with_received_data::<()>(inputs, |_, _| panic!("failed correlation loan entered"))
                .is_err()
        );
        if calls == 4 {
            // The actual SDK must retain its accepted original after fencing.
            // This clone is independent fixture inspection, never a grant.
            let guard = attempt.guard.as_mut().unwrap();
            let envelope = guard.incoming_requests().next().unwrap().clone();
            assert!(matches!(
                guard.receive(&envelope),
                Err(ProviderError::Correlation("connection is fenced"))
            ));
            assert!(guard.incoming_requests().next() == Some(&envelope));
        }
    }
    let retained = attempt.retained_requested_bytes_data(original).unwrap();
    let pointer = attempt.guard.as_ref().map(std::ptr::from_ref);
    original.cut = cut;
    assert!(
        original
            .retain_bootstrap_correlation_data(
                &normalizations,
                &literal,
                &parsed,
                &codec,
                &mut attempt,
                &model
            )
            .is_err()
    );
    assert!(
        original
            .retain_bootstrap_correlation_data(
                &normalizations,
                &literal,
                &parsed,
                &codec,
                &mut Attempt::empty_data(),
                &model
            )
            .is_err()
    );
    assert_eq!(model.calls.get(), calls);
    assert_eq!(
        attempt.retained_requested_bytes_data(original).unwrap(),
        retained
    );
    assert_eq!(attempt.guard.as_ref().map(std::ptr::from_ref), pointer);
}

#[test]
fn correlation_quote_uses_actual_closed_guard_tree_layout_and_exact_peak() {
    use crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM;
    use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
    };
    use crate::reference_packet::service::complete_restore::import18::hello::native_import18_hello_declaration_data;
    use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures;
    use crucible_node_format::{Bytes, Id};
    use std::collections::BTreeSet;

    let selected: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(inert_bootstrap_fixtures::initial_selected_launch(false)).unwrap();
    let row = construction_data(selected.launch_data(), usize::MAX).unwrap();
    let peak = row.into_iter().sum::<usize>();
    assert_eq!(
        construction_data(selected.launch_data(), peak).unwrap(),
        row
    );
    assert!(construction_data(selected.launch_data(), peak - 1).is_err());
    assert_eq!(
        construction_data(selected.launch_data(), peak + 4096).unwrap(),
        row
    );
    let declaration = native_import18_hello_declaration_data(selected.launch_data()).unwrap();
    let keys: BTreeSet<String> = declaration
        .keys_data()
        .iter()
        .flatten()
        .map(|(key, _)| key.to_string())
        .collect();
    let id = "a".repeat(crucible_node_format::values::MAX_ID_BYTES);
    let value = serde_json::json!({
        "protocol":"CNP/1", "message":"request", "method":"native_import18_bootstrap",
        "session_id":id, "incarnation_id":id, "node_id":id, "execution_owner_id":id,
        "capture_owner_id":id, "request_id":id, "operation_id":id, "sequence":"2",
        "body":{"schema":NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,"recipe_identity":Bytes::new(vec![0;32]),"initial_funding":{
            "retained_requested_bytes":u64::MAX.to_string(),"maximum_simultaneous_transient_bytes":u64::MAX.to_string(),"declared_counter_scratch_bytes":u64::MAX.to_string()}},
        "extensions":{(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF):{"schema":NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF,"algorithm":PACKET_COMPLETE_RESTORE_ALGORITHM,"context_digest":Bytes::new(vec![0;32]),"mac":Bytes::new(vec![0;32])}},
    });
    let envelope: Envelope = serde_json::from_value(value).unwrap();
    let mut attempt = Attempt::empty_data();
    attempt.guard = Some(
        CorrelationGuard::new(Id::new(&id).unwrap(), Id::new(&id).unwrap(), 64, keys).unwrap(),
    );
    attempt.guard.as_mut().unwrap().receive(&envelope).unwrap();
    assert!(attempt.requested_storage_data().unwrap() <= row[0]);
    assert!(
        Attempt::received_loan_counter_scratch_data::<[u8; 4096]>().unwrap()
            >= Attempt::received_loan_counter_scratch_data::<()>().unwrap() + 4096
    );
}

/// Completes original correlation without opening an additional full SDK loan.
pub(in super::super::super) fn complete_for_proof(
    original: &mut OriginalImport18RawBootstrap,
    reserve: bool,
) -> (Normalizations, Literal, Parsed, Codec, Attempt) {
    let (normalizations, literal, parsed, codec) =
        super::super::bootstrap_codec::tests::complete_for_correlation(original);
    let mut attempt = Attempt::empty_data();
    let model = Model {
        suffix: "complete",
        calls: Cell::new(0),
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
            parsed.retained_requested_bytes_data(original).unwrap(),
            codec.retained_requested_bytes_data(original).unwrap(),
        ],
    };
    if reserve {
        original
            .retain_bootstrap_correlation_data(
                &normalizations,
                &literal,
                &parsed,
                &codec,
                &mut attempt,
                &model,
            )
            .unwrap();
    }
    assert_eq!(model.calls.get(), if reserve { 4 } else { 0 });
    (normalizations, literal, parsed, codec, attempt)
}

/// Inspects the actual SDK fence while retaining its accepted request record.
pub(in super::super::super) fn assert_fenced_record(attempt: &mut Attempt) {
    let guard = attempt.guard.as_mut().unwrap();
    let original = guard.incoming_requests().next().unwrap().clone();
    assert!(matches!(
        guard.receive(&original),
        Err(ProviderError::Correlation("connection is fenced"))
    ));
    assert_eq!(guard.incoming_requests().count(), 1);
    assert_eq!(guard.incoming_requests().next(), Some(&original));
}
