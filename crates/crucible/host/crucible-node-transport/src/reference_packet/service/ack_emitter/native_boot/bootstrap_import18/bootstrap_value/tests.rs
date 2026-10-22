//! Exercises strict bootstrap DATA without treating fixture callbacks as funding.

use super::*;
use crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM;
use std::cell::Cell;
use std::io::Write;

const PREFIX: &str = "initial_policy_kernel_normalizations_host_value_";

fn request_bytes(suffix: &str) -> Vec<u8> {
    use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
    };
    let digest = "A".repeat(43);
    let mut value = serde_json::json!({
        "protocol": "CNP/1", "message": "request", "session_id": "session",
        "incarnation_id": "incarnation", "node_id": null, "execution_owner_id": null,
        "capture_owner_id": null, "request_id": "bootstrap", "operation_id": null,
        "sequence": "2", "method": "native_import18_bootstrap",
        "body": {"schema": NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
            "recipe_identity": digest, "initial_funding": {
                "retained_requested_bytes": "1", "maximum_simultaneous_transient_bytes": "1",
                "declared_counter_scratch_bytes": "1"}},
        "extensions": {(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF): {
            "schema": NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, "algorithm": PACKET_COMPLETE_RESTORE_ALGORITHM,
            "context_digest": digest, "mac": digest}},
    });
    if suffix == "maximal_escaped" {
        for field in [
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
        ] {
            value[field] = Value::String("a".repeat(crucible_node_format::values::MAX_ID_BYTES));
        }
        value["sequence"] = Value::String(u64::MAX.to_string());
        for field in [
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ] {
            value["body"]["initial_funding"][field] = Value::String(u64::MAX.to_string());
        }
    }
    let body = serde_json::to_vec(&value).unwrap();
    match suffix {
        "invalid_utf8" => b"{\"body\":\"\xff\"}".to_vec(),
        "duplicate" => b"{\"body\":{},\"body\":{}}".to_vec(),
        "malformed" => b"{\"body\":tru}".to_vec(),
        "profile_refused" => serde_json::to_vec(&vec![0; 4096]).unwrap(),
        "escaped" | "maximal_escaped" => {
            let mut escaped = Vec::new();
            for byte in body {
                // Escape every A inside the three digest strings. This tests
                // the lexical spelling bound without changing parsed DATA.
                if byte == b'A' || (suffix == "maximal_escaped" && byte.is_ascii_alphanumeric()) {
                    write!(escaped, "\\u{:04x}", byte).unwrap();
                } else {
                    escaped.push(byte);
                }
            }
            escaped
        }
        "whitespace" => {
            let mut padded = vec![b' '; 32768];
            padded.extend_from_slice(&body);
            padded
        }
        _ => body,
    }
}

/// Queues immutable parser input independently of the native consumer.
pub(in super::super::super) fn write_parent_frame(case: &str, peer: &mut UnixStream) {
    let body = request_bytes(case.strip_prefix(PREFIX).unwrap());
    peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(&body).unwrap();
    peer.write_all(b"unconsumed suffix").unwrap();
}

struct Model<'a> {
    suffix: &'a str,
    retained: [usize; 3],
    calls: Cell<usize>,
}

impl Model<'_> {
    fn census(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
    ) {
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.retained[0]
        );
        assert_eq!(
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            self.retained[1]
        );
        assert_eq!(
            literal.retained_requested_bytes_data(original).unwrap(),
            self.retained[2]
        );
    }
}

impl Admission for Model<'_> {
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        attempt: &Attempt,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        self.census(original, normalizations, literal);
        assert!(original.bootstrap_value_started && attempt.started);
        assert!(attempt.row.is_none());
        assert_eq!(
            attempt.retained_requested_bytes_data(original).unwrap(),
            size_of::<Attempt>()
        );
        assert_eq!(scratch, counter_scratch_data().unwrap());
        if self.suffix == "reject_quote" {
            return Err(ProviderError::Conflict("parser quote model"));
        }
        if self.suffix == "expire_quote" {
            std::thread::sleep(Duration::from_secs(5));
        }
        if self.suffix == "revoke_quote" {
            original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        Ok(())
    }

    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        self.census(original, normalizations, literal);
        assert_eq!(attempt.row, Some(row));
        assert_eq!(
            attempt.retained_requested_bytes_data(original).unwrap(),
            size_of::<Attempt>()
        );
        assert!(attempt.value.value_fixture_data().is_none());
        let maximum = construction_data(
            original.typed_bodies_data().unwrap().launch.launch_data(),
            original.bounds.requested_peak,
        )
        .unwrap();
        assert!(
            row.into_iter()
                .zip(maximum)
                .all(|(actual, bound)| actual <= bound)
        );
        if self.suffix == "reject_construction" {
            return Err(ProviderError::Conflict("parser construction model"));
        }
        if self.suffix == "expire_construction" {
            std::thread::sleep(Duration::from_secs(5));
        }
        if self.suffix == "revoke_construction" {
            original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        attempt: &Attempt,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(3), 2);
        self.census(original, normalizations, literal);
        assert_eq!(
            actual,
            attempt.retained_requested_bytes_data(original).unwrap()
        );
        assert!(actual <= attempt.row.unwrap()[0]);
        if self.suffix == "expire_finish" {
            std::thread::sleep(Duration::from_secs(5));
        }
        if self.suffix == "revoke_finish" {
            original
                .hello_registrar
                .retained_authority_fixture_data()
                .unwrap()
                .revoke_epoch_fixture_data();
        }
        if self.suffix == "reject_finish" {
            return Err(ProviderError::Conflict("parser finish model"));
        }
        Ok(())
    }
}

/// Preserves the full original plus raw and parsed external owners on failure.
pub(in super::super::super) fn assert_child(
    case: &str,
    original: &mut OriginalImport18RawBootstrap,
) {
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let (normalizations, literal) = if suffix == "missing_literal" {
        (
            super::super::bootstrap_normalizations::tests::complete_for_host(original),
            Literal::empty_data(),
        )
    } else {
        super::super::bootstrap_literal::tests::complete_for_value(original)
    };
    let mut attempt = Attempt::empty_data();
    let model = Model {
        suffix,
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
        ],
        calls: Cell::new(0),
    };
    let cut = original.cut;
    if suffix == "changed_cut" {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    let raw = original.bodies.each_ref().map(Vec::as_ptr);
    let launch = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let outcome =
        original.decode_bootstrap_value_data(&normalizations, &literal, &mut attempt, &model);
    let success = matches!(
        suffix,
        "complete" | "reactive" | "escaped" | "whitespace" | "callback_refused" | "loan_expired"
    );
    assert_eq!(
        outcome.is_ok(),
        success,
        "{case}: {outcome:?}; expired={}",
        original.cut.is_expired()
    );
    assert!(original.bootstrap_value_started && attempt.started);
    assert_eq!(attempt.complete, success);
    assert_eq!(attempt.failed, !success);
    model.census(original, &normalizations, &literal);
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), raw);
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch
    );
    let calls = match suffix {
        "changed_cut" | "missing_literal" => 0,
        "reject_quote" | "profile_refused" | "expire_quote" | "revoke_quote" => 1,
        "reject_construction" | "expire_construction" | "revoke_construction" => 2,
        _ => 3,
    };
    assert_eq!(model.calls.get(), calls);
    if success {
        let entered = Cell::new(false);
        let outcome = attempt.with_value_data(original, &normalizations, &literal, |value| {
            entered.set(true);
            assert_eq!(
                value,
                &serde_json::from_slice::<Value>(&request_bytes("complete")).unwrap()
            );
            if suffix == "callback_refused" {
                return Err(ProviderError::Conflict("parsed loan model"));
            }
            if suffix == "loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            Ok(())
        });
        assert!(
            entered.get(),
            "{case}: {outcome:?}; expired={}",
            original.cut.is_expired()
        );
        assert_eq!(
            outcome.is_ok(),
            !matches!(suffix, "callback_refused" | "loan_expired"),
            "{case}: {outcome:?}; expired={}",
            original.cut.is_expired()
        );
        if suffix == "callback_refused" {
            attempt
                .with_value_data(original, &normalizations, &literal, |_| Ok(()))
                .unwrap();
        }
    } else {
        assert!(
            attempt
                .with_value_data(original, &normalizations, &literal, |_| Ok(()))
                .is_err()
        );
    }
    if matches!(suffix, "reject_finish" | "expire_finish" | "revoke_finish") {
        assert!(attempt.value.value_fixture_data().is_some());
    }
    if matches!(
        suffix,
        "reject_quote"
            | "expire_quote"
            | "revoke_quote"
            | "reject_construction"
            | "expire_construction"
            | "revoke_construction"
    ) {
        assert!(attempt.value.value_fixture_data().is_none());
        assert_eq!(
            attempt.retained_requested_bytes_data(original).unwrap(),
            size_of::<Attempt>()
        );
    }
    let retained = attempt.retained_requested_bytes_data(original).unwrap();
    let value = attempt.value.value_fixture_data().map(std::ptr::from_ref);
    original.cut = cut;
    assert!(
        original
            .decode_bootstrap_value_data(&normalizations, &literal, &mut attempt, &model)
            .is_err()
    );
    assert!(
        original
            .decode_bootstrap_value_data(
                &normalizations,
                &literal,
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
    assert_eq!(
        attempt.value.value_fixture_data().map(std::ptr::from_ref),
        value
    );
}

#[test]
fn closed_parser_bound_covers_escaped_input_without_charging_whitespace_as_nodes() {
    use crate::reference_packet::service::complete_restore::import18::{
        PacketNativeImport18SelectedLaunchWireData, inert_bootstrap_fixtures,
    };
    let selected: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(inert_bootstrap_fixtures::initial_selected_launch(false)).unwrap();
    let launch = selected.launch_data();
    let bound = construction_data(launch, usize::MAX).unwrap();
    let peak = bound.into_iter().sum::<usize>();
    assert_eq!(construction_data(launch, peak).unwrap(), bound);
    assert!(construction_data(launch, peak - 1).is_err());
    assert_eq!(construction_data(launch, peak + 4096).unwrap(), bound);
    for suffix in [
        "complete",
        "escaped",
        "maximal_escaped",
        "whitespace",
        "duplicate",
        "invalid_utf8",
        "malformed",
    ] {
        let raw = request_bytes(suffix);
        if matches!(
            suffix,
            "complete" | "escaped" | "maximal_escaped" | "whitespace"
        ) {
            crucible_node_format::canonical::parse_json_with_depth(&raw, raw.len(), 64).unwrap();
        }
        let (parser, _) = storage::actual_data(&raw, usize::MAX).unwrap();
        assert!(
            parser_row_data(parser)
                .unwrap()
                .into_iter()
                .zip(bound)
                .all(|(actual, maximum)| actual <= maximum),
            "{suffix}"
        );
    }
    assert!(
        Attempt::value_loan_counter_scratch_data::<[u8; 4096]>().unwrap()
            >= Attempt::value_loan_counter_scratch_data::<()>().unwrap() + 4096
    );
}

#[test]
fn retained_schedule_counts_failed_normalization_or_complete_literal_and_parser() {
    let proof = [
        size_of::<super::super::bootstrap_proof::Attempt>() + 1000,
        1,
        1,
    ];
    let correlation = [
        size_of::<super::super::bootstrap_correlation::Attempt>() + 1000,
        1,
        1,
    ];
    let normalizations = [size_of::<Normalizations>() + 1_000_000, 1, 1];
    let literal = [size_of::<Literal>() + 65540, 1, 1];
    let value = [size_of::<Attempt>() + 10000, 1, 1];
    let codec = [
        size_of::<super::super::bootstrap_codec::Attempt>() + 1000,
        1,
        1,
    ];
    assert_eq!(
        retained_schedule_data(normalizations, literal, value, codec, correlation, proof).unwrap(),
        normalizations[0]
            + size_of::<Literal>()
            + size_of::<Attempt>()
            + size_of::<super::super::bootstrap_codec::Attempt>()
            + size_of::<super::super::bootstrap_correlation::Attempt>()
            + size_of::<super::super::bootstrap_proof::Attempt>()
    );
    let value = [size_of::<Attempt>() + 2_000_000, 1, 1];
    assert_eq!(
        retained_schedule_data(normalizations, literal, value, codec, correlation, proof).unwrap(),
        size_of::<Normalizations>() + literal[0] + value[0] + codec[0] + correlation[0] + proof[0]
    );
    assert!(
        retained_schedule_data([usize::MAX; 3], literal, value, codec, correlation, proof).is_err()
    );
    assert!(
        retained_schedule_data(
            normalizations,
            [usize::MAX; 3],
            value,
            codec,
            correlation,
            proof
        )
        .is_err()
    );
    assert!(
        retained_schedule_data(
            normalizations,
            literal,
            [usize::MAX; 3],
            codec,
            correlation,
            proof
        )
        .is_err()
    );
}

/// Completes strict DATA without spending another full original loan.
pub(in super::super::super) fn complete_for_codec(
    original: &mut OriginalImport18RawBootstrap,
) -> (Normalizations, Literal, Attempt) {
    let (normalizations, literal) =
        super::super::bootstrap_literal::tests::complete_for_value(original);
    let mut attempt = Attempt::empty_data();
    let model = Model {
        suffix: "complete",
        retained: [
            original.retained_requested_bytes().unwrap(),
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            literal.retained_requested_bytes_data(original).unwrap(),
        ],
        calls: Cell::new(0),
    };
    original
        .decode_bootstrap_value_data(&normalizations, &literal, &mut attempt, &model)
        .unwrap();
    assert_eq!(model.calls.get(), 3);
    (normalizations, literal, attempt)
}

#[test]
fn retained_schedule_refuses_typed_codec_overflow() {
    assert!(
        retained_schedule_data([1; 3], [1; 3], [1; 3], [usize::MAX; 3], [1; 3], [1; 3]).is_err()
    );
}

#[test]
fn retained_schedule_refuses_sdk_correlation_overflow() {
    assert!(
        retained_schedule_data([1; 3], [1; 3], [1; 3], [1; 3], [usize::MAX; 3], [1; 3]).is_err()
    );
}

#[test]
fn retained_schedule_refuses_original_proof_overflow() {
    assert!(
        retained_schedule_data([1; 3], [1; 3], [1; 3], [1; 3], [1; 3], [usize::MAX; 3]).is_err()
    );
}
