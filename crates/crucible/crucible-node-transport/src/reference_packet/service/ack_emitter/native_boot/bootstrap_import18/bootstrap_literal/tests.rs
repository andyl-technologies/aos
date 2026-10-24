//! Exercises raw post-Hello custody without manufacturing an assigned request.

use super::*;
use std::cell::Cell;
use std::io::{Cursor, Write};

const BODY: &[u8] = b"\xff{deliberately unparsed bootstrap DATA";
const PREFIX: &str = "initial_policy_kernel_normalizations_host_frame_";

/// Queues one next frame, preserving a deliberate suffix or half-close.
pub(in super::super::super) fn write_parent_frame(case: &str, peer: &mut UnixStream) {
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let length = match suffix {
        "zero" => 0,
        "oversized" => u32::MAX,
        "partial_body" | "timeout" => 128,
        _ => BODY.len() as u32,
    };
    let header = length.to_be_bytes();
    if suffix == "partial_header" {
        peer.write_all(&header[..2]).unwrap();
    } else {
        peer.write_all(&header).unwrap();
        peer.write_all(BODY).unwrap();
        if !matches!(suffix, "partial_body" | "timeout") {
            peer.write_all(b"unconsumed suffix").unwrap();
        }
    }
    if matches!(suffix, "partial_header" | "partial_body") {
        peer.shutdown(std::net::Shutdown::Write).unwrap();
    }
}

struct Model<'a> {
    suffix: &'a str,
    original: usize,
    normalizations: usize,
    calls: Cell<usize>,
}

impl Admission for Model<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(original.bootstrap_literal_started && attempt.started);
        assert_eq!(attempt.row, Some(row));
        assert_eq!(attempt.received, 0);
        assert!(attempt.bank.is_empty() && attempt.digest.is_none());
        assert_eq!(original.retained_requested_bytes().unwrap(), self.original);
        assert_eq!(
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            self.normalizations
        );
        assert_eq!(
            attempt.retained_requested_bytes_data(original).unwrap(),
            size_of::<Attempt>()
        );
        if self.suffix == "reject_construction" {
            return Err(ProviderError::Conflict("literal admission model"));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        attempt: &Attempt,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.original);
        assert_eq!(
            normalizations
                .retained_requested_bytes_data(original)
                .unwrap(),
            self.normalizations
        );
        assert_eq!(
            actual,
            attempt.retained_requested_bytes_data(original).unwrap()
        );
        assert_eq!(actual, attempt.row.unwrap()[0]);
        assert!(attempt.received <= attempt.bank.len());
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
            return Err(ProviderError::Conflict("literal census model"));
        }
        Ok(())
    }
}

/// Checks both actual owners and the unchanged original receiver on either outcome.
pub(in super::super::super) fn assert_child(
    case: &str,
    original: &mut OriginalImport18RawBootstrap,
) {
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let normalizations = if suffix == "missing_normalizations" {
        Normalizations::empty_data()
    } else {
        super::super::bootstrap_normalizations::tests::complete_for_host(original)
    };
    let mut attempt = Attempt::empty_data();
    assert!(
        attempt
            .with_body_data(original, &normalizations, |_| Ok(()))
            .is_err()
    );
    let raw = original.bodies.each_ref().map(Vec::as_ptr);
    let launch = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let model = Model {
        suffix,
        original: original.retained_requested_bytes().unwrap(),
        normalizations: normalizations
            .retained_requested_bytes_data(original)
            .unwrap(),
        calls: Cell::new(0),
    };
    let cut = original.cut;
    if suffix == "changed_cut" {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    let outcome = original.receive_bootstrap_literal_data(&normalizations, &mut attempt, &model);
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
    assert!(original.bootstrap_literal_started && attempt.started);
    assert_eq!(attempt.complete, success);
    assert_eq!(attempt.failed, !success);
    assert_eq!(original.retained_requested_bytes().unwrap(), model.original);
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), raw);
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch
    );
    let expected_calls = match suffix {
        "missing_normalizations" | "changed_cut" => 0,
        "reject_construction" => 1,
        _ => 2,
    };
    assert_eq!(model.calls.get(), expected_calls);
    if success {
        let entered = Cell::new(false);
        let result = attempt.with_body_data(original, &normalizations, |body| {
            entered.set(true);
            assert_eq!(body, BODY);
            if suffix == "callback_refused" {
                return Err(ProviderError::Conflict("literal callback model"));
            }
            if suffix == "loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            Ok(())
        });
        assert!(entered.get());
        assert_eq!(result.is_ok(), matches!(suffix, "complete" | "reactive"));
        if suffix == "callback_refused" {
            attempt
                .with_body_data(original, &normalizations, |_| Ok(()))
                .unwrap();
        }
    } else {
        assert!(
            attempt
                .with_body_data(original, &normalizations, |_| Ok(()))
                .is_err()
        );
        if suffix == "partial_header" {
            assert_eq!(attempt.received, 2);
        }
        if matches!(suffix, "partial_body" | "timeout") {
            assert_eq!(attempt.received, BODY.len() + 4);
            assert_eq!(&attempt.bank[4..attempt.received], BODY);
            assert!(attempt.digest.is_none());
        }
        if matches!(suffix, "zero" | "oversized") {
            assert_eq!(attempt.received, 4);
            assert_eq!(attempt.bank.len(), 4);
        }
    }
    let retained = attempt.retained_requested_bytes_data(original).unwrap();
    let received = attempt.received;
    let bank = attempt.bank.as_ptr();
    let calls = model.calls.get();
    original.cut = cut;
    assert!(
        original
            .receive_bootstrap_literal_data(&normalizations, &mut attempt, &model)
            .is_err()
    );
    assert!(
        original
            .receive_bootstrap_literal_data(&normalizations, &mut Attempt::empty_data(), &model)
            .is_err()
    );
    assert_eq!(model.calls.get(), calls);
    assert_eq!(
        attempt.retained_requested_bytes_data(original).unwrap(),
        retained
    );
    assert_eq!(attempt.bank.as_ptr(), bank);
    assert_eq!(attempt.received, received);
}

/// Completes the original raw receiver for a separately admitted parser fixture.
pub(in super::super::super) fn complete_for_value(
    original: &mut OriginalImport18RawBootstrap,
) -> (Normalizations, Attempt) {
    let normalizations = super::super::bootstrap_normalizations::tests::complete_for_host(original);
    let mut attempt = Attempt::empty_data();
    let model = Model {
        suffix: "complete",
        original: original.retained_requested_bytes().unwrap(),
        normalizations: normalizations
            .retained_requested_bytes_data(original)
            .unwrap(),
        calls: Cell::new(0),
    };
    original
        .receive_bootstrap_literal_data(&normalizations, &mut attempt, &model)
        .unwrap();
    assert_eq!(model.calls.get(), 2);
    (normalizations, attempt)
}

#[test]
fn literal_reader_preserves_prefixes_and_leaves_the_next_frame_unread() {
    for body in [b"x".as_slice(), BODY] {
        let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(body);
        let end = bytes.len();
        bytes.extend_from_slice(b"suffix");
        let mut stream = Cursor::new(bytes);
        let mut attempt = Attempt::empty_data();
        attempt.read(&mut stream, body.len()).unwrap();
        assert_eq!(stream.position(), end as u64);
        assert_eq!(&attempt.bank[4..], body);
        assert_eq!(attempt.received, end);
        assert_eq!(
            attempt.digest,
            Some(*blake3::hash(&attempt.bank).as_bytes())
        );
        assert_eq!(attempt.bank.capacity(), end);
    }
}

#[test]
fn literal_construction_prices_the_negotiated_full_bank_before_reading() {
    use crate::reference_packet::service::complete_restore::import18::{
        PacketNativeImport18SelectedLaunchWireData, inert_bootstrap_fixtures,
    };
    let launch: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(inert_bootstrap_fixtures::initial_selected_launch(false)).unwrap();
    let launch = launch.launch_data();
    let row = construction_data(launch, usize::MAX).unwrap();
    assert_eq!(
        row[0],
        size_of::<Attempt>() + maximum_data(launch).unwrap() + 4
    );
    let peak = row.into_iter().sum::<usize>();
    assert_eq!(construction_data(launch, peak).unwrap(), row);
    assert!(construction_data(launch, peak - 1).is_err());
    assert_eq!(construction_data(launch, peak + 4096).unwrap(), row);
    assert!(row[1] > 0 && row[2] > 0);
    assert!(
        Attempt::body_loan_counter_scratch_data::<[u8; 4096]>().unwrap()
            >= Attempt::body_loan_counter_scratch_data::<()>().unwrap() + 4096
    );
}
