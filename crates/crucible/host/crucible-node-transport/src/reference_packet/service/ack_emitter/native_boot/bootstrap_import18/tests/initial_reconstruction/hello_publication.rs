//! Exercises canonical publication under actual inherited bootstrap/socket custody.
//!
//! Admission callbacks are model controls, not genuine Source/Birth grants. The
//! real SDK lease and actual socket owners remain in the original bootstrap.

use super::super::super::hello_publication::OriginalImport18HelloPublicationAdmission;
use super::*;
use std::cell::Cell;

/// Gives the refusal control a request-sized limit below its complete response.
pub(super) fn prepare_selected(case: &str, selected: &mut Value) {
    if case == "initial_hello_publication_small_frame" {
        let provider =
            canonical::canonical_json(&selected["launch"]["selection"]["provider"]).unwrap();
        selected["launch"]["limits"]["frame_bytes"] = json!(provider.len().to_string());
    }
}

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloPublicationAdmission for Admission<'_> {
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(scratch > 0);
        assert!(original.hello_publication.row_fixture_data().is_none());
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        original
            .with_hello_authority_data(|lease| lease.ensure_live())
            .unwrap();
        if self.case == "initial_hello_publication_quote_refused" {
            return Err(ProviderError::Conflict("publication quote refused"));
        }
        if self.case == "initial_hello_publication_quote_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert_eq!(original.hello_publication.row_fixture_data(), Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_publication_construct_refused" {
            return Err(ProviderError::Conflict("publication construction refused"));
        }
        if self.case == "initial_hello_publication_construct_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(3), 2);
        assert_eq!(
            original.hello_publication_backing_data().unwrap(),
            actual_backing
        );
        assert!(actual_backing <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual_backing
        );
        if self.case == "initial_hello_publication_finish_refused" {
            return Err(ProviderError::Conflict("publication census refused"));
        }
        if self.case == "initial_hello_publication_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

fn publishes(case: &str) -> bool {
    matches!(
        case,
        "initial_hello_publication_complete"
            | "initial_hello_publication_reactive"
            | "initial_hello_publication_unsorted_versions"
            | "initial_hello_publication_optional_feature"
            | "initial_hello_publication_larger_limits"
            | "initial_hello_publication_finish_refused"
            | "initial_hello_publication_finish_expired"
            | "initial_hello_publication_callback_refused"
            | "initial_hello_publication_loan_expired"
            | "initial_hello_publication_substituted_cut"
    )
}

pub(super) fn assert_parent_bytes(case: &str, bytes: &[u8]) {
    if !publishes(case) {
        assert!(bytes.is_empty(), "{case}: unexpected publication");
        return;
    }
    assert!(bytes.len() > 4, "{case}: response frame absent");
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(
        bytes.len(),
        length + 4,
        "{case}: not exactly one original response"
    );
    let value = canonical::parse_json(&bytes[4..], 1024 * 1024).unwrap();
    assert_eq!(canonical::canonical_json(&value).unwrap(), bytes[4..]);
    let envelope: crate::envelope::Envelope = serde_json::from_value(value).unwrap();
    envelope.validate().unwrap();
    assert_eq!(envelope.message, crate::envelope::MessageKind::Response);
    assert_eq!(envelope.method, crate::envelope::Method::Hello);
    assert_eq!(envelope.sequence.get(), 1);
    assert_eq!(envelope.request_id.0.unwrap().as_str(), "hello/initial");
    assert_eq!(envelope.body["status"], "completed");
    let result: crate::handshake::HelloResult =
        serde_json::from_value(envelope.body["result"].clone()).unwrap();
    assert_eq!(result.provider_nonce.as_slice().len(), 32);
    assert_eq!(result.controller_nonce.as_slice(), &[19; 32]);
    assert!(result.resumed_operations.is_empty());
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case == "initial_hello_publication_without_admission" {
        super::hello_response::construct_for_verifier(owner);
    } else {
        super::hello_admission::construct_for_publication(owner);
    }
    let before = owner.retained_requested_bytes().unwrap();
    let authority = owner
        .hello_registrar
        .retained_authority_fixture_data()
        .map(std::ptr::from_ref);
    let response = owner
        .hello_response
        .envelope_fixture_data()
        .map(std::ptr::from_ref);
    let expected = owner
        .with_hello_response_data(|response| {
            Ok(
                canonical::canonical_json(&serde_json::to_value(response).unwrap())
                    .unwrap()
                    .len(),
            )
        })
        .unwrap();
    if case == "initial_hello_publication_small_frame" {
        assert!(
            expected
                > owner
                    .typed_bodies_data()
                    .unwrap()
                    .launch
                    .launch_data()
                    .limits
                    .frame_bytes
                    .get() as usize
        );
    }
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        row: Cell::new(None),
    };

    let outcome = owner.publish_hello_response_data(&admission);

    let success = publishes(case)
        && !matches!(
            case,
            "initial_hello_publication_finish_refused" | "initial_hello_publication_finish_expired"
        );
    if success {
        outcome.unwrap();
        assert_eq!(admission.calls.get(), 3);
        assert_eq!(
            owner
                .with_published_hello_body_data(|body| Ok(body.len()))
                .unwrap(),
            expected
        );
        owner
            .with_hello_authority_data(|lease| lease.ensure_live())
            .unwrap();
        if case == "initial_hello_publication_callback_refused" {
            assert!(
                owner
                    .with_published_hello_body_data::<()>(|_| Err(ProviderError::Conflict(
                        "inspection refused"
                    )))
                    .is_err()
            );
            assert_eq!(
                owner
                    .with_published_hello_body_data(|body| Ok(body.len()))
                    .unwrap(),
                expected
            );
        }
        if case == "initial_hello_publication_substituted_cut" {
            let original = owner.cut;
            owner.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
            assert!(owner.with_published_hello_body_data(|_| Ok(())).is_err());
            owner.cut = original;
            assert_eq!(
                owner
                    .with_published_hello_body_data(|body| Ok(body.len()))
                    .unwrap(),
                expected
            );
        }
        if case == "initial_hello_publication_loan_expired" {
            assert!(
                owner
                    .with_published_hello_body_data(|_| {
                        std::thread::sleep(Duration::from_secs(5));
                        Ok(())
                    })
                    .is_err()
            );
            assert!(owner.with_published_hello_body_data(|_| Ok(())).is_err());
        }
    } else {
        assert!(outcome.is_err(), "{case}");
        assert!(owner.with_published_hello_body_data(|_| Ok(())).is_err());
        assert!(owner.with_hello_authority_data(|_| Ok(())).is_err());
        if let Some(lease) = owner.hello_registrar.retained_authority_fixture_data() {
            assert!(lease.ensure_live().is_err());
        }
    }
    let calls = admission.calls.get();
    assert!(owner.publish_hello_response_data(&admission).is_err());
    assert_eq!(admission.calls.get(), calls);
    assert_eq!(
        owner
            .hello_registrar
            .retained_authority_fixture_data()
            .map(std::ptr::from_ref),
        authority
    );
    assert_eq!(
        owner
            .hello_response
            .envelope_fixture_data()
            .map(std::ptr::from_ref),
        response
    );
    assert!(owner.retained_requested_bytes().is_ok());
}

#[test]
fn original_response_publication_keeps_same_lease_socket_and_terminal_custody() {
    for case in [
        "initial_hello_publication_complete",
        "initial_hello_publication_reactive",
        "initial_hello_publication_unsorted_versions",
        "initial_hello_publication_optional_feature",
        "initial_hello_publication_larger_limits",
        "initial_hello_publication_without_admission",
        "initial_hello_publication_quote_refused",
        "initial_hello_publication_quote_expired",
        "initial_hello_publication_construct_refused",
        "initial_hello_publication_construct_expired",
        "initial_hello_publication_finish_refused",
        "initial_hello_publication_finish_expired",
        "initial_hello_publication_broken_pipe",
        "initial_hello_publication_small_frame",
        "initial_hello_publication_callback_refused",
        "initial_hello_publication_substituted_cut",
        "initial_hello_publication_loan_expired",
    ] {
        flight(case);
    }
}
