//! Exercises SDK lease custody with model callbacks, without native qualification.

use super::*;
use crate::envelope::Nullable;
use crate::handshake::{
    EXTENSION_NEGOTIATION_V1, ExtensionOfferV1, ExtensionSelectionV1, ResumedOperation,
    TrustedInstallation,
};
use crate::reference_packet::service::complete_restore::import18::hello::{
    NATIVE_IMPORT18_CONNECTION_ID, native_import18_hello_declaration_data,
};
use crucible_node_format::{
    Bytes, ContentRef, ContractError, Extensions, IdSet, ProviderManifest, SchemaRef, U64,
};
use serde_json::json;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    Authentication,
    IoRaw,
    IoKind,
    IoOwned,
    Contract,
    Expire,
}

#[derive(Debug)]
struct OwnedDiagnostic {
    reason: String,
}

impl std::fmt::Display for OwnedDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for OwnedDiagnostic {}

struct ModelVerifier {
    fault: Fault,
    authenticated: usize,
    contracts: usize,
}

impl ModelVerifier {
    fn new(fault: Fault) -> Self {
        Self {
            fault,
            authenticated: 0,
            contracts: 0,
        }
    }
}

impl TrustedHandshakeVerifier for ModelVerifier {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        _: &TrustedInstallation,
        _: &HelloRequest,
        _: &HelloResult,
    ) -> Result<(), ProviderError> {
        self.authenticated += 1;
        match self.fault {
            Fault::Authentication => {
                return Err(ProviderError::Correlation("model authentication refused"));
            }
            Fault::IoRaw => return Err(std::io::Error::from_raw_os_error(13).into()),
            Fault::IoKind => {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into());
            }
            Fault::IoOwned => {
                let mut reason = String::with_capacity(8192);
                reason.push_str("retained model I/O diagnostic");
                return Err(std::io::Error::other(OwnedDiagnostic { reason }).into());
            }
            _ => {}
        }
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        _: &ProviderManifest,
        _: &IdSet,
        _: &[SchemaRef],
        _: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.contracts += 1;
        if self.fault == Fault::Contract {
            let mut reason = String::with_capacity(8192);
            reason.push_str("retained model contract refusal");
            return Err(ProviderError::Contract(ContractError::Invalid {
                field: "fixture",
                reason,
            }));
        }
        if self.fault == Fault::Expire {
            std::thread::sleep(Duration::from_millis(1100));
        }
        Ok(())
    }

    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        _: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        panic!("initial admission must not resume")
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        panic!("initial admission must not fence an earlier connection")
    }
}

struct Fixture {
    attempt: Attempt,
    cut: OperationalDeadline,
    hello: HelloRequest,
    result: HelloResult,
    request: Envelope,
    response: Envelope,
}

impl Fixture {
    fn new(reactive: bool) -> Self {
        let (launch, _, _) = super::super::super::tests::configuration_data(reactive);
        let declaration = native_import18_hello_declaration_data(&launch).unwrap();
        let mut selection = None;
        declaration
            .retain_selection_into_data(&mut selection)
            .unwrap();
        let selection = selection.unwrap();
        let binding = &launch.selection.realization.bindings[0];
        let hello = HelloRequest {
            versions: vec!["CNP/1".into()],
            session_id: binding.authority.session_id.clone(),
            controller_nonce: Bytes::new(vec![3; 32]),
            required_features: selection.0.clone(),
            optional_features: Vec::new(),
            limits: launch.limits,
            admission_token: launch.admission_token.clone(),
            resume_session: None,
            extensions: Extensions::new(),
        };
        let result = HelloResult {
            version: "CNP/1".into(),
            session_id: binding.authority.session_id.clone(),
            incarnation_id: binding.authority.incarnation_id.clone(),
            controller_nonce: hello.controller_nonce.clone(),
            provider_nonce: Bytes::new(vec![5; 32]),
            selected_features: selection.0.clone(),
            limits: launch.limits,
            resume_token: Nullable(None),
            provider_identity: launch.selection.provider.clone(),
            resumed_operations: Vec::new(),
        };
        let mut request: Envelope = serde_json::from_value(json!({
            "protocol": "CNP/1", "message": "request", "method": "hello",
            "session_id": null, "incarnation_id": null, "node_id": null,
            "execution_owner_id": null, "capture_owner_id": null,
            "operation_id": null, "request_id": "original-hello/1", "sequence": "1",
            "body": &hello, "extensions": {}
        }))
        .unwrap();
        let mut response: Envelope = serde_json::from_value(json!({
            "protocol": "CNP/1", "message": "response", "method": "hello",
            "session_id": null, "incarnation_id": &result.incarnation_id, "node_id": null,
            "execution_owner_id": null, "capture_owner_id": null,
            "operation_id": null, "request_id": "original-hello/1", "sequence": "1",
            "body": {"status": "completed", "operation_state": "completed", "result": &result, "extensions": {}},
            "extensions": {}
        })).unwrap();
        request.extensions.insert(
            EXTENSION_NEGOTIATION_V1.into(),
            serde_json::to_value(ExtensionOfferV1 {
                format: U64::new(1),
                required: Vec::new(),
                optional: Vec::new(),
            })
            .unwrap(),
        );
        response.extensions.insert(
            EXTENSION_NEGOTIATION_V1.into(),
            serde_json::to_value(ExtensionSelectionV1 {
                format: U64::new(1),
                selected: Vec::new(),
            })
            .unwrap(),
        );
        let cut = OperationalDeadline::after(Duration::from_secs(1)).unwrap();
        let row = super::super::super::construction_data(&launch, 268_435_456).unwrap();
        let mut attempt = Attempt::empty_data();
        attempt.start_data(cut).unwrap();
        attempt.quote_data(row).unwrap();
        attempt.construct_data(&launch, &selection, cut).unwrap();
        attempt.complete_data().unwrap();
        Self {
            attempt,
            cut,
            hello,
            result,
            request,
            response,
        }
    }

    fn admit(&mut self, verifier: &mut ModelVerifier) -> Result<(), ProviderError> {
        self.attempt.admit_initial_data(
            &self.request,
            &self.response,
            &self.hello,
            &self.result,
            Id::new(NATIVE_IMPORT18_CONNECTION_ID).unwrap(),
            verifier,
            self.cut,
        )
    }
}

#[test]
fn original_sdk_lease_is_retained_once_without_replacing_the_fresh_wrapper() {
    for reactive in [false, true] {
        let mut fixture = Fixture::new(reactive);
        let wrapper = std::ptr::from_ref(fixture.attempt.wrapper.as_ref().unwrap());
        let before = fixture.attempt.retained_backing_data().unwrap();
        let mut verifier = ModelVerifier::new(Fault::None);

        fixture.admit(&mut verifier).unwrap();

        assert_eq!(verifier.authenticated, 1);
        assert_eq!(verifier.contracts, 1);
        assert_eq!(
            std::ptr::from_ref(fixture.attempt.wrapper.as_ref().unwrap()),
            wrapper
        );
        assert!(fixture.attempt.data(fixture.cut).is_err());
        assert!(fixture.attempt.state_data(fixture.cut).is_ok());
        assert!(
            fixture
                .attempt
                .authority_data(fixture.cut)
                .unwrap()
                .ensure_live()
                .is_ok()
        );
        assert!(fixture.attempt.retained_backing_data().unwrap() > before);
        assert!(fixture.admit(&mut verifier).is_err());
        assert_eq!(verifier.authenticated, 1);
        assert_eq!(verifier.contracts, 1);
    }
}

#[test]
fn sdk_refusal_keeps_its_actual_diagnostic_and_spends_the_original_attempt() {
    for fault in [Fault::Authentication, Fault::Contract] {
        let mut fixture = Fixture::new(false);
        let before = fixture.attempt.retained_backing_data().unwrap();
        let mut verifier = ModelVerifier::new(fault);

        assert!(fixture.admit(&mut verifier).is_err());

        assert!(fixture.attempt.authority.is_none());
        assert!(fixture.attempt.admission_failure.is_some());
        assert!(fixture.attempt.state_data(fixture.cut).is_err());
        assert!(fixture.attempt.data(fixture.cut).is_err());
        let after = fixture.attempt.retained_backing_data().unwrap();
        if fault == Fault::Contract {
            assert!(after >= before + 8192);
        }
        let calls = (verifier.authenticated, verifier.contracts);
        assert!(fixture.admit(&mut verifier).is_err());
        assert_eq!((verifier.authenticated, verifier.contracts), calls);
        assert_eq!(fixture.attempt.retained_backing_data().unwrap(), after);
    }
}

#[test]
fn expiry_after_sdk_success_contains_and_keeps_the_actual_selected_lease() {
    let mut fixture = Fixture::new(false);
    let mut verifier = ModelVerifier::new(Fault::Expire);

    assert!(fixture.admit(&mut verifier).is_err());

    assert!(fixture.cut.is_expired());
    assert_eq!(verifier.contracts, 1);
    assert!(
        fixture
            .attempt
            .authority
            .as_ref()
            .unwrap()
            .ensure_live()
            .is_err()
    );
    assert!(fixture.attempt.admission_failure.is_some());
    assert!(fixture.attempt.authority_data(fixture.cut).is_err());
    assert!(fixture.attempt.retained_backing_data().unwrap() > 0);
    assert!(fixture.admit(&mut verifier).is_err());
    assert_eq!(verifier.contracts, 1);
}

#[test]
fn later_terminal_refusal_revokes_the_retained_lease_without_reclaiming_it() {
    let mut fixture = Fixture::new(false);
    fixture.admit(&mut ModelVerifier::new(Fault::None)).unwrap();
    let authority = std::ptr::from_ref(fixture.attempt.authority.as_ref().unwrap());
    let before = fixture.attempt.retained_backing_data().unwrap();

    fixture.attempt.contain_admission_data().unwrap();

    assert_eq!(
        std::ptr::from_ref(fixture.attempt.authority.as_ref().unwrap()),
        authority
    );
    assert!(
        fixture
            .attempt
            .authority
            .as_ref()
            .unwrap()
            .ensure_live()
            .is_err()
    );
    assert!(fixture.attempt.state_data(fixture.cut).is_err());
    assert_eq!(fixture.attempt.retained_backing_data().unwrap(), before);
}

#[test]
fn incomplete_original_construction_and_resume_claims_refuse_before_sdk_callbacks() {
    for incomplete in [false, true] {
        let mut fixture = Fixture::new(false);
        if incomplete {
            fixture.attempt.stage = Stage::Wrapped;
        } else {
            fixture.result.resume_token = Nullable(Some(Bytes::new(vec![9; 32])));
        }
        let mut verifier = ModelVerifier::new(Fault::None);

        assert!(fixture.admit(&mut verifier).is_err());

        assert_eq!(verifier.authenticated, 0);
        assert_eq!(verifier.contracts, 0);
        assert!(fixture.attempt.authority.is_none());
        assert!(fixture.attempt.admission_failure.is_some());
        assert!(fixture.attempt.retained_backing_data().is_ok());
        assert!(fixture.admit(&mut verifier).is_err());
    }
}

#[test]
fn changed_original_envelope_bodies_refuse_before_trusted_sdk_callbacks() {
    for change_response in [false, true] {
        let mut fixture = Fixture::new(false);
        if change_response {
            fixture.response.body.get_mut("result").unwrap()["session_id"] = json!("foreign");
        } else {
            fixture
                .request
                .body
                .insert("session_id".into(), json!("foreign"));
        }
        let mut verifier = ModelVerifier::new(Fault::None);

        assert!(fixture.admit(&mut verifier).is_err());

        assert_eq!(verifier.authenticated, 0);
        assert_eq!(verifier.contracts, 0);
        assert!(fixture.attempt.authority.is_none());
        assert!(fixture.attempt.admission_failure.is_some());
        assert!(fixture.attempt.retained_backing_data().is_ok());
        assert!(fixture.admit(&mut verifier).is_err());
    }
}

#[test]
fn independent_source_retained_projection_covers_real_initial_sdk_census_growth() {
    for reactive in [false, true] {
        for spare_capacity in [false, true] {
            let (launch, _, _) = super::super::super::tests::configuration_data(reactive);
            let projected = super::super::super::initial_admission_backing::retained_backing_data(
                &launch,
                268_435_456,
            )
            .unwrap();
            let mut fixture = Fixture::new(reactive);
            let spelling = "r".repeat(crucible_node_format::MAX_ID_BYTES);
            let mut original =
                String::with_capacity(if spare_capacity { 8192 } else { spelling.len() });
            original.push_str(&spelling);
            fixture.request.request_id = Nullable(Some(Id::new(original).unwrap()));
            fixture.response.request_id = Nullable(Some(Id::new(spelling).unwrap()));
            if spare_capacity {
                fixture.result.selected_features.reserve(8192);
            }
            let before = fixture.attempt.retained_backing_data().unwrap();
            let mut verifier = ModelVerifier::new(Fault::None);

            fixture.admit(&mut verifier).unwrap();

            let after = fixture.attempt.retained_backing_data().unwrap();
            let additional = after.checked_sub(before).unwrap();
            assert!(additional > 0);
            assert!(
                additional <= projected,
                "actual={additional}, projected={projected}"
            );
            assert!(
                super::super::super::initial_admission_backing::retained_backing_data(
                    &launch,
                    projected - 1
                )
                .is_err()
            );
            assert!(
                super::super::super::initial_admission_backing::retained_backing_data(&launch, 0)
                    .is_err()
            );

            fixture.attempt.contain_admission_data().unwrap();
            assert_eq!(fixture.attempt.retained_backing_data().unwrap(), after);
        }
    }
}

#[test]
fn sdk_io_refusal_keeps_actual_diagnostics_and_counts_only_proven_nonowning_representations() {
    for fault in [Fault::IoRaw, Fault::IoKind, Fault::IoOwned] {
        let mut fixture = Fixture::new(false);
        let before = fixture.attempt.retained_backing_data().unwrap();
        let wrapper = std::ptr::from_ref(fixture.attempt.wrapper.as_ref().unwrap());
        let mut verifier = ModelVerifier::new(fault);

        assert!(fixture.admit(&mut verifier).is_err());

        assert_eq!(verifier.authenticated, 1);
        assert_eq!(verifier.contracts, 0);
        assert!(fixture.attempt.authority.is_none());
        assert!(fixture.attempt.authority_data(fixture.cut).is_err());
        assert!(fixture.attempt.state_data(fixture.cut).is_err());
        assert_eq!(
            std::ptr::from_ref(fixture.attempt.wrapper.as_ref().unwrap()),
            wrapper
        );
        let ProviderError::Io(error) = fixture.attempt.admission_failure.as_ref().unwrap() else {
            panic!("actual SDK I/O failure must stay in its original slot");
        };
        if fault == Fault::IoOwned {
            let diagnostic = error
                .get_ref()
                .unwrap()
                .downcast_ref::<OwnedDiagnostic>()
                .unwrap();
            let original = diagnostic.reason.as_ptr();
            assert_eq!(diagnostic.reason.capacity(), 8192);
            assert!(fixture.attempt.retained_backing_data().is_err());
            let ProviderError::Io(error) = fixture.attempt.admission_failure.as_ref().unwrap()
            else {
                unreachable!();
            };
            let retained = error
                .get_ref()
                .unwrap()
                .downcast_ref::<OwnedDiagnostic>()
                .unwrap();
            assert_eq!(retained.reason.as_ptr(), original);
            assert_eq!(retained.reason.capacity(), 8192);
        } else {
            assert!(error.get_ref().is_none());
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert_eq!(error.raw_os_error(), (fault == Fault::IoRaw).then_some(13));
            assert_eq!(fixture.attempt.retained_backing_data().unwrap(), before);
        }

        assert!(fixture.admit(&mut verifier).is_err());
        assert_eq!(verifier.authenticated, 1);
        assert_eq!(verifier.contracts, 0);
        assert!(fixture.attempt.admission_failure.is_some());
    }
}

#[test]
fn original_sdk_preserves_unsorted_version_advertisements_and_duplicate_refusal() {
    for reactive in [false, true] {
        for duplicate in [false, true] {
            let mut fixture = Fixture::new(reactive);
            // This population exercises internal splits and parent propagation
            // in the real temporary validation tree, in descending wire order.
            fixture.hello.versions = (0..1024)
                .rev()
                .map(|index| format!("future/{index}"))
                .chain(std::iter::once("CNP/1".to_owned()))
                .collect();
            if duplicate {
                fixture.hello.versions.push("future/511".to_owned());
            }
            fixture.request.body = serde_json::to_value(&fixture.hello)
                .unwrap()
                .as_object()
                .unwrap()
                .clone();
            let mut verifier = ModelVerifier::new(Fault::None);
            let original_versions = fixture.hello.versions.clone();
            let components = super::super::super::initial_admission_controls::data().unwrap();
            assert!(components.into_iter().all(|axis| axis > 0));
            assert!(fixture.attempt.authority.is_none());
            assert!(!fixture.attempt.admission_started);

            let outcome = fixture.admit(&mut verifier);

            assert_eq!(fixture.hello.versions, original_versions);
            if duplicate {
                assert!(outcome.is_err());
                assert_eq!((verifier.authenticated, verifier.contracts), (0, 0));
                assert!(fixture.attempt.authority.is_none());
                let Some(ProviderError::Contract(ContractError::Invalid { field, reason })) =
                    fixture.attempt.admission_failure.as_ref()
                else {
                    panic!("duplicate version must retain its original validation failure");
                };
                assert_eq!(*field, "versions");
                assert_eq!(reason, "duplicate protocol version");
            } else {
                outcome.unwrap();
                assert_eq!((verifier.authenticated, verifier.contracts), (1, 1));
                fixture
                    .attempt
                    .authority_data(fixture.cut)
                    .unwrap()
                    .ensure_live()
                    .unwrap();
            }
            assert!(fixture.admit(&mut verifier).is_err());
        }
    }
}
