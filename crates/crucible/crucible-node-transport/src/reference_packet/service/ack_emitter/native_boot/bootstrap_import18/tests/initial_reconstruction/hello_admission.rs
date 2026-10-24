//! Exercises actual original SDK admission with inherited private/public custody.
//!
//! Model funding callbacks check each boundary; they grant no genuine Source
//! credit. The SDK runs the real original native verifier and retains its lease.

use super::super::super::hello_admission::OriginalImport18HelloAdmission;
use super::*;
use crate::reference_packet::service::complete_restore::import18::hello::NATIVE_IMPORT18_CONNECTION_ID;
use std::cell::Cell;

/// Gives successful SDK controls a schema-valid sorted provider advertisement.
pub(super) fn prepare_selected(case: &str, selected: &mut Value) {
    if case == "initial_hello_admission_invalid_manifest" {
        return;
    }
    selected["launch"]["selection"]["provider"]["extensions_supported"]
        .as_array_mut()
        .unwrap()
        .sort_by(|left, right| left.as_str().unwrap().cmp(right.as_str().unwrap()));
    let provider: crucible_node_format::ProviderManifest =
        serde_json::from_value(selected["launch"]["selection"]["provider"].clone()).unwrap();
    crucible_node_format::Validate::validate(&provider).unwrap();
}

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    registrar_before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloAdmission for Admission<'_> {
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(scratch > 0);
        assert!(original.hello_admission.row_fixture_data().is_none());
        assert!(
            original
                .hello_registrar
                .retained_authority_fixture_data()
                .is_none()
        );
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        if self.case == "initial_hello_admission_quote_refused" {
            return Err(ProviderError::Conflict("SDK quote admission"));
        }
        if self.case == "initial_hello_admission_quote_expired" {
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
        assert_eq!(original.hello_admission.row_fixture_data(), Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert!(
            original
                .hello_registrar
                .retained_authority_fixture_data()
                .is_none()
        );
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_admission_construct_refused" {
            return Err(ProviderError::Conflict("SDK constructor admission"));
        }
        if self.case == "initial_hello_admission_construct_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        registrar_backing: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(3), 2);
        assert_eq!(
            original.hello_registrar.retained_backing_data().unwrap(),
            registrar_backing
        );
        let additional = registrar_backing
            .checked_sub(self.registrar_before)
            .unwrap();
        assert!(additional <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + additional
        );
        let initialized = !matches!(
            self.case,
            "initial_hello_admission_construct_expired"
                | "initial_hello_admission_invalid_manifest"
        );
        assert_eq!(
            original
                .hello_registrar
                .retained_authority_fixture_data()
                .is_some(),
            initialized,
            "{}: actual SDK failure: {:?}",
            self.case,
            original.hello_registrar.admission_failure_fixture_data(),
        );
        if initialized {
            original
                .hello_registrar
                .authority_data(original.cut)
                .unwrap()
                .ensure_live()
                .unwrap();
        }
        if self.case == "initial_hello_admission_finish_refused" {
            return Err(ProviderError::Conflict("SDK terminal admission"));
        }
        if self.case == "initial_hello_admission_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn construct_for_publication(owner: &mut OriginalImport18RawBootstrap) {
    super::hello_response::construct_for_verifier(owner);
    let admission = Admission {
        case: "initial_hello_admission_complete",
        calls: Cell::new(0),
        before: owner.retained_requested_bytes().unwrap(),
        registrar_before: owner.hello_registrar.retained_backing_data().unwrap(),
        row: Cell::new(None),
    };
    owner.admit_hello_data(&admission).unwrap();
    assert_eq!(admission.calls.get(), 3);
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case == "initial_hello_admission_unchecked_response" {
        super::hello_envelope::construct_for_response(owner);
    } else {
        super::hello_response::construct_for_verifier(owner);
    }
    let request = owner
        .hello_sdk_request
        .request_fixture_data()
        .map(std::ptr::from_ref);
    let result = owner
        .hello_result
        .result_fixture_data()
        .map(std::ptr::from_ref);
    let envelope = owner
        .hello_envelope
        .envelope_fixture_data()
        .map(std::ptr::from_ref);
    let response = owner
        .hello_response
        .envelope_fixture_data()
        .map(std::ptr::from_ref);
    let before = owner.retained_requested_bytes().unwrap();
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        registrar_before: owner.hello_registrar.retained_backing_data().unwrap(),
        row: Cell::new(None),
    };

    let outcome = owner.admit_hello_data(&admission);

    let success = matches!(
        case,
        "initial_hello_admission_complete"
            | "initial_hello_admission_reactive"
            | "initial_hello_admission_unsorted_versions"
            | "initial_hello_admission_optional_feature"
            | "initial_hello_admission_larger_limits"
            | "initial_hello_admission_callback_refused"
            | "initial_hello_admission_loan_expired"
            | "initial_hello_admission_error_loan_expired"
            | "initial_hello_admission_substituted_cut"
    );
    if success {
        outcome.unwrap();
        assert_eq!(admission.calls.get(), 3);
        let authority = owner
            .hello_registrar
            .retained_authority_fixture_data()
            .unwrap();
        let original = std::ptr::from_ref(authority);
        let launch = owner.typed_bodies_data().unwrap().launch.launch_data();
        let binding = &launch.selection.realization.bindings[0];
        assert_eq!(
            authority.connection_id().as_str(),
            NATIVE_IMPORT18_CONNECTION_ID
        );
        assert_eq!(authority.session_id(), &binding.authority.session_id);
        assert_eq!(
            authority.incarnation_id(),
            &binding.authority.incarnation_id
        );
        assert_eq!(authority.selected_extensions(), Some([].as_slice()));
        assert_eq!(authority.limits(), launch.limits);
        assert_eq!(
            owner
                .with_hello_authority_data(|lease| Ok(std::ptr::from_ref(lease)))
                .unwrap(),
            original
        );
        assert!(owner.retained_requested_bytes().unwrap() > before);

        if case == "initial_hello_admission_callback_refused" {
            assert!(
                owner
                    .with_hello_authority_data::<()>(|_| {
                        Err(ProviderError::Conflict("inspection refused"))
                    })
                    .is_err()
            );
            owner
                .with_hello_authority_data(|lease| lease.ensure_live())
                .unwrap();
        }
        if case == "initial_hello_admission_substituted_cut" {
            let original_cut = owner.cut;
            owner.cut = OperationalDeadline::after(Duration::from_secs(4)).unwrap();
            assert!(owner.with_hello_authority_data(|_| Ok(())).is_err());
            owner.cut = original_cut;
            owner.with_hello_authority_data(|_| Ok(())).unwrap();
        }
        if matches!(
            case,
            "initial_hello_admission_loan_expired" | "initial_hello_admission_error_loan_expired"
        ) {
            assert!(
                owner
                    .with_hello_authority_data(|_| {
                        std::thread::sleep(Duration::from_secs(5));
                        if case == "initial_hello_admission_error_loan_expired" {
                            return Err(ProviderError::Conflict("expired inspection"));
                        }
                        Ok(())
                    })
                    .is_err()
            );
            assert!(owner.with_hello_authority_data(|_| Ok(())).is_err());
        }
    } else {
        assert!(outcome.is_err(), "{case}");
        if case == "initial_hello_admission_invalid_manifest" {
            assert!(
                matches!(owner.hello_registrar.admission_failure_fixture_data(),
                    Some(ProviderError::Contract(crucible_node_format::ContractError::Invalid { field: "extensions_supported", reason }))
                        if reason == "set must be strictly sorted with no duplicates"
                )
            );
        }
        assert!(owner.with_hello_authority_data(|_| Ok(())).is_err());
        let retained = owner.hello_registrar.retained_authority_fixture_data();
        let initialized = matches!(
            case,
            "initial_hello_admission_finish_refused" | "initial_hello_admission_finish_expired"
        );
        assert_eq!(retained.is_some(), initialized);
        if let Some(retained) = retained {
            assert!(retained.ensure_live().is_err());
            assert!(owner.retained_requested_bytes().unwrap() > before);
        }
    }
    let calls = admission.calls.get();
    assert!(owner.admit_hello_data(&admission).is_err());
    assert_eq!(admission.calls.get(), calls);
    assert_eq!(
        owner
            .hello_sdk_request
            .request_fixture_data()
            .map(std::ptr::from_ref),
        request
    );
    assert_eq!(
        owner
            .hello_result
            .result_fixture_data()
            .map(std::ptr::from_ref),
        result
    );
    assert_eq!(
        owner
            .hello_envelope
            .envelope_fixture_data()
            .map(std::ptr::from_ref),
        envelope
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
fn original_sdk_admission_keeps_the_real_lease_and_spends_every_boundary() {
    for case in [
        "initial_hello_admission_complete",
        "initial_hello_admission_reactive",
        "initial_hello_admission_invalid_manifest",
        "initial_hello_admission_unsorted_versions",
        "initial_hello_admission_optional_feature",
        "initial_hello_admission_larger_limits",
        "initial_hello_admission_unchecked_response",
        "initial_hello_admission_quote_refused",
        "initial_hello_admission_quote_expired",
        "initial_hello_admission_construct_refused",
        "initial_hello_admission_construct_expired",
        "initial_hello_admission_finish_refused",
        "initial_hello_admission_finish_expired",
        "initial_hello_admission_callback_refused",
        "initial_hello_admission_substituted_cut",
        "initial_hello_admission_loan_expired",
        "initial_hello_admission_error_loan_expired",
    ] {
        flight(case);
    }
}
