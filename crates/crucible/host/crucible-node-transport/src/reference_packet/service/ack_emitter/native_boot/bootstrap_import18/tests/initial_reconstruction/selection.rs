//! Checks complete new definitions against the actual inherited launch owner.

use super::super::super::selection::OriginalImport18SelectionAdmission;
use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    native_import18_declared_features_data, native_import18_schema_data,
    native_import18_stage_schema_data,
};
use std::cell::Cell;

pub(super) fn prepare_selected(case: &str, selected: &mut Value) {
    let schemas = json!([
        native_import18_schema_data().unwrap(),
        native_import18_stage_schema_data().unwrap(),
    ]);
    selected["launch"]["selection"]["provider"]["implementation"]["formats"] = schemas.clone();
    selected["launch"]["selection"]["provider"]["extensions_supported"] =
        json!(native_import18_declared_features_data());
    selected["launch"]["selection"]["realization"]["bindings"][0]["compatibility"]["implementation"]
        ["formats"] = schemas;

    let launch = &mut selected["launch"]["selection"];
    let formats = if case.contains("_binding_") {
        &mut launch["realization"]["bindings"][0]["compatibility"]["implementation"]["formats"]
    } else {
        &mut launch["provider"]["implementation"]["formats"]
    };
    if case.ends_with("_missing") && case != "initial_selection_feature_missing" {
        formats.as_array_mut().unwrap().remove(0);
    } else if case.ends_with("_duplicate") {
        let duplicate = formats[1].clone();
        formats.as_array_mut().unwrap().push(duplicate);
    } else if case.ends_with("_media") {
        formats[0]["definition"]["media_type"] = json!("application/cbor");
    } else if case.ends_with("_digest") {
        formats[1]["definition"]["hash"]["digest"] = json!("a".repeat(64));
    } else if case.ends_with("_length") {
        formats[0]["definition"]["length"] = json!("1");
    } else if case.ends_with("_version") {
        formats[1]["version"] = json!(17);
    } else if case.ends_with("_extensions") {
        formats[0]["extensions"] = json!({"cnp.test/1": {"changed": true}});
    } else if case.ends_with("_domain") {
        formats[1]["definition"]["hash"]["domain"] = json!("other.domain");
    } else if case.ends_with("_id") {
        formats[0]["id"] = json!("source-owned.packet-native-import/19");
    }
    if case == "initial_selection_feature_missing" {
        launch["provider"]["extensions_supported"]
            .as_array_mut()
            .unwrap()
            .remove(2);
    }
    if case == "initial_selection_feature_repeated" {
        let feature = launch["provider"]["extensions_supported"][0].clone();
        launch["provider"]["extensions_supported"]
            .as_array_mut()
            .unwrap()
            .push(feature);
    }
}

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    retained: usize,
}

impl OriginalImport18SelectionAdmission for Admission<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert_eq!(row[0], 0);
        assert!(row[1] > 0 && row[2] > 0);
        assert_eq!(original.selection_construction_row, Some(row));
        assert!(original.selection_started);
        assert!(!original.selection_authenticated);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.retained);
        if self.case == "initial_selection_construct_refused" {
            return Err(ProviderError::Conflict("actual definition admission"));
        }
        if self.case == "initial_selection_construct_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(&self, original: &OriginalImport18RawBootstrap) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.retained);
        if self.case == "initial_selection_finish_refused" {
            return Err(ProviderError::Conflict("actual definition terminal"));
        }
        if self.case == "initial_selection_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn authenticate_for_hello(owner: &mut OriginalImport18RawBootstrap) {
    let admission = Admission {
        case: "initial_selection_complete",
        calls: Cell::new(0),
        retained: owner.retained_requested_bytes().unwrap(),
    };
    owner.authenticate_selection_data(&admission).unwrap();
    assert!(owner.selection_authenticated);
    assert_eq!(admission.calls.get(), 2);
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    let retained = owner.retained_requested_bytes().unwrap();
    let pointers = owner.bodies.each_ref().map(|body| body.as_ptr());
    let admission = Admission {
        case,
        calls: Cell::new(0),
        retained,
    };
    if case == "initial_selection_incomplete" {
        owner.initial_reconstructed = false;
    }
    if case == "initial_selection_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    let outcome = owner.authenticate_selection_data(&admission);
    let complete = matches!(
        case,
        "initial_selection_complete" | "initial_selection_reactive"
    );
    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(owner.selection_authenticated, complete);
    assert!(owner.selection_started);
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_selection_incomplete" | "initial_selection_before_expired" => 0,
            "initial_selection_construct_refused" | "initial_selection_construct_expired" => 1,
            _ => 2,
        }
    );
    assert!(owner.authenticate_selection_data(&admission).is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), pointers);
    assert!(owner.inputs.is_empty_data());
    assert!(owner.hello_selection.is_none());
}

#[test]
fn native_definitions_use_full_original_rosters_before_any_model_or_hello() {
    for case in [
        "initial_selection_complete",
        "initial_selection_reactive",
        "initial_selection_provider_missing",
        "initial_selection_binding_missing",
        "initial_selection_provider_duplicate",
        "initial_selection_binding_duplicate",
        "initial_selection_provider_media",
        "initial_selection_binding_media",
        "initial_selection_provider_digest",
        "initial_selection_binding_digest",
        "initial_selection_provider_length",
        "initial_selection_binding_version",
        "initial_selection_provider_extensions",
        "initial_selection_binding_domain",
        "initial_selection_provider_id",
        "initial_selection_feature_missing",
        "initial_selection_feature_repeated",
        "initial_selection_incomplete",
        "initial_selection_before_expired",
        "initial_selection_construct_refused",
        "initial_selection_construct_expired",
        "initial_selection_finish_refused",
        "initial_selection_finish_expired",
    ] {
        flight(case);
    }
}
