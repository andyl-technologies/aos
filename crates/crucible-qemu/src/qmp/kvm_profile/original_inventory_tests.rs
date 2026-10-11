//! Native-return page wire models; these controls do not execute KVM.

use super::*;
use serde_json::json;

fn request() -> QmpKvmOriginalReturnsRequest {
    QmpKvmOriginalReturnsRequest {
        generation: 5,
        first_record: 7,
        maximum_records: 2,
    }
}

fn page() -> serde_json::Value {
    let entries: Vec<_> = [7, 8]
        .into_iter()
        .map(|record| {
            json!({"record-index":record,"generation":4,"expected-invocation":2,
                "vcpu-index":0,"native-vcpu-id":0,"issued":true,
                "receipt-known":true,"no-birth-known":false,"ack-known":false})
        })
        .collect();
    json!({"schema-version":1,"generation":5,"first-record":7,"next-record":9,
        "retained-returns":10,"entries":entries,"profile-qualified":false})
}

#[test]
fn original_inventory_command_preserves_exact_observational_namespace() {
    let request = request();
    let command = QmpCommand::KvmOriginalReturns { request: &request };
    assert_eq!(command.kind(), QmpCommandKind::KvmOriginalReturns);
    assert_eq!(
        command.request(),
        json!({"execute":"x-crucible-kvm-original-returns","arguments":{
            "generation":5,"first-record":7,"maximum-records":2
        }})
    );
    // One CPU may occur in historical windows, and BSP native ID zero is valid.
    assert!(parse_original_returns(&request, &page()).is_ok());
}

#[test]
fn inventory_credit_is_finite_and_accepts_exact_empty_final_page() {
    let mut request = request();
    request.maximum_records = 0;
    assert!(validate_original_returns_request(&request).is_err());
    request.maximum_records = 129;
    assert!(validate_original_returns_request(&request).is_err());
    request.maximum_records = 128;
    request.first_record = 65_537;
    assert!(validate_original_returns_request(&request).is_err());
    request.first_record = 65_536;
    assert!(validate_original_returns_request(&request).is_ok());
    let value = json!({"schema-version":1,"generation":5,"first-record":65_536,
        "next-record":65_536,"retained-returns":65_536,"entries":[],
        "profile-qualified":false});
    assert!(parse_original_returns(&request, &value).is_ok());
}

#[test]
fn source_row_count_order_scope_and_qualification_cannot_be_forged() {
    for (field, replacement) in [
        ("schema-version", json!(2)),
        ("generation", json!(6)),
        ("first-record", json!(6)),
        ("next-record", json!(8)),
        ("retained-returns", json!(6)),
        ("profile-qualified", json!(true)),
        ("new-wire-field", json!(0)),
    ] {
        let mut value = page();
        value[field] = replacement;
        assert!(
            parse_original_returns(&request(), &value).is_err(),
            "{field}"
        );
    }
    let mut value = page();
    value["entries"] = json!([]);
    assert!(parse_original_returns(&request(), &value).is_err());
    value = page();
    value["entries"][1]["record-index"] = json!(7);
    assert!(parse_original_returns(&request(), &value).is_err());
}

#[test]
fn source_identity_and_original_knowledge_obligations_cannot_be_rebound() {
    for (field, replacement) in [
        ("generation", json!(0)),
        ("generation", json!(6)),
        ("expected-invocation", json!(0)),
        ("vcpu-index", json!(4096)),
        ("issued", json!(false)),
        ("no-birth-known", json!(true)),
    ] {
        let mut value = page();
        value["entries"][0][field] = replacement;
        assert!(
            parse_original_returns(&request(), &value).is_err(),
            "{field}"
        );
    }
}

#[test]
fn actual_no_birth_and_ack_observations_preserve_distinct_original_custody() {
    let mut value = page();
    value["entries"][0]["receipt-known"] = json!(false);
    value["entries"][0]["no-birth-known"] = json!(true);
    value["entries"][0]["ack-known"] = json!(true);
    assert!(parse_original_returns(&request(), &value).is_ok());
    value["entries"][0]["ack-known"] = json!(false);
    assert!(parse_original_returns(&request(), &value).is_err());
}
