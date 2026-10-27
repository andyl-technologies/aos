//! Checks the actual post-Commit comparison without a live owner or permission.

use super::*;
use crate::envelope::Nullable;

fn original() -> Envelope {
    let present = || Nullable(Some(Id::new("data/scope").unwrap()));
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: present(),
        incarnation_id: present(),
        node_id: present(),
        execution_owner_id: present(),
        capture_owner_id: Nullable(None),
        request_id: present(),
        operation_id: Nullable(None),
        sequence: U64::new(7),
        method: Method::Begin,
        body: Default::default(),
        extensions: Default::default(),
    }
}

#[test]
fn completed_commit_comparison_keeps_original_prepare_token_mapping_and_full_digests() {
    let reference = canonical::content_ref(b"actual", "application/json").unwrap();
    let reference = serde_json::to_value(reference).unwrap();
    let mut request = original();
    request.extensions.insert(
        PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION.into(),
        serde_json::json!({"restoration":{"mapping":reference}}),
    );
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.sequence = U64::new(9);
    response.extensions.clear();
    response.extensions.insert(
        PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION.into(),
        serde_json::json!({"transfer_token":"actual-token"}),
    );
    let references = [inputs::Reference::borrow(&reference).unwrap(); 6];
    let prepare = PrepareInputs {
        original: &request,
        response: &response,
        request_id: request.request_id.0.as_ref().unwrap(),
        token: "actual-token",
        references,
    };
    let commit = serde_json::json!({
        "prepare": request.extensions.get(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION).unwrap(),
        "prepare_request_id":prepare.request_id,"prepare_request_sequence":request.sequence,
        "prepare_response_sequence":response.sequence,
        "prepare_request_digest":crucible_node_format::Bytes::new(
            complete_restore_transfer_original_digest(&request,65536).unwrap().to_vec()),
        "prepare_response_digest":crucible_node_format::Bytes::new(
            complete_restore_transfer_original_digest(&response,65536).unwrap().to_vec()),
        "transfer_token":"actual-token",
    });
    let receipt =
        serde_json::json!({"transfer_token":"actual-token","installed_mapping":reference});

    authenticate_commit_correspondence(&prepare, &commit, &receipt, 65536).unwrap();

    for (pointer, value) in [
        (
            "/prepare/restoration/mapping/media_type",
            Value::String("changed/type".into()),
        ),
        (
            "/prepare_request_id",
            Value::String("another/prepare".into()),
        ),
        ("/prepare_request_sequence", Value::String("8".into())),
        ("/prepare_response_sequence", Value::String("10".into())),
        ("/transfer_token", Value::String("another-token".into())),
        (
            "/prepare_request_digest",
            serde_json::to_value(crucible_node_format::Bytes::new(vec![1; 32])).unwrap(),
        ),
        (
            "/prepare_response_digest",
            serde_json::to_value(crucible_node_format::Bytes::new(vec![2; 32])).unwrap(),
        ),
    ] {
        let mut changed = commit.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            authenticate_commit_correspondence(&prepare, &changed, &receipt, 65536).is_err(),
            "{pointer}"
        );
    }
    for pointer in ["/transfer_token", "/installed_mapping/media_type"] {
        let mut changed = receipt.clone();
        *changed.pointer_mut(pointer).unwrap() = Value::String("changed".into());
        assert!(
            authenticate_commit_correspondence(&prepare, &commit, &changed, 65536).is_err(),
            "{pointer}"
        );
    }
    let mut changed_request = request.clone();
    changed_request
        .body
        .insert("changed_original".into(), Value::Bool(true));
    let changed = PrepareInputs {
        original: &changed_request,
        ..prepare
    };
    assert!(authenticate_commit_correspondence(&changed, &commit, &receipt, 65536).is_err());
}

#[test]
fn completed_commit_baseline_uses_shared_transaction_with_distinct_assigned_ids() {
    let reference = canonical::content_ref(b"actual", "application/json").unwrap();
    let reference = serde_json::to_value(reference).unwrap();
    let mut request = original();
    request.request_id = Nullable(Some(Id::new("prepare/request").unwrap()));
    request.body.insert(
        "arguments".into(),
        serde_json::json!({"transaction_id":"source/transaction"}),
    );
    request.extensions.insert(
        PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION.into(),
        serde_json::json!({"transaction_id":"source/transaction"}),
    );
    let mut response = request.clone();
    response.message = MessageKind::Response;
    let prepare = PrepareInputs {
        original: &request,
        response: &response,
        request_id: request.request_id.0.as_ref().unwrap(),
        token: "actual-token",
        references: [inputs::Reference::borrow(&reference).unwrap(); 6],
    };
    let mut commit_original = original();
    commit_original.request_id = Nullable(Some(Id::new("commit/request").unwrap()));
    commit_original.body.insert(
        "arguments".into(),
        serde_json::json!({"transaction_id":"source/transaction"}),
    );
    let mut commit_response = commit_original.clone();
    commit_response.message = MessageKind::Response;
    commit_response.body.insert(
        "result".into(),
        serde_json::json!({"transaction_id":"source/transaction"}),
    );
    let commit = serde_json::json!({"prepare":{"transaction_id":"source/transaction"}});

    assert_ne!(request.request_id, commit_original.request_id);
    assert_ne!(
        request.request_id.0.as_ref().unwrap().as_str(),
        "source/transaction"
    );
    assert_ne!(
        commit_original.request_id.0.as_ref().unwrap().as_str(),
        "source/transaction"
    );
    authenticate_completed_commit_baselines(&prepare, &commit_original, &commit_response, &commit)
        .unwrap();

    for replacement in ["commit/request", "prepare/request", "another/transaction"] {
        let mut changed = commit_response.clone();
        changed.body.get_mut("result").unwrap()["transaction_id"] =
            Value::String(replacement.into());
        assert!(
            authenticate_completed_commit_baselines(&prepare, &commit_original, &changed, &commit)
                .is_err(),
            "{replacement}"
        );
    }
    let mut changed = commit_original.clone();
    changed.body.get_mut("arguments").unwrap()["transaction_id"] =
        Value::String("another/transaction".into());
    assert!(
        authenticate_completed_commit_baselines(&prepare, &changed, &commit_response, &commit)
            .is_err()
    );
    let mut changed = commit.clone();
    changed["prepare"]["transaction_id"] = Value::String("another/transaction".into());
    assert!(
        authenticate_completed_commit_baselines(
            &prepare,
            &commit_original,
            &commit_response,
            &changed
        )
        .is_err()
    );
}
