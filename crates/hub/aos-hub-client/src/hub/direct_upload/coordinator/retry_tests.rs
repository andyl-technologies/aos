//! Exercises completion reply failures without renewing retained operations.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

struct Replies {
    expected: DirectUploadRequest,
    replies: Mutex<VecDeque<Result<DirectUploadResponse, DirectClientError>>>,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl DirectUploadControl for Replies {
    async fn execute(
        &self,
        request: &DirectUploadRequest,
    ) -> Result<DirectUploadResponse, DirectClientError> {
        assert_eq!(request, &self.expected, "retry changed retained Complete");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.replies.lock().unwrap().pop_front().unwrap()
    }
}

fn request() -> DirectUploadRequest {
    let version = WireInteger::new(1);
    let request = DirectUploadRequest::CompleteBatch(DirectBatch {
        operation_id: "ab".repeat(32),
        items: vec![DirectCompleteRequest {
            session: DirectSessionRef {
                session_id: "retained-session".into(),
                logical_fingerprint: "cd".repeat(32),
            },
            operation_id: "ef".repeat(32),
            expected_resource_version: version,
            manifests: vec![DirectManifestCommitment {
                placement: DirectPlacementRef {
                    placement_id: version,
                    placement_fingerprint: "ab".repeat(32),
                    placement_resource_version: version,
                    write_spec_version: version,
                    binding_id: version,
                    binding_resource_version: version,
                    binding_write_revision: version,
                    profile_fingerprint: "bc".repeat(32),
                    private_policy_digest: "de".repeat(32),
                    checksum_algorithm: DirectChecksumAlgorithm::Sha256,
                },
                manifest_digest: "fa".repeat(32),
                part_count: 1,
            }],
        }],
    });
    request.validate().unwrap();
    request
}

fn reply(codes: &[DirectItemErrorCode]) -> DirectUploadResponse {
    let response = DirectUploadResponse {
        operation_id: "ab".repeat(32),
        sessions: Vec::new(),
        grants: Vec::new(),
        errors: codes
            .iter()
            .enumerate()
            .map(|(index, &code)| DirectItemError {
                item_id: format!("retained-operation-{index}"),
                code,
            })
            .collect(),
    };
    response.validate().unwrap();
    response
}

async fn run(
    replies: Vec<Result<DirectUploadResponse, DirectClientError>>,
    expected: Result<DirectUploadResponse, DirectClientError>,
    expected_calls: usize,
) {
    let control = Replies {
        expected: request(),
        replies: Mutex::new(replies.into()),
        calls: AtomicUsize::new(0),
    };

    assert_eq!(execute_retry(&control, &control.expected).await, expected);
    assert_eq!(control.calls.load(Ordering::SeqCst), expected_calls);
}

#[tokio::test]
async fn unavailable_item_and_lost_reply_replay_the_exact_complete() {
    run(
        vec![
            Ok(reply(&[DirectItemErrorCode::Unavailable])),
            Err(DirectClientError::ControlUnavailable),
            Ok(reply(&[])),
        ],
        Ok(reply(&[])),
        3,
    )
    .await;
}

#[tokio::test]
async fn unavailable_items_exhaust_the_same_three_attempt_budget() {
    run(
        vec![Ok(reply(&[DirectItemErrorCode::Unavailable])); 3],
        Err(DirectClientError::ControlUnavailable),
        3,
    )
    .await;
}

#[tokio::test]
async fn mixed_non_retryable_items_stop_even_when_unavailable_is_first() {
    for (code, expected) in [
        (
            DirectItemErrorCode::BlockedUnknown,
            DirectClientError::Blocked,
        ),
        (DirectItemErrorCode::Denied, DirectClientError::Denied),
        (DirectItemErrorCode::Invalid, DirectClientError::Invalid),
        (DirectItemErrorCode::Conflict, DirectClientError::Invalid),
        (DirectItemErrorCode::Unsupported, DirectClientError::Invalid),
    ] {
        run(
            vec![Ok(reply(&[DirectItemErrorCode::Unavailable, code]))],
            Err(expected),
            1,
        )
        .await;
    }
}

#[tokio::test]
async fn an_uncorrelated_reply_never_authorizes_a_retry() {
    let mut changed = reply(&[DirectItemErrorCode::Unavailable]);
    changed.operation_id = "ba".repeat(32);
    run(vec![Ok(changed)], Err(DirectClientError::Invalid), 1).await;
}
