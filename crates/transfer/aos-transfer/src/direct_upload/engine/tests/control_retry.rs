//! Checks bounded replay of retryable item replies with unchanged originals.

use super::*;

struct Replies {
    requests: Mutex<Vec<DirectUploadRequest>>,
    codes: Vec<DirectItemErrorCode>,
    unavailable_replies: usize,
    wrong_operation: bool,
}

#[async_trait]
impl DirectUploadControl for Replies {
    async fn execute(
        &self,
        request: &DirectUploadRequest,
    ) -> Result<DirectUploadResponse, DirectClientError> {
        let mut requests = self.requests.lock().unwrap();
        requests.push(request.clone());
        Ok(DirectUploadResponse {
            operation_id: if self.wrong_operation {
                "ff".repeat(32)
            } else {
                helpers::request_operation(request).into()
            },
            sessions: Vec::new(),
            grants: Vec::new(),
            errors: if requests.len() <= self.unavailable_replies {
                self.codes
                    .iter()
                    .enumerate()
                    .map(|(index, code)| DirectItemError {
                        item_id: format!("fixture-{index}"),
                        code: *code,
                    })
                    .collect()
            } else {
                Vec::new()
            },
        })
    }
}

fn request() -> DirectUploadRequest {
    DirectUploadRequest::StatusBatch(DirectBatch {
        operation_id: "ab".repeat(32),
        items: (0..2)
            .map(|index| DirectStatusQuery {
                session: DirectSessionRef {
                    session_id: format!("fixture-{index}"),
                    logical_fingerprint: "12".repeat(32),
                },
                after: None,
                maximum_parts: 1,
            })
            .collect(),
    })
}

fn replies(codes: Vec<DirectItemErrorCode>, unavailable_replies: usize) -> Replies {
    Replies {
        requests: Mutex::new(Vec::new()),
        codes,
        unavailable_replies,
        wrong_operation: false,
    }
}

#[tokio::test]
async fn unavailable_item_reply_retries_identical_original() {
    let control = replies(vec![DirectItemErrorCode::Unavailable], 1);
    let request = request();

    helpers::control(&control, &request).await.unwrap();

    assert_eq!(
        *control.requests.lock().unwrap(),
        vec![request.clone(), request]
    );
}

#[tokio::test]
async fn unavailable_item_replies_stop_after_three_attempts() {
    let control = replies(vec![DirectItemErrorCode::Unavailable], usize::MAX);

    assert_eq!(
        helpers::control(&control, &request()).await.unwrap_err(),
        DirectClientError::ControlUnavailable,
    );

    assert_eq!(control.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn unknown_denied_and_mixed_item_replies_do_not_retry() {
    for codes in [
        vec![DirectItemErrorCode::BlockedUnknown],
        vec![DirectItemErrorCode::Denied],
        vec![
            DirectItemErrorCode::Unavailable,
            DirectItemErrorCode::BlockedUnknown,
        ],
    ] {
        let control = replies(codes, usize::MAX);

        assert!(helpers::control(&control, &request()).await.is_err());

        assert_eq!(control.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn mismatched_unavailable_item_reply_does_not_retry() {
    let mut control = replies(vec![DirectItemErrorCode::Unavailable], usize::MAX);
    control.wrong_operation = true;

    assert_eq!(
        helpers::control(&control, &request()).await.unwrap_err(),
        DirectClientError::Invalid,
    );

    assert_eq!(control.requests.lock().unwrap().len(), 1);
}
