//! Preserves accepted admissions while keeping discovery freshness at dispatch.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;

struct HeldBegin {
    inner: Control,
    cache_deadline: u64,
    change_binding: bool,
}

#[async_trait]
impl DirectUploadControl for HeldBegin {
    async fn execute(
        &self,
        request: &DirectUploadRequest,
    ) -> Result<DirectUploadResponse, DirectClientError> {
        let mut reply = self.inner.execute(request).await?;
        if matches!(request, DirectUploadRequest::BeginBatch(_)) {
            // Native has accepted the exact request. Wait for the original
            // discovery cache to expire before delivering that acknowledgement.
            while unix_now() < self.cache_deadline {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if self.change_binding {
                reply.sessions[0].placements[0].binding_write_revision = WireInteger::new(2);
            }
        }
        Ok(reply)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn accepted_begin_survives_discovery_expiry_without_replaying_begin() {
    let destinations = placements(1);
    let mut source = objects(1, b"acknowledged-source", &destinations, 0).await;
    let cache_deadline = unix_now() + 15;
    source[0].discovery.valid_until = WireInteger::new(cache_deadline);
    let original = source[0].discovery.clone();
    let control = HeldBegin {
        inner: Control::new(destinations),
        cache_deadline,
        change_binding: false,
    };
    let store = Store::default();
    let provider = Provider::default();

    let result = upload_direct_batch(&control, &store, &provider, source)
        .await
        .unwrap();

    assert!(original
        .validate_at_for(&original.target, unix_now())
        .is_err());
    assert_eq!(original.valid_until.get(), cache_deadline);
    assert_eq!(result[0].state, DirectSessionState::StagedVerified);
    assert_eq!(
        provider.bytes.load(Ordering::SeqCst),
        b"acknowledged-source".len()
    );
    let state = control.inner.state.lock().unwrap();
    assert_eq!(
        state
            .controls
            .iter()
            .filter(|request| matches!(request, DirectUploadRequest::BeginBatch(_)))
            .count(),
        1
    );
}

#[tokio::test]
async fn a_late_acknowledgement_cannot_change_the_admitted_writer() {
    let destinations = placements(1);
    let mut source = objects(1, b"unchanged-source", &destinations, 0).await;
    let cache_deadline = unix_now() + 15;
    source[0].discovery.valid_until = WireInteger::new(cache_deadline);
    let control = HeldBegin {
        inner: Control::new(destinations),
        cache_deadline,
        change_binding: true,
    };
    let store = Store::default();
    let provider = Provider::default();

    let result = upload_direct_batch(&control, &store, &provider, source).await;

    assert_eq!(result, Err(DirectClientError::Invalid));
    assert_eq!(control.inner.state.lock().unwrap().controls.len(), 1);
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expired_discovery_never_dispatches_a_new_begin() {
    let destinations = placements(1);
    let mut source = objects(1, b"not-admitted", &destinations, 0).await;
    source[0].discovery.valid_until = WireInteger::new(1);
    let control = Control::new(destinations);
    let store = Store::default();
    let provider = Provider::default();

    let result = upload_direct_batch(&control, &store, &provider, source).await;

    assert_eq!(result, Err(DirectClientError::Invalid));
    assert!(control.state.lock().unwrap().controls.is_empty());
    assert!(store.0.lock().unwrap().intents.is_empty());
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
}
