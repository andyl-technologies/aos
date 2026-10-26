//! Supplies deliberately limited services for transport-only socket tests.
//!
//! Unused methods return explicit unsupported status. The fixture is not a
//! Distribution backend and supplies no authentication or custody evidence.

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use terrane_sdk::wire::{
    services::{ContentService, RefService, TierService},
    status::{Outcome, ProtocolError},
    transport::TransportLimits,
    v1,
};

#[derive(Default)]
pub(super) struct Services {
    pub(super) calls: AtomicUsize,
    pub(super) dropped_stream: Arc<AtomicBool>,
    pub(super) tokens: std::sync::Mutex<Vec<Vec<u8>>>,
    pub(super) has_bitmap: Option<Vec<u8>>,
    pub(super) has_delay: std::time::Duration,
}

fn unsupported() -> connectrpc::ConnectError {
    ProtocolError::from_outcome(Outcome::MethodUnavailable, "transport-fixture").into()
}

macro_rules! unavailable_unary {
    ($method:ident, $request:ty, $response:ty) => {
        async fn $method(
            &self,
            _context: RequestContext,
            _request: ServiceRequest<'_, $request>,
        ) -> ServiceResult<$response> {
            Err::<Response<$response>, _>(unsupported())
        }
    };
}

macro_rules! unavailable_stream {
    ($method:ident, $request:ty, $response:ty) => {
        async fn $method(
            &self,
            _context: RequestContext,
            _request: ServiceRequest<'_, $request>,
        ) -> ServiceResult<ServiceStream<$response>> {
            Err::<Response<ServiceStream<$response>>, _>(unsupported())
        }
    };
}

// The fixture intentionally exposes concrete messages for opaque generated responses.
#[allow(refining_impl_trait)]
impl ContentService for Services {
    unavailable_unary!(negotiate, v1::NegotiateRequest, v1::NegotiateResponse);
    unavailable_unary!(
        presign_read,
        v1::PresignReadRequest,
        v1::PresignReadResponse
    );
    unavailable_stream!(get_bundle, v1::GetBundleRequest, v1::BundleFrame);
    unavailable_stream!(get_filter, v1::GetFilterRequest, v1::FilterShard);
    unavailable_stream!(get_index, v1::GetIndexRequest, v1::IndexShard);

    async fn has(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::HasRequest>,
    ) -> ServiceResult<v1::HasResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.has_delay.is_zero() {
            tokio::time::sleep(self.has_delay).await;
        }
        if let Some(token) = context
            .extensions()
            .get::<terrane_sdk::wire::authentication::RequestToken>()
        {
            self.tokens
                .lock()
                .map_err(|_| unsupported())?
                .push(token.bytes().to_vec());
        }
        let hashes = request.to_owned_message().hashes;
        let mut present_bitmap = vec![0; hashes.len().div_ceil(8)];
        for (position, hash) in hashes.iter().enumerate() {
            if hash.value == [7; 32] {
                present_bitmap[position / 8] |= 1 << (position % 8);
            }
        }
        Ok(Response::new(v1::HasResponse {
            present_bitmap: self.has_bitmap.clone().unwrap_or(present_bitmap),
            ..Default::default()
        }))
    }

    async fn put_pack(
        &self,
        _context: RequestContext,
        _requests: connectrpc::InboundStream<v1::PutPackFrame>,
    ) -> ServiceResult<v1::PutPackResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err::<Response<v1::PutPackResponse>, _>(unsupported())
    }

    async fn get_range(
        &self,
        _context: RequestContext,
        _request: ServiceRequest<'_, v1::GetRangeRequest>,
    ) -> ServiceResult<ServiceStream<v1::GetRangeFrame>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let stream: ServiceStream<v1::GetRangeFrame> = Box::pin(PendingBody {
            emitted: false,
            dropped: self.dropped_stream.clone(),
        });
        Ok(Response::new(stream))
    }
}

struct PendingBody {
    emitted: bool,
    dropped: Arc<AtomicBool>,
}

impl futures_util::Stream for PendingBody {
    type Item = Result<v1::GetRangeFrame, connectrpc::ConnectError>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.emitted {
            return std::task::Poll::Pending;
        }
        self.emitted = true;
        std::task::Poll::Ready(Some(Ok(v1::GetRangeFrame {
            data: b"first frame".to_vec(),
            ..Default::default()
        })))
    }
}

impl Drop for PendingBody {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[allow(refining_impl_trait)]
impl RefService for Services {
    unavailable_unary!(get_ref, v1::GetRefRequest, v1::RefState);
    unavailable_unary!(
        compare_and_swap_ref,
        v1::CompareAndSwapRefRequest,
        v1::RefState
    );
    unavailable_stream!(get_ref_log, v1::GetRefLogRequest, v1::RefLogEntry);
    unavailable_stream!(watch_refs, v1::WatchRefsRequest, v1::RefEvent);
    unavailable_stream!(list_refs, v1::ListRefsRequest, v1::RefState);
}

#[allow(refining_impl_trait)]
impl TierService for Services {
    unavailable_unary!(
        capabilities,
        v1::CapabilitiesRequest,
        v1::CapabilitiesResponse
    );
    unavailable_unary!(residency, v1::ResidencyRequest, v1::ResidencyResponse);
    unavailable_unary!(r#where, v1::WhereRequest, v1::WhereResponse);
    unavailable_unary!(warm, v1::WarmRequest, v1::WarmResponse);
    unavailable_unary!(costs, v1::CostsRequest, v1::CostsResponse);
}

pub(super) fn limits() -> TransportLimits {
    TransportLimits {
        max_request_bytes: 2 * 1024 * 1024,
        max_message_bytes: 1024 * 1024,
        max_element_memory: 1024 * 1024,
        max_concurrent_streams: 8,
        handshake_timeout: std::time::Duration::from_secs(10),
        header_timeout: std::time::Duration::from_secs(2),
        request_timeout: std::time::Duration::from_secs(2),
    }
}
