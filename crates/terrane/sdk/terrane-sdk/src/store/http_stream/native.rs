//! Binds incremental portable HTTP bodies to the native HTTP client.
//!
//! Network chunks may be larger than consumer chunks. Each returned chunk is
//! bounded without collecting the complete response. A refused response drops
//! its transport handle and cannot subsequently manufacture successful EOF.

use super::{
    HttpBodyStream, HttpError, HttpStreamError, HttpStreamLimits, LimitedHttpBody,
    StreamingHttpRequest, StreamingHttpResponse,
};
use bytes::Bytes;

pub(in crate::store) async fn send(
    client: &reqwest::Client,
    request: StreamingHttpRequest,
    request_limits: HttpStreamLimits,
    response_limits: HttpStreamLimits,
) -> Result<StreamingHttpResponse, HttpStreamError> {
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(invalid)?;
    let mut outgoing = client.request(method, request.url);
    for (name, value) in request.headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(invalid)?;
        let value = reqwest::header::HeaderValue::from_bytes(&value).map_err(invalid)?;
        outgoing = outgoing.header(name, value);
    }
    let source = LimitedHttpBody::new(request.body, request_limits);
    let body = futures_util::stream::try_unfold(source, |mut source| async move {
        match source.next().await? {
            Some(chunk) => Ok::<_, HttpStreamError>(Some((Bytes::from(chunk), source))),
            None => Ok(None),
        }
    });
    let response = outgoing
        .body(reqwest::Body::wrap_stream(body))
        .send()
        .await
        .map_err(unavailable)?;
    if let Some(declared) = response.content_length()
        && declared > response_limits.body_bytes()
    {
        return Err(HttpStreamError::Limit {
            maximum: response_limits.body_bytes(),
            observed: declared,
        });
    }
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    Ok(StreamingHttpResponse {
        status,
        headers,
        body: Box::new(ResponseBody {
            response: Some(response),
            pending: Bytes::new(),
            limits: response_limits,
            consumed: 0,
            failed: false,
        }),
    })
}

struct ResponseBody {
    response: Option<reqwest::Response>,
    pending: Bytes,
    limits: HttpStreamLimits,
    consumed: u64,
    failed: bool,
}

impl ResponseBody {
    async fn receive(&mut self) -> Result<Option<Vec<u8>>, HttpStreamError> {
        if self.failed {
            return Err(HttpStreamError::Terminated);
        }
        while self.pending.is_empty() {
            let Some(response) = self.response.as_mut() else {
                return Ok(None);
            };
            let Some(chunk) = response.chunk().await.map_err(unavailable)? else {
                self.response = None;
                return Ok(None);
            };
            let length = u64::try_from(chunk.len()).map_err(|_| HttpStreamError::Limit {
                maximum: self.limits.body_bytes(),
                observed: u64::MAX,
            })?;
            let observed = self
                .consumed
                .checked_add(length)
                .ok_or(HttpStreamError::Limit {
                    maximum: self.limits.body_bytes(),
                    observed: u64::MAX,
                })?;
            if observed > self.limits.body_bytes() {
                return Err(HttpStreamError::Limit {
                    maximum: self.limits.body_bytes(),
                    observed,
                });
            }
            self.consumed = observed;
            self.pending = chunk;
        }
        let length = self.pending.len().min(self.limits.chunk_bytes());
        Ok(Some(self.pending.split_to(length).to_vec()))
    }
}

#[async_trait::async_trait]
impl HttpBodyStream for ResponseBody {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, HttpStreamError> {
        let result = self.receive().await;
        if result.is_err() {
            self.failed = true;
            self.response = None;
            self.pending = Bytes::new();
        }
        result
    }
}

fn invalid(error: impl std::error::Error + Send + Sync + 'static) -> HttpStreamError {
    HttpStreamError::Transport(HttpError::InvalidRequest(Box::new(error)))
}

fn unavailable(error: impl std::error::Error + Send + Sync + 'static) -> HttpStreamError {
    HttpStreamError::Transport(HttpError::Unavailable(Box::new(error)))
}
