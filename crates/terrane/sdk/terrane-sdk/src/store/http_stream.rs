//! Streams HTTP bodies through explicit finite byte limits.
//!
//! A body yields nonempty byte chunks followed by a genuine end-of-stream.
//! Transport failures and resource refusals remain errors; neither establishes
//! a successful upload or an absent object. Application protocols still verify
//! their frames, identities, authorization and durability independently.

use super::{HttpClient, HttpError};
use std::{error::Error, fmt};

#[cfg(feature = "tokio")]
pub(super) mod native;

/// Supplies an owned HTTP body without selecting an asynchronous runtime.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait HttpBodyStream {
    /// Returns the next nonempty chunk, or `None` after a genuine stream end.
    ///
    /// # Errors
    /// Preserves source failures and rejects invalid or excessive body data.
    /// A caller must abandon the stream after an error.
    async fn next(&mut self) -> Result<Option<Vec<u8>>, HttpStreamError>;
}

/// Owns a body that can move between native executor threads.
#[cfg(feature = "send")]
pub type OwnedHttpBody = Box<dyn HttpBodyStream + Send>;

/// Owns a body that remains on its WebAssembly host thread.
#[cfg(not(feature = "send"))]
pub type OwnedHttpBody = Box<dyn HttpBodyStream>;

/// Bounds each yielded chunk and the complete body independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpStreamLimits {
    chunk_bytes: usize,
    body_bytes: u64,
}

impl HttpStreamLimits {
    /// Constructs explicit positive limits without selecting protocol defaults.
    ///
    /// # Errors
    /// Rejects zero bounds, unrepresentable chunk lengths and chunks larger than
    /// the complete body allowance.
    pub fn new(chunk_bytes: usize, body_bytes: u64) -> Result<Self, HttpStreamError> {
        if chunk_bytes == 0
            || body_bytes == 0
            || u64::try_from(chunk_bytes).map_or(true, |chunk| chunk > body_bytes)
        {
            return Err(HttpStreamError::InvalidLimits);
        }
        Ok(Self {
            chunk_bytes,
            body_bytes,
        })
    }

    /// Returns the maximum number of bytes in one consumer-visible chunk.
    pub fn chunk_bytes(self) -> usize {
        self.chunk_bytes
    }

    /// Returns the maximum number of bytes in the complete body.
    pub fn body_bytes(self) -> u64 {
        self.body_bytes
    }
}

/// Describes an HTTP request whose body is consumed incrementally.
pub struct StreamingHttpRequest {
    /// HTTP method token, validated by the selected binding.
    pub method: String,
    /// Complete request URL.
    pub url: String,
    /// Raw headers, preserving repeated names and values.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Owned body, including any resources needed to produce subsequent chunks.
    pub body: OwnedHttpBody,
}

/// Returns response metadata before requiring the complete body to arrive.
pub struct StreamingHttpResponse {
    /// Numeric HTTP status, including non-success responses.
    pub status: u16,
    /// Raw response headers, preserving repeated names and values.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Incremental body; genuine EOF is distinct from truncation or refusal.
    pub body: OwnedHttpBody,
}

/// Extends HTTP transport with incremental request and response bodies.
///
/// Existing buffered clients remain usable through [`HttpClient`]. Streaming
/// protocols require this interface explicitly rather than silently buffering
/// their complete bodies through the older operation.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait StreamingHttpClient: HttpClient {
    /// Exchanges headers and streams bodies within the supplied independent bounds.
    ///
    /// Request limits apply before each produced chunk is sent. Response limits
    /// apply before bytes are delivered to the caller. Success supplies response
    /// metadata only; an application acknowledgement must still be decoded and
    /// verified from the actual response. Request cancellation has no durability
    /// or remote-effect semantics.
    ///
    /// # Errors
    /// Rejects malformed requests and oversized declared responses; preserves
    /// transport failures. Later body failures are returned by the response stream.
    async fn send_stream(
        &self,
        request: StreamingHttpRequest,
        request_limits: HttpStreamLimits,
        response_limits: HttpStreamLimits,
    ) -> Result<StreamingHttpResponse, HttpStreamError>;
}

/// Distinguishes invalid bounds, failed transport and refused streaming data.
#[derive(Debug)]
pub enum HttpStreamError {
    /// Configured chunk and body bounds are zero or inconsistent.
    InvalidLimits,
    /// A producer yielded an empty chunk instead of data or explicit EOF.
    EmptyChunk,
    /// A body exceeds its configured byte allowance.
    Limit {
        /// Configured upper bound.
        maximum: u64,
        /// Actual observed or declared byte count, saturated on overflow.
        observed: u64,
    },
    /// A body was already refused and cannot supply further data or EOF evidence.
    Terminated,
    /// The selected HTTP binding could not represent or complete the exchange.
    Transport(HttpError),
}

impl fmt::Display for HttpStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid HTTP stream limits"),
            Self::EmptyChunk => formatter.write_str("HTTP body yielded an empty chunk"),
            Self::Limit { maximum, observed } => {
                write!(
                    formatter,
                    "HTTP body has {observed} bytes; limit is {maximum}"
                )
            }
            Self::Terminated => formatter.write_str("HTTP body was already refused"),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}

impl Error for HttpStreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

/// Enforces actual producer bounds before handing body chunks to a consumer.
///
/// The wrapper retains failures as failures on subsequent calls and reports EOF
/// only after its original source ends normally.
pub struct LimitedHttpBody {
    source: OwnedHttpBody,
    limits: HttpStreamLimits,
    consumed: u64,
    failed: bool,
    finished: bool,
}

impl LimitedHttpBody {
    /// Binds one owned source to already validated explicit limits.
    pub fn new(source: OwnedHttpBody, limits: HttpStreamLimits) -> Self {
        Self {
            source,
            limits,
            consumed: 0,
            failed: false,
            finished: false,
        }
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl HttpBodyStream for LimitedHttpBody {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, HttpStreamError> {
        if self.failed {
            return Err(HttpStreamError::Terminated);
        }
        if self.finished {
            return Ok(None);
        }
        let result = self.source.next().await.and_then(|chunk| {
            let Some(chunk) = chunk else {
                self.finished = true;
                return Ok(None);
            };
            let length = u64::try_from(chunk.len()).map_err(|_| HttpStreamError::Limit {
                maximum: self.limits.body_bytes,
                observed: u64::MAX,
            })?;
            if length == 0 {
                return Err(HttpStreamError::EmptyChunk);
            }
            if chunk.len() > self.limits.chunk_bytes {
                return Err(HttpStreamError::Limit {
                    maximum: self.limits.chunk_bytes as u64,
                    observed: length,
                });
            }
            let total = self
                .consumed
                .checked_add(length)
                .ok_or(HttpStreamError::Limit {
                    maximum: self.limits.body_bytes,
                    observed: u64::MAX,
                })?;
            if total > self.limits.body_bytes {
                return Err(HttpStreamError::Limit {
                    maximum: self.limits.body_bytes,
                    observed: total,
                });
            }
            self.consumed = total;
            Ok(Some(chunk))
        });
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}
