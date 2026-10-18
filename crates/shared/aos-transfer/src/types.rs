//! Core types for the transfer engine.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncRead;

/// HTTP-like method for transfers.
///
/// Non-HTTP protocols map these onto their closest native operation
/// (e.g. for SFTP, `Get` is a remote read, `Head` is a `stat`, and
/// `Delete` is an `unlink`). Not every protocol supports every method;
/// unsupported combinations produce an error at execution time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Download data (HTTP GET, S3 GetObject, SFTP read, file read).
    Get,
    /// Upload data (HTTP PUT, S3 PutObject, SFTP write, file write).
    Put,
    /// Check existence and size without transferring the body.
    Head,
    /// Delete the remote object or file.
    Delete,
    /// Submit data (HTTP only; other protocols reject POST).
    Post,
}

/// The body to send with a transfer request.
pub enum TransferBody {
    /// Upload from a local file.
    File(PathBuf),
    /// Upload raw bytes.
    Bytes(Vec<u8>),
    /// Upload from an async stream. Not all protocols accept a stream
    /// body via [`Protocol::execute`](crate::protocol::Protocol::execute);
    /// prefer [`TransferBody::File`] or [`TransferBody::Bytes`] where
    /// possible.
    Stream(Box<dyn AsyncRead + Send + Sync + Unpin>),
}

impl std::fmt::Debug for TransferBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(p) => f.debug_tuple("File").field(p).finish(),
            Self::Bytes(b) => f.debug_tuple("Bytes").field(&b.len()).finish(),
            Self::Stream(_) => f.debug_tuple("Stream").finish(),
        }
    }
}

/// Callback invoked for each streamed transfer chunk.
pub type TransferCallback = dyn Fn(&[u8]) -> anyhow::Result<()> + Send + Sync;

/// A replayable streaming destination for managed downloads.
///
/// Unlike a plain callback, a sink exposes its committed byte position. The
/// transfer engine can therefore issue a new ranged request after a transient
/// response-body failure without replaying bytes already accepted by the
/// destination. Implementations commonly retain an already-open file
/// descriptor when path lookup would be unsafe.
pub trait TransferSink: Send + Sync {
    /// Returns the number of bytes durably accepted by the sink.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination position cannot be inspected.
    fn position(&self) -> anyhow::Result<u64>;

    /// Appends one response chunk to the sink.
    ///
    /// # Errors
    ///
    /// Returns an error when the chunk cannot be committed.
    fn write(&self, bytes: &[u8]) -> anyhow::Result<()>;

    /// Flushes buffered destination state after a successful response.
    ///
    /// # Errors
    ///
    /// Returns an error when buffered state cannot be flushed.
    fn flush(&self) -> anyhow::Result<()>;
}

/// Where to write the transfer output.
pub enum TransferOutput {
    /// Write to a local file (supports resume).
    File(PathBuf),
    /// Buffer the entire response in memory and return in `TransferResult::body`.
    Memory,
    /// Stream chunks to a callback.
    Callback(Box<TransferCallback>),
    /// Stream chunks to a replayable destination.
    Sink(Arc<dyn TransferSink>),
}

impl std::fmt::Debug for TransferOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(p) => f.debug_tuple("File").field(p).finish(),
            Self::Memory => write!(f, "Memory"),
            Self::Callback(_) => write!(f, "Callback"),
            Self::Sink(_) => write!(f, "Sink"),
        }
    }
}

/// Hash algorithm for verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (32-byte digest, 64 hex characters).
    Sha256,
    /// SHA-512 (64-byte digest, 128 hex characters).
    Sha512,
}

/// Expected hash for verification during transfer.
#[derive(Debug, Clone)]
pub struct HashSpec {
    /// The hash algorithm to use.
    pub algorithm: HashAlgorithm,
    /// Hex-encoded expected hash value. A `"sha256:"` or `"sha512:"`
    /// prefix is accepted and stripped before comparison.
    pub expected: String,
}

/// A request to transfer data.
///
/// Construct one with the convenience constructors ([`get`],
/// [`get_to_file`], [`put`], [`put_file`], [`post`], [`head`]) and
/// refine it with the builder-style `with_*` methods, or build the
/// struct literally for full control.
///
/// [`get`]: TransferRequest::get
/// [`get_to_file`]: TransferRequest::get_to_file
/// [`put`]: TransferRequest::put
/// [`put_file`]: TransferRequest::put_file
/// [`post`]: TransferRequest::post
/// [`head`]: TransferRequest::head
#[derive(Debug)]
pub struct TransferRequest {
    /// The URL to transfer to/from.
    pub url: String,
    /// The HTTP method (or equivalent for non-HTTP protocols).
    pub method: Method,
    /// Additional headers to send.
    pub headers: Vec<(String, String)>,
    /// Request body for PUT requests.
    pub body: Option<TransferBody>,
    /// Expected hash for download verification.
    pub hash: Option<HashSpec>,
    /// Maximum response-body bytes accepted before the transfer is aborted.
    pub maximum_bytes: Option<u64>,
    /// Required complete response size, including any resumed prefix.
    pub expected_size: Option<u64>,
    /// Whether to attempt resuming a partial download. Only effective
    /// for protocols that support ranged reads and when `output` is a
    /// [`TransferOutput::File`] or [`TransferOutput::Sink`]. The destination's
    /// current size or position is used as the resume offset.
    pub resume: bool,
    /// Where to write the output.
    pub output: TransferOutput,
}

impl TransferRequest {
    /// Create a simple GET request that buffers the response in memory.
    pub fn get(url: &str) -> Self {
        Self {
            url: url.to_string(),
            method: Method::Get,
            headers: Vec::new(),
            body: None,
            hash: None,
            maximum_bytes: None,
            expected_size: None,
            resume: false,
            output: TransferOutput::Memory,
        }
    }

    /// Create a GET request that writes to a file.
    pub fn get_to_file(url: &str, path: PathBuf) -> Self {
        Self {
            url: url.to_string(),
            method: Method::Get,
            headers: Vec::new(),
            body: None,
            hash: None,
            maximum_bytes: None,
            expected_size: None,
            resume: false,
            output: TransferOutput::File(path),
        }
    }

    /// Create a PUT request with bytes body.
    pub fn put(url: &str, data: Vec<u8>) -> Self {
        Self {
            url: url.to_string(),
            method: Method::Put,
            headers: Vec::new(),
            body: Some(TransferBody::Bytes(data)),
            hash: None,
            maximum_bytes: None,
            expected_size: None,
            resume: false,
            output: TransferOutput::Memory,
        }
    }

    /// Create a PUT request with a local file body.
    pub fn put_file(url: &str, path: PathBuf) -> Self {
        Self {
            url: url.to_string(),
            method: Method::Put,
            headers: Vec::new(),
            body: Some(TransferBody::File(path)),
            hash: None,
            maximum_bytes: None,
            expected_size: None,
            resume: false,
            output: TransferOutput::Memory,
        }
    }

    /// Create a POST request with bytes body.
    pub fn post(url: &str, data: Vec<u8>) -> Self {
        Self {
            url: url.to_string(),
            method: Method::Post,
            headers: Vec::new(),
            body: Some(TransferBody::Bytes(data)),
            hash: None,
            maximum_bytes: None,
            expected_size: None,
            resume: false,
            output: TransferOutput::Memory,
        }
    }

    /// Create a HEAD request.
    pub fn head(url: &str) -> Self {
        Self {
            url: url.to_string(),
            method: Method::Head,
            headers: Vec::new(),
            body: None,
            hash: None,
            maximum_bytes: None,
            expected_size: None,
            resume: false,
            output: TransferOutput::Memory,
        }
    }

    /// Enable resume for this request.
    pub fn with_resume(mut self) -> Self {
        self.resume = true;
        self
    }

    /// Set hash verification for this request.
    pub fn with_hash(mut self, algorithm: HashAlgorithm, expected: &str) -> Self {
        self.hash = Some(HashSpec {
            algorithm,
            expected: expected.to_string(),
        });
        self
    }

    /// Limit the number of response-body bytes the transfer may consume.
    pub fn with_maximum_bytes(mut self, maximum_bytes: u64) -> Self {
        self.maximum_bytes = Some(maximum_bytes);
        self
    }

    /// Requires the complete response to contain exactly `expected_size` bytes.
    pub fn with_expected_size(mut self, expected_size: u64) -> Self {
        self.expected_size = Some(expected_size);
        self
    }

    /// Add a header to this request.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// The result of a completed transfer.
#[derive(Debug)]
pub struct TransferResult {
    /// HTTP status code (or equivalent).
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Content-Length from the response, if available.
    pub content_length: Option<u64>,
    /// Response body bytes (populated when output is `Memory`).
    pub body: Option<Vec<u8>>,
    /// Computed hash hex string (if `HashSpec` was provided).
    pub hash: Option<String>,
    /// Whether this transfer was resumed from a partial file.
    pub resumed: bool,
}

impl TransferResult {
    /// Get the body as a UTF-8 string, if available.
    ///
    /// Returns `None` when no body was buffered (the output was not
    /// [`TransferOutput::Memory`]) or when the body is not valid UTF-8.
    pub fn body_string(&self) -> Option<String> {
        self.body
            .as_ref()
            .and_then(|b| String::from_utf8(b.clone()).ok())
    }

    /// Get a response header value by name (case-insensitive).
    ///
    /// Returns the first matching header, or `None` if absent.
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_constructor_sets_method_and_body() {
        let req = TransferRequest::post("http://example.com/x", vec![1, 2, 3]);
        assert_eq!(req.method, Method::Post);
        assert_eq!(req.url, "http://example.com/x");
        match req.body {
            Some(TransferBody::Bytes(b)) => assert_eq!(b, vec![1, 2, 3]),
            _ => panic!("expected Bytes body"),
        }
    }
}
