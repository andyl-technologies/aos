//! Portable contracts for immutable content, mutable refs, and host I/O.
//!
//! Backends and combinators implement the interfaces in specification 11.
//! Runtime bindings are selected through features (CRATE-6 to CRATE-8).

use std::error::Error;
use std::fmt;
use std::num::NonZeroU8;
use std::time::{Duration, SystemTime};

use terrane_core::identity::{Identity, IdentityKind};
use terrane_core::refs::{Locality, RefLogRecord, RefRecord};

/// Describes an exact range of immutable bytes (STORE-4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    /// The zero-based offset in the complete content.
    pub start: u64,
    /// The exact number of requested bytes.
    pub length: u64,
}

/// Names the verified mutable-ref mode (STORE-9, STORE-12).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefCapability {
    /// Whole-record CAS and log create-if-absent are atomic.
    Cas,
    /// Atomicity is unavailable; callers must enforce one writer.
    SingleWriter,
    /// This backend cannot hold refs.
    None,
}

/// Describes the backend's partial-read support (STORE-4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeCapability {
    /// A range within a pack can be served without reading the entire pack.
    Ranges,
    /// Only whole-object reads are supported.
    WholeObjectOnly,
}

/// Describes the durability scope of acknowledged writes (STORE-12).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Durability {
    /// Durable on one host.
    Local,
    /// Durable across one zone.
    Zone,
    /// Durable across one region.
    Region,
    /// Durable in the given number of independent regions.
    Regions(NonZeroU8),
}

/// Reports properties verified before a backend serves requests (STORE-12).
///
/// Combinators may narrow these values. In particular, an API that offers a
/// conditional method does not itself establish `RefCapability::Cas`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    /// The verified ref write mode.
    pub refs: RefCapability,
    /// The verified partial-read mode.
    pub ranges: RangeCapability,
    /// Whether presigned reads can be issued.
    pub presign: bool,
    /// Placement labels.
    pub locality: Locality,
    /// Acknowledged durability scope.
    pub durability: Durability,
    /// Whether sealed backing objects can be handed to surfaces.
    pub sealed: bool,
}

/// Names the closed set of store failures (STORE-30).
///
/// A CAS mismatch and a reflog collision carry their current values as
/// operation outcomes. Ref absence is `None` from `ref_get`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreErrorKind {
    /// Requested immutable content is not held.
    Absent(Identity),
    /// Stored bytes failed verification and cannot be returned.
    Corrupt(Identity),
    /// The backend cannot accept writes.
    ReadOnly,
    /// The guard denied a verb on a pattern without disclosing more detail.
    Denied { verb: &'static str, pattern: String },
    /// The backend is temporarily unreachable.
    Unavailable { retry_after: Option<Duration> },
    /// A reservation or quota would be exceeded.
    Capacity,
    /// Uploaded content violates the named rule.
    Invalid { rule_id: &'static str },
    /// A required backend capability is absent.
    Unsupported,
}

impl fmt::Display for StoreErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent(_) => f.write_str("content absent"),
            Self::Corrupt(_) => f.write_str("stored content corrupt"),
            Self::ReadOnly => f.write_str("store is read-only"),
            Self::Denied { verb, pattern } => write!(f, "{verb} denied on {pattern}"),
            Self::Unavailable { .. } => f.write_str("store unavailable"),
            Self::Capacity => f.write_str("store capacity exceeded"),
            Self::Invalid { rule_id } => write!(f, "content violates {rule_id}"),
            Self::Unsupported => f.write_str("store capability unsupported"),
        }
    }
}

/// Carries a store failure and an optional backend diagnostic (STORE-30).
///
/// The source chain never changes the public outcome used by a protocol or
/// surface. Translators inspect [`Self::kind`], not diagnostic text.
#[derive(Debug)]
pub struct StoreFailure {
    kind: StoreErrorKind,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl StoreFailure {
    /// Creates a failure with a specified outcome.
    #[must_use]
    pub fn new(kind: StoreErrorKind) -> Self {
        Self { kind, source: None }
    }

    /// Attaches a backend diagnostic while preserving the outcome.
    #[must_use]
    pub fn with_source<E>(kind: StoreErrorKind, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            kind,
            source: Some(Box::new(source)),
        }
    }

    /// Returns the stable outcome for surface or protocol mapping.
    #[must_use]
    pub fn kind(&self) -> &StoreErrorKind {
        &self.kind
    }
}

impl fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)
    }
}

impl Error for StoreFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as &dyn Error)
    }
}

/// Selects an identity domain and digest prefix for advisory listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityPrefix {
    /// The identity domain.
    pub kind: IdentityKind,
    /// Leading digest bytes, empty for the entire domain.
    pub digest_prefix: Vec<u8>,
}

/// Makes verified capabilities available before any store request (STORE-12).
pub trait CapabilityReport {
    /// Returns the capabilities established when this backend opened.
    fn capabilities(&self) -> &Capabilities;
}

/// Stores immutable content without granting any ref authority (STORE-32).
///
/// Implementations satisfy STORE-1 through STORE-6, STORE-11, and STORE-33.
/// `put` validates an upload before it becomes visible, computes its identity,
/// and leaves existing bytes unchanged on a dedup hit. `get` verifies stored
/// bytes before returning even a partial range. `has` returns one bit per
/// input, in order, and only claims content that `get` can serve now. `list`
/// is advisory and only for recovery, GC, or scrub.
///
/// A content-only caller has no ref methods:
///
/// ```compile_fail
/// use terrane::store::{ContentStore, StoreFailure};
///
/// async fn cannot_advance_ref<S: ContentStore>(cache: &S) -> Result<(), StoreFailure> {
///     cache.ref_get("refs/heads/main").await?;
///     Ok(())
/// }
/// ```
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait ContentStore: CapabilityReport {
    /// Validates and idempotently stores bytes under their computed identity.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` for a failed rule, `ReadOnly` for a non-writing
    /// backend, or another specified failure if admission fails.
    async fn put(&self, kind: IdentityKind, bytes: &[u8]) -> Result<Identity, StoreFailure>;

    /// Returns verified bytes or exactly the requested byte range.
    ///
    /// # Errors
    ///
    /// Returns `Absent` if content is not held, `Corrupt` on verification
    /// failure, `Unsupported` if a range cannot be served, or another
    /// specified failure if retrieval fails.
    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure>;

    /// Tests many identities, preserving their input order.
    ///
    /// # Errors
    ///
    /// Returns a specified failure if membership cannot be determined.
    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure>;

    /// Lists advisory identities for recovery, GC, or scrub only.
    ///
    /// # Errors
    ///
    /// Returns a specified failure if listing cannot be completed.
    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure>;
}

/// Reports the outcome of a whole-record ref compare-and-swap (STORE-7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefCasOutcome {
    /// The expected record matched and the new record was written.
    Applied,
    /// The expectation failed; this was the current record, if any.
    Conflict(Option<RefRecord>),
}

/// Reports the outcome of a create-if-absent reflog append (STORE-8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefLogAppendOutcome {
    /// The record was written exactly once.
    Appended,
    /// The `(name, seq)` key already existed and was not changed.
    Exists,
}

/// Streams ordered reflog records without selecting a runtime (STORE-32).
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait RefWatch {
    /// Returns the next record, or `None` when the watch is closed.
    ///
    /// # Errors
    ///
    /// Returns a specified store failure when watching cannot continue.
    async fn next(&mut self) -> Result<Option<RefLogRecord>, StoreFailure>;
}

/// Holds mutable refs without exposing immutable content operations (STORE-32).
///
/// Implementations must provide whole-record atomic CAS or report
/// `single-writer` at open time (STORE-7, STORE-9). Appends are create-if-absent
/// on `(name, seq)` (STORE-8); reads and watches preserve sequence order.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait RefStore: CapabilityReport {
    /// The stream returned when a caller watches a ref.
    type Watch: RefWatch;

    /// Reads the current record, or `None` if the ref is absent.
    ///
    /// # Errors
    ///
    /// Returns a specified store failure if the ref cannot be read.
    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure>;

    /// Atomically swaps a whole ref record when `expect` matches.
    ///
    /// # Errors
    ///
    /// Returns a specified store failure if the CAS cannot be attempted.
    /// A mismatch is `Conflict(current)`, not a transport error.
    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure>;

    /// Creates a reflog entry at `(name, seq)` without replacing one.
    ///
    /// # Errors
    ///
    /// Returns a specified store failure if the append cannot be attempted.
    /// An existing key returns `Exists` without modifying that record.
    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure>;

    /// Reads reflog records at or after `from_seq` in sequence order.
    ///
    /// # Errors
    ///
    /// Returns a specified store failure for a read error or a sequence gap.
    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure>;

    /// Starts watching reflog records at or after `from_seq`.
    ///
    /// # Errors
    ///
    /// Returns a specified store failure if the watch cannot start.
    async fn ref_watch(&self, name: &str, from_seq: u64) -> Result<Self::Watch, StoreFailure>;
}

/// Combines immutable content with mutable-ref authority (STORE-32).
pub trait Store: ContentStore + RefStore {}

impl<T> Store for T where T: ContentStore + RefStore {}

/// Describes a transport request without binding a network runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    /// The HTTP method token.
    pub method: String,
    /// The complete request URL.
    pub url: String,
    /// Header names and raw values, preserving repeated names and bytes.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The request body.
    pub body: Vec<u8>,
}

/// Describes a raw HTTP response, including non-success statuses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    /// The numeric status.
    pub status: u16,
    /// Header names and raw values, preserving repeated names and bytes.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The response body.
    pub body: Vec<u8>,
}

/// Classifies failures from an HTTP binding before a store maps them.
#[derive(Debug)]
pub enum HttpError {
    /// The request cannot be represented by the selected transport.
    InvalidRequest(Box<dyn Error + Send + Sync>),
    /// The transport could not complete a valid request.
    Unavailable(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(_) => f.write_str("invalid HTTP request"),
            Self::Unavailable(_) => f.write_str("HTTP transport unavailable"),
        }
    }
}

impl Error for HttpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRequest(source) | Self::Unavailable(source) => Some(source.as_ref()),
        }
    }
}

/// Supplies HTTP transport without selecting a runtime (CRATE-7).
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait HttpClient {
    /// Sends a request and returns its raw response.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the request cannot be sent or received.
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError>;
}

/// Supplies wall-clock time without selecting a host binding (CRATE-7).
pub trait Clock {
    /// Returns the current wall-clock time.
    fn now(&self) -> SystemTime;
}

/// Supplies a WebAssembly host's fetch and time primitives (CRATE-8).
///
/// A host implementation binds these methods to its platform APIs. The
/// adapter below gives library callers the same [`HttpClient`] and [`Clock`]
/// contracts used by native callers, without requiring a second identity or
/// store implementation.
#[cfg(feature = "wasm")]
#[async_trait::async_trait(?Send)]
pub trait WasmHost {
    /// Fetches an HTTP request through the host's fetch primitive.
    ///
    /// # Errors
    ///
    /// Returns a typed transport failure if the host rejects the request or
    /// cannot deliver a response.
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpError>;

    /// Returns the host's current wall-clock time.
    fn now(&self) -> SystemTime;
}

/// Adapts one WebAssembly host to the portable HTTP and clock contracts.
#[cfg(feature = "wasm")]
#[derive(Clone, Debug)]
pub struct WasmBindings<H> {
    host: H,
}

#[cfg(feature = "wasm")]
impl<H> WasmBindings<H> {
    /// Selects the host binding for this I/O consumer.
    #[must_use]
    pub fn new(host: H) -> Self {
        Self { host }
    }
}

// A WebAssembly fetch future may be !Send. A consumer enabling `send` selects
// the native binding; `wasm` and `tokio` may coexist in an all-features build.
#[cfg(all(feature = "wasm", not(feature = "send")))]
#[async_trait::async_trait(?Send)]
impl<H: WasmHost> HttpClient for WasmBindings<H> {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.host.fetch(request).await
    }
}

#[cfg(feature = "wasm")]
impl<H: WasmHost> Clock for WasmBindings<H> {
    fn now(&self) -> SystemTime {
        self.host.now()
    }
}

/// Supplies filesystem operations only under `std` (CRATE-7).
#[cfg(feature = "std")]
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait LocalFs {
    /// Reads a complete file.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if the file cannot be read.
    async fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>>;

    /// Creates a new file without replacing an existing one.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if the file exists or cannot be written.
    async fn write_new(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()>;

    /// Renames one path within a filesystem.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if the rename cannot complete.
    async fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()>;
}

/// Binds portable HTTP transport to the native runtime (CRATE-8).
#[cfg(feature = "tokio")]
#[derive(Clone, Debug)]
pub struct TokioHttpClient {
    client: reqwest::Client,
}

#[cfg(feature = "tokio")]
impl TokioHttpClient {
    /// Wraps an already configured native HTTP client.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl HttpClient for TokioHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|source| HttpError::InvalidRequest(Box::new(source)))?;
        let mut outgoing = self.client.request(method, request.url);

        for (name, value) in request.headers {
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|source| HttpError::InvalidRequest(Box::new(source)))?;
            let value = reqwest::header::HeaderValue::from_bytes(&value)
                .map_err(|source| HttpError::InvalidRequest(Box::new(source)))?;
            outgoing = outgoing.header(name, value);
        }

        let response = outgoing
            .body(request.body)
            .send()
            .await
            .map_err(|source| HttpError::Unavailable(Box::new(source)))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|source| HttpError::Unavailable(Box::new(source)))?;

        Ok(HttpResponse {
            status,
            headers,
            body: body.to_vec(),
        })
    }
}

/// Binds portable wall-clock reads to the native host (CRATE-8).
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioClock;

#[cfg(feature = "tokio")]
impl Clock for TokioClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Binds portable file operations to the native runtime (CRATE-8).
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioLocalFs;

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl LocalFs for TokioLocalFs {
    async fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        tokio::fs::read(path).await
    }

    async fn write_new(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await?;
        file.write_all(bytes).await?;
        file.sync_all().await
    }

    async fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
        tokio::fs::rename(from, to).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll_ready<F: std::future::Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Waker};

        let mut future = Box::pin(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test host must complete synchronously"),
        }
    }

    struct ContentOnlyCache {
        capabilities: Capabilities,
    }

    impl CapabilityReport for ContentOnlyCache {
        fn capabilities(&self) -> &Capabilities {
            &self.capabilities
        }
    }

    #[cfg_attr(feature = "send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
    impl ContentStore for ContentOnlyCache {
        async fn put(&self, _kind: IdentityKind, _bytes: &[u8]) -> Result<Identity, StoreFailure> {
            Err(StoreFailure::new(StoreErrorKind::ReadOnly))
        }

        async fn get(
            &self,
            identity: &Identity,
            _range: Option<ByteRange>,
        ) -> Result<Vec<u8>, StoreFailure> {
            Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())))
        }

        async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
            Ok(vec![false; identities.len()])
        }

        async fn list(&self, _prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn error_outcomes_preserve_sources_without_changing_category() {
        let source = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "backend detail");
        let failure = StoreFailure::with_source(StoreErrorKind::ReadOnly, source);

        assert_eq!(failure.kind(), &StoreErrorKind::ReadOnly);
        assert_eq!(failure.to_string(), "store is read-only");
        assert_eq!(
            failure.source().map(ToString::to_string).as_deref(),
            Some("backend detail")
        );
    }

    #[test]
    fn conflict_and_existing_log_are_distinct_from_backend_failure() {
        let conflict = RefCasOutcome::Conflict(None);
        let duplicate = RefLogAppendOutcome::Exists;

        assert!(matches!(conflict, RefCasOutcome::Conflict(None)));
        assert_eq!(duplicate, RefLogAppendOutcome::Exists);
    }

    #[test]
    fn content_only_cache_implements_no_ref_authority() {
        fn accepts_content_store<S: ContentStore>(_: &S) {}

        let cache = ContentOnlyCache {
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::Ranges,
                presign: false,
                locality: Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
        };

        accepts_content_store(&cache);
        assert_eq!(cache.capabilities().refs, RefCapability::None);
        assert!(poll_ready(cache.has(&[])).unwrap().is_empty());
    }

    #[cfg(all(feature = "wasm", not(feature = "send")))]
    #[test]
    fn wasm_binding_forwards_fetch_and_host_time() {
        struct TestHost;

        #[async_trait::async_trait(?Send)]
        impl WasmHost for TestHost {
            async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
                Ok(HttpResponse {
                    status: 206,
                    headers: vec![],
                    body: request.body,
                })
            }

            fn now(&self) -> SystemTime {
                SystemTime::UNIX_EPOCH + Duration::from_secs(42)
            }
        }

        let binding = WasmBindings::new(TestHost);
        let request = HttpRequest {
            method: "POST".to_owned(),
            url: "https://example.invalid".to_owned(),
            headers: vec![],
            body: b"payload".to_vec(),
        };

        let response = poll_ready(binding.send(request)).unwrap();
        assert_eq!(response.status, 206);
        assert_eq!(response.body, b"payload");
        assert_eq!(
            binding.now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(42)
        );
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn native_create_new_preserves_existing_bytes() {
        let path =
            std::env::temp_dir().join(format!("terrane-store-create-new-{}", std::process::id()));
        let fs = TokioLocalFs;

        fs.write_new(&path, b"first").await.unwrap();
        let second = fs.write_new(&path, b"second").await;
        assert_eq!(
            second.unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs.read(&path).await.unwrap(), b"first");

        tokio::fs::remove_file(path).await.unwrap();
    }
}
