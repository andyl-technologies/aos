//! Portable contracts for immutable content, mutable refs, and host I/O.
//!
//! Backends and combinators implement the interfaces in specification 11.
//! Runtime bindings are selected through features (CRATE-6 to CRATE-8).

// An I/O consumer selects one binding. Library-only builds may select none.
#[cfg(all(feature = "tokio", feature = "wasm"))]
compile_error!("CRATE-8: tokio and wasm are mutually exclusive I/O bindings");

#[cfg(all(feature = "wasm", feature = "send"))]
compile_error!("CRATE-7: wasm host futures do not support the send feature");

#[cfg(feature = "std")]
mod native_clock;
#[cfg(feature = "std")]
mod native_effect;
#[cfg(feature = "std")]
pub(crate) mod protected_read;

#[cfg(feature = "std")]
pub use native_clock::NativeEffectClock;
#[cfg(feature = "std")]
pub(crate) use native_effect::initialization::request_for_open as native_initialization_request;
#[cfg(feature = "std")]
pub use native_effect::initialization::{
    NativePendingRoot, NativePublicationInitialization, NativePublicationInitializationOutcome,
};
#[cfg(feature = "std")]
pub(crate) use native_effect::publication as native_publication_effects;
#[cfg(all(feature = "std", test))]
pub(crate) use native_effect::{EffectFault, EffectFaultProbe};
#[cfg(feature = "std")]
pub use native_effect::{NativeEffectFailure, NativeExclusion, NativeFsEffect};
#[cfg(feature = "std")]
pub use protected_read::{NativeProtectedRead, NativeProtectedRecord};

use std::error::Error;
use std::fmt;
use std::num::NonZeroU8;
use std::time::{Duration, SystemTime};

use terrane_core::chunking::ChunkProfile;
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

/// Distinguishes the two diagnostics carried by `invalid` (STORE-30).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidReason {
    /// Uploaded bytes failed the named validation rule.
    Upload { rule_id: &'static str },
    /// A request asks for bytes beyond the content boundary.
    Range(ByteRange),
    /// A request cannot be decoded or exceeds a protocol limit.
    MalformedRequest,
}

/// Identifies stored data that failed verification (STORE-30).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorruptSubject {
    /// An immutable object failed its identity or encoding check.
    Identity(Identity),
    /// A mutable ref or its reflog failed validation.
    RefName(String),
}

/// Names the closed set of store failures (STORE-30).
///
/// A CAS mismatch and a reflog collision carry their current values as
/// operation outcomes. Ref absence is `None` from `ref_get`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreErrorKind {
    /// Requested immutable content is not held.
    Absent(Identity),
    /// Stored immutable content, a ref, or a reflog failed verification.
    Corrupt(CorruptSubject),
    /// The backend cannot accept writes.
    ReadOnly,
    /// The guard denied a verb on a pattern without disclosing more detail.
    Denied { verb: &'static str, pattern: String },
    /// The backend is temporarily unreachable.
    Unavailable { retry_after: Option<Duration> },
    /// A reservation or quota would be exceeded.
    Capacity,
    /// Uploaded content or a requested range is invalid.
    Invalid(InvalidReason),
    /// A required backend capability is absent.
    Unsupported,
}

impl fmt::Display for StoreErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent(_) => f.write_str("content absent"),
            Self::Corrupt(_) => f.write_str("stored data corrupt"),
            Self::ReadOnly => f.write_str("store is read-only"),
            Self::Denied { verb, pattern } => write!(f, "{verb} denied on {pattern}"),
            Self::Unavailable { .. } => f.write_str("store unavailable"),
            Self::Capacity => f.write_str("store capacity exceeded"),
            Self::Invalid(InvalidReason::Upload { rule_id }) => {
                write!(f, "content violates {rule_id}")
            }
            Self::Invalid(InvalidReason::Range(_)) => f.write_str("range beyond content end"),
            Self::Invalid(InvalidReason::MalformedRequest) => f.write_str("malformed request"),
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
    ///
    /// Denials discard the diagnostic so callers cannot inspect policy detail.
    #[must_use]
    pub fn with_source<E>(kind: StoreErrorKind, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        // A denial must disclose only its verb and pattern, even to callers
        // that inspect the source chain (STORE-30).
        if matches!(kind, StoreErrorKind::Denied { .. }) {
            return Self::new(kind);
        }

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

/// Identifies a chunk's role in its object for admission checks (CDC-15, CDC-16).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkPosition {
    /// The chunk must end at the first valid chunker boundary.
    NonFinal,
    /// The chunk ends its object and may be shorter than the profile minimum.
    Final,
}

/// Carries a configured validator's opaque chunk dependency declaration.
///
/// The validator interprets metadata and returns these declarations. A backend
/// checks the named bytes against its actual catalog and chunk profile before
/// admitting metadata, including on dedup hits; it does not parse the schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkRequirement {
    /// The required plaintext identity in the chunk domain.
    pub identity: Identity,
    /// The exact plaintext length bounding decompression.
    pub declared_plaintext_len: usize,
    /// The chunk's final or nonfinal position in the declared object.
    pub position: ChunkPosition,
    /// The metadata rule violated when this dependency is absent.
    pub missing_rule_id: &'static str,
}

/// Supplies the context required to verify an encoded chunk before admission.
#[derive(Clone, Copy, Debug)]
pub struct ChunkUpload<'a> {
    /// The codec byte and encoded body to retain after verification.
    pub encoded: &'a [u8],
    /// The offered plaintext identity in the chunk domain (CDC-14).
    pub identity: &'a Identity,
    /// The exact plaintext length bounding decompression (CDC-12).
    pub declared_plaintext_len: usize,
    /// The object's final or nonfinal chunk position (CDC-15, CDC-16).
    pub position: ChunkPosition,
    /// The chunking profile, which the backend must match to its configuration.
    pub profile: &'a ChunkProfile,
}

/// Carries opaque meta bytes under a non-chunk identity domain.
///
/// Construction validates only the domain. The admitting backend must invoke
/// its configured [`ContentValidator`] before making new bytes visible.
#[derive(Clone, Copy, Debug)]
pub struct MetaUpload<'a> {
    kind: IdentityKind,
    bytes: &'a [u8],
}

impl<'a> MetaUpload<'a> {
    /// Constructs an opaque upload under a non-chunk identity domain.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(MalformedRequest)` when `kind` is the chunk domain,
    /// because chunk admission requires [`ChunkUpload`] context.
    pub fn new(kind: IdentityKind, bytes: &'a [u8]) -> Result<Self, StoreFailure> {
        if kind == IdentityKind::Chunk {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::MalformedRequest,
            )));
        }

        Ok(Self { kind, bytes })
    }

    /// Returns the non-chunk identity domain.
    #[must_use]
    pub fn kind(&self) -> IdentityKind {
        self.kind
    }

    /// Returns the opaque encoded bytes.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// Distinguishes chunk admission context from opaque meta uploads (STORE-33).
#[derive(Clone, Copy, Debug)]
pub enum ContentUpload<'a> {
    /// Encoded chunk bytes and their independent admission declarations.
    Chunk(ChunkUpload<'a>),
    /// Opaque meta bytes, requiring the configured format validator.
    Meta(MetaUpload<'a>),
}

/// Delegates pure meta-format validation without interpreting storage content.
///
/// Formats or repository code supplies this validator when a backend opens.
/// The backend must invoke it before admitting new meta bytes (STORE-33),
/// retain failures as `Invalid(Upload)` with the failing rule ID, and never
/// substitute a validator supplied by an upload request. The validator owns
/// schema interpretation; the backend owns visibility and identity (ARCH-2).
pub trait ContentValidator {
    /// Validates an opaque upload against its domain's registered canonical format.
    ///
    /// Pack and index encodings are binary; CBOR is required only for domains
    /// whose registered schemas specify it. The validator owns that distinction.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` when the bytes violate a format rule. Any
    /// failure prevents admission; it cannot be treated as successful validation.
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure>;

    /// Returns the chunk declarations required by validated opaque metadata.
    ///
    /// Backends invoke this configured validator for every metadata upload and
    /// verify each returned declaration before deduplication or publication.
    /// Validators for reference-bearing schemas, such as manifests, override
    /// this method. The default is appropriate for schemas without chunk refs.
    /// Requests cannot supply a replacement validator or declaration list.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` if the metadata cannot supply valid declarations,
    /// preserving the failed format rule. Any failure prevents admission.
    fn chunk_requirements(
        &self,
        _upload: &MetaUpload<'_>,
    ) -> Result<Vec<ChunkRequirement>, StoreFailure> {
        Ok(Vec::new())
    }
}

/// Stores immutable content without granting any ref authority (STORE-32).
///
/// Implementations satisfy STORE-1 through STORE-6, STORE-11, and STORE-33.
/// `put` validates an upload before it becomes visible, computes its identity,
/// and leaves existing bytes unchanged on a dedup hit. A backend matches the
/// chunk profile to its configuration and validates encoded chunks using their
/// offered identity, declared length, and position. A prior final-chunk admit
/// does not establish a later nonfinal boundary: the backend must check that
/// boundary before accepting such an offer. Meta validation is delegated to
/// the backend's configured [`ContentValidator`], never trusted to the caller.
/// `get` verifies stored bytes before returning even a partial range. `has` returns one bit per
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
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure>;

    /// Returns the opaque stored encoding or an exact range within it.
    ///
    /// A chunk result includes its codec byte and encoded body, not decoded
    /// plaintext. Its identity is verified against the plaintext before bytes
    /// are returned. Other results retain their registered canonical encoded bytes. Ranges
    /// address the stored encoding, including encoded chunk bodies within packs.
    ///
    /// # Errors
    ///
    /// Returns `Absent` if content is not held, `Corrupt` on verification
    /// failure, `Invalid(Range)` when the range exceeds content, `Unsupported`
    /// if ranges are unavailable, or another specified retrieval failure.
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
    Conflict(Option<Box<RefRecord>>),
}

/// Reports the outcome of a create-if-absent reflog append (STORE-8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefLogAppendOutcome {
    /// The record was written exactly once.
    Appended,
    /// The exact legacy or candidate key already existed and was not changed.
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
/// on `(name, seq, candidate_id)` for new proposals or `(name, seq)` for
/// legacy records (STORE-8); reads and watches expose committed history in
/// sequence order.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait RefStore: CapabilityReport {
    /// The stream returned when a caller watches a ref.
    type Watch: RefWatch;

    /// Reads the current record, or `None` if the ref is absent.
    ///
    /// # Errors
    ///
    /// Returns `Corrupt(RefName)` for an invalid stored record, or another
    /// specified failure if the ref cannot be read.
    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure>;

    /// Atomically swaps a whole ref record when `expect` matches.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(MalformedRequest)` for a non-successor record, or
    /// another specified failure if the CAS cannot be attempted.
    /// A mismatch is `Conflict(current)`, not a transport error. A branch
    /// authority validates the exact selected proposal against `expect` and
    /// `new` before publication (REF-12). An authority
    /// validates sequence, epoch, and home transitions at this write boundary
    /// with [`RefRecord::validate_successor`], even if the caller constructed
    /// `new` directly.
    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure>;

    /// Creates an immutable reflog proposal without replacing its exact key.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(MalformedRequest)` if the record's sequence differs
    /// from `seq`, or another specified failure if append cannot be attempted.
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
    /// A gap is `Corrupt(RefName)` because the request itself is valid.
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
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait Clock {
    /// Returns the current wall-clock time.
    fn now(&self) -> SystemTime;

    /// Returns ticks since an arbitrary monotonic origin for elapsed time.
    ///
    /// Callers compare values from the same clock instance; they never persist
    /// a tick or compare it with wall time.
    fn monotonic(&self) -> Duration;

    /// Retains this binding's exact clock state for queued native final checks.
    ///
    /// This optional synchronous hook returns an opaque owned adapter. It adds
    /// no `Clone`, `Sync`, `Send`, or `'static` bound to this trait or to generic
    /// clock consumers. The default refuses without effects.
    ///
    /// # Errors
    /// Returns `Unsupported` when the binding cannot retain its actual state.
    #[cfg(feature = "std")]
    fn retain_native_clock(&self) -> std::io::Result<NativeEffectClock> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "retained native clock unavailable",
        ))
    }

    /// Waits for at least the requested elapsed duration through the host timer.
    ///
    /// A clock that supplies timestamps alone explicitly refuses timer use.
    ///
    /// # Errors
    /// Returns an I/O error if the timer is unavailable or cannot represent
    /// the requested duration. The default reports `Unsupported`.
    ///
    /// # Panics
    /// A native Tokio binding requires a runtime with its time driver enabled.
    async fn sleep(&self, _duration: Duration) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "host timer unavailable",
        ))
    }
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

    /// Returns the host's monotonic ticks from an arbitrary origin.
    fn monotonic(&self) -> Duration;

    /// Waits through the WebAssembly host's timer primitive.
    ///
    /// # Errors
    /// Returns a host timer failure; the default reports `Unsupported`.
    async fn sleep(&self, _duration: Duration) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "host timer unavailable",
        ))
    }
}

/// Adapts one WebAssembly host to the portable HTTP and clock contracts.
///
/// Consumers enable `wasm` without `tokio` or `send`: host fetch futures
/// may remain on their host thread (CRATE-7, CRATE-8).
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

// A WebAssembly fetch future may be !Send and remains on its host thread.
#[cfg(all(feature = "wasm", not(feature = "send")))]
#[async_trait::async_trait(?Send)]
impl<H: WasmHost> HttpClient for WasmBindings<H> {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.host.fetch(request).await
    }
}

#[cfg(feature = "wasm")]
#[async_trait::async_trait(?Send)]
impl<H: WasmHost> Clock for WasmBindings<H> {
    fn now(&self) -> SystemTime {
        self.host.now()
    }

    fn monotonic(&self) -> Duration {
        self.host.monotonic()
    }

    async fn sleep(&self, duration: Duration) -> std::io::Result<()> {
        self.host.sleep(duration).await
    }
}

/// Supplies filesystem operations only under `std` (CRATE-7).
#[cfg(feature = "std")]
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait LocalFs {
    /// Runs the private fresh-root creator with owned native retention.
    ///
    /// The binding submits one fixed program before the first root mutation.
    /// Its worker retains actual opened directory descriptors independently of
    /// acquired exclusions through durable Pending and complete genesis staging.
    /// Cancellation of the asynchronous waiter must not release those inputs
    /// while physical work remains. An existing root grants no freshness.
    /// The default refuses before creating any directory or coordination inode.
    ///
    /// # Errors
    /// Returns `Unsupported` when retained native initialization is unavailable,
    /// and preserves unsafe or replaced physical input, incomplete staging and
    /// genuine I/O, durability or worker failures.
    async fn initialize_publication(
        &self,
        _request: NativePublicationInitialization,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }

    /// Obtains cryptographically secure bytes from the platform entropy source.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the requested buffer cannot be allocated or
    /// the platform cannot supply secure randomness. Implementations must
    /// never substitute timestamps, counters, or deterministic pseudorandomness.
    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>>;

    /// The owned guard that releases file exclusion when dropped.
    #[cfg(feature = "send")]
    type Lock: Send;

    /// The owned guard that releases file exclusion when dropped.
    #[cfg(not(feature = "send"))]
    type Lock;

    /// Acquires exclusive file exclusion until the returned guard is dropped.
    ///
    /// The lock file is created if absent. All writers must use this same
    /// stable path and must never unlink or replace its inode while the store
    /// is open. A CAS writer retains the guard through durable directory
    /// synchronization. Process death releases exclusion without stale-lock
    /// deletion; this primitive does not infer ownership from file age.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be opened or locked, including
    /// when the platform cannot supply the required exclusion.
    async fn lock_exclusive(&self, path: &std::path::Path) -> std::io::Result<Self::Lock>;

    /// Locks an existing stable coordination inode without creating a file.
    ///
    /// Existing-state inspection uses this primitive so a missing or replaced
    /// lock cannot silently initialize a namespace. Implementations open without
    /// following symlinks, require a single-link regular file, and verify that
    /// the locked descriptor still names the same inode after any lock wait.
    /// The default refuses unsupported bindings without filesystem effects.
    ///
    /// # Errors
    /// Returns `NotFound` for missing coordination, an I/O error for unsafe or
    /// replaced inodes or failed locking, and `Unsupported` when unavailable.
    async fn lock_existing_exclusive(
        &self,
        _path: &std::path::Path,
    ) -> std::io::Result<Self::Lock> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "existing-only coordination locking unavailable",
        ))
    }

    /// Retains exclusion by duplicating an actual already held native guard.
    ///
    /// The opaque result has no public constructor or descriptor accessor. This
    /// synchronous hook never borrows the guard across an await and adds no
    /// `Sync`, `Clone`, or `'static` requirement to `Self::Lock`.
    /// The default refuses without filesystem effects.
    ///
    /// # Errors
    /// Returns `Unsupported` for bindings without retained native exclusion,
    /// or an I/O error when duplicating the actual held descriptor fails.
    fn retain_native_exclusion(&self, _held: &Self::Lock) -> std::io::Result<NativeExclusion> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "retained native exclusion unavailable",
        ))
    }

    /// Consumes one privately fixed effect through native completion and durability.
    ///
    /// The effect owns its actual exclusions and owned final checks inside the
    /// physical worker. Bindings must not forward its mutations to detached
    /// child filesystem futures or release retained locks before durable sync.
    /// The default refuses without filesystem effects.
    ///
    /// # Errors
    /// Preserves genuine final-check rejection, physical I/O or sync failure,
    /// worker failure, and `Unsupported` for bindings without retained execution.
    async fn execute_retained_effect(
        &self,
        _effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "retained native effects unavailable",
        )
        .into())
    }

    /// Reads a complete file.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if the file cannot be read.
    async fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>>;

    /// Reads an exact byte range without reading the entire file.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the range cannot be read in full.
    async fn read_range(
        &self,
        path: &std::path::Path,
        range: ByteRange,
    ) -> std::io::Result<Vec<u8>>;

    /// Creates a new file without replacing an existing one.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if the file exists or cannot be written.
    async fn write_new(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()>;

    /// Creates a directory and its missing ancestors.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if creation fails.
    async fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()>;

    /// Lists the immediate children of a directory.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if listing fails.
    async fn read_dir(&self, path: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>>;

    /// Returns metadata for a file or directory.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if metadata cannot be read.
    async fn metadata(&self, path: &std::path::Path) -> std::io::Result<std::fs::Metadata>;

    /// Returns metadata for a path itself without following a symlink.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if metadata cannot be read.
    async fn symlink_metadata(&self, path: &std::path::Path) -> std::io::Result<std::fs::Metadata>;

    /// Returns nofollow metadata for every requested path in its original order.
    ///
    /// Each entry preserves its actual metadata result, including an individual
    /// read failure. The default performs the existing individual operations;
    /// native bindings may batch worker dispatch without caching observations
    /// or treating the reads as atomic. Validation in request order preserves
    /// an earlier physical-policy rejection ahead of a later read failure.
    /// Callers validate the complete result count and each required physical
    /// predicate, and retain their existing initial and final fences.
    ///
    /// # Errors
    /// Returns a native worker or runtime failure. Individual metadata failures
    /// remain in their original positions in the returned vector.
    async fn symlink_metadata_batch(
        &self,
        paths: &[std::path::PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        let mut observations = Vec::with_capacity(paths.len());
        for path in paths {
            observations.push(self.symlink_metadata(path).await);
        }
        Ok(observations)
    }

    /// Executes a fixed protected-record read in one native worker when supported.
    ///
    /// The recipe preserves all ordered duplicate parent observations, rejects
    /// unsafe metadata before reading the body, and binds before/after checks to
    /// the same nofollow descriptor. It supplies read data alone; callers retain
    /// their complete initial and final resolver fences and actual exclusion.
    /// The default returns `None` without I/O so the caller can use its existing
    /// scalar read path. Wrappers with method-level fault interception keep that
    /// fallback rather than bypassing their original observation boundaries.
    ///
    /// # Errors
    /// Preserves unsafe-path, changed-incarnation and individual I/O failures in
    /// their original order. A supported binding never reports a failed read as
    /// an unavailable optimization or silently retries it through another path.
    async fn read_protected_record(
        &self,
        _read: NativeProtectedRead,
    ) -> Result<Option<NativeProtectedRecord>, StoreFailure> {
        Ok(None)
    }

    /// Removes a file after GC, eviction, or temporary-write cleanup.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if removal fails.
    async fn remove_file(&self, path: &std::path::Path) -> std::io::Result<()>;

    /// Renames one path within a filesystem.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if the rename cannot complete.
    async fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()>;

    /// Installs a completed file under a new name without replacement.
    ///
    /// The source and destination must be on one filesystem. A failure to
    /// remove the old name after installation leaves both names pointing to
    /// the same bytes; callers may safely retry cleanup.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` when the destination exists, or another I/O
    /// error if installation or cleanup fails.
    async fn rename_no_replace(
        &self,
        from: &std::path::Path,
        to: &std::path::Path,
    ) -> std::io::Result<()>;

    /// Synchronizes a file's content and metadata.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if durability cannot be established.
    async fn sync_file(&self, path: &std::path::Path) -> std::io::Result<()>;

    /// Synchronizes the expected regular file through one nofollow descriptor.
    ///
    /// The opened descriptor must match the expected physical identity before
    /// synchronization. The returned metadata describes that same descriptor
    /// after synchronization. Callers retain backend exclusion and separately
    /// synchronize directories; this operation establishes neither creation age
    /// nor a secure incarnation version.
    ///
    /// # Errors
    /// Returns an I/O error for a symlink, nonregular or replaced file, failed
    /// synchronization, an unavailable required runtime, or an unsupported
    /// identity or nofollow implementation.
    async fn sync_file_nofollow(
        &self,
        _path: &std::path::Path,
        _expected: &std::fs::Metadata,
    ) -> std::io::Result<std::fs::Metadata> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "nofollow file synchronization unavailable",
        ))
    }

    /// Synchronizes directory entries after a rename or removal.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if directory durability cannot be established.
    async fn sync_directory(&self, path: &std::path::Path) -> std::io::Result<()>;

    /// Reads a regular file while refusing a symbolic link in its final segment.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn read_nofollow(&self, _path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }

    /// Reads a symbolic link target without following it.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn read_link(&self, _path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }

    /// Creates a symbolic link without replacing an existing path.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn symlink(
        &self,
        _target: &std::path::Path,
        _link: &std::path::Path,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }

    /// Creates an additional name for an existing file without replacement.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn hard_link(
        &self,
        _existing: &std::path::Path,
        _new: &std::path::Path,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }

    /// Applies the requested permissions to an owned realization path.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn set_permissions(
        &self,
        _path: &std::path::Path,
        _permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }

    /// Lists extended attribute names without following the final symbolic link.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn list_xattrs(
        &self,
        _path: &std::path::Path,
    ) -> std::io::Result<Vec<std::ffi::OsString>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }

    /// Reads an extended attribute without following the final symbolic link.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn get_xattr(
        &self,
        _path: &std::path::Path,
        _name: &std::ffi::OsStr,
    ) -> std::io::Result<Option<Vec<u8>>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }

    /// Writes an extended attribute without following the final symbolic link.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn set_xattr(
        &self,
        _path: &std::path::Path,
        _name: &std::ffi::OsStr,
        _value: &[u8],
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }

    /// Applies permissions and syncs their metadata through the same owned handle.
    ///
    /// The binding opens the path before restricting its permissions, so even
    /// an unreadable final mode can be made durable without reopening it.
    ///
    /// # Errors
    /// Returns an I/O error if opening, changing permissions, or syncing fails.
    /// The default reports `Unsupported`.
    async fn set_permissions_and_sync(
        &self,
        _path: &std::path::Path,
        _permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "durable permissions unavailable",
        ))
    }

    /// Creates one private directory atomically and refuses an existing path.
    ///
    /// A native Unix directory initially excludes group and other access;
    /// realization may later apply its final permissions.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn create_dir_new(&self, _path: &std::path::Path) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }

    /// Removes one empty directory without recursive deletion.
    ///
    /// # Errors
    /// Returns an I/O error if the operation fails. A binding that does not
    /// implement it reports `Unsupported` rather than approximating it.
    async fn remove_dir(&self, _path: &std::path::Path) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem operation unavailable",
        ))
    }
}

#[cfg(feature = "tokio")]
mod bindings;

#[cfg(feature = "tokio")]
pub use bindings::{TokioClock, TokioFileLock, TokioHttpClient, TokioLocalFs};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "A failed test setup or assertion intentionally panics."
)]
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
        async fn put(&self, _upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
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

        let denied = StoreFailure::with_source(
            StoreErrorKind::Denied {
                verb: "get",
                pattern: "refs/heads/private".to_owned(),
            },
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "secret policy detail"),
        );
        assert!(denied.source().is_none());
        assert_eq!(denied.to_string(), "get denied on refs/heads/private");

        let corrupt_ref = StoreFailure::new(StoreErrorKind::Corrupt(CorruptSubject::RefName(
            "refs/heads/main".to_owned(),
        )));
        assert!(matches!(
            corrupt_ref.kind(),
            StoreErrorKind::Corrupt(CorruptSubject::RefName(name)) if name == "refs/heads/main"
        ));
    }

    #[test]
    fn invalid_diagnostics_preserve_upload_and_range_context() {
        let encoded = b"opaque meta bytes";
        let meta = MetaUpload::new(IdentityKind::Manifest, encoded).unwrap();
        let chunk_without_context = MetaUpload::new(IdentityKind::Chunk, encoded).unwrap_err();

        assert_eq!(meta.kind(), IdentityKind::Manifest);
        assert_eq!(meta.bytes(), encoded);
        assert_eq!(
            chunk_without_context.kind(),
            &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
        );

        let upload = StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "CDC-6" });
        let requested = ByteRange {
            start: 128,
            length: 32,
        };
        let range = StoreErrorKind::Invalid(InvalidReason::Range(requested));

        assert_eq!(upload.to_string(), "content violates CDC-6");
        assert_eq!(range.to_string(), "range beyond content end");
        assert_eq!(
            StoreErrorKind::Invalid(InvalidReason::MalformedRequest).to_string(),
            "malformed request"
        );
        assert!(
            matches!(range, StoreErrorKind::Invalid(InvalidReason::Range(actual)) if actual == requested)
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
    fn wasm_binding_forwards_fetch_and_separates_wall_from_elapsed_time() {
        use std::cell::Cell;

        struct TestHost {
            wall: Cell<SystemTime>,
            ticks: Cell<Duration>,
        }

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
                self.wall.get()
            }

            fn monotonic(&self) -> Duration {
                self.ticks.get()
            }
        }

        let binding = WasmBindings::new(TestHost {
            wall: Cell::new(SystemTime::UNIX_EPOCH + Duration::from_secs(42)),
            ticks: Cell::new(Duration::from_secs(8)),
        });
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

        let deadline = binding.monotonic() + Duration::from_secs(5);
        binding.host.wall.set(SystemTime::UNIX_EPOCH);
        assert_eq!(binding.monotonic(), Duration::from_secs(8));
        binding.host.ticks.set(Duration::from_secs(14));
        assert!(binding.monotonic() >= deadline);
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn native_clock_ticks_do_not_move_backward() {
        let clock = TokioClock;
        let first = clock.monotonic();
        let second = clock.monotonic();

        assert!(second >= first);
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn native_http_client_is_send_and_sync() {
        fn accepts_native_client<C: HttpClient + Send + Sync>() {}

        accepts_native_client::<TokioHttpClient>();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn native_file_binding_preserves_atomic_names_and_ranges() {
        async fn check_binding<F: LocalFs + Sync>(fs: &F, directory: &std::path::Path) {
            let source = directory.join("source");
            let destination = directory.join("destination");

            fs.create_dir_all(directory).await.unwrap();

            let lock_path = directory.join("cas.lock");
            let guard = fs.lock_exclusive(&lock_path).await.unwrap();
            let contender = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .unwrap();

            assert!(contender.try_lock().is_err());
            drop(guard);
            contender.try_lock().unwrap();
            drop(contender);

            let replacement_guard = fs.lock_exclusive(&lock_path).await.unwrap();
            drop(replacement_guard);
            fs.remove_file(&lock_path).await.unwrap();

            fs.write_new(&source, b"first bytes").await.unwrap();
            fs.sync_file(&source).await.unwrap();
            assert_eq!(
                fs.read_range(
                    &source,
                    ByteRange {
                        start: 6,
                        length: 5,
                    },
                )
                .await
                .unwrap(),
                b"bytes"
            );
            assert_eq!(fs.metadata(&source).await.unwrap().len(), 11);
            assert_eq!(fs.read_dir(directory).await.unwrap(), vec![source.clone()]);

            let second = fs.write_new(&source, b"replacement").await;
            assert_eq!(
                second.unwrap_err().kind(),
                std::io::ErrorKind::AlreadyExists
            );
            fs.rename_no_replace(&source, &destination).await.unwrap();
            assert_eq!(fs.read(&destination).await.unwrap(), b"first bytes");

            #[cfg(unix)]
            {
                let link = directory.join("link");
                std::os::unix::fs::symlink(&destination, &link).unwrap();
                assert!(
                    fs.symlink_metadata(&link)
                        .await
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
                assert_eq!(fs.metadata(&link).await.unwrap().len(), 11);
                fs.remove_file(&link).await.unwrap();
            }

            fs.write_new(&source, b"new source").await.unwrap();
            let collision = fs.rename_no_replace(&source, &destination).await;
            assert_eq!(
                collision.unwrap_err().kind(),
                std::io::ErrorKind::AlreadyExists
            );
            assert_eq!(fs.read(&destination).await.unwrap(), b"first bytes");
            fs.remove_file(&source).await.unwrap();
            fs.sync_directory(directory).await.unwrap();
            fs.remove_file(&destination).await.unwrap();
        }

        let unique = TokioClock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("terrane-localfs-{}-{unique}", std::process::id()));

        check_binding(&TokioLocalFs, &directory).await;
        tokio::fs::remove_dir(directory).await.unwrap();
    }
}
