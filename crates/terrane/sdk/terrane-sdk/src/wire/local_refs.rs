//! Connects local reference RPC reads to the repository's current-policy guard.
//!
//! Only repositories retained by the native open/initialize factories qualify.
//! Read-cache and driver wrappers cannot acquire this original authority marker.
//! Every operation requires an authenticated request extension and independently
//! passes its exact token to the repository. This read service does not publish
//! refs or implement resumable multi-ref watch; those methods remain unavailable.

use std::{
    fmt,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
mod read;
mod response;

use read::{ReadRequest, protocol};
use response::{ResponseBudget, limit};

use terrane_format::{
    auth::{Grant, Verb, Verbs},
    refs::RefName,
};

use super::{
    authentication::RequestToken, refs::RefCodec, services::RefService, status::Outcome, v1,
};
use crate::{
    repository::Repository,
    store::{Clock, LocalFs, RefInventory, Store},
};

/// Bounds request names and represented response data in a local ref service.
///
/// The repository's existing inventory and history APIs materialize their backend
/// results before these response bounds apply. Native storage policy and the
/// enclosing transport's message/deadline limits remain independently required.
#[derive(Clone, Copy, Debug)]
pub struct LocalRefLimits {
    /// Maximum request name or pattern bytes before parsing or repository I/O.
    pub max_name_bytes: NonZeroUsize,
    /// Maximum canonical bytes for each ref or reflog record.
    pub max_record_bytes: NonZeroUsize,
    /// Maximum rows prepared for one finite listing or reflog response.
    pub max_entries: NonZeroUsize,
    /// Maximum variable-length represented bytes prepared for a finite response.
    pub max_content_bytes: NonZeroUsize,
}

/// Serves guarded local reference point reads, finite listings and committed logs.
///
/// Construction retains the original native repository rather than a raw store
/// or signing key. Capability authentication is still required on the enclosing
/// transport. Handlers refuse missing authentication extensions and independently
/// check current repository policy, including on each streamed row.
///
/// Direct native authority reads resolve the current selected head under backend
/// exclusion and independently enforce its configured home. They report zero
/// staleness for every supported freshness mode; cache/remote composition cannot
/// acquire this service binding. Successful rows grant no later authority. CAS
/// publication, watch cursors and production listener deployment remain separate.
///
/// Configured read-only Serve repositories qualify through their original
/// native binding without acquiring authoring, audit or collection authority.
pub struct LocalRefService<S: Store, C: Clock, F: LocalFs> {
    repository: Arc<Repository<S, C, F>>,
    limits: LocalRefLimits,
    codec: RefCodec,
    instance: String,
    next_request: AtomicU64,
}

/// Reports a refused local reference service binding.
#[derive(Debug)]
pub enum LocalRefServiceError {
    /// Refuses a repository without the original native authority route.
    Authority,
    /// Preserves failed native request-identity entropy acquisition.
    Entropy(std::io::Error),
    /// Refuses a filesystem binding returning an incorrect entropy size.
    EntropySize,
    /// Preserves invalid canonical codec bounds.
    Codec(super::refs::RefWireError),
}

impl fmt::Display for LocalRefServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Authority => "local ref service requires an original native authority route",
            Self::Entropy(_) | Self::EntropySize => {
                "local ref service request identity unavailable"
            }
            Self::Codec(_) => "local ref service canonical bounds invalid",
        })
    }
}

impl std::error::Error for LocalRefServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Entropy(error) => Some(error),
            Self::Codec(error) => Some(error),
            _ => None,
        }
    }
}

impl<S, C, F> LocalRefService<S, C, F>
where
    S: Store + RefInventory + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    F: LocalFs + Send + Sync + 'static,
{
    /// Binds an original native repository and explicit finite response policy.
    ///
    /// A random instance identifier and checked request counter identify errors
    /// without logging credentials, names, paths or backend diagnostics. This
    /// does not replace the eventual cross-tier trace propagation contract.
    ///
    /// # Errors
    /// Refuses generic or cache-composed repositories, failed native entropy,
    /// invalid entropy lengths and invalid canonical record bounds.
    pub async fn new(
        repository: Arc<Repository<S, C, F>>,
        limits: LocalRefLimits,
    ) -> Result<Self, LocalRefServiceError> {
        if !repository.has_native_ref_authority() {
            return Err(LocalRefServiceError::Authority);
        }
        let entropy = repository
            .coordinator()
            .fs()
            .random_bytes(16)
            .await
            .map_err(LocalRefServiceError::Entropy)?;
        if entropy.len() != 16 {
            return Err(LocalRefServiceError::EntropySize);
        }
        let instance = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let codec =
            RefCodec::new(limits.max_record_bytes.get()).map_err(LocalRefServiceError::Codec)?;
        Ok(Self {
            repository,
            limits,
            codec,
            instance,
            next_request: AtomicU64::new(1),
        })
    }

    fn request(&self, context: &RequestContext) -> Result<ReadRequest<S, C, F>, ConnectError> {
        let sequence = self
            .next_request
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| protocol(Outcome::Internal, &self.instance))?;
        let trace = format!("{}-{sequence:016x}", self.instance);
        let token = context
            .extensions()
            .get::<RequestToken>()
            .ok_or_else(|| protocol(Outcome::Unauthenticated, &trace))?;
        let request = ReadRequest {
            repository: self.repository.clone(),
            token: Arc::from(token.bytes()),
            trace: Arc::from(trace),
        };
        request.identity()?;
        Ok(request)
    }

    fn name(&self, name: &str, trace: &str) -> Result<(), ConnectError> {
        self.name_size(name, trace)?;
        RefName::parse(name)
            .map(|_| ())
            .map_err(|_| limit("ref-name", 0, 0, trace))
    }

    fn name_size(&self, name: &str, trace: &str) -> Result<(), ConnectError> {
        if name.len() > self.limits.max_name_bytes.get() {
            return Err(limit(
                "ref-name-bytes",
                self.limits.max_name_bytes.get(),
                name.len(),
                trace,
            ));
        }
        Ok(())
    }

    fn pattern(&self, pattern: &str, trace: &str) -> Result<(), ConnectError> {
        self.name_size(pattern, trace)?;
        if pattern.contains(':') {
            return Err(limit("ref-pattern", 0, 0, trace));
        }
        let read = Verbs::new(Verb::Read as u8).map_err(|_| protocol(Outcome::Internal, trace))?;
        Grant::new(pattern.to_owned(), read)
            .map(|_| ())
            .map_err(|_| limit("ref-pattern", 0, 0, trace))
    }

    fn profile(&self) -> &str {
        &self
            .repository
            .coordinator()
            .guard()
            .config()
            .chunk_profile_name
    }
}

#[allow(refining_impl_trait)]
impl<S, C, F> RefService for LocalRefService<S, C, F>
where
    S: Store + RefInventory + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    F: LocalFs + Send + Sync + 'static,
{
    async fn get_ref(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::GetRefRequest>,
    ) -> ServiceResult<v1::RefState> {
        let read = self.request(&context)?;
        let request = request.to_owned_message();
        self.name(&request.name, &read.trace)?;
        let freshness = request
            .freshness
            .as_known()
            .ok_or_else(|| protocol(Outcome::UnknownEnum, &read.trace))?;
        if freshness == v1::Freshness::Bounded && request.bound_ms == 0 {
            return Err(limit("bound-ms", 1, 0, &read.trace));
        }
        // Construction permits only the original native factory route. Its
        // bucket reads the current selected head under exclusion, and Guard
        // refuses a foreign home before returning an authorized record.
        let record = read
            .head(&request.name)
            .await?
            .ok_or_else(|| protocol(Outcome::NotFound, &read.trace))?;
        let state = response::state(
            self.codec,
            self.profile(),
            request.name,
            &record,
            &read.trace,
        )?;
        ResponseBudget::new(self.limits).state(&state, &read.trace)?;
        read.identity()?;
        Ok(Response::new(state))
    }

    async fn compare_and_swap_ref(
        &self,
        context: RequestContext,
        _request: ServiceRequest<'_, v1::CompareAndSwapRefRequest>,
    ) -> ServiceResult<v1::RefState> {
        let read = self.request(&context)?;
        Err(protocol(Outcome::MethodUnavailable, &read.trace))
    }

    async fn watch_refs(
        &self,
        context: RequestContext,
        _request: ServiceRequest<'_, v1::WatchRefsRequest>,
    ) -> ServiceResult<ServiceStream<v1::RefEvent>> {
        let read = self.request(&context)?;
        Err(protocol(Outcome::MethodUnavailable, &read.trace))
    }

    async fn get_ref_log(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::GetRefLogRequest>,
    ) -> ServiceResult<ServiceStream<v1::RefLogEntry>> {
        let read = self.request(&context)?;
        let request = request.to_owned_message();
        self.name(&request.name, &read.trace)?;
        let history = read.history(&request.name, request.from_sequence).await?;
        if history.head().is_none() {
            return Err(protocol(Outcome::NotFound, &read.trace));
        }
        if history.entries().len() > self.limits.max_entries.get() {
            return Err(limit(
                "ref-response-entries",
                self.limits.max_entries.get(),
                history.entries().len(),
                &read.trace,
            ));
        }
        let mut entries = Vec::new();
        let mut budget = ResponseBudget::new(self.limits);
        for entry in history.entries() {
            let value = self
                .codec
                .encode_log(entry, self.profile(), "")
                .map_err(|_| protocol(Outcome::Internal, &read.trace))?;
            budget.log(&value, &read.trace)?;
            entries.push(value);
        }
        let name = request.name;
        let head = history.head().cloned();
        let stream = futures_util::stream::unfold(
            (entries.into_iter(), false),
            move |(mut entries, failed)| {
                let read = read.clone();
                let name = name.clone();
                let head = head.clone();
                async move {
                    if failed {
                        return None;
                    }
                    // This also checks the empty/terminal poll. A completed stream
                    // cannot retain a stale identity or a different whole horizon.
                    let checked = read.head(&name).await;
                    let value = match checked {
                        Ok(current) if current == head => Ok(entries.next()?),
                        Ok(_) => Err(protocol(Outcome::Transient(None), &read.trace)),
                        Err(error) => Err(error),
                    };
                    let failed = value.is_err();
                    Some((value, (entries, failed)))
                }
            },
        );
        Ok(Response::new(
            Box::pin(stream) as ServiceStream<v1::RefLogEntry>
        ))
    }

    async fn list_refs(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::ListRefsRequest>,
    ) -> ServiceResult<ServiceStream<v1::RefState>> {
        let read = self.request(&context)?;
        let request = request.to_owned_message();
        self.pattern(&request.pattern, &read.trace)?;
        let listed = read.listing(&request.pattern).await?;
        if listed.len() > self.limits.max_entries.get() {
            return Err(limit(
                "ref-response-entries",
                self.limits.max_entries.get(),
                listed.len(),
                &read.trace,
            ));
        }
        let mut budget = ResponseBudget::new(self.limits);
        for entry in &listed {
            self.name(entry.name(), &read.trace)?;
            let value = response::state(
                self.codec,
                self.profile(),
                entry.name().into(),
                entry.record(),
                &read.trace,
            )?;
            budget.state(&value, &read.trace)?;
        }
        let codec = self.codec;
        let profile = self.profile().to_owned();
        let pattern = request.pattern;
        let listed = Arc::new(listed);
        let stream = futures_util::stream::unfold(
            (listed, 0_usize, false),
            move |(listed, position, failed)| {
                let read = read.clone();
                let profile = profile.clone();
                let pattern = pattern.clone();
                async move {
                    if failed {
                        return None;
                    }
                    let value = if let Some(next) = listed.get(position) {
                        match read.head(next.name()).await {
                            Ok(Some(current)) if &current == next.record() => response::state(
                                codec,
                                &profile,
                                next.name().into(),
                                &current,
                                &read.trace,
                            ),
                            Ok(_) => Err(protocol(Outcome::Transient(None), &read.trace)),
                            Err(error) => Err(error),
                        }
                    } else {
                        // Re-enumeration supplies the same complete guarded closing
                        // check for empty listings and after the final disclosed row.
                        match read.listing(&pattern).await {
                            Ok(current) if current == *listed => return None,
                            Ok(_) => Err(protocol(Outcome::Transient(None), &read.trace)),
                            Err(error) => Err(error),
                        }
                    };
                    let failed = value.is_err();
                    Some((value, (listed, position.saturating_add(1), failed)))
                }
            },
        );
        Ok(Response::new(
            Box::pin(stream) as ServiceStream<v1::RefState>
        ))
    }
}
