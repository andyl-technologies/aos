//! Routes verified content in configured order while retaining one ref authority.
//!
//! [`Routed`] borrows no tokens and performs no authorization. Its children
//! remain responsible for verifying their returned encodings and validating
//! uploads. It never copies refs or writes caches, and forwards every authority
//! operation exactly once. Read deadlines and circuits affect content only.

mod deadline;

use super::{
    ByteRange, Capabilities, CapabilityReport, Clock, ContentStore, ContentUpload, IdentityPrefix,
    InvalidReason, RangeCapability, RefCapability, RefCasOutcome, RefLogAppendOutcome, RefStore,
    StoreErrorKind, StoreFailure,
};
use crate::{bucket::BucketBinding, host::cache::CircuitBreaker};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use terrane_format::{
    identity::Identity,
    refs::{Locality, RefLogRecord, RefRecord},
};

#[cfg(feature = "send")]
type Child<'child> = &'child (dyn ContentStore + Send + Sync);
#[cfg(not(feature = "send"))]
type Child<'child> = &'child dyn ContentStore;

/// Supplies explicit finite routing resources, without establishing authority.
#[derive(Clone, Debug)]
pub struct RoutingPolicy {
    /// Bounds the total elapsed time of one content read or membership request.
    pub read_budget: Duration,
    /// Bounds each child attempt within the remaining whole-request budget.
    pub child_budget: Duration,
    /// Opens a child's circuit after this many consecutive failed attempts.
    pub failure_threshold: u32,
    /// Allows one new probe per interval while a child's circuit is open.
    pub probe_interval: Duration,
    /// Bounds the total number of configured children, including the authority.
    pub max_children: usize,
    /// Bounds the number of identities in one membership request.
    pub max_membership: usize,
}

/// Retains ordered content caches and one independently opened ref authority.
///
/// All bindings belong to the same disclosure domain and immutable profile;
/// their trusted opener must establish that relationship. This raw combinator
/// receives no caller token. A repository Guard authorizes its use separately.
/// Clones share the actual authority, children and circuit state.
pub struct Routed<C, A, K> {
    inner: Arc<Inner<C, A, K>>,
}

struct Inner<C, A, K> {
    caches: Vec<C>,
    authority: A,
    authority_position: usize,
    clock: K,
    policy: RoutingPolicy,
    capabilities: Capabilities,
    circuits: Mutex<Vec<CircuitBreaker>>,
}

impl<C, A, K> Clone for Routed<C, A, K> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<C, A, K> Routed<C, A, K>
where
    C: ContentStore + BucketBinding,
    A: ContentStore + RefStore + BucketBinding,
    K: Clock + BucketBinding,
{
    /// Binds real opened children and inserts the authority at its read position.
    ///
    /// Cache positions before and after the authority retain their configured
    /// order. Capabilities derive from the opened children; locality labels
    /// describe this routed instance. Sealed handles and presigning require
    /// separate interfaces and are not advertised by this content adapter.
    ///
    /// # Errors
    /// Rejects a missing authority capability, any cache claiming refs, an
    /// out-of-range authority position, and zero, inconsistent or exceeded bounds.
    pub fn new(
        caches: Vec<C>,
        authority: A,
        authority_position: usize,
        locality: Locality,
        clock: K,
        policy: RoutingPolicy,
    ) -> Result<Self, StoreFailure> {
        let count = caches.len().checked_add(1).ok_or_else(invalid)?;
        if authority.capabilities().refs == RefCapability::None
            || caches
                .iter()
                .any(|cache| cache.capabilities().refs != RefCapability::None)
            || authority_position > caches.len()
            || policy.read_budget.is_zero()
            || policy.child_budget.is_zero()
            || policy.child_budget > policy.read_budget
            || policy.failure_threshold == 0
            || policy.probe_interval.is_zero()
            || policy.max_membership == 0
            || count > policy.max_children
        {
            return Err(invalid());
        }
        let mut capabilities = authority.capabilities().clone();
        capabilities.locality = locality;
        capabilities.presign = false;
        capabilities.sealed = false;
        if caches
            .iter()
            .any(|cache| cache.capabilities().ranges == RangeCapability::WholeObjectOnly)
        {
            capabilities.ranges = RangeCapability::WholeObjectOnly;
        }
        let circuits = (0..count)
            .map(|_| CircuitBreaker::new(policy.failure_threshold, policy.probe_interval))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            inner: Arc::new(Inner {
                caches,
                authority,
                authority_position,
                clock,
                policy,
                capabilities,
                circuits: Mutex::new(circuits),
            }),
        })
    }

    fn child(&self, position: usize) -> Result<Child<'_>, StoreFailure> {
        if position == self.inner.authority_position {
            return Ok(&self.inner.authority);
        }
        let index = if position > self.inner.authority_position {
            position - 1
        } else {
            position
        };
        self.inner
            .caches
            .get(index)
            .map(|child| child as Child<'_>)
            .ok_or_else(invalid)
    }

    fn allow(&self, position: usize) -> Result<bool, StoreFailure> {
        let mut circuits = self.inner.circuits.lock().map_err(|_| unavailable())?;
        let circuit = circuits.get_mut(position).ok_or_else(invalid)?;
        Ok(circuit.allow(self.inner.clock.monotonic()))
    }

    fn observe<T>(
        &self,
        position: usize,
        result: &Result<T, StoreFailure>,
    ) -> Result<(), StoreFailure> {
        let mut circuits = self.inner.circuits.lock().map_err(|_| unavailable())?;
        let circuit = circuits.get_mut(position).ok_or_else(invalid)?;
        match result {
            Err(error) if failed_child(error) => circuit.failure(self.inner.clock.monotonic()),
            Ok(_) => circuit.success(),
            Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => circuit.success(),
            Err(_) => {}
        }
        Ok(())
    }
}

impl<C, A, K> CapabilityReport for Routed<C, A, K> {
    fn capabilities(&self) -> &Capabilities {
        &self.inner.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<C, A, K> ContentStore for Routed<C, A, K>
where
    C: ContentStore + BucketBinding,
    A: ContentStore + RefStore + BucketBinding,
    K: Clock + BucketBinding,
{
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        // The exact authority owns upload validation, admission and durability.
        self.inner.authority.put(upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        if range.is_some() && self.capabilities().ranges == RangeCapability::WholeObjectOnly {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let started = self.inner.clock.monotonic();
        let mut problem = None;
        for position in 0..=self.inner.caches.len() {
            if let Err(error) = deadline::remaining(&self.inner.clock, &self.inner.policy, started)
            {
                retain_problem(&mut problem, error);
                return Err(problem.unwrap_or_else(unavailable));
            }
            if !self.allow(position)? {
                retain_problem(&mut problem, unavailable());
                continue;
            }
            let result = deadline::read(
                &self.inner.clock,
                &self.inner.policy,
                started,
                self.child(position)?.get(identity, range),
            )
            .await;
            self.observe(position, &result)?;
            match result {
                Ok(bytes) => return Ok(bytes),
                Err(error) if matches!(error.kind(), StoreErrorKind::Absent(_)) => {}
                Err(error) if failed_child(&error) => retain_problem(&mut problem, error),
                Err(error) => return Err(error),
            }
        }
        Err(problem.unwrap_or_else(|| StoreFailure::new(StoreErrorKind::Absent(identity.clone()))))
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        if identities.len() > self.inner.policy.max_membership {
            return Err(invalid());
        }
        let started = self.inner.clock.monotonic();
        let mut present = vec![false; identities.len()];
        let mut problem = None;
        for position in 0..=self.inner.caches.len() {
            let missing = identities
                .iter()
                .zip(&present)
                .filter_map(|(identity, found)| (!found).then_some(identity.clone()))
                .collect::<Vec<_>>();
            if missing.is_empty() {
                return Ok(present);
            }
            if let Err(error) = deadline::remaining(&self.inner.clock, &self.inner.policy, started)
            {
                retain_problem(&mut problem, error);
                return Err(problem.unwrap_or_else(unavailable));
            }
            if !self.allow(position)? {
                retain_problem(&mut problem, unavailable());
                continue;
            }
            let result = deadline::read(
                &self.inner.clock,
                &self.inner.policy,
                started,
                self.child(position)?.has(&missing),
            )
            .await
            .and_then(|rows| {
                if rows.len() == missing.len() {
                    Ok(rows)
                } else {
                    Err(unavailable())
                }
            });
            self.observe(position, &result)?;
            match result {
                Ok(rows) => {
                    let mut rows = rows.into_iter();
                    for found in &mut present {
                        if !*found {
                            *found = rows.next().ok_or_else(unavailable)?;
                        }
                    }
                }
                Err(error) if failed_child(&error) => retain_problem(&mut problem, error),
                Err(error) => return Err(error),
            }
        }
        // An unqueried or failed child can still hold any unresolved identity.
        // Never turn an open circuit or malformed answer into negative evidence.
        if present.iter().any(|found| !found)
            && let Some(error) = problem
        {
            return Err(error);
        }
        Ok(present)
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        // Listing remains an advisory authority candidate set, never a read hint.
        self.inner.authority.list(prefix).await
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<C, A, K> RefStore for Routed<C, A, K>
where
    C: ContentStore + BucketBinding,
    A: ContentStore + RefStore + BucketBinding,
    K: Clock + BucketBinding,
{
    type Watch = A::Watch;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        self.inner.authority.ref_get(name).await
    }

    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        self.inner.authority.ref_cas(name, expect, new).await
    }

    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        self.inner.authority.ref_log_append(name, seq, record).await
    }

    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.inner.authority.ref_log_read(name, from_seq).await
    }

    async fn ref_watch(&self, name: &str, from_seq: u64) -> Result<Self::Watch, StoreFailure> {
        self.inner.authority.ref_watch(name, from_seq).await
    }
}

fn failed_child(error: &StoreFailure) -> bool {
    matches!(
        error.kind(),
        StoreErrorKind::Unavailable { .. } | StoreErrorKind::Corrupt(_)
    )
}

/// Keeps an unavailable outcome and the shortest retry hint actually reported.
fn retain_problem(problem: &mut Option<StoreFailure>, error: StoreFailure) {
    let replace = match (problem.as_ref().map(StoreFailure::kind), error.kind()) {
        (None, _) => true,
        (Some(StoreErrorKind::Corrupt(_)), StoreErrorKind::Unavailable { .. }) => true,
        (
            Some(StoreErrorKind::Unavailable {
                retry_after: previous,
            }),
            StoreErrorKind::Unavailable {
                retry_after: Some(next),
            },
        ) => previous.is_none_or(|previous| *next < previous),
        _ => false,
    };
    if replace {
        *problem = Some(error);
    }
}

fn invalid() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest))
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}
