//! Dispatches complete source requalification through the actual native factory.
//!
//! The capture shares the opened bucket's existing Arc and retains no installed
//! verifier. Each invocation restores its genuine full Original state and actual
//! clock on a held Guard. Public arguments cannot manufacture checked evidence.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use super::{OriginalState, PublicationClock, retain_clock, unavailable};
use crate::guard::Guard;
use crate::ref_advance::{AdvanceError, CommitTiming, PublicationBinding};
use crate::store::{Clock, Store};
use terrane_core::refs::RefRecord;

/// Carries ordinary untrusted request fields into the closed configured factory.
pub(super) struct Requalification {
    source: String,
    token: Vec<u8>,
    surface: String,
    started: Duration,
    timing: CommitTiming,
}

#[cfg(feature = "send")]
type RequalificationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RefRecord, AdvanceError>> + Send + 'a>>;
#[cfg(not(feature = "send"))]
type RequalificationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RefRecord, AdvanceError>> + 'a>>;

/// Invokes only the factory that captured the actual opened native backend.
#[cfg(feature = "send")]
pub(super) type RequalificationCheck = dyn for<'a> Fn(
        Requalification,
        &'a PublicationClock<'a>,
        OriginalState,
    ) -> RequalificationFuture<'a>
    + Send
    + Sync;
/// Invokes the actual configured factory without requiring Send futures.
#[cfg(not(feature = "send"))]
pub(super) type RequalificationCheck = dyn for<'a> Fn(
    Requalification,
    &'a PublicationClock<'a>,
    OriginalState,
) -> RequalificationFuture<'a>;

impl<S: Store, C: Clock> Guard<S, C> {
    /// Compares the actual restored verifier's checked local authority.
    ///
    /// # Errors
    /// Refuses absent dispatch, poisoned state or a different actual authority.
    pub(crate) fn check_source_requalification_authority(
        &self,
        expected: &crate::guard::OriginalAuthority,
    ) -> Result<(), crate::store::StoreFailure> {
        if self.original_verifier()?.authority != *expected {
            return Err(crate::guard::invalid());
        }
        Ok(())
    }

    /// Runs separate complete source admission before a later cold fork.
    ///
    /// # Errors
    /// Refuses absent native dispatch, poisoned state, incomplete source context,
    /// current denial, changed selected inputs and originating storage failures.
    pub(crate) async fn requalify_fork_source_native(
        &self,
        source: &str,
        token: &[u8],
        surface: &str,
        started: Duration,
        timing: CommitTiming,
    ) -> Result<RefRecord, AdvanceError>
    where
        C: PublicationBinding,
    {
        let verifier = self.original_verifier()?;
        let state = OriginalState {
            verifier: Some(verifier.clone()),
            baselines: self
                .original_baselines
                .read()
                .map_err(|_| unavailable())?
                .clone(),
            commits: self
                .original_commits
                .read()
                .map_err(|_| unavailable())?
                .clone(),
        };
        (verifier.requalification)(
            Requalification {
                source: source.to_owned(),
                token: token.to_vec(),
                surface: surface.to_owned(),
                started,
                timing,
            },
            self.clock(),
            state,
        )
        .await
    }
}

/// Captures the actual binding without creating a self-retaining verifier cycle.
#[cfg(unix)]
pub(super) fn factory<F, B, V>(
    concrete: Arc<Guard<crate::bucket::FileBucket<F, B, V>, ()>>,
    authority: crate::guard::OriginalAuthority,
) -> Arc<RequalificationCheck>
where
    F: crate::store::LocalFs + crate::bucket::BucketBinding + 'static,
    B: Clock + crate::bucket::BucketBinding + 'static,
    V: crate::store::ContentValidator + crate::bucket::BucketBinding + 'static,
{
    use crate::selected_bridge::native_guard::source_requalification::{
        self, RequalificationRequest,
    };

    Arc::new(move |input, clock, state| {
        let concrete = Arc::clone(&concrete);
        let authority = authority.clone();
        Box::pin(async move {
            let clock = retain_clock(clock)?;
            let holder = crate::bucket::held::SingleHeld::acquire(concrete.store()).await?;
            let guard = concrete.held_guard(holder.destination(), clock)?;
            *guard.original_verifier.write().map_err(|_| unavailable())? = state.verifier;
            *guard
                .original_baselines
                .write()
                .map_err(|_| unavailable())? = state.baselines;
            *guard.original_commits.write().map_err(|_| unavailable())? = state.commits;
            let observed = guard.store().observe_publication().await?;
            source_requalification::publish(
                &concrete,
                &guard,
                &authority,
                &observed,
                RequalificationRequest {
                    source: &input.source,
                    token: &input.token,
                    surface: &input.surface,
                    started: input.started,
                    timing: input.timing,
                },
            )
            .await
        })
    })
}
