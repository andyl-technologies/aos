//! Bounded isolate coordination for exact, independently verified renewals.
//!
//! The owner alone polls its issuer future. Followers keep only ordinary Rust
//! state and use timers created in their own invocation, never another Durable
//! Object's Promise or waker. A failed owner admits no takeover before its
//! original deadline. Expiring coordination settles no remote issuance history.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::Future;
use std::rc::Rc;

use anyhow::{ensure, Result};
use aos_hub_db::storage_authority::lease::LeaseClock;

/// Commits the complete existing cache context and separate renewal custody.
pub(super) fn coordination_key(context: &impl serde::Serialize, renewal: &str) -> Result<String> {
    super::super::protocol::digest(&(context, super::super::protocol::digest(&renewal)?))
}

/// Checks renewal transport separation before lending any retained result.
pub(super) fn validate_roles(
    renewal: &str,
    storage_work: &str,
    object_guard: &str,
    stage: Option<&str>,
) -> Result<()> {
    ensure!(
        renewal != storage_work
            && renewal != object_guard
            && stage.is_none_or(|key| renewal != key),
        "issuer renewal key must be independent"
    );
    Ok(())
}

/// Matches the existing independently configured cohort and cache ceiling.
pub(super) const MAX_COHORTS: usize = 32;
/// Bounds followers of one owner without a deployment-wide cache assumption.
pub(super) const MAX_FOLLOWERS: usize = 32;
/// Matches the existing short issuer request horizon.
pub(super) const REQUEST_SECONDS: i64 = 30;
/// Preserves the existing conservative cache refresh margin.
pub(super) const REFRESH_SECONDS: i64 = 5;
/// Each waiting invocation creates and polls its own timer.
pub(super) const POLL_MILLIS: u64 = 50;

#[derive(Clone)]
pub(super) struct VerifiedLease {
    pub(super) token: String,
    pub(super) issued_at: i64,
    pub(super) not_after: i64,
    pub(super) last_observed_at: i64,
}

impl VerifiedLease {
    fn fresh(&self, clock: LeaseClock, latest: i64) -> bool {
        clock.observed_at >= self.last_observed_at
            && self.issued_at <= latest
            && latest < self.not_after
    }

    fn usable(&self, clock: LeaseClock, latest: i64) -> bool {
        self.fresh(clock, latest)
            && latest
                .checked_add(REFRESH_SECONDS)
                .is_some_and(|next| next < self.not_after)
    }
}

#[derive(Clone, Copy)]
pub(super) struct Window {
    pub(super) issued_at: i64,
    pub(super) expires_at: i64,
}

impl Window {
    /// Bounds issuer authentication across both qualified clock intervals.
    ///
    /// Backdating the start also shortens the expiry, preserving the signed
    /// request's maximum lifetime and the original renewal flight's cutoff.
    ///
    /// # Errors
    /// Returns an error for unqualified uncertainty, arithmetic overflow, or
    /// clock bounds that leave no live request interval.
    pub(super) fn for_issuer(
        self,
        sender_uncertainty: i64,
        maximum_uncertainty: i64,
    ) -> Result<Self> {
        ensure!(
            sender_uncertainty >= 0 && sender_uncertainty <= maximum_uncertainty,
            "issuer request clock uncertainty is unqualified"
        );
        let margin = sender_uncertainty
            .checked_add(maximum_uncertainty)
            .ok_or_else(|| anyhow::anyhow!("issuer request clock margin overflow"))?;
        let issued_at = self
            .issued_at
            .checked_sub(margin)
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow::anyhow!("issuer request clock margin underflow"))?;
        let expires_at = self.expires_at.min(
            issued_at
                .checked_add(REQUEST_SECONDS)
                .ok_or_else(|| anyhow::anyhow!("issuer request expiry overflow"))?,
        );
        ensure!(
            self.issued_at < expires_at,
            "qualified clocks leave no live issuer request interval"
        );

        Ok(Self {
            issued_at,
            expires_at,
        })
    }

    pub(super) fn check(self, clock: LeaseClock) -> Result<()> {
        ensure!(
            clock.observed_at >= self.issued_at
                && clock.uncertainty >= 0
                && clock
                    .observed_at
                    .checked_add(clock.uncertainty)
                    .is_some_and(|latest| latest < self.expires_at),
            "original renewal window expired or rolled back"
        );
        Ok(())
    }
}

/// Waits for an authenticated issuer's clock floor within the original request.
///
/// # Errors
/// Refuses unqualified offsets, local rollback, exhausted waits or expiry of the
/// original request. The caller authenticates the reply before supplying its floor.
pub(super) async fn wait_for_issuer_clock<C, W, WF>(
    issuer_floor: i64,
    maximum_uncertainty: i64,
    window: Window,
    clock: C,
    wait: W,
) -> Result<()>
where
    C: Fn() -> Result<LeaseClock>,
    W: Fn() -> WF,
    WF: Future<Output = ()>,
{
    let initial = clock()?;
    window.check(initial)?;
    ensure!(
        issuer_floor >= 0 && initial.uncertainty >= 0 && initial.uncertainty <= maximum_uncertainty,
        "issuer clock wait is unqualified"
    );
    let margin = maximum_uncertainty
        .checked_add(initial.uncertainty)
        .ok_or_else(|| anyhow::anyhow!("issuer clock margin overflow"))?;
    ensure!(
        issuer_floor
            <= initial
                .observed_at
                .checked_add(margin)
                .ok_or_else(|| anyhow::anyhow!("issuer clock bound overflow"))?,
        "issuer clock offset exceeds qualified bounds"
    );
    let polls = u64::try_from(margin)?
        .checked_mul(1000)
        .ok_or_else(|| anyhow::anyhow!("issuer clock wait overflow"))?
        / POLL_MILLIS;

    // Separate clocks can straddle a seconds boundary. Wait for the original
    // signed floor; never move either clock, reissue a request or extend expiry.
    let mut previous = initial.observed_at;
    for attempt in 0..=polls {
        let observed = clock()?;
        window.check(observed)?;
        ensure!(
            observed.observed_at >= previous
                && observed.uncertainty >= 0
                && observed.uncertainty <= maximum_uncertainty,
            "issuer clock wait rolled back or became unqualified"
        );
        if observed.observed_at >= issuer_floor {
            return Ok(());
        }
        if attempt == polls {
            break;
        }
        previous = observed.observed_at;
        wait().await;
    }
    anyhow::bail!("issuer clock did not reach its authenticated floor")
}

enum Outcome {
    Pending,
    Complete(VerifiedLease),
    Unavailable,
}

struct Flight {
    window: Window,
    participants: Cell<usize>,
    outcome: RefCell<Outcome>,
}

#[derive(Default)]
pub(super) struct Renewals {
    cache: RefCell<BTreeMap<String, VerifiedLease>>,
    flights: RefCell<BTreeMap<String, Rc<Flight>>>,
    clock_floor: Cell<i64>,
}

impl Renewals {
    fn latest(&self, clock: LeaseClock) -> Result<i64> {
        ensure!(
            clock.observed_at >= self.clock_floor.get() && clock.uncertainty >= 0,
            "renewal observation rolled back"
        );
        let latest = clock
            .observed_at
            .checked_add(clock.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("renewal observation overflow"))?;
        self.clock_floor.set(clock.observed_at);
        Ok(latest)
    }

    fn join(self: &Rc<Self>, key: &str, clock: LeaseClock) -> Result<Ticket> {
        let latest = self.latest(clock)?;
        let caller_expires_at = clock
            .observed_at
            .checked_add(REQUEST_SECONDS)
            .ok_or_else(|| anyhow::anyhow!("renewal caller window overflow"))?;
        let mut flights = self.flights.borrow_mut();
        // An expired request cannot authorize a delayed response. Removing this
        // isolate entry does not resolve any issued token or durable journal.
        flights.retain(|_, flight| {
            if latest >= flight.window.expires_at {
                *flight.outcome.borrow_mut() = Outcome::Unavailable;
                false
            } else {
                true
            }
        });
        let (flight, owner) = if let Some(flight) = flights.get(key) {
            ensure!(
                !matches!(*flight.outcome.borrow(), Outcome::Unavailable),
                "original renewal is unavailable"
            );
            ensure!(
                flight.participants.get() < 1 + MAX_FOLLOWERS,
                "renewal follower admission is full"
            );
            flight.participants.set(flight.participants.get() + 1);
            (Rc::clone(flight), false)
        } else {
            ensure!(
                flights.len() < MAX_COHORTS,
                "renewal cohort admission is full"
            );
            let expires_at = clock
                .observed_at
                .checked_add(REQUEST_SECONDS)
                .ok_or_else(|| anyhow::anyhow!("renewal request overflow"))?;
            ensure!(latest < expires_at, "renewal request has no fresh window");
            let flight = Rc::new(Flight {
                window: Window {
                    issued_at: clock.observed_at,
                    expires_at,
                },
                participants: Cell::new(1),
                outcome: RefCell::new(Outcome::Pending),
            });
            flights.insert(key.to_owned(), Rc::clone(&flight));
            (flight, true)
        };
        let expires_at = caller_expires_at.min(flight.window.expires_at);
        Ok(Ticket {
            pool: Rc::clone(self),
            key: key.to_owned(),
            flight,
            owner,
            expires_at,
        })
    }

    /// Executes one owner future or observes its result with origin-local waits.
    ///
    /// Callers starting a bulk integrity read disable cached reuse so earlier
    /// upload work cannot consume their lease window before the stream starts.
    /// Concurrent callers still share an in-flight issuance. No active read is
    /// renewed, and the issuer's original lifetime and attestation bounds apply.
    ///
    /// Errors or cancellation retain an unavailable flight until its original
    /// expiry. They never elect a replacement or claim a remote request drained.
    pub(super) async fn acquire<C, W, WF, I, IF>(
        self: &Rc<Self>,
        key: String,
        reuse_cached: bool,
        clock: C,
        wait: W,
        issue: I,
    ) -> Result<String>
    where
        C: Fn() -> Result<LeaseClock>,
        W: Fn() -> WF,
        WF: Future<Output = ()>,
        I: FnOnce(Window) -> IF,
        IF: Future<Output = Result<VerifiedLease>>,
    {
        let observed = clock()?;
        let latest = self.latest(observed)?;
        {
            let mut cache = self.cache.borrow_mut();
            if let Some(lease) = cache.get_mut(&key).filter(|_| reuse_cached) {
                if lease.usable(observed, latest) {
                    lease.last_observed_at = observed.observed_at;
                    return Ok(lease.token.clone());
                }
            }
            cache.remove(&key);
        }
        let ticket = self.join(&key, observed)?;
        if ticket.owner {
            ticket.check(clock()?)?;
            let mut pending = Box::pin(issue(ticket.flight.window));
            loop {
                ticket.check(clock()?)?;
                let tick = Box::pin(wait());
                match futures_util::future::select(pending, tick).await {
                    futures_util::future::Either::Left((result, _)) => {
                        let mut lease = result?;
                        let observed = clock()?;
                        let latest = ticket.check(observed)?;
                        ensure!(
                            lease.fresh(observed, latest),
                            "renewed lease is unavailable"
                        );
                        lease.last_observed_at = observed.observed_at;
                        *ticket.flight.outcome.borrow_mut() = Outcome::Complete(lease.clone());
                        let mut cache = self.cache.borrow_mut();
                        if cache.len() >= MAX_COHORTS {
                            cache.clear();
                        }
                        cache.insert(key, lease.clone());
                        return Ok(lease.token);
                    }
                    futures_util::future::Either::Right((_, next)) => pending = next,
                }
            }
        }
        loop {
            let observed = clock()?;
            let latest = ticket.check(observed)?;
            match &*ticket.flight.outcome.borrow() {
                Outcome::Complete(lease) => {
                    ensure!(
                        lease.fresh(observed, latest),
                        "renewed lease is unavailable"
                    );
                    return Ok(lease.token.clone());
                }
                Outcome::Unavailable => anyhow::bail!("original renewal is unavailable"),
                Outcome::Pending => {}
            }
            wait().await;
        }
    }
}

struct Ticket {
    pool: Rc<Renewals>,
    key: String,
    flight: Rc<Flight>,
    owner: bool,
    expires_at: i64,
}

impl Ticket {
    fn check(&self, clock: LeaseClock) -> Result<i64> {
        let latest = self.pool.latest(clock)?;
        ensure!(latest < self.expires_at, "original renewal window expired");
        Ok(latest)
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut outcome = self.flight.outcome.borrow_mut();
        if self.owner && matches!(*outcome, Outcome::Pending) {
            *outcome = Outcome::Unavailable;
        }
        self.flight
            .participants
            .set(self.flight.participants.get().saturating_sub(1));
        let remove =
            self.flight.participants.get() == 0 && matches!(*outcome, Outcome::Complete(_));
        drop(outcome);
        if remove {
            let mut flights = self.pool.flights.borrow_mut();
            if flights
                .get(&self.key)
                .is_some_and(|current| Rc::ptr_eq(current, &self.flight))
            {
                flights.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests;
