//! Refreshes genuine request time and caveats using the configured issuer keys.
//!
//! Retained native checks own the exact injected clock and successful request
//! inputs. They do not establish current ACL, selected configuration or physical
//! exclusion; those remain obligations of the checked publication producer.

use std::time::SystemTime;

use terrane_core::auth::{self, IssuerKey, Request, RequestRoot};
use terrane_core::refs::Locality;

use super::{AuthorizedRef, denied};
use crate::store::{Clock, StoreFailure};

pub(super) fn refresh(
    keys: &[IssuerKey],
    home: &Locality,
    clock: &impl Clock,
    authorized: &AuthorizedRef,
) -> Result<(), StoreFailure> {
    let reference = &authorized.reference;
    let verb = authorized.verb;
    let now = clock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| denied(reference, verb))?
        .as_secs();
    let verified =
        auth::verify(&authorized.token_bytes, keys, now).map_err(|_| denied(reference, verb))?;
    if verified.authority().subject != authorized.token.authority().subject {
        return Err(denied(reference, verb));
    }

    let roots = authorized
        .root_paths
        .iter()
        .zip(&authorized.root_domains)
        .map(|(path, domain)| RequestRoot { path, domain })
        .collect::<Vec<_>>();
    let epoch = authorized
        .record
        .as_ref()
        .map_or(0, |record| record.writer_epoch);
    verified
        .authorize(&Request {
            reference: reference.as_bytes(),
            verb,
            roots: &roots,
            now,
            surface: &authorized.surface,
            locality: home,
            epochs: &[(reference.as_str(), epoch)],
        })
        .map_err(|_| denied(reference, verb))
}

#[cfg(feature = "std")]
pub(super) fn retention_failure(error: std::io::Error) -> StoreFailure {
    let kind = if error.kind() == std::io::ErrorKind::Unsupported {
        crate::store::StoreErrorKind::Unsupported
    } else {
        crate::store::StoreErrorKind::Unavailable { retry_after: None }
    };
    StoreFailure::with_source(kind, error)
}

/// Pairs an exact successful request with freshly authenticated immutable token data.
#[cfg(feature = "std")]
struct RetainedRequest {
    authorized: AuthorizedRef,
    token: auth::VerifiedToken,
    issuer_public_key: [u8; 32],
}

/// Owns authenticated token data and the exact injected clock for native checks.
///
/// Construction reauthenticates every actual request's exact bytes against this
/// Guard's configured key rows. Later checks reuse only that genuine opaque value,
/// reselect the actual issuer row and authorize every caveat at freshly sampled
/// time. Physical controls, current ACLs and complete Guard configuration remain
/// separate obligations of the selected publication producer.
#[cfg(feature = "std")]
pub(crate) struct RetainedRequests {
    clock: crate::store::NativeEffectClock,
    keys: Vec<IssuerKey>,
    home: Locality,
    requests: Vec<RetainedRequest>,
    started: std::time::Duration,
    maximum: std::time::Duration,
}

#[cfg(feature = "std")]
impl RetainedRequests {
    /// Authenticates every exact request under this actual Guard's configured rows.
    ///
    /// # Errors
    /// Preserves clock, empty-request, deadline, signature, issuer, principal
    /// and request-context refusal before any retained value can be returned.
    pub(super) fn new(
        clock: crate::store::NativeEffectClock,
        keys: Vec<IssuerKey>,
        home: Locality,
        requests: Vec<AuthorizedRef>,
        started: std::time::Duration,
        maximum: std::time::Duration,
    ) -> Result<Self, StoreFailure> {
        let first = requests.first().ok_or_else(super::invalid)?;
        check_deadline(&clock, first, started, maximum)?;

        let mut retained = Vec::with_capacity(requests.len());
        for authorized in requests {
            let now = request_time(&clock, &authorized)?;
            let token = auth::verify(&authorized.token_bytes, &keys, now)
                .map_err(|_| denied(&authorized.reference, authorized.verb))?;
            if token.authority().subject != authorized.token.authority().subject {
                return Err(denied(&authorized.reference, authorized.verb));
            }
            let issuer_public_key = matching_issuer(&keys, &token, &authorized, now)?.public_key;
            authorize_retained(&token, &authorized, &home, now)?;
            retained.push(RetainedRequest {
                authorized,
                token,
                issuer_public_key,
            });
        }

        let checks = Self {
            clock,
            keys,
            home,
            requests: retained,
            started,
            maximum,
        };
        checks.check_deadline()?;
        Ok(checks)
    }

    /// Rechecks the original deadline and every authenticated request's current caveats.
    ///
    /// # Errors
    /// Rejects reversed or expired monotonic time, token expiry, issuer retirement,
    /// and mismatched scope, surface, locality or epoch caveats. Clock rollback
    /// cannot make an ambiguous formerly retired issuer row acceptable.
    pub(crate) fn recheck(&self) -> Result<(), StoreFailure> {
        self.check_deadline()?;
        for request in &self.requests {
            let authorized = &request.authorized;
            let now = request_time(&self.clock, authorized)?;
            let key = matching_issuer(&self.keys, &request.token, authorized, now)?;
            if key.public_key != request.issuer_public_key {
                return Err(denied(&authorized.reference, authorized.verb));
            }
            authorize_retained(&request.token, authorized, &self.home, now)?;
        }

        // Fresh authorization itself can consume the remaining budget. Keep the
        // unchanged operation bound on both sides of every retained refresh.
        self.check_deadline()
    }

    fn check_deadline(&self) -> Result<(), StoreFailure> {
        let request = self.requests.first().ok_or_else(super::invalid)?;
        check_deadline(&self.clock, &request.authorized, self.started, self.maximum)
    }
}

#[cfg(feature = "std")]
fn request_time(clock: &impl Clock, request: &AuthorizedRef) -> Result<u64, StoreFailure> {
    clock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| denied(&request.reference, request.verb))
}

// Full verification filters issuer rows at the current timestamp before testing
// uniqueness. Keep that scalar selection even when immutable signatures are
// retained: a wall-clock rollback can reactivate a previously retired duplicate.
#[cfg(feature = "std")]
fn matching_issuer<'keys>(
    keys: &'keys [IssuerKey],
    token: &auth::VerifiedToken,
    request: &AuthorizedRef,
    now: u64,
) -> Result<&'keys IssuerKey, StoreFailure> {
    let authority = token.authority();
    let mut matches = keys.iter().filter(|key| {
        key.issuer == authority.issuer
            && key.key_id == authority.key_id
            && key.retirement.is_none_or(|retirement| now < retirement)
    });
    let key = matches
        .next()
        .ok_or_else(|| denied(&request.reference, request.verb))?;
    if matches.next().is_some() {
        return Err(denied(&request.reference, request.verb));
    }
    Ok(key)
}

#[cfg(feature = "std")]
fn authorize_retained(
    token: &auth::VerifiedToken,
    authorized: &AuthorizedRef,
    home: &Locality,
    now: u64,
) -> Result<(), StoreFailure> {
    let roots = authorized
        .root_paths
        .iter()
        .zip(&authorized.root_domains)
        .map(|(path, domain)| RequestRoot { path, domain })
        .collect::<Vec<_>>();
    let epoch = authorized
        .record
        .as_ref()
        .map_or(0, |record| record.writer_epoch);
    token
        .authorize(&Request {
            reference: authorized.reference.as_bytes(),
            verb: authorized.verb,
            roots: &roots,
            now,
            surface: &authorized.surface,
            locality: home,
            epochs: &[(authorized.reference.as_str(), epoch)],
        })
        .map_err(|_| denied(&authorized.reference, authorized.verb))
}

#[cfg(feature = "std")]
fn check_deadline(
    clock: &impl Clock,
    request: &AuthorizedRef,
    started: std::time::Duration,
    maximum: std::time::Duration,
) -> Result<(), StoreFailure> {
    let elapsed = clock.monotonic().checked_sub(started);
    if elapsed.is_none_or(|elapsed| elapsed > maximum) {
        return Err(StoreFailure::with_source(
            denied(&request.reference, request.verb).kind().clone(),
            crate::ref_advance::AdvanceError::Expired,
        ));
    }
    Ok(())
}

#[cfg(all(test, feature = "tokio", unix))]
#[path = "time/tests.rs"]
mod tests;
