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

/// Owns time inputs captured from actual successful authorization snapshots.
#[cfg(feature = "std")]
pub(crate) struct RetainedRequests {
    clock: crate::store::NativeEffectClock,
    keys: Vec<IssuerKey>,
    home: Locality,
    requests: Vec<AuthorizedRef>,
    started: std::time::Duration,
    maximum: std::time::Duration,
}

#[cfg(feature = "std")]
impl RetainedRequests {
    pub(super) fn new(
        clock: crate::store::NativeEffectClock,
        keys: Vec<IssuerKey>,
        home: Locality,
        requests: Vec<AuthorizedRef>,
        started: std::time::Duration,
        maximum: std::time::Duration,
    ) -> Self {
        Self {
            clock,
            keys,
            home,
            requests,
            started,
            maximum,
        }
    }

    /// Rechecks the unchanged deadline and every captured authenticated request.
    ///
    /// # Errors
    /// Rejects reversed or expired monotonic time, token expiry, issuer retirement,
    /// and mismatched scope, surface, locality or epoch caveats.
    pub(crate) fn recheck(&self) -> Result<(), StoreFailure> {
        self.check_deadline()?;
        for request in &self.requests {
            refresh(&self.keys, &self.home, &self.clock, request)?;
        }

        // Capability verification itself can consume the remaining budget.
        // The unchanged operation bound is checked again at final dispatch.
        self.check_deadline()
    }

    fn check_deadline(&self) -> Result<(), StoreFailure> {
        let request = self.requests.first().ok_or_else(super::invalid)?;
        let elapsed = self.clock.monotonic().checked_sub(self.started);
        if elapsed.is_none_or(|elapsed| elapsed > self.maximum) {
            return Err(StoreFailure::with_source(
                denied(&request.reference, request.verb).kind().clone(),
                crate::ref_advance::AdvanceError::Expired,
            ));
        }
        Ok(())
    }
}
