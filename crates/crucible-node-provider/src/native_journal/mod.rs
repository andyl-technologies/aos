//! Native operation, input, and observation custody beneath a finite supervisor.
//!
//! The journal reserves original request identities before giving a trusted
//! adapter access to resources. Typed outcomes remain tied to original grants;
//! transport loss and cancellation never unlock unknown native effects. Dropping
//! the journal transfers its resources and complete ledger to a previously
//! reserved supervision slot instead of abandoning either.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_node_contract::{HashRef, Id, U64, Validate, canonical};
use serde_json::{Map, Value};

use crate::ProviderError;
use crate::bodies::{self, RequestBody};
use crate::envelope::{Envelope, RequestOrigin};
use crate::handshake::ConnectionAuthority;
use crate::journal::{
    JournalLimits, JournalState, Registration, RequestJournal, RequestKey, Reservation,
};

mod inputs;
mod models;
mod observations;
mod operations;

pub use inputs::{InputAcceptance, NativeInputReconciler, NativeInputVerifier};
pub use models::*;
pub use observations::NativeObservationVerifier;
pub use operations::{
    BeginRegistration, NativeOperationPermit, NativeOutcomeVerifier, NativeScopeVerifier,
};

static NEXT_REGISTRY: AtomicU64 = AtomicU64::new(1);

/// Owns finite native resources and their original portable obligations.
pub struct NativeJournal<C: 'static> {
    identity: u64,
    session: Id,
    incarnation: Id,
    limits: NativeJournalLimits,
    custody: Option<NativeCustody<C>>,
    supervision: Box<dyn NativeSupervision<C>>,
}

impl<C: 'static> NativeJournal<C> {
    /// Reserves supervision before admitting any request or native resource effect.
    ///
    /// `resources` must contain only inert resources at this point. Spawning or
    /// activating resources happens through a later registered request callback.
    /// The supervisor reserves a finite slot that survives the journal's owner.
    ///
    /// # Errors
    /// Rejects invalid bounds, exhausted local identities, journal creation, or
    /// unavailable supervision capacity before any request can be registered.
    pub fn new(
        session: Id,
        incarnation: Id,
        journal_limits: JournalLimits,
        limits: NativeJournalLimits,
        resources: C,
        supervisor: &dyn NativeJournalSupervisor<C>,
    ) -> Result<Self, ProviderError> {
        limits.validate()?;
        let journal = RequestJournal::new(session.clone(), incarnation.clone(), journal_limits)?;
        let identity = NEXT_REGISTRY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| ProviderError::ResourceExhausted("native registry identities"))?;
        let supervision = supervisor.reserve()?;

        Ok(Self {
            identity,
            session: session.clone(),
            incarnation: incarnation.clone(),
            limits,
            custody: Some(NativeCustody {
                session_id: session,
                incarnation_id: incarnation,
                resources,
                requests: journal,
                reservations: BTreeMap::new(),
                operations: BTreeMap::new(),
                inputs: BTreeMap::new(),
                input_streams: BTreeMap::new(),
                observation_streams: BTreeMap::new(),
                observations: Vec::new(),
                retained_bytes: 0,
            }),
            supervision,
        })
    }

    /// Returns resources for trusted read-only native verification.
    pub fn resources(&self) -> &C {
        &self.custody().resources
    }

    /// Returns the complete retained ledger without transferring resource custody.
    pub fn snapshot(&self) -> &NativeCustody<C> {
        self.custody()
    }

    /// Reclaims actual same-incarnation custody without resetting retained streams.
    ///
    /// The capsule must come from trusted supervision of the surviving native
    /// resources. This operation does not import wire claims or restore another
    /// process incarnation. Every old opaque local permit becomes invalid.
    ///
    /// # Errors
    /// Returns both the error and complete original custody when configured
    /// bounds, local identity allocation, or supervision reservation fail.
    pub fn from_custody(
        custody: NativeCustody<C>,
        limits: NativeJournalLimits,
        supervisor: &dyn NativeJournalSupervisor<C>,
    ) -> Result<Self, Box<NativeReclaimFailure<C>>> {
        let preflight = || -> Result<(u64, Box<dyn NativeSupervision<C>>), ProviderError> {
            limits.validate()?;
            if custody
                .operations
                .values()
                .filter(|entry| !entry.retired)
                .count()
                > limits.operations
                || custody
                    .operations
                    .values()
                    .filter(|entry| entry.retired)
                    .count()
                    > limits.operation_tombstones
                || custody.inputs.len() > limits.input_batches
                || custody.observations.len() > limits.observation_batches
                || custody.retained_bytes > limits.retained_bytes
            {
                return Err(ProviderError::ResourceExhausted(
                    "reclaimed native custody exceeds configured bounds",
                ));
            }
            let identity = NEXT_REGISTRY
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| ProviderError::ResourceExhausted("native registry identities"))?;
            Ok((identity, supervisor.reserve()?))
        };
        match preflight() {
            Ok((identity, supervision)) => Ok(Self {
                identity,
                session: custody.session_id.clone(),
                incarnation: custody.incarnation_id.clone(),
                limits,
                custody: Some(custody),
                supervision,
            }),
            Err(error) => Err(Box::new(NativeReclaimFailure { error, custody })),
        }
    }

    /// Registers one original request while its authenticated connection is live.
    ///
    /// # Errors
    /// Rejects revoked connections, foreign scope, changed material, retired
    /// identities, or exhausted request credit. Identical retries receive only
    /// their retained status; they receive no replacement resource permit.
    pub fn register_request(
        &mut self,
        authority: &ConnectionAuthority,
        request: &Envelope,
        origin: RequestOrigin,
    ) -> Result<NativeRequestRegistration, ProviderError> {
        self.check_authority(authority)?;
        authority.with_live(|| self.register_unfenced(request, origin))
    }

    /// Runs a trusted resource effect under an original registered request.
    ///
    /// Errors retain uncertainty and the original native resources. This method
    /// does not validate model authority; the adapter must do that before entry.
    /// For begin operations, use the stricter operation permit instead.
    ///
    /// # Errors
    /// Rejects a foreign, terminal, or previously executed permit and propagates
    /// native adapter failure without discarding its obligation.
    pub fn with_request_resources<T>(
        &mut self,
        permit: &NativeRequestPermit,
        effect: impl FnOnce(&mut C) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        self.check_request_permit(permit)?;
        if self
            .custody()
            .requests
            .get(&permit.key)
            .is_some_and(|entry| entry.state() == JournalState::Terminal)
        {
            return Err(ProviderError::Conflict(
                "terminal request cannot begin native effects",
            ));
        }
        let record = self.custody_mut().reservations.get_mut(&permit.key).ok_or(
            ProviderError::Correlation("request reservation disappeared"),
        )?;
        if record.started {
            return Err(ProviderError::Conflict(
                "original request effect already started",
            ));
        }
        record.started = true;
        let reservation = record.reservation.clone();
        self.custody_mut().requests.mark_uncertain(&reservation)?;
        effect(&mut self.custody_mut().resources)
    }

    /// Retains an immutable non-begin terminal result after local body validation.
    ///
    /// Trusted callers must verify referenced native evidence first. Begin
    /// outcomes require [`Self::record_terminal`] and its mandatory verifier.
    ///
    /// # Errors
    /// Rejects foreign permits, malformed or nonterminal responses, begin
    /// requests, changed outcomes, or exhausted retained outcome storage.
    pub fn record_request_terminal(
        &mut self,
        permit: &NativeRequestPermit,
        response: &Map<String, Value>,
    ) -> Result<(), ProviderError> {
        self.check_request_permit(permit)?;
        let record =
            self.custody()
                .reservations
                .get(&permit.key)
                .ok_or(ProviderError::Correlation(
                    "request reservation disappeared",
                ))?;
        let request = bodies::decode_request(record.original.method, &record.original.body)?;
        if matches!(request, RequestBody::Begin(_)) {
            return Err(ProviderError::Conflict(
                "begin result requires native operation verifier",
            ));
        }
        let decoded = bodies::decode_response(&request, response)?;
        if decoded.shape.is_accepted() {
            return Err(ProviderError::Conflict(
                "accepted is not a terminal outcome",
            ));
        }
        let reservation = record.reservation.clone();
        self.custody_mut()
            .requests
            .record_terminal(&reservation, &Value::Object(response.clone()))
    }

    /// Retires a separately consumed origin-scoped request outcome.
    ///
    /// This does not retire its operation, input stream, or native resource pins.
    /// Those obligations remain in the complete ledger until their independent
    /// authenticated disposition is established.
    ///
    /// # Errors
    /// Rejects unknown, outstanding, uncertain, or already retired requests,
    /// invalid receipt custody, foreign origins, and full tombstone storage.
    pub fn retire_request(
        &mut self,
        origin: RequestOrigin,
        request: &Id,
        receipt: &crucible_node_contract::ContentRef,
        verifier: &dyn crate::journal::ConsumptionVerifier,
    ) -> Result<(), ProviderError> {
        receipt.validate()?;
        let key = RequestKey {
            origin,
            id: request.clone(),
        };
        let reservation = self.reservation(&key)?;
        self.custody_mut()
            .requests
            .retire(&reservation, receipt, verifier)
    }

    fn check_authority(&self, authority: &ConnectionAuthority) -> Result<(), ProviderError> {
        if authority.session_id() != &self.session
            || authority.incarnation_id() != &self.incarnation
        {
            return Err(ProviderError::Correlation(
                "foreign native journal authority",
            ));
        }
        authority.ensure_live()
    }

    fn register_unfenced(
        &mut self,
        request: &Envelope,
        origin: RequestOrigin,
    ) -> Result<NativeRequestRegistration, ProviderError> {
        let key = request_key(request, origin)?;
        let identity = self.identity;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(request).map_err(crucible_node_contract::ContractError::from)?,
        )?
        .len();
        let reserved_bytes = if self.custody().reservations.contains_key(&key) {
            self.custody().retained_bytes
        } else {
            self.reserve_bytes(bytes)?
        };
        let custody = self.custody_mut();
        match custody.requests.register(request, origin)? {
            Registration::Existing(entry) => {
                Ok(NativeRequestRegistration::Original(RequestSnapshot {
                    key,
                    hash: entry.request_hash().clone(),
                    state: entry.state(),
                    outcome: entry.outcome().map(<[u8]>::to_vec),
                }))
            }
            Registration::New(reservation) => {
                custody.retained_bytes = reserved_bytes;
                custody.reservations.insert(
                    key.clone(),
                    RequestRecord {
                        reservation,
                        original: request.clone(),
                        started: false,
                    },
                );
                Ok(NativeRequestRegistration::New(NativeRequestPermit {
                    identity,
                    key,
                }))
            }
        }
    }

    fn check_request_permit(&self, permit: &NativeRequestPermit) -> Result<(), ProviderError> {
        if permit.identity != self.identity {
            return Err(ProviderError::Correlation("foreign native request permit"));
        }
        let entry = self
            .custody()
            .requests
            .get(&permit.key)
            .ok_or(ProviderError::Correlation("unknown native request permit"))?;
        if entry.state() == JournalState::Retired {
            return Err(ProviderError::Conflict("native request permit is retired"));
        }
        Ok(())
    }

    fn custody(&self) -> &NativeCustody<C> {
        // Custody is taken only in Drop, after all callable methods have ended.
        match &self.custody {
            Some(custody) => custody,
            None => std::process::abort(),
        }
    }

    fn custody_mut(&mut self) -> &mut NativeCustody<C> {
        match &mut self.custody {
            Some(custody) => custody,
            None => std::process::abort(),
        }
    }

    fn reserve_bytes(&self, additional: usize) -> Result<usize, ProviderError> {
        let total = self
            .custody()
            .retained_bytes
            .checked_add(additional)
            .ok_or(ProviderError::ResourceExhausted("native retained bytes"))?;
        if total > self.limits.retained_bytes {
            return Err(ProviderError::ResourceExhausted("native retained bytes"));
        }
        Ok(total)
    }

    fn preflight_metadata(&self, envelope: &Envelope, extra: usize) -> Result<(), ProviderError> {
        let envelope_bytes = canonical::canonical_json(
            &serde_json::to_value(envelope).map_err(crucible_node_contract::ContractError::from)?,
        )?
        .len();
        let total = envelope_bytes
            .checked_add(extra)
            .ok_or(ProviderError::ResourceExhausted("native metadata bytes"))?;
        self.reserve_bytes(total)?;
        Ok(())
    }
}

impl<C: 'static> Drop for NativeJournal<C> {
    fn drop(&mut self) {
        if let Some(custody) = self.custody.take() {
            self.supervision.retain(custody);
        }
    }
}

fn request_key(request: &Envelope, origin: RequestOrigin) -> Result<RequestKey, ProviderError> {
    Ok(RequestKey {
        origin,
        id: request
            .request_id
            .0
            .clone()
            .ok_or(ProviderError::Correlation("request has no identity"))?,
    })
}

fn canonical_map(value: &Map<String, Value>) -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&Value::Object(value.clone()))?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
