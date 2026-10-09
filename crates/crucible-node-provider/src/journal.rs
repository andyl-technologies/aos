//! Origin-scoped retained requests, terminal outcomes and bounded tombstones.
//!
//! Registering a request reserves its identity before an adapter begins effects.
//! The adapter still owns the original arguments, native operation, owner lock
//! and receipts. This journal never treats EOF or cancellation as completion.
//! It belongs to one surviving incarnation; process restart requires explicit
//! restoration rather than reexecution of ambiguous entries.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_node_contract::{ContentRef, HashRef, Id, canonical};
use serde_json::Value;

use crate::ProviderError;
use crate::envelope::{Envelope, MessageKind, RequestOrigin};

static NEXT_JOURNAL: AtomicU64 = AtomicU64::new(1);

/// Limits retained journal entries independently for each request origin.
pub const MAX_JOURNAL_ENTRIES: usize = 4096;

/// Configures finite request, outcome-byte and retired-identity allowances.
#[derive(Clone, Copy, Debug)]
pub struct JournalLimits {
    /// Bounds live records separately for controller and provider origins.
    pub entries_per_origin: usize,
    /// Bounds canonical retained terminal bytes across both origins.
    pub outcome_bytes: usize,
    /// Bounds retired records separately for each origin before refusal.
    pub tombstones_per_origin: usize,
}

/// Identifies an original request within this journal's fixed incarnation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestKey {
    /// Identifies the sender that owns retirement authority.
    pub origin: RequestOrigin,
    /// Identifies the sender's original logical request.
    pub id: Id,
}

/// Reports retained effect knowledge without manufacturing native receipts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalState {
    /// Identity is registered and its completion obligation remains outstanding.
    Outstanding,
    /// Native effects or completion are uncertain and require reconciliation.
    Unknown,
    /// The original terminal response is retained for identical retries.
    Terminal,
    /// The outcome was consumed; this identity can never become new work.
    Retired,
}

/// Retains the original request commitment and any canonical terminal response.
#[derive(Debug)]
pub struct JournalEntry {
    request_hash: HashRef,
    operation_id: Option<Id>,
    state: JournalState,
    outcome: Option<Vec<u8>>,
}

impl JournalEntry {
    /// Returns the commitment to the original request and its origin.
    pub fn request_hash(&self) -> &HashRef {
        &self.request_hash
    }

    /// Returns the original operation association when one was supplied.
    pub fn operation_id(&self) -> Option<&Id> {
        self.operation_id.as_ref()
    }

    /// Returns retained effect knowledge rather than requested progress.
    pub fn state(&self) -> JournalState {
        self.state
    }

    /// Returns the exact retained terminal response bytes, if completed.
    pub fn outcome(&self) -> Option<&[u8]> {
        self.outcome.as_deref()
    }
}

/// Binds an adapter's completion authority to one original journal record.
#[derive(Clone, Debug)]
pub struct Reservation {
    journal: u64,
    key: RequestKey,
    hash: HashRef,
}

/// Distinguishes first registration from an identical retry without new effects.
pub enum Registration<'a> {
    /// Identity storage was reserved before the original adapter effect.
    New(Reservation),
    /// The exact original identity already exists and must not execute again.
    Existing(&'a JournalEntry),
}

/// Verifies host-selected durable outcome consumption before retirement.
///
/// Implementations are trusted host adapters, not provider-supplied assertions.
/// Their receipt must prove durable acceptance or transferred outcome custody
/// for this exact original request and terminal bytes.
pub trait ConsumptionVerifier {
    /// Verifies consumption under the request origin's retirement authority.
    ///
    /// # Errors
    /// Refuses absent, foreign or uncommitted custody evidence.
    fn verify(
        &self,
        key: &RequestKey,
        request_hash: &HashRef,
        terminal_bytes: &[u8],
        receipt: &ContentRef,
    ) -> Result<(), ProviderError>;
}

/// Owns a finite request journal for one admitted surviving incarnation.
pub struct RequestJournal {
    identity: u64,
    session: Id,
    incarnation: Id,
    limits: JournalLimits,
    entries: BTreeMap<RequestKey, JournalEntry>,
    outcome_bytes: usize,
}

impl RequestJournal {
    /// Creates a journal with bounded per-origin entries and tombstones.
    ///
    /// # Errors
    /// Rejects zero or excessive allowances and exhaustion of local identities.
    /// Fixed-size identity metadata is additionally bounded by record counts.
    pub fn new(session: Id, incarnation: Id, limits: JournalLimits) -> Result<Self, ProviderError> {
        if limits.entries_per_origin == 0
            || limits.entries_per_origin > MAX_JOURNAL_ENTRIES
            || limits.outcome_bytes == 0
            || limits.tombstones_per_origin == 0
            || limits.tombstones_per_origin > MAX_JOURNAL_ENTRIES
        {
            return Err(ProviderError::ResourceExhausted(
                "invalid journal allowances",
            ));
        }
        let identity = NEXT_JOURNAL
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ProviderError::ResourceExhausted("journal incarnation identities"))?;

        Ok(Self {
            identity,
            session,
            incarnation,
            limits,
            entries: BTreeMap::new(),
            outcome_bytes: 0,
        })
    }

    /// Reserves an original request identity or returns its unchanged record.
    ///
    /// # Errors
    /// Rejects foreign session/incarnation, changed request material, exhausted
    /// per-origin credit, and retired identity reuse. New registration is not
    /// native acceptance: the adapter must still check grants and owner custody.
    pub fn register(
        &mut self,
        request: &Envelope,
        origin: RequestOrigin,
    ) -> Result<Registration<'_>, ProviderError> {
        request.validate()?;
        if request.message != MessageKind::Request
            || request.session_id.0.as_ref() != Some(&self.session)
            || request.incarnation_id.0.as_ref() != Some(&self.incarnation)
        {
            return Err(ProviderError::Correlation("journal request scope mismatch"));
        }
        let id = request
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("missing journal request ID"))?;
        let key = RequestKey {
            origin,
            id: id.clone(),
        };
        let hash = request.request_hash(origin)?;

        if self.entries.contains_key(&key) {
            let existing = self
                .entries
                .get(&key)
                .ok_or(ProviderError::Correlation("journal identity disappeared"))?;
            if existing.request_hash != hash {
                return Err(ProviderError::Conflict("request ID changed material"));
            }
            if existing.state == JournalState::Retired {
                return Err(ProviderError::Conflict(
                    "operation retired; identity cannot be reused",
                ));
            }
            return Ok(Registration::Existing(existing));
        }
        let live = self
            .entries
            .iter()
            .filter(|(key, entry)| key.origin == origin && entry.state != JournalState::Retired)
            .count();
        if live >= self.limits.entries_per_origin {
            return Err(ProviderError::ResourceExhausted("journal request credit"));
        }

        self.entries.insert(
            key.clone(),
            JournalEntry {
                request_hash: hash.clone(),
                operation_id: request.operation_id.0.clone(),
                state: JournalState::Outstanding,
                outcome: None,
            },
        );
        Ok(Registration::New(Reservation {
            journal: self.identity,
            key,
            hash,
        }))
    }

    /// Retains uncertainty without releasing the original completion obligation.
    ///
    /// # Errors
    /// Rejects a foreign or retired reservation. A terminal response remains
    /// terminal; loss of its transport acknowledgment cannot erase completion.
    pub fn mark_uncertain(&mut self, reservation: &Reservation) -> Result<(), ProviderError> {
        let entry = self.entry_mut(reservation)?;
        if entry.state != JournalState::Terminal {
            entry.state = JournalState::Unknown;
        }
        Ok(())
    }

    /// Stores the original terminal response after selected-schema validation.
    ///
    /// # Errors
    /// Rejects foreign custody, oversized outcomes and changed terminal results.
    /// On failure the original entry and uncertainty remain retained. The host
    /// adapter must validate native evidence and method semantics before calling.
    pub fn record_terminal(
        &mut self,
        reservation: &Reservation,
        response: &Value,
    ) -> Result<(), ProviderError> {
        let bytes = canonical::canonical_json(response)?;
        let entry = self.entry(reservation)?;
        if let Some(original) = &entry.outcome {
            if original != &bytes {
                return Err(ProviderError::Conflict("original terminal outcome changed"));
            }
            return Ok(());
        }
        let used = self
            .outcome_bytes
            .checked_add(bytes.len())
            .ok_or(ProviderError::ResourceExhausted("journal outcome bytes"))?;
        if used > self.limits.outcome_bytes {
            return Err(ProviderError::ResourceExhausted("journal outcome bytes"));
        }

        let entry = self.entry_mut(reservation)?;
        entry.outcome = Some(bytes);
        entry.state = JournalState::Terminal;
        self.outcome_bytes = used;
        Ok(())
    }

    /// Retires one consumed terminal response while retaining a reuse tombstone.
    ///
    /// # Errors
    /// Rejects outstanding/uncertain results, absent or foreign consumption
    /// evidence, another origin's receipt, and exhausted tombstone credit.
    /// No outcome is discarded until the trusted consumption check succeeds.
    pub fn retire(
        &mut self,
        reservation: &Reservation,
        receipt: &ContentRef,
        verifier: &dyn ConsumptionVerifier,
    ) -> Result<(), ProviderError> {
        let entry = self.entry(reservation)?;
        if entry.state != JournalState::Terminal {
            return Err(ProviderError::Conflict(
                "only consumed terminal outcomes retire",
            ));
        }
        let tombstones = self
            .entries
            .iter()
            .filter(|(key, entry)| {
                key.origin == reservation.key.origin && entry.state == JournalState::Retired
            })
            .count();
        if tombstones >= self.limits.tombstones_per_origin {
            return Err(ProviderError::ResourceExhausted("retired identity storage"));
        }
        let bytes = entry
            .outcome
            .as_ref()
            .ok_or(ProviderError::Correlation("terminal outcome absent"))?;
        verifier.verify(&reservation.key, &entry.request_hash, bytes, receipt)?;
        let length = bytes.len();

        let entry = self.entry_mut(reservation)?;
        entry.outcome = None;
        entry.state = JournalState::Retired;
        self.outcome_bytes -= length;
        Ok(())
    }

    /// Returns the current retained record for a scoped request identity.
    pub fn get(&self, key: &RequestKey) -> Option<&JournalEntry> {
        self.entries.get(key)
    }

    fn entry(&self, reservation: &Reservation) -> Result<&JournalEntry, ProviderError> {
        if reservation.journal != self.identity {
            return Err(ProviderError::Correlation("foreign journal reservation"));
        }
        let entry = self
            .entries
            .get(&reservation.key)
            .ok_or(ProviderError::Correlation("unknown journal reservation"))?;
        if entry.request_hash != reservation.hash || entry.state == JournalState::Retired {
            return Err(ProviderError::Conflict("reservation is stale or retired"));
        }
        Ok(entry)
    }

    fn entry_mut(&mut self, reservation: &Reservation) -> Result<&mut JournalEntry, ProviderError> {
        self.entry(reservation)?;
        self.entries
            .get_mut(&reservation.key)
            .ok_or(ProviderError::Correlation("unknown journal reservation"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crucible_node_contract::U64;
    use serde_json::json;

    use crate::envelope::{Nullable, tests::request};

    use super::*;

    fn journal() -> RequestJournal {
        RequestJournal::new(
            Id::new("session-1").unwrap(),
            Id::new("provider-1").unwrap(),
            JournalLimits {
                entries_per_origin: 2,
                outcome_bytes: 1024,
                tombstones_per_origin: 2,
            },
        )
        .unwrap()
    }

    fn reserve(journal: &mut RequestJournal, request: &Envelope) -> Reservation {
        match journal
            .register(request, RequestOrigin::Controller)
            .unwrap()
        {
            Registration::New(reservation) => reservation,
            Registration::Existing(_) => panic!("expected a new reservation"),
        }
    }

    struct AcceptTestConsumption;

    impl ConsumptionVerifier for AcceptTestConsumption {
        fn verify(
            &self,
            _: &RequestKey,
            _: &HashRef,
            _: &[u8],
            _: &ContentRef,
        ) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    #[test]
    fn uncertain_retry_retains_original_request_without_another_reservation() {
        let mut journal = journal();
        let original = request();
        let reservation = reserve(&mut journal, &original);
        journal.mark_uncertain(&reservation).unwrap();
        let mut retry = original.clone();
        retry.sequence = U64::new(77);

        match journal.register(&retry, RequestOrigin::Controller).unwrap() {
            Registration::Existing(entry) => assert_eq!(entry.state(), JournalState::Unknown),
            Registration::New(_) => panic!("ambiguous request executed again"),
        }
        retry
            .body
            .insert("after_observation_sequence".into(), json!("1"));
        assert!(matches!(
            journal.register(&retry, RequestOrigin::Controller),
            Err(ProviderError::Conflict(_))
        ));
    }

    #[test]
    fn terminal_result_survives_lost_ack_and_cannot_be_replaced() {
        let mut journal = journal();
        let original = request();
        let reservation = reserve(&mut journal, &original);
        let terminal = json!({"status":"completed", "result":{"position":"17"}});
        journal.record_terminal(&reservation, &terminal).unwrap();

        journal.mark_uncertain(&reservation).unwrap();
        assert_eq!(
            journal.entry(&reservation).unwrap().state(),
            JournalState::Terminal
        );
        assert!(
            journal
                .record_terminal(&reservation, &json!({"position":"18"}))
                .is_err()
        );
        assert_eq!(
            journal.entry(&reservation).unwrap().outcome(),
            Some(canonical::canonical_json(&terminal).unwrap().as_slice())
        );
    }

    #[test]
    fn a_reservation_from_another_live_journal_never_mutates_this_one() {
        let mut first = journal();
        let reservation = reserve(&mut first, &request());
        let mut second = journal();
        reserve(&mut second, &request());

        assert!(second.record_terminal(&reservation, &json!({})).is_err());
        assert!(second.mark_uncertain(&reservation).is_err());
    }

    #[test]
    fn retirement_reclaims_bytes_but_never_reexecutes_the_retired_identity() {
        let mut journal = journal();
        let original = request();
        let reservation = reserve(&mut journal, &original);
        let receipt =
            canonical::content_ref(b"test-only-consumption", "application/octet-stream").unwrap();
        assert!(
            journal
                .retire(&reservation, &receipt, &AcceptTestConsumption)
                .is_err()
        );
        journal
            .record_terminal(&reservation, &json!({"status":"completed"}))
            .unwrap();

        journal
            .retire(&reservation, &receipt, &AcceptTestConsumption)
            .unwrap();
        assert_eq!(journal.outcome_bytes, 0);
        assert!(matches!(
            journal.register(&original, RequestOrigin::Controller),
            Err(ProviderError::Conflict(_))
        ));
        assert!(journal.record_terminal(&reservation, &json!({})).is_err());
    }

    #[test]
    fn origins_have_independent_request_credit_and_changed_material_never_evicts() {
        let mut journal = journal();
        let first = request();
        reserve(&mut journal, &first);
        let mut second = first.clone();
        second.request_id = Nullable(Some(Id::new("request-2").unwrap()));
        reserve(&mut journal, &second);
        let mut third = first.clone();
        third.request_id = Nullable(Some(Id::new("request-3").unwrap()));

        assert!(matches!(
            journal.register(&third, RequestOrigin::Controller),
            Err(ProviderError::ResourceExhausted(_))
        ));
        assert!(matches!(
            journal.register(&first, RequestOrigin::Provider).unwrap(),
            Registration::New(_)
        ));
        assert_eq!(journal.entries.len(), 3);
    }
}
