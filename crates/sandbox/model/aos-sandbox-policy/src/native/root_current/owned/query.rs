//! Advances only this same owned programme through the initial Source query.
//!
//! The short actual receiving loan pays its cumulative Stage and service before
//! request construction. Returned protocol DATA cannot supply a reply or grant
//! another native role, append, signing or serving transition.

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SOURCE_CURRENT_QUERY_BYTES_V1;

use super::super::initial_source_query::RootInitialSourceQueryErrorV1 as E;
use super::RootOwnedCurrentOriginalV1;

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Pays the fixed initial query from the same genuine completed trust prefix.
    ///
    /// # Errors
    /// Retains prior purpose, repeated entry, foreign Initial, supplier, debit or
    /// service refusal. No request is encoded under this short L/U loan.
    pub fn begin_initial_source_query_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.source_query.claim_entry_once_v1().is_err() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        if self.require_initial_trust_complete_v1().is_err() {
            self.source_query.refuse_unprepared_v1();
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let predecessor = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.source_query.park_predecessor_refusal_v1(error);
                return Err(RootObservationErrorV1::Service);
            }
        };
        let open = self.open.as_ref().ok_or(RootObservationErrorV1::Service)?;
        let trust = self.trust.as_ref().ok_or(RootObservationErrorV1::Service)?;
        self.source_query.begin_once_v1(
            &open.prepared, &self.ready, trust, predecessor, startup, exclusion,
        )
    }

    /// Constructs the initial query using the sole existing protocol codecs.
    ///
    /// # Errors
    /// Refuses missing genuine trust/receiving completion, malformed Ready
    /// framing, another lane, or actual Root-record/query encoding failure.
    pub fn encode_initial_source_query_once_v1(&mut self) -> Result<(), E> {
        self.require_initial_trust_complete_v1().map_err(|_| E::Incomplete)?;
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        self.source_query.encode_once_v1(&open.prepared, &self.ready)
    }

    /// Requires this actual query's original Root record and Ready-held receipt.
    ///
    /// # Errors
    /// Refuses incomplete same-owner trust/query custody or changed correlation.
    pub fn require_initial_source_query_complete_v1(&self) -> Result<(), E> {
        self.require_initial_trust_complete_v1().map_err(|_| E::Incomplete)?;
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        self.source_query.require_complete_for_v1(&open.prepared, &self.ready)
    }

    /// Borrows the encoded protocol DATA from the same completed query owner.
    ///
    /// # Errors
    /// Refuses incomplete or changed actual originals. Request DATA is not a
    /// reply, Cache/Use grant, append gate or a replacement purpose owner.
    pub fn initial_source_query_bytes_data_v1(
        &self,
    ) -> Result<&[u8; SOURCE_CURRENT_QUERY_BYTES_V1], E> {
        self.require_initial_source_query_complete_v1()?;
        self.source_query.prepared_bytes_v1()
    }
}
