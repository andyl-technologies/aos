//! Advances the same owned Current through its Reserved Source exchange.
//!
//! Native transport and reply verification remain outside the short real
//! Initial/L/U stages. Its independently owed post APIs operate on retained
//! originals after body failure and never accept supplied completed results.

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::{
    SourceCurrentReplyFieldsV1, SOURCE_CURRENT_PACKET_BYTES_V1,
};

use super::super::initial_source_exchange::RootInitialSourceExchangeErrorV1 as E;
use super::RootOwnedCurrentOriginalV1;
use super::super::proof_turn::RootCurrentProofTurnV1;

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Pays the actual Source exchange from the same admitted original query.
    ///
    /// # Errors
    /// Retains prior purpose, repeated entry, same-Initial, supplier, debit or
    /// selected service refusal. No native socket or writer IO runs under L/U.
    pub fn begin_use_source_exchange_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.refreshed_source_exchange.claim_entry_once_v1().is_err() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        if self.require_use_source_query_complete_v1().is_err() {
            self.refreshed_source_exchange.refuse_unprepared_v1();
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let predecessor = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.refreshed_source_exchange.park_predecessor_refusal_v1(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let open = self.open.as_ref().ok_or(RootObservationErrorV1::Service)?;
        let returned = self.refreshed_source_exchange.begin_once_v1(
            &open.prepared, &self.ready, &self.refreshed_source_query,
            predecessor, startup, exclusion,
        );
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
        returned
    }

    /// Runs the same fixed native transport and authenticates the original query.
    ///
    /// The supplied UID/GID remain the original socket-custody expectations.
    /// The fixed transport independently observes its actual compiled endpoint;
    /// those scalar expectations cannot construct a native role or successful pin.
    ///
    /// # Errors
    /// Retains real writer/readback/clock/socket/framing/signature/correlation
    /// refusal. All originals stay owned and admitted posts remain owed.
    pub fn exchange_use_source_once_v1(
        &mut self,
        signer_uid: u32,
        socket_gid: u32,
    ) -> Result<(), E> {
        self.require_use_source_query_complete_v1().map_err(|_| E::Incomplete)?;
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        let writers = match &self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        self.refreshed_source_exchange.exchange_for_turn_once_v1(
            writers, &open.prepared, &self.pins, &self.refreshed_source_query,
            signer_uid, socket_gid,
            RootCurrentProofTurnV1::Reserved { authorization: &self.use_authorized, reserved: &self.use_reserved },
        )
    }

    /// Observes the independent same-writer post after an admitted body attempt.
    pub fn observe_use_source_exchange_native_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Some(Ok(writers)) = &self.writers {
            self.refreshed_source_exchange.observe_native_posts_for_turn_once_v1(writers, &open.prepared,
                RootCurrentProofTurnV1::Reserved { authorization: &self.use_authorized, reserved: &self.use_reserved });
        }
    }

    /// Arms the genuine independently owed Source-exchange peer post.
    pub fn arm_use_source_exchange_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        let returned = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => self.refreshed_source_exchange.arm_peer_once_v1(predecessor, startup, exclusion),
            Err(error) => {
                self.refreshed_source_exchange.park_peer_refusal_v1(error);
                Err(())
            }
        };
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Negatively closes an upper arm refusal without suppressing its owed clock.
    pub fn refuse_use_source_exchange_post_arm_once_v1(&mut self) {
        self.refreshed_source_exchange.refuse_peer_arm_once_v1();
    }

    /// Observes the independent peer, retained clock and reply interval check.
    pub fn observe_use_source_exchange_post_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        self.refreshed_source_exchange.observe_peer_and_clock_once_v1(&self.originals, &open.prepared);
    }

    /// Requires this actual exchange and both independently reached post stages.
    ///
    /// # Errors
    /// Refuses any incomplete same-owner prior stage, native body or owed post.
    pub fn require_use_source_exchange_complete_v1(&self) -> Result<(), E> {
        self.require_use_source_query_complete_v1().map_err(|_| E::Incomplete)?;
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        self.refreshed_source_exchange.require_use_complete_for_v1(&open.prepared, &self.use_authorized, &self.use_reserved)
    }

    /// Borrows authenticated reply packet DATA from this same complete exchange.
    ///
    /// # Errors
    /// Refuses incomplete actual originals. Packet DATA grants no native Cache,
    /// Use, append, NoApply, signing or terminal serving transition.
    pub fn use_source_reply_packet_data_v1(
        &self,
    ) -> Result<&[u8; SOURCE_CURRENT_PACKET_BYTES_V1], E> {
        self.require_use_source_exchange_complete_v1()?;
        self.refreshed_source_exchange.verified_packet_v1()
    }

    /// Copies authenticated reply field DATA from this same completed exchange.
    ///
    /// # Errors
    /// Refuses incomplete genuine exchange or any same-owner prior failure.
    pub fn use_source_reply_fields_data_v1(&self) -> Result<SourceCurrentReplyFieldsV1, E> {
        self.require_use_source_exchange_complete_v1()?;
        self.refreshed_source_exchange.fields_v1()
    }

    /// Reads the original minimum Root/Source cutoff after actual completion.
    ///
    /// # Errors
    /// Refuses incomplete custody; no caller cutoff can renew either interval.
    pub fn use_source_reply_cutoff_data_v1(&self) -> Result<u64, E> {
        self.require_use_source_exchange_complete_v1()?;
        self.refreshed_source_exchange.original_cutoff_v1()
    }
}
