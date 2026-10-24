//! Advances the same owned Current through its finite Reserved Cache proof turn.
//!
//! Configuration comes from the actual producer, while signer pins and Ready
//! bytes remain on the same enclosing owner. No turn, signer tuple, proof DATA,
//! supplied stream or successful result can construct this purpose.

use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootObservationErrorV1,
    RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    cache_held::current_proof::CacheCurrentProofBodyDataV1,
    use_reserved::USE_CURRENT_PROOFS_BYTES_V1,
};

use super::super::initial_cache::{
    RootInitialCacheProofErrorV1 as E, RootInitialCacheProofFrameBorrowV1,
};
use super::RootOwnedCurrentOriginalV1;
use super::super::proof_turn::RootCurrentProofTurnV1;

impl<'startup> RootOwnedCurrentOriginalV1<'startup> {
    /// Pays refreshed Cache framing from its actual complete Source/pins prefix.
    ///
    /// # Errors
    /// Retains repeated entry, prior purpose, same-Initial, supplier, debit or
    /// selected service refusal. No framing, decoder capsule or native IO runs here.
    pub fn begin_use_cache_proof_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.refreshed_cache_proof.claim_fixed_once_v1().is_err() {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        if self.require_use_source_exchange_complete_v1().is_err()
            || self.require_initial_bundle_ownership_complete_v1().is_err()
            || self.require_initial_pins_complete_v1().is_err()
        {
            self.refreshed_cache_proof.refuse_unprepared_v1();
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let predecessor = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.refreshed_cache_proof.park_predecessor_refusal_v1(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let open = self.open.as_ref().ok_or(RootObservationErrorV1::Service)?;
        let returned = self.refreshed_cache_proof.begin_reserved_fixed_once_v1(
            &open.prepared, &self.bundle_ownership, &self.pins, &self.refreshed_source_exchange,
            &self.use_authorized, &self.use_reserved, predecessor, startup, exclusion,
        );
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
        returned
    }

    /// Starts Root's signer half before inviting the same Controller proof frame.
    ///
    /// # Errors
    /// Retains framing, configuration, bookend, clock, connection, invitation or
    /// strict-buffer refusal. Every fixed-admitted body still owes the posts.
    pub fn borrow_use_cache_proof_once_v1(
        &mut self,
    ) -> Result<RootInitialCacheProofFrameBorrowV1<'_, 'startup>, E> {
        self.require_use_source_exchange_complete_v1().map_err(|_| E::Incomplete)?;
        self.require_initial_bundle_ownership_complete_v1()?;
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        let writers = match &self.writers {
            Some(Ok(writers)) => writers,
            _ => return Err(E::Incomplete),
        };
        RootInitialCacheProofFrameBorrowV1::prepare_reserved_once_v1(
            &mut self.refreshed_cache_proof, writers, &open.prepared, &self.ready,
            &self.refreshed_source_exchange, &self.pins, &self.bundle_ownership,
            &mut self.originals, &self.original, &self.use_authorized, &self.use_reserved,
        )
    }

    /// Observes independent location/readback posts after actual fixed admission.
    pub fn observe_use_cache_proof_native_posts_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        if let Some(Ok(writers)) = &self.writers {
            self.refreshed_cache_proof.observe_native_posts_for_turn_once_v1(writers, &open.prepared,
                RootCurrentProofTurnV1::Reserved { authorization: &self.use_authorized, reserved: &self.use_reserved });
        }
    }

    /// Arms the genuine independently owed Cache proof peer post.
    pub fn arm_use_cache_proof_post_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        let returned = match self.originals.peer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => self.refreshed_cache_proof.arm_peer_once_v1(predecessor, startup, exclusion),
            Err(error) => {
                self.refreshed_cache_proof.park_peer_refusal_v1(error);
                Err(())
            }
        };
        if returned.is_err() {
            initial.latch_root_refusal_v1();
        }
    }

    /// Negatively parks an upper arm refusal without suppressing its owed clock.
    pub fn refuse_use_cache_proof_post_arm_once_v1(&mut self) {
        self.refreshed_cache_proof.refuse_peer_arm_once_v1();
    }

    /// Observes the independently owed peer, retained clock and sample ordering.
    pub fn observe_use_cache_proof_post_once_v1(&mut self) {
        let Some(open) = &self.open else {
            return;
        };
        self.refreshed_cache_proof.observe_peer_and_clock_once_v1(
            &self.originals, &open.prepared, &self.refreshed_source_exchange,
        );
    }

    /// Requires both actual signer halves and every independently owed post.
    ///
    /// # Errors
    /// Refuses incomplete prior stages, actual framing/signature/packet
    /// refusal, or either native/peer/clock post failure.
    pub fn require_use_cache_proof_complete_v1(&self) -> Result<(), E> {
        self.require_initial_bundle_ownership_complete_v1()?;
        let open = self.open.as_ref().ok_or(E::Incomplete)?;
        self.refreshed_cache_proof.require_use_complete_for_v1(&open.prepared, &self.use_authorized, &self.use_reserved)
    }

    /// Borrows the independently verified packet as comparison DATA.
    ///
    /// # Errors
    /// Refuses incomplete actual custody; DATA supplies no Controller/Use grant.
    pub fn use_cache_packet_data_v1(&self) -> Result<&[u8], E> {
        self.require_use_cache_proof_complete_v1()?;
        self.refreshed_cache_proof.verified_packet_v1()
    }

    /// Borrows the saved verified Cache body as comparison DATA.
    ///
    /// # Errors
    /// Refuses incomplete actual custody and independently owed posts.
    pub fn use_cache_body_data_v1(&self) -> Result<&CacheCurrentProofBodyDataV1, E> {
        self.require_use_cache_proof_complete_v1()?;
        self.refreshed_cache_proof.verified_body_v1()
    }

    /// Borrows the exact UseCurrentProofs payload as comparison DATA.
    ///
    /// # Errors
    /// Refuses incomplete custody or an unexpected retained frame extent.
    pub fn use_cache_proofs_payload_data_v1(&self) -> Result<&[u8; USE_CURRENT_PROOFS_BYTES_V1], E> {
        self.require_use_cache_proof_complete_v1()?;
        self.refreshed_cache_proof.use_current_proofs_payload_v1()
    }
}
