//! Derives the unsigned proposal and Root body from the same completed owners.
//!
//! The upper pure calculator receives only passive dimensions and the verified
//! snapshot. Its returned vector is encoded as a proposal; it cannot satisfy the
//! local Root Stage or Controller's independent real admission and rechecks.

use super::*;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    cache_held::CacheHeldBodyDataV1,
    use_authorized::{current_proofs_commitment_v1, source_current_reply_commitment_v1},
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;
use super::super::{
    initial_bundle::RootInitialBundleOwnershipOriginalV1,
    initial_cache::RootInitialCacheProofOriginalV1,
    initial_controller::RootInitialControllerReadonlyOriginalV1,
    initial_open::RootInitialOpenPreparedOriginalV1,
    initial_ready::RootInitialReadyOriginalV1,
    initial_source_exchange::RootInitialSourceExchangeOriginalV1,
};

/// Borrows passive dimensions from the actual completed Root Current purposes.
///
/// These values size an unsigned future Controller proposal. They supply no
/// original, successful phase, local Root receiving permit or mutation grant.
pub struct RootInitialUseProspectiveInputsDataV1<'snapshot> {
    /// Contains the same independently retained Session recipe's limits.
    pub session_limits: JournalLimits,
    /// Contains the same independently retained Session native prefix length.
    pub session_native_bytes: u64,
    /// Contains the actual independently captured Controller recipe's limits.
    pub controller_limits: JournalLimits,
    /// Contains that same Controller native prefix length.
    pub controller_native_bytes: u64,
    /// Contains the signed Source current reply's original end.
    pub source_end: u64,
    /// Contains the protected-built prospective request's normalized byte width.
    pub request_shape_bytes: usize,
    /// Borrows the five Cache ends from the same verified current body.
    pub cache_snapshot: &'snapshot CacheHeldBodyDataV1,
}

/// Mutably borrows the genuine UseAuthorized body beside its real predecessors.
///
/// There is no public constructor. The owned programme lends this only after
/// its own local fixed admission and independently armed append post.
pub struct RootInitialUseAuthorizedPreparedBorrowV1<'turn> {
    pub(in crate::native::root_current) state: &'turn mut RootInitialUseAuthorizedOriginalV1,
    pub(in crate::native::root_current) open: &'turn RootInitialOpenPreparedOriginalV1,
    pub(in crate::native::root_current) ready: &'turn RootInitialReadyOriginalV1,
    pub(in crate::native::root_current) source: &'turn RootInitialSourceExchangeOriginalV1,
    pub(in crate::native::root_current) cache: &'turn RootInitialCacheProofOriginalV1,
    pub(in crate::native::root_current) ownership: &'turn RootInitialBundleOwnershipOriginalV1,
    pub(in crate::native::root_current) readonly: &'turn RootInitialControllerReadonlyOriginalV1,
}

impl RootInitialUseAuthorizedPreparedBorrowV1<'_> {
    /// Borrows only the proposal inputs from the same actual completed owners.
    ///
    /// # Errors
    /// Refuses an incomplete Controller, Source, Cache, Ownership or original
    /// full Session/Controller extent and retains each cause on its real owner.
    pub fn prospective_inputs_v1(&self) -> Result<RootInitialUseProspectiveInputsDataV1<'_>, E> {
        self.readonly.require_complete_v1().map_err(|_| E::Incomplete)?;
        self.source.require_complete_v1().map_err(|_| E::Incomplete)?;
        self.cache.require_complete_v1().map_err(|_| E::Incomplete)?;
        self.ownership.require_complete_v1().map_err(|_| E::Incomplete)?;
        let session = self.readonly.prospective_session_extent_v1().map_err(|_| E::Incomplete)?;
        let controller = self.readonly.actual_controller_extent_v1().map_err(|_| E::Incomplete)?;
        Ok(RootInitialUseProspectiveInputsDataV1 {
            session_limits: session.limits,
            session_native_bytes: session.native_bytes,
            controller_limits: controller.limits,
            controller_native_bytes: controller.native_bytes,
            source_end: self.source.fields_v1().map_err(|_| E::Incomplete)?.source_end,
            request_shape_bytes: self.readonly.prospective_use_plan_v1().map_err(|_| E::Incomplete)?
                .request_shape_bytes_v1(),
            cache_snapshot: &self.cache.verified_body_v1().map_err(|_| E::Incomplete)?.snapshot,
        })
    }

    /// Parks the unsigned calculator result and prepares the exact Root members.
    ///
    /// This DATA does not complete the local Stage, append, send, owed posts or
    /// Controller Use. The same actual Current borrowers derive every binding.
    ///
    /// # Errors
    /// Retains the original prospective quote refusal and refuses reentry,
    /// malformed history, incomplete native predecessors or checked overflow.
    pub fn prepare_proposal_once_v1(
        &mut self,
        receiving: Result<ResourceVector, crate::storage_session_geometry_data::StorageSessionGeometryRefusalV1>,
    ) -> Result<(), E> {
        if self.state.receiving.is_some() || self.state.primary.is_some() || self.state.closed {
            self.state.closed = true;
            return Err(E::Incomplete);
        }
        self.state.receiving = Some(receiving);
        let result = self.prepare_inner();
        self.state.primary = Some(result);
        positive(&self.state.primary).map(|_| ())
    }

    fn prepare_inner(&mut self) -> Result<(), E> {
        let receiving = *positive(&self.state.receiving)?;
        self.state.body = Some(self.make_body(receiving));
        let body = *positive(&self.state.body)?;
        self.state.body_encoding = Some(body.encode());
        let lane = self.open.body_v1()?.open.lane;
        let key = KeyV1::new(lane, OwnerV1::Root, 2)?;
        let phase = PhaseV1::new(OwnerV1::Root, 2)?;
        self.state.pair.prepare_once_v1(key, phase, body.root_open, body.association.seed,
            positive(&self.state.body_encoding)?)?;
        self.state.pair.prepare_use_authorized_cut_once_v1(self.open)
            .map_err(E::from)
    }

    fn make_body(&self, receiving: ResourceVector) -> Result<UseAuthorizedBodyDataV1, E> {
        let root_body = self.open.body_v1()?;
        let inputs = self.cache.controller_receipt_v1(self.open, self.ready).map_err(|_| E::Incomplete)?;
        let input = inputs.body(root_body.open.lane)?;
        let root_record = RecordEnvelopeV1::decode(self.open.committed_record_v1()?,
            KeyV1::new(root_body.open.lane, OwnerV1::Root, 1)?,
            PhaseV1::new(OwnerV1::Root, 1)?)?;
        let input_record = RecordEnvelopeV1::decode(inputs.record,
            KeyV1::new(root_body.open.lane, OwnerV1::Controller, 3)?,
            PhaseV1::new(OwnerV1::Controller, 2)?)?;
        let lease = self.ownership.completed_response_v1().map_err(|_| E::Incomplete)?
            .value().ok_or(E::Incomplete)?;
        Ok(UseAuthorizedBodyDataV1 {
            association: input.association,
            root_nonce: root_body.root_nonce,
            root_open: root_record.checksum(),
            ready: root_body.open.ready,
            inputs_ready: input_record.checksum(),
            current_proofs: current_proofs_commitment_v1(self.cache.current_proofs_payload_v1().map_err(|_| E::Incomplete)?),
            source_current: source_current_reply_commitment_v1(self.source.verified_packet_v1().map_err(|_| E::Incomplete)?),
            assignment: *self.ownership.completed_manifest_v1().map_err(|_| E::Incomplete)?.digest().as_bytes(),
            ownership_lease: *lease.digest().as_bytes(),
            receiving,
        })
    }

    /// Borrows the actual first retained body refusal without observing anything.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.state.failure_v1()
    }
}
