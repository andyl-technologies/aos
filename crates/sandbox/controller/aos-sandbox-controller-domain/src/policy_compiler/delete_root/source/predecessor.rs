//! Binds the actual pre-Planned Source prefix to the same fresh signed D reply.
//!
//! The fixed Root Source reader keeps its own files, names, canonical cursor,
//! complete semantic models and independently owed native afters. The existing
//! Source stage's paid Root/C/clock bookends enclose this entire read as well.

use super::*;

#[derive(Clone, Copy)]
pub(crate) enum RootDeleteSourcePredecessorPhaseV2 {
    Native,
    Semantic,
}

impl RootDeleteSourcePredecessorPhaseV2 {
    fn index(self) -> usize {
        match self {
            Self::Native => 0,
            Self::Semantic => 1,
        }
    }
}

impl RootDeleteSourceCurrentOriginalV1 {
    pub(super) fn observe_predecessor_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &mut RootDeleteControllerCurrentOriginalV1,
        query: SourceDeleteCurrentQueryDataV1,
        fields: SourceDeleteCurrentReplyFieldsV1,
        uid: u32,
    ) -> Result<(), RootDeleteErrorV1> {
        self.predecessor.as_mut().ok_or(RootDeleteErrorV1::Original)?.capture_once(uid);
        self.predecessor_capture = Some(self.predecessor.as_ref().ok_or(RootDeleteErrorV1::Original)?.require_captured_v1());
        self.require(
            matches!(self.predecessor_capture, Some(Ok(()))),
            First::Predecessor,
        )?;
        self.predecessor_native = Some(self.predecessor.as_ref().ok_or(RootDeleteErrorV1::Original)?.replay_demand_v1());
        self.require(
            matches!(self.predecessor_native, Some(Ok(_))),
            First::Predecessor,
        )?;
        self.admit_predecessor_v2(
            flight,
            challenge,
            controller,
            RootDeleteSourcePredecessorPhaseV2::Native,
        )?;
        self.predecessor.as_mut().ok_or(RootDeleteErrorV1::Original)?
            .audit_delete_graph_once_v2(controller.graph_controller_rows_v2()?);
        self.predecessor_semantic =
            Some(self.predecessor.as_ref().ok_or(RootDeleteErrorV1::Original)?.additional_delete_graph_predecessor_demand_v2());
        self.require(
            matches!(self.predecessor_semantic, Some(Ok(_))),
            First::Predecessor,
        )?;
        self.admit_predecessor_v2(
            flight,
            challenge,
            controller,
            RootDeleteSourcePredecessorPhaseV2::Semantic,
        )?;
        let original = self.predecessor.as_mut().ok_or(RootDeleteErrorV1::Original)?;
        let (state, census) = controller.take_graph_inputs_v2()?;
        self.predecessor_graph_entry = Some(original.replay_delete_graph_predecessor_once_v2(
            query, fields.pending_native, state, census));
        self.require(matches!(self.predecessor_graph_entry, Some(Ok(()))), First::Predecessor)?;
        self.require(self.predecessor.as_ref().is_some_and(|original| original.failure().is_none()), First::Predecessor)
    }

    fn admit_predecessor_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
        phase: RootDeleteSourcePredecessorPhaseV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.predecessor_phase = Some(phase);
        self.predecessor_permits[phase.index()] =
            Some(flight.admit_delete_source_predecessor_v2(challenge, controller, self));
        self.require(
            matches!(self.predecessor_permits[phase.index()], Some(Ok(()))),
            First::PredecessorPermit(phase.index()),
        )
    }

    pub(super) fn finish_predecessor_binding_v2(&mut self) {
        self.predecessor_binding = Some((|| {
            let fields = self
                .reply
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(SourceDeleteCurrentDataErrorV1::Native)?
                .fields;
            let native = self.predecessor_readback_v2()
                .map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?;
            let actual = self.predecessor_data_v2()
                .map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?;
            if native.names != fields.names
                || native.next != fields.next
                || native.end != fields.end
                || actual.native != fields.pending_native
                || actual.tree.generation != fields.tree_generation
                || actual.tree.commitment != fields.tree_commitment
                || actual.tree.head != fields.tree_head
                || actual.tree.lineage != fields.lineage_head
            {
                return Err(SourceDeleteCurrentDataErrorV1::Association);
            }
            Ok(())
        })());
        if !matches!(self.predecessor_binding, Some(Ok(()))) {
            self.first.get_or_insert(First::PredecessorBinding);
        }
    }

    // This DATA getter is downstream of the actual complete Source stage,
    // including signature, all64 native bytes, Root clocks/service afters and
    // independent Source native mount/name/metadata posts. No raw model enters.
    pub(crate) fn verified_source_predecessor_v2(
        &self,
    ) -> Result<
        aos_sandbox_ledger_replay::delete_pending::DeleteSourcePredecessorDataV2,
        RootDeleteErrorV1,
    > {
        self.verified_fields_v1()?;
        if !matches!(self.predecessor_binding, Some(Ok(()))) {
            return Err(RootDeleteErrorV1::Original);
        }
        self.predecessor_data_v2()
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    // The caller has paid the complete batch decoder before this getter. The
    // record comes from this actual completed old Source cut, not caller DATA.
    pub(in crate::policy_compiler::delete_root) fn planned_batch_data_v3(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::delete_batch::LifecycleDeleteBatchRecordV1, Box<dyn std::error::Error + Send + Sync>>
    {
        use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::{
            LIFECYCLE_PROTECTED_KEY_PREFIX_V1, borrow_lifecycle_auxiliary_member_data_v1};
        use aos_sandbox_protocol::domain_ledger::records::borrowed::borrow_protected_key_data_v1;
        let fields = self.verified_fields_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        let native = self.predecessor_readback_v2()?;
        let transaction: [u8;16] = fields.pending_native[..16].try_into().map_err(|_| JournalError::ProtectedBoundary)?;
        let mut selected = None;
        for ((namespace, key), value) in native.state {
            if *namespace != crate::RecordNamespace::DesiredState || !key.starts_with(LIFECYCLE_PROTECTED_KEY_PREFIX_V1) { continue; }
            let (kind, identity) = borrow_protected_key_data_v1(key, LIFECYCLE_PROTECTED_KEY_PREFIX_V1)?;
            if kind != 5 || identity.len() != 48 || identity[..16] != fields.project || identity[32..] != fields.operation { continue; }
            let member = borrow_lifecycle_auxiliary_member_data_v1(key, value, &transaction)?;
            if member.kind != crate::lifecycle::LifecycleAuxiliaryKindV1::DeleteBatch as u8 { continue; }
            let record = aos_sandbox_protocol::domain_ledger::delete_batch::LifecycleDeleteBatchRecordV1::from_bytes(member.payload)?;
            if record.state() != 1 || record.batch().project().as_bytes() != &fields.project
                || record.batch().operation().as_bytes() != &fields.operation || selected.is_some()
                || aos_sandbox_protocol::domain_ledger::delete_root::source_current::source_delete_current_batch_digest_v1(record.batch().as_bytes())
                    .map_err(|_| JournalError::StaleAuthoritySnapshot)? != fields.batch { return Err(JournalError::StaleAuthoritySnapshot.into()); }
            selected = Some(record);
        }
        selected.ok_or_else(|| JournalError::ProtectedBoundary.into())
    }

    pub(crate) fn verified_graph_request_receiving_bytes_v2(&self) -> Result<usize, JournalError> {
        self.verified_source_predecessor_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        self.completed_predecessor.as_ref().ok_or(JournalError::ProtectedBoundary)?
            .delete_graph_request_receiving_bytes_v2()
    }

    // This move is permitted only after the SAME Source signature, EOF/native64,
    // prior cut, full semantics and all Source/Root/C/clock afters completed.
    pub(crate) fn take_verified_graph_base_v2(&mut self)
        -> Result<aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphBaseDataV2, RootDeleteErrorV1>
    {
        self.verified_source_predecessor_v2()?;
        let result = self.completed_predecessor.as_mut().ok_or(RootDeleteErrorV1::Original)?
            .take_delete_graph_base_data_v2().map_err(|_| RootDeleteErrorV1::Original);
        if result.is_err() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
        }
        result
    }

    fn predecessor_readback_v2(&self) -> Result<
        crate::policy_compiler::create_storage_current::controller_readonly::native_read::RootFixedNativeReadbackV1<'_>,
        JournalError,
    > {
        match &self.completed_predecessor {
            Some(data) => data.readback_v2(),
            None => self.predecessor.as_ref().ok_or(JournalError::ProtectedBoundary)?.terminal_native_v1(),
        }
    }

    fn predecessor_data_v2(&self) -> Result<
        aos_sandbox_ledger_replay::delete_pending::DeleteSourcePredecessorDataV2,
        JournalError,
    > {
        match &self.completed_predecessor {
            Some(data) => data.delete_predecessor_data_v2(),
            None => self.predecessor.as_ref().ok_or(JournalError::ProtectedBoundary)?.delete_predecessor_data_v2(),
        }
    }

    pub(super) fn retire_predecessor_once_v2(&mut self) -> Result<(), JournalError> {
        if self.completed_predecessor.is_some() { return Err(JournalError::ProtectedBoundary); }
        let original = self.predecessor.take().ok_or(JournalError::ProtectedBoundary)?;
        match original.into_completed_data_v2() {
            Ok(data) => { self.completed_predecessor = Some(data); Ok(()) }
            Err(original) => { self.predecessor = Some(original); Err(JournalError::ProtectedBoundary) }
        }
    }

    pub(super) fn retained_predecessor_shape_v2(
        &self,
        mut shape: ResourceVector,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if let Some(Ok(native)) = &self.predecessor_native {
            shape = shape.checked_add(*native)?;
        }
        if let Some(Ok(semantic)) = &self.predecessor_semantic {
            shape = shape.checked_add(*semantic)?;
        }
        Ok(shape)
    }

    pub(crate) fn predecessor_receiving_demand_v2(
        &self,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let phase = self
            .predecessor_phase
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if !self.entered
            || !self.native_entered
            || self.complete
            || self.first.is_some()
            || !matches!(self.signature, Some(Ok(())))
            || !matches!(self.native, Some(Ok(())))
            || !matches!(self.predecessor_capture, Some(Ok(())))
            || self.predecessor_permits[phase.index()].is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if !matches!(self.predecessor_native, Some(Ok(_)))
            || matches!(phase, RootDeleteSourcePredecessorPhaseV2::Semantic)
                && !matches!(self.predecessor_semantic, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.retained_predecessor_shape_v2(self.receiving_recipe_v1()?)
            .map(aos_sandbox_model::component_receiving::without_operation_traffic_v1)
    }
}
