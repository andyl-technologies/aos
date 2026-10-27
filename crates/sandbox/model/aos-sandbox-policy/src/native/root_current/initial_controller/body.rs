//! Keeps Initial's receipt, rooted opening and native Audit in their old order.
//!
//! Each method is one finite outside-exclusion interval. The actual purpose
//! retains every result and opens the next interval only after its real stage.

use super::*;

impl RootInitialControllerReadonlyBodyV1 {
    pub(super) fn claim_body_scope_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), E> {
        self.fixed.require_complete_v1()?;
        if self.body_entered || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.body_entered = true;
        let uid = open.body_v1().map(|body| body.controller_uid).unwrap_or(0);
        self.reader.begin_current_purpose_once_v1(uid)?;
        Ok(())
    }

    pub(super) fn arm_body_peer_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if !self.body_entered || self.peer_original.is_some() || self.peer_arm.is_some() {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.peer_original = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(
            predecessor,
            startup,
            exclusion,
        ));
        self.peer_arm = Some(match &self.peer_original {
            Some(original) => original.require_armed_v1(),
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer_arm, Some(Ok(()))) {
            Ok(())
        } else {
            self.primary.get_or_insert(Err(E::Incomplete));
            Err(RootObservationErrorV1::Service)
        }
    }

    pub(super) fn park_body_peer_refusal_once_v1(&mut self, error: RootObservationErrorV1) {
        if self.peer_arm.is_none() {
            self.peer_arm = Some(Err(error));
            self.primary.get_or_insert(Err(E::Incomplete));
        }
    }

    pub(super) fn admit_named_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        self.receiving
            .admit_named_once_v1(initial, open, &self.fixed, financial, exclusion)
    }

    pub(super) fn refuse_named_entry_once_v1(&mut self) {
        self.receiving.refuse_named_entry_once_v1();
    }

    pub(super) fn prepare_files_once_v1(
        &mut self,
        receipt: InputsReadyNativeReceiptDataV1<'_>,
    ) -> Result<(), E> {
        {
            let mut receiving = self.receiving.preparation_v1();
            self.reader.prepare_current_files_once_v1(&mut receiving);
        }
        if self.reader.failure().is_some() {
            self.primary.get_or_insert(Err(E::Incomplete));
            return Err(E::Incomplete);
        }
        self.captured_binding = Some((|| {
            let extent = self.reader.captured_extent_v1()?;
            if extent.native_bytes != self.expected_end.unwrap_or(receipt.after_end) {
                return Err(ReadError::ProtectedBoundary);
            }
            Ok(())
        })());
        positive(&self.captured_binding).map(|_| ())
    }

    pub(super) fn audit_native_once_v1(&mut self, bundle: ReadyBundleDataV1<'_>) -> Result<(), E> {
        self.native.require_complete_v1()?;
        if self.audit_entered || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.audit_entered = true;
        let geometry = positive(&self.history_geometry)?;
        // The SAME native-stage quote paid these two variable copies before
        // their first transaction construction. InputsReady stayed fixed-paid.
        for (index, record) in [bundle.intent_record, bundle.assignment_planned]
            .into_iter()
            .enumerate()
        {
            let key = KeyV1::new(bundle.lane, OwnerV1::Controller, (index + 1) as u64)?;
            let phase = PhaseV1::new(OwnerV1::Controller, [1, 12][index])?;
            self.previous_expected[index] = Some(prepare_readonly_pair(
                key,
                phase,
                record,
                &geometry.heads[index],
            ));
            positive(&self.previous_expected[index])?;
        }
        self.reader.audit_once();
        let audit = self.reader.current_audit_original_v1();
        if audit.failure().is_some() {
            self.primary.get_or_insert(Err(E::Incomplete));
            return Err(E::Incomplete);
        }
        self.bank_use_geometry = Some(aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory::additional_use_receiving_demand_v1(
            audit.native_data_v1().and_then(|native| native.state()).ok_or(E::Incomplete)?,
        ));
        positive(&self.bank_use_geometry).map(|_| ())
    }
}

pub(in crate::native::root_current) fn prepare_readonly_pair(
    key: KeyV1,
    phase: PhaseV1,
    record: &[u8],
    head: &[u8; 40],
) -> Result<JournalTransaction, ReadError> {
    aos_sandbox_protocol::prepare_readonly_history_pair_recipe_v1!(
        key = key, phase = phase, record = record,
        invalid = ReadError::ProtectedBoundary,
        prepared = aos_sandbox_protocol::domain_ledger::create_storage_history::prepare_history_pair_v1(
            key, phase, record, head,
        ).map_err(|error| match error {
            aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1::Envelope => ReadError::ProtectedBoundary,
            aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1::Transaction(cause) => ReadError::from(Mechanical::from(cause)),
        })
    )
}
