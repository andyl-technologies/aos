//! Borrows the actual Core-completed child after its same C23 and Root posts.
//!
//! The raw Effect is captured from the canonical Core result, then compared to
//! the still-held Controller map. This cannot construct an Apply, publication
//! action or lifecycle capability from serialized bytes or a success flag.

use super::*;
use aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRowKindV1;

/// Keeps the actual Action, C23, Root client and Controller borrowed together.
///
/// Its private constructor is the same genuine Action's completed method. The
/// canonical receipt encoder separately consumes the exact raw child and the
/// actual committed typed companion set; neither getter grants another turn.
pub(crate) struct CompletedPublicationChildDataV1<'held> {
    effect: &'held [u8],
    records: ProvisioningResourceRecordsV1,
    _action: &'held OriginalPublicationActionV1,
    _receiving: &'held crate::CreateProvisioningOriginalsV1,
    _root: ChildRootCustodyV1<'held>,
    _controller: &'held Journal,
}

enum ChildRootCustodyV1<'held> {
    Completed(&'held crate::normal_root::RootStorageApplyClientOriginalV1),
    Current(&'held crate::normal_root::RootStorageApplyCurrentTurnV1<'held>),
}

impl CompletedPublicationChildDataV1<'_> {
    pub(crate) const fn applied_effect_v1(&self) -> &[u8] { self.effect }

    pub(crate) const fn records_v1(&self) -> ProvisioningResourceRecordsV1 { self.records }
}

impl OriginalPublicationActionV1 {
    /// Lends only this actual completed child's still-held native readback.
    ///
    /// This is a comparison borrower, not the complete outer Source terminal.
    /// The next lifecycle phase must independently validate the actual stored
    /// request/outcome, fresh workspace inventory and current Source operation.
    pub(crate) fn completed_child_data_v1<'held>(&'held self,
        receiving: &'held crate::CreateProvisioningOriginalsV1,
        root: &'held crate::normal_root::RootStorageApplyClientOriginalV1,
        controller: &'held Journal,
    ) -> Result<CompletedPublicationChildDataV1<'held>, ResourceReservationErrorV1> {
        if !self.child_succeeded_v1()
            || self.contract.records.fields_v1().mode != ProvisioningModeDataV1::CreateStopped {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        root.require_completed_publication_turn_v1(self, receiving, controller)?;
        self.completed_child_from_current_rows_v1(receiving, ChildRootCustodyV1::Completed(root), controller)
    }

    /// Rejoins the same captured child inside the next genuine Source window.
    ///
    /// A completed-only borrower cannot outlive begin-next. This method instead
    /// requires the actual current Root/C23 window, then shares the exact held
    /// child and companion comparison with the completed borrower.
    pub(crate) fn child_for_current_source_v1<'held>(&'held self,
        receiving: &'held crate::CreateProvisioningOriginalsV1,
        turn: &'held crate::normal_root::RootStorageApplyCurrentTurnV1<'held>,
        controller: &'held Journal,
    ) -> Result<CompletedPublicationChildDataV1<'held>, ResourceReservationErrorV1> {
        turn.require_action_v1(self, receiving, controller)?;
        self.completed_child_from_current_rows_v1(receiving, ChildRootCustodyV1::Current(turn), controller)
    }

    fn completed_child_from_current_rows_v1<'held>(&'held self,
        receiving: &'held crate::CreateProvisioningOriginalsV1,
        root: ChildRootCustodyV1<'held>,
        controller: &'held Journal,
    ) -> Result<CompletedPublicationChildDataV1<'held>, ResourceReservationErrorV1> {
        if !self.child_succeeded_v1()
            || self.contract.records.fields_v1().mode != ProvisioningModeDataV1::CreateStopped {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let original = self.completed_effect.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let key = aos_sandbox_protocol::domain_ledger::operation::effect_key(
            self.publication_operation_v1(), 0,
        );
        let effect = controller.get(crate::RecordNamespace::Effect, &key)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if effect != original {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let records = self.contract.records;
        for kind in [ProvisioningResourceRowKindV1::Parent,
            ProvisioningResourceRowKindV1::Assignment, ProvisioningResourceRowKindV1::Reservation] {
            let key = records.key_v1(kind);
            let row = records.encode_v1(kind);
            if controller.get(crate::RecordNamespace::DesiredState, &key) != Some(row.as_slice()) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        Ok(CompletedPublicationChildDataV1 { effect, records,
            _action: self, _receiving: receiving, _root: root, _controller: controller })
    }
}
