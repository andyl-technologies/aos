//! Preserves local Root Use admission, preparation, append and send frontiers.
//!
//! Prospective Controller receiving remains unsigned DATA. Its original upper
//! Source error is retained before the canonical native refusal marker; neither
//! that proposal nor a copied successful result supplies the local Root Stage.

use aos_sandbox_policy::storage_create_use_data::StorageCreateUseSecurityShapeDataV1;
use aos_sandbox_policy::storage_session_geometry_data::StorageSessionGeometryRefusalV1;

use super::{Action, Error, First, RootOwnedInitialCurrentAttemptV1, Stage};
use crate::normal_root::ProductionNormalRootStartupV1;

impl RootOwnedInitialCurrentAttemptV1<'_, '_, '_> {
    pub(super) fn receive_use_authorized_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        private: StorageCreateUseSecurityShapeDataV1,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::UseAuthorizedFixed, 67)?;
        // Old arm refusal returns before entering the body/post scope.
        self.drive_v1(startup, Stage::UseAuthorizedAppend, 68)?;
        let body = self.receive_use_authorized_body_v1(startup, private);
        self.latch_native_v1();
        for slot in [69, 70] {
            if matches!(self.actions[slot], Some(Err(_))) {
                self.first.get_or_insert(First::Action(slot));
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_initial_use_authorized_append_posts_once_v1();
        }
        self.latch_native_v1();
        body?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .frame_initial_use_authorized_once_v1()
            .map_err(Action::UseAuthorized);
        self.record_v1(74, returned)?;
        self.drive_v1(startup, Stage::UseAuthorizedSend, 75)?;
        // The native send owns its unconditional post/readback/end/live tail.
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .send_initial_use_authorized_once_v1()
            .map_err(Action::UseAuthorized);
        self.record_v1(76, returned)?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_use_authorized_complete_v1()
            .map_err(Action::UseAuthorized);
        self.record_v1(77, returned)
    }

    fn receive_use_authorized_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        private: StorageCreateUseSecurityShapeDataV1,
    ) -> Result<(), Error> {
        let native = self.native.as_mut().ok_or(Error::Original)?;
        let mut prepared = match native.borrow_initial_use_authorized_once_v1() {
            Ok(prepared) => prepared,
            Err(error) => {
                self.actions[69] = Some(Err(Action::UseAuthorized(error)));
                return Err(Error::Open);
            }
        };
        self.actions[69] = Some(Ok(()));
        let inputs = match prepared.prospective_inputs_v1() {
            Ok(inputs) => inputs,
            Err(error) => {
                if prepared.failure_v1().is_some() {
                    self.first.get_or_insert(First::Native);
                }
                self.actions[70] = Some(Err(Action::UseAuthorized(error)));
                return Err(Error::Open);
            }
        };
        self.use_proposal = Some(super::use_prospective_geometry::receiving_demand_v1(
            inputs, private,
        ));
        let receiving = match &self.use_proposal {
            Some(Ok(receiving)) => Ok(*receiving),
            Some(Err(_)) => {
                self.first.get_or_insert(First::UseProposal);
                Err(StorageSessionGeometryRefusalV1)
            }
            None => return Err(Error::Original),
        };
        self.actions[70] = Some(Ok(()));
        let returned = prepared
            .prepare_proposal_once_v1(receiving)
            .map_err(Action::UseAuthorized);
        if prepared.failure_v1().is_some() {
            self.first.get_or_insert(First::Native);
        }
        self.actions[71] = Some(returned);
        let succeeded = matches!(self.actions[71], Some(Ok(())));
        drop(prepared);
        if !succeeded {
            self.first.get_or_insert(First::Action(71));
            return Err(Error::Open);
        }
        self.drive_v1(startup, Stage::UseAuthorizedCrossing, 72)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .append_initial_use_authorized_once_v1()
            .map_err(Action::UseAuthorized);
        self.record_v1(73, returned)
    }
}
