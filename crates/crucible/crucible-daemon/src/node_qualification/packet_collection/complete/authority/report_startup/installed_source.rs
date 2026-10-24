//! Retains the installed Host source revision inside the counted startup holder.

use super::*;
use crucible_engine::node_contract::HostSchedulingOwner;

impl PacketCompleteReportStartupHolder {
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_installed_scene_creator_data(
        &self,
    ) -> Result<(), QualificationError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(super::super::super::refused());
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retain_installed_host_owner(
        &self,
        owner: HostSchedulingOwner,
    ) -> Result<(), QualificationError> {
        self.authenticate_installed_scene_creator_data()?;
        let source = owner.source();
        if !Rc::ptr_eq(&source, self.authority.host_source()) {
            return Err(super::super::super::refused());
        }
        self.installed_host_owner
            .set(owner)
            .map_err(|_| super::super::super::refused())
    }
}
