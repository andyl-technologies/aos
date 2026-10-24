//! Counts independent scene/oracle allocations without following Core authorities.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;

impl PacketCompleteExecutionScene {
    pub(in crate::node_qualification::packet_collection::complete) fn charge_retained_storage(
        &self,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        if counter.rc(&self.authority)? {
            self.authority.charge_retained_storage(counter)?;
        }
        if counter.rc(&self.plan)? {
            counter.add(
                self.plan
                    .retained_allocation_bytes_excluding_authority()
                    .map_err(|_| refused())?,
            )?;
        }
        if counter.rc(&self.oracle)? {
            self.oracle.charge_retained_storage(counter)?;
        }
        Ok(())
    }
}
