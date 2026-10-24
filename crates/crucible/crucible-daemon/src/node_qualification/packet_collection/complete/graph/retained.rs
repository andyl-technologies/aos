//! Observes original graph-policy owners, not borrowed source or Host backings.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;

impl InstalledPacketCompleteGraphPolicy {
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_retained_origin_data(
        &self,
    ) -> Result<(), QualificationError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn charge_retained_storage(
        &self,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        self.roster.charge_retained_storage(counter)?;
        counter.charge(&self.world)?;
        counter.charge(&self.requirements)?;
        counter.charge(&self.content)?;
        counter.charge(&self.schemas)?;
        counter.charge(&self.proof)?;
        counter.charge(&self.interpretation)?;
        counter.charge(&self.connections)?;
        counter.charge(&self.closures)?;
        counter.charge(&self.measurements)?;
        for files in &self.files {
            if counter.rc(files)? {
                files.charge_retained_storage(counter)?;
            }
        }
        // Native/source Rc and genuine Host2 allocations are separate Core and
        // source rows. Pointer aliases never become another typed clone here.
        Ok(())
    }
}
