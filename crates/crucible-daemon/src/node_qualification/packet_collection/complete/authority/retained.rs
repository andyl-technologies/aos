//! Observes the original authority's independent graph, plan and audit owners.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;

impl InstalledPacketCompleteCollectionAuthority {
    pub(in crate::node_qualification::packet_collection::complete) fn charge_retained_storage(
        &self,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        self.roster.charge_retained_storage(counter)?;
        if counter.rc(&self.host)? {
            let host = self
                .host
                .retained_original_metadata_bytes_excluding_runtime(counter.remaining())
                .map_err(|_| refused())?;
            counter.add(host)?;
        }
        if counter.rc(&self.graph_policy)? {
            self.graph_policy.charge_retained_storage(counter)?;
        }
        counter.charge(&self.world)?;
        counter.charge(&self.requirements)?;
        counter.charge(&self.kernel)?;
        counter.charge(&self.population.plan)?;
        counter.charge(&self.population.reference)?;
        counter.charge(&self.population.bytes)?;
        counter.charge(&self.population.bodies)?;
        counter.charge(self.audit.record())?;
        let issued = self
            .audit
            .issued_retained_requested_storage_data(counter.remaining())?;
        counter.add(issued)?;
        counter.charge(&self.refused_reference)?;
        counter.charge(&self.refused_bytes)?;
        counter.charge(&self.roots)?;
        counter.charge(&self.private_launches)?;
        counter.charge(&self.directories)?;
        let slots = self
            .original_ack_hello
            .try_borrow()
            .map_err(|_| refused())?;
        for slot in slots.iter().flatten() {
            if counter.rc(slot)? {
                let held = slot.try_borrow().map_err(|_| refused())?;
                if let Some(journal) = held.as_ref() {
                    let facts = journal
                        .original_retained_metadata_facts()
                        .map_err(|_| refused())?;
                    counter.metadata(&facts)?;
                }
            }
        }
        Ok(())
    }
}
