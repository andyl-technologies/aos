//! Observes the original authority's independent graph, plan and audit owners.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;

impl InstalledPacketCompleteCollectionAuthority {
    pub(super) fn original_retained_authority_backing(
        &self,
        maximum: usize,
    ) -> Result<usize, QualificationError> {
        // Raw source creator checks precede inherited RefCell/SDK observation.
        // This is a data loan; no native-currentness or graph qualifier runs.
        let mut sources = [0usize; 3];
        for (slot, source) in sources.iter_mut().zip(&self.roster.sources) {
            *slot = source
                .original_complete_retained_storage_data(maximum)
                .and_then(|report| report.complete_requested_bytes())
                .map_err(|_| refused())?;
        }
        let mut counter = Counter::new(maximum);
        self.charge_retained_storage(&mut counter)?;
        for source in sources {
            // Each report includes its actual source Rc root and underlying
            // source Box. The fixed roster was authenticated as three distinct
            // allocations; equal source labels do not provide any refund.
            counter.add(source)?;
        }
        // These private Weak links were issued only from the original installed
        // factory/scene. A live upgrade retains their concrete root while the
        // compiled inline/header is observed; child heaps belong to the actor's
        // separate factory/scene row and are not followed recursively here.
        if let Some(factory) = self.capture_factory.get() {
            let factory = factory.upgrade().ok_or_else(refused)?;
            counter.rc(&factory)?;
        }
        if let Some(scene) = self.execution_scene.get() {
            let scene = scene.upgrade().ok_or_else(refused)?;
            counter.rc(&scene)?;
        }
        Ok(counter.bytes())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn original_execution_scene_storage_data(
        &self,
    ) -> Result<Option<Rc<super::super::execution::PacketCompleteExecutionScene>>, QualificationError>
    {
        self.graph_policy.authenticate_retained_origin_data()?;
        let scene = self.execution_scene.get().and_then(std::rc::Weak::upgrade);
        self.graph_policy.authenticate_retained_origin_data()?;
        Ok(scene)
    }

    /// Counts nested owners of the actual erased registration/conformance issuer.
    ///
    /// The process observer separately charges this authority's enclosing Rc and
    /// inline payload. This loan follows actual backing identities only, avoids
    /// current/kernel callbacks, and remains data after collection revocation.
    pub(in crate::node_qualification::packet_collection::complete) fn original_retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        self.graph_policy
            .authenticate_retained_origin_data()
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
        let mut counter = Counter::new(maximum);
        // Source3 is walked by the actual preparation/holder rows. The Host is
        // either an original source or this exact fresh capsule's archive tuple.
        self.charge_report_startup_retained_storage(&mut counter)
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ResourceLimit)?;
        match self
            .host
            .retained_original_metadata_bytes_excluding_runtime_precredit_data(counter.remaining())
        {
            Ok(bytes) => {
                counter
                    .rc(&self.host)
                    .map_err(|_| crucible_engine::node_contract::RuntimeError::ResourceLimit)?;
                counter
                    .add(bytes)
                    .map_err(|_| crucible_engine::node_contract::RuntimeError::ResourceLimit)?;
            }
            Err(crucible_engine::node_contract::RuntimeError::UnsupportedFacet) => {
                let holder = self
                    .report_startup_holder
                    .get()
                    .and_then(std::rc::Weak::upgrade)
                    .ok_or(crucible_engine::node_contract::RuntimeError::OwnerUnavailable)?;
                let held = holder
                    .try_borrow()
                    .map_err(|_| crucible_engine::node_contract::RuntimeError::OwnerBusy)?;
                held.charge_fresh_host_archive_precredit_data(self, &mut counter)?;
            }
            Err(error) => return Err(error),
        }
        self.graph_policy
            .authenticate_retained_origin_data()
            .map_err(|_| crucible_engine::node_contract::RuntimeError::ForeignAuthority)?;
        Ok(counter.bytes())
    }

    pub(super) fn original_retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, QualificationError> {
        self.graph_policy.authenticate_retained_origin_data()?;
        let mut counter = Counter::new(maximum);
        self.charge_retained_storage(&mut counter)?;
        self.graph_policy.authenticate_retained_origin_data()?;
        Ok(counter.bytes())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn charge_retained_storage(
        &self,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        self.charge_retained_storage_for_startup(counter, false)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn charge_report_startup_retained_storage(
        &self,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        // The concrete registered capsule counts its exact restored Host and
        // verified archive together. Source3 is separately observed by Core.
        self.charge_retained_storage_for_startup(counter, true)
    }

    fn charge_retained_storage_for_startup(
        &self,
        counter: &mut Counter,
        restored_host_counted_by_capsule: bool,
    ) -> Result<(), QualificationError> {
        self.roster.charge_retained_storage(counter)?;
        if !restored_host_counted_by_capsule && counter.rc(&self.host)? {
            let host = self
                .host
                .retained_original_metadata_bytes_excluding_runtime_precredit_data(
                    counter.remaining(),
                )
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
        for launch in &self.original_launches {
            let facts =
                crucible_node_transport::retained_metadata::observe_retained_native_launch(launch)
                    .map_err(|_| refused())?;
            counter.metadata(&facts)?;
        }
        if let Some(holder) = self.report_startup_holder.get() {
            counter.weak(holder)?;
        }
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
        // Weak links retain their allocation even after the payload is dropped.
        // Charge their requested layout conservatively without marking a strong
        // owner's nested fields as visited: a later strong walk must still run.
        if let Some(factory) = self.capture_factory.get() {
            counter.weak(factory)?;
        }
        if let Some(scene) = self.execution_scene.get() {
            counter.weak(scene)?;
        }
        Ok(())
    }
}
