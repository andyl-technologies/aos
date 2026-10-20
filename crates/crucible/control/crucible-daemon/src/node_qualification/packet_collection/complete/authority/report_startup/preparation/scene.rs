//! Lends actual fixed preparation slots to the trusted complete-scene driver.
//!
//! Mutable SDK continuation retains the original preparation, response, Hello
//! and registry slots. Whole owning rechecks use only immutable loans after
//! dispatch; no public controller or detached preparation can be extracted.

use super::*;

impl PreparationOwners {
    /// Lends the known owner paired with the same retained operational handle.
    ///
    /// # Errors
    /// Refuses an invalid peer, unfinished reservation or missing original owner.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_known_supervisor_data(
        &self,
        selected: usize,
    ) -> Result<&OriginalRetainedSupervisor, RuntimeError> {
        let peer = self
            .peers
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !self.attempted || peer.operational.is_none() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        peer.supervisor
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Lends the same registered literal Hello output slot.
    ///
    /// # Errors
    /// Refuses an invalid peer or absent original registered slot.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_hello_slot_data(
        &self,
        selected: usize,
    ) -> Result<
        &Rc<RefCell<Option<crucible_node_transport::client::OriginalHelloJournal>>>,
        RuntimeError,
    > {
        self.peers
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .hello_slot
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    /// Authenticates the actual retained preparation against the closed Core scope.
    ///
    /// # Errors
    /// Refuses an invalid peer, absent preparation or another preparation allocation.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn authenticate_original_initial_preparation_data(
        &self,
        selected: usize,
        scope: &crucible_engine::node_admission::OriginalHostInitialLifecycleScope<'_>,
    ) -> Result<(), RuntimeError> {
        let preparation = self
            .peers
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .preparation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !scope.is_original_preparation(preparation) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl PacketCompleteReportStartupHolder {
    /// Moves the already owned query IDs into their original fixed preparation slots.
    ///
    /// # Errors
    /// Refuses foreign, busy, late or incomplete originals before moving any ID.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn stage_original_scene_query_ids_data(
        &self,
        incoming: &mut [Option<Id>; 3],
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        let mut owners = self
            .preparations
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if owners.attempted
            || incoming.iter().any(Option::is_none)
            || owners.peers.iter().any(|peer| peer.planned_id.is_some())
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        for (peer, id) in owners.peers.iter_mut().zip(incoming) {
            peer.planned_id = id.take();
        }
        Ok(())
    }

    /// Consumes the admitted initial lifecycle into the same original peer slots.
    ///
    /// # Errors
    /// Refuses busy or occupied output slots and any closed Source continuation failure.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn continue_original_scene_peer_data(
        &self,
        selected: usize,
        window: &mut crucible_engine::node_admission::CompleteOriginalHostInitialLifecycleWindow,
        sdk: &mut crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk,
        guard: &mut Option<crucible_engine::node_adapters::cnp::CnpSemanticLaunchGuard>,
        role: &mut Option<crucible_engine::node_adapters::cnp::InstalledCnpConformanceRole>,
        admit_id: &Id,
    ) -> Result<(), RuntimeError> {
        let mut owners = self
            .preparations
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let peer = owners
            .peers
            .get_mut(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if peer.preparation.is_some() || peer.admit_response.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        window.prepare_original_initial_lifecycle_into(
            sdk,
            &self.authority.original_launches[selected],
            guard,
            role,
            peer.supervisor
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            admit_id,
            peer.hello_slot
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &mut peer.preparation,
            &mut peer.admit_response,
            &mut peer.registry,
        )
    }
}

impl PacketCompleteReportStartupHolder {
    /// Connects the same opaque SDK using its actual known supervisor pair.
    ///
    /// # Errors
    /// Refuses busy or missing originals and any Source-authenticated Hello failure.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn connect_original_scene_sdk_data(
        &self,
        selected: usize,
        window: &mut crucible_engine::node_admission::CompleteOriginalHostInitialLifecycleWindow,
        sdk: &mut crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk,
        guard: &crucible_engine::node_adapters::cnp::CnpSemanticLaunchGuard,
        stream: &mut Option<std::os::unix::net::UnixStream>,
    ) -> Result<(), RuntimeError> {
        let owners = self
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let peer = owners
            .peers
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        window.connect_original_host_sdk_into(
            sdk,
            guard,
            stream,
            peer.operational
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            peer.supervisor
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )
    }
}

impl PacketCompleteReportStartupHolder {
    /// Requeries the actual Prepared target after all mutable output loans end.
    ///
    /// # Errors
    /// Refuses busy, missing or changed originals or a complete conjunction exceeding policy.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn recheck_original_scene_peer_data(
        &self,
        selected: usize,
        window: &crucible_engine::node_admission::CompleteOriginalHostInitialLifecycleWindow,
        sdks: [&crucible_engine::node_adapters::cnp::PacketCompleteOriginalHostSdk; 3],
        socket: &std::path::Path,
    ) -> Result<usize, RuntimeError> {
        let owners = self
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let peer = owners
            .peers
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        window.recheck_original_inputs_data(
            &self.authority.roster.sources,
            &self.authority.original_launches,
            sdks,
            peer.preparation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            socket,
            peer.supervisor
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            peer.hello_slot
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )
    }

    /// Retires every actual retained preparation without extracting its custody.
    ///
    /// # Errors
    /// Refuses a conflicting preparation bank loan; surviving owners remain retained.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn retire_original_scene_preparations(
        &self,
    ) -> Result<(), RuntimeError> {
        let mut owners = self
            .preparations
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for peer in &mut owners.peers {
            if let Some(preparation) = &mut peer.preparation {
                preparation.retire_original();
            }
        }
        Ok(())
    }
}

impl PreparationOwners {
    /// Counts actual preparation descriptor views without kernel or protocol effects.
    ///
    /// # Errors
    /// Refuses an unsupported ordinary constructor, unknown custody or arithmetic overflow.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn retained_descriptor_views_precredit_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let mut total = 0usize;
        for peer in &self.peers {
            if peer.connection.is_some() {
                // The ordinary constructor is a different opaque owner family.
                return Err(RuntimeError::UnsupportedFacet);
            }
            if let Some(preparation) = &peer.preparation {
                total = total
                    .checked_add(preparation.retained_descriptor_views_precredit_data()?)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        // Hello journals are frame/body owners; their live transport remains in
        // the actual SDK or preparation row. Known retained supervisors own no
        // descriptor. Neither a ResponseBody nor an Id acquires a descriptor.
        Ok(total)
    }
}

impl PacketCompleteReportStartupHolder {
    // Fresh installation already reserves the known supervisors. It may stage
    // IDs only while those exact peer slots are empty and no HOST attempt began.
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn stage_original_fresh_query_ids_data(
        &self,
        incoming: &mut [Option<Id>; 3],
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        if !matches!(&self.purpose, StartupHolderPurpose::FreshRestoration(_)) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut owners = self
            .preparations
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.attempted
            || incoming.iter().any(Option::is_none)
            || owners.peers.iter().any(|peer| {
                peer.planned_id.is_some()
                    || peer.host_attempted
                    || peer.preparation.is_some()
                    || peer.ticket.get().is_some()
                    || peer.operational.is_none()
                    || peer.supervisor.is_none()
            })
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        for (peer, id) in owners.peers.iter_mut().zip(incoming) {
            peer.planned_id = id.take();
        }
        Ok(())
    }
}
