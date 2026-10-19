//! Calls Core's installed action before each original inactive constructor step.

use super::*;

impl PacketCompleteReportStartupHolder {
    fn authenticate_runtime_member_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        scope: &OriginalRuntimeConstructionScope<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        let phase = scope.phase();
        let selected = index(phase);
        if !std::ptr::eq(self.authority.as_ref(), authority)
            || !scope.is_original_authority(authority)
            || !scope.is_original_plan(&self.plan)
            || !std::ptr::eq(scope.sources(), &authority.roster.sources)
            || !std::ptr::eq(scope.launches(), &authority.original_launches)
            || !self.runtime_attempted[selected].get()
            || self.original_scene_retired.get()
            || (scope.is_post_construction() && self.runtime_members[selected].get().is_none())
            || (!scope.is_post_construction() && self.runtime_issuing.get() != Some(phase))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.graph_owner
            .authenticate_original_report_policy_data(&authority.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok(())
    }

    fn authenticate_runtime_scope_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        scope: &OriginalRuntimeConstructionScope<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_runtime_member_data(authority, scope)?;
        let scene = self.runtime_construction_owner_data()?;
        scene.authenticate_completed_lifecycle()?;
        if !std::ptr::eq(scope.activation(), scene.activation()?)
            || scope.limits() != scene.limits()?
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Existing scene and graph constructors use producer/relay/sink/Host
        // order. Reject another order rather than silently reorder identities.
        let selections = authority
            .roster
            .sources
            .each_ref()
            .map(|s| s.installation());
        let host = authority.host_source().selection();
        for pair in [
            &selections[0].descriptor.id,
            &selections[1].descriptor.id,
            &selections[2].descriptor.id,
            &host.descriptor.id,
        ]
        .windows(2)
        {
            if pair[0] >= pair[1] {
                return Err(RuntimeError::UnsupportedFacet);
            }
        }
        let outputs = self
            .host_sdk_outputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let sdks = scope.sdks();
        for i in 0..3 {
            if !std::ptr::eq(
                sdks[i],
                outputs[i].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            ) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Ok(())
    }

    fn runtime_policy_data(
        &self,
        phase: OriginalRuntimeConstructionPhase,
    ) -> Result<OriginalRuntimeConstructionPolicy, RuntimeError> {
        let base = self
            .policy_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let observation_scratch = if phase == OriginalRuntimeConstructionPhase::InactiveRuntime
            && matches!(&self.purpose, StartupHolderPurpose::OriginalScene)
        {
            observation_growth::counter_scratch_data()?
        } else {
            0
        };
        Ok(OriginalRuntimeConstructionPolicy {
            maximum_requested_bytes: base.maximum_requested_bytes,
            maximum_owned_descriptors: usize::try_from(self.resources.descriptors.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
            declared_observer_scratch_bytes: add(
                base.declared_observer_scratch_bytes,
                add(
                    storage::counter_scratch_data()?,
                    observation_scratch,
                    usize::MAX,
                )?,
                usize::MAX,
            )?,
        })
    }

    /// Selects the closed original bootstrap that stops after private mutation.
    ///
    /// The three real initial grants park at time five, before the public
    /// event's evaluation. Selection precedes every runtime construction member
    /// and never creates a grant, native result or publication acknowledgement.
    /// The default installer path keeps its existing time-one schedule.
    ///
    /// # Errors
    /// Refuses a foreign/fresh owner, repeated or late selection, retirement,
    /// already staged runtime owners, or a busy actual holder.
    pub fn select_original_private_mutation_capture_schedule(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if !matches!(&held.purpose, StartupHolderPurpose::OriginalScene)
            || held.original_scene_retired.get()
            || held.runtime_attempted.iter().any(Cell::get)
            || held.runtime_issuing.get().is_some()
            || held.runtime_in_flight.get().is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        let mut owners = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if owners.capture_bootstrap.is_some()
            || owners.schedule.is_some()
            || owners.oracle.is_some()
            || owners.actor.is_some()
            || owners.complete
        {
            return Err(RuntimeError::DuplicateOperation);
        }

        owners.capture_bootstrap =
            Some(super::super::super::super::execution::schedule::Bootstrap::PrivateMutation);
        Ok(())
    }

    /// Constructs the same original four-node runtime and attaches it inactive.
    ///
    /// Each installed Core member is spent and retained before its corresponding
    /// constructor. The sole reader, supervisor, node preparations and reserved
    /// slot move through fixed banks. No readiness, operation or publication is
    /// performed, and a refused phase cannot be retried or mint another member.
    ///
    /// # Errors
    /// Retains partial originals on foreign, repeated, busy, unsupported or
    /// excessive resource phases, callback refusal and failed post-growth fit.
    pub fn prepare_original_scene_runtime(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            if !matches!(&held.purpose, StartupHolderPurpose::OriginalScene) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Self::prepare_runtime_construction_data(original)
    }

    pub(super) fn prepare_runtime_construction_data(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        for phase in [
            OriginalRuntimeConstructionPhase::InputOwners,
            OriginalRuntimeConstructionPhase::CollectingGraph,
            OriginalRuntimeConstructionPhase::InactiveRuntime,
        ] {
            let i = index(phase);
            if held.runtime_attempted[i].replace(true)
                || held.runtime_issuing.get().is_some()
                || held.runtime_in_flight.get().is_some()
            {
                return Err(RuntimeError::DuplicateOperation);
            }
            held.runtime_issuing.set(Some(phase));
            let issuing = PhaseLoan {
                phase: &held.runtime_issuing,
                previous: None,
            };
            {
                let scene = held.runtime_construction_owner_data()?;
                let outputs = held
                    .host_sdk_outputs
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let [a, b, c] = outputs
                    .each_ref()
                    .map(|n| n.as_ref().ok_or(RuntimeError::OwnerUnavailable));
                #[cfg(test)]
                eprintln!("native control: runtime {phase:?} reserve begin");
                let member = held.plan.reserve_original_runtime_construction(
                    phase,
                    &held.authority.roster.sources,
                    &held.authority.original_launches,
                    [a?, b?, c?],
                    scene.activation()?,
                    scene.limits()?,
                )?;
                held.runtime_members[i]
                    .set(member)
                    .map_err(|_| RuntimeError::DuplicateOperation)?;
                #[cfg(test)]
                eprintln!("native control: runtime {phase:?} reserve end");
            }
            drop(issuing);
            let member = held.runtime_members[i]
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let _phase = PhaseLoan {
                phase: &held.runtime_in_flight,
                previous: held.runtime_in_flight.replace(Some(phase)),
            };
            let _callbacks = CallbackLoan {
                authority: &held.authority,
                initial: held
                    .authority
                    .original_initial_callback_active
                    .replace(true),
                runtime: held
                    .authority
                    .original_runtime_callback_active
                    .replace(true),
            };
            let _diagnostics = {
                let scene = held.runtime_construction_owner_data()?;
                let outputs = held
                    .host_sdk_outputs
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let [a, b, c] = outputs
                    .each_ref()
                    .map(|n| n.as_ref().ok_or(RuntimeError::OwnerUnavailable));
                member.begin_original_constructor_diagnostics(
                    &held.plan,
                    phase,
                    &held.authority.roster.sources,
                    &held.authority.original_launches,
                    [a?, b?, c?],
                    scene.activation()?,
                    scene.limits()?,
                )?
            };
            let _daemon_diagnostics =
                super::super::super::super::construction_diagnostics::Scope::enter();
            #[cfg(test)]
            eprintln!("native control: runtime {phase:?} construct begin");
            match phase {
                OriginalRuntimeConstructionPhase::InputOwners => inputs::construct(&held, member)?,
                OriginalRuntimeConstructionPhase::CollectingGraph => graph::construct(&held)?,
                OriginalRuntimeConstructionPhase::InactiveRuntime => match &held.purpose {
                    StartupHolderPurpose::OriginalScene => inactive::construct(&held)?,
                    StartupHolderPurpose::FreshRestoration(_) => {
                        held.construct_fresh_inactive_data()?
                    }
                },
            }
            #[cfg(test)]
            eprintln!("native control: runtime {phase:?} construct end");
            let scene = held.runtime_construction_owner_data()?;
            let outputs = held
                .host_sdk_outputs
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let [a, b, c] = outputs
                .each_ref()
                .map(|n| n.as_ref().ok_or(RuntimeError::OwnerUnavailable));
            #[cfg(test)]
            eprintln!("native control: runtime {phase:?} recheck begin");
            member.recheck_original_data(
                &held.plan,
                &held.authority.roster.sources,
                &held.authority.original_launches,
                [a?, b?, c?],
                scene.activation()?,
                scene.limits()?,
            )?;
            #[cfg(test)]
            eprintln!("native control: runtime {phase:?} recheck end");
        }
        held.runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .complete = true;
        Ok(())
    }
}

struct PhaseLoan<'a> {
    phase: &'a Cell<Option<OriginalRuntimeConstructionPhase>>,
    previous: Option<OriginalRuntimeConstructionPhase>,
}

impl Drop for PhaseLoan<'_> {
    fn drop(&mut self) {
        self.phase.set(self.previous);
    }
}

struct CallbackLoan<'a> {
    authority: &'a InstalledPacketCompleteCollectionAuthority,
    initial: bool,
    runtime: bool,
}

impl Drop for CallbackLoan<'_> {
    fn drop(&mut self) {
        self.authority
            .original_runtime_callback_active
            .set(self.runtime);
        self.authority
            .original_initial_callback_active
            .set(self.initial);
    }
}

impl InstalledPacketCompleteCollectionAuthority {
    fn runtime_holder_data(
        &self,
    ) -> Result<Rc<RefCell<PacketCompleteReportStartupHolder>>, RuntimeError> {
        self.graph_policy
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.report_startup_holder
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn original_runtime_construction_policy_data(
        &self,
        scope: &OriginalRuntimeConstructionScope<'_>,
    ) -> Result<OriginalRuntimeConstructionPolicy, RuntimeError> {
        let original = self.runtime_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_runtime_scope_data(self, scope)?;
        held.runtime_policy_data(scope.phase())
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_runtime_construction_data(
        &self,
        scope: &OriginalRuntimeConstructionScope<'_>,
        policy: &OriginalRuntimeConstructionPolicy,
    ) -> Result<OriginalRuntimeConstructionStorage, RuntimeError> {
        let original = self.runtime_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_runtime_scope_data(self, scope)?;
        if held.runtime_policy_data(scope.phase())? != *policy {
            return Err(RuntimeError::ForeignAuthority);
        }
        let maximum = policy
            .maximum_requested_bytes
            .checked_sub(policy.declared_observer_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        let retained_holder_bytes =
            PacketCompleteReportStartupHolder::runtime_construction_holder_storage_data(
                &original, &held, scope, maximum,
            )?;
        let mut construction_retained_observation_growth_bytes = 0;
        let construction = if scope.is_post_construction() {
            (0, 0, 0)
        } else {
            match scope.phase() {
                OriginalRuntimeConstructionPhase::InputOwners => {
                    (inputs::quote(&held, maximum)?, 0, 0)
                }
                OriginalRuntimeConstructionPhase::CollectingGraph => graph::quote(&held, maximum)?,
                OriginalRuntimeConstructionPhase::InactiveRuntime => match &held.purpose {
                    StartupHolderPurpose::OriginalScene => {
                        let quoted = inactive::quote(&held, maximum)?;
                        construction_retained_observation_growth_bytes =
                            quoted.retained_observation_growth_bytes;
                        (
                            quoted.retained_requested_bytes,
                            quoted.maximum_simultaneous_transient_bytes,
                            quoted.declared_counter_scratch_bytes,
                        )
                    }
                    StartupHolderPurpose::FreshRestoration(_) => {
                        held.quote_fresh_inactive_data(maximum)?
                    }
                },
            }
        };
        let mut transient = self.original_initial_callback_transient_data()?;
        if let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose {
            transient = add(
                transient,
                capsule
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .original_fresh_construction_callback_transient_data(maximum)?,
                maximum,
            )?;
        }
        transient = add(
            transient,
            InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                self.world(),
                maximum,
            )?,
            maximum,
        )?;
        for source in &self.roster.sources {
            let selected = source.installation();
            for bytes in [
                InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                    &selected.descriptor,
                    maximum,
                )?,
                InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                    &selected.binding,
                    maximum,
                )?,
                InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                    &selected.owner,
                    maximum,
                )?,
            ] {
                transient = add(transient, bytes, maximum)?;
            }
        }

        // Every real graph-currentness callback validates the same complete
        // three-Source coordinator. Count those exact producer rows explicitly.
        for source in &self.roster.sources {
            transient = add(
                transient,
                source.original_collecting_validation_storage_data(maximum)?,
                maximum,
            )?;
        }
        Ok(OriginalRuntimeConstructionStorage {
            retained_holder_bytes,
            maximum_simultaneous_transient_bytes: transient,
            construction_retained_requested_bytes: construction.0,
            construction_retained_observation_growth_bytes,
            construction_transient_requested_bytes: construction.1,
            construction_counter_scratch_bytes: construction.2,
            retained_descriptors: held.original_initial_retained_descriptors_data()?,
            maximum_simultaneous_transient_descriptors: 1,
        })
    }

    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_runtime_construction_member_data(
        &self,
        scope: &OriginalRuntimeConstructionScope<'_>,
    ) -> Result<(), RuntimeError> {
        let original = self.runtime_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_runtime_member_data(self, scope)
    }
}

impl PacketCompleteReportStartupHolder {
    pub(in crate::node_qualification::packet_collection::complete) fn has_original_runtime_mechanism_data(
        original: &Rc<RefCell<Self>>,
    ) -> Result<bool, RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        Ok(held.authority.original_launches.iter().all(|launch|launch.complete_restore_selection==Some(
            crucible_node_provider::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)))
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn retire_original_runtime_owners(
        &self,
    ) -> Result<(), RuntimeError> {
        let mut owners = self
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let limits = match &self.purpose {
            StartupHolderPurpose::OriginalScene => {
                self.original_scene
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .inputs
                    .runtime_limits
            }
            StartupHolderPurpose::FreshRestoration(_) => {
                self.fresh_lifecycle
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .inputs
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .runtime_limits
            }
        };
        if let Some(actor) = &mut owners.actor {
            actor.retire_original_inactive_construction()?;
        }
        if let Some(failure) = &mut owners.attachment_failure {
            if let Some(runtime) = &mut failure.incoming {
                runtime.retire_original()?;
            }
        }
        if let Some(runtime) = &mut owners.runtime {
            runtime.retire_original()?;
        }
        if let Some(provider) = &mut owners.provider {
            provider.retire_original(limits)?;
        }
        if let Some(failure) = &mut owners.provider_failure {
            failure.original.retire_original(limits)?;
        }
        if let Some(crucible::node_adapters::cnp::CnpSemanticWorldPreparationFailure::Runtime(
            failure,
        )) = &mut owners.preparation_failure
        {
            failure.retire_original()?;
        }
        for node in owners.nodes.iter_mut().flatten() {
            node.retire_original();
        }
        for node in &mut owners.node_vector {
            node.retire_original();
        }
        Ok(())
    }
}

impl InstalledPacketCompleteCollectionAuthority {
    /// Selects the actual original inactive constructor without issuing authority.
    ///
    /// # Errors
    /// Refuses a busy, unavailable or foreign registered construction holder.
    pub(in crate::node_qualification::packet_collection::complete) fn original_inactive_oracle_callback_data(
        &self,
    ) -> Result<bool, RuntimeError> {
        if !self.original_runtime_callback_active.get() {
            return Ok(false);
        }
        let original = self.runtime_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        Ok(matches!(&held.purpose, StartupHolderPurpose::OriginalScene)
            && matches!(
                held.runtime_in_flight.get(),
                Some(
                    OriginalRuntimeConstructionPhase::CollectingGraph
                        | OriginalRuntimeConstructionPhase::InactiveRuntime
                )
            ))
    }
}
