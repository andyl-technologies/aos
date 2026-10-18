//! Authenticates the same installed scene for its initial host lifecycle window.
//!
//! Whole callbacks run under immutable loans only. The member callback checks
//! creator, registered holder, Source/plan and sticky phase without reborrowing
//! SDK, native, controller or preparation banks during their mutable dispatch.

use super::*;
use crucible::node_admission::{
    OriginalHostInitialLifecycleMemberScope, OriginalHostInitialLifecyclePolicy,
    OriginalHostInitialLifecycleScope, OriginalHostInitialLifecycleStorage,
};

impl PacketCompleteReportStartupHolder {
    fn authenticate_initial_scope_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        scope: &OriginalHostInitialLifecycleScope<'_>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        if !std::ptr::eq(self.authority.as_ref(), authority)
            || !scope.is_original_authority(authority)
            || !scope.is_original_plan(&self.plan)
            || !scope.is_original_sources(&authority.roster.sources)
            || !scope.is_original_launches(&authority.original_launches)
            || !self.host_sdk_completed.get()
            || self.host_sdk_in_flight.get()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.graph_owner
            .authenticate_original_report_policy_data(&authority.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scene = self.host_initial_lifecycle_owner_data()?;
        let selected = scope.selected();
        if selected >= 3
            || !scene.staged()
            || !scene.initial_attempted()[selected].get()
            || !scene.initial_in_flight()[selected].get()
            || scene.initial_completed()[selected].get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let launches = self
            .native_launches
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let socket = launches.original_socket_data(selected)?;
        let outputs = self
            .host_sdk_outputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for (index, output) in outputs.iter().enumerate() {
            if !scope.is_original_sdk(
                index,
                output.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            ) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        let preparations = self
            .preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !std::ptr::eq(scope.control_socket(), socket)
            || !scope.is_original_supervisor(preparations.original_known_supervisor_data(selected)?)
            || !scope.is_original_hello_slot(preparations.original_hello_slot_data(selected)?)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if scope.original_preparation().is_some() {
            preparations.authenticate_original_initial_preparation_data(selected, scope)?;
        } else {
            let roles = scene
                .roles()
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let role = roles[selected]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let (guard, _) = launches.original_guard_and_socket_data(selected)?;
            if !scope.is_original_guard(guard) || !scope.is_original_role(role) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Ok(())
    }

    fn initial_lifecycle_policy_data(
        &self,
    ) -> Result<OriginalHostInitialLifecyclePolicy, RuntimeError> {
        let base = self
            .policy_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let scratch = [
            base.declared_observer_scratch_bytes,
            InstalledConformancePlan::original_host_initial_lifecycle_counter_scratch_data()?,
            crucible::node_adapters::cnp::CnpSemanticLaunchGuard::original_initial_lifecycle_storage_counter_scratch_data(),
            std::mem::size_of::<std::cell::Ref<'_, native_startup::NativeLaunchOwners>>(),
            std::mem::size_of::<std::cell::Ref<'_, [Option<crucible::node_adapters::cnp::PacketCompleteOriginalHostSdk>; 3]>>(),
            std::mem::size_of::<std::cell::Ref<'_, super::super::preparation::PreparationOwners>>(),
            // The concrete callback quote itself examines these fixed reason
            // pointers and scalar phase totals before any dynamic owning walk.
            std::mem::size_of::<[&'static str; 7]>(),
            std::mem::size_of::<QualificationError>(),
            std::mem::size_of::<[usize; 8]>(),
        ].into_iter().try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })?;
        Ok(OriginalHostInitialLifecyclePolicy {
            maximum_requested_bytes: base.maximum_requested_bytes,
            maximum_owned_descriptors: usize::try_from(self.resources.descriptors.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
            declared_observer_scratch_bytes: scratch,
        })
    }
}

impl InstalledPacketCompleteCollectionAuthority {
    fn initial_scene_holder_data(
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

    /// Returns the installed resource limits under the same authenticated scene scope.
    ///
    /// # Errors
    /// Refuses foreign, busy or incomplete originals or invalid compiled scratch.
    pub(in crate::node_qualification::packet_collection::complete::authority) fn original_host_initial_lifecycle_policy_data(
        &self,
        scope: &OriginalHostInitialLifecycleScope<'_>,
    ) -> Result<OriginalHostInitialLifecyclePolicy, RuntimeError> {
        let original = self.initial_scene_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_initial_scope_data(self, scope)?;
        held.initial_lifecycle_policy_data()
    }

    /// Counts the same actual holder and concrete callback phase under installed policy.
    ///
    /// # Errors
    /// Refuses changed policy, unknown owners, busy loans or arithmetic and resource excess.
    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_host_initial_lifecycle_data(
        &self,
        scope: &OriginalHostInitialLifecycleScope<'_>,
        policy: &OriginalHostInitialLifecyclePolicy,
    ) -> Result<OriginalHostInitialLifecycleStorage, RuntimeError> {
        let original = self.initial_scene_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_initial_scope_data(self, scope)?;
        if held.initial_lifecycle_policy_data()? != *policy {
            return Err(RuntimeError::ForeignAuthority);
        }
        let maximum = policy
            .maximum_requested_bytes
            .checked_sub(policy.declared_observer_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
        let retained_holder_bytes =
            PacketCompleteReportStartupHolder::original_initial_holder_storage_data(
                &original, &held, maximum,
            )?;
        held.authenticate_initial_scope_data(self, scope)?;
        Ok(OriginalHostInitialLifecycleStorage {
            retained_holder_bytes,
            maximum_simultaneous_transient_bytes: self
                .original_initial_callback_transient_data()?,
            retained_descriptors: held.original_initial_retained_descriptors_data()?,
            // This concrete callback opens only its fixed kernel-release File.
            // CurrentFiles hashes retained FDs. Core separately includes the
            // Source's three nested validation opens and each pending SDK phase.
            maximum_simultaneous_transient_descriptors: 1,
        })
    }

    /// Authenticates private member currency without borrowing SDK or preparation banks.
    ///
    /// # Errors
    /// Refuses another creator, plan, source, graph revision or sticky lifecycle phase.
    pub(in crate::node_qualification::packet_collection::complete::authority) fn authenticate_original_host_initial_lifecycle_member_data(
        &self,
        scope: &OriginalHostInitialLifecycleMemberScope<'_>,
    ) -> Result<(), RuntimeError> {
        let original = self.initial_scene_holder_data()?;
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        let selected = scope.selected();
        if selected >= 3
            || !std::ptr::eq(held.authority.as_ref(), self)
            || !scope.is_original_authority(self)
            || !scope.is_original_plan(&held.plan)
            || !std::ptr::eq(scope.source(), self.roster.sources[selected].as_ref())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let scene = held.host_initial_lifecycle_owner_data()?;
        if !scene.staged()
            || !scene.initial_attempted()[selected].get()
            || (!scene.initial_in_flight()[selected].get()
                && !scene.initial_completed()[selected].get())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // The private member window was issued only after its actual written
        // launch and guard check. Its callback may already hold that launch
        // bank mutably while transferring the guard into preparation.
        held.graph_owner
            .authenticate_original_report_policy_data(&self.graph_policy)
            .map_err(|_| RuntimeError::ForeignAuthority)
    }
}

impl PacketCompleteReportStartupHolder {
    /// Runs the separately admitted original socket, Hello and initial protocol.
    ///
    /// Each private window enters its fixed scene slot before its first effect.
    /// Source owns the controller/handshake continuation; no raw controller can
    /// be extracted here. Its original preparation and Admit response occupy the
    /// same preparation bank before terminal checks. Refusal keeps all owners
    /// and the spent window, with no replacement stream or repeated method.
    ///
    /// # Errors
    /// Refuses an unfinished or repeated scene, changed originals or policy,
    /// incomplete owning observations, acquisition/Hello/codec/protocol failure
    /// or a terminal whole-holder/source bound that no longer fits.
    pub fn complete_original_scene_initial_lifecycle(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        {
            let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            if !matches!(&held.purpose, StartupHolderPurpose::OriginalScene) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Self::complete_retained_host_initial_lifecycle(original)
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn complete_retained_host_initial_lifecycle(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        let scene = held.host_initial_lifecycle_owner_data()?;
        if !scene.staged() || !scene.launched().get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        for selected in 0..3 {
            Self::complete_retained_host_initial_lifecycle_member(original, selected)?;
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn complete_retained_host_initial_lifecycle_member(
        original: &Rc<RefCell<Self>>,
        selected: usize,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        let scene = held.host_initial_lifecycle_owner_data()?;
        if selected >= 3 || !scene.staged() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        held.native_launches
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .original_guard_and_socket_data(selected)?;
        if scene.initial_attempted()[selected].replace(true)
            || scene.initial_completed()[selected].get()
            || scene.windows()[selected].get().is_some()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        scene.initial_in_flight()[selected].set(true);
        let _loan = StartupLoan(&scene.initial_in_flight()[selected]);
        {
            let outputs = held
                .host_sdk_outputs
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let sdks = [
                outputs[0].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                outputs[1].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                outputs[2].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            ];
            let launches = held
                .native_launches
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let (guard, socket) = launches.original_guard_and_socket_data(selected)?;
            let roles = scene
                .roles()
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let role = roles[selected]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let preparations = held
                .preparations
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let window = held.plan.reserve_original_host_initial_lifecycle(
                &held.authority.roster.sources,
                &held.authority.original_launches,
                sdks,
                selected,
                guard,
                role,
                socket,
                preparations.original_known_supervisor_data(selected)?,
                preparations.original_hello_slot_data(selected)?,
            )?;
            scene.windows()[selected]
                .set(RefCell::new(window))
                .map_err(|_| RuntimeError::DuplicateOperation)?;
        }
        if held
            .authority
            .original_initial_callback_active
            .replace(true)
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        let _callback_loan = StartupLoan(&held.authority.original_initial_callback_active);
        let mut window = scene.windows()[selected]
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        {
            let launches = held
                .native_launches
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let (guard, socket) = launches.original_guard_and_socket_data(selected)?;
            let mut outputs = held
                .host_sdk_outputs
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let sdk = outputs[selected]
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let mut streams = held
                .host_sdk_streams
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            window.acquire_original_control_socket_into(
                sdk,
                guard,
                socket,
                &mut streams[selected],
            )?;
        }
        {
            let launches = held
                .native_launches
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let (guard, _) = launches.original_guard_and_socket_data(selected)?;
            let mut outputs = held
                .host_sdk_outputs
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let sdk = outputs[selected]
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let mut streams = held
                .host_sdk_streams
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            held.connect_original_scene_sdk_data(
                selected,
                &mut window,
                sdk,
                guard,
                &mut streams[selected],
            )?;
        }
        {
            let mut launches = held
                .native_launches
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let guard = launches.original_guard_slot_for_initial_lifecycle(selected)?;
            let mut roles = scene
                .roles()
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let mut outputs = held
                .host_sdk_outputs
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let sdk = outputs[selected]
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            held.continue_original_scene_peer_data(
                selected,
                &mut window,
                sdk,
                guard,
                &mut roles[selected],
                &scene.admit_ids()?[selected],
            )?;
        }
        // All mutable output loans end before Core repeats the actual
        // complete owning conjunction over the resulting preparation.
        drop(window);
        let window = scene.windows()[selected]
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        {
            let launches = held
                .native_launches
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let socket = launches.original_socket_data(selected)?;
            let outputs = held
                .host_sdk_outputs
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let sdks = [
                outputs[0].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                outputs[1].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                outputs[2].as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            ];
            held.recheck_original_scene_peer_data(selected, &window, sdks, socket)?;
        }
        scene.initial_completed()[selected].set(true);
        Ok(())
    }

    /// Runs a trusted original complete scene through its same retained owners.
    ///
    /// This entry stages actual inputs, executes each independently installed
    /// report/native/SDK action once, then consumes the separately installed
    /// initial-lifecycle windows. It grants no Arm, activation, execution,
    /// Capture, behavioral acceptance or restored-world permission.
    ///
    /// # Errors
    /// Refuses invalid installed inputs, repeated/foreign custody, unsupported
    /// owning data, insufficient installed resources or any original phase
    /// failure. The registered holder retains surviving partial owners.
    pub fn run_original_scene_into(
        original: &Rc<RefCell<Self>>,
        incoming: &mut Option<PacketCompleteOriginalSceneInputs>,
    ) -> Result<(), RuntimeError> {
        Self::stage_original_scene_into(original, incoming)?;
        Self::launch_and_complete_original_scene(original)
    }
}

/// Names the closed daemon refusal retained by the bounded callback phase.
pub(super) const INITIAL_CALLBACK_REFUSAL: &str = "original complete host callback refused";

impl InstalledPacketCompleteCollectionAuthority {
    /// Selects the bounded currentness path only during an issued original lifecycle.
    ///
    /// # Errors
    /// Refuses changed originals or currentness; ordinary calls preserve their existing path.
    pub(in crate::node_qualification::packet_collection::complete::authority) fn current_for_original_initial_callback(
        &self,
    ) -> Result<(), QualificationError> {
        if !self.original_initial_callback_active.get() {
            return self.current();
        }
        let original = self
            .report_startup_holder
            .get()
            .and_then(std::rc::Weak::upgrade)
            .ok_or_else(refused)?;
        let held = original.try_borrow().map_err(|_| refused())?;
        let selected = held.runtime_in_flight.get().is_some()
            || held
                .host_initial_lifecycle_in_flight_data()
                .map_err(|_| refused())?;
        if !selected {
            return Err(refused());
        }
        held.authenticate_native_origin_data()
            .map_err(|_| refused())?;
        self.current_original_initial_callback_data()
            .map_err(|_| QualificationError::Refused(INITIAL_CALLBACK_REFUSAL))
    }

    fn current_original_initial_callback_data(&self) -> Result<(), RuntimeError> {
        self.graph_policy
            .authenticate_original_initial_callback_scope_data(
                &self.roster,
                &self.host,
                &self.world,
                &self.requirements,
            )?;
        crate::node_qualification::packet_collection::fixture::authenticate_original_kernel_data(
            &self.kernel,
        )?;
        self.population
            .reference
            .verify(&self.population.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if !matches!(
            self.audit.record().decision,
            crate::node_qualification::AcceptanceDecision::Refused { .. }
        ) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.graph_policy
            .authenticate_original_initial_callback_scope_data(
                &self.roster,
                &self.host,
                &self.world,
                &self.requirements,
            )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn original_initial_callback_transient_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        // All source/current Host diagnostics are a Source row. This concrete
        // daemon layer additionally owns complete file hashing, kernel checking,
        // the population ContentRef BLAKE3 identity and its own fixed diagnostic.
        let files = self
            .graph_policy
            .original_initial_callback_currentness_storage_data()?;
        let kernel = crate::node_qualification::packet_collection::fixture::original_kernel_validation_counter_scratch_data();
        // These are the complete fixed reasons in ContentRef::validate/verify.
        // Their ContractError is dropped by the raw mapper before the daemon
        // diagnostic is constructed; conservatively retain both phase rows.
        let content_failure = [
            "unsupported hash algorithm",
            "expected 1–128 ASCII bytes",
            "expected 64 lowercase hexadecimal characters",
            "content must use cnp.blob.v1",
            "expected 1–128 printable ASCII bytes",
            "stored byte length disagrees with reference",
            "stored bytes disagree with digest",
        ]
        .into_iter()
        .map(str::len)
        .max()
        .ok_or(RuntimeError::UnsupportedFacet)?;
        let hash = std::mem::size_of::<blake3::Hasher>()
            .checked_add(std::mem::size_of::<blake3::Hash>())
            .and_then(|bytes| {
                bytes.checked_add(returned_layout_bytes(|| {
                    blake3::Hash::from([0; 32]).to_hex()
                }))
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<crucible_node_contract::HashRef>())
            })
            .and_then(|bytes| bytes.checked_add(9 + 11 + 64))
            .and_then(|bytes| bytes.checked_add(content_failure))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<crucible_node_contract::ContractError>())
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        // The only daemon failures in this selected callback phase are closed
        // static refusals. qualification_reason writes exactly prefix+message
        // into one requested bank; no arbitrary formatter is priced by a byte
        // factor. Source separately counts its own delegated error families.
        let complete_refusal = match refused() {
            QualificationError::Refused(message) => message,
            _ => return Err(RuntimeError::UnsupportedFacet),
        };
        let diagnostic = QUALIFICATION_REFUSAL_PREFIX
            .len()
            .checked_add(INITIAL_CALLBACK_REFUSAL.len().max(complete_refusal.len()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<String>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<QualificationError>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OperationFailure>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<EvidenceError>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        [files, kernel, hash, diagnostic]
            .into_iter()
            .try_fold(0usize, |sum, bytes| {
                sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
            })
    }
}

impl PacketCompleteReportStartupHolder {
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_initial_retained_descriptors_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.original_host_descriptor_views_data()
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_host_descriptor_views_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_native_origin_data()?;
        let scene = match &self.purpose {
            StartupHolderPurpose::OriginalScene => Some(
                self.original_scene
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?,
            ),
            StartupHolderPurpose::FreshRestoration(_) => {
                if self.fresh_lifecycle.get().is_none() {
                    return Err(RuntimeError::OwnerUnavailable);
                }
                None
            }
        };
        let mut total = self
            .authority
            .graph_policy
            .original_initial_retained_descriptors_data()?;
        total = total
            .checked_add(
                self.receiver_group
                    .retained_descriptor_views_precredit_data()?,
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        if let Some(scene) = &scene {
            total = total
                .checked_add(
                    scene
                        .inputs
                        .supervisor
                        .original_data()?
                        .retained_descriptor_count_data()?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
            // Incoming owners exist before staging; successful staging moves each
            // original into the native fixed bank, leaving only genuinely empty slots.
            for inputs in scene.inputs.launches.iter().flatten() {
                if let Some(slot) = &inputs.slot {
                    total = total
                        .checked_add(
                            slot.retained_descriptor_views_precredit_data()?
                                .ok_or(RuntimeError::UnsupportedFacet)?,
                        )
                        .ok_or(RuntimeError::ResourceLimit)?;
                }
                total = total
                    .checked_add(usize::from(inputs.bootstrap_reader.is_some()))
                    .and_then(|sum| sum.checked_add(usize::from(inputs.bootstrap_writer.is_some())))
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        if scene.is_none() {
            let fresh = self
                .fresh_lifecycle
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let inputs = fresh
                .inputs
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            total = total
                .checked_add(fresh.supervisor_descriptor_data()?)
                .ok_or(RuntimeError::ResourceLimit)?;
            for input in inputs.launches.iter().flatten() {
                if let Some(slot) = &input.slot {
                    total = total
                        .checked_add(
                            slot.retained_descriptor_views_precredit_data()?
                                .ok_or(RuntimeError::UnsupportedFacet)?,
                        )
                        .ok_or(RuntimeError::ResourceLimit)?;
                }
                total = total
                    .checked_add(usize::from(input.bootstrap_reader.is_some()))
                    .and_then(|value| {
                        value.checked_add(usize::from(input.bootstrap_writer.is_some()))
                    })
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        total = total
            .checked_add(
                self.native_launches
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .retained_descriptor_views_precredit_data()?,
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        for sdk in self
            .host_sdk_outputs
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .iter()
            .flatten()
        {
            total = total
                .checked_add(sdk.retained_descriptor_views_precredit_data()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        total = total
            .checked_add(
                self.host_sdk_streams
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .iter()
                    .filter(|stream| stream.is_some())
                    .count(),
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        total = total
            .checked_add(
                self.preparations
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .retained_descriptor_views_precredit_data()?,
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        total = total
            .checked_add(self.original_runtime_descriptor_views_data()?)
            .ok_or(RuntimeError::ResourceLimit)?;
        total = total
            .checked_add(self.fresh_runtime_descriptor_data()?)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(total)
    }
}

// Type inference observes the exact return layout without calling the closure
// or constructing the future hash/hex bank merely to quote its size.
fn returned_layout_bytes<T>(_: impl FnOnce() -> T) -> usize {
    std::mem::size_of::<T>()
}

// Both families use the same installed baseline protocol. These borrowed views
// never change the holder purpose or create an original-scene runtime actor.
enum HostInitialLifecycleOwner<'a> {
    Original(std::cell::Ref<'a, OriginalSceneOwners>),
    Fresh(std::cell::Ref<'a, super::super::restoration::FreshLifecycleOwners>),
}

impl HostInitialLifecycleOwner<'_> {
    fn staged(&self) -> bool {
        match self {
            Self::Original(owner) => owner.staged,
            Self::Fresh(owner) => owner.staged,
        }
    }

    fn launched(&self) -> &Cell<bool> {
        match self {
            Self::Original(owner) => &owner.launched,
            Self::Fresh(owner) => &owner.launched,
        }
    }

    fn initial_attempted(&self) -> &[Cell<bool>; 3] {
        match self {
            Self::Original(owner) => &owner.initial_attempted,
            Self::Fresh(owner) => &owner.initial_attempted,
        }
    }

    fn initial_in_flight(&self) -> &[Cell<bool>; 3] {
        match self {
            Self::Original(owner) => &owner.initial_in_flight,
            Self::Fresh(owner) => &owner.initial_in_flight,
        }
    }

    fn initial_completed(&self) -> &[Cell<bool>; 3] {
        match self {
            Self::Original(owner) => &owner.initial_completed,
            Self::Fresh(owner) => &owner.initial_completed,
        }
    }

    fn roles(&self) -> &RefCell<[Option<InstalledCnpConformanceRole>; 3]> {
        match self {
            Self::Original(owner) => &owner.roles,
            Self::Fresh(owner) => &owner.roles,
        }
    }

    fn windows(
        &self,
    ) -> &[OnceCell<RefCell<crucible::node_admission::CompleteOriginalHostInitialLifecycleWindow>>; 3]
    {
        match self {
            Self::Original(owner) => &owner.windows,
            Self::Fresh(owner) => &owner.windows,
        }
    }

    fn admit_ids(&self) -> Result<&[Id; 3], RuntimeError> {
        match self {
            Self::Original(owner) => Ok(&owner.inputs.admit_ids),
            Self::Fresh(owner) => owner
                .admit_ids
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable),
        }
    }
}

impl PacketCompleteReportStartupHolder {
    fn host_initial_lifecycle_owner_data(
        &self,
    ) -> Result<HostInitialLifecycleOwner<'_>, RuntimeError> {
        match &self.purpose {
            StartupHolderPurpose::OriginalScene => self
                .original_scene
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow()
                .map(HostInitialLifecycleOwner::Original)
                .map_err(|_| RuntimeError::OwnerBusy),
            StartupHolderPurpose::FreshRestoration(_) => self
                .fresh_lifecycle
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .try_borrow()
                .map(HostInitialLifecycleOwner::Fresh)
                .map_err(|_| RuntimeError::OwnerBusy),
        }
    }

    fn host_initial_lifecycle_in_flight_data(&self) -> Result<bool, RuntimeError> {
        if self.original_scene.get().is_none() && self.fresh_lifecycle.get().is_none() {
            return Ok(false);
        }
        Ok(self
            .host_initial_lifecycle_owner_data()?
            .initial_in_flight()
            .iter()
            .any(Cell::get))
    }
}

pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn fresh_view_counter_scratch_data()
-> usize {
    use std::mem::size_of;
    size_of::<HostInitialLifecycleOwner<'static>>()
        + size_of::<Result<HostInitialLifecycleOwner<'static>, RuntimeError>>()
        + size_of::<&HostInitialLifecycleOwner<'static>>()
        + size_of::<Option<std::cell::Ref<'static, OriginalSceneOwners>>>()
        + size_of::<&RefCell<[Option<InstalledCnpConformanceRole>; 3]>>()
        + size_of::<&[Cell<bool>; 3]>()
        + size_of::<Result<bool, QualificationError>>()
        + size_of::<Result<bool, RuntimeError>>()
        + size_of::<Result<&[Id; 3], RuntimeError>>()
}

/// Counts launch locals that remain live inside an initial lifecycle callback.
pub(super) fn paired_launch_counter_scratch_data() -> usize {
    use crucible::node_adapters::cnp::PacketCompleteAckPeerBootMaterial;
    use std::mem::size_of;

    size_of::<[Option<PacketCompleteAckPeerBootMaterial<'static>>; 3]>()
        + size_of::<std::cell::Ref<'static, PacketCompleteReportStartupHolder>>()
        + size_of::<HostInitialLifecycleOwner<'static>>()
        + size_of::<
            Option<
                fn(
                    &Rc<RefCell<PacketCompleteReportStartupHolder>>,
                    usize,
                ) -> Result<(), RuntimeError>,
            >,
        >()
        + size_of::<[usize; 3]>()
        + size_of::<usize>()
        + size_of::<bool>()
}
