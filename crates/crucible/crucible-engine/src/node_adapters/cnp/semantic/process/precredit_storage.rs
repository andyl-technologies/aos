//! Observes the same process capsule with raw precredit failures.
//!
//! This path never dispatches to legacy formatting-error callbacks. Unsupported
//! erased owners remain explicit obligations, including partial failure custody.

use std::mem::{size_of, size_of_val};

use crucible_node_transport::{
    connection::OriginalRetainedSupervisor, handshake::OriginalExtensionRegistryOwner,
};

use super::{CnpSemanticLaunchGuard, CnpSemanticProcessCustody};
use crate::{
    node_adapters::cnp::semantic::retained_storage::preparation::{
        PreparationCounter, metadata_failure,
    },
    node_contract::RuntimeError,
};

impl CnpSemanticLaunchGuard {
    pub(in crate::node_adapters::cnp::semantic) fn preparation_storage_origin_precredit_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let native = self
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        native.storage_origin_precredit_data()?;
        if let Some(runtime) = &native.runtime {
            runtime.installed_storage_origin_precredit_data()?;
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn charge_retained_storage_precredit_data(
        &self,
        registry: Option<&OriginalExtensionRegistryOwner>,
        retained_supervisor: Option<&OriginalRetainedSupervisor>,
        counter: &mut PreparationCounter,
    ) -> Result<(), RuntimeError> {
        self.charge_retained_storage_selected_precredit_data(
            registry,
            retained_supervisor,
            None,
            counter,
        )
    }

    pub(in crate::node_adapters::cnp::semantic) fn charge_initial_lifecycle_retained_storage_precredit_data(
        &self,
        registry: Option<&OriginalExtensionRegistryOwner>,
        retained_supervisor: Option<&OriginalRetainedSupervisor>,
        source: &std::rc::Rc<super::super::PacketCompleteSemanticSource>,
        counter: &mut PreparationCounter,
    ) -> Result<(), RuntimeError> {
        self.charge_retained_storage_selected_precredit_data(
            registry,
            retained_supervisor,
            Some(source),
            counter,
        )
    }

    fn charge_retained_storage_selected_precredit_data(
        &self,
        registry: Option<&OriginalExtensionRegistryOwner>,
        retained_supervisor: Option<&OriginalRetainedSupervisor>,
        initial_source: Option<&std::rc::Rc<super::super::PacketCompleteSemanticSource>>,
        counter: &mut PreparationCounter,
    ) -> Result<(), RuntimeError> {
        self.preparation_storage_origin_precredit_data()?;
        if let Some(slot) = &self.slot {
            counter.add(size_of_val(slot.as_ref()))?;
            match slot.retained_requested_storage_precredit_data(counter.remaining())? {
                Some(bytes) => counter.add(bytes)?,
                None => counter.unknowns.supervisor_slot = true,
            }
            self.preparation_storage_origin_precredit_data()?;
        }
        let native = self
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        counter.add(size_of::<CnpSemanticProcessCustody>())?;
        native.charge_retained_storage_precredit_data(
            registry,
            retained_supervisor,
            initial_source,
            counter,
        )?;
        self.preparation_storage_origin_precredit_data()
    }
}

#[cfg(test)]
mod tests;

impl CnpSemanticProcessCustody {
    pub(in crate::node_adapters::cnp::semantic) fn storage_origin_precredit_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.ensure_origin()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.executable_guard
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .storage_origin_precredit_data()?;
        self.read_owner.storage_precredit_data()
    }

    fn charge_retained_storage_precredit_data(
        &self,
        registry: Option<&OriginalExtensionRegistryOwner>,
        retained_supervisor: Option<&OriginalRetainedSupervisor>,
        initial_source: Option<&std::rc::Rc<super::super::PacketCompleteSemanticSource>>,
        counter: &mut PreparationCounter,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_precredit_data()?;
        let Self {
            creator_process: _,
            child,
            original_child,
            provider_pid: _,
            directory,
            controller,
            compact_runtime,
            protocol_supervisor,
            handshake,
            extension_handshake,
            expected_executable,
            installation_kind: _,
            registration,
            installed_identity,
            source,
            acceptance,
            conformance,
            collection_plan,
            runtime,
            completed_ack_protocol_started: _,
            completed_ack_admission,
            rejected_control,
            group: _,
            killed: _,
            reaped: _,
            read_owner,
            kernel_identity: _,
            executable_guard,
        } = self;
        if let Some(runtime) = runtime {
            runtime.installed_storage_origin_precredit_data()?;
            if runtime.installed_restoration.is_some() {
                counter
                    .add(runtime.installed_retained_storage_precredit_data(counter.remaining())?)?;
            }
        }
        counter.path(directory)?;
        counter.content_reference(expected_executable)?;
        if let Some(identity) = installed_identity {
            for text in [&identity.algorithm, &identity.domain, &identity.digest] {
                counter.add(text.capacity())?;
            }
        }
        counter.rc(read_owner)?;

        if child.is_some() && original_child.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if let Some(original) = original_child {
            original
                .retained_metadata_data()
                .map_err(metadata_failure)?;
        }
        if let Some(child) = child {
            let streams = child.stdin.is_some() || child.stdout.is_some() || child.stderr.is_some();
            counter.unknowns.child_streams |= streams;
            counter.unknowns.child_process_backing = true;
            counter.std_child_layout |= cfg!(all(
                target_os = "linux",
                target_env = "gnu",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )) && !streams;
        }

        {
            let supervisor = protocol_supervisor
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            match (
                controller,
                compact_runtime,
                supervisor.as_ref(),
                retained_supervisor,
            ) {
                (Some(_), Some(_), _, _) => return Err(RuntimeError::ForeignAuthority),
                (None, Some(runtime), witness, Some(owner)) => counter.metadata(
                    &runtime
                        .retained_metadata_facts_with_retained_supervisor(owner, witness)
                        .map_err(metadata_failure)?,
                )?,
                (None, Some(_), _, None) => {
                    // The opaque owner cannot be priced through an erased callback.
                    // Refuse rather than hide its banks or surviving failure state.
                    return Err(RuntimeError::UnsupportedFacet);
                }
                (Some(controller), None, witness, Some(owner)) => counter.metadata(
                    &controller
                        .original_restoration_host_metadata_facts_with_retained_supervisor(
                            owner, witness,
                        )
                        .map_err(metadata_failure)?,
                )?,
                (Some(controller), None, _, None) => {
                    // Generic erased callbacks are never called precredit.
                    // The known direct family above supplies actual backing;
                    // an unsupported witness remains an explicit obligation.
                    counter.metadata(
                        &controller
                            .original_owned11_metadata_facts()
                            .map_err(metadata_failure)?,
                    )?;
                    counter.unknowns.protocol_supervisor_callback = true;
                    counter.unknowns.live_sdk_backing = true;
                }
                (None, None, None, None) => {}
                (None, None, _, _) => return Err(RuntimeError::ForeignAuthority),
            }
        }

        if let Some(handshake) = handshake {
            counter.metadata(
                &handshake
                    .retained_metadata_facts_data()
                    .map_err(metadata_failure)?,
            )?;
        }
        if let Some(extension) = extension_handshake {
            if let Some(registry) = registry {
                registry
                    .authenticate_original(extension)
                    .map_err(metadata_failure)?;
                counter.metadata(
                    &extension
                        .retained_metadata_facts_data(registry)
                        .map_err(metadata_failure)?,
                )?;
            } else {
                counter.unknowns.extension_callback = true;
            }
        } else if registry.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if let Some((controller, handshake)) = rejected_control {
            // This separate retained controller has its own erased supervisor.
            // A loan authenticated against the primary controller cannot cover it.
            counter.unknowns.protocol_supervisor_callback = true;
            counter.unknowns.live_sdk_backing = true;
            counter.metadata(
                &controller
                    .original_owned11_metadata_facts()
                    .map_err(metadata_failure)?,
            )?;
            counter.metadata(
                &handshake
                    .retained_metadata_facts_data()
                    .map_err(metadata_failure)?,
            )?;
        }

        // Typed callbacks own their concrete retained graph. The default does
        // not delegate to a potentially allocating OperationFailure observer.
        macro_rules! installed {
            ($value:expr, $observe:path) => {
                if let Some(value) = $value
                    && counter.rc(value)?
                {
                    let nested = $observe(value.as_ref(), counter.remaining())?;
                    self.storage_origin_precredit_data()?;
                    match nested {
                        Some(bytes) => counter.add(bytes)?,
                        None => counter.unknowns.installed_source_owners = true,
                    }
                }
            };
        }
        installed!(
            registration,
            super::super::CnpSemanticRegistrationPolicy::retained_requested_storage_precredit_data
        );
        if let Some(original) = initial_source {
            CnpSemanticLaunchGuard::charge_original_initial_lifecycle_source_precredit_data(
                source.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                original,
                counter,
            )?;
        } else {
            installed!(
                source,
                super::super::CnpSemanticSource::retained_requested_storage_precredit_data
            );
        }
        installed!(
            acceptance,
            super::super::CnpSemanticAcceptance::retained_requested_storage_precredit_data
        );
        installed!(
            conformance,
            super::super::CnpSemanticConformanceAuthority::retained_requested_storage_precredit_data
        );

        if let Some(plan) = collection_plan {
            // The private Plan contains another authority Rc. Excluding that
            // edge's backing is valid only for the exact allocation already
            // visited through this custody's conformance owner.
            let authority = conformance.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
            if !plan.has_authority(authority.as_ref()) {
                return Err(RuntimeError::ForeignAuthority);
            }
            counter.add(plan.retained_allocation_bytes_excluding_authority_precredit_data()?)?;
        }
        let admission = completed_ack_admission
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(admission) = admission.as_ref() {
            admission.charge_retained_storage_precredit_data(counter)?;
        }
        if let Some(executable) = executable_guard
            && counter.rc(executable)?
        {
            executable.charge_retained_storage_precredit_data(counter)?;
        }
        self.storage_origin_precredit_data()
    }
}

impl CnpSemanticLaunchGuard {
    /// Counts an exact original Source through its closed initial owner walk.
    pub(in crate::node_adapters::cnp::semantic) fn charge_original_initial_lifecycle_source_precredit_data(
        installed: &std::rc::Rc<dyn super::super::CnpSemanticSource>,
        original: &std::rc::Rc<super::super::PacketCompleteSemanticSource>,
        counter: &mut PreparationCounter,
    ) -> Result<(), RuntimeError> {
        original.storage_origin_with_error::<RuntimeError>()?;
        if !std::ptr::eq(
            std::rc::Rc::as_ptr(installed).cast::<()>(),
            std::rc::Rc::as_ptr(original).cast::<()>(),
        ) {
            return Err(RuntimeError::ForeignAuthority);
        }
        // Charge the same actual Rc root as the ordinary callback. Its real
        // identity also keeps completed-admission aliases on existing dedup.
        if counter.rc(installed)? {
            counter.add(
                original
                    .original_initial_lifecycle_nested_source_storage_data(counter.remaining())?,
            )?;
        }
        original.storage_origin_with_error::<RuntimeError>()
    }
}
