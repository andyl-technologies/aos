//! Observes process-capsule roots without querying or changing a native process.

use std::mem::{size_of, size_of_val};

use super::{CnpSemanticLaunchGuard, CnpSemanticProcessCustody};
use crate::node_adapters::cnp::semantic::{
    refused,
    retained_storage::{Counter, common},
    unknown,
};
use crate::node_contract::OperationFailure;

impl CnpSemanticLaunchGuard {
    pub(in crate::node_adapters::cnp::semantic) fn storage_origin_data(
        &self,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin().map_err(unknown)?;
        let native = self
            .custody
            .as_ref()
            .ok_or_else(|| refused("original CNP process owner was transferred"))?;
        native.storage_origin_data()
    }

    pub(in crate::node_adapters::cnp::semantic) fn charge_retained_storage_data(
        &self,
        registry: Option<&crucible_node_transport::handshake::OriginalExtensionRegistryOwner>,
        counter: &mut Counter,
    ) -> Result<(), OperationFailure> {
        self.storage_origin_data()?;
        // The guard is inline in its containing preparation. A supervisor slot
        // is a distinct actual Box, not a configured reservation byte count.
        if let Some(slot) = &self.slot {
            counter.add(size_of_val(slot.as_ref()))?;
            if let Some(bytes) = slot.retained_requested_storage_data(counter.remaining())? {
                counter.add(bytes)?;
            } else {
                counter.unknowns.supervisor_slot = true;
            }
        }
        let native = self
            .custody
            .as_ref()
            .ok_or_else(|| refused("original CNP process owner was transferred"))?;
        counter.add(size_of::<CnpSemanticProcessCustody>())?;
        native.charge_retained_storage_data(registry, counter)?;
        self.storage_origin_data()
    }
}

impl CnpSemanticProcessCustody {
    pub(in crate::node_adapters::cnp::semantic) fn storage_origin_data(
        &self,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin().map_err(unknown)?;
        // Check the actual creator thread before any RefCell, callback owner or
        // SDK journal observation. This invokes no kernel/source current check.
        self.executable_guard
            .as_ref()
            .ok_or_else(|| refused("original executable ownership is unavailable"))?
            .ensure_origin()
            .map_err(unknown)
    }

    fn charge_retained_storage_data(
        &self,
        registry: Option<&crucible_node_transport::handshake::OriginalExtensionRegistryOwner>,
        counter: &mut Counter,
    ) -> Result<(), OperationFailure> {
        self.storage_origin_data()?;
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
        counter.charge(directory)?;
        counter.charge(expected_executable)?;
        counter.charge(installed_identity)?;
        counter.rc(read_owner)?;

        if child.is_some() && original_child.is_some() {
            return Err(super::super::refused(
                "original process has conflicting std and descriptor child owners",
            ));
        }
        if let Some(original) = original_child {
            // OwnedFd, creator identity and typed exit cache are concrete inline
            // fields already counted with Self. Kernel descriptor state is separate.
            original.retained_metadata_data().map_err(unknown)?;
        }
        if let Some(child) = child {
            // Child's root is inline in Self. Kernel PID/FD tables are separate;
            // no private std process/pipe heap is inferred from size_of<Child>.
            let streams = child.stdin.is_some() || child.stdout.is_some() || child.stderr.is_some();
            counter.unknowns.child_streams |= streams;
            // The exact pinned AOS Rust 1.98.1 GNU/Linux implementation owns
            // only pid, inline exit status and Option<PidFd<FileDesc<OwnedFd>>>
            // beneath Child when no parent stdio pipe is retained. This is a
            // source-qualified zero heap, not a size or stack approximation.
            let supported = cfg!(all(
                target_os = "linux",
                target_env = "gnu",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )) && !streams;
            // A matching cfg and these fields do not authenticate the compiler
            // product. The selected implementation must separately bind the
            // exact audited producer/stdlib contract before closing this term.
            counter.unknowns.child_process_backing = true;
            counter.std_child_layout |= supported;
        }
        {
            // The witness and its Option are inline in this custody. The SDK
            // walks the same controller plus its actual shared supervisor and
            // retained protocol view; no second guessed header is charged.
            let supervisor = protocol_supervisor.try_borrow().map_err(unknown)?;
            // This legacy callback has no independently retained concrete
            // supervisor loan for the compact owner. Native18 uses the raw
            // precredit path; old observers must never silently omit that graph.
            if compact_runtime.is_some() {
                return Err(refused(
                    "compact runtime requires its concrete supervisor census",
                ));
            }
            match (controller, supervisor.as_ref()) {
                (Some(controller), Some(supervisor)) => counter.metadata(
                    &controller
                        .original_owned11_metadata_facts_with_supervisor(supervisor)
                        .map_err(unknown)?,
                )?,
                (Some(controller), None) => counter.metadata(
                    &controller
                        .original_owned11_metadata_facts()
                        .map_err(unknown)?,
                )?,
                (None, Some(_)) => {
                    return Err(refused("original supervisor has no owning controller"));
                }
                (None, None) => {}
            }
        }
        if let Some(handshake) = handshake {
            counter.metadata(&handshake.retained_metadata_facts_data().map_err(unknown)?)?;
        }
        if let Some(extension) = extension_handshake {
            if let Some(registry) = registry {
                // The SDK verifies actual wrapper/callback Rc identity before
                // exposing this known family's fields. No supplied DTO or
                // empty-selection label can substitute a metadata owner.
                registry.authenticate_original(extension).map_err(unknown)?;
                counter.metadata(
                    &extension
                        .retained_metadata_facts_data(registry)
                        .map_err(unknown)?,
                )?;
            } else {
                counter.unknowns.extension_callback = true;
            }
        } else if registry.is_some() {
            return Err(refused("registry owner has no original handshake"));
        }
        if let Some((controller, handshake)) = rejected_control {
            counter.metadata(
                &controller
                    .original_owned11_metadata_facts()
                    .map_err(unknown)?,
            )?;
            counter.metadata(&handshake.retained_metadata_facts_data().map_err(unknown)?)?;
        }
        if let Some(value) = registration
            && counter.rc(value)?
        {
            let nested = value.retained_requested_storage_data(counter.remaining())?;
            self.storage_origin_data()?;
            match nested {
                Some(bytes) => counter.add(bytes)?,
                None => counter.unknowns.installed_source_owners = true,
            }
        }
        if let Some(value) = source
            && counter.rc(value)?
        {
            let nested = value.retained_requested_storage_data(counter.remaining())?;
            self.storage_origin_data()?;
            match nested {
                Some(bytes) => counter.add(bytes)?,
                None => counter.unknowns.installed_source_owners = true,
            }
        }
        if let Some(value) = acceptance
            && counter.rc(value)?
        {
            let nested = value.retained_requested_storage_data(counter.remaining())?;
            self.storage_origin_data()?;
            match nested {
                Some(bytes) => counter.add(bytes)?,
                None => counter.unknowns.installed_source_owners = true,
            }
        }
        if let Some(value) = conformance
            && counter.rc(value)?
        {
            let nested =
                super::super::CnpSemanticConformanceAuthority::retained_requested_storage_data(
                    value.as_ref(),
                    counter.remaining(),
                )?;
            self.storage_origin_data()?;
            match nested {
                Some(bytes) => counter.add(bytes)?,
                None => counter.unknowns.installed_source_owners = true,
            }
        }
        if let Some(plan) = collection_plan {
            // The original private Plan walker conservatively charges its
            // backing per view; it never invents an equality-based discount.
            counter.add(
                plan.retained_allocation_bytes_excluding_authority()
                    .map_err(unknown)?,
            )?;
        }
        if let Some(runtime) = runtime {
            common::runtime(runtime, counter)?;
        }
        let admission = completed_ack_admission.try_borrow().map_err(unknown)?;
        if let Some(admission) = admission.as_ref() {
            admission.charge_retained_storage_data(counter)?;
        }
        if let Some(executable) = executable_guard
            && counter.rc(executable)?
        {
            executable.charge_retained_storage_data(counter)?;
        }
        self.storage_origin_data()
    }
}

impl CnpSemanticProcessCustody {
    /// Retains metadata identity from the same actual typed extension handshake.
    ///
    /// This is an inert owner alias, not extension acceptance or native authority.
    /// Generic erased verifiers have no supported metadata owner and refuse.
    ///
    /// # Errors
    /// Refuses foreign origins, changed actual process/registrar custody, missing
    /// original extension handshake or an unsupported concrete registry family.
    pub fn original_extension_registry_metadata_owner(
        &self,
    ) -> Result<crucible_node_transport::handshake::OriginalExtensionRegistryOwner, OperationFailure>
    {
        self.storage_origin_data()?;
        self.authenticate_process().map_err(unknown)?;
        let extension = self
            .extension_handshake
            .as_ref()
            .ok_or_else(|| refused("original extension handshake is absent"))?;
        let controller = self
            .original_controller_data()
            .map_err(unknown)?
            .ok_or_else(|| refused("original extension controller is absent"))?;
        extension
            .verify_authority(controller.authority())
            .map_err(unknown)?;
        let owner = extension
            .retain_original_registry_metadata_owner()
            .map_err(unknown)?;
        owner.authenticate_original(extension).map_err(unknown)?;
        self.authenticate_process().map_err(unknown)?;
        Ok(owner)
    }

    /// Rechecks a retained metadata owner against this same original handshake.
    ///
    /// # Errors
    /// Refuses another process/thread, changed actual native or registrar state,
    /// a missing handshake or a different concrete registry owner allocation.
    pub fn authenticate_original_extension_registry_metadata_owner(
        &self,
        owner: &crucible_node_transport::handshake::OriginalExtensionRegistryOwner,
    ) -> Result<(), OperationFailure> {
        self.storage_origin_data()?;
        self.authenticate_process().map_err(unknown)?;
        let extension = self
            .extension_handshake
            .as_ref()
            .ok_or_else(|| refused("original extension handshake is absent"))?;
        let controller = self
            .original_controller_data()
            .map_err(unknown)?
            .ok_or_else(|| refused("original extension controller is absent"))?;
        extension
            .verify_authority(controller.authority())
            .map_err(unknown)?;
        owner.authenticate_original(extension).map_err(unknown)?;
        self.authenticate_process().map_err(unknown)
    }
}
