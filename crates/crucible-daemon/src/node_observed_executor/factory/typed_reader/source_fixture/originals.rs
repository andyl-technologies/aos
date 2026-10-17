//! Conjoins private issuance with actual surviving kernel and registrar custody.

use super::super::{InstalledTypedReaderPackage, kernel};
use super::{InstalledTypedReaderSourceFixture, invalid, launch};
use crucible::node_adapters::cnp::OriginalRuntimeLineage;
use crucible::node_contract::{InputProvenanceClosure, OriginalInputLineage};
use crucible::node_scheduling::RuntimeInputBatch;
use crucible_node_contract::{ContentRef, ResourceLimits};
use crucible_node_provider::{
    ProviderError,
    client::OriginalLineageRealization,
    reference_lineage::LineageSourceGuard,
    reference_service::{ReferenceNegotiatedLineageReaderLaunchBootstrap, ReferenceProfile},
};

impl InstalledTypedReaderSourceFixture {
    /// Rechecks the full regenerated source and independently selected resources.
    ///
    /// # Errors
    /// Refuses foreign plan/package/profile/host source or exhausted original credit.
    pub fn authenticate_source(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        resources: &ResourceLimits,
    ) -> Result<(), ProviderError> {
        let source = self.source(&profile.descriptor.id)?;
        if plan != &self.reference
            || package.identity() != self.package.identity()
            || resources != &self.resources
        {
            return Err(invalid());
        }
        let current = package
            .profile(
                profile.descriptor.id.clone(),
                profile.owner.id.clone(),
                source.launch.bootstrap.quantum_ps,
                source.launch.bootstrap.host_budget_ns,
                source.launch.closed_ingress,
            )
            .map_err(|_| invalid())?;
        profile.preflight_retention(1024 * 1024)?;
        if launch::profile_bytes(profile)? != launch::profile_bytes(&source.profile)?
            || launch::profile_bytes(&current)? != launch::profile_bytes(profile)?
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Checks the exact private bootstrap without hashing or publishing its token.
    ///
    /// # Errors
    /// Refuses any substituted secret, host receipt, authority, source body or limit.
    pub fn authenticate_launch(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        original: &ReferenceNegotiatedLineageReaderLaunchBootstrap,
    ) -> Result<(), ProviderError> {
        self.authenticate_source(plan, package, profile, &self.resources)?;
        let source = self.source(&profile.descriptor.id)?;
        super::super::owning::count_launch(original, 16 * 1024 * 1024)?;
        // Private serialized bytes are compared only in temporary owning memory.
        // No content identity or public evidence is derived from this comparison.
        if launch::encode(original, 16 * 1024 * 1024)?
            != launch::encode(&source.launch, 16 * 1024 * 1024)?
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Enrolls actual original two-group kernel facts beneath initialized native custody.
    ///
    /// # Errors
    /// Refuses changed private launch/realization/registrar/PID/start/maps/limits;
    /// any existing enrollment remains unchanged on refusal.
    pub fn authenticate_realization(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        guard: &LineageSourceGuard,
        original: &OriginalLineageRealization<'_>,
        resources: &ResourceLimits,
    ) -> Result<(), ProviderError> {
        self.authenticate_source(plan, package, profile, resources)?;
        let source = self.source(&profile.descriptor.id)?;
        guard.verify_extension_registrar()?;
        if guard.selected_extensions()
            != Some(std::slice::from_ref(package.definition().selection()))
            || launch::encode(original.bootstrap(), 16 * 1024 * 1024)?
                != launch::encode(&source.launch.bootstrap, 16 * 1024 * 1024)?
            || original.realization().prepared_token != source.launch.bootstrap.prepared_token
            || original.closed_gate().gate_id != source.launch.bootstrap.gate_id
            || !original.closed_gate().gate_closed
            || original.realization().realization_manifest.bindings.len() != 1
            || original.realization().realization_manifest.bindings[0].compatibility
                != source.binding
        {
            return Err(invalid());
        }
        let features = guard.negotiated_features(4)?;
        if features != super::handshake::features()? {
            return Err(invalid());
        }
        let mut retained_features = source.features.try_borrow_mut().map_err(|_| invalid())?;
        if retained_features
            .as_ref()
            .is_some_and(|old| old != &features)
        {
            return Err(invalid());
        }
        let provider = guard.provider_pid().ok_or_else(invalid)?;
        let native = u32::try_from(original.native_pid().get()).map_err(|_| invalid())?;
        let actual = kernel::enroll(package, provider, original, resources)?;
        guard.verify_extension_registrar()?;
        let mut enrolled = source.enrollment.try_borrow_mut().map_err(|_| invalid())?;
        if enrolled
            .as_ref()
            .is_some_and(|old| old != &(provider, native, actual.clone()))
        {
            return Err(invalid());
        }
        // Enrollment retains the first actual private gate and owning capsule.
        // Equal wire IDs or a new kernel snapshot cannot replace that owner.
        let read_handle = guard.original_read_handle()?;
        let mut retained_read = source.read_handle.try_borrow_mut().map_err(|_| invalid())?;
        if let Some(original_read) = retained_read.as_ref() {
            if !original_read.same_original(&read_handle) {
                return Err(invalid());
            }
            original_read.ensure_current()?;
        } else {
            *retained_read = Some(read_handle);
        }
        *enrolled = Some((provider, native, actual));
        *retained_features = Some(features);
        Ok(())
    }

    /// Checks an original window against surviving private scope and kernel enrollment.
    ///
    /// Source-native semantic/body enrollment is separately performed by the
    /// shared host oracle immediately after this callback, before common reports.
    ///
    /// # Errors
    /// Refuses a foreign current owner, operation, world, bootstrap or kernel tuple.
    pub fn authenticate_window(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        original: &OriginalRuntimeLineage<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_source(plan, package, profile, &self.resources)?;
        self.current(&profile.descriptor.id)?;
        let source = self.source(&profile.descriptor.id)?;
        let operation = original.operation();
        let record = operation.activation().record();
        if operation.token().route().node != profile.descriptor.id
            || record.world_binding_hash != self.world
            || record.generation.get() != 1
            || record.activation_id != source.launch.bootstrap.activation_id
            || original.source().stop().session_id != source.launch.bootstrap.authority.session_id
            || original.source().stop().incarnation_id
                != source.launch.bootstrap.authority.incarnation_id
        {
            return Err(invalid());
        }
        self.current(&profile.descriptor.id)?;
        self.staging.enroll_window(&self.programme, original)?;
        Ok(())
    }

    /// Checks surviving producer and consumer groups before an original Stage.
    ///
    /// Full producer semantics and ordered bodies are independently checked by
    /// the same shared native oracle against its preceding source callbacks.
    ///
    /// # Errors
    /// Refuses changed plan, world, route, lineage activation or any original group.
    pub fn authenticate_inputs(
        &self,
        plan: &ContentRef,
        package: &InstalledTypedReaderPackage,
        profile: &ReferenceProfile,
        original: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<(), ProviderError> {
        self.authenticate_source(plan, package, profile, &self.resources)?;
        if original.node() != &profile.descriptor.id
            || provenance.node() != &profile.descriptor.id
            || original.activation().record().world_binding_hash != self.world
            || provenance.activation().record().world_binding_hash != self.world
        {
            return Err(invalid());
        }
        for source in &self.sources {
            self.current(&source.profile.descriptor.id)?;
        }
        self.staging.retain_inputs(original, provenance, lineage)?;
        Ok(())
    }

    pub(in super::super) fn current(
        &self,
        node: &crucible_node_contract::Id,
    ) -> Result<(), ProviderError> {
        let source = self.source(node)?;
        let retained = source.enrollment.try_borrow().map_err(|_| invalid())?;
        let (provider, native, original) = retained.as_ref().ok_or_else(invalid)?;
        if kernel::current(
            &self.package,
            *provider,
            *native,
            &self.resources,
            &original.ready,
        )? != *original
        {
            return Err(invalid());
        }
        Ok(())
    }
}
