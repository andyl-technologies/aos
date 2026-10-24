//! Retains direct edges of the genuine current Host17 producer.
//!
//! This separately guarded family permits the actual archive-backed Host source.
//! It leaves original15 origin checks and its Host2 dependency plan unchanged.

use super::*;
use crate::node_contract::HostSchedulingRestoredContinuation17;

impl HostSchedulingSource {
    // Raw retained archive-backed data is also observed before attachment. This
    // does not run the live current17 guard or confer a current capture grant.
    pub(in crate::node_contract::host_scheduling_owner) fn retained_archive_capture_dependency_storage_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        if self.process != std::process::id()
            || self.owner_thread != thread::current().id()
            || self.edition != preservation::Edition::CompleteOriginalLineage
            || self.original_ticket.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.archive_ticket
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .authenticate_birth()?;
        let plan = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        plan.as_ref().map_or(Ok(0), |plan| plan.retained_storage())
    }

    fn restored_dependency_origin17_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.owner_thread != thread::current().id()
            || self.edition != preservation::Edition::CompleteOriginalLineage
            || self.original_ticket.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.archive_ticket
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .authenticate_birth()?;
        self.authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let mut schemas = self
            .selection
            .binding
            .compatibility
            .implementation
            .formats
            .iter()
            .filter(|schema| schema.id.as_str() == "source-owned.host-scheduling-continuation/17");
        let schema = schemas.next().ok_or(RuntimeError::UnsupportedFacet)?;
        if schemas.next().is_some() {
            return Err(RuntimeError::InvalidReceipt);
        }
        crate::node_contract::authenticate_host_scheduling_restored_continuation_schema17_data(
            schema,
        )
    }

    pub(crate) fn restored_capture_dependency_construction17_data<'a>(
        &self,
        runtime_object: &'a ContentRef,
        objects: impl Iterator<Item = &'a ContentRef>,
        first_host: &'a ContentRef,
        first_semantic: [(&'a Id, &'a ContentRef); 3],
        parent_index_backing: usize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.restored_dependency_origin17_data()?;
        let mut rows = row_bytes(
            std::iter::once(runtime_object)
                .chain(objects)
                .chain(std::iter::once(first_host))
                .chain(first_semantic.into_iter().map(|(_, reference)| reference)),
        )?;
        rows = add(rows, add(size_of::<ContentRef>(), parent_index_backing)?)?;
        rows = add(
            rows,
            row_bytes(self.restored_immutable_dependencies17_data())?,
        )?;
        let generated_snapshot = generated_hash_bytes() + "application/json".len();
        let fixed = add(
            plan_header()?,
            add(reference_bytes(runtime_object)?, generated_snapshot)?,
        )?;
        let journal = add(reference_bytes(runtime_object)?, generated_snapshot)?;
        let old = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let old = old.as_ref().map_or(Ok(0), |plan| plan.retained_storage())?;
        within(add(old, add(fixed, add(rows, journal)?)?)?, maximum)
    }

    fn restored_immutable_dependencies17_data(&self) -> impl Iterator<Item = &ContentRef> + Clone {
        let selection = &self.selection;
        let compatibility = &selection.binding.compatibility;
        [
            &selection.descriptor.model_ref,
            &selection.descriptor.configuration_ref,
            &selection.descriptor.initialization_ref,
            &compatibility.profile_ref,
            &compatibility.configuration_ref,
            &compatibility.operating_contract.policy_ref,
            &compatibility.capabilities_ref,
            &compatibility.guarantees_ref,
            &selection.binding.authority.host_receipt,
        ]
        .into_iter()
        .chain(
            compatibility
                .implementation
                .artifacts
                .iter()
                .map(|artifact| &artifact.content),
        )
        .chain(compatibility.implementation.model_definitions.iter())
        .chain(
            compatibility
                .implementation
                .formats
                .iter()
                .map(|schema| &schema.definition),
        )
        .chain(compatibility.qualification_refs.iter())
    }

    pub(crate) fn prepare_restored_capture_dependency_plan17_data(
        &self,
        snapshot: &HostSchedulingRestoredContinuation17,
        runtime_object: &InputPayload,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.restored_dependency_origin17_data()?;
        let record = snapshot.record_data();
        if record.source != self.selection
            || record.runtime.source_activation.world_binding_hash != self.world
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let dependencies = std::iter::once(&runtime_object.reference)
            .chain(record.objects.iter().map(|object| &object.reference))
            .chain([
                &record.ancestry.parent_archive_index,
                &record.ancestry.first_host,
            ])
            .chain(
                record
                    .ancestry
                    .first_semantic
                    .iter()
                    .map(|entry| &entry.object),
            )
            .chain(self.restored_immutable_dependencies17_data());
        let count = dependencies.clone().count();
        let mut rows = Vec::new();
        let old = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let old = old.as_ref().map_or(Ok(0), |plan| plan.retained_storage())?;
        let fixed = add(
            plan_header()?,
            add(
                reference_bytes(&runtime_object.reference)?,
                reference_bytes(&snapshot.encoded_data().reference)?,
            )?,
        )?;
        let journal = add(
            reference_bytes(&runtime_object.reference)?,
            reference_bytes(&snapshot.encoded_data().reference)?,
        )?;
        within(
            add(
                old,
                add(fixed, add(row_bytes(dependencies.clone())?, journal)?)?,
            )?,
            maximum,
        )?;
        rows.try_reserve_exact(count)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let mut actual = rows
            .capacity()
            .checked_mul(size_of::<ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?;
        for reference in dependencies.clone() {
            actual = add(actual, reference_bytes(reference)?)?;
        }
        within(add(old, add(fixed, add(actual, journal)?)?)?, maximum)?;
        rows.extend(dependencies.cloned());
        rows.sort_unstable();
        rows.dedup();
        let plan = Rc::new(OriginalHostDependencyPlan {
            runtime: runtime_object.reference.clone(),
            snapshot: snapshot.encoded_data().reference.clone(),
            snapshot_dependencies: rows,
            journal_dependencies: [
                runtime_object.reference.clone(),
                snapshot.encoded_data().reference.clone(),
            ],
            journal: RefCell::new(None),
        });
        // Retain the actual plan before the post-construction census can fail.
        *self
            .capture_dependencies
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)? = Some(plan);
        let retained = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        within(
            retained
                .as_ref()
                .ok_or(RuntimeError::OutstandingObligations)?
                .retained_storage()?,
            maximum,
        )?;
        drop(retained);
        self.restored_dependency_origin17_data()
    }

    pub(crate) fn retain_restored_capture_journal_dependencies17_data(
        &self,
        runtime: &ContentRef,
        snapshot: &ContentRef,
        journal: &ContentRef,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.restored_dependency_origin17_data()?;
        let plan = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        plan.as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?
            .retain_journal(runtime, snapshot, journal, maximum)?;
        drop(plan);
        self.restored_dependency_origin17_data()
    }

    /// Quotes the exact current17 dependency plan without copying its edges.
    ///
    /// # Errors
    /// Refuses foreign or busy custody, an absent plan or another Runtime object.
    pub fn restored_complete_capture_dependency_preflight17_data(
        &self,
        runtime: &ContentRef,
    ) -> Result<HostCaptureDependencyStorageData, RuntimeError> {
        self.restored_dependency_origin17_data()?;
        let plans = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let plan = plans.as_ref().ok_or(RuntimeError::OutstandingObligations)?;
        if &plan.runtime != runtime {
            return Err(RuntimeError::ForeignAuthority);
        }
        let data = plan.data()?;
        drop(plans);
        self.restored_dependency_origin17_data()?;
        Ok(data)
    }

    /// Quotes only direct edges retained by the actual current17 producer.
    ///
    /// # Errors
    /// Refuses foreign or busy custody and excess count; unknown rows return None.
    pub fn restored_complete_capture_dependency_lookup17_data(
        &self,
        reference: &ContentRef,
        maximum_objects: usize,
    ) -> Result<Option<HostCaptureDependencyLookupData>, RuntimeError> {
        self.restored_dependency_origin17_data()?;
        let plans = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let data = plans
            .as_ref()
            .map(|plan| plan.lookup(reference, maximum_objects))
            .transpose()?
            .flatten();
        drop(plans);
        self.restored_dependency_origin17_data()?;
        Ok(data)
    }

    /// Copies the actual current17 producer's direct edges after bounded hashing.
    ///
    /// # Errors
    /// Refuses changed bytes, foreign or busy custody and insufficient storage.
    pub fn restored_complete_capture_dependencies17_data(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum_objects: usize,
        maximum_scratch_bytes: usize,
    ) -> Result<Option<Vec<ContentRef>>, RuntimeError> {
        self.restored_dependency_origin17_data()?;
        let plans = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let data = plans
            .as_ref()
            .map(|plan| {
                plan.copy_dependencies(reference, bytes, maximum_objects, maximum_scratch_bytes)
            })
            .transpose()?
            .flatten();
        drop(plans);
        self.restored_dependency_origin17_data()?;
        Ok(data)
    }
}
