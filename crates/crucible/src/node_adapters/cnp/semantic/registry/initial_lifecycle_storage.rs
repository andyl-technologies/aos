//! Observes actual installed role and registry backing before initial dispatch.
//!
//! The installed action authenticates origin and exact holder identity before
//! entering these callbacks. They follow only typed raw-error owning observers;
//! erased unknown owners refuse rather than fall back to formatted diagnostics.

use std::mem::{align_of, size_of};

use super::CnpSemanticRegistry;
use crate::{
    node_adapters::cnp::semantic::{
        InstalledCnpConformanceRole, retained_storage::preparation::PreparationCounter,
    },
    node_contract::{NodeRuntime, RuntimeError},
};

fn fixed_scratch() -> usize {
    size_of::<PreparationCounter>() + size_of::<[usize; 4]>()
}

impl CnpSemanticRegistry {
    /// Counts the actual fixed nested bank for the typed registry observer.
    pub const fn retained_requested_storage_counter_scratch_data() -> usize {
        size_of::<PreparationCounter>() + size_of::<[usize; 4]>()
    }

    /// Counts the real registry tree and installed policy backing as data.
    ///
    /// The result excludes this registry's inline root. The caller first admits
    /// the fixed counter and policy nested observers, and authenticates the same
    /// registered holder's creator. No policy authentication, hash, serializer,
    /// source currentness or kernel callback runs through this data entry.
    ///
    /// # Errors
    /// Refuses invalid registry geometry, unsupported typed policy owners or
    /// checked traversal/storage ceilings. Legacy observers are never invoked.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            policy,
            installed,
            maximum_roles,
        } = self;
        if *maximum_roles == 0 || *maximum_roles > 256 || installed.len() > *maximum_roles {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut counter = PreparationCounter::new(maximum);
        if counter.rc(policy)? {
            counter.add(
                policy
                    .retained_requested_storage_precredit_data(counter.remaining())?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )?;
        }
        counter.add(NodeRuntime::capture_protocol_tree_storage(
            1,
            installed.len(),
            size_of::<(crucible_node_contract::HashRef, ())>(),
            align_of::<(crucible_node_contract::HashRef, ())>(),
            counter.remaining(),
        )?)?;
        for identity in installed {
            for text in [&identity.algorithm, &identity.domain, &identity.digest] {
                counter.add(text.capacity())?;
            }
        }
        counter.finish().complete_requested_bytes_precredit_data()
    }
}

impl InstalledCnpConformanceRole {
    /// Counts the fixed counter for an actual registered conformance role.
    pub fn retained_requested_storage_counter_scratch_data() -> usize {
        fixed_scratch()
    }

    /// Counts the actual role's policy, Source, authority, plan and hash backing.
    ///
    /// This excludes the inline role root, already owned by its actual fixed
    /// slot. All shared edges are traversed through their real Rc identities;
    /// independently repeated observers receive no cross-call alias discount.
    /// The default unknown typed callback refuses complete storage. This data
    /// observation cannot install or authenticate a role or dispatch a method.
    ///
    /// # Errors
    /// Refuses unknown concrete backing, a plan/authority mismatch, typed origin
    /// or busy failures, or requested storage above the supplied ceiling.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.retained_storage_data(None, maximum)
    }

    /// Counts a role while excluding its same independently observed Source.
    ///
    /// The caller owns and counts that actual Source allocation separately in
    /// the same complete resource conjunction. Only a pointer-exact Source loan
    /// can exclude that backing; equal installation data cannot substitute it.
    /// All policy, authority, plan and hash owners remain included. This is data
    /// decomposition, never permission or evidence of complete whole storage.
    ///
    /// # Errors
    /// Refuses a foreign Source loan, unsupported remaining backing or an
    /// actual row exceeding the supplied requested-storage ceiling.
    pub fn retained_requested_storage_excluding_original_source_precredit_data(
        &self,
        original: &std::rc::Rc<crate::node_adapters::cnp::PacketCompleteSemanticSource>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.retained_storage_data(Some(original), maximum)
    }

    fn retained_storage_data(
        &self,
        excluded: Option<&std::rc::Rc<crate::node_adapters::cnp::PacketCompleteSemanticSource>>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let super::InstalledCnpSemanticRole {
            kind: _,
            policy,
            identity,
            source,
            acceptance,
            conformance,
            collection_plan,
        } = &self.0;
        if let Some(original) = excluded
            && !std::ptr::eq(
                std::rc::Rc::as_ptr(source).cast::<()>(),
                std::rc::Rc::as_ptr(original).cast::<()>(),
            )
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut counter = PreparationCounter::new(maximum);
        for text in [&identity.algorithm, &identity.domain, &identity.digest] {
            counter.add(text.capacity())?;
        }
        if counter.rc(policy)? {
            counter.add(
                policy
                    .retained_requested_storage_precredit_data(counter.remaining())?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )?;
        }
        if excluded.is_none() && counter.rc(source)? {
            counter.add(
                source
                    .retained_requested_storage_precredit_data(counter.remaining())?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )?;
        }
        if let Some(acceptance) = acceptance
            && counter.rc(acceptance)?
        {
            counter.add(
                acceptance
                    .retained_requested_storage_precredit_data(counter.remaining())?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )?;
        }
        if let Some(conformance) = conformance
            && counter.rc(conformance)?
        {
            counter.add(
                super::super::CnpSemanticConformanceAuthority::retained_requested_storage_precredit_data(
                    conformance.as_ref(),
                    counter.remaining(),
                )?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )?;
        }
        match (collection_plan, conformance) {
            (Some(plan), Some(authority)) if plan.has_authority(authority.as_ref()) => {
                counter
                    .add(plan.retained_allocation_bytes_excluding_authority_precredit_data()?)?;
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        counter.finish().complete_requested_bytes_precredit_data()
    }
}

impl InstalledCnpConformanceRole {
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_original_initial_lifecycle_source_data(
        &self,
        source: &std::rc::Rc<crate::node_adapters::cnp::PacketCompleteSemanticSource>,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        if !matches!(
            self.0.kind,
            super::SemanticInstallationKind::CollectingCompletePacket
        ) || !std::ptr::eq(
            std::rc::Rc::as_ptr(&self.0.source).cast::<()>(),
            std::rc::Rc::as_ptr(source).cast::<()>(),
        ) || self.0.acceptance.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let authority = self
            .0
            .conformance
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let original_plan = self
            .0
            .collection_plan
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !plan.has_authority(authority.as_ref())
            || !plan.has_same_initial_original_plan_data(original_plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl CnpSemanticRegistry {
    /// Compares the actual retained registration policy allocation as DATA only.
    ///
    /// Equal policy bytes or an equal implementation name provide no identity.
    /// This comparison installs no role and grants no callback permission.
    pub fn is_original_registration_policy_data(
        &self,
        original: &dyn super::CnpSemanticRegistrationPolicy,
    ) -> bool {
        std::ptr::addr_eq(self.policy.as_ref(), original)
    }
}
