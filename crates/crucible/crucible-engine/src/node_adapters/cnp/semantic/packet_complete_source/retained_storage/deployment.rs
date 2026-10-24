//! Joins complete initial Source components to their original deployment read.
//!
//! The initial-lifecycle visitor counts every actual present component and
//! refuses unresolved native reads. This wrapper retains the distinct process
//! reservation obligation; it does not turn an observed byte count into funding,
//! SDK completion, an opaque recipe or native permission.

use super::*;
use crate::node_adapters::cnp::source_birth_derivation::{
    deployment::SourceDeploymentStorageRead, installation::VerifiedSourceBirthMechanism,
};
use crate::node_contract::RuntimeError;
use crucible_host_resources::{
    DeploymentResourceLease, DeploymentResourceReadContext, LinuxProcessSupervisorError,
};
use std::mem::{size_of, size_of_val};

impl PacketCompleteSemanticSource {
    /// Observes actual initial Source components under the same deployment.
    ///
    /// The caller retains the whole-holder reservation across this read and
    /// independently counts every other owner. Existing and failed Source
    /// fields remain in place. Both underlying native reads must be complete;
    /// an unresolved worker or callback cannot be discounted as absent.
    ///
    /// # Errors
    /// Refuses foreign creation or deployment custody, missing or revoked
    /// containment, busy or unsupported components, unresolved native reads,
    /// arithmetic overflow or the supplied component restriction.
    pub fn original_initial_lifecycle_deployment_storage_data<'a>(
        self: &'a Rc<Self>,
        context: &DeploymentResourceReadContext<'_>,
        maximum: usize,
    ) -> Result<SourceDeploymentStorageRead<'a>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let lease = self
            .native_import18_derivation_mechanism
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .deployment_lease()?;
        lease
            .authenticate_in(context)
            .map_err(|_| RuntimeError::ForeignAuthority)?;

        let observed = self
            .original_complete_holder_storage_data_with_error::<RuntimeError>(maximum)
            .and_then(|holders| {
                self.original_initial_lifecycle_storage_with_holders_data(holders, maximum)
            });

        // A refused component walk still closes both original custody checks.
        // Preserve the component error ahead of any terminal refusal.
        let deployment = lease
            .authenticate_in(context)
            .map_err(|_| RuntimeError::ForeignAuthority);
        let origin = self.storage_origin_with_error::<RuntimeError>();
        let known = observed?;
        deployment?;
        origin?;
        Ok(SourceDeploymentStorageRead::from_original(known, lease))
    }

    /// Quotes the component visitor and its additional deployment-read controls.
    ///
    /// Original process-runtime enforcement remains a separate conjunction.
    /// These fixed headers do not price or replace that operational envelope.
    pub fn initial_lifecycle_deployment_counter_scratch_data() -> usize {
        let controls = [
            size_of::<&Rc<Self>>() * 2,
            size_of::<&usize>(),
            size_of::<&DeploymentResourceReadContext<'static>>(),
            size_of::<Option<&Rc<VerifiedSourceBirthMechanism>>>(),
            size_of::<&Rc<VerifiedSourceBirthMechanism>>(),
            size_of::<Result<&Rc<VerifiedSourceBirthMechanism>, RuntimeError>>(),
            size_of::<&DeploymentResourceLease>() * 2,
            size_of::<Result<&DeploymentResourceLease, RuntimeError>>(),
            size_of::<SourceDeploymentStorageRead<'static>>() * 2,
            size_of::<Result<SourceDeploymentStorageRead<'static>, RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>() * 3,
            size_of::<Result<(), LinuxProcessSupervisorError>>() * 2,
            size_of::<Result<(), RuntimeError>>() * 5,
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<std::iter::Copied<std::slice::Iter<'static, usize>>>(),
            size_of::<usize>() * 5,
        ];
        Self::retained_requested_storage_precredit_scratch_data()
            .saturating_add(Self::isolated_derivation_counter_scratch_data())
            .saturating_add(Self::native_import18_private_birth_counter_scratch_data())
            .saturating_add(controls.iter().copied().fold(0usize, usize::saturating_add))
            .saturating_add(size_of_val(&controls))
            .saturating_add(size_of_val(&controls.into_iter()))
    }
}
