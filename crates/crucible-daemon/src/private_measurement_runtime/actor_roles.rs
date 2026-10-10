//! Publishes the actor's paired accounts from one authenticated parent carrier.
//!
//! The parent retains the whole physical actor payment before execution. This
//! issuer moves the same guest origin into its original supervisor, charges
//! local structural allocations once, and keeps those accounts outside their
//! funded controls. Metadata is a subset of physical residency. No independent
//! account, replacement clock, numeric ceiling or image description issues it.

use std::sync::Arc;

use crucible_linux_resource::host_supervision::{HostOperationGuard, HostOperationSupervisor};
use crucible_linux_resource::measurement_origin::AuthenticatedParentInvocation;
use crucible_qemu::{
    OriginalActorAccountCustody, OriginalNativeAccountFactoryBinding, OriginalNativeAccountRoster,
};

use super::MeasurementRuntimeAdmissionError;
use crate::private_original_capture::OriginalPreparation;

/// Keeps the one authenticated actor publisher and its original accounts.
///
/// The consuming constructor accepts only the closed parent carrier. Its paired
/// accounts retain their permanent initial structural charge through every
/// original guard, watcher and supervisor allocation. Native assignments need
/// their own finite stage admission within these accounts and their TOTAL
/// metadata subset; this publisher alone cannot authorize a native process.
///
/// Dropping an unsettled publisher retains the same accounts and guards. A
/// genuine consuming factory retirement path must discharge all independent
/// child, source, controller and quarantine lifetimes before releasing them.
#[must_use = "retain original actor custody through genuine physical retirement"]
pub struct OriginalActorRoleIssuer {
    held: Option<PublishedActor>,
}

struct PublishedActor {
    preparation: Arc<HostOperationGuard>,
    supervisor: HostOperationSupervisor,
    accounts: OriginalActorAccountCustody,
}

impl OriginalActorRoleIssuer {
    pub(super) fn prepare_workflow_decode_owner(
        &self,
    ) -> Result<crucible_qemu::OriginalActorDecodeOwner, MeasurementRuntimeAdmissionError> {
        self.require_original()?;
        let held = self
            .held
            .as_ref()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original actor custody",
            ))?;
        Ok(held.accounts.prepare_decode_owner()?)
    }

    pub(super) fn admit_workflow_service(
        &self,
        decoder: &crucible_qemu::OriginalActorDecodeOwner,
        bytes: &[u8],
    ) -> Result<crucible_qemu::OriginalActorServicePolicy, MeasurementRuntimeAdmissionError> {
        let held = self
            .held
            .as_ref()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original actor custody",
            ))?;
        Ok(held.accounts.admit_workflow_service(decoder, bytes)?)
    }

    pub(super) fn prepare_catalog_owner(
        &self,
        decoder: &crucible_qemu::OriginalActorDecodeOwner,
    ) -> Result<
        crate::private_measurement_runtime::catalog::OriginalActorCatalogOwner,
        MeasurementRuntimeAdmissionError,
    > {
        let held = self
            .held
            .as_ref()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original actor custody",
            ))?;
        Ok(super::catalog::OriginalActorCatalogOwner::prepare(
            &held.accounts,
            decoder,
        )?)
    }

    pub(super) fn prepare_workflow_sqlite(
        &self,
        policy: crucible_qemu::OriginalActorServicePolicy,
    ) -> Result<super::sqlite::OriginalActorSqliteOwner, MeasurementRuntimeAdmissionError> {
        let held = self
            .held
            .as_ref()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original actor custody",
            ))?;
        Ok(super::sqlite::OriginalActorSqliteOwner::prepare(
            &held.accounts,
            policy,
        )?)
    }

    /// Consumes the same authenticated parent invocation before publication.
    ///
    /// The immutable certified partition supplies the aggregate account values
    /// and the original Preparation class policy. Per-process NOFILE is not an
    /// aggregate descriptor counter. Complete preloader, loader, stack and
    /// physical enforcement coverage belongs to the parent constructor; parsed
    /// image facts and positive scalar floors cannot call this constructor.
    ///
    /// # Errors
    /// Refuses mismatched or expired original parent binding, either original
    /// structural account, target layout overflow, or original supervision
    /// before or after publication. No refusal starts a replacement interval.
    pub fn admit_parent(
        invocation: AuthenticatedParentInvocation,
    ) -> Result<Self, MeasurementRuntimeAdmissionError> {
        let (accounts, preparation, supervisor) =
            OriginalActorAccountCustody::publish_parent(invocation)?;
        let issuer = Self {
            held: Some(PublishedActor {
                preparation,
                supervisor,
                accounts,
            }),
        };

        // The lower publication already retained the complete record before
        // its original postcheck. Moving those same owners adds no new effect.
        Ok(issuer)
    }

    /// Returns the target's once-charged initial publication extent.
    ///
    /// This includes the expanded original supervisor, paired account controls
    /// and the one shared returned guard. It excludes the stack-held issuer,
    /// native state, factory, Source pool, watcher and quarantine purposes.
    ///
    /// # Errors
    /// Refuses layout, target width or byte-count overflow.
    pub fn initial_structure_bytes() -> Result<u64, MeasurementRuntimeAdmissionError> {
        Ok(OriginalActorAccountCustody::initial_structure_bytes()?)
    }

    /// Checks the same retained original operation without renewing its clock.
    ///
    /// # Errors
    /// Preserves the original's cancellation, terminal state, class deadline,
    /// private absolute end and unavailable supervision refusal.
    pub fn require_original(&self) -> Result<(), MeasurementRuntimeAdmissionError> {
        let held = self
            .held
            .as_ref()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original actor custody",
            ))?;
        held.accounts.require_original()?;
        Ok(())
    }

    /// Prepares the fixed external account roster for the genuine factory.
    ///
    /// The parent-selected width and same original banks determine every slot.
    /// The returned external owner must outlive the actual factory and every
    /// native control alias; its weak binding cannot issue a launch permission.
    ///
    /// # Errors
    /// Refuses consumed publication, either original account, or the original
    /// interval before or after admitting the actual native pairs.
    pub fn prepare_native_account_roster(
        &mut self,
    ) -> Result<
        (
            OriginalNativeAccountRoster,
            OriginalNativeAccountFactoryBinding,
        ),
        MeasurementRuntimeAdmissionError,
    > {
        let held = self
            .held
            .as_mut()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original actor custody",
            ))?;
        Ok(held.accounts.prepare_native_account_roster()?)
    }

    /// Prepares the genuine service's packaged factory under this same actor.
    ///
    /// The returned owner borrows this external issuer and retains the native
    /// roster outside the factory allocation. Preparation uses the service's
    /// original repository, checkpoint backend and existing source lifecycle;
    /// no second Linux factory, service account or capture route is constructed.
    ///
    /// # Errors
    /// Refuses original custody, native pair admission or genuine packaged
    /// preparation. Failed preparation retains its external roster and banks.
    /// The supplied service and config still require authenticated physical
    /// storage, Source and prebirth purposes; account custody is not a grant.
    pub fn prepare_genuine_packaged_executor<'actor>(
        &'actor mut self,
        service: &crate::PreparedCampaignLocalService,
        config: crate::PackagedQemuExecutorConfig,
    ) -> Result<OriginalPreparedPackagedExecutor<'actor>, OriginalPackagedPreparationError> {
        let original = self.retain_preparation()?;
        let (roster, binding) = self.prepare_native_account_roster()?;
        let executor = service.prepare_original_packaged_executor(config, original, binding)?;
        let owner = OriginalPreparedPackagedExecutor {
            _actor: self,
            roster: Some(roster),
            executor: Some(executor),
        };
        if let Err(source) = owner._actor.require_original() {
            // Publish physical and external custody together before the
            // fallible original postcut, including an already-open factory.
            std::mem::forget(owner);
            return Err(source.into());
        }

        Ok(owner)
    }

    /// Retains the same admitted guard for the genuine packaged capture route.
    ///
    /// This clones only existing aliases. It creates no guard, account, clock
    /// or shared allocation. The issuer remains external to those aliases and
    /// their enclosing concrete factory allocation throughout retirement.
    ///
    /// # Errors
    /// Preserves the same original refusal before and after alias acquisition.
    pub fn retain_preparation(
        &self,
    ) -> Result<OriginalPreparation, MeasurementRuntimeAdmissionError> {
        self.require_original()?;
        let held = self
            .held
            .as_ref()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original actor custody",
            ))?;
        let original = OriginalPreparation::retain_admitted(
            Arc::clone(&held.preparation),
            held.supervisor.clone(),
        );
        self.require_original()?;
        Ok(original)
    }
}

impl Drop for OriginalActorRoleIssuer {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            // Facade return, body drop and an Arc count do not prove physical
            // retirement. Keep the exact original custody on error or unwind;
            // the enclosing ParentVM still owns its external whole payment.
            std::mem::forget(held);
        }
    }
}

/// Preserves external account and roster custody around the genuine executor.
///
/// This owner provides no extracting getter. Dropping it retains the concrete
/// executor and roster because facade destruction cannot certify Source,
/// child, namespace, controller or shared-allocation retirement. The enclosing
/// original actor remains borrowed throughout this owner's lifetime.
#[must_use = "retain the real factory and external credits through physical retirement"]
pub struct OriginalPreparedPackagedExecutor<'actor> {
    _actor: &'actor mut OriginalActorRoleIssuer,
    roster: Option<OriginalNativeAccountRoster>,
    executor: Option<crate::PackagedQemuExecutor>,
}

/// Preserves original account or genuine service preparation refusal.
#[derive(Debug, thiserror::Error)]
pub enum OriginalPackagedPreparationError {
    /// The same actor's retained original accounts or interval refused.
    #[error("original packaged account preparation refused: {0}")]
    Actor(#[from] MeasurementRuntimeAdmissionError),
    /// The genuine repository, capture or factory preparation refused.
    #[error("original packaged service preparation refused: {0}")]
    Service(#[from] crate::CampaignLocalServiceError),
}

impl Drop for OriginalPreparedPackagedExecutor<'_> {
    fn drop(&mut self) {
        if let Some(executor) = self.executor.take() {
            std::mem::forget(executor);
        }
        if let Some(roster) = self.roster.take() {
            std::mem::forget(roster);
        }
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- this actual paired first-refusal control panics only when structural admission allocates or accepts an insufficient original account.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_services::{HostServiceBootstrap, HostServiceError};
    use crucible_linux_resource::test_support::TestAllocationObserver;

    #[test]
    fn either_original_structural_refusal_precedes_every_shared_control() {
        let required = OriginalActorRoleIssuer::initial_structure_bytes().unwrap();
        for (resident, metadata) in [(required - 1, required), (required, required - 1)] {
            let original = HostServiceBootstrap::new(4096, 65_536, resident, metadata).unwrap();

            let (result, counts) =
                TestAllocationObserver::count(|| original.reserve_structure(required));

            assert!(matches!(result, Err(HostServiceError::CapacityExhausted)));
            assert_eq!(counts.allocations, 0);
            assert_eq!(counts.reallocations, 0);
            assert!(!counts.overflow);
        }
        // This is an actual original-stack/allocator cut. It does not create
        // parent evidence, a live actor, or a paid Source/loader certificate.
        eprintln!(
            "actor_issuer_inline={} initial_published_structure={required}",
            std::mem::size_of::<OriginalActorRoleIssuer>()
        );
    }
}
