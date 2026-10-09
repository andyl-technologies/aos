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
use crucible_qemu::{OriginalActorAccountCustody, OriginalNativeAccountCredit};

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

    /// Retains FULL native residency and TOTAL metadata in external credit.
    ///
    /// The pair comes only from the same published original banks. The actual
    /// used factory must still bind physical backing, Source and domain custody
    /// before a native role or research launch permission can be constructed.
    /// This issuer retains the bank owner outside that factory allocation.
    ///
    /// # Errors
    /// Refuses the same original before or after reservation, either original
    /// counter, or consumed custody. Account and post-original refusals remain
    /// distinct; an uncertain postcheck retains the actual paired credit.
    pub fn reserve_native_account_credit(
        &self,
    ) -> Result<OriginalNativeAccountCredit, MeasurementRuntimeAdmissionError> {
        let held = self
            .held
            .as_ref()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "retained original actor custody",
            ))?;
        Ok(held.accounts.reserve_native_account_credit()?)
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

#[cfg(test)]
// crucible-lint: allow rust-allow -- this actual paired first-refusal control panics only when structural admission allocates or accepts an insufficient original account.
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
