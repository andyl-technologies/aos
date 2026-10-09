//! Owns the private daemon actor admission before its genuine packaged factory.
//!
//! Target-derived structural geometry is available now. Complete Source,
//! loader, descriptor overlap, stack and factory-purpose certificates are not;
//! the used actor therefore refuses before publishing any account or factory.
//! A policy ceiling or a mechanism test can never fill those missing facts.

use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceBootstrap, HostServiceError,
};
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationGuard, HostOperationSupervisor, HostSupervisionBootstrap,
    HostSupervisionError,
};
use crucible_linux_resource::measurement_origin::{
    MeasurementInvocationOrigin, MeasurementOriginError,
};

/// First refusal while deriving the closed original actor from its actual issuer.
#[derive(Debug, thiserror::Error)]
pub enum MeasurementRuntimeAdmissionError {
    /// The actual issuer or same original absolute interval refused admission.
    #[error("original actor issuance refused: {0}")]
    Origin(#[from] MeasurementOriginError),
    /// A required compiled complete-purpose certificate is absent.
    #[error("original actor lacks compiled complete purpose at {0}")]
    MissingPurpose(&'static str),
    /// An absent purpose remains primary when the same original interval ends.
    #[error("original actor lacks {purpose}; post-original refusal: {after}")]
    MissingPurposeBoundary {
        /// Exact first omitted compiled purpose.
        purpose: &'static str,
        /// Same retained interval's separate postcheck refusal.
        after: MeasurementOriginError,
    },
    /// The same stack original paired accounts refused structural admission.
    #[error("original actor structural admission refused: {0}")]
    Account(#[from] HostServiceError),
    /// The same original supervisor or preparation refused publication.
    #[error("original actor supervision refused: {0}")]
    Supervision(#[from] HostSupervisionError),
}

// These closed facts must come from the compiled trusted purpose table, never
// an actor argument, a numeric nonzero role, or another fixture's original bank.
#[derive(Debug)]
struct CompletePurposeTable {
    source_and_loader: Option<u64>,
    initial_descriptor_peak: Option<u64>,
    whole_stack_and_controls: Option<u64>,
    factory_and_cleanup: Option<u64>,
}

impl CompletePurposeTable {
    fn compiled() -> Self {
        Self {
            source_and_loader: None,
            initial_descriptor_peak: None,
            whole_stack_and_controls: None,
            factory_and_cleanup: None,
        }
    }

    fn require_complete(&self) -> Result<(), &'static str> {
        for (name, bound) in [
            ("Source/preloader/loader", self.source_and_loader),
            (
                "descriptor initial/transient peak",
                self.initial_descriptor_peak,
            ),
            (
                "whole stack/control first refusal",
                self.whole_stack_and_controls,
            ),
            ("genuine factory/physical cleanup", self.factory_and_cleanup),
        ] {
            if bound.is_none_or(|bytes| bytes == 0) {
                return Err(name);
            }
        }
        Ok(())
    }
}

struct OriginalRuntime {
    // External original accounts outlive the charged supervisor allocations;
    // placing their last aliases inside OuterAuthority would refund too early.
    preparation: std::sync::Arc<HostOperationGuard>,
    _supervisor: HostOperationSupervisor,
    _resident: HostServiceAllocator,
    _metadata: HostServiceAllocator,
}

impl OriginalRuntime {
    fn admit(
        origin: MeasurementInvocationOrigin,
    ) -> Result<Self, MeasurementRuntimeAdmissionError> {
        origin.remaining()?;
        let roles = origin.actor_account_ceilings()?;
        let table = CompletePurposeTable::compiled();
        if let Err(purpose) = table.require_complete() {
            return Err(match origin.remaining() {
                Ok(_) => MeasurementRuntimeAdmissionError::MissingPurpose(purpose),
                Err(after) => {
                    MeasurementRuntimeAdmissionError::MissingPurposeBoundary { purpose, after }
                }
            });
        }

        // This path is unreachable until a reviewed compiled table covers ALL
        // purposes. Authenticated ceilings never certify that completeness.
        let accounts = HostServiceBootstrap::new(
            roles.tasks(),
            roles.descriptors(),
            roles.resident_bytes(),
            roles.metadata_bytes(),
        )?;
        // The library's existing finite class policy remains unchanged. A
        // prospective measurement class policy needs its own reviewed binding.
        let budgets = HostOperationBudgets::default();
        let original = HostSupervisionBootstrap::from_measurement_origin(origin, budgets)?;
        // The same returned guard's Arc is included before publication, never
        // speculatively allocated to discover its width. Permanent structural
        // credit stays in the external accounts through the final Arc free.
        let (guard_arc, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<HostOperationGuard>())
        .map_err(|_| HostServiceError::CapacityExhausted)?;
        let guard_arc_bytes = u64::try_from(guard_arc.pad_to_align().size())
            .map_err(|_| HostServiceError::CapacityExhausted)?;
        let structural = HostSupervisionBootstrap::structure_bytes()?
            .checked_add(HostServiceBootstrap::control_bytes()?)
            .and_then(|bytes| bytes.checked_add(guard_arc_bytes))
            .ok_or(HostServiceError::CapacityExhausted)?;
        let admitted = accounts.reserve_structure(structural)?;
        let (supervisor, preparation) = original.publish(&admitted)?;
        let (resident, metadata) = admitted.publish();
        let runtime = Self {
            preparation: std::sync::Arc::new(preparation),
            _supervisor: supervisor,
            _resident: resident,
            _metadata: metadata,
        };
        // On refusal this record drops guards/root BEFORE its original banks.
        // Separately checking loose locals would drop the newer banks first.
        runtime.preparation.wait_slice()?;
        Ok(runtime)
    }
}

/// Runs the one private actor's actual authenticated original admission path.
///
/// This entry does not install Linux enforcement or create a native process.
/// Until complete compiled purpose facts exist it refuses before publication;
/// no actor argument can override that refusal or supply another account.
///
/// # Errors
/// Refuses issuer authentication, original expiry, missing complete purpose,
/// structural account admission or original preparation publication.
pub fn run_original_actor() -> Result<(), MeasurementRuntimeAdmissionError> {
    let origin = MeasurementInvocationOrigin::receive_original()?;
    let runtime = OriginalRuntime::admit(origin)?;
    runtime.preparation.wait_slice()?;
    let _original = crate::private_original_capture::OriginalPreparation::retain_admitted(
        std::sync::Arc::clone(&runtime.preparation),
        runtime._supervisor.clone(),
    );
    // The genuine used route is PreparedCampaignLocalService's private
    // original prepare method. A compiled immutable workflow/source loader is
    // still required; no actor argument may substitute a service or config.
    // This daemon entry shares the genuine packaged factory's crate. Its next
    // used slice must retain that existing factory and SourcePool; the compiled
    // table still refuses before either can be published or cause effects.
    Err(MeasurementRuntimeAdmissionError::MissingPurpose(
        "used genuine pool/domain integration",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_missing_compiled_purpose_refuses_without_numeric_role_substitution() {
        let table = CompletePurposeTable::compiled();
        assert_eq!(table.require_complete(), Err("Source/preloader/loader"));
        // Each row validator is exercised separately as an omission control,
        // not as a complete Source/loader certificate or eligible issuer.
        for missing in 0..4 {
            let mut table = CompletePurposeTable {
                source_and_loader: Some(1),
                initial_descriptor_peak: Some(1),
                whole_stack_and_controls: Some(1),
                factory_and_cleanup: Some(1),
            };
            let fields = [
                &mut table.source_and_loader,
                &mut table.initial_descriptor_peak,
                &mut table.whole_stack_and_controls,
                &mut table.factory_and_cleanup,
            ];
            *fields.into_iter().nth(missing).unwrap() = None;
            assert!(table.require_complete().is_err());
        }
    }

    #[test]
    fn actual_paired_structure_refuses_either_insufficient_original_counter() {
        let structural = HostSupervisionBootstrap::structure_bytes().unwrap()
            + HostServiceBootstrap::control_bytes().unwrap();
        for (resident, metadata) in [(structural - 1, structural), (structural, structural - 1)] {
            let account = HostServiceBootstrap::new(1, 1, resident, metadata).unwrap();
            assert!(matches!(
                account.reserve_structure(structural),
                Err(HostServiceError::CapacityExhausted)
            ));
        }
        let accounts = HostServiceBootstrap::new(1, 1, structural, structural)
            .unwrap()
            .reserve_structure(structural)
            .unwrap();
        assert_eq!(accounts.structural_bytes(), structural);
        // This is actual paired structural admission only, never birth proof.
    }
}
