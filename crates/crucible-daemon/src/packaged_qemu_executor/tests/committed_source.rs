//! Real packaged decorators around an already constructed production owner.
//!
//! Only the launch provider is scripted; the original status and evidence
//! factories construct the same wrapper chain used by the packaged executor.

use super::*;
use crucible_api::ProductionVmLifecycleLoop;

struct SuppliedLifecycleFactory(Option<ProductionVmLifecycleLoop>);

impl QemuFreshAttemptLifecycleFactory for SuppliedLifecycleFactory {
    type Lifecycle = ProductionVmLifecycleLoop;
    type Error = SchedulerError;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        _start: &Configuration,
        _replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.0.take().ok_or_else(|| {
            AttemptWorkerFailure::Terminal(SchedulerError::BoundaryViolation {
                message: String::from("scripted production owner was already consumed"),
            })
        })
    }
}

/// Installs the original packaged status and evidence decorators.
///
/// # Errors
///
/// Returns the original factory failure if the supplied owner cannot be admitted.
pub(crate) fn wrap_packaged_owner(
    owner: ProductionVmLifecycleLoop,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<impl QemuFreshAttemptLifecycleOwner + use<>, Box<dyn std::error::Error>> {
    wrap_packaged_owner_with_evidence(owner, source, context).map(|(owner, _evidence)| owner)
}

/// Installs the packaged decorators and retains their original evidence owner.
///
/// # Errors
///
/// Returns the original factory failure when the supplied owner is refused.
pub(crate) fn wrap_packaged_owner_with_evidence(
    owner: ProductionVmLifecycleLoop,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
) -> Result<
    (
        impl QemuFreshAttemptLifecycleOwner + use<>,
        QemuAttemptExecutionEvidence,
    ),
    Box<dyn std::error::Error>,
> {
    let factory = PackagedStatusLifecycleFactory {
        inner: SuppliedLifecycleFactory(Some(owner)),
        lifecycles: PackagedWorldLifecycleTracker::new(),
    };
    let (mut factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let scenario = source.scenario_def();
    let start = Configuration::genesis(scenario.clone());
    factory
        .start_fresh_lifecycle(
            &scenario,
            source,
            &start,
            &crucible::SignalFaultCampaignReplayPlan::empty(start.clone()),
            context,
        )
        .map(|owner| (owner, evidence))
        .map_err(|error| format!("packaged decorator factory failed: {error:?}").into())
}
