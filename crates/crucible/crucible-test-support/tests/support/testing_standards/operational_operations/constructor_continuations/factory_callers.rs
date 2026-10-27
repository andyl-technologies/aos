//! Binds factory adapters to their same retained Source and native body.
//!
//! Adapters borrow the actual factory; they create no cleanup guard or receiver.
//! Complete producer companions keep continuation distinct from new admission.

use super::{Companion, Contract, facts};

const COMPANIONS: &[Companion] = &[
    Companion {
        path: "crates/crucible/crucible-daemon/src/qemu_campaign_lifecycle/source_construction/native_observation.rs",
        required: super::native::CONTRACT.required,
    },
    Companion {
        path: "crates/crucible/crucible-daemon/src/qemu_campaign_lifecycle/source_construction/retained.rs",
        required: super::retained::CONTRACT.required,
    },
    facts::MAIN_RETIREMENT,
    facts::RESERVATION,
    facts::QUEUE,
    facts::BODY_DRIVER,
    facts::REPORT_PINS,
    facts::RECEIPT,
    facts::PUBLICATION_FACT,
];

const RETAINED_EFFECT: &[(&str, usize)] = &[(
    "fn try_retire_original( &mut self, _original: &crucible_host_resources::host_supervision::HostOperationGuard, ) -> Result<(), Self::Error> { self.retry_retained_source_installation() }",
    1,
)];
const RETAINED_NAMES: &[(&str, usize)] = &[("retry_retained_source_installation", 1)];

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-daemon",
        target: "src/packaged_qemu_executor/native_plugin_flight/admission",
        required: &[
            (
                "struct MainFlightAdmission<'a> { factory: &'a mut dyn MainFlightSource,",
                1,
            ),
            (
                "struct FlightOwner<'a> { factory: &'a mut dyn MainFlightSource,",
                1,
            ),
            ("self.factory.begin(self.context, self.source)?;", 1),
            (
                "Ok(FlightOwner { factory: self.factory, context: self.context, node: &node.id, catalog: self.catalog, generation: None, })",
                1,
            ),
            (
                "pub(crate) fn finish(&mut self) -> Result<(), QemuAttemptProductionVmLifecycleError> { self.factory.finish_body() }",
                1,
            ),
            ("self.begin_native_observation_default(context, source)", 1),
            ("self.with_native_observation(apply)", 1),
            ("HostOperationSupervisor::new(", 0),
        ],
        expressions: &[("self.retry_native_observation_body()", 1)],
        identifiers: &[("retry_native_observation_body", 1)],
        companions: COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/qemu_campaign_lifecycle",
        required: &[
            (
                "fn retire_lifecycle(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Error> { self.retain_returned_lifecycle(lifecycle) }",
                1,
            ),
            (
                "fn try_retire_original( &mut self, _original: &crucible_host_resources::host_supervision::HostOperationGuard, ) -> Result<(), Self::Error>",
                2,
            ),
        ],
        expressions: RETAINED_EFFECT,
        identifiers: RETAINED_NAMES,
        companions: COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/qemu_campaign_resume",
        required: &[
            (
                "fn retire_lifecycle(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Error> { self.retain_returned_lifecycle(lifecycle) }",
                1,
            ),
            (
                "fn try_retire_original( &mut self, _original: &crucible_host_resources::host_supervision::HostOperationGuard, ) -> Result<(), Self::Error>",
                2,
            ),
            (
                "QemuProductionExactResumeLifecycleFactory::try_retire_original(self.inner_mut(), original) .map_err(QemuObservedFreshAttemptLifecycleFactoryError::Inner)",
                1,
            ),
            (
                "self.lifecycles .try_retire_original(original) .map_err(|first| ResumeFailure::Lifecycle(first).into())",
                1,
            ),
        ],
        expressions: RETAINED_EFFECT,
        identifiers: RETAINED_NAMES,
        companions: COMPANIONS,
    },
];
