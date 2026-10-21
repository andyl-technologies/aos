//! Quotes the actual upper Root adapter representations as inert layout DATA.
//!
//! Cumulative permits, Stage mutations, and original prefix custody belong to
//! the native Initial. This module cannot supply a completed stage.

use super::*;

impl RootReceivingOriginalV1 {
    pub(super) fn role_layout_v1() -> super::super::bank::NativeLayoutDemand {
        super::super::q04_intake::native_layout().with_root_role_adapters((|| {
            let profile = Self::profile_adapter_geometry_v1().ok()?;
            let selected =
                crate::normal_root::RootSelectedStartupReceivingV1::adapter_demand_v1().ok()?;
            let currentness =
                crate::normal_root::RootServiceCurrentnessV1::adapter_demand_v1().ok()?;
            Some([profile, selected, currentness])
        })()).with_root_listener_layout(Some(
            crate::normal_root::RootPolicyListenerReceivingV1::fixed_demand(),
        ))
    }

    fn profile_adapter_geometry_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        // The lower lane pays only its actual native owners. This private
        // role separately pays its retained classification and constructor
        // carriers, with no DATA supplied by an external caller.
        let error_arc = std::mem::size_of::<ResourceReservationErrorV1>()
            .checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|bytes| {
                bytes.checked_add(std::mem::align_of::<ResourceReservationErrorV1>() - 1)
            })
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let adapter_bytes = std::mem::size_of::<Self>().checked_mul(2)
                .and_then(|bytes| bytes.checked_add(
                    crate::normal_root::RootReceivingGuardV1::startup_driver_control_bytes_v1()?,
                ))
                .and_then(|bytes| bytes.checked_add(
                    crate::policy_compiler::RootPolicyStartupJournalV1::selected_adapter_control_bytes_v1()?,
                ))
                // Heap backing and its actual construction carrier coexist
                // on the one failed debit. Later views clone only Arc pointers.
                .and_then(|bytes| bytes.checked_add(error_arc.checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(
                    aos_sandbox_policy::native::RootStartupProvisionOriginalV1::additional_control_bytes_v1()?,
                ))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<crate::normal_root::NormalRootStartupErrorV1>,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
                    usize, usize, std::sync::Mutex<()>,
                )>()))
                .and_then(|bytes| bytes.checked_add(
                    std::mem::size_of::<ResourceVector>().checked_mul(5)?,
                ))
                // Actual Root67 nested construction carriers: OwnershipTrust
                // container and fixed/typed/SourceExchange provisions. Their
                // stored destinations are already in actual Self above.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_ownership_trust::RootCurrentOwnershipTrustProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >().checked_mul(3)?))
                // BundleOwnership's private container/fixed/typed constructor
                // carriers exist before their own later admission can succeed.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_bundle_ownership::RootCurrentBundleOwnershipProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >().checked_mul(2)?))
                // These two actual RootAttempt headers are constructed at new,
                // before BundleOwnership admission. State/child Box allocations
                // remain in their own later fixed/typed suppliers.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::bundle_ownership::
                        RootCurrentBundleOwnershipStateV1,
                >>>()))
                // CacheCurrent adds its own provision constructor and two
                // RootAttempt headers at new, before its later fixed gate.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::cache_current::
                        RootCurrentCacheProofStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<
                    (), aos_sandbox_broker::receiving::RootObservationErrorV1,
                >>()))
                // The readonly stage container and its three provision
                // constructors precede their own later successful gates.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_controller_readonly::RootCurrentControllerReadonlyProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >().checked_mul(3)?))
                // The two headers are initialized with the actual RootAttempt.
                // Its State Box/backing remains a later fixed-stage cost.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::controller_readonly::
                        RootCurrentControllerReadonlyStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
                >()))
                // The new Box header is present from initial attempt creation;
                // its backing and construction are admitted only at UA entry.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::use_authorized::
                        RootCurrentUseAuthorizedStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_provision::RootCurrentProvisionV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::use_reserved::RootCurrentUseReservedStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Result<
                    (), crate::normal_root::NormalRootStartupErrorV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    current_use_reserved::RootCurrentUseReservedProvisionV1,
                >()))
                // Fresh Source query/exchange are distinct inline originals;
                // their native reservoirs remain paid at their own R stages.
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    crate::policy_compiler::create_storage_current::source_current::RootCurrentSourceQueryStateV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                    crate::policy_compiler::create_storage_current::source_current::RootCurrentSourceExchangeStateV1,
                >()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::cache_current::RootCurrentCacheProofStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Result<
                    (), crate::normal_root::NormalRootStartupErrorV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<current_provision::RootCurrentProvisionV1>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<
                    crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Result<
                    (), crate::normal_root::NormalRootStartupErrorV1,
                >>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<current_signed_bound::RootSignedProvisionV1>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Box<crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1>>>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>>()))
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let adapter = ResourceVector::ZERO
            .with(
                aos_sandbox_model::ResourceDimension::MemoryBytes,
                u64::try_from(adapter_bytes)
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?,
            )
            // Four financial fields move to the actual lower original;
            // the historical parent subtotal therefore falls from27 to23.
            // Keep the existing additional parent/nested controls below.
            // Arc/Mutex/startup and financial carriers, eight older nested
            // controls and four older constructors. BundleOwnership adds
            // six nested fixed/typed destination+Result controls and three
            // constructors; its two RootAttempt headers are also upfront.
            // CacheCurrent adds its parent above plus two embedded Results,
            // one constructor and two RootAttempt headers. The independent
            // retained RootChunk clock header from 81b3 remains upfront;
            // its physical bytes are already in listener sizeof(RootAttempt).
            // The armed header moved to the native original. The actual
            // checked handoff Result now owns one explicit cell and sizeof
            // above. ControllerReadonly adds its parent field, three
            // embedded stage destinations and six permit/before Results,
            // four constructor carriers and two early RootAttempt headers:
            // sixteen cells beyond the existing65, for actual upfront81.
            // Native initial's69 cells remain separately paid; later State
            // backing/model/native/semantic stages retain their own gates.
            .with(
                aos_sandbox_model::ResourceDimension::MetadataEntries,
                (27 - 4) + 1 + 3 + 5 + 8 + 4 + 6 + 3 + 2 + 2 + 1 + 2 + 1 + 1 + 9 + 4 + 2,
            );
        let guards = crate::normal_root::RootReceivingGuardV1::construction_demand_v1()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        adapter
            .checked_add(guards)
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
    }
}
