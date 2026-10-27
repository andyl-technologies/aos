//! Borrows the two existing Controller lenders for Cache construction.
//!
//! Both variants retain a real scoped lower loan. This module creates no
//! account, receipt, provision, Controller original or reusable paid permit.
//! The five native owners and four model/physical highwaters remain distinct;
//! the prebank import can enter only its established two destinations.

use aos_sandbox_broker::controller_receiving::{
    ControllerCachePreBankImportLoanV1,
    bank_launch::{ControllerBankLaunchErrorV1, ControllerCacheConstructionLoanV1},
};
use aos_sandbox_model::ResourceVector;

use crate::protected_owner::initialization::baseline::CacheConstructionOriginalsV1;

/// Names a fixed existing representation owner, without supplying a budget.
#[derive(Clone, Copy)]
pub(crate) enum ConstructionOwnerV1 {
    BootstrapNative,
    HoldNative,
    ClockNative,
    AuthorityNative,
    StateNative,
    ImportModels,
    BootstrapModels,
    AuthorityModels,
    Physical,
}

// Constructors elsewhere in this crate borrow only these genuine original
// intervals. An upper caller cannot implement a payer or install paid DATA.
pub(crate) enum ConstructionLoanV1<'borrow, 'writer, 'launch, 'profile, P> {
    Confirmed {
        originals: &'borrow CacheConstructionOriginalsV1,
        loan: &'borrow mut ControllerCacheConstructionLoanV1<'writer, 'launch, 'profile, P>,
        semantic_supplement: Option<ResourceVector>,
        upper_forwarding_bytes: usize,
    },
    Import {
        originals: &'borrow CacheConstructionOriginalsV1,
        loan: &'borrow mut ControllerCachePreBankImportLoanV1<'profile>,
        semantic_supplement: Option<ResourceVector>,
        upper_forwarding_bytes: usize,
    },
}

impl<P> ConstructionLoanV1<'_, '_, '_, '_, P> {
    // These forwarding frames coexist with the original receiving caller.
    // The existing lender dispatch, paid lock and OnceLock operation retain
    // their old pricing; no resident owner padding substitutes for new frames.
    pub(crate) fn forwarding_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;

        use crate::protected_owner::initialization::{
            InitializationCauseV1,
            baseline::CacheConstructionOwnerV1,
        };

        let bank_result = size_of::<Result<(), ControllerBankLaunchErrorV1>>();
        let mut bytes = size_of::<(&mut Self, ConstructionOwnerV1, ResourceVector)>()
            .checked_mul(2)?;
        // require_complete's constructor, ABI and caller Result are distinct
        // from its closure Result and the new mirror helper's returned Result.
        bytes = bytes.checked_add(bank_result.checked_mul(9)?)?;
        bytes = bytes.checked_add(size_of::<(
            &mut Self,
            &ConstructionOwnerV1,
            &ResourceVector,
            &&CacheConstructionOriginalsV1,
        )>().checked_mul(2)?)?;
        bytes = bytes.checked_add(size_of::<&CacheConstructionOriginalsV1>())?;

        // The mirror helper receives its own argument tuple and selects the
        // same fixed slot; the original lock/debit chronology is unchanged.
        bytes = bytes.checked_add(size_of::<(
            &CacheConstructionOriginalsV1,
            ConstructionOwnerV1,
            ResourceVector,
        )>().checked_mul(2)?)?;
        bytes = bytes.checked_add(size_of::<CacheConstructionOwnerV1>())?;

        // The refusal helper owns the cause through its receiver/argument
        // crossing and reconstructs Err(cause) for the same original cell.
        bytes = bytes.checked_add(size_of::<(
            &CacheConstructionOriginalsV1,
            ControllerBankLaunchErrorV1,
        )>().checked_mul(2)?)?;
        bytes = bytes.checked_add(size_of::<ControllerBankLaunchErrorV1>())?;
        bytes = bytes.checked_add(bank_result.checked_mul(2)?)?;

        // The receiving adapter's owner conversion and immediate error map
        // remain separate from the lower owning Bank Result above.
        bytes = bytes.checked_add(size_of::<(
            CacheConstructionOwnerV1,
            ConstructionOwnerV1,
        )>().checked_mul(2)?)?;
        bytes = bytes.checked_add(size_of::<Result<(), InitializationCauseV1>>()
            .checked_mul(2)?)?;
        // This finite quote's scalar locals and Option return controls are
        // also explicit. It allocates nothing and supplies no paid original.
        bytes.checked_add(size_of::<([usize; 3], [Option<usize>; 3])>())
    }

    // The shared upper control plane overlaps all five writers. It belongs
    // once to the existing Bootstrap native highwater, including import's two
    // phases; no other account or scalar receipt is created.
    pub(crate) fn upper_forwarding_bytes_v1(&self, owner: ConstructionOwnerV1) -> usize {
        if !matches!(owner, ConstructionOwnerV1::BootstrapNative) { return 0; }
        match self {
            Self::Confirmed { upper_forwarding_bytes, .. }
            | Self::Import { upper_forwarding_bytes, .. } => *upper_forwarding_bytes,
        }
    }

    pub(crate) fn semantic_supplement_data_v1(&self) -> Option<ResourceVector> {
        match self {
            Self::Confirmed { semantic_supplement, .. }
            | Self::Import { semantic_supplement, .. } => *semantic_supplement,
        }
    }

    pub(crate) fn require_complete_v1(
        &mut self,
        owner: ConstructionOwnerV1,
        complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let originals = match self {
            Self::Confirmed { originals, .. } | Self::Import { originals, .. } => *originals,
        };
        if originals.failure().is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let returned = (|| {
            match self {
                Self::Confirmed { loan, .. } => match owner {
                    ConstructionOwnerV1::BootstrapNative => {
                        loan.require_bootstrap_native_complete(complete)
                    }
                    ConstructionOwnerV1::HoldNative => loan.require_hold_native_complete(complete),
                    ConstructionOwnerV1::ClockNative => loan.require_clock_native_complete(complete),
                    ConstructionOwnerV1::AuthorityNative => {
                        loan.require_authority_native_complete(complete)
                    }
                    ConstructionOwnerV1::StateNative => loan.require_state_native_complete(complete),
                    ConstructionOwnerV1::ImportModels => loan.require_import_models_complete(complete),
                    ConstructionOwnerV1::BootstrapModels => {
                        loan.require_source_models_complete(complete)
                    }
                    ConstructionOwnerV1::AuthorityModels => {
                        loan.require_authority_models_complete(complete)
                    }
                    ConstructionOwnerV1::Physical => loan.require_physical_complete(complete),
                },
                Self::Import { loan, .. } => match owner {
                    ConstructionOwnerV1::BootstrapNative => loan
                        .require_bootstrap_native_complete(complete)
                        .map_err(ControllerBankLaunchErrorV1::from),
                    ConstructionOwnerV1::ImportModels => loan
                        .require_import_models_complete(complete)
                        .map_err(ControllerBankLaunchErrorV1::from),
                    _ => Err(ControllerBankLaunchErrorV1::Conflict),
                },
            }?;
            // Preserve the actual debit-before-mirror-before-effect order.
            // A paid mirror can compare only this same interval's real debit.
            originals.record_paid_native_v1(owner, complete)
        })();
        match returned {
            Ok(()) => Ok(()),
            Err(cause) => {
                originals.retain_receiving_failure_v1(cause);
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }
}
