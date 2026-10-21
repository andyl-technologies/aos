//! Holds one of Cache's five captured construction stages under its real loan.
//!
//! Fixed geometry precedes acquisition. Actual captured-prefix geometry
//! precedes replay, and the private semantic adapter debits the same interval
//! before decoded model growth. Once native entry is funded, the name post runs
//! independently of the primary result and no failed native writer is moved.

use std::error::Error;
use std::path::Path;

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1;
use aos_sandbox_model::{AccountingError, ResourceVector};
use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1;

use super::construction::{ConstructionLoanV1, ConstructionOwnerV1};
use super::opening::CacheWriterOpeningV1;
use super::{CacheWriterCurrentnessOriginalV1, Journal, JournalError, RecoveryReport};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CacheConstructionStageErrorV1 {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Receiving(#[from] ControllerBankLaunchErrorV1),
    #[error(transparent)]
    Journal(#[from] JournalError),
}

pub(crate) struct CacheNativeStageV1 {
    opening: CacheWriterOpeningV1,
    preparation: Option<Result<ResourceVector, CacheConstructionStageErrorV1>>,
    prefix: Option<Result<ResourceVector, CacheConstructionStageErrorV1>>,
    names: Option<Result<(), JournalError>>,
    names_original: CacheWriterCurrentnessOriginalV1,
}

impl CacheNativeStageV1 {
    pub(crate) const fn new() -> Self {
        Self {
            opening: CacheWriterOpeningV1::new(),
            preparation: None,
            prefix: None,
            names: None,
            names_original: CacheWriterCurrentnessOriginalV1::new(),
        }
    }

    pub(crate) fn open_once<P>(
        &mut self,
        loan: &mut ConstructionLoanV1<'_, '_, '_, '_, P>,
        role: CacheJournalRecipeRoleV1,
        uid: u32,
        allow_create: bool,
    ) -> Result<(Journal, RecoveryReport), ()> {
        if self.preparation.is_some() {
            return Err(());
        }
        let root = Path::new(role.writer_directory_v1());
        let name = role.basename_v1();
        let limits = role.limits_v1();
        let owner = match role {
            CacheJournalRecipeRoleV1::Bootstrap => ConstructionOwnerV1::BootstrapNative,
            CacheJournalRecipeRoleV1::Hold => ConstructionOwnerV1::HoldNative,
            CacheJournalRecipeRoleV1::Clock => ConstructionOwnerV1::ClockNative,
            CacheJournalRecipeRoleV1::Authority => ConstructionOwnerV1::AuthorityNative,
            CacheJournalRecipeRoleV1::State => ConstructionOwnerV1::StateNative,
        };

        self.preparation = Some((|| {
            let invalid = || JournalError::limit_exceeded("Cache construction path geometry");
            let directories = root
                .components()
                .count()
                .checked_add(1)
                .and_then(|count| count.checked_mul(2))
                .and_then(|count| u16::try_from(count).ok())
                .ok_or_else(invalid)?;
            let bytes = root
                .as_os_str()
                .as_encoded_bytes()
                .len()
                .checked_add(name.len())
                .and_then(|bytes| u16::try_from(bytes).ok())
                .ok_or_else(invalid)?;
            let fixed =
                CacheWriterOpeningV1::fixed_receiving_demand_v1::<Self>(directories, bytes)?;
            // Import is the larger actual forwarding route: native entry
            // argument; phase call argument/receiver; receiving-constructor
            // argument/receiver. Confirmed construction has no phase call.
            // The receiving owner itself remains in its full existing invoice.
            let forwarding = std::mem::size_of::<(Option<ResourceVector>, usize)>()
                .checked_mul(5)
                .and_then(|bytes| {
                    // The loan's supplement and upper-bound getters each
                    // return through their own ABI to this stage's caller.
                    bytes.checked_add(std::mem::size_of::<(
                        [Option<ResourceVector>; 2],
                        [usize; 2],
                    )>())
                })
                .and_then(|bytes| {
                    // New full semantic validator, checkpoint demand and
                    // complete-prefix local, beyond the old native variable.
                    bytes.checked_add(std::mem::size_of::<(
                        ResourceVector, ResourceVector, ResourceVector,
                    )>())
                })
                .and_then(|bytes| {
                    // Preparation and prefix closures each construct,
                    // return and park this actual owning Result type.
                    bytes.checked_add(
                        std::mem::size_of::<Result<ResourceVector, CacheConstructionStageErrorV1>>()
                            .checked_mul(6)?,
                    )
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        super::readonly_receiving::full_prefix_element_control_bytes_v1()?,
                    )
                })
                .and_then(|bytes| {
                    bytes.checked_add(ConstructionLoanV1::<P>::forwarding_control_bytes_v1()?)
                })
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(invalid)?;
            let forwarding = forwarding.checked_add(u64::try_from(
                loan.upper_forwarding_bytes_v1(owner),
            ).map_err(|_| invalid())?).ok_or_else(invalid)?;
            let fixed = fixed.checked_add(
                ResourceVector::ZERO
                    .with(aos_sandbox_model::ResourceDimension::MemoryBytes, forwarding),
            )?;
            loan.require_complete_v1(owner, fixed)?;
            Ok(fixed)
        })());
        let fixed = *self
            .preparation
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(())?;
        let primary = (|| {
            self.opening
                .prepare_once(root, name, limits, uid, allow_create)?;
            self.prefix = Some((|| {
                let extent = self
                    .opening
                    .prepared_extent()
                    .ok_or(JournalError::boundary())?;
                let native = extent
                    .dominant_native_receiving_demand_v1()
                    .map_err(JournalError::from_ordinary_native_v1)?;
                let validator = super::readonly_receiving::full_prefix_semantic_with_supplement_v1(
                    &extent,
                    loan.semantic_supplement_data_v1(),
                )?;
                // The full ordinary recipe retains committed challenge
                // checkpoints even with no external challenge witness. Their
                // historical backing is additional to the final native map.
                let checkpoints =
                    aos_sandbox_ledger_replay::geometry::retained_challenge_history_demand_v1(
                        extent.native_bytes(),
                    ).map_err(JournalError::from)?;
                let complete = fixed
                    .checked_add(native)?
                    .checked_add(validator)?
                    .checked_add(checkpoints)?;
                loan.require_complete_v1(owner, complete)?;
                Ok(complete)
            })());
            let complete = *self
                .prefix
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(())?;
            self.opening.replay_once(loan, owner, complete)
        })();

        // This is owed by actual funded native entry, including a failed
        // acquisition or a later financial/model refusal. It needs no new loan.
        self.names = Some(self.opening.observe_names_once(
            root,
            name,
            limits,
            uid,
            &mut self.names_original,
        ));
        primary?;
        if !matches!(self.names, Some(Ok(()))) {
            return Err(());
        }
        self.opening.take_completed_once().ok_or(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.preparation
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.opening.failure())
            .or_else(|| self.prefix.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.names_original.failure())
            .or_else(|| self.names.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}
