//! Lends only the actual existing financial origin to fixed Cache native audits.
//!
//! Identity fields are equality DATA. Only genuine scoped J/U/Delete loans
//! construct financial borrowers; no DATA value creates a Cache owner, phase,
//! account, budget, captured prefix or permission to append or open a writer.

use aos_sandbox_model::{ResourceVector, component_receiving::complete_bound_delta_v1};

use crate::controller_receiving::source_prebank::ControllerSourceOriginalRefV1;

use super::{
    CacheControllerOriginalRefV1, ControllerBankLaunchErrorV1,
    ControllerCacheRootObservationFundingLoanV1,
    ControllerCreateContinuationClosedV1, ControllerCreateContinuationFundingLoanV1,
    ControllerCreateStorageUseClosedV1, ControllerCreateStorageUseFundingLoanV1,
};

/// Identifies the same already-borrowed Cache association as equality DATA.
///
/// These in-process addresses cannot construct an original or authenticate a
/// received value. The private Cache native owner derives them from its actual
/// held references and independently rejoins every genuine funding original.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ControllerCacheAuditIdentityDataV1 {
    /// Identifies the actual borrowed initialization allocation.
    pub initialization: usize,
    /// Identifies the actual borrowed Cache owner allocation.
    pub owner: usize,
    /// Identifies the actual borrowed bootstrap writer allocation.
    pub source: usize,
    /// Identifies the actual borrowed state writer allocation.
    pub state: usize,
    /// Identifies the actual borrowed authority writer allocation.
    pub authority: usize,
    /// Identifies the actual borrowed clock owner allocation.
    pub clock: usize,
    /// Identifies the actual borrowed physical Cache allocation.
    pub physical: usize,
    /// Preserves the owner UID from the same actual Cache association.
    pub uid: u32,
}

/// Preserves the same actual account refusal or owning arithmetic cause.
#[derive(Debug, thiserror::Error)]
pub enum ControllerCacheAuditFundingErrorV1 {
    /// Marks J's refusal while its original retains the precise first cause.
    #[error(transparent)]
    Continuation(#[from] ControllerCreateContinuationClosedV1),
    /// Marks U's refusal while its original retains the precise first cause.
    #[error(transparent)]
    StorageUse(#[from] ControllerCreateStorageUseClosedV1),
    /// Retains the actual fixed association or checked accounting refusal.
    #[error(transparent)]
    Native(#[from] ControllerBankLaunchErrorV1),
}

struct CacheAuditAssociationV1<'funding> {
    identity: ControllerCacheAuditIdentityDataV1,
    cache: &'funding CacheControllerOriginalRefV1,
    source: &'funding ControllerSourceOriginalRefV1,
}

struct UseCacheAuditV1<'funding, 'profile> {
    original: ControllerCreateStorageUseFundingLoanV1<'funding, 'profile>,
    association: CacheAuditAssociationV1<'funding>,
    non_cache: ResourceVector,
    prepaid_semantic: ResourceVector,
    cache_complete_base: ResourceVector,
    paid_complete: ResourceVector,
}

enum CacheAuditPurposeV1<'funding, 'profile> {
    InitialJ {
        original: ControllerCreateContinuationFundingLoanV1<'funding, 'profile>,
        association: CacheAuditAssociationV1<'funding>,
        cache_complete_base: ResourceVector,
        required_complete: ResourceVector,
    },
    CurrentJ {
        original: ControllerCreateContinuationFundingLoanV1<'funding, 'profile>,
        association: CacheAuditAssociationV1<'funding>,
        non_cache: ResourceVector,
        property_traffic: ResourceVector,
        prepaid_semantic: ResourceVector,
        cache_complete_base: ResourceVector,
        required_complete: ResourceVector,
    },
    CurrentU(UseCacheAuditV1<'funding, 'profile>),
    ReleaseU(UseCacheAuditV1<'funding, 'profile>),
    Delete(super::ControllerCacheDeleteAuditFundingLoanV1<'funding, 'profile>),
}

/// Borrows the genuine financial origin of one fixed Cache audit purpose.
///
/// Factories rejoin the same Controller, Source and profile. J's existing
/// labeled highwater remains on its actual original; U factories debit their
/// actual additional demand before returning. The private Cache constructor
/// separately binds the equality DATA to its actual borrowed native owners.
/// No factory accepts an account, capacity, paid receipt or native writer.
#[must_use = "retain this genuine borrower through the reached Cache audit"]
pub struct ControllerCacheAuditFundingLoanV1<'funding, 'profile> {
    purpose: CacheAuditPurposeV1<'funding, 'profile>,
    failed: bool,
}

impl<'funding, 'profile> ControllerCreateContinuationFundingLoanV1<'funding, 'profile> {
    /// Lends the same already-admitted initial J Cache highwater.
    ///
    /// # Errors
    /// Refuses foreign originals/profile, closed J or insufficient actual
    /// CacheHeld admission. The demand is compared with J's private ledger.
    pub fn into_initial_cache_audit_v1(
        mut self,
        cache: &'funding CacheControllerOriginalRefV1,
        source: &'funding ControllerSourceOriginalRefV1,
        identity: ControllerCacheAuditIdentityDataV1,
        required_complete: ResourceVector,
    ) -> Result<ControllerCacheAuditFundingLoanV1<'funding, 'profile>, ControllerCacheAuditFundingErrorV1> {
        self.require_controller_original_v1(cache)?;
        self.require_source_original_v1(source)?;
        self.require_cache_complete_v1(required_complete)?;
        Ok(ControllerCacheAuditFundingLoanV1 {
            purpose: CacheAuditPurposeV1::InitialJ {
                original: self,
                association: CacheAuditAssociationV1 { identity, cache, source },
                cache_complete_base: required_complete,
                required_complete,
            },
            failed: false,
        })
    }

    /// Lends the same admitted RootExchange highwater to its current Cache audit.
    ///
    /// The actual upper owner supplies its existing non-Cache quote and
    /// cumulative property traffic after its independently paid peer prepay.
    /// These are demands; the actual J ledger verifies their admission.
    ///
    /// # Errors
    /// Preserves arithmetic failure and refuses foreign originals/profile,
    /// closed J or a RootExchange bound not already admitted on this original.
    pub fn into_current_cache_audit_v1(
        mut self,
        cache: &'funding CacheControllerOriginalRefV1,
        source: &'funding ControllerSourceOriginalRefV1,
        identity: ControllerCacheAuditIdentityDataV1,
        non_cache: ResourceVector,
        cache_complete: ResourceVector,
        property_traffic: ResourceVector,
        prepaid_semantic: ResourceVector,
    ) -> Result<ControllerCacheAuditFundingLoanV1<'funding, 'profile>, ControllerCacheAuditFundingErrorV1> {
        self.require_controller_original_v1(cache)?;
        self.require_source_original_v1(source)?;
        let required_complete = non_cache.checked_add(cache_complete)
            .and_then(|base| base.checked_add(property_traffic))
            .map_err(ControllerBankLaunchErrorV1::from)?;
        self.require_root_exchange_complete_v1(required_complete)?;
        Ok(ControllerCacheAuditFundingLoanV1 {
            purpose: CacheAuditPurposeV1::CurrentJ {
                original: self,
                association: CacheAuditAssociationV1 { identity, cache, source },
                non_cache,
                property_traffic,
                prepaid_semantic,
                cache_complete_base: cache_complete,
                required_complete,
            },
            failed: false,
        })
    }
}

impl<'funding, 'profile> ControllerCreateStorageUseFundingLoanV1<'funding, 'profile> {
    /// Debits the distinct current-proof U purpose before its native audit.
    ///
    /// This replaces the existing first U current-proof reserve at the same
    /// actual upper frontier. Earlier Root traffic remains separately charged.
    ///
    /// # Errors
    /// Preserves arithmetic and same-U debit refusal or foreign affinity.
    pub fn into_current_cache_audit_v1(
        mut self,
        cache: &'funding CacheControllerOriginalRefV1,
        source: &'funding ControllerSourceOriginalRefV1,
        identity: ControllerCacheAuditIdentityDataV1,
        non_cache: ResourceVector,
        cache_complete: ResourceVector,
        prepaid_semantic: ResourceVector,
    ) -> Result<ControllerCacheAuditFundingLoanV1<'funding, 'profile>, ControllerCacheAuditFundingErrorV1> {
        self.require_controller_original_v1(cache)?;
        self.require_source_original_v1(source)?;
        let paid_complete = non_cache.checked_add(cache_complete)
            .map_err(ControllerBankLaunchErrorV1::from)?;
        self.reserve_additional_v1(paid_complete)?;
        Ok(ControllerCacheAuditFundingLoanV1 {
            purpose: CacheAuditPurposeV1::CurrentU(UseCacheAuditV1 {
                original: self,
                association: CacheAuditAssociationV1 { identity, cache, source },
                non_cache,
                prepaid_semantic,
                cache_complete_base: cache_complete,
                paid_complete,
            }),
            failed: false,
        })
    }

    /// Debits the actual release U purpose before its native Cache audit.
    ///
    /// This replaces the existing release-purpose reserve. Reached semantic
    /// excess subsequently extends this same U without refund or a new account.
    ///
    /// # Errors
    /// Refuses foreign originals/profile, closed U or its actual debit failure.
    pub fn into_release_cache_audit_v1(
        mut self,
        cache: &'funding CacheControllerOriginalRefV1,
        source: &'funding ControllerSourceOriginalRefV1,
        identity: ControllerCacheAuditIdentityDataV1,
        non_cache: ResourceVector,
        cache_complete: ResourceVector,
        prepaid_semantic: ResourceVector,
    ) -> Result<ControllerCacheAuditFundingLoanV1<'funding, 'profile>, ControllerCacheAuditFundingErrorV1> {
        self.require_controller_original_v1(cache)?;
        self.require_source_original_v1(source)?;
        let paid_complete = non_cache.checked_add(cache_complete)
            .map_err(ControllerBankLaunchErrorV1::from)?;
        self.reserve_additional_v1(paid_complete)?;
        Ok(ControllerCacheAuditFundingLoanV1 {
            purpose: CacheAuditPurposeV1::ReleaseU(UseCacheAuditV1 {
                original: self,
                association: CacheAuditAssociationV1 { identity, cache, source },
                non_cache,
                prepaid_semantic,
                cache_complete_base: cache_complete,
                paid_complete,
            }),
            failed: false,
        })
    }
}

impl<'funding, 'profile> ControllerCacheAuditFundingLoanV1<'funding, 'profile> {
    /// Binds the actual Source-created, same-turn Delete financial borrower.
    ///
    /// No demand or paid scalar enters this handoff. The actual Source factory
    /// already owns its debit, requirement mirror, live turn and native affinity.
    pub fn from_delete_v1(
        original: super::ControllerCacheDeleteAuditFundingLoanV1<'funding, 'profile>,
    ) -> Self {
        Self {
            purpose: CacheAuditPurposeV1::Delete(original),
            failed: false,
        }
    }

    /// Prices this finite borrower and its construction and recurring controls.
    ///
    /// The existing actual fixed invoice includes this MemoryBytes term before
    /// constructing the borrower. Its inline enum includes the real lower loan;
    /// Delete's separate lower construction supplier prices its own factory.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        type Arguments<'a> = (
            &'a CacheControllerOriginalRefV1,
            &'a ControllerSourceOriginalRefV1,
            ControllerCacheAuditIdentityDataV1,
            [ResourceVector; 4],
        );
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<Self, ControllerCacheAuditFundingErrorV1>>())?
            .checked_add(std::mem::size_of::<Arguments<'_>>().checked_mul(2)?)?
            .checked_add(Self::recurring_control_bytes_v1()?)?
            .checked_add(std::mem::size_of::<&ControllerCreateStorageUseFundingLoanV1<'_, '_>>())?
            .checked_add(std::mem::size_of::<Result<(), ControllerCreateStorageUseClosedV1>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<&Self>())?
            .checked_add(std::mem::size_of::<Result<(), ControllerCacheAuditFundingErrorV1>>().checked_mul(2)?)?
            // Initial, Current and Release are exclusive finite purposes.
            // Their identical purpose-check argument/return planes count once
            // beside the existing named-check recipe.
            .checked_add(std::mem::size_of::<(
                ControllerCacheAuditIdentityDataV1,
                Result<(), ControllerCacheAuditFundingErrorV1>,
            )>())
    }

    /// Prices only the reached same-U Root observation reborrow controls.
    ///
    /// The actual U upper operation adds this once to its existing fixed
    /// non-Cache bound before admission. Ordinary readonly, Initial J and
    /// Delete invoices do not pay unrelated future Root observation controls.
    #[must_use]
    pub fn root_observation_funding_receiving_bytes_v1() -> Option<usize> {
        std::mem::size_of::<ControllerCacheRootObservationFundingLoanV1<'_>>().checked_mul(4)?
            // These are the actual lower Result constructor, ABI return and
            // caller planes; separate loan headers cannot finance the tag.
            .checked_add(std::mem::size_of::<Result<ControllerCacheRootObservationFundingLoanV1<'_>, ControllerCacheAuditFundingErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&mut ControllerCacheRootObservationFundingLoanV1<'_>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), ControllerCreateStorageUseClosedV1>>().checked_mul(4)?)?
            .checked_add(std::mem::size_of::<ResourceVector>().checked_mul(2)?)
    }

    fn recurring_control_bytes_v1() -> Option<usize> {
        use aos_sandbox_model::AccountingError;
        use std::mem::size_of;

        // Name the actual discriminated controls rather than treating their
        // ResourceVector payloads as interchangeable untyped storage credit.
        size_of::<Result<(), ControllerCacheAuditFundingErrorV1>>().checked_mul(3)?
            .checked_add(size_of::<Result<ResourceVector, ControllerCacheAuditFundingErrorV1>>().checked_mul(2)?)?
            .checked_add(size_of::<ControllerCacheAuditIdentityDataV1>().checked_mul(2)?)?
            .checked_add(size_of::<ResourceVector>().checked_mul(4)?)?
            .checked_add(size_of::<Option<ResourceVector>>())?
            .checked_add(size_of::<Result<(ResourceVector, ResourceVector), AccountingError>>())?
            .checked_add(size_of::<Result<(ResourceVector, ResourceVector), ControllerBankLaunchErrorV1>>())?
            .checked_add(size_of::<Result<ResourceVector, AccountingError>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<ResourceVector, ControllerBankLaunchErrorV1>>().checked_mul(2)?)?
            .checked_add(size_of::<(&CacheControllerOriginalRefV1, &ControllerSourceOriginalRefV1)>())
    }

    /// Refuses every purpose except the original Current J or Current U lane.
    ///
    /// # Errors
    /// Retains a foreign purpose or the existing named/original/profile refusal.
    pub fn require_current_original_v1(
        &mut self,
        identity: ControllerCacheAuditIdentityDataV1,
    ) -> Result<(), ControllerCacheAuditFundingErrorV1> {
        if !matches!(&self.purpose, CacheAuditPurposeV1::CurrentJ { .. } | CacheAuditPurposeV1::CurrentU(_)) {
            self.failed = true;
            return Err(ControllerBankLaunchErrorV1::Conflict.into());
        }
        self.require_named_preparation_v1(identity)
    }

    /// Reborrows genuine U for the actual upper Root observation interval.
    ///
    /// No reservation, profile acquisition or native observation occurs here.
    /// Cache's purpose highwater stays in this same facade while the temporary
    /// Root borrower charges only its old independently owed additional work.
    ///
    /// # Errors
    /// Refuses a non-U purpose. Existing Cache denial remains retained; this
    /// inert same-U borrow does not suppress independently owed Root posts.
    /// Any actual reservation or new debit still checks the same real U owner.
    pub fn borrow_root_observation_funding_v1(
        &mut self,
    ) -> Result<ControllerCacheRootObservationFundingLoanV1<'_>, ControllerCacheAuditFundingErrorV1> {
        match &mut self.purpose {
            CacheAuditPurposeV1::CurrentU(actual) | CacheAuditPurposeV1::ReleaseU(actual) => {
                Ok(actual.original.borrow_root_observation_funding_v1())
            }
            _ => {
                self.failed = true;
                Err(ControllerBankLaunchErrorV1::Conflict.into())
            }
        }
    }

    /// Checks the same actual U reservation without another Cache health gate.
    ///
    /// Independently owed Root observations inspect this same U even after a
    /// Cache denial. The Cache's sticky denial remains unchanged and its own
    /// named/admission methods still refuse; this observation grants no phase.
    ///
    /// # Errors
    /// Refuses a non-U purpose or the actual original U reservation refusal.
    pub fn require_storage_use_reserved_v1(
        &self,
    ) -> Result<(), ControllerCacheAuditFundingErrorV1> {
        match &self.purpose {
            CacheAuditPurposeV1::CurrentU(actual) | CacheAuditPurposeV1::ReleaseU(actual) => {
                actual.original.require_reserved_v1().map_err(Into::into)
            }
            _ => Err(ControllerBankLaunchErrorV1::Conflict.into()),
        }
    }

    /// Refuses every funding purpose except the actual initial Held J.
    ///
    /// This affinity check grants no Source, Controller or Root phase. Their
    /// actual semantic checks and independent posts remain on the upper owner.
    ///
    /// # Errors
    /// Refuses a foreign purpose, changed identity or actual original debt.
    pub fn require_initial_held_original_v1(
        &mut self,
        identity: ControllerCacheAuditIdentityDataV1,
    ) -> Result<(), ControllerCacheAuditFundingErrorV1> {
        if !matches!(&self.purpose, CacheAuditPurposeV1::InitialJ { .. }) {
            self.failed = true;
            return Err(ControllerBankLaunchErrorV1::Conflict.into());
        }
        self.require_named_preparation_v1(identity)
    }

    /// Refuses every funding purpose except the actual same-U release audit.
    ///
    /// A successful check grants no release phase or append permission. It
    /// only denies funding substitution at the private native append context.
    ///
    /// # Errors
    /// Refuses a foreign purpose, changed identity or actual original debt.
    pub fn require_release_original_v1(
        &mut self,
        identity: ControllerCacheAuditIdentityDataV1,
    ) -> Result<(), ControllerCacheAuditFundingErrorV1> {
        if !matches!(&self.purpose, CacheAuditPurposeV1::ReleaseU(_)) {
            self.failed = true;
            return Err(ControllerBankLaunchErrorV1::Conflict.into());
        }
        self.require_named_preparation_v1(identity)
    }

    /// Rejoins this account to the actual private Cache Controller original.
    ///
    /// The private Cache owner supplies its actual retained Controller. J/U
    /// rejoin their already-borrowed genuine Source association; Delete retains
    /// its actual Source/C17 intake borrow. No second upper Source borrow,
    /// equality DATA or successful receipt substitutes for those originals.
    ///
    /// # Errors
    /// Refuses an earlier failure or foreign Controller, Source or profile,
    /// retaining the existing original's actual first financial cause.
    pub fn require_cache_original_v1(
        &mut self,
        cache: &CacheControllerOriginalRefV1,
    ) -> Result<(), ControllerCacheAuditFundingErrorV1> {
        if self.failed {
            return Err(ControllerBankLaunchErrorV1::Conflict.into());
        }
        let result = match &mut self.purpose {
            CacheAuditPurposeV1::InitialJ { original, association, .. }
            | CacheAuditPurposeV1::CurrentJ { original, association, .. } => {
                original.require_controller_original_v1(cache)
                    .and_then(|()| original.require_source_original_v1(association.source))
                    .map_err(Into::into)
            }
            CacheAuditPurposeV1::CurrentU(actual)
            | CacheAuditPurposeV1::ReleaseU(actual) => {
                actual.original.require_controller_original_v1(cache)
                    .and_then(|()| actual.original.require_source_original_v1(actual.association.source))
                    .map_err(Into::into)
            }
            CacheAuditPurposeV1::Delete(original) => original
                .require_cache_original_v1(cache).map_err(Into::into),
        };
        self.failed |= result.is_err();
        result
    }

    /// Rejoins the same actual original before named capture or replay entry.
    ///
    /// # Errors
    /// Refuses a substituted Cache association, prior failure, foreign genuine
    /// Controller/Source/profile or an actual financial bound no longer valid.
    pub fn require_named_preparation_v1(
        &mut self,
        identity: ControllerCacheAuditIdentityDataV1,
    ) -> Result<(), ControllerCacheAuditFundingErrorV1> {
        if self.failed {
            return Err(ControllerBankLaunchErrorV1::Conflict.into());
        }
        let result = match &mut self.purpose {
            CacheAuditPurposeV1::InitialJ { original, association, required_complete, .. } => {
                require_identity(association, identity)
                    .and_then(|()| original.require_controller_original_v1(association.cache).map_err(Into::into))
                    .and_then(|()| original.require_source_original_v1(association.source).map_err(Into::into))
                    .and_then(|()| original.require_cache_complete_v1(*required_complete).map_err(Into::into))
            }
            CacheAuditPurposeV1::CurrentJ { original, association, required_complete, .. } => {
                require_identity(association, identity)
                    .and_then(|()| original.require_controller_original_v1(association.cache).map_err(Into::into))
                    .and_then(|()| original.require_source_original_v1(association.source).map_err(Into::into))
                    .and_then(|()| original.require_root_exchange_complete_v1(*required_complete).map_err(Into::into))
            }
            CacheAuditPurposeV1::CurrentU(actual) | CacheAuditPurposeV1::ReleaseU(actual) => {
                require_identity(&actual.association, identity)
                    .and_then(|()| actual.original.require_controller_original_v1(actual.association.cache).map_err(Into::into))
                    .and_then(|()| actual.original.require_source_original_v1(actual.association.source).map_err(Into::into))
                    .and_then(|()| actual.original.require_charged_v1(actual.paid_complete).map_err(Into::into))
            }
            CacheAuditPurposeV1::Delete(original) => original
                .require_named_preparation_v1(identity).map_err(Into::into),
        };
        self.failed |= result.is_err();
        result
    }

    /// Compares the genuine admission with the Cache constructor's own shape.
    ///
    /// The private Cache constructor derives both values from its actual five
    /// held extents. A public factory's demand DATA cannot waive a later
    /// semantic charge merely by describing a larger prepaid component.
    ///
    /// # Errors
    /// Refuses a changed identity, prior original failure, or any mismatch in
    /// the actual private complete base or already included semantic demand.
    pub fn require_cache_shape_v1(
        &mut self,
        identity: ControllerCacheAuditIdentityDataV1,
        complete_base: ResourceVector,
        prepaid_semantic: ResourceVector,
    ) -> Result<(), ControllerCacheAuditFundingErrorV1> {
        self.require_named_preparation_v1(identity)?;
        let result = match &mut self.purpose {
            CacheAuditPurposeV1::InitialJ { cache_complete_base, .. } => {
                require_shape(*cache_complete_base, ResourceVector::ZERO,
                    complete_base, prepaid_semantic)
            }
            CacheAuditPurposeV1::CurrentJ {
                cache_complete_base, prepaid_semantic: expected_semantic, ..
            } => require_shape(*cache_complete_base, *expected_semantic,
                complete_base, prepaid_semantic),
            CacheAuditPurposeV1::CurrentU(actual)
            | CacheAuditPurposeV1::ReleaseU(actual) => require_shape(
                actual.cache_complete_base, actual.prepaid_semantic,
                complete_base, prepaid_semantic,
            ),
            CacheAuditPurposeV1::Delete(original) => original
                .require_cache_shape_v1(identity, complete_base, prepaid_semantic)
                .map_err(Into::into),
        };
        self.failed |= result.is_err();
        result
    }

    /// Admits the actual complete reached Cache demand before model growth.
    ///
    /// # Errors
    /// Preserves same-origin admission and arithmetic refusal. J extends its
    /// existing purpose highwater; U debits only the reached excess; Delete
    /// compares against its actual previously admitted complete Source bound.
    pub fn admit_complete_v1(
        &mut self,
        identity: ControllerCacheAuditIdentityDataV1,
        cache_complete: ResourceVector,
    ) -> Result<(), ControllerCacheAuditFundingErrorV1> {
        self.require_named_preparation_v1(identity)?;
        let result = (|| {
            let base = match &self.purpose {
                CacheAuditPurposeV1::InitialJ { cache_complete_base, .. }
                | CacheAuditPurposeV1::CurrentJ { cache_complete_base, .. } =>
                    Some(*cache_complete_base),
                CacheAuditPurposeV1::CurrentU(actual)
                | CacheAuditPurposeV1::ReleaseU(actual) => Some(actual.cache_complete_base),
                CacheAuditPurposeV1::Delete(_) => None,
            };
            if base.is_some_and(|base| !base.is_within(cache_complete)) {
                return Err(ControllerBankLaunchErrorV1::Conflict.into());
            }
            match &mut self.purpose {
                CacheAuditPurposeV1::InitialJ { original, required_complete, .. } => {
                    original.reserve_cache_complete_v1(cache_complete).map_err(Into::into)
                        .map(|()| *required_complete = required_complete.componentwise_max(cache_complete))
                }
                CacheAuditPurposeV1::CurrentJ {
                    original, non_cache, property_traffic, required_complete, ..
                } => {
                    let complete = non_cache.checked_add(cache_complete)
                        .and_then(|base| base.checked_add(*property_traffic))
                        .map_err(ControllerBankLaunchErrorV1::from)?;
                    original.reserve_root_exchange_complete_v1(complete).map_err(Into::into)
                        .map(|()| *required_complete = required_complete.componentwise_max(complete))
                }
                CacheAuditPurposeV1::CurrentU(actual) | CacheAuditPurposeV1::ReleaseU(actual) => {
                    let reached = actual.non_cache.checked_add(cache_complete)
                        .map_err(ControllerBankLaunchErrorV1::from)?;
                    let (complete, additional) = complete_bound_delta_v1(actual.paid_complete, reached)
                        .map_err(ControllerBankLaunchErrorV1::from)?;
                    actual.original.reserve_additional_v1(additional).map_err(Into::into)
                        .map(|()| actual.paid_complete = complete)
                }
                CacheAuditPurposeV1::Delete(original) => original
                    .admit_complete_v1(identity, cache_complete).map_err(Into::into),
            }
        })();
        self.failed |= result.is_err();
        result
    }

    /// Returns this exact purpose's already included semantic comparison demand.
    ///
    /// # Errors
    /// Refuses an earlier admission failure or the same Delete turn's refusal.
    pub fn prepaid_semantic_demand_v1(&self) -> Result<ResourceVector, ControllerCacheAuditFundingErrorV1> {
        if self.failed {
            return Err(ControllerBankLaunchErrorV1::Conflict.into());
        }
        match &self.purpose {
            CacheAuditPurposeV1::InitialJ { .. } => Ok(ResourceVector::ZERO),
            CacheAuditPurposeV1::CurrentJ { prepaid_semantic, .. } => Ok(*prepaid_semantic),
            CacheAuditPurposeV1::CurrentU(actual) | CacheAuditPurposeV1::ReleaseU(actual) => Ok(actual.prepaid_semantic),
            CacheAuditPurposeV1::Delete(original) => original.prepaid_semantic_demand_v1().map_err(Into::into),
        }
    }
}

fn require_identity(
    association: &CacheAuditAssociationV1<'_>,
    identity: ControllerCacheAuditIdentityDataV1,
) -> Result<(), ControllerCacheAuditFundingErrorV1> {
    if association.identity == identity {
        Ok(())
    } else {
        Err(ControllerBankLaunchErrorV1::Conflict.into())
    }
}

fn require_shape(
    expected_base: ResourceVector,
    expected_semantic: ResourceVector,
    actual_base: ResourceVector,
    actual_semantic: ResourceVector,
) -> Result<(), ControllerCacheAuditFundingErrorV1> {
    if expected_base == actual_base && expected_semantic == actual_semantic {
        Ok(())
    } else {
        Err(ControllerBankLaunchErrorV1::Conflict.into())
    }
}
