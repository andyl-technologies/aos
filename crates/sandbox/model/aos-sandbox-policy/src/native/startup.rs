//! Retains selected startup Authority opening before its credentials exist.
//!
//! This owner is distinct from completed Authority: signer pins and deployment
//! are installed only after this same fixed writer has been received. It keeps
//! every reached opening, names observation, and independently owed final post.

pub(in crate::native) use credential_gate::StartupCredentialAppendGateV1;

mod credentials;
#[cfg(any(test, feature = "test-fixtures"))]
pub use credentials::RootStartupFixedAdmissionFixtureV1;
mod provision;
pub(in crate::native) use provision::ServiceStageV1;
pub use provision::{RootCompletedPolicyListenerBorrowV1, RootCompletedPolicyListenerOriginalV1, RootControllerPeerProvisionOriginalV1, RootCurrentWritersPredecessorV1, RootStartupControllerPeerOriginalV1, RootStartupProvisionErrorV1, RootStartupProvisionOriginalV1};
pub use credentials::{RootStartupBindingReadErrorV1, RootStartupCredentialErrorV1, RootStartupCredentialWriterV1};

mod credential_authority;
mod credential_gate;

use aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1, RootSelectedProvisionBorrowV1,
    RootWriterPostOriginalV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use std::error::Error;

use super::PolicyNativeJournalErrorV1;
use super::journal::names::{
    RootFixedNameRecipeV1, RootFixedNameRoleV1, RootPolicyNameObservationOriginalV1,
};
use super::journal::{
    PolicyJournalStorageV1, RootPolicyJournalConstructionOriginalV1, RootPolicyJournalPurposeV1,
    RootPolicyJournalV1,
};

/// Preserves startup journal errors before completed Authority exists.
#[derive(Debug, thiserror::Error)]
pub enum RootStartupJournalErrorV1 {
    /// Owns a native, replay, financial, or durable append error.
    #[error(transparent)]
    Native(#[from] PolicyNativeJournalErrorV1),
    /// Retains the actual fixed-name error on this same startup owner.
    #[error("the startup Authority names observation refused")]
    Names,
    /// Refuses unavailable, repeated, foreign, or already-ended custody.
    #[error("the startup Authority journal is closed")]
    Closed,
}

/// Owns the selected startup Authority before signer credential admission.
///
/// Only a genuine settled selected-provision borrow constructs this owner. It
/// does not accept a journal, completed prefix, account, pathname, or success.
pub struct RootSelectedStartupJournalOriginalV1 {
    financial: RootJournalFinancialOriginalV1,
    construction: RootPolicyJournalConstructionOriginalV1,
    journal: Option<RootPolicyJournalV1>,
    final_post: Option<RootWriterPostOriginalV1>,
    names: Option<RootPolicyNameObservationOriginalV1>,
    post_result: Option<Result<(), PolicyNativeJournalErrorV1>>,
    preparation_entered: bool,
    finished: bool,
}

impl RootSelectedStartupJournalOriginalV1 {
    /// Creates inert custody from the actual same settled selected Initial.
    #[must_use]
    pub fn new(provision: &RootSelectedProvisionBorrowV1<'_>) -> Self {
        Self {
            financial: provision.financial_original_v1().clone(),
            construction: RootPolicyJournalConstructionOriginalV1::new(),
            journal: None,
            final_post: None,
            names: None,
            post_result: None,
            preparation_entered: false,
            finished: false,
        }
    }

    /// Prices complete selected opening and actual startup owner controls.
    ///
    /// The real earlier receiving owner must Stage this before construction or
    /// opening. Complete held native/semantic/index and credential representation
    /// remain separately derived before their original later frontiers.
    ///
    /// # Errors
    /// Preserves native geometry or checked carrier overflow.
    pub fn fixed_preparation_demand_v1() -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(), RootStartupJournalErrorV1>>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<RootJournalFinancialOriginalV1>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<&RootSelectedProvisionBorrowV1<'_>>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(PolicyNativeJournalErrorV1::geometry)?;
        let current = RootPolicyNameObservationOriginalV1::additional_demand_v1(
            RootFixedNameRoleV1::Authority,
            RootFixedNameRecipeV1::Owner,
        )?;
        let current_bytes = std::mem::size_of::<RootPolicyNameObservationOriginalV1>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                Result<&mut RootPolicyJournalV1, RootStartupJournalErrorV1>>().checked_mul(3)?)
            })
            .and_then(|bytes| bytes.checked_add(credential_gate::control_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(credential_authority::control_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(PolicyNativeJournalErrorV1::geometry)?;
        RootPolicyJournalConstructionOriginalV1::fixed_demand_v1(
            RootPolicyJournalPurposeV1::StartupAuthority,
        )?
        .checked_add(current)
        .map_err(|_| PolicyNativeJournalErrorV1::geometry())?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, current_bytes))
        .map_err(|_| PolicyNativeJournalErrorV1::geometry())?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        .map_err(|_| PolicyNativeJournalErrorV1::geometry())
    }

    /// Enters only this same Initial's once-only fixed startup opening.
    ///
    /// # Errors
    /// Refuses another Initial, reentry, or an ended owner. Physical preparation
    /// retains every reached original in the same native construction reservoir.
    pub fn prepare_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), RootStartupJournalErrorV1> {
        if self.preparation_entered || self.finished {
            initial.latch_root_refusal_v1();
            return Err(RootStartupJournalErrorV1::Closed);
        }
        self.preparation_entered = true;
        if !initial
            .financial_diagnostic_original_v1()
            .as_ref()
            .is_some_and(|actual| actual.same_original_data_v1(&self.financial))
        {
            initial.latch_root_refusal_v1();
            return Err(RootStartupJournalErrorV1::Closed);
        }
        self.construction
            .prepare_once(initial, RootPolicyJournalPurposeV1::StartupAuthority);
        if self.construction.failure().is_some() {
            Err(RootStartupJournalErrorV1::Closed)
        } else {
            Ok(())
        }
    }

    /// Borrows the same physically captured prefix without another native sample.
    #[must_use]
    pub fn extent_v1(&self) -> Option<&CanonicalReplayExtentDataV1> {
        self.construction.extent()
    }

    /// Prices the actual held opening's native replay index.
    ///
    /// # Errors
    /// Preserves an absent/failed preparation or native geometry refusal.
    pub fn index_demand_v1(&self) -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        self.construction.index_demand_v1()
    }

    pub(in crate::native) fn variable_components_v1(
        &self,
    ) -> Result<[ResourceVector; 3], PolicyNativeJournalErrorV1> {
        self.construction.variable_components_v1()
    }

    /// Runs the sole complete cold replay and its existing names post.
    pub fn replay_once_v1(&mut self) {
        if self.finished {
            return;
        }
        self.construction.replay_once();
        self.construction.finish_names_once();
    }

    /// Completes independently owed construction names after primary refusal.
    pub fn finish_receiving_names_once_v1(&mut self) {
        self.construction.finish_names_once();
    }

    /// Reports actual full native/replay/tail/names completion as DATA.
    #[must_use]
    pub fn replay_ready_data_v1(&self) -> bool {
        self.construction.ready()
    }

    /// Completes the separately prearmed final startup writer names post.
    ///
    /// # Errors
    /// Refuses repetition, missing custody or an actual independent post error.
    /// Poison or an earlier credential refusal cannot suppress the owed IO.
    pub fn finish_names_once_v1(&mut self) -> Result<(), RootStartupJournalErrorV1> {
        if self.finished {
            return Err(RootStartupJournalErrorV1::Closed);
        }
        self.finished = true;
        self.post_result = Some(match (&self.journal, self.final_post.as_mut()) {
            (Some(journal), Some(post)) => match &journal.storage {
                PolicyJournalStorageV1::Selected { writer, .. } => {
                    writer.finish_native_post_once_v1(post).map_err(Into::into)
                }
                PolicyJournalStorageV1::Ordinary { .. } => {
                    Err(PolicyNativeJournalErrorV1::boundary())
                }
            },
            _ => {
                self.construction.finish_names_once();
                if self.construction.failure().is_none() {
                    Ok(())
                } else {
                    Err(PolicyNativeJournalErrorV1::boundary())
                }
            }
        });
        if matches!(self.post_result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootStartupJournalErrorV1::Closed)
        }
    }

    /// Borrows the earliest actual original cause without taking failed custody.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        // Match the old selected concrete-first selector. A prior entered
        // append keeps its first cause; a later shared refusal cannot mask the
        // independent final post's actual native IO error.
        self.journal
            .as_ref()
            .and_then(RootPolicyJournalV1::concrete_failure_v1)
            .or_else(|| self.construction.concrete_failure_v1())
            .or_else(|| self.names.as_ref().and_then(|original| original.failure()))
            .or_else(|| {
                self.final_post
                    .as_ref()
                    .and_then(|post| post.concrete_failure_v1())
            })
            .or_else(|| {
                self.post_result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| self.construction.failure())
            .or_else(|| self.journal.as_ref().and_then(RootPolicyJournalV1::failure))
            .or_else(|| self.final_post.as_ref().and_then(|post| post.failure()))
    }

    // The native credential writer alone calls this before each actual fixed
    // admission. No mutable Journal or generic transaction port is exported.
    fn journal_mut_v1(&mut self) -> Result<&mut RootPolicyJournalV1, RootStartupJournalErrorV1> {
        if self.finished {
            return Err(RootStartupJournalErrorV1::Closed);
        }
        if self.journal.is_none() {
            self.journal = self.construction.take_journal_once();
        }
        let journal = self
            .journal
            .as_ref()
            .ok_or(RootStartupJournalErrorV1::Closed)?;
        if self.final_post.is_none() {
            self.final_post = Some(match &journal.storage {
                PolicyJournalStorageV1::Selected { writer, .. } => writer
                    .arm_native_post_once_v1()
                    .map_err(PolicyNativeJournalErrorV1::from)?,
                PolicyJournalStorageV1::Ordinary { .. } => {
                    return Err(RootStartupJournalErrorV1::Closed);
                }
            });
        }
        // A complete positive local sample may be disposed just as the old
        // temporary was. A failed one remains on this same startup owner.
        if self
            .names
            .as_ref()
            .is_some_and(|original| original.failure().is_some())
        {
            return Err(RootStartupJournalErrorV1::Names);
        }
        self.names = Some(RootPolicyNameObservationOriginalV1::new());
        let names = self
            .names
            .as_mut()
            .ok_or(RootStartupJournalErrorV1::Closed)?;
        names
            .observe_once(
                journal,
                RootFixedNameRoleV1::Authority,
                RootFixedNameRecipeV1::Owner,
            )
            .map_err(|()| RootStartupJournalErrorV1::Names)?;
        self.journal
            .as_mut()
            .ok_or(RootStartupJournalErrorV1::Closed)
    }
}

// Ordinary and selected custody are named physical purposes. No absent or
// failed selected lender can select the ordinary branch.
enum StartupJournalStorageV1 {
    Selected(RootSelectedStartupJournalOriginalV1),
    Ordinary(RootOrdinaryStartupJournalOriginalV1),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OrdinaryStartupPurposeV1 {
    StartupHeld,
    FixedAdmission,
}

struct RootOrdinaryStartupJournalOriginalV1 {
    opening: super::journal::RootPolicyOrdinaryOpeningOriginalV1,
    purpose: OrdinaryStartupPurposeV1,
    names: Option<RootPolicyNameObservationOriginalV1>,
    final_names: Option<RootPolicyNameObservationOriginalV1>,
    open_entered: bool,
    finished: bool,
}

/// Retains one explicit native startup journal through fixed credential admission.
///
/// The selected constructor requires the actual settled Initial lender. The
/// ordinary constructor is a distinct fixed acquisition with its existing
/// allocation policy and never supplies selected receiving or finance.
pub struct RootStartupJournalOriginalV1 {
    storage: StartupJournalStorageV1,
    signer_pins: Option<credentials::StartupSignerPinsV1>,
}

impl RootStartupJournalOriginalV1 {
    /// Creates selected custody from the same genuine settled provision lender.
    #[must_use]
    pub fn new_selected_v1(provision: &RootSelectedProvisionBorrowV1<'_>) -> Self {
        Self {
            storage: StartupJournalStorageV1::Selected(RootSelectedStartupJournalOriginalV1::new(
                provision,
            )),
            signer_pins: None,
        }
    }

    /// Creates inert ordinary fixed Authority custody without a selected grant.
    #[must_use]
    pub fn new_ordinary_v1() -> Self {
        Self::new_ordinary_purpose_v1(OrdinaryStartupPurposeV1::StartupHeld)
    }

    /// Creates the distinct ordinary one-off fixed-admission owner.
    ///
    /// Its five fixed helpers keep their original already-opened entry policy;
    /// it acquires no startup credential loan or selected receiving authority.
    #[must_use]
    pub fn new_fixed_admission_v1() -> Self {
        Self::new_ordinary_purpose_v1(OrdinaryStartupPurposeV1::FixedAdmission)
    }

    fn new_ordinary_purpose_v1(purpose: OrdinaryStartupPurposeV1) -> Self {
        Self {
            storage: StartupJournalStorageV1::Ordinary(RootOrdinaryStartupJournalOriginalV1 {
                opening: super::journal::RootPolicyOrdinaryOpeningOriginalV1::new(),
                purpose,
                names: None,
                final_names: None,
                open_entered: false,
                finished: false,
            }),
            signer_pins: None,
        }
    }

    /// Opens only this explicit ordinary owner's fixed Authority recipe once.
    ///
    /// # Errors
    /// Refuses selected purpose or repeated entry; the actual ordinary failure
    /// graph remains on this same owner through its original final-post scope.
    pub fn open_ordinary_once_v1(&mut self) -> Result<(), RootStartupJournalErrorV1> {
        let StartupJournalStorageV1::Ordinary(ordinary) = &mut self.storage else {
            return Err(RootStartupJournalErrorV1::Closed);
        };
        if ordinary.open_entered || ordinary.finished {
            return Err(RootStartupJournalErrorV1::Closed);
        }
        ordinary.open_entered = true;
        ordinary.opening.open_startup_authority_once_v1();
        if ordinary.opening.failure_v1().is_some() {
            Err(RootStartupJournalErrorV1::Closed)
        } else {
            Ok(())
        }
    }

    /// Enters only this selected owner's same-Initial physical opening.
    ///
    /// # Errors
    /// Refuses ordinary purpose or the actual selected preparation failure.
    pub fn prepare_selected_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), RootStartupJournalErrorV1> {
        match &mut self.storage {
            StartupJournalStorageV1::Selected(selected) => selected.prepare_once_v1(initial),
            StartupJournalStorageV1::Ordinary(_) => {
                initial.latch_root_refusal_v1();
                Err(RootStartupJournalErrorV1::Closed)
            }
        }
    }

    /// Prices the complete actual selected wrapper before native construction.
    ///
    /// # Errors
    /// Preserves checked fixed native/constructor/return geometry refusal.
    pub fn selected_fixed_preparation_demand_v1()
    -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<RootStartupJournalFailureOriginalV1>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<StartupJournalStorageV1>().checked_mul(2)?)
            })
            .and_then(|bytes| bytes.checked_add(Self::credential_writer_control_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(PolicyNativeJournalErrorV1::geometry)?;
        RootSelectedStartupJournalOriginalV1::fixed_preparation_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| PolicyNativeJournalErrorV1::geometry())
    }

    /// Borrows this same owner's actual reached original failure.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        match &self.storage {
            StartupJournalStorageV1::Selected(selected) => selected.failure_v1(),
            StartupJournalStorageV1::Ordinary(ordinary) => ordinary
                .opening
                .failure_v1()
                .or_else(|| ordinary.names.as_ref().and_then(|names| names.failure()))
                .or_else(|| ordinary.final_names.as_ref().and_then(|names| names.failure())),
        }
    }

    // Exactly one owned-name observation precedes each fixed semantic entry.
    // Claim/namespace checks follow that method's original encode/decode work.
    fn journal_mut_v1(&mut self) -> Result<&mut RootPolicyJournalV1, RootStartupJournalErrorV1> {
        match &mut self.storage {
            StartupJournalStorageV1::Selected(selected) => selected.journal_mut_v1(),
            StartupJournalStorageV1::Ordinary(ordinary) => {
                if ordinary.finished {
                    return Err(RootStartupJournalErrorV1::Closed);
                }
                if ordinary.purpose == OrdinaryStartupPurposeV1::FixedAdmission {
                    return ordinary
                        .opening
                        .journal_mut_v1()
                        .ok_or(RootStartupJournalErrorV1::Closed);
                }
                let journal = ordinary
                    .opening
                    .journal_v1()
                    .ok_or(RootStartupJournalErrorV1::Closed)?;
                if ordinary
                    .names
                    .as_ref()
                    .is_some_and(|names| names.failure().is_some())
                {
                    return Err(RootStartupJournalErrorV1::Names);
                }
                ordinary.names = Some(RootPolicyNameObservationOriginalV1::new());
                ordinary
                    .names
                    .as_mut()
                    .ok_or(RootStartupJournalErrorV1::Closed)?
                    .observe_once(
                        journal,
                        RootFixedNameRoleV1::Authority,
                        RootFixedNameRecipeV1::Owner,
                    )
                    .map_err(|()| RootStartupJournalErrorV1::Names)?;
                ordinary
                    .opening
                    .journal_mut_v1()
                    .ok_or(RootStartupJournalErrorV1::Closed)
            }
        }
    }

    fn journal_v1(&self) -> Option<&RootPolicyJournalV1> {
        match &self.storage {
            StartupJournalStorageV1::Selected(selected) => selected.journal.as_ref(),
            StartupJournalStorageV1::Ordinary(ordinary) => ordinary.opening.journal_v1(),
        }
    }

    // After a fixed admission's earlier entry/decode, this borrow performs no
    // second names sample. Only its actual backend can select the next gate.
    fn journal_after_entry_mut_v1(&mut self) -> Option<&mut RootPolicyJournalV1> {
        match &mut self.storage {
            StartupJournalStorageV1::Selected(selected) => selected.journal.as_mut(),
            StartupJournalStorageV1::Ordinary(ordinary) => ordinary.opening.journal_mut_v1(),
        }
    }
}

impl RootStartupJournalOriginalV1 {
    /// Moves the whole same owner into a diagnostic without disposing failed originals.
    #[must_use]
    pub fn into_failure_v1(self) -> RootStartupJournalFailureOriginalV1 {
        RootStartupJournalFailureOriginalV1 { owner: self }
    }

    /// Borrows the actual selected physical prefix at the original receiving frontier.
    #[must_use]
    pub fn selected_extent_v1(&self) -> Option<&CanonicalReplayExtentDataV1> {
        match &self.storage {
            StartupJournalStorageV1::Selected(selected) => selected.extent_v1(),
            StartupJournalStorageV1::Ordinary(_) => None,
        }
    }

    /// Prices the actual selected opening's native index without resampling metadata.
    ///
    /// # Errors
    /// Refuses ordinary purpose, absent preparation, or native geometry failure.
    pub fn selected_index_demand_v1(&self) -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        match &self.storage {
            StartupJournalStorageV1::Selected(selected) => selected.index_demand_v1(),
            StartupJournalStorageV1::Ordinary(_) => Err(PolicyNativeJournalErrorV1::boundary()),
        }
    }

    /// Replays this same selected opening through the sole full cold engine.
    ///
    /// # Errors
    /// Refuses ordinary purpose; actual native/replay errors remain on the owner.
    pub fn replay_selected_once_v1(&mut self) -> Result<(), RootStartupJournalErrorV1> {
        let StartupJournalStorageV1::Selected(selected) = &mut self.storage else {
            return Err(RootStartupJournalErrorV1::Closed);
        };
        selected.replay_once_v1();
        if selected.replay_ready_data_v1() {
            Ok(())
        } else {
            Err(RootStartupJournalErrorV1::Closed)
        }
    }

    /// Completes this selected opening's independently owed receiving-name post.
    ///
    /// # Errors
    /// Refuses ordinary purpose without starting another physical recipe.
    pub fn finish_selected_receiving_names_once_v1(
        &mut self,
    ) -> Result<(), RootStartupJournalErrorV1> {
        match &mut self.storage {
            StartupJournalStorageV1::Selected(selected) => {
                selected.finish_receiving_names_once_v1();
                Ok(())
            }
            StartupJournalStorageV1::Ordinary(_) => Err(RootStartupJournalErrorV1::Closed),
        }
    }
}

/// Retains the actual startup owner and all reached failed opening/post originals.
///
/// Moving this diagnostic cannot create a receiving loan, erase a refusal, or
/// admit another startup attempt. Its source borrows only this same owner.
pub struct RootStartupJournalFailureOriginalV1 {
    owner: RootStartupJournalOriginalV1,
}

impl std::fmt::Debug for RootStartupJournalFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("RootStartupJournalFailureOriginalV1")
            .field("cause", &self.owner.failure_v1())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RootStartupJournalFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.owner.failure_v1() {
            Some(cause) => std::fmt::Display::fmt(cause, output),
            None => output.write_str("the startup journal owner refused continuation"),
        }
    }
}

impl Error for RootStartupJournalFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.owner.failure_v1()
    }
}

impl RootStartupJournalOriginalV1 {
    /// Lends this selected owner with the same actual continuously held finance.
    ///
    /// # Errors
    /// Refuses ordinary purpose or a foreign actual financial original without
    /// performing native observations or changing to an ordinary fallback.
    pub fn selected_credential_writer_v1<'borrow>(
        &'borrow mut self,
        original: aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'borrow>,
    ) -> Result<RootStartupCredentialWriterV1<'borrow>, RootStartupJournalErrorV1> {
        let StartupJournalStorageV1::Selected(selected) = &self.storage else {
            return Err(RootStartupJournalErrorV1::Closed);
        };
        let actual = original
            .diagnostic_original_v1()
            .ok_or(RootStartupJournalErrorV1::Closed)?;
        if !actual.same_original_data_v1(&selected.financial) {
            return Err(RootStartupJournalErrorV1::Closed);
        }
        Ok(RootStartupCredentialWriterV1::new(self, Some(original)))
    }

    /// Lends only this explicitly ordinary owner's actual fixed writer.
    ///
    /// # Errors
    /// Refuses selected purpose; missing finance cannot choose this method.
    pub fn ordinary_credential_writer_v1(
        &mut self,
    ) -> Result<RootStartupCredentialWriterV1<'_>, RootStartupJournalErrorV1> {
        if !matches!(self.storage, StartupJournalStorageV1::Ordinary(_)) {
            return Err(RootStartupJournalErrorV1::Closed);
        }
        Ok(RootStartupCredentialWriterV1::new(self, None))
    }

    fn fixed_admission_purpose_data_v1(&self) -> bool {
        matches!(&self.storage, StartupJournalStorageV1::Ordinary(ordinary)
            if ordinary.purpose == OrdinaryStartupPurposeV1::FixedAdmission)
    }

    fn credential_writer_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<RootStartupCredentialWriterV1<'_>>()
            .checked_mul(3)?
            .checked_add(
                size_of::<Result<RootStartupCredentialWriterV1<'_>, RootStartupJournalErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<(
                    &mut Self,
                    aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<Option<aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>>(
                )
                .checked_mul(2)?,
            )?
            .checked_add(size_of::<Option<RootJournalFinancialOriginalV1>>().checked_mul(3)?)?
            .checked_add(size_of::<OrdinaryStartupPurposeV1>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}

impl RootStartupJournalOriginalV1 {
    /// Runs the independent final names post for this actual original purpose.
    ///
    /// # Errors
    /// Refuses repeated or one-off fixed-admission entry and retains actual
    /// selected or ordinary full/partial opening names failures on this owner.
    pub fn finish_names_once_v1(&mut self) -> Result<(), RootStartupJournalErrorV1> {
        match &mut self.storage {
            StartupJournalStorageV1::Selected(selected) => selected.finish_names_once_v1(),
            StartupJournalStorageV1::Ordinary(ordinary) => {
                if ordinary.finished || ordinary.purpose != OrdinaryStartupPurposeV1::StartupHeld {
                    return Err(RootStartupJournalErrorV1::Closed);
                }
                ordinary.finished = true;
                ordinary.final_names = Some(RootPolicyNameObservationOriginalV1::new());
                ordinary
                    .final_names
                    .as_mut()
                    .ok_or(RootStartupJournalErrorV1::Closed)?
                    .observe_startup_final_ordinary_once_v1(&ordinary.opening)
                    .map_err(|()| RootStartupJournalErrorV1::Names)
            }
        }
    }
}
