//! Parks fixed Authority acquisition and every reached role construction prefix.

use std::error::Error;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1;
use aos_sandbox_broker::receiving::RootInitialReceivingOriginalV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use crate::native::PolicyNativeJournalErrorV1;
use crate::native::journal::{
    RootPolicyJournalConstructionOriginalV1, RootPolicyJournalPurposeV1, RootPolicyJournalV1,
};

use super::RootAuthorityOriginalV1;
use super::currentness::RootAuthorityCurrentCustodyV1;
use super::error::RootAuthorityErrorV1;
use super::history::RootAuthorityHistoryOriginalV1;
use super::names::{RootAuthorityNameRecipeV1, RootAuthorityNamesOriginalV1};
use super::pins::RootAuthorityPinsOriginalV1;

/// Retains a genuine Authority opening until full role checks and native posts.
///
/// The inert constructor allocates nothing. The actual Root receiver funds
/// fixed native capture and captured-prefix/index demand through the existing
/// opening recipe; role capture then uses that same held writer's actual payer.
/// Failed native graphs stay here. No caller-provided map or pins are adopted.
pub struct RootAuthorityConstructionOriginalV1 {
    physical: RootPolicyJournalConstructionOriginalV1,
    ordinary: Option<Result<(), PolicyNativeJournalErrorV1>>,
    journal: Option<RootPolicyJournalV1>,
    pins: Option<RootAuthorityPinsOriginalV1>,
    owner: RootAuthorityNamesOriginalV1,
    pins_owner: RootAuthorityNamesOriginalV1,
    parsed_owner: RootAuthorityNamesOriginalV1,
    physical_names: RootAuthorityNamesOriginalV1,
    history: RootAuthorityHistoryOriginalV1,
    admission: Option<Result<(), PolicyNativeJournalErrorV1>>,
    preparation: Option<Result<ResourceVector, RootAuthorityErrorV1>>,
    body: Option<Result<(), ()>>,
    transfer: Option<Result<(), PolicyNativeJournalErrorV1>>,
    entered: bool,
    native_taken: bool,
    selected_entered: bool,
    transferred: bool,
    transfer_entered: bool,
    closed: bool,
    secondary_panic: Option<Box<dyn std::any::Any + Send>>,
}

impl RootAuthorityConstructionOriginalV1 {
    /// Creates empty role/native destinations without IO, allocation or a grant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            physical: RootPolicyJournalConstructionOriginalV1::new(),
            ordinary: None,
            journal: None,
            pins: Some(RootAuthorityPinsOriginalV1::new()),
            owner: RootAuthorityNamesOriginalV1::new(),
            pins_owner: RootAuthorityNamesOriginalV1::new(),
            parsed_owner: RootAuthorityNamesOriginalV1::new(),
            physical_names: RootAuthorityNamesOriginalV1::new(),
            history: RootAuthorityHistoryOriginalV1::new(),
            admission: None,
            preparation: None,
            body: None,
            transfer: None,
            entered: false,
            native_taken: false,
            selected_entered: false,
            transferred: false,
            transfer_entered: false,
            closed: false,
            secondary_panic: None,
        }
    }

    /// Bounds the real fixed physical constructor and role/header return planes.
    ///
    /// Dynamic index/history and later native role observations remain separate
    /// actual stages, paid before growth. This comparison DATA is no permit.
    ///
    /// # Errors
    /// Preserves the shared fixed opening geometry and checked overflow.
    pub fn fixed_demand_v1() -> Result<ResourceVector, RootAuthorityErrorV1> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<RootAuthorityOriginalV1>().checked_mul(3)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(PolicyNativeJournalErrorV1::geometry)?;
        RootPolicyJournalConstructionOriginalV1::fixed_demand_v1(
            RootPolicyJournalPurposeV1::CurrentAuthority,
        )?
        // Four actual inline name originals own separate retained controls:
        // owner, pin-loader owner, parsed-owner and physical names.
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::MetadataEntries, crate::native::RootPolicyNameObservationOriginalV1::retained_control_cells_v1() * 4))
        .map_err(|_| PolicyNativeJournalErrorV1::geometry().into())
    }

    /// Enters the genuine once-only current Authority opening on the Root owner.
    pub fn prepare_once(&mut self, initial: &mut RootInitialReceivingOriginalV1) {
        if self.ordinary.is_some() || self.selected_entered {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return;
        }
        self.selected_entered = true;
        self.physical
            .prepare_once(initial, RootPolicyJournalPurposeV1::CurrentAuthority);
        self.physical.observe_names_before_once();
    }

    /// Opens the existing ordinary factory through its actual fixed native recipe.
    ///
    /// This explicit entry does not borrow Initial, receive an account or claim
    /// a selected purpose. It is never selected by absence of financial custody.
    /// The real ordinary caller retains its legacy startup and original peer.
    pub fn open_fixed_ordinary_once_v1(&mut self) {
        if self.native_taken
            || self.ordinary.is_some()
            || self.selected_entered
            || self.entered
            || self.closed
        {
            self.closed = true;
            return;
        }
        self.native_taken = true;
        let returned = RootPolicyJournalV1::open_fixed_ordinary_authority_v1();
        self.ordinary = Some(match returned {
            Ok(journal) => {
                self.journal = Some(journal);
                Ok(())
            }
            Err(error) => Err(error),
        });
    }

    /// Borrows the actual captured native prefix without replay or adoption.
    #[must_use]
    pub fn extent(&self) -> Option<&CanonicalReplayExtentDataV1> {
        self.physical.extent()
    }

    /// Bounds the same captured prefix's actual canonical index constructor.
    ///
    /// # Errors
    /// Rejects incomplete fixed capture or checked index geometry overflow.
    pub fn index_demand_v1(&self) -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        self.physical.index_demand_v1()
    }

    /// Runs the sole full semantic replay on the actual opening's same cursor.
    pub fn replay_once(&mut self) {
        self.physical.replay_once();
    }

    /// Runs the independently owed same-name post even after replay refusal.
    pub fn finish_names_once(&mut self) {
        self.physical.finish_names_once();
    }

    /// Requires the same completed physical replay and independently owed names.
    ///
    /// This observes only retained stages. Role completion and its actual debit
    /// remain a separate step after the upper L/U financial guards release.
    #[must_use]
    pub fn replay_ready_v1(&self) -> bool {
        self.physical.ready()
    }

    /// Reports the actual parked writer before later role completion.
    ///
    /// This opened-only availability check deliberately adds no financial or
    /// role-health gate that could suppress an independently owed observation.
    #[must_use]
    pub fn native_taken_ready_v1(&self) -> bool {
        self.native_taken && self.journal.is_some()
    }

    /// Parks the completed physical journal before later independent role work.
    ///
    /// Callers finish and release their opening financial guards before entering
    /// `complete_role_once`, whose real debit must not reenter an already held L.
    pub fn take_native_once(&mut self) {
        if self.native_taken {
            self.closed = true;
            return;
        }
        self.native_taken = true;
        self.journal = self.physical.take_journal_once();
    }

    fn role_demand_v1() -> Result<ResourceVector, RootAuthorityErrorV1> {
        let overflow = || PolicyNativeJournalErrorV1::geometry();
        let pins = RootAuthorityPinsOriginalV1::fixed_demand_v1().ok_or_else(overflow)?;
        let owner =
            RootAuthorityNamesOriginalV1::fixed_demand_v1(RootAuthorityNameRecipeV1::Owner)?;
        let physical =
            RootAuthorityNamesOriginalV1::fixed_demand_v1(RootAuthorityNameRecipeV1::Physical)?;
        pins.checked_add(owner)
            .and_then(|demand| demand.checked_add(physical))
            .map_err(|_| overflow().into())
    }

    /// Captures independent pins and checks the whole role after physical transfer.
    ///
    /// This actual held writer pays role demand before native capture or tuple
    /// construction. The independent pin post runs after failure and unwinding;
    /// full history is validated only after its exact positive credential cut.
    ///
    /// # Errors
    /// Returns a marker while the real fixed native, credential, payer and
    /// complete-history failures remain in this original.
    ///
    /// # Panics
    /// Resumes an actual native panic only after the independent pin post, while
    /// retaining the same failed graph and any later panic payload here.
    pub fn complete_role_once(&mut self) -> Result<(), ()> {
        if self.entered || self.transferred || self.closed {
            self.closed = true;
            return Err(());
        }
        self.entered = true;
        if self.ordinary.is_some() {
            return self.complete_ordinary_role_body_v1();
        }
        self.preparation = Some(Self::role_demand_v1());
        let demand = match self.preparation.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(()),
        };
        self.admission = self
            .journal
            .as_ref()
            .map(|journal| journal.admit_role_observation_v1(demand));
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(());
        }
        let journal = self.journal.as_ref().ok_or(())?;
        let pins = self.pins.as_mut().ok_or(())?;
        let capture = catch_unwind(AssertUnwindSafe(|| pins.capture_once(journal)));
        let post = catch_unwind(AssertUnwindSafe(|| pins.finish_once()));
        match (capture, post) {
            (Err(primary), Err(later)) => {
                self.secondary_panic = Some(later);
                resume_unwind(primary);
            }
            (Err(primary), Ok(())) | (Ok(()), Err(primary)) => resume_unwind(primary),
            (Ok(()), Ok(())) => {}
        }
        self.body = Some((|| {
            if !pins.ready() {
                return Err(());
            }
            self.owner
                .observe_once(journal, RootAuthorityNameRecipeV1::Owner)?;
            self.owner.settle_positive_once_v1();
            self.history.observe_once(journal, pins)?;
            self.physical_names
                .observe_once(journal, RootAuthorityNameRecipeV1::Physical)?;
            self.physical_names.settle_positive_once_v1();
            Ok(())
        })());
        if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn complete_ordinary_role_body_v1(&mut self) -> Result<(), ()> {
        if !matches!(self.ordinary, Some(Ok(()))) {
            return Err(());
        }
        let journal = self.journal.as_ref().ok_or(())?;
        let pins = self.pins.as_mut().ok_or(())?;
        // Preserve open_fixed's owner gate and the pin loader's independent
        // owner gate before either administrative credential is captured.
        self.owner
            .observe_once(journal, RootAuthorityNameRecipeV1::Owner)?;
        self.owner.settle_positive_once_v1();
        self.pins_owner
            .observe_once(journal, RootAuthorityNameRecipeV1::Owner)?;
        self.pins_owner.settle_positive_once_v1();
        pins.capture_once(journal);
        if !pins.has_positive_capture_v1() {
            return Err(());
        }
        // The old load's parsed-owner check precedes its two credential
        // readbacks. A malformed tuple never enters that later native work.
        self.parsed_owner
            .observe_once(journal, RootAuthorityNameRecipeV1::Owner)?;
        self.parsed_owner.settle_positive_once_v1();
        pins.finish_once();
        self.body = Some((|| {
            if !pins.ready() {
                return Err(());
            }
            self.history.observe_once(journal, pins)?;
            self.physical_names
                .observe_once(journal, RootAuthorityNameRecipeV1::Physical)?;
            self.physical_names.settle_positive_once_v1();
            Ok(())
        })());
        if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Transfers only the completed same physical owner and actual pin originals.
    ///
    /// All fallible checks precede native movement. Missing fields are restored
    /// before refusal, and no externally supplied owner or result is accepted.
    #[must_use]
    pub fn take_authority_once(&mut self) -> Option<RootAuthorityOriginalV1> {
        if self.transferred
            || self.transfer_entered
            || self.closed
            || !matches!(self.body, Some(Ok(())))
            || !self.history.is_complete()
            || !self.pins.as_ref().is_some_and(|pins| pins.ready())
        {
            return None;
        }
        self.transfer_entered = true;
        self.transfer = self
            .journal
            .as_ref()
            .map(|journal| journal.require_native_original());
        if !matches!(self.transfer, Some(Ok(()))) {
            return None;
        }
        let names = self.physical_names.names()?;
        match (self.journal.take(), self.pins.take()) {
            (Some(journal), Some(pins)) => {
                self.transferred = true;
                Some(RootAuthorityOriginalV1 {
                    journal,
                    pins,
                    names,
                    current: RootAuthorityCurrentCustodyV1::new(),
                })
            }
            (journal, pins) => {
                self.journal = journal;
                self.pins = pins;
                None
            }
        }
    }

    /// Borrows the first reached real construction error without new observations.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.ordinary
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as _)
            .or_else(|| self.physical.failure())
            .or_else(|| self.owner.failure())
            .or_else(|| self.pins_owner.failure())
            .or_else(|| {
                self.preparation
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.admission
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.pins.as_ref().and_then(|pins| pins.failure()))
            .or_else(|| self.parsed_owner.failure())
            .or_else(|| self.history.failure())
            .or_else(|| self.physical_names.failure())
            .or_else(|| {
                self.transfer
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
    }
}

impl Default for RootAuthorityConstructionOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}
