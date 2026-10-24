//! Retains the existing-only ordinary genesis opening in its original order.
//!
//! The target is fixed inside the native journal factory. This owner accepts no
//! supplied writer, map, credential, physical witness or successful replay DTO.

use std::error::Error;

use aos_sandbox_broker::root_nonce::fresh_root_nonce;

use crate::native::journal::RootPolicyJournalV1;

use super::super::RootAuthorityOriginalV1;
use super::super::currentness::RootAuthorityCurrentCustodyV1;
use super::super::history::RootAuthorityHistoryOriginalV1;
use super::super::names::{RootAuthorityNameRecipeV1, RootAuthorityNamesOriginalV1};
use super::super::pins::RootAuthorityPinsOriginalV1;
use super::{FirstSuccessorWireRecipeV3, RootGenesisOwnerRecipeV3, RootSourceGenesisAuthorityV1};

/// Retains every reached native prefix of an existing-only genesis opening.
///
/// A genuine fixed ordinary open is distinct from selected construction. The
/// independently held administrative originals, fresh kernel nonce and complete
/// history remain resident on failure; no financial handle selects this route.
pub struct RootFirstSourceSuccessorOpeningV2 {
    native: Option<Result<RootPolicyJournalV1, crate::native::PolicyNativeJournalErrorV1>>,
    owner: RootAuthorityNamesOriginalV1,
    pins_owner: RootAuthorityNamesOriginalV1,
    parsed_owner: RootAuthorityNamesOriginalV1,
    pins: Option<RootAuthorityPinsOriginalV1>,
    names: RootAuthorityNamesOriginalV1,
    nonce: Option<std::io::Result<[u8; 16]>>,
    history: RootAuthorityHistoryOriginalV1,
    entered: bool,
    transferred: bool,
    refusal: Option<super::super::RootAuthorityErrorV1>,
}

impl RootFirstSourceSuccessorOpeningV2 {
    /// Creates inert native destinations without IO or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            native: None,
            owner: RootAuthorityNamesOriginalV1::new(),
            pins_owner: RootAuthorityNamesOriginalV1::new(),
            parsed_owner: RootAuthorityNamesOriginalV1::new(),
            pins: Some(RootAuthorityPinsOriginalV1::new()),
            names: RootAuthorityNamesOriginalV1::new(),
            nonce: None,
            history: RootAuthorityHistoryOriginalV1::new(),
            entered: false,
            transferred: false,
            refusal: None,
        }
    }

    /// Opens the fixed existing writer and transfers only its complete owner.
    ///
    /// # Errors
    /// Returns a marker while the same reservoir retains unsafe fixed custody,
    /// administrative credentials, physical names, nonce or complete history.
    pub fn open_into(
        &mut self,
        destination: &mut Option<RootSourceGenesisAuthorityV1>,
        controller_uid: u32,
        source_uid: u32,
    ) -> Result<(), ()> {
        if self.entered || destination.is_some() || controller_uid == 0 || source_uid == 0 {
            self.refusal
                .get_or_insert(super::super::RootAuthorityErrorV1::Conflict);
            return Err(());
        }
        self.entered = true;
        self.native = Some(RootPolicyJournalV1::open_existing_fixed_ordinary_authority_v1());
        let journal = self
            .native
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(())?;

        // These captures remain independent after the first owner refusal. The
        // old pins loader has two additional owner checks around actual capture.
        let _owner = self
            .owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner);
        let pins_owner = self
            .pins_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner);
        if pins_owner.is_ok() {
            let pins = self.pins.as_mut().ok_or(())?;
            pins.capture_once(journal);
            if pins.has_positive_capture_v1() {
                let parsed_owner = self
                    .parsed_owner
                    .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner);
                if parsed_owner.is_ok() {
                    pins.finish_once();
                }
            }
        }
        let _names = self
            .names
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Physical);
        self.nonce = Some(fresh_root_nonce());
        if let Some(pins) = self.pins.as_ref().filter(|pins| pins.ready()) {
            let _history = self.history.observe_once(journal, pins);
        }
        if self.failure().is_some() || !self.history.is_complete() {
            return Err(());
        }
        let names = self.names.names().ok_or(())?;
        let nonce = *self
            .nonce
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(())?;
        match (self.native.take(), self.pins.take()) {
            (Some(Ok(journal)), Some(pins)) => {
                // All fallible work precedes this one-way native owner transfer.
                *destination = Some(RootSourceGenesisAuthorityV1 {
                    authority: RootAuthorityOriginalV1 {
                        journal,
                        pins,
                        names,
                        current: RootAuthorityCurrentCustodyV1::new(),
                    },
                    nonce,
                    controller_uid,
                    source_uid,
                    accepted: None,
                    genesis_recipe: RootGenesisOwnerRecipeV3::StrictV1,
                    successor_recipe: FirstSuccessorWireRecipeV3::StrictV2,
                    strict: super::strict_custody::RootStrictGenesisCustodyV1::new(),
                });
                self.transferred = true;
                Ok(())
            }
            (native, pins) => {
                self.native = native;
                self.pins = pins;
                Err(())
            }
        }
    }

    /// Opens the same existing native writer for the mixed successor recipe.
    ///
    /// # Errors
    /// Retains the exact existing-only opening failure without provisioning state.
    pub fn open_project_successor_into_v3(
        &mut self,
        destination: &mut Option<RootSourceGenesisAuthorityV1>,
        controller_uid: u32,
        source_uid: u32,
    ) -> Result<(), ()> {
        self.open_into(destination, controller_uid, source_uid)?;
        destination.as_mut().ok_or(())?.successor_recipe = FirstSuccessorWireRecipeV3::MixedV3;
        Ok(())
    }

    /// Opens the same existing native writer for the project genesis recipe.
    ///
    /// # Errors
    /// Retains the exact existing-only opening failure without provisioning state.
    pub fn open_project_genesis_into_v3(
        &mut self,
        destination: &mut Option<RootSourceGenesisAuthorityV1>,
        controller_uid: u32,
        source_uid: u32,
    ) -> Result<(), ()> {
        self.open_into(destination, controller_uid, source_uid)?;
        destination.as_mut().ok_or(())?.genesis_recipe = RootGenesisOwnerRecipeV3::ProjectV3;
        Ok(())
    }

    /// Borrows the earliest actual native failure without another observation.
    #[must_use]
    pub fn error(&self) -> Option<&(dyn Error + 'static)> {
        self.failure()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as _)
            .or_else(|| self.owner.failure())
            .or_else(|| self.pins_owner.failure())
            .or_else(|| self.pins.as_ref().and_then(|pins| pins.failure()))
            .or_else(|| self.parsed_owner.failure())
            .or_else(|| self.names.failure())
            .or_else(|| {
                self.nonce
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.history.failure())
            .or_else(|| self.refusal.as_ref().map(|error| error as _))
    }
}

impl Default for RootFirstSourceSuccessorOpeningV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl RootFirstSourceSuccessorOpeningV2 {
    // The creating ordinary purpose has a different original history/nonce
    // order. It never falls back from an unavailable selected construction.
    pub(super) fn open_creating_into(
        &mut self,
        destination: &mut Option<RootSourceGenesisAuthorityV1>,
        controller_uid: u32,
        source_uid: u32,
    ) -> Result<(), ()> {
        if self.entered || destination.is_some() || controller_uid == 0 || source_uid == 0 {
            self.refusal
                .get_or_insert(super::super::RootAuthorityErrorV1::Conflict);
            return Err(());
        }
        self.entered = true;
        self.native = Some(RootPolicyJournalV1::open_fixed_ordinary_authority_v1());
        let journal = self
            .native
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(())?;
        self.owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)?;
        self.pins_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)?;
        let pins = self.pins.as_mut().ok_or(())?;
        pins.capture_once(journal);
        if !pins.has_positive_capture_v1() {
            return Err(());
        }
        self.parsed_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)?;
        pins.finish_once();
        if !pins.ready() {
            return Err(());
        }
        self.history.observe_once(journal, pins)?;
        self.names
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Physical)?;
        self.nonce = Some(fresh_root_nonce());
        let names = self.names.names().ok_or(())?;
        let nonce = *self
            .nonce
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(())?;
        match (self.native.take(), self.pins.take()) {
            (Some(Ok(journal)), Some(pins)) => {
                *destination = Some(RootSourceGenesisAuthorityV1 {
                    authority: RootAuthorityOriginalV1 {
                        journal,
                        pins,
                        names,
                        current: RootAuthorityCurrentCustodyV1::new(),
                    },
                    nonce,
                    controller_uid,
                    source_uid,
                    accepted: None,
                    genesis_recipe: RootGenesisOwnerRecipeV3::StrictV1,
                    successor_recipe: FirstSuccessorWireRecipeV3::StrictV2,
                    strict: super::strict_custody::RootStrictGenesisCustodyV1::new(),
                });
                self.transferred = true;
                Ok(())
            }
            (native, pins) => {
                self.native = native;
                self.pins = pins;
                Err(())
            }
        }
    }
}

/// Retains the exact failed ordinary opening instead of formatting its cause.
///
/// The returned error owns the same native files, issuer capture, names and
/// complete-history destinations. It grants no retry, selected payer or role.
pub struct RootGenesisOpeningFailureV1 {
    pub(super) original: RootFirstSourceSuccessorOpeningV2,
    pub(super) owner: Option<RootSourceGenesisAuthorityV1>,
    pub(super) returned: Option<super::super::RootAuthorityErrorV1>,
}

impl std::fmt::Debug for RootGenesisOpeningFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootGenesisOpeningFailureV1")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RootGenesisOpeningFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.source() {
            Some(cause) => write!(formatter, "{cause}"),
            None => formatter.write_str("the original Root genesis opening was refused"),
        }
    }
}

impl Error for RootGenesisOpeningFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .failure()
            .or_else(|| {
                self.owner
                    .as_ref()
                    .and_then(|owner| owner.authority.retained_failure())
            })
            .or_else(|| self.returned.as_ref().map(|cause| cause as _))
    }
}

/// Probes the same actual fixed Root history for existing recovery routing.
///
/// Absence is routing DATA, not Source custody or renewed administrative input.
/// The existing creating fixed purpose is preserved. This probe does not sample
/// a new nonce or construct a completed per-flight Authority session.
///
/// # Errors
/// Retains unsafe fixed opening, independent role credentials, changed names or
/// complete-history failures in the same ordinary opening error original.
pub fn fixed_root_source_genesis_recovery_available_v1()
-> Result<bool, super::super::RootAuthorityErrorV1> {
    use super::super::RootAuthorityErrorV1;
    use aos_sandbox_model::RecordNamespace;
    use aos_sandbox_ledger_replay::replay::root_genesis_records::{FLOOR_PREFIX, INTENT_PREFIX};

    let mut original = RootFirstSourceSuccessorOpeningV2::new();
    original.entered = true;
    original.native = Some(RootPolicyJournalV1::open_fixed_ordinary_authority_v1());
    let returned = (|| {
        let journal = original
            .native
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(())?;
        original
            .owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)?;
        let retained = journal
            .records(RecordNamespace::DesiredState)
            .any(|(key, _)| key.starts_with(INTENT_PREFIX) || key.starts_with(FLOOR_PREFIX));
        if !retained {
            return Ok(false);
        }

        original
            .pins_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)?;
        let pins = original.pins.as_mut().ok_or(())?;
        pins.capture_once(journal);
        if !pins.has_positive_capture_v1() {
            return Err(());
        }
        original
            .parsed_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)?;
        pins.finish_once();
        if !pins.ready() {
            return Err(());
        }
        original.history.observe_once(journal, pins)?;
        if !original.history.is_complete() {
            return Err(());
        }
        Ok(true)
    })();
    match returned {
        Ok(retained) => Ok(retained),
        Err(()) => Err(RootAuthorityErrorV1::GenesisOpening(Box::new(
            RootGenesisOpeningFailureV1 {
                original,
                owner: None,
                returned: None,
            },
        ))),
    }
}
