//! Owns actual ordinary Root genesis, successor and Nix server contexts.
//!
//! Each session owns the genuine fixed Authority original and retains its
//! private nonce, signed acceptance, exact role UIDs and purpose. Canonical
//! records and signatures remain DATA; no caller can adopt a journal or create
//! a native crossing from a decoded floor. The selected Q04 owner is separate.

mod admission;
mod advisory;
mod append;
mod capacity;
mod clock;
mod controller_readback;
mod current;
mod deployment;
mod mutation;
mod native_cut;
mod nix;
mod observations;
mod opening;
mod saved_floor;
mod strict_custody;
mod successor;
mod successor_mutation;
mod successor_shape;

use aos_sandbox_ledger_replay::replay::root_genesis_records::{
    RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1,
};
use aos_sandbox_ledger_replay::source_signer_data::VerifiedSourceTreeGenesisReadbackV1;
use aos_sandbox_ledger_replay::source_signer_data::controller_genesis_readback::ControllerGenesisReadbackDataV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use aos_sandbox_protocol::source_genesis_wire::FirstSuccessorWireRecipeV3;

use super::{RootAuthorityErrorV1, RootAuthorityOriginalV1};

pub(in crate::native) use advisory::RootGenesisAdvisoryCutV1;
pub use current::{
    CurrentRootFirstSourceSuccessorFloorV2, CurrentRootProjectSuccessorFloorV3,
    CurrentRootSourceGenesisFloorV1, CurrentRootSourceProjectGenesisFloorV3,
};
pub(in crate::native) use native_cut::{
    GlobalRootGenesisNativeCutV2, RootGenesisCapacityCutDataV1, RootProjectGenesisNativeCutV3,
    RootStrictGenesisNativeCutV1, RootSuccessorNativeServerCutV3,
};
pub use nix::CurrentNixRootArchiveAttemptV1;
pub use opening::{
    RootFirstSourceSuccessorOpeningV2, RootGenesisOpeningFailureV1,
    fixed_root_source_genesis_recovery_available_v1,
};
pub use strict_custody::RootStrictGenesisFailureV1;
pub use successor_mutation::RootFirstSuccessorMutationResultsV2;
pub(in crate::native) use successor_shape::RootSuccessorAdvisoryCutV1;

const INSTANCE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.source-genesis.root-instance-transaction.v1\0";
const MAXIMUM_PROJECTS: usize = 4096;

/// Retains the same real Authority and one original ordinary server flight.
///
/// The independent native writer, administrative credentials, complete history
/// and currentness live in Authority. This session adds only its own original
/// nonce/UID/admission and strict-versus-project recipe, never a new account.
pub struct RootSourceGenesisAuthorityV1 {
    authority: RootAuthorityOriginalV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
    accepted: Option<ControllerGenesisReadbackDataV1>,
    genesis_recipe: RootGenesisOwnerRecipeV3,
    successor_recipe: FirstSuccessorWireRecipeV3,
    strict: strict_custody::RootStrictGenesisCustodyV1,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RootGenesisOwnerRecipeV3 {
    StrictV1,
    ProjectV3,
}

impl RootSourceGenesisAuthorityV1 {
    /// Opens the actual creating ordinary fixed Authority for one server flight.
    ///
    /// This explicit old ordinary recipe creates no selected invocation or
    /// account and never substitutes for unavailable selected finance.
    ///
    /// # Errors
    /// Retains unsafe native opening, independent credential, complete history,
    /// fresh nonce and final currentness failures in the actual owning error.
    pub fn open_fixed(controller_uid: u32, source_uid: u32) -> Result<Self, RootAuthorityErrorV1> {
        if controller_uid == 0 || source_uid == 0 {
            return Err(RootAuthorityErrorV1::NonCanonical);
        }
        let mut original = RootFirstSourceSuccessorOpeningV2::new();
        let mut owner = None;
        if original
            .open_creating_into(&mut owner, controller_uid, source_uid)
            .is_err()
        {
            return Err(RootAuthorityErrorV1::GenesisOpening(Box::new(
                RootGenesisOpeningFailureV1 {
                    original,
                    owner,
                    returned: None,
                },
            )));
        }
        let Some(actual) = owner.take() else {
            return Err(RootAuthorityErrorV1::GenesisOpening(Box::new(
                RootGenesisOpeningFailureV1 {
                    original,
                    owner,
                    returned: None,
                },
            )));
        };
        if let Err(cause) = actual.recheck() {
            return Err(RootAuthorityErrorV1::GenesisOpening(Box::new(
                RootGenesisOpeningFailureV1 {
                    original,
                    owner: Some(actual),
                    returned: Some(cause),
                },
            )));
        }
        Ok(actual)
    }

    /// Rechecks the same actual writer, pins and complete saved history.
    ///
    /// # Errors
    /// Refuses changed native custody or any altered complete role association,
    /// retaining the reached failed native prefix in this same Authority.
    pub fn recheck(&self) -> Result<(), RootAuthorityErrorV1> {
        self.authority.recheck()
    }

    /// Borrows a reached native failure without opening or observing again.
    #[must_use]
    pub fn retained_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.authority.retained_failure()
    }
}

/// Retains actual selected Root mutations, source verification and clock debts.
pub struct RootProjectGenesisMutationResultsV3 {
    source: Option<
        Result<
            aos_sandbox_ledger_replay::source_signer_data::VerifiedSourceProjectGenesisReadbackV3,
            aos_sandbox_ledger_replay::source_signer_data::SourceHoldReadbackErrorV1,
        >,
    >,
    global_source: Option<
        Result<
            VerifiedSourceTreeGenesisReadbackV1,
            aos_sandbox_ledger_replay::source_signer_data::SourceHoldReadbackErrorV1,
        >,
    >,
    instance_preparation: Option<Result<(), RootAuthorityErrorV1>>,
    instance_transaction: Option<JournalTransaction>,
    instance_native: Option<
        Result<
            aos_sandbox_broker::canonical_journal::CommitResult,
            crate::native::PolicyNativeJournalErrorV1,
        >,
    >,
    instance_readback: Option<Result<(), RootAuthorityErrorV1>>,
    preparation: Option<Result<(), RootAuthorityErrorV1>>,
    transaction: Option<JournalTransaction>,
    prepared: Option<capacity::PreparedRootGenesisCapacityOriginalV1>,
    reservation: Option<capacity::RootGenesisCapacityOriginalV1>,
    native_prepare: Option<
        Result<
            (
                aos_sandbox_broker::canonical_journal::CommitResult,
                capacity::RootGenesisCapacityOriginalV1,
            ),
            crate::native::PolicyNativeJournalErrorV1,
        >,
    >,
    native_anchor: Option<
        Result<
            aos_sandbox_broker::canonical_journal::CommitResult,
            crate::native::PolicyNativeJournalErrorV1,
        >,
    >,
    intent: Option<RootSourceGenesisIntentRecordV1>,
    floor: Option<SourceHierarchyFloorRecordV1>,
    readback: Option<Result<(), RootAuthorityErrorV1>>,
    post: Option<Result<(), RootAuthorityErrorV1>>,
    clock_post: Option<Result<aos_sandbox_model::RawPairedClockSample, RootAuthorityErrorV1>>,
    instance_crossing: native_cut::RootGenesisNativeCrossingOriginalV1,
    instance_advisory: native_cut::RootGenesisNativeCrossingOriginalV1,
    prepare_crossing: native_cut::RootGenesisNativeCrossingOriginalV1,
    anchor_crossing: native_cut::RootGenesisNativeCrossingOriginalV1,
    first_advisory: native_cut::RootGenesisNativeCrossingOriginalV1,
    commit_advisory: native_cut::RootGenesisNativeCrossingOriginalV1,
    recovery_owner: super::names::RootAuthorityNamesOriginalV1,
    first_failure: Option<RootProjectGenesisSiteV3>,
}
impl Default for RootProjectGenesisMutationResultsV3 {
    fn default() -> Self {
        Self {
            source: None,
            global_source: None,
            instance_preparation: None,
            instance_transaction: None,
            instance_native: None,
            instance_readback: None,
            preparation: None,
            transaction: None,
            prepared: None,
            reservation: None,
            native_prepare: None,
            native_anchor: None,
            intent: None,
            floor: None,
            readback: None,
            post: None,
            clock_post: None,
            instance_crossing: native_cut::RootGenesisNativeCrossingOriginalV1::new(),
            instance_advisory: native_cut::RootGenesisNativeCrossingOriginalV1::new(),
            prepare_crossing: native_cut::RootGenesisNativeCrossingOriginalV1::new(),
            anchor_crossing: native_cut::RootGenesisNativeCrossingOriginalV1::new(),
            first_advisory: native_cut::RootGenesisNativeCrossingOriginalV1::new(),
            commit_advisory: native_cut::RootGenesisNativeCrossingOriginalV1::new(),
            recovery_owner: super::names::RootAuthorityNamesOriginalV1::new(),
            first_failure: None,
        }
    }
}

#[derive(Clone, Copy)]
enum RootProjectGenesisSiteV3 {
    Source,
    GlobalSource,
    InstancePreparation,
    InstanceNative,
    InstanceReadback,
    Preparation,
    NativePrepare,
    NativeAnchor,
    Readback,
    Post,
    Clock,
}

impl RootProjectGenesisMutationResultsV3 {
    /// Creates a single-use inert custody reservoir.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the original first failing Result without another observation.
    pub fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            RootProjectGenesisSiteV3::Source => {
                self.source.as_ref()?.as_ref().err().map(|e| e as _)
            }
            RootProjectGenesisSiteV3::GlobalSource => {
                self.global_source.as_ref()?.as_ref().err().map(|e| e as _)
            }
            RootProjectGenesisSiteV3::InstancePreparation => self
                .instance_preparation
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as _),
            RootProjectGenesisSiteV3::InstanceNative => self
                .instance_crossing
                .failure()
                .or_else(|| self.instance_advisory.failure())
                .or_else(|| {
                    self.instance_native
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|e| e as _)
                }),
            RootProjectGenesisSiteV3::InstanceReadback => self
                .instance_readback
                .as_ref()?
                .as_ref()
                .err()
                .map(|e| e as _),
            RootProjectGenesisSiteV3::Preparation => self
                .prepared
                .as_ref()
                .and_then(|prepared| prepared.failure())
                .or_else(|| self.recovery_owner.failure())
                .or_else(|| self.first_advisory.failure())
                .or_else(|| self.preparation.as_ref()?.as_ref().err().map(|e| e as _)),
            RootProjectGenesisSiteV3::NativePrepare => self
                .commit_advisory
                .failure()
                .or_else(|| self.prepare_crossing.failure())
                .or_else(|| self.native_prepare.as_ref()?.as_ref().err().map(|e| e as _)),
            RootProjectGenesisSiteV3::NativeAnchor => self
                .commit_advisory
                .failure()
                .or_else(|| self.anchor_crossing.failure())
                .or_else(|| self.native_anchor.as_ref()?.as_ref().err().map(|e| e as _)),
            RootProjectGenesisSiteV3::Readback => {
                self.readback.as_ref()?.as_ref().err().map(|e| e as _)
            }
            RootProjectGenesisSiteV3::Post => self.post.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisSiteV3::Clock => {
                self.clock_post.as_ref()?.as_ref().err().map(|e| e as _)
            }
        }
    }

    fn latch(&mut self, site: RootProjectGenesisSiteV3, failed: bool) {
        if failed && self.first_failure.is_none() {
            self.first_failure = Some(site);
        }
    }

    fn posts(
        &mut self,
        owner: &RootSourceGenesisAuthorityV1,
        clock: &aos_sandbox_model::RawPairedClockSample,
        deadline: std::time::Instant,
    ) {
        self.post = Some(owner.recheck());
        self.latch(
            RootProjectGenesisSiteV3::Post,
            self.post.as_ref().is_some_and(Result::is_err),
        );
        self.clock_post = Some(
            clock::observe_original_clock(Some(*clock)).and_then(|current| {
                if std::time::Instant::now() >= deadline {
                    return Err(RootAuthorityErrorV1::Stale);
                }
                Ok(current)
            }),
        );
        self.latch(
            RootProjectGenesisSiteV3::Clock,
            self.clock_post.as_ref().is_some_and(Result::is_err),
        );
    }
}
