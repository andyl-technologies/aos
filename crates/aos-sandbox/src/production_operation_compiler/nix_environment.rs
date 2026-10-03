//! Concrete fixed-credential selection for retained authenticated Start work.
//!
//! This owner consumes original PID1 startup capture, retains only fixed public
//! credentials, and selects a signed recipe only for vacant idempotency. It
//! admits a durable continuation, not a Nix effect, floor or observed result.
//!
//! ```text
//! catalog = AOSNRC02 || version:u16be=2 || reserved:6=0 || count:u32be ||
//!           (length:u32be || original-signed-recipe)[count] || sha256:32
//! ```
//!
//! The fixed domain credential uses canonical compact JSON, with identifiers
//! serialized by their existing Core data codecs:
//!
//! ```text
//! {"version":2,"identities":[controllerUID,controllerGID,builderUID,builderGID],
//!  "node":...,"deployment":...,"endpoint":...,"domain":...,
//!  "domain_commitment":...,"disclosure":...}
//! ```
//!
//! Retained admission keeps the same lower credential reservoir, including its
//! original descriptors, behind one closed synchronization boundary. Public
//! DATA and terminal causes borrow a move-only guard rather than detached
//! preimages. The legacy consuming constructor retains its original storage
//! and observation order. Neither route grants a physical floor or drain.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError};

use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;
use aos_sandbox_broker_session_protocol::manifest::{
    BrokerSessionManifestAudienceV1, BrokerSessionManifestV1,
};
use aos_sandbox_core::format::decode_trust_policy;
use aos_sandbox_core::{
    BrokerPlanTrustAnchor, DecodeLimits, KeyUsage, MediaType, NodeId, ObjectDescriptor,
    ObjectDigest, OperationId, OwnershipLeaseTrustAnchor, PortableMediaType,
    RevocationScopeId, SandboxId, SignaturePurpose, descriptor_for_bytes,
};
use aos_sandbox_ownership_protocol::{OwnershipAuthorityVerifier, UnverifiedOwnershipLeaseResponse};
use aos_sandbox_protocol::nix_build::{
    NIX_REQUEST_MAXIMUM_BYTES_V2, NixBuildSchemaErrorV2, VerifiedNixRecipeArtifactV2,
    verify_nix_recipe_artifact_v2,
};
use sha2::{Digest as _, Sha256};

use crate::Journal;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use crate::normal_root::{ProductionControllerNixStartupCaptureV1, ProductionControllerNixStartupV1};
use crate::public_api_session::{
    ControllerNixPublicCredentialCustodyV1, PinnedSystemdCredential,
};
use crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1;
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityLimits, RuntimeAuthorityStore};
use crate::runtime_scope::{CurrentRuntimeScopePolicy, RuntimeScopeHolder};

mod authority;
mod carrier;
mod continuation;
mod fixed_domain;

pub(crate) use authority::CheckedStartAuthorityV2;
pub(crate) use carrier::NixStartAdmissionCarrierV2;
use carrier::OriginalAssignmentV2;
pub use continuation::{CurrentRetainedNixStartV2, NixStartContinuationErrorV2};
pub use fixed_domain::{NixFixedDomainPinsDataV2, NixFixedDomainPinsDecodeErrorV2};

const CATALOG_MAGIC: &[u8; 8] = b"AOSNRC02";
const CATALOG_DOMAIN: &[u8] = b"aos.sandbox.nix.recipe-catalog.v2\0";
const MAXIMUM_CATALOG_BYTES: usize = 1_048_576;

/// Reports failure to retain an authentic, bounded original Start continuation.
///
/// Retained-custody variants are additions to this exhaustive public enum.
/// External exhaustive matches must account for them. Their actual nested
/// causes remain in the same owner and are borrowed through its failure loan.
#[derive(Debug, thiserror::Error)]
pub enum NixStartAdmissionErrorV2 {
    /// Original installed startup custody changed or cannot be admitted.
    #[error(transparent)]
    Startup(#[from] crate::normal_root::NormalRootStartupErrorV1),
    /// A fixed public credential is unavailable, unsafe or changed.
    #[error(transparent)]
    Credential(#[from] crate::public_api_session::PublicApiSessionError),
    /// The independent signed recipe is malformed or unauthentic.
    #[error(transparent)]
    Recipe(#[from] NixBuildSchemaErrorV2),
    /// Genuine pre-launch assignment selection or verification failed.
    #[error(transparent)]
    Assignment(#[from] crate::runtime_scope::CurrentRuntimeScopeError),
    /// Protected Controller journal custody failed.
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    /// Canonical historical data cannot be encoded or decoded within its cap.
    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
    /// Original/current identity, bounds, ledger or credential pins disagree.
    #[error("retained Nix Start admission is unavailable or inconsistent")]
    Invalid,
    /// The same retained credential owner is permanently closed.
    #[error("Controller Nix original credential custody is closed")]
    CredentialCustodyClosed,
    /// Another loan prevents access to the same retained credential owner.
    #[error("Controller Nix original credential custody is already borrowed")]
    CredentialCustodyContended,
    /// An interrupted mutex owner cannot be borrowed without recovery.
    #[error("Controller Nix original credential custody is poisoned")]
    CredentialCustodyPoisoned,
    /// An abandoned or unwinding observation permanently closed the owner.
    #[error("Controller Nix original credential observation was interrupted")]
    CredentialCustodyInterrupted,
    /// The terminal owner cannot lend its original recorded cause.
    #[error("Controller Nix original credential cause is unavailable")]
    CredentialCauseUnavailable,
}

/// Owns original installed startup and twelve exact fixed PUBLIC credentials.
///
/// Construction cannot accept caller paths, keys, policies, catalogs or a
/// synthetic startup token. Retained recipes remain separate from Controller
/// admission and never choose the durable operation identity.
pub struct ControllerNixStartRecipeSelectorV2 {
    startup: Arc<ProductionControllerNixStartupV1>,
    pins: NixFixedDomainPinsDataV2,
    credentials: SelectorPublicCredentials,
    recipes: Vec<VerifiedNixRecipeArtifactV2>,
}

impl std::fmt::Debug for ControllerNixStartRecipeSelectorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerNixStartRecipeSelectorV2(<retained fixed custody>)")
    }
}

/// Borrows the same first owning selector or nested Nix refusal.
///
/// Diagnostics expose a fixed class only, not credential bytes or paths.
/// Retained-credential variants extend this exhaustive public enum and require
/// external exhaustive matches to be updated.
pub enum ControllerNixSelectorFailureRefV2<'attempt> {
    /// The selector retains this actual credential/codec/policy cause.
    Selector(&'attempt NixStartAdmissionErrorV2),
    /// The same nested capture retains its actual lower cause.
    Nix(&'attempt crate::normal_root::NormalRootStartupErrorV1),
    /// The plain admission reservoir retains this actual lower cause.
    Credential(&'attempt (dyn std::error::Error + 'static)),
    /// The completed selector lends its same guard-bound terminal cause.
    CredentialLoan(ControllerNixPublicDataLoanV2<'attempt>),
    /// Diagnosis is unavailable without recovering or replacing the owner.
    CredentialUnavailable(NixStartAdmissionErrorV2),
    /// The original attempt is irreversibly closed.
    Closed,
}

impl std::fmt::Debug for ControllerNixSelectorFailureRefV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Selector(_) => "Controller Nix selector admission refused",
            Self::Nix(_) => "Controller Nix original startup refused",
            Self::Credential(_) | Self::CredentialLoan(_) => {
                "Controller Nix original credentials refused"
            }
            Self::CredentialUnavailable(_) => "Controller Nix original cause unavailable",
            Self::Closed => "Controller Nix selector admission closed",
        })
    }
}

enum SelectorAdmissionFailure {
    Selector(NixStartAdmissionErrorV2),
    Nix,
    Credentials,
    Closed,
}

/// Retains one same-capture admission and every returned fixed public credential.
///
/// Failed/abandoned/unwinding attempts abort before field release. This is not
/// funding, physical drain or public readiness. The fixed lower reservoir owns
/// returned credential descriptors and buffers before later checks.
#[must_use]
pub struct ControllerNixSelectorAdmissionV2 {
    capture: ProductionControllerNixStartupCaptureV1,
    controller_uid: u32,
    controller_gid: u32,
    node: NodeId,
    credentials: Option<ControllerNixPublicCredentialCustodyV1>,
    pins: Option<NixFixedDomainPinsDataV2>,
    startup: Option<Arc<ProductionControllerNixStartupV1>>,
    recipes: Option<Vec<VerifiedNixRecipeArtifactV2>>,
    completed: Option<ControllerNixStartRecipeSelectorV2>,
    attempted: bool,
    first_failure: Option<SelectorAdmissionFailure>,
    armed: bool,
    not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
}

enum SelectorPublicCredentials {
    Legacy([PinnedSystemdCredential; 12]),
    Retained(RetainedControllerPublics),
}

// Only this fixed Controller owner is synchronized. A failure record never
// becomes a permit, and no caller supplies a loader, endpoint or policy.
struct RetainedControllerPublics {
    original: Mutex<ControllerNixPublicCredentialCustodyV1>,
    failure: OnceLock<PublicCredentialRefusal>,
}

#[derive(Debug, thiserror::Error)]
enum PublicCredentialRefusal {
    #[error("the original lower credential owner refused")]
    Lower,
    #[error("the original Nix startup refused")]
    Startup(#[source] crate::normal_root::NormalRootStartupErrorV1),
    #[error("the original credential owner is already borrowed")]
    Contended,
    #[error("the original credential owner is poisoned")]
    Poisoned,
    #[error("the original credential observation was interrupted")]
    Interrupted,
}

impl RetainedControllerPublics {
    fn new(original: ControllerNixPublicCredentialCustodyV1) -> Self {
        Self {
            original: Mutex::new(original),
            failure: OnceLock::new(),
        }
    }

    fn record(&self, cause: PublicCredentialRefusal) {
        // Losing a later refusal cannot displace the actual first cause.
        let _ = self.failure.set(cause);
    }

    fn refusal(&self) -> NixStartAdmissionErrorV2 {
        match self.failure.get() {
            Some(PublicCredentialRefusal::Contended) => {
                NixStartAdmissionErrorV2::CredentialCustodyContended
            }
            Some(PublicCredentialRefusal::Poisoned) => {
                NixStartAdmissionErrorV2::CredentialCustodyPoisoned
            }
            Some(PublicCredentialRefusal::Interrupted) => {
                NixStartAdmissionErrorV2::CredentialCustodyInterrupted
            }
            _ => NixStartAdmissionErrorV2::CredentialCustodyClosed,
        }
    }

    fn borrow(
        &self,
        disposition: PublicLoanDisposition,
    ) -> Result<RetainedPublicGuard<'_>, NixStartAdmissionErrorV2> {
        let diagnostic = matches!(disposition, PublicLoanDisposition::Diagnosis);
        if !diagnostic && self.failure.get().is_some() {
            return Err(self.refusal());
        }

        let original = match self.original.try_lock() {
            Ok(original) => original,
            Err(TryLockError::WouldBlock) => {
                if !diagnostic {
                    self.record(PublicCredentialRefusal::Contended);
                }
                return Err(NixStartAdmissionErrorV2::CredentialCustodyContended);
            }
            Err(TryLockError::Poisoned(_)) => {
                if !diagnostic {
                    self.record(PublicCredentialRefusal::Poisoned);
                }
                return Err(NixStartAdmissionErrorV2::CredentialCustodyPoisoned);
            }
        };
        let guard = RetainedPublicGuard {
            owner: self,
            original,
            disposition,
        };

        if !diagnostic && self.failure.get().is_some() {
            // A concurrent refusal remains terminal even after lock acquisition.
            return Err(guard.close());
        }
        Ok(guard)
    }
}

#[derive(Clone, Copy)]
enum PublicLoanDisposition {
    Observation,
    Data,
    Diagnosis,
}

struct RetainedPublicGuard<'owner> {
    owner: &'owner RetainedControllerPublics,
    original: MutexGuard<'owner, ControllerNixPublicCredentialCustodyV1>,
    disposition: PublicLoanDisposition,
}

impl RetainedPublicGuard<'_> {
    fn fail(mut self, cause: PublicCredentialRefusal) -> NixStartAdmissionErrorV2 {
        self.owner.record(cause);
        self.original.fence();
        self.disposition = PublicLoanDisposition::Data;
        self.owner.refusal()
    }

    fn close(mut self) -> NixStartAdmissionErrorV2 {
        self.original.fence();
        self.disposition = PublicLoanDisposition::Data;
        self.owner.refusal()
    }

    fn finish(mut self) -> Result<Self, NixStartAdmissionErrorV2> {
        if self.owner.failure.get().is_some() {
            return Err(self.close());
        }
        // This final read is the success linearization point, not revocation
        // of earlier borrowed DATA or an atomic external policy snapshot.
        self.disposition = PublicLoanDisposition::Data;
        Ok(self)
    }
}

impl Drop for RetainedPublicGuard<'_> {
    fn drop(&mut self) {
        let interrupted = matches!(self.disposition, PublicLoanDisposition::Observation)
            || (matches!(self.disposition, PublicLoanDisposition::Data)
                && std::thread::panicking());
        if interrupted {
            self.owner.record(PublicCredentialRefusal::Interrupted);
            self.original.fence();
        }
    }
}

enum ControllerPublicLoan<'owner> {
    Legacy(&'owner [PinnedSystemdCredential; 12]),
    Retained(RetainedPublicGuard<'owner>),
}

/// Borrows original Controller public DATA or a terminal credential cause.
///
/// The move-only loan retains the same mutex guard on the retained route.
/// References returned by its accessors borrow this loan, not a detached
/// credential array. It is neither Send nor Sync and grants no currentness,
/// admission, floor, descriptor access or drain. A terminal diagnostic loan
/// cannot lend Ready preimages or resume the original owner.
#[must_use = "keep this loan alive while comparing its original DATA or cause"]
pub struct ControllerNixPublicDataLoanV2<'owner> {
    original: ControllerPublicLoan<'owner>,
    not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
}

impl std::fmt::Debug for ControllerNixPublicDataLoanV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerNixPublicDataLoanV2(<borrowed original custody>)")
    }
}

impl<'owner> ControllerNixPublicDataLoanV2<'owner> {
    fn new(original: ControllerPublicLoan<'owner>) -> Self {
        Self {
            original,
            not_sync: std::marker::PhantomData,
        }
    }

    fn publics(&self) -> Option<[&PinnedSystemdCredential; 12]> {
        match &self.original {
            ControllerPublicLoan::Legacy(original) => Some(original.each_ref()),
            ControllerPublicLoan::Retained(guard) => {
                if matches!(guard.disposition, PublicLoanDisposition::Diagnosis)
                    || guard.owner.failure.get().is_some()
                {
                    return None;
                }
                guard.original.publics()
            }
        }
    }

    /// Borrows twelve original preimages in their fixed order without I/O.
    ///
    /// Returns None for terminal diagnosis or a concurrent original refusal.
    /// These references cannot outlive this loan and are nonauthorizing DATA.
    pub fn preimages(&self) -> Option<[&[u8]; 12]> {
        self.publics().map(|publics| publics.map(PinnedSystemdCredential::bytes))
    }

    /// Borrows the actual first cause without moving or copying it.
    ///
    /// Nested Error::source references share this loan's lifetime. An absent
    /// cause is not a freshness assertion; terminal borrow acquisition reports
    /// unavailable cause custody rather than manufacturing an error.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let ControllerPublicLoan::Retained(guard) = &self.original else {
            return None;
        };
        match guard.owner.failure.get()? {
            PublicCredentialRefusal::Lower => guard.original.failure().map(|cause| {
                cause as &(dyn std::error::Error + 'static)
            }),
            PublicCredentialRefusal::Startup(cause) => Some(cause),
            cause => Some(cause),
        }
    }
}

// Keep the literal legacy expression list. Retained admission selects the sole
// lower fixed-name capture engine, then both routes borrow the same decoders.
// No caller chooses a loader, name, index, policy or execution callback.
macro_rules! selector_loads {
    (legacy, $storage:ident, $originals:ident, $credentials:ident, $( $index:literal => $load:expr ),+ $(,)?) => {
        let $originals = [$( $load? ),+];
        let $credentials = $originals.each_ref();
    };
    (retained, $storage:ident, $originals:ident, $credentials:ident, $( $index:literal => $load:expr ),+ $(,)?) => {
        let lower = $storage.credentials.as_mut().ok_or(SelectorAdmissionFailure::Closed)?;
        if lower.capture().is_err() {
            return Err(SelectorAdmissionFailure::Credentials);
        }
        let $credentials = $storage.credentials.as_ref()
            .and_then(ControllerNixPublicCredentialCustodyV1::publics)
            .ok_or(SelectorAdmissionFailure::Closed)?;
    };
}

macro_rules! selector_bind {
    (legacy, $storage:ident, $name:ident, $expression:expr) => {
        let $name = $expression?;
    };
    (retained, $storage:ident, $name:ident, $expression:expr) => {
        $storage.$name = Some($expression.map_err(SelectorAdmissionFailure::Selector)?);
        let $name = $storage.$name.as_ref().ok_or(SelectorAdmissionFailure::Closed)?;
    };
}

macro_rules! selector_invalid {
    (legacy) => { NixStartAdmissionErrorV2::Invalid };
    (retained) => { SelectorAdmissionFailure::Selector(NixStartAdmissionErrorV2::Invalid) };
}

macro_rules! selector_startup {
    (legacy, $storage:ident, $capture:ident, $pins:ident, $startup:ident) => {
        let $startup = Arc::new($capture.admit_selected($pins.identities)?);
    };
    (retained, $storage:ident, $capture:ident, $pins:ident, $startup:ident) => {
        if $storage.capture.admit_selected_once($pins.identities).is_err() {
            return Err(SelectorAdmissionFailure::Nix);
        }
        if $storage.startup.is_some() {
            return Err(SelectorAdmissionFailure::Closed);
        }
        let Some(original) = $storage.capture.take_admitted_startup() else {
            return Err(SelectorAdmissionFailure::Closed);
        };
        // This existing sharing allocation is a FUNDING exclusion. No
        // recoverable-allocation or universal caught-unwind custody is claimed.
        $storage.startup = Some(Arc::new(original));
    };
}

macro_rules! selector_finish {
    (legacy, $storage:ident, $startup:ident, $pins:ident, $originals:ident, $recipes:ident) => {
        let owner = Self {
            startup: $startup, pins: $pins,
            credentials: SelectorPublicCredentials::Legacy($originals), recipes: $recipes,
        };
        owner.recheck()?;
        owner.assignment_policy()?;
        Ok(owner)
    };
    (retained, $storage:ident, $startup:ident, $pins:ident, $originals:ident, $recipes:ident) => {
        $storage.assemble_selector()?;
        let owner = $storage.completed.as_ref().ok_or(SelectorAdmissionFailure::Closed)?;
        owner.recheck().map_err(SelectorAdmissionFailure::Selector)?;
        owner.assignment_policy().map_err(SelectorAdmissionFailure::Selector)?;
        Ok(())
    };
}

macro_rules! selector_admission_recipe {
    ($mode:ident, $storage:ident, $capture:ident, $uid:ident, $gid:ident, $node:ident) => {{
        selector_loads!($mode, $storage, originals, credentials,
            0 => PinnedSystemdCredential::load_nix_recipe_issuer_v2(),
            1 => PinnedSystemdCredential::load_nix_fixed_domain_pins_v2(),
            2 => PinnedSystemdCredential::load_nix_broker_session_manifest_v1(),
            3 => PinnedSystemdCredential::load_nix_preadmitted_recipes_v2(),
            4 => PinnedSystemdCredential::load_nix_ownership_policy(),
            5 => PinnedSystemdCredential::load_nix_ownership_public_key(),
            6 => PinnedSystemdCredential::load_nix_host_plan_policy(),
            7 => PinnedSystemdCredential::load_nix_host_plan_public_key(),
            8 => PinnedSystemdCredential::load_nix_host_plan_revocation_scope(),
            9 => PinnedSystemdCredential::load_nix_mount_plan_policy(),
            10 => PinnedSystemdCredential::load_nix_mount_plan_public_key(),
            11 => PinnedSystemdCredential::load_nix_mount_plan_revocation_scope(),
        );
        selector_bind!($mode, $storage, pins, decode_public_domain_pins(&credentials));
        if pins.node != $node || pins.identities[..2] != [$uid, $gid] {
            return Err(selector_invalid!($mode));
        }
        selector_startup!($mode, $storage, $capture, pins, startup);
        selector_bind!($mode, $storage, recipes, decode_public_catalog(&credentials, &pins, $node));
        selector_finish!($mode, $storage, startup, pins, originals, recipes)
    }};
}

impl ControllerNixSelectorAdmissionV2 {
    fn new(capture: ProductionControllerNixStartupCaptureV1, controller_uid: u32, controller_gid: u32, node: NodeId) -> Self {
        let mut owner = Self {
            capture, controller_uid, controller_gid, node,
            credentials: Some(ControllerNixPublicCredentialCustodyV1::new()),
            pins: None,
            startup: None,
            recipes: None,
            completed: None,
            attempted: false,
            first_failure: None,
            armed: true,
            not_sync: std::marker::PhantomData,
        };
        if owner.capture.retain_admission().is_err() {
            owner.first_failure = Some(SelectorAdmissionFailure::Nix);
        }
        owner
    }

    /// Runs the existing fixed admission sequence once with resident custody.
    ///
    /// # Errors
    /// Borrows the same first credential, Nix startup, codec or policy cause.
    /// Repetition is permanently closed without another load or observation.
    pub fn admit_once(&mut self) -> Result<(), ControllerNixSelectorFailureRefV2<'_>> {
        if self.attempted || self.first_failure.is_some() {
            self.first_failure.get_or_insert(SelectorAdmissionFailure::Closed);
        } else {
            self.attempted = true;
            let result = {
                let _unwind = AbortSelectorAdmissionUnwind;
                self.admit_body()
            };
            match result {
                Ok(()) => return Ok(()),
                Err(cause) => { self.first_failure.get_or_insert(cause); }
            }
        }
        Err(self.failure_view())
    }

    /// Borrows a short view of the same nested first cause.
    pub fn first_failure(&self) -> Option<ControllerNixSelectorFailureRefV2<'_>> {
        self.first_failure.as_ref().map(|_| self.failure_view())
    }

    /// Moves the same completed selector once without observation/allocation.
    ///
    /// The caller parks its successful Arc before passing clones into runtime.
    #[must_use]
    pub fn take_admitted_selector(&mut self) -> Option<ControllerNixStartRecipeSelectorV2> {
        if !self.attempted || self.first_failure.is_some() || self.completed.is_none()
            || self.credentials.is_some() || self.pins.is_some()
            || self.startup.is_some() || self.recipes.is_some()
        {
            return None;
        }
        let completed = self.completed.take();
        self.armed = false;
        completed
    }

    fn failure_view(&self) -> ControllerNixSelectorFailureRefV2<'_> {
        // A final bookend may fail after the same lower owner has moved into
        // completed. Borrow it there; do not diagnose the emptied plain slot.
        if let Some(completed) = &self.completed {
            match completed.retained_credential_failure() {
                Ok(Some(loan)) => {
                    return ControllerNixSelectorFailureRefV2::CredentialLoan(loan);
                }
                Err(cause) => {
                    return ControllerNixSelectorFailureRefV2::CredentialUnavailable(cause);
                }
                Ok(None) => {}
            }
        }
        match &self.first_failure {
            Some(SelectorAdmissionFailure::Selector(cause)) => ControllerNixSelectorFailureRefV2::Selector(cause),
            Some(SelectorAdmissionFailure::Nix) => match self.capture.first_failure() {
                Some(cause) => ControllerNixSelectorFailureRefV2::Nix(cause),
                None => ControllerNixSelectorFailureRefV2::Closed,
            },
            Some(SelectorAdmissionFailure::Credentials) => {
                let cause = self.credentials.as_ref()
                    .and_then(ControllerNixPublicCredentialCustodyV1::failure);
                match cause {
                    Some(cause) => ControllerNixSelectorFailureRefV2::Credential(cause),
                    None => ControllerNixSelectorFailureRefV2::Closed,
                }
            }
            Some(SelectorAdmissionFailure::Closed) | None => ControllerNixSelectorFailureRefV2::Closed,
        }
    }

    fn admit_body(&mut self) -> Result<(), SelectorAdmissionFailure> {
        let controller_uid = self.controller_uid;
        let controller_gid = self.controller_gid;
        let node = self.node;
        selector_admission_recipe!(retained, self, capture, controller_uid, controller_gid, node)
    }

    fn assemble_selector(&mut self) -> Result<(), SelectorAdmissionFailure> {
        if self.completed.is_some() || self.startup.is_none() || self.pins.is_none()
            || self.credentials.is_none() || self.recipes.is_none()
            || self.credentials.as_ref()
                .and_then(ControllerNixPublicCredentialCustodyV1::publics).is_none()
        {
            return Err(SelectorAdmissionFailure::Closed);
        }
        let originals = (
            self.startup.take(), self.pins.take(),
            self.credentials.take(), self.recipes.take(),
        );
        match originals {
            (Some(startup), Some(pins), Some(credentials), Some(recipes)) => {
                self.completed = Some(ControllerNixStartRecipeSelectorV2 {
                    startup,
                    pins,
                    credentials: SelectorPublicCredentials::Retained(
                        RetainedControllerPublics::new(credentials),
                    ),
                    recipes,
                });
                Ok(())
            }
            (startup, pins, credentials, recipes) => {
                self.startup = startup;
                self.pins = pins;
                self.credentials = credentials;
                self.recipes = recipes;
                Err(SelectorAdmissionFailure::Closed)
            }
        }
    }
}

impl Drop for ControllerNixSelectorAdmissionV2 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

struct AbortSelectorAdmissionUnwind;

impl Drop for AbortSelectorAdmissionUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

impl ControllerNixStartRecipeSelectorV2 {
    /// Parks the same opaque capture before the first fixed credential load.
    ///
    /// Construction performs no observation. Allocation/funding failure at
    /// successful Arc sharing remains outside retained admission custody.
    #[must_use]
    pub fn begin_retained_original(
        capture: ProductionControllerNixStartupCaptureV1,
        controller_uid: u32,
        controller_gid: u32,
        node: NodeId,
    ) -> ControllerNixSelectorAdmissionV2 {
        ControllerNixSelectorAdmissionV2::new(capture, controller_uid, controller_gid, node)
    }

    /// Consumes the sole original capture and independently loaded fixed pins.
    ///
    /// # Errors
    /// Rejects missing/changed public credentials, noncanonical catalog or pins,
    /// issuer/session key reuse, and actual selected startup/identity failure.
    pub fn admit_original(
        capture: ProductionControllerNixStartupCaptureV1,
        controller_uid: u32,
        controller_gid: u32,
        node: NodeId,
    ) -> Result<Self, NixStartAdmissionErrorV2> {
        selector_admission_recipe!(legacy, unused, capture, controller_uid, controller_gid, node)
    }

    fn recheck(&self) -> Result<(), NixStartAdmissionErrorV2> {
        self.recheck_and_borrow_publics()?;
        Ok(())
    }

    fn recheck_and_borrow_publics(
        &self,
    ) -> Result<ControllerNixPublicDataLoanV2<'_>, NixStartAdmissionErrorV2> {
        match &self.credentials {
            SelectorPublicCredentials::Legacy(credentials) => {
                self.startup.recheck()?;
                for credential in credentials {
                    credential.recheck()?;
                }
                self.startup.recheck()?;
                Ok(ControllerNixPublicDataLoanV2::new(
                    ControllerPublicLoan::Legacy(credentials),
                ))
            }
            SelectorPublicCredentials::Retained(credentials) => {
                // The original guard is prearmed before the first bookend.
                let mut observation = credentials.borrow(PublicLoanDisposition::Observation)?;
                if let Err(cause) = self.startup.recheck() {
                    return Err(observation.fail(PublicCredentialRefusal::Startup(cause)));
                }
                if observation.original.recheck().is_err() {
                    return Err(observation.fail(PublicCredentialRefusal::Lower));
                }
                if let Err(cause) = self.startup.recheck() {
                    return Err(observation.fail(PublicCredentialRefusal::Startup(cause)));
                }
                let observation = observation.finish()?;
                Ok(ControllerNixPublicDataLoanV2::new(
                    ControllerPublicLoan::Retained(observation),
                ))
            }
        }
    }

    fn borrow_publics(
        &self,
    ) -> Result<ControllerNixPublicDataLoanV2<'_>, NixStartAdmissionErrorV2> {
        let original = match &self.credentials {
            SelectorPublicCredentials::Legacy(credentials) => {
                ControllerPublicLoan::Legacy(credentials)
            }
            SelectorPublicCredentials::Retained(credentials) => {
                let guard = credentials.borrow(PublicLoanDisposition::Data)?;
                if guard.original.publics().is_none() {
                    return Err(guard.fail(PublicCredentialRefusal::Lower));
                }
                ControllerPublicLoan::Retained(guard)
            }
        };
        Ok(ControllerNixPublicDataLoanV2::new(original))
    }

    /// Lends the same selector's terminal credential cause without observation.
    ///
    /// Legacy or no recorded retained refusal returns None without locking.
    /// A terminal retained owner is borrowed with exactly one nonblocking lock
    /// attempt. This remains usable after successful selector handoff; a DATA
    /// observation may fail before it can return any public-preimage loan.
    /// Diagnosis does not recheck, retry, replace custody or write a first cause.
    ///
    /// # Errors
    /// Reports typed contention, poison or inconsistent cause availability.
    /// Unavailable diagnosis leaves the actual original first cause resident;
    /// it does not manufacture an I/O error or recover a poisoned guard.
    pub fn retained_credential_failure(
        &self,
    ) -> Result<Option<ControllerNixPublicDataLoanV2<'_>>, NixStartAdmissionErrorV2> {
        let SelectorPublicCredentials::Retained(credentials) = &self.credentials else {
            return Ok(None);
        };
        if credentials.failure.get().is_none() {
            return Ok(None);
        }

        let guard = credentials.borrow(PublicLoanDisposition::Diagnosis)?;
        let loan = ControllerNixPublicDataLoanV2::new(ControllerPublicLoan::Retained(guard));
        if loan.failure().is_none() {
            return Err(NixStartAdmissionErrorV2::CredentialCauseUnavailable);
        }
        Ok(Some(loan))
    }

    pub(crate) fn recheck_session_floor_origin(&self) -> Result<(), NixStartAdmissionErrorV2> {
        self.recheck()
    }

    pub(crate) fn session_floor_startup(&self) -> &ProductionControllerNixStartupV1 {
        &self.startup
    }

    pub(crate) fn session_floor_pins(&self) -> &NixFixedDomainPinsDataV2 {
        &self.pins
    }

    pub(crate) fn session_floor_public_preimages(
        &self,
    ) -> Result<ControllerNixPublicDataLoanV2<'_>, NixStartAdmissionErrorV2> {
        self.borrow_publics()
    }

    fn commitments(&self) -> Result<Vec<[u8; 32]>, NixStartAdmissionErrorV2> {
        let loan = self.borrow_publics()?;
        let credentials = loan.publics()
            .ok_or(NixStartAdmissionErrorV2::CredentialCustodyClosed)?;

        Ok(credentials.iter().map(|credential| {
            Sha256::digest(credential.bytes()).into()
        }).collect())
    }

    fn assignment_policy(&self) -> Result<CurrentRuntimeScopePolicy, NixStartAdmissionErrorV2> {
        let loan = self.recheck_and_borrow_publics()?;
        let credentials = loan.publics()
            .ok_or(NixStartAdmissionErrorV2::CredentialCustodyClosed)?;
        assignment_policy_from_publics(&credentials, &self.pins)
    }

    /// Compares DATA from the independently retained fixed owner public set.
    ///
    /// This constructs no selector, startup, Session, currentness or floor.
    ///
    /// # Errors
    /// Preserves encoding/catalog failures and rejects mismatched node/profile,
    /// endpoint/issuer/session pins or ownership/plan policy validation failures.
    pub(crate) fn validate_owner_floor_publics(
        credentials: &[PinnedSystemdCredential; 12],
        node: NodeId,
        identities: [u32; 4],
    ) -> Result<NixFixedDomainPinsDataV2, NixStartAdmissionErrorV2> {
        let publics = credentials.each_ref();
        let pins = decode_public_domain_pins(&publics)?;
        if pins.node != node || pins.identities != identities {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        decode_public_catalog(&publics, &pins, node)?;
        assignment_policy_from_publics(&publics, &pins)?;
        Ok(pins)
    }

    pub(super) fn prepare_vacant(
        &self,
        journal: &mut Journal,
        authorized: &AuthorizedPublicMutationRequestV1,
        operation: OperationId,
        request_digest: [u8; 32],
        context: &crate::reconciler::PublicMutationEffectV1,
        desired: &(Vec<u8>, Vec<u8>),
    ) -> Result<NixStartAdmissionCarrierV2, NixStartAdmissionErrorV2> {
        self.recheck()?;
        let authority = authorized.checked_start_authority().map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let crate::cli_model::DormantSandboxRequestKindV1::Start(request) = authorized.request().request() else {
            return Err(NixStartAdmissionErrorV2::Invalid);
        };
        let sandbox = SandboxId::from_bytes(array::<16>(&request.sandbox_id)?);
        let record = PublicProjectionStoreV1::new(journal)
            .get(PublicProjectionKindV1::Sandbox, *sandbox.as_bytes())
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let PublicProjectionResourceV1::Sandbox(resource) = record.resource() else {
            return Err(NixStartAdmissionErrorV2::Invalid);
        };
        let previous = resource.desired.as_option().ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let mutation = request.mutation.as_option().ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let next_generation = previous.generation.checked_add(1).ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let mut clock = crate::controller::ControllerProtectedClockV1::open_fixed()
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let target = crate::runtime_scope::acquire_current_assignment(
            journal, RuntimeScopeHolder { sandbox, holder: authority.holder },
            self.assignment_policy()?, &mut || clock.sample(),
        )?;
        let original_binding = target.binding().clone();
        target.verified_plan_lease(journal, &mut || clock.sample())?;
        let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?.current(sandbox)
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        if binding != original_binding {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        let manifest = binding.manifest().manifest();
        if manifest.project() != authority.project
            || manifest.desired_generation().get() != next_generation
            || manifest.policy() != &authority.policy
            || resource.project_id != authority.project.as_bytes()
            || mutation.expected_resource_version != resource.resource_version
            || (!mutation.expected_incarnation_id.is_empty()
                && mutation.expected_incarnation_id != manifest.incarnation().as_bytes())
            || previous.specification.as_option().is_none_or(|specification| !same_descriptor(specification, manifest.sandbox_spec()))
            || resource.effective_policy.as_option().is_none_or(|policy| !same_descriptor(policy, &authority.policy))
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        let mut recipes = self.recipes.iter().filter(|recipe| {
            let recipe = recipe.recipe();
            recipe.project == authority.project && recipe.sandbox == sandbox
                && recipe.specification == *manifest.sandbox_spec()
                && recipe.environment == *manifest.environment()
                && recipe.policy == authority.policy
        });
        let recipe = recipes.next().ok_or(NixStartAdmissionErrorV2::Invalid)?;
        if recipes.next().is_some() {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        self.require_recipe_pins(recipe)?;
        require_recipe_assignment(recipe, &binding, authority)?;
        let carrier = NixStartAdmissionCarrierV2 {
            operation, request_digest, authority: authority.clone(),
            assignment: capture_assignment(journal, &binding)?,
            recipe: recipe.canonical_bytes().to_vec(), recipe_digest: recipe.digest(),
            credential_commitments: self.commitments()?,
            ordinary_effect: context.encode_plain().map_err(|_| NixStartAdmissionErrorV2::Invalid)?,
            desired_key: desired.0.clone(), desired_value: desired.1.clone(),
            original_resource_version: resource.resource_version.clone(),
            original_incarnation: manifest.incarnation().as_bytes().to_vec(),
            original_generation: previous.generation,
        };
        self.recheck_retained(journal, &carrier, authority)?;
        carrier.encode()?;
        Ok(carrier)
    }

    pub(super) fn recheck_retained(
        &self,
        journal: &mut Journal,
        carrier: &NixStartAdmissionCarrierV2,
        current: &CheckedStartAuthorityV2,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        carrier.authority.require_current_decision(current)?;
        self.recheck()?;
        journal.validate_held_protected_names()?;
        if carrier.credential_commitments != self.commitments()? {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        // Membership verifies the ORIGINAL artifact. It does not select a new
        // recipe on replay, even when another catalog entry would now match.
        let recipe = self.recipes.iter().find(|recipe| {
            recipe.digest() == carrier.recipe_digest && recipe.canonical_bytes() == carrier.recipe
        }).ok_or(NixStartAdmissionErrorV2::Invalid)?;
        self.require_recipe_pins(recipe)?;
        let sandbox = recipe.recipe().sandbox;
        let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?.current(sandbox)
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        require_recipe_assignment(recipe, &binding, &carrier.authority)?;
        let original_manifest = binding.manifest().manifest();
        if binding.holder() != Some(carrier.authority.holder)
            || original_manifest.node() != self.pins.node
            || original_manifest.desired_generation().get() != carrier.original_generation.checked_add(1)
                .ok_or(NixStartAdmissionErrorV2::Invalid)?
            || original_manifest.incarnation().as_bytes() != carrier.original_incarnation.as_slice()
            || capture_assignment(journal, &binding)? != carrier.assignment
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        let claim = crate::reconciler::runtime_authority_claim(journal, &binding)
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let mut clock = crate::controller::ControllerProtectedClockV1::open_fixed()
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let before = clock.sample().map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let assignment = &carrier.assignment;
        let verified = self.assignment_policy()?.ownership_verifier.verify_response(
            &claim,
            UnverifiedOwnershipLeaseResponse::from_transport(
                assignment.lease.clone(), assignment.signature.clone(),
                assignment.receipt.clone(), assignment.receipt_signature.clone(),
            ).map_err(|_| NixStartAdmissionErrorV2::Invalid)?, &before,
        ).map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let after = clock.sample().map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        before.validate_later_sample(after).map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let current_binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?.current(sandbox)
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        if after.host_boot_id() != before.host_boot_id()
            || after.boottime_nanoseconds() < before.boottime_nanoseconds()
            || after.wall_seconds() < before.wall_seconds()
            || after.wall_seconds() < current.accepted_wall_seconds
            || after.wall_seconds() >= carrier.authority.coordinates.capability_expires_at
            || after.wall_seconds() >= carrier.authority.coordinates.policy_expires_at
            || after.wall_seconds() >= verified.authority_expires_seconds()
            || after.boottime_nanoseconds().checked_sub(before.boottime_nanoseconds())
                .is_none_or(|elapsed| elapsed > 10_000_000_000)
            || current_binding != binding
            || capture_assignment(journal, &binding)? != carrier.assignment
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        require_desired_assignment(carrier, &binding)?;
        self.recheck()?;
        journal.validate_held_protected_names()?;
        Ok(())
    }

    fn require_recipe_pins(
        &self,
        artifact: &VerifiedNixRecipeArtifactV2,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        let recipe = artifact.recipe();
        let generation = crate::environment::decode_environment_generation_v1(&recipe.generation_manifest)
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        if recipe.node != self.pins.node || recipe.deployment != self.pins.deployment
            || recipe.endpoint != self.pins.endpoint || recipe.domain != self.pins.domain
            || recipe.domain_commitment != self.pins.domain_commitment || recipe.disclosure != self.pins.disclosure
            || generation.project() != recipe.project || generation.sandbox() != recipe.sandbox
            || generation.environment_descriptor() != &recipe.environment
            || generation.effective_policy() != &recipe.policy
            || generation.selected_output().as_str() != recipe.selected_output
            || generation.target_system().as_str() != recipe.target_system
            || generation.inputs().iter().filter(|input| {
                input.role() == crate::environment::EnvironmentDescriptorRoleV1::ProjectSource && input.descriptor() == &recipe.source
            }).count() != 1
            || generation.inputs().iter().filter(|input| {
                input.role() == crate::environment::EnvironmentDescriptorRoleV1::LockFile && input.descriptor() == &recipe.lock
            }).count() != 1
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        Ok(())
    }
}

fn decode_public_domain_pins(
    credentials: &[&PinnedSystemdCredential; 12],
) -> Result<NixFixedDomainPinsDataV2, NixStartAdmissionErrorV2> {
    NixFixedDomainPinsDataV2::decode(credentials[1].bytes())
        .map_err(|error| match error {
            NixFixedDomainPinsDecodeErrorV2::Encoding(source) => {
                NixStartAdmissionErrorV2::Encoding(source)
            }
            NixFixedDomainPinsDecodeErrorV2::Invalid => NixStartAdmissionErrorV2::Invalid,
        })
}

fn decode_public_catalog(
    credentials: &[&PinnedSystemdCredential; 12],
    pins: &NixFixedDomainPinsDataV2,
    node: NodeId,
) -> Result<Vec<VerifiedNixRecipeArtifactV2>, NixStartAdmissionErrorV2> {
    let issuer = array::<32>(credentials[0].bytes())?;
    let manifest = BrokerSessionManifestV1::decode(credentials[2].bytes())
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    if manifest.protocol() != BrokerSessionProtocolV1::Nix
        || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
        || manifest.node_id() != *node.as_bytes()
        || manifest.domain_id() != *pins.domain.as_bytes()
        || manifest.route_id() != *pins.endpoint.as_bytes()
        || manifest.key_pins().iter().any(|pin| pin.public_key() == &issuer)
        || manifest.key_pins().iter().any(|pin| {
            pin.is_revoked() || pin.superseded_by_key_generation().is_some()
        })
        || [5, 7, 10].into_iter().any(|index| credentials[index].bytes() == issuer)
    {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    decode_catalog(credentials[3].bytes(), issuer)
}

fn assignment_policy_from_publics(
    credentials: &[&PinnedSystemdCredential; 12],
    pins: &NixFixedDomainPinsDataV2,
) -> Result<CurrentRuntimeScopePolicy, NixStartAdmissionErrorV2> {
    let policy_bytes = credentials[4].bytes();
    let policy = decode_trust_policy(policy_bytes, DecodeLimits::default())
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    aos_sandbox_core::validate_required_features(policy.required_features())
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    let [authority] = policy.allowed_keys() else {
        return Err(NixStartAdmissionErrorV2::Invalid);
    };
    if policy.purpose() != SignaturePurpose::OwnershipLease
        || authority.usage() != KeyUsage::OwnershipLease
    {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    let descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?,
        policy_bytes,
    );
    let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
        policy_bytes.to_vec(),
        descriptor,
        policy.trust_scope(),
        authority.clone(),
        array::<32>(credentials[5].bytes())?,
        DecodeLimits::default(),
    ).map_err(|_| NixStartAdmissionErrorV2::Invalid)?;

    Ok(CurrentRuntimeScopePolicy {
        node: pins.node,
        clock_provenance: *b"aos-cli-clock-v1",
        maximum_validity_seconds: 10,
        runtime_limits: RuntimeAuthorityLimits::default(),
        ownership_verifier: OwnershipAuthorityVerifier::new(anchor, authority.clone()),
        broker_anchor: plan_anchor_from_publics(credentials, 6)?,
        mount_broker_anchor: plan_anchor_from_publics(credentials, 9)?,
    })
}

fn plan_anchor_from_publics(
    credentials: &[&PinnedSystemdCredential; 12],
    index: usize,
) -> Result<BrokerPlanTrustAnchor, NixStartAdmissionErrorV2> {
    let bytes = credentials[index].bytes();
    let public = array::<32>(credentials[index + 1].bytes())?;
    let scope = array::<16>(credentials[index + 2].bytes())?;
    let policy = decode_trust_policy(bytes, DecodeLimits::default())
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    aos_sandbox_core::validate_required_features(policy.required_features())
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public).into());
    let mut matches = policy.allowed_keys().iter().filter(|key| {
        key.usage() == KeyUsage::BrokerAuthorization
            && key.public_key_sha256() == fingerprint
    });
    let signer = matches.next().cloned().ok_or(NixStartAdmissionErrorV2::Invalid)?;
    if policy.purpose() != SignaturePurpose::BrokerAuthorization
        || matches.next().is_some()
        || scope == [0; 16]
    {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    BrokerPlanTrustAnchor::from_trusted_configuration(
        bytes.to_vec(),
        descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .map_err(|_| NixStartAdmissionErrorV2::Invalid)?,
            bytes,
        ),
        policy.trust_scope(),
        signer,
        public,
        RevocationScopeId::from_bytes(scope),
        DecodeLimits::default(),
    ).map_err(|_| NixStartAdmissionErrorV2::Invalid)
}

fn require_desired_assignment(
    carrier: &NixStartAdmissionCarrierV2,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<(), NixStartAdmissionErrorV2> {
    let (key, value) = carrier.desired();
    let projection = crate::controller_service::public_projection::decode_checked_public_projection_v1(key, value)
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    let PublicProjectionResourceV1::Sandbox(sandbox) = projection.resource() else {
        return Err(NixStartAdmissionErrorV2::Invalid);
    };
    let desired = sandbox.desired.as_option().ok_or(NixStartAdmissionErrorV2::Invalid)?;
    let manifest = binding.manifest().manifest();
    if desired.specification.as_option().is_none_or(|descriptor| !same_descriptor(descriptor, manifest.sandbox_spec()))
        || sandbox.effective_policy.as_option().is_none_or(|descriptor| !same_descriptor(descriptor, manifest.policy()))
    {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    Ok(())
}

fn capture_assignment(
    journal: &mut Journal,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<OriginalAssignmentV2, NixStartAdmissionErrorV2> {
    Ok(checked_assignment_readback(journal, binding)?.preimages().into_owned())
}

/// Keeps one fresh decoded publication beside the actual borrowed binding bytes.
///
/// This ephemeral readback cannot outlive the immutable journal/binding borrow.
/// It supplies historical comparison data, not retained current authority.
struct CheckedAssignmentReadbackV2<'readback> {
    publication: crate::publication::CurrentAuthorityPublicationV1,
    binding: &'readback RuntimeAuthorityBindingV1,
    binding_bytes: &'readback [u8],
}

impl CheckedAssignmentReadbackV2<'_> {
    fn preimages(&self) -> AssignmentPreimagesV2<'_> {
        let lease = self.publication.lease();
        AssignmentPreimagesV2 {
            bytes: [
                self.binding_bytes,
                self.binding.manifest().canonical_bytes(),
                self.publication.canonical_bytes(),
                lease.canonical_lease(),
                lease.canonical_signature(),
                lease.canonical_receipt(),
                lease.canonical_receipt_signature(),
            ],
            binding_digest: self.binding.digest(),
            publication_digest: self.publication.digest(),
        }
    }

    fn matches_original(&self, original: &OriginalAssignmentV2) -> bool {
        self.preimages().matches_original(original)
    }
}

/// Projects every original preimage and both digests without copying its bytes.
struct AssignmentPreimagesV2<'original> {
    bytes: [&'original [u8]; 7],
    binding_digest: ObjectDigest,
    publication_digest: ObjectDigest,
}

impl AssignmentPreimagesV2<'_> {
    fn into_owned(self) -> OriginalAssignmentV2 {
        let [binding, assignment, publication, lease, signature, receipt, receipt_signature] =
            self.bytes;

        OriginalAssignmentV2 {
            binding: binding.to_vec(),
            binding_digest: self.binding_digest,
            assignment: assignment.to_vec(),
            publication: publication.to_vec(),
            publication_digest: self.publication_digest,
            lease: lease.to_vec(),
            signature: signature.to_vec(),
            receipt: receipt.to_vec(),
            receipt_signature: receipt_signature.to_vec(),
        }
    }

    fn matches_original(&self, original: &OriginalAssignmentV2) -> bool {
        self.bytes == [
            original.binding.as_slice(),
            original.assignment.as_slice(),
            original.publication.as_slice(),
            original.lease.as_slice(),
            original.signature.as_slice(),
            original.receipt.as_slice(),
            original.receipt_signature.as_slice(),
        ] && self.binding_digest == original.binding_digest
            && self.publication_digest == original.publication_digest
    }
}

fn checked_assignment_readback<'readback>(
    journal: &'readback mut Journal,
    binding: &'readback RuntimeAuthorityBindingV1,
) -> Result<CheckedAssignmentReadbackV2<'readback>, NixStartAdmissionErrorV2> {
    let publication = crate::publication::AuthorityPublicationStore::new(journal).current(binding.sandbox())
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?.ok_or(NixStartAdmissionErrorV2::Invalid)?;
    if publication.digest() != binding.publication_digest()
        || publication.manifest() != binding.manifest()
        || publication.lease_generation() != binding.lease_generation()
        || publication.lease_digest() != binding.lease_digest()
    {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    let mut key = b"binding/".to_vec();
    key.extend_from_slice(binding.sandbox().as_bytes());
    key.extend_from_slice(&binding.revision().to_be_bytes());
    let bytes = journal.get(crate::RecordNamespace::RuntimeAuthority, &key)
        .ok_or(NixStartAdmissionErrorV2::Invalid)?;

    let readback = CheckedAssignmentReadbackV2 {
        publication,
        binding,
        binding_bytes: bytes,
    };
    // The complete cap precedes either owned retention or borrowed equality.
    // No readback is retained across later clock, target or journal effects.
    require_assignment_preimage_lengths(readback.preimages().bytes.map(|original| original.len()))?;
    Ok(readback)
}

fn require_assignment_preimage_lengths(lengths: [usize; 7]) -> Result<(), NixStartAdmissionErrorV2> {
    lengths.into_iter().try_fold(0_usize, |total, length| {
        total.checked_add(length).filter(|length| *length <= carrier::MAXIMUM_BYTES)
            .ok_or(NixStartAdmissionErrorV2::Invalid)
    })?;
    Ok(())
}

fn require_recipe_assignment(
    artifact: &VerifiedNixRecipeArtifactV2,
    binding: &RuntimeAuthorityBindingV1,
    authority: &CheckedStartAuthorityV2,
) -> Result<(), NixStartAdmissionErrorV2> {
    let recipe = artifact.recipe();
    let manifest = binding.manifest().manifest();
    let request = crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(authority.original_request())
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    let crate::cli_model::DormantSandboxRequestKindV1::Start(request) = request.request() else {
        return Err(NixStartAdmissionErrorV2::Invalid);
    };
    let generation = crate::environment::decode_environment_generation_v1(&recipe.generation_manifest)
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    let policy = crate::publisher_policy::PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        authority.project, authority.coordinates.policy_generation,
        authority.coordinates.policy_not_before, authority.coordinates.policy_expires_at,
        &authority.canonical_policy, DecodeLimits::default(),
    ).map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    if recipe.sandbox.as_bytes() != request.sandbox_id.as_slice()
        || recipe.project != authority.project || manifest.project() != authority.project
        || manifest.sandbox() != recipe.sandbox || manifest.sandbox_spec() != &recipe.specification
        || manifest.environment() != &recipe.environment || manifest.policy() != &recipe.policy
        || recipe.policy != authority.policy
        || generation.disclosure() != policy.policy().cache_domain()
        || !generation.inputs().iter().all(|input| manifest.source_commitments().contains(input.descriptor()))
    {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    Ok(())
}

fn same_descriptor(
    proto: &aos_proto::aos::sandbox::v1::ObjectDescriptor,
    descriptor: &ObjectDescriptor,
) -> bool {
    proto.media_type == descriptor.media_type().as_str()
        && proto.sha256 == descriptor.digest().as_bytes()
        && proto.encoded_size == descriptor.encoded_size()
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NixStartAdmissionErrorV2> {
    bytes.try_into().map_err(|_| NixStartAdmissionErrorV2::Invalid)
}

fn decode_catalog(
    bytes: &[u8],
    issuer: [u8; 32],
) -> Result<Vec<VerifiedNixRecipeArtifactV2>, NixStartAdmissionErrorV2> {
    if !(52..=MAXIMUM_CATALOG_BYTES).contains(&bytes.len()) || &bytes[..8] != CATALOG_MAGIC
        || bytes[8..10] != 2_u16.to_be_bytes() || bytes[10..16] != [0; 6]
    {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    let end = bytes.len() - 32;
    if Sha256::new().chain_update(CATALOG_DOMAIN).chain_update(&bytes[..end]).finalize().as_slice() != &bytes[end..] {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    let count = u32::from_be_bytes(array::<4>(&bytes[16..20])?) as usize;
    if !(1..=4).contains(&count) {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    let mut cursor = 20_usize;
    let mut recipes: Vec<VerifiedNixRecipeArtifactV2> = Vec::with_capacity(count);
    for _ in 0..count {
        let header_end = cursor.checked_add(4).filter(|value| *value <= end).ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let length = u32::from_be_bytes(array::<4>(&bytes[cursor..header_end])?) as usize;
        let recipe_end = header_end.checked_add(length).filter(|value| *value <= end).ok_or(NixStartAdmissionErrorV2::Invalid)?;
        if length == 0 || length > NIX_REQUEST_MAXIMUM_BYTES_V2 {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        let recipe = verify_nix_recipe_artifact_v2(&bytes[header_end..recipe_end], issuer)?;
        // Both purposes use the existing purpose-separated artifact identity,
        // not an unrelated raw SHA256 of the signed artifact.
        if recipes.last().is_some_and(|previous| previous.digest() >= recipe.digest()) {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        recipes.push(recipe);
        cursor = recipe_end;
    }
    if cursor != end {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    Ok(recipes)
}

#[cfg(test)]
mod credential_guard_tests {
    use super::*;

    // Empty lower slots and real state refusals construct no protected owner.
    fn empty_publics() -> RetainedControllerPublics {
        RetainedControllerPublics::new(ControllerNixPublicCredentialCustodyV1::new())
    }

    #[test]
    fn observation_entry_does_not_record_interruption() {
        let owner = empty_publics();
        let guard = owner.borrow(PublicLoanDisposition::Observation).unwrap();

        assert!(owner.failure.get().is_none());
        drop(guard);

        assert!(matches!(owner.failure.get(), Some(PublicCredentialRefusal::Interrupted)));
    }

    #[test]
    fn terminal_loan_borrows_the_same_real_lower_state_cause() {
        let owner = empty_publics();
        let mut guard = owner.borrow(PublicLoanDisposition::Observation).unwrap();
        assert!(guard.original.recheck().is_err());
        let original = guard.original.failure().unwrap() as *const _;

        assert!(matches!(guard.fail(PublicCredentialRefusal::Lower),
            NixStartAdmissionErrorV2::CredentialCustodyClosed));
        let guard = owner.borrow(PublicLoanDisposition::Diagnosis).unwrap();
        let loan = ControllerNixPublicDataLoanV2::new(ControllerPublicLoan::Retained(guard));
        let cause = loan.failure().unwrap().downcast_ref::<
            crate::public_api_session::ControllerNixPublicCredentialErrorV1,
        >().unwrap();

        assert!(std::ptr::eq(cause, original));
        assert!(loan.preimages().is_none());
    }

    #[test]
    fn diagnostic_contention_never_replaces_first_refusal() {
        let owner = empty_publics();
        let held = owner.borrow(PublicLoanDisposition::Data).unwrap();
        assert!(matches!(owner.borrow(PublicLoanDisposition::Observation),
            Err(NixStartAdmissionErrorV2::CredentialCustodyContended)));
        let original = owner.failure.get().unwrap() as *const _;

        assert!(matches!(owner.borrow(PublicLoanDisposition::Diagnosis),
            Err(NixStartAdmissionErrorV2::CredentialCustodyContended)));

        assert!(std::ptr::eq(owner.failure.get().unwrap(), original));
        drop(held);
        assert!(matches!(owner.borrow(PublicLoanDisposition::Data),
            Err(NixStartAdmissionErrorV2::CredentialCustodyContended)));
    }

    #[test]
    fn observation_unwind_preserves_refusal_before_mutex_poison() {
        let owner = empty_publics();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = owner.borrow(PublicLoanDisposition::Observation).unwrap();
            panic!("interrupted empty credential observation");
        }));

        assert!(result.is_err());
        assert!(matches!(owner.failure.get(), Some(PublicCredentialRefusal::Interrupted)));
        let original = owner.failure.get().unwrap() as *const _;
        assert!(matches!(owner.borrow(PublicLoanDisposition::Diagnosis),
            Err(NixStartAdmissionErrorV2::CredentialCustodyPoisoned)));
        assert!(std::ptr::eq(owner.failure.get().unwrap(), original));
    }

    #[test]
    fn diagnostic_drop_lends_startup_cause_without_an_observation() {
        let owner = empty_publics();
        owner.record(PublicCredentialRefusal::Startup(
            crate::normal_root::NormalRootStartupErrorV1::Profile,
        ));
        let Some(PublicCredentialRefusal::Startup(original)) = owner.failure.get() else {
            panic!("missing original negative startup cause");
        };
        let guard = owner.borrow(PublicLoanDisposition::Diagnosis).unwrap();
        let loan = ControllerNixPublicDataLoanV2::new(ControllerPublicLoan::Retained(guard));

        let cause = loan.failure().unwrap().downcast_ref::<
            crate::normal_root::NormalRootStartupErrorV1,
        >().unwrap();
        assert!(std::ptr::eq(cause, original));
        assert!(loan.preimages().is_none());
        drop(loan);

        assert!(matches!(owner.failure.get(), Some(PublicCredentialRefusal::Startup(_))));
    }

    #[test]
    fn shareable_selector_has_no_borrowed_guard_field() {
        fn require_send_sync<T: Send + Sync>() {}

        require_send_sync::<ControllerNixStartRecipeSelectorV2>();
    }
}

#[cfg(test)]
mod retained_failure_view_tests {
    use super::*;

    #[test]
    fn selector_failure_view_borrows_the_same_cause() {
        let cause = NixStartAdmissionErrorV2::Invalid;
        let view = ControllerNixSelectorFailureRefV2::Selector(&cause);

        assert!(matches!(view, ControllerNixSelectorFailureRefV2::Selector(retained)
            if std::ptr::eq(retained, &cause)));
        assert_eq!(format!("{view:?}"), "Controller Nix selector admission refused");
    }

    #[test]
    fn nested_nix_failure_view_is_borrowed_and_bounded() {
        let cause = crate::normal_root::NormalRootStartupErrorV1::Confinement;
        let view = ControllerNixSelectorFailureRefV2::Nix(&cause);

        assert!(matches!(view, ControllerNixSelectorFailureRefV2::Nix(retained)
            if std::ptr::eq(retained, &cause)));
        assert_eq!(format!("{view:?}"), "Controller Nix original startup refused");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These buffers are historical DATA, not a publication, journal or owner.
    fn assignment_buffers() -> [Vec<u8>; 7] {
        std::array::from_fn(|index| vec![u8::try_from(index + 1).unwrap(); index + 2])
    }

    fn assignment_preimages(buffers: &[Vec<u8>; 7]) -> AssignmentPreimagesV2<'_> {
        AssignmentPreimagesV2 {
            bytes: buffers.each_ref().map(Vec::as_slice),
            binding_digest: ObjectDigest::from_bytes([8; 32]),
            publication_digest: ObjectDigest::from_bytes([9; 32]),
        }
    }

    #[test]
    fn borrowed_assignment_matches_the_complete_old_owned_layout() {
        let buffers = assignment_buffers();
        let original = OriginalAssignmentV2 {
            binding: buffers[0].clone(),
            binding_digest: ObjectDigest::from_bytes([8; 32]),
            assignment: buffers[1].clone(),
            publication: buffers[2].clone(),
            publication_digest: ObjectDigest::from_bytes([9; 32]),
            lease: buffers[3].clone(),
            signature: buffers[4].clone(),
            receipt: buffers[5].clone(),
            receipt_signature: buffers[6].clone(),
        };

        let owned = assignment_preimages(&buffers).into_owned();

        assert_eq!(owned, original);
        assert!(assignment_preimages(&buffers).matches_original(&original));
        assert_eq!(
            serde_json::to_vec(&owned).unwrap(),
            serde_json::to_vec(&original).unwrap(),
        );
    }

    #[test]
    fn borrowed_assignment_rejects_every_preimage_and_both_digest_substitutions() {
        let buffers = assignment_buffers();
        let original = assignment_preimages(&buffers).into_owned();

        for index in 0..buffers.len() {
            let mut substituted = buffers.clone();
            substituted[index][0] ^= 1;
            let view = assignment_preimages(&substituted);

            assert!(!view.matches_original(&original), "preimage {index}");
            assert_ne!(view.into_owned(), original, "preimage {index}");
        }

        let mut substituted = assignment_preimages(&buffers);
        substituted.binding_digest = ObjectDigest::from_bytes([10; 32]);
        assert!(!substituted.matches_original(&original));
        assert_ne!(substituted.into_owned(), original);

        let mut substituted = assignment_preimages(&buffers);
        substituted.publication_digest = ObjectDigest::from_bytes([10; 32]);
        assert!(!substituted.matches_original(&original));
        assert_ne!(substituted.into_owned(), original);
    }

    #[test]
    fn borrowed_assignment_compares_contents_not_buffer_identity() {
        let buffers = assignment_buffers();
        let original = assignment_preimages(&buffers).into_owned();
        let separate = buffers.clone();

        assert!(assignment_preimages(&separate).matches_original(&original));
        for (left, right) in buffers.iter().zip(&separate) {
            assert_ne!(left.as_ptr(), right.as_ptr());
        }
    }

    #[test]
    fn borrowed_assignment_rejects_trailing_bytes_and_reordered_families() {
        let buffers = assignment_buffers();
        let original = assignment_preimages(&buffers).into_owned();

        for index in 0..buffers.len() {
            let mut extended = buffers.clone();
            extended[index].push(0);

            assert!(
                !assignment_preimages(&extended).matches_original(&original),
                "preimage {index}",
            );
        }

        let mut reordered = buffers;
        reordered.swap(3, 4);
        assert!(!assignment_preimages(&reordered).matches_original(&original));
    }

    #[test]
    fn assignment_bound_counts_all_seven_preimages_and_checked_overflow() {
        let exact = [carrier::MAXIMUM_BYTES - 6, 1, 1, 1, 1, 1, 1];

        assert!(require_assignment_preimage_lengths(exact).is_ok());
        for index in 0..exact.len() {
            let mut oversized = exact;
            oversized[index] += 1;

            assert!(require_assignment_preimage_lengths(oversized).is_err(), "preimage {index}");
        }
        assert!(require_assignment_preimage_lengths([1, usize::MAX, 0, 0, 0, 0, 0]).is_err());
        assert!(require_assignment_preimage_lengths([usize::MAX, 0, 0, 0, 0, 0, 0]).is_err());
    }

    fn catalog_prefix(count: u32) -> Vec<u8> {
        let mut bytes = CATALOG_MAGIC.to_vec();
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes
    }

    fn checksum(mut bytes: Vec<u8>) -> Vec<u8> {
        let digest = Sha256::new().chain_update(CATALOG_DOMAIN).chain_update(&bytes).finalize();
        bytes.extend_from_slice(&digest);
        bytes
    }

    #[test]
    fn catalog_refuses_empty_count_excess_count_and_aggregate_overflow() {
        for count in [0, 5, u32::MAX] {
            assert!(decode_catalog(&checksum(catalog_prefix(count)), [1; 32]).is_err());
        }
        let mut oversized = catalog_prefix(1);
        oversized.resize(MAXIMUM_CATALOG_BYTES + 1, 0);
        assert!(decode_catalog(&oversized, [1; 32]).is_err());
    }

    #[test]
    fn catalog_refuses_nested_length_overflow_and_nonzero_reserved_bytes() {
        let mut bytes = catalog_prefix(1);
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_catalog(&checksum(bytes), [1; 32]).is_err());

        let mut bytes = catalog_prefix(1);
        bytes[10] = 1;
        assert!(decode_catalog(&checksum(bytes), [1; 32]).is_err());
    }

    #[test]
    fn catalog_checksum_does_not_make_unsigned_recipe_authority() {
        let mut bytes = catalog_prefix(1);
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.extend_from_slice(b"drv");

        assert!(decode_catalog(&checksum(bytes), [1; 32]).is_err());
    }
}
