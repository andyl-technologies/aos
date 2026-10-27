//! Fixed protected journal receiving mechanics.
//!
//! This wrapper shares the existing native opener, bounded-prefix semantic
//! parser and tail engine. Its results are custody and representation DATA,
//! never a service grant, Session endpoint, floor or permission to replay.
//! Each genuine recipient prepays fixed native work before preparation
//! and admits this same held extent before the argument-free replay call.

mod storage_host;
pub use storage_host::StorageHostSessionCapturedJournalOpenV1;

mod controller;
mod controller_floor;
mod storage_floor;
mod initial_checkpoint_residue;
mod method46_initial;
pub(crate) use method46_initial::Method46InitialMainWriterOriginalV1;
pub use controller::{
    ControllerBrokerSessionCapturedJournalOpenV1,
    ControllerStartResourceSessionCapturedJournalOpenV4,
};
pub use controller_floor::ControllerStorageFloorCapturedJournalOpenV1;
pub use storage_floor::StorageBrokerFloorCapturedJournalOpenV2;


use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use super::{
    Journal, JournalError, JournalLimits, ProtectedJournalPreopenReplayExtentV1,
    ProtectedWriterOpenOriginalsV1, RecoveryReport,
};

// Intrinsic identity of the actual Journal held by this facade. Cloning this
// existing Arc allocates no new identity and grants no replay or domain authority.
#[derive(Clone)]
pub(crate) struct StorageNativeOpeningOwnerLinkV1(Arc<super::JournalAuthorityInstance>);

impl StorageNativeOpeningOwnerLinkV1 {
    fn of(journal: &Journal) -> Self {
        Self(Arc::clone(&journal.authority_instance))
    }

    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn same_journal(&self, journal: &Journal) -> bool {
        Arc::ptr_eq(&self.0, &journal.authority_instance)
    }

    pub(crate) fn matches_journal_v1(&self, journal: &Journal) -> bool {
        Arc::ptr_eq(&self.0, &journal.authority_instance)
    }
}

impl Journal {
    // Passive intrinsic identity of the same held Journal, not a new identity,
    // writer, floor, account or authorization. Actual role gates remain separate.
    pub(crate) fn held_session_owner_link_v1(&self) -> StorageNativeOpeningOwnerLinkV1 {
        StorageNativeOpeningOwnerLinkV1::of(self)
    }
}

// Shared fixed path DATA. Genuine boot/D owners still prove the selected
// role and actual retained Journal; this recipe lends no File or authority.
pub(crate) const fn controller_session_directory_data_v1(
    role: crate::ControllerInitialBrokerSessionRoleV1,
) -> &'static str {
    controller::directory(role)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FixedProtectedJournalRecipeV1 {
    BrokerSession,
    BrokerFloor,
    RuntimeState,
    Workspaces,
    NativeIssuance,
    ExecutionOutput,
    HostPeer,
    HostExecution,
    HostAgent,
    HostLifecycle,
    HostArgument,
    EnvironmentEvidence,
    MountBrokerSession,
    HostBrokerSession,
    RuntimeDeploymentMain,
    RuntimeDeploymentFloor,
}

impl FixedProtectedJournalRecipeV1 {
    const fn directory(self) -> &'static str {
        match self {
            Self::RuntimeDeploymentMain | Self::RuntimeDeploymentFloor => {
                "/var/lib/aos/sandbox/runtime-deployment"
            }
            Self::HostPeer
            | Self::HostExecution
            | Self::HostAgent
            | Self::HostLifecycle
            | Self::HostArgument => "/var/lib/aos/sandbox-host",
            Self::BrokerSession | Self::BrokerFloor => {
                "/var/lib/aos/sandbox-storage/broker-session"
            }
            Self::EnvironmentEvidence => "/var/lib/aos/sandbox/source-evidence",
            Self::MountBrokerSession => "/var/lib/aos/sandbox-mount/broker-session",
            Self::HostBrokerSession => "/var/lib/aos/sandbox-host/broker-session",
            Self::RuntimeState
            | Self::Workspaces
            | Self::NativeIssuance
            | Self::ExecutionOutput => "/var/lib/aos/sandbox-storage",
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::RuntimeDeploymentMain => "preparation.journal",
            Self::RuntimeDeploymentFloor => "tpm-floor.journal",
            Self::BrokerSession
            | Self::MountBrokerSession
            | Self::HostBrokerSession => "session.journal",
            Self::BrokerFloor => {
                aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::SIDECAR_NAME_V1
            }
            Self::RuntimeState => "storage-state.journal",
            Self::Workspaces => "storage-workspaces.journal",
            Self::NativeIssuance => "storage-native-issuance.journal",
            Self::ExecutionOutput => "execution-output.journal",
            Self::HostPeer => "runtime-agent-peer.journal",
            Self::HostExecution => "runtime-execution.journal",
            Self::HostAgent => "runtime-agent-state.journal",
            Self::HostLifecycle => "runtime-lifecycle.journal",
            Self::HostArgument => "runtime-argument-attempt.journal",
            Self::EnvironmentEvidence => "environment-authority-v1.journal",
        }
    }

    const fn directory_descriptors(self) -> u16 {
        match self {
            Self::RuntimeDeploymentMain
            | Self::RuntimeDeploymentFloor
            | Self::BrokerSession
            | Self::BrokerFloor
            | Self::EnvironmentEvidence
            | Self::MountBrokerSession
            | Self::HostBrokerSession => 6,
            Self::HostPeer
            | Self::HostExecution
            | Self::HostAgent
            | Self::HostLifecycle
            | Self::HostArgument => 5,
            Self::RuntimeState
            | Self::Workspaces
            | Self::NativeIssuance
            | Self::ExecutionOutput => 5,
        }
    }
}

// The fixed roles and the genuinely joined Trust role share one staged state
// machine. Joined coordinates are populated only by closed original-loan
// gates; no public constructor accepts their path, UID or an owning File.
enum ProtectedCapturedJournalRecipeV1 {
    Fixed(FixedProtectedJournalRecipeV1),
    JoinedRequestTrust(Option<std::path::PathBuf>),
    JoinedStorageHostSession(Option<u32>),
    JoinedControllerSession(Option<(crate::ControllerInitialBrokerSessionRoleV1, u32)>),
    JoinedControllerStorageFloor(Option<u32>),
    JoinedStartResourceSession(Option<(crate::ControllerInitialBrokerSessionRoleV1, u32)>),
    JoinedMethod46InitialMain(Option<(aos_sandbox_broker::receiving::Method46InitialServiceRoleV1, u32)>),
    JoinedMethod46InitialFloor(Option<(aos_sandbox_broker::receiving::Method46InitialServiceRoleV1, u32)>),
    #[cfg(test)]
    Method46InitialFloorFixture(std::path::PathBuf, u32),
}

impl ProtectedCapturedJournalRecipeV1 {
    const TRUST_BASENAME: &'static str = "storage-live-export-request-trust.journal";

    fn directory(&self) -> Option<&Path> {
        match self {
            Self::Fixed(recipe) => Some(Path::new(recipe.directory())),
            Self::JoinedRequestTrust(directory) => directory.as_deref(),
            Self::JoinedStorageHostSession(_) => Some(Path::new(storage_host::DIRECTORY)),
            Self::JoinedControllerSession(Some((role, _))) => {
                Some(Path::new(controller::directory(*role)))
            }
            Self::JoinedControllerSession(None) => None,
            Self::JoinedMethod46InitialMain(coordinates)
            | Self::JoinedMethod46InitialFloor(coordinates) => coordinates.map(|(role, _)| {
                Path::new(method46_initial::directory(role))
            }),
            Self::JoinedStartResourceSession(Some((role, _))) => {
                Some(Path::new(controller::directory(*role)))
            }
            Self::JoinedStartResourceSession(None) => None,
            Self::JoinedControllerStorageFloor(Some(_)) => Some(Path::new(controller::directory(
                crate::ControllerInitialBrokerSessionRoleV1::Storage,
            ))),
            Self::JoinedControllerStorageFloor(None) => None,
            #[cfg(test)]
            Self::Method46InitialFloorFixture(directory, _) => Some(directory),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Fixed(recipe) => recipe.name(),
            Self::JoinedRequestTrust(_) => Self::TRUST_BASENAME,
            Self::JoinedStorageHostSession(_) => "session.journal",
            Self::JoinedControllerSession(_) | Self::JoinedStartResourceSession(_) => {
                "session.journal"
            }
            Self::JoinedMethod46InitialMain(_) => "session.journal",
            Self::JoinedControllerStorageFloor(_) | Self::JoinedMethod46InitialFloor(_) => {
                aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::SIDECAR_NAME_V1
            }
            #[cfg(test)]
            Self::Method46InitialFloorFixture(_, _) => {
                aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::SIDECAR_NAME_V1
            }
        }
    }

    fn retained_append_identity_v1(&self) -> Option<(&'static str, &'static str, u32)> {
        match self {
            Self::JoinedStorageHostSession(Some(uid)) => {
                Some((storage_host::DIRECTORY, "session.journal", *uid))
            }
            Self::Fixed(
                recipe @ (FixedProtectedJournalRecipeV1::HostPeer
                | FixedProtectedJournalRecipeV1::HostExecution
                | FixedProtectedJournalRecipeV1::HostAgent
                | FixedProtectedJournalRecipeV1::HostLifecycle
                | FixedProtectedJournalRecipeV1::HostArgument
                | FixedProtectedJournalRecipeV1::EnvironmentEvidence
                | FixedProtectedJournalRecipeV1::ExecutionOutput
                | FixedProtectedJournalRecipeV1::MountBrokerSession
                | FixedProtectedJournalRecipeV1::HostBrokerSession
                | FixedProtectedJournalRecipeV1::RuntimeDeploymentMain
                | FixedProtectedJournalRecipeV1::RuntimeDeploymentFloor
                | FixedProtectedJournalRecipeV1::BrokerFloor
                | FixedProtectedJournalRecipeV1::BrokerSession),
            ) => Some((recipe.directory(), recipe.name(), 0)),
            Self::JoinedControllerSession(Some((
                role @ (crate::ControllerInitialBrokerSessionRoleV1::Host
                | crate::ControllerInitialBrokerSessionRoleV1::Storage),
                uid,
            ))) => Some((controller::directory(*role), "session.journal", *uid)),
            Self::JoinedStartResourceSession(Some((role, uid))) => {
                Some((controller::directory(*role), "session.journal", *uid))
            }
            _ => None,
        }
    }

    fn uid(&self) -> Option<u32> {
        match self {
            Self::Fixed(_) | Self::JoinedRequestTrust(_) => Some(0),
            Self::JoinedStorageHostSession(uid) => *uid,
            Self::JoinedControllerSession(coordinates) => coordinates.map(|(_, uid)| uid),
            Self::JoinedControllerStorageFloor(uid) => *uid,
            Self::JoinedStartResourceSession(coordinates) => coordinates.map(|(_, uid)| uid),
            Self::JoinedMethod46InitialMain(coordinates) => coordinates.map(|(_, uid)| uid),
            Self::JoinedMethod46InitialFloor(coordinates) => coordinates.map(|(_, uid)| uid),
            #[cfg(test)]
            Self::Method46InitialFloorFixture(_, uid) => Some(*uid),
        }
    }
}

/// Selects the unchanged native existing or create-and-repair behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturedJournalOpenModeV1 {
    /// Requires both names, rejects stale compaction and incomplete tails.
    ExistingOnly,
    /// Permits missing names, stale-compaction cleanup and incomplete-tail repair.
    CreateAndRepair,
}

struct FixedProtectedCapturedJournalOpenV1 {
    recipe: ProtectedCapturedJournalRecipeV1,
    original: ProtectedWriterOpenOriginalsV1,
    limits: Option<JournalLimits>,
    before: Option<Result<(), JournalError>>,
    after: Option<Result<(), JournalError>>,
    final_currentness: Option<Result<(), JournalError>>,
    closed: Option<JournalError>,
    replay_entered: bool,
    taken: bool,
    owner_link: Option<StorageNativeOpeningOwnerLinkV1>,
    before_originals: super::ProtectedJournalCurrentnessOriginalsV1,
    after_originals: super::ProtectedJournalCurrentnessOriginalsV1,
    final_originals: [super::ProtectedJournalCurrentnessOriginalsV1; 2],
}

impl FixedProtectedCapturedJournalOpenV1 {
    /// Creates empty fixed custody without I/O or a replay allocation.
    #[must_use]
    const fn new(recipe: FixedProtectedJournalRecipeV1) -> Self {
        Self::with_recipe(ProtectedCapturedJournalRecipeV1::Fixed(recipe))
    }

    const fn with_recipe(recipe: ProtectedCapturedJournalRecipeV1) -> Self {
        Self {
            recipe,
            original: ProtectedWriterOpenOriginalsV1::new(),
            limits: None,
            before: None,
            after: None,
            final_currentness: None,
            closed: None,
            replay_entered: false,
            taken: false,
            owner_link: None,
            before_originals: super::ProtectedJournalCurrentnessOriginalsV1::new(),
            after_originals: super::ProtectedJournalCurrentnessOriginalsV1::new(),
            final_originals: [
                super::ProtectedJournalCurrentnessOriginalsV1::new(),
                super::ProtectedJournalCurrentnessOriginalsV1::new(),
            ],
        }
    }

    /// Prices fixed native custody before the first preparation operation.
    ///
    /// Each private recipe fixes its directory depth: six original directories
    /// for broker Session and Ownership, five for Storage siblings. Lock/main
    /// add two. A failed primary and its independent post can each retain one
    /// full rooted traversal and both names; complete positives dispose their
    /// actual fresh descriptors before the next stage.
    ///
    /// The owner, three ancestor-vector widths, sixteen fixed path/name copies and
    /// 32 bounded native-error payloads are provisioned separately from all
    /// semantic replay buffers. Strict syscall/path limits and the genuine
    /// service cgroup back allocator metadata and kernel objects (RFC-0006).
    /// This DATA does not authenticate or pay a receiving original.
    #[must_use]
    fn fixed_preparation_demand(
        recipe: FixedProtectedJournalRecipeV1,
    ) -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError> {
        let demand = ProtectedWriterOpenOriginalsV1::fixed_writable_preparation_demand_v1::<Self>(
            recipe.directory_descriptors(),
            (recipe.directory().len() + recipe.name().len()) as u16,
        )?;
        if matches!(
            recipe,
            FixedProtectedJournalRecipeV1::HostPeer
                | FixedProtectedJournalRecipeV1::HostExecution
                | FixedProtectedJournalRecipeV1::HostAgent
                | FixedProtectedJournalRecipeV1::HostLifecycle
                | FixedProtectedJournalRecipeV1::HostArgument
                | FixedProtectedJournalRecipeV1::EnvironmentEvidence
                | FixedProtectedJournalRecipeV1::MountBrokerSession
                | FixedProtectedJournalRecipeV1::HostBrokerSession
                | FixedProtectedJournalRecipeV1::RuntimeDeploymentMain
                | FixedProtectedJournalRecipeV1::RuntimeDeploymentFloor
                | FixedProtectedJournalRecipeV1::BrokerFloor
                | FixedProtectedJournalRecipeV1::BrokerSession
        ) {
            demand.checked_add(
                super::native_interval::captured::CapturedAppendOwnerV1::construction_demand_v1()
                    .ok_or(aos_sandbox_model::AccountingError::ArithmeticOverflow {
                        dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
                    })?,
            )
        } else {
            Ok(demand)
        }
    }

    /// Prepares the fixed original files and initial metadata once.
    ///
    /// The caller has already paid fixed native work. Existing-only selection
    /// cannot create either name, remove compaction, synchronize a creation or
    /// repair a tail. Failure leaves every reached original in this owner.
    fn prepare_once(&mut self, limits: JournalLimits, mode: CapturedJournalOpenModeV1) {
        if self.limits.is_some() || self.closed.is_some() || self.taken {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        let Some(directory) = self.recipe.directory() else {
            self.closed = Some(JournalError::ProtectedBoundary);
            return;
        };
        let Some(uid) = self.recipe.uid() else {
            self.closed = Some(JournalError::ProtectedBoundary);
            return;
        };
        self.limits = Some(limits);
        self.original.prepare_captured_for_uid_once(
            directory,
            self.recipe.name(),
            limits,
            uid,
            mode == CapturedJournalOpenModeV1::CreateAndRepair,
        );
    }

    /// Borrows partial representation DATA from the same actually held prefix.
    ///
    /// The genuine outer loan derives its permit while borrowing this owner;
    /// copying this DATA cannot fund replay or create another opening.
    #[must_use]
    fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        if self.closed.is_some() || self.replay_entered || self.taken {
            return None;
        }
        self.original.prepared_extent()
    }

    /// Replays that exact prefix once after its genuine receiving admission.
    ///
    /// The same held File/lock names are checked before entry. Independent
    /// post-names are retained even after a parser or tail error. No replacement
    /// path, UID, File, limit, decoded receipt or arbitrary callback is accepted.
    fn replay_once(&mut self) {
        if self.replay_entered || self.closed.is_some() || self.taken {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.replay_entered = true;
        let Some(limits) = self.limits else {
            self.closed = Some(JournalError::ProtectedBoundary);
            return;
        };
        let Some(directory) = self.recipe.directory() else {
            self.closed = Some(JournalError::ProtectedBoundary);
            return;
        };
        let Some(uid) = self.recipe.uid() else {
            self.closed = Some(JournalError::ProtectedBoundary);
            return;
        };
        self.before = Some(self.original.check_named_currentness_retaining(
            directory,
            self.recipe.name(),
            limits,
            uid,
            &mut self.before_originals,
        ));
        self.before_originals.settle_positive_once_v1();
        if matches!(self.before, Some(Ok(()))) && self.original.prepared_extent().is_some() {
            self.original.replay_prepared_once();
        }
        self.after = Some(self.original.check_named_currentness_retaining(
            directory,
            self.recipe.name(),
            limits,
            uid,
            &mut self.after_originals,
        ));
        self.after_originals.settle_positive_once_v1();
        if self.replay_ready() {
            if let Some(journal) = self.original.journal_mut() {
                self.owner_link = Some(StorageNativeOpeningOwnerLinkV1::of(journal));
            }
        }
    }

    /// Reports complete mechanical replay and names, without issuing authority.
    ///
    /// The actual Journal remains held here. The outer Session/floor/endpoint
    /// owner still validates its own independent policy before readiness.
    #[must_use]
    fn replay_ready(&self) -> bool {
        self.replay_entered
            && !self.taken
            && self.failure().is_none()
            && matches!(self.before, Some(Ok(())))
            && matches!(self.after, Some(Ok(())))
            && self.original.captured_opened_ready()
    }

    /// Moves the same Journal and recovery report after all positive bookends.
    ///
    /// A final held-file/name check precedes removal. This mechanical tuple
    /// establishes no Session schema, TPM floor, endpoint, grant or readiness.
    #[must_use]
    fn take_opened(&mut self) -> Option<(Journal, RecoveryReport)> {
        if !self.replay_ready() {
            return None;
        }
        let limits = self.limits?;
        if self.final_currentness.is_some() {
            self.closed = Some(JournalError::ProtectedBoundary);
            return None;
        }
        let directory = self.recipe.directory()?;
        let uid = self.recipe.uid()?;
        self.final_currentness = Some((|| {
            let journal = self
                .original
                .journal_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            journal.validate_held_owned_at_for_uid_retaining(
                directory,
                self.recipe.name(),
                uid,
                &mut self.final_originals[0],
            )?;
            self.final_originals[0].settle_positive_once_v1();
            journal.require_protected_location_retaining(
                directory,
                self.recipe.name(),
                uid,
                limits,
                &mut self.final_originals[1],
            )
        })());
        if !matches!(self.final_currentness, Some(Ok(()))) {
            return None;
        }
        self.final_originals[1].settle_positive_once_v1();
        if let Some((directory, name, uid)) = self.recipe.retained_append_identity_v1() {
            let journal = self.original.journal_mut()?;
            let super::native_backing::JournalNativeBackingV1::Ordinary(ordinary) =
                &mut journal.native
            else {
                return None;
            };
            if ordinary.captured_append.is_some() {
                return None;
            }
            // The actual fixed capture (or genuine B-derived role/UID) alone
            // selects this inert storage mode. Its real recipient pays growth.
            ordinary.captured_append = Some(
                super::native_interval::captured::CapturedAppendOwnerV1::new(directory, name, uid),
            );
        }
        let opened = self.original.take_captured_opened()?;
        self.taken = true;
        Some(opened)
    }

    // Status of this exact consumed Native tuple. It supplies no receiving or
    // domain authority; the genuine upper owner separately closes its posts.
    fn was_taken_positive(&self) -> bool {
        self.taken
            && self.replay_entered
            && self.failure().is_none()
            && matches!(self.before, Some(Ok(())))
            && matches!(self.after, Some(Ok(())))
            && matches!(self.final_currentness, Some(Ok(())))
    }

    /// Borrows the earliest original cause while later post debt stays held.
    #[must_use]
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .failure()
            .or_else(|| self.before_originals.failure())
            .or_else(|| {
                self.before
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| self.after_originals.failure())
            .or_else(|| {
                self.after
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| self.final_originals[0].failure())
            .or_else(|| self.final_originals[1].failure())
            .or_else(|| {
                self.final_currentness
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| {
                self.closed
                    .as_ref()
                    .map(|cause| cause as &(dyn Error + 'static))
            })
    }
}

/// Retains one fixed Storage broker Session opening across its replay permit.
///
/// This owns custody and DATA, never a Session, floor, payer or endpoint grant.
#[must_use = "retain partial native opening and independent posts on failure"]
pub struct StorageBrokerCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);

/// Retains one fixed Storage runtime-state opening across its replay permit.
///
/// Its compiled root-owned path is independent of the Session journal. The
/// same genuine Storage owner must separately price each actual opening.
#[must_use = "retain partial native opening and independent posts on failure"]
pub struct StorageStateCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);

/// Retains one fixed Storage workspace journal across its replay permit.
///
/// The actual upper owner keeps ordinary create/repair or operator existing-only
/// policy separate from this nonauthorizing native custody.
#[must_use = "retain partial native opening and independent posts on failure"]
pub struct StorageWorkspaceCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);

/// Retains one fixed Storage native-issuance journal across its replay permit.
///
/// The selected upper owner chooses existing-only mode and validates its own
/// complete issuance schema after the same original native replay.
#[must_use = "retain partial native opening and independent posts on failure"]
pub struct StorageNativeIssuanceCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);

/// Retains the fixed local Ownership journal before its separately paid replay.
///
/// The exact existing root-owned directory and basename are compiled here.
/// This private facade supplies custody and DATA; its genuine Ownership F
/// receiver must separately admit preparation, the held prefix and domain work.
#[must_use = "retain partial native opening and independent posts on failure"]
pub(crate) struct OwnershipCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);

// These facades expose the same custody mechanics, with no public recipe/path
// constructor. The private selector fixes each role's actual production name.
/// Retains the fixed already-provisioned Storage execution-output journal.
///
/// This facade supplies custody and extent DATA only. The selected caller must
/// pay its genuine receiving stage, use existing-only mode, and authenticate the
/// same original credential capacity/key before exposing a normal ledger.
pub struct StorageOutputCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);

/// Retains the fixed Environment evidence prefix without supplying authority.
#[must_use = "retain the same native prefix through independently paid posts"]
pub(crate) struct EnvironmentEvidenceCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);

/// Retains the fixed Host peer journal before separately paid replay.
///
/// This mechanical owner grants no Host peer, runtime or execution authority.
#[must_use = "retain failed native preparation and independent name posts"]
pub struct HostPeerCapturedJournalOpenV2(FixedProtectedCapturedJournalOpenV1);

/// Retains the fixed Host execution journal before separately paid replay.
#[must_use = "retain failed native preparation and independent name posts"]
pub struct HostExecutionCapturedJournalOpenV2(FixedProtectedCapturedJournalOpenV1);

/// Retains the fixed Host Agent journal before separately paid replay.
#[must_use = "retain failed native preparation and independent name posts"]
pub struct HostAgentCapturedJournalOpenV2(FixedProtectedCapturedJournalOpenV1);

/// Retains the fixed Host lifecycle journal before separately paid replay.
#[must_use = "retain failed native preparation and independent name posts"]
pub struct HostLifecycleCapturedJournalOpenV2(FixedProtectedCapturedJournalOpenV1);

/// Retains the fixed Host one-shot argument journal before separately paid replay.
///
/// It uses the same native/lock/parser/tail engine as the other fixed recipes.
/// A positive mechanical tuple still proves no argument or Guest authorization.
#[must_use = "retain failed native preparation and independent name posts"]
pub struct HostArgumentCapturedJournalOpenV2(FixedProtectedCapturedJournalOpenV1);

/// Retains the fixed Mount broker Session native opening and every failed prefix.
#[must_use = "retain the actual opening through all independently owed posts"]
pub struct MountBrokerSessionCapturedJournalOpenV4(FixedProtectedCapturedJournalOpenV1);

/// Retains Host's fixed broker Session opening without granting cleanup effects.
#[must_use = "retain the actual opening through all independently owed posts"]
pub struct HostBrokerSessionCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);


macro_rules! fixed_captured_journal_facade {
    ($facade:ident, $recipe:ident) => {
        impl $facade {
            /// Creates empty fixed custody without I/O or replay allocation.
            #[must_use]
            pub const fn new() -> Self {
                Self(FixedProtectedCapturedJournalOpenV1::new(
                    FixedProtectedJournalRecipeV1::$recipe,
                ))
            }

            /// Prices fixed native custody before preparation, without paying it.
            ///
            /// # Errors
            /// Refuses unrepresentable native or writable construction geometry.
            #[must_use]
            pub fn fixed_preparation_demand() -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError> {
                FixedProtectedCapturedJournalOpenV1::fixed_preparation_demand(
                    FixedProtectedJournalRecipeV1::$recipe,
                )
            }

            /// Prepares the compiled original path and first metadata once.
            ///
            /// Existing-only mode never creates either name or repairs a tail.
            pub fn prepare_once(&mut self, limits: JournalLimits, mode: CapturedJournalOpenModeV1) {
                self.0.prepare_once(limits, mode);
            }

            /// Borrows partial DATA from this same held original prefix.
            #[must_use]
            pub fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
                self.0.captured_extent()
            }

            /// Replays this exact held prefix after its separate genuine permit.
            ///
            /// Whole parser results and independent posts stay in this owner.
            pub fn replay_once(&mut self) {
                self.0.replay_once();
            }

            /// Reports positive mechanical replay and posts, without authority.
            #[must_use]
            pub fn replay_ready(&self) -> bool {
                self.0.replay_ready()
            }

            /// Moves the same Journal/report after the final original-name check.
            #[must_use]
            pub fn take_opened(&mut self) -> Option<(Journal, RecoveryReport)> {
                self.0.take_opened()
            }

            /// Borrows the original first cause while later debt remains held.
            #[must_use]
            pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
                self.0.failure()
            }

            /// Reports positive transfer of this exact original Journal tuple.
            ///
            /// This is custody DATA only, without domain or receiving authority.
            #[must_use]
            pub fn was_taken_positive_v1(&self) -> bool {
                self.0.was_taken_positive()
            }

            pub(crate) fn opening_owner_link_v1(&self) -> Option<&StorageNativeOpeningOwnerLinkV1> {
                self.0.owner_link.as_ref()
            }
        }

        impl Default for $facade {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}


/// Retains the fixed deployment055 main opening and every failed native prefix.
///
/// This mechanical destination supplies no Source, signed purpose, floor or
/// append authority. The normal publisher always selects existing-only mode.
#[must_use = "retain this same original through all independently owed posts"]
pub struct RuntimeDeploymentMainCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);

/// Retains the fixed deployment055 sidecar opening and failed native prefixes.
///
/// The same staged native/semantic engine supplies custody only. The actual
/// normal caller separately pays and authenticates its complete floor schema.
#[must_use = "retain this same original through all independently owed posts"]
pub struct RuntimeDeploymentFloorCapturedJournalOpenV1(FixedProtectedCapturedJournalOpenV1);

fixed_captured_journal_facade!(
    RuntimeDeploymentMainCapturedJournalOpenV1,
    RuntimeDeploymentMain
);
fixed_captured_journal_facade!(
    RuntimeDeploymentFloorCapturedJournalOpenV1,
    RuntimeDeploymentFloor
);



fixed_captured_journal_facade!(MountBrokerSessionCapturedJournalOpenV4, MountBrokerSession);
fixed_captured_journal_facade!(HostBrokerSessionCapturedJournalOpenV1, HostBrokerSession);

fixed_captured_journal_facade!(
    EnvironmentEvidenceCapturedJournalOpenV1,
    EnvironmentEvidence
);
fixed_captured_journal_facade!(StorageBrokerCapturedJournalOpenV1, BrokerSession);
fixed_captured_journal_facade!(StorageStateCapturedJournalOpenV1, RuntimeState);

fixed_captured_journal_facade!(StorageWorkspaceCapturedJournalOpenV1, Workspaces);
fixed_captured_journal_facade!(StorageNativeIssuanceCapturedJournalOpenV1, NativeIssuance);
fixed_captured_journal_facade!(StorageOutputCapturedJournalOpenV1, ExecutionOutput);
fixed_captured_journal_facade!(HostPeerCapturedJournalOpenV2, HostPeer);
fixed_captured_journal_facade!(HostExecutionCapturedJournalOpenV2, HostExecution);
fixed_captured_journal_facade!(HostAgentCapturedJournalOpenV2, HostAgent);
fixed_captured_journal_facade!(HostLifecycleCapturedJournalOpenV2, HostLifecycle);
fixed_captured_journal_facade!(HostArgumentCapturedJournalOpenV2, HostArgument);

/// Retains the actual Storage-origin-joined request-trust journal opening.
///
/// The directory comes only from the same genuine Storage receiving loan's
/// retained PID1/own-argv join. The literal basename is compiled here. This
/// facade grants no trust, signer, service, replay or receiving authority.
#[must_use = "retain partial native opening and independent posts on failure"]
pub struct StorageRequestTrustCapturedJournalOpenV1 {
    inner: FixedProtectedCapturedJournalOpenV1,
    entry: Option<Result<(), crate::StorageReceivingClosedV1>>,
    directory: Option<Result<(), crate::StorageReceivingClosedV1>>,
    reservation: Option<Result<(), std::collections::TryReserveError>>,
    attempted: bool,
}

impl StorageRequestTrustCapturedJournalOpenV1 {
    /// Creates empty custody without acquiring a path or native object.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: FixedProtectedCapturedJournalOpenV1::with_recipe(
                ProtectedCapturedJournalRecipeV1::JoinedRequestTrust(None),
            ),
            entry: None,
            directory: None,
            reservation: None,
            attempted: false,
        }
    }

    /// Derives native preparation geometry from the same retained original path.
    ///
    /// No path copy or native open occurs here. The actual receiving owner must
    /// debit this demand before marking its one trust preparation as prepared.
    ///
    /// # Errors
    /// Rejects changed original Storage custody or unrepresentable native path
    /// depth/width; a scalar or caller pathname cannot select this directory.
    pub fn fixed_preparation_demand(
        original: &mut crate::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<aos_sandbox_model::ResourceVector, crate::StorageReceivingClosedV1> {
        let directory = original.storage_authority_directory_v1()?;
        let (descriptors, bytes) = request_trust_directory_geometry(directory)?;
        ProtectedWriterOpenOriginalsV1::fixed_writable_preparation_demand_v1::<Self>(descriptors, bytes)
            .map_err(|error| original.retain_native_geometry_refusal_v1(error))
    }

    /// Consumes the same original's prepaid trust preparation before path/IO.
    ///
    /// The actual startup guard selects existing/create policy and unchanged
    /// limits. A denied gate, directory/currentness error or partial native
    /// preparation stays resident; none can retry or select another directory.
    pub fn prepare_once(
        &mut self,
        limits: JournalLimits,
        mode: CapturedJournalOpenModeV1,
        original: &mut crate::StoragePrepareReceivingLoanV1<'_>,
    ) {
        if self.attempted {
            self.inner
                .closed
                .get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.attempted = true;
        self.entry = Some(original.enter_request_trust_fixed_preparation_once_v1());
        if !matches!(self.entry, Some(Ok(()))) {
            self.inner.closed = Some(JournalError::ProtectedBoundary);
            return;
        }
        self.directory = Some((|| {
            let directory = original.storage_authority_directory_v1()?;
            request_trust_directory_geometry(directory)?;
            let ProtectedCapturedJournalRecipeV1::JoinedRequestTrust(saved) =
                &mut self.inner.recipe
            else {
                return Err(crate::StorageReceivingClosedV1);
            };
            *saved = Some(std::path::PathBuf::new());
            let saved = saved.as_mut().ok_or(crate::StorageReceivingClosedV1)?;
            self.reservation = Some(saved.try_reserve_exact(directory.as_os_str().len()));
            if !matches!(self.reservation, Some(Ok(()))) {
                return Err(crate::StorageReceivingClosedV1);
            }
            saved.push(directory);
            Ok(())
        })());
        if !matches!(self.directory, Some(Ok(()))) {
            self.inner.closed = Some(JournalError::ProtectedBoundary);
            return;
        }
        self.inner.prepare_once(limits, mode);
    }

    /// Borrows DATA from this same held native prefix, without a replay grant.
    #[must_use]
    pub fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        self.inner.captured_extent()
    }

    /// Replays the same captured file after its actual separate receiving debit.
    pub fn replay_once(&mut self) {
        self.inner.replay_once();
    }

    /// Reports complete mechanical replay and names, never admitted trust.
    #[must_use]
    pub fn replay_ready(&self) -> bool {
        self.inner.replay_ready()
    }

    /// Moves the same Journal/report after the final same-original name check.
    #[must_use]
    pub fn take_opened(&mut self) -> Option<(Journal, RecoveryReport)> {
        self.inner.take_opened()
    }

    /// Reports positive transfer of this exact joined original Journal tuple.
    ///
    /// This is custody DATA and supplies no Trust, payer or domain authority.
    #[must_use]
    pub fn was_taken_positive_v1(&self) -> bool {
        matches!(self.entry, Some(Ok(())))
            && matches!(self.directory, Some(Ok(())))
            && matches!(self.reservation, Some(Ok(())))
            && self.inner.was_taken_positive()
    }

    pub(crate) fn opening_owner_link_v1(&self) -> Option<&StorageNativeOpeningOwnerLinkV1> {
        self.inner.owner_link.as_ref()
    }

    /// Borrows the first original failure while later post debt stays held.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.entry
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| {
                self.reservation
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| {
                self.directory
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| self.inner.failure())
    }
}

impl Default for StorageRequestTrustCapturedJournalOpenV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn request_trust_directory_geometry(
    directory: &Path,
) -> Result<(u16, u16), crate::StorageReceivingClosedV1> {
    use std::path::Component;

    if !directory.is_absolute()
        || directory
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(crate::StorageReceivingClosedV1);
    }
    let descriptors = u16::try_from(directory.components().count())
        .map_err(|_| crate::StorageReceivingClosedV1)?;
    let bytes = directory
        .as_os_str()
        .len()
        .checked_add(ProtectedCapturedJournalRecipeV1::TRUST_BASENAME.len())
        .and_then(|bytes| u16::try_from(bytes).ok())
        .ok_or(crate::StorageReceivingClosedV1)?;
    Ok((descriptors, bytes))
}

#[cfg(test)]
mod owner_link_tests {
    use super::*;

    #[test]
    fn reopened_same_file_cannot_replace_the_actual_opening_identity() {
        // Actual native opens establish both identities. This tests the
        // historical same-name substitution witness without constructing a
        // receiving original or claiming positive protected-facade custody.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.journal");
        let (historical_journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let historical = StorageNativeOpeningOwnerLinkV1::of(&historical_journal);
        drop(historical_journal);

        let (actual_journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let actual = StorageNativeOpeningOwnerLinkV1::of(&actual_journal);
        let same_actual = actual.clone();

        assert!(actual.same_owner(&same_actual));
        assert!(!actual.same_owner(&historical));
        assert!(!historical.same_owner(&same_actual));
        drop(actual_journal);
    }
}
