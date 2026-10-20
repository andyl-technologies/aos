//! Same-original Storage startup journals through one closed staged engine.
//!
//! The guard borrows both the genuine receiver and the actual fixed Native
//! opener before preparation. No path, descriptor, prefix or ceiling supplied
//! by a caller can mint this loan or substitute another prepared opener.

use super::*;
use crate::journal::{
    CapturedJournalOpenModeV1, JournalLimits, ProtectedJournalPreopenReplayExtentV1,
    StorageStateCapturedJournalOpenV1, StorageWorkspaceCapturedJournalOpenV1,
    StorageOutputCapturedJournalOpenV1,
    StorageNativeIssuanceCapturedJournalOpenV1, StorageRequestTrustCapturedJournalOpenV1,
};

#[derive(Default)]
struct StartupStageV1 {
    fixed: bool,
    prepared: bool,
    native_entered: bool,
    schema: bool,
    replayed: bool,
    initialization: bool,
    taken: bool,
}

#[derive(Clone, Copy)]
enum StartupProfileV1 {
    Ordinary,
    HeldNative,
}

impl StartupProfileV1 {
    fn argument(self) -> &'static str {
        match self {
            Self::Ordinary => "-",
            Self::HeldNative => "zfs-hold-key-v1",
        }
    }
}

#[derive(Clone, Copy)]
enum OutputProfileV1 {
    Absent,
    Provisioned,
}

pub(super) struct StartupJournalStagesV1 {
    profile: Option<Result<StartupProfileV1, StorageReceivingClosedV1>>,
    configuration: bool,
    output_profile: Option<OutputProfileV1>,
    output_configuration: bool,
    output: StartupStageV1,
    output_identity: Option<crate::journal::StorageNativeOpeningOwnerLinkV1>,
    state_identity: Option<crate::journal::StorageNativeOpeningOwnerLinkV1>,
    workspace_identity: Option<crate::journal::StorageNativeOpeningOwnerLinkV1>,
    output_names_post_entered: bool,
    retirement: bool,
    retirement_post_reservation: Option<Result<(), StorageReceivingClosedV1>>,
    retirement_post_armed: bool,
    retirement_post_entered: bool,
    retirement_names_entered: bool,
    retirement_work_entered: bool,
    trust_configuration: bool,
    state: StartupStageV1,
    workspace: StartupStageV1,
    issuance: StartupStageV1,
    trust: StartupStageV1,
}

impl StartupJournalStagesV1 {
    pub(super) const fn new() -> Self {
        const FRESH: StartupStageV1 = StartupStageV1 {
            fixed: false,
            prepared: false,
            native_entered: false,
            schema: false,
            replayed: false,
            initialization: false,
            taken: false,
        };
        Self {
            profile: None,
            configuration: false,
            output_profile: None,
            output_configuration: false,
            output: FRESH,
            output_identity: None,
            state_identity: None,
            workspace_identity: None,
            output_names_post_entered: false,
            retirement: false,
            retirement_post_reservation: None,
            retirement_post_armed: false,
            retirement_post_entered: false,
            retirement_names_entered: false,
            retirement_work_entered: false,
            trust_configuration: false,
            state: FRESH,
            workspace: FRESH,
            issuance: FRESH,
            trust: FRESH,
        }
    }

    pub(super) fn failure(&self) -> Option<&StorageReceivingClosedV1> {
        self.profile.as_ref().and_then(|result| result.as_ref().err())
    }

    pub(super) fn before_runtime_configuration_v1(&self) -> bool {
        self.profile.is_none() && !self.configuration && !self.state.fixed
    }

    pub(super) fn complete(&self) -> bool {
        let writers_complete = self.configuration && self.output_complete() && self.state.taken
            && self.workspace.taken && self.issuance.taken;
        match self.profile {
            Some(Ok(StartupProfileV1::Ordinary)) => writers_complete,
            Some(Ok(StartupProfileV1::HeldNative)) => writers_complete && self.trust.taken,
            _ => false,
        }
    }

    pub(super) fn state_recovery_ready_v1(&self, journal: &crate::Journal) -> bool {
        self.complete() && self.state_identity.as_ref()
            .is_some_and(|writer| writer.matches_journal_v1(journal))
    }

    pub(super) fn state_initial_pin_quiescence_ready_v1(&self, journal: &crate::Journal) -> bool {
        self.configuration && self.output_complete() && self.state.taken
            && matches!(self.profile, Some(Ok(StartupProfileV1::Ordinary | StartupProfileV1::HeldNative)))
            && !self.workspace.fixed && !self.issuance.fixed && !self.trust.fixed
            && self.state_identity.as_ref()
                .is_some_and(|writer| writer.matches_journal_v1(journal))
    }

    pub(super) fn matches_workspace_journal_v1(&self, journal: &crate::Journal) -> bool {
        self.complete() && self.workspace_identity.as_ref()
            .is_some_and(|writer| writer.matches_journal_v1(journal))
    }

    pub(super) fn state_identity_v1(&self) -> Option<crate::journal::StorageNativeOpeningOwnerLinkV1> {
        self.state_identity.clone()
    }

    pub(super) fn output_post_ready_v1(&self) -> bool {
        self.configuration && self.output_configuration && !self.state.fixed
            && matches!(self.output_profile, Some(OutputProfileV1::Provisioned))
    }

    pub(super) fn output_currentness_ready_v1(&self, journal: &crate::Journal) -> bool {
        self.output_configuration && self.output.taken
            && matches!(self.output_profile, Some(OutputProfileV1::Provisioned))
            && self.output_identity.as_ref().is_some_and(|owner| owner.matches_journal_v1(journal))
    }

    pub(super) fn arm_output_names_post_v1(&mut self) {
        self.output_names_post_entered = false;
    }

    pub(super) fn enter_output_names_post_v1(&mut self, journal: &crate::Journal) -> bool {
        if !self.output_currentness_ready_v1(journal) || self.output_names_post_entered {
            return false;
        }
        self.output_names_post_entered = true;
        true
    }

    fn output_complete(&self) -> bool {
        match self.output_profile {
            Some(OutputProfileV1::Absent) => true,
            Some(OutputProfileV1::Provisioned) => self.output.taken,
            None => false,
        }
    }

    pub(super) fn state_ready_for_initialization(&self) -> bool {
        self.configuration && self.state.taken && self.state.initialization && !self.workspace.fixed
    }

    fn stage(&mut self, kind: KindV1) -> &mut StartupStageV1 {
        match kind {
            KindV1::Output => &mut self.output,
            KindV1::State => &mut self.state,
            KindV1::Workspace => &mut self.workspace,
            KindV1::Issuance => &mut self.issuance,
            KindV1::Trust => &mut self.trust,
        }
    }

    pub(super) fn native_settlement_ready(&self, kind: NativeOpeningKindV1) -> bool {
        let stage = match kind {
            NativeOpeningKindV1::Output => &self.output,
            NativeOpeningKindV1::State => &self.state,
            NativeOpeningKindV1::Workspace => &self.workspace,
            NativeOpeningKindV1::Issuance => &self.issuance,
            NativeOpeningKindV1::Trust => &self.trust,
            NativeOpeningKindV1::Session => return false,
        };
        stage.fixed && stage.prepared && stage.native_entered && stage.schema
            && stage.replayed && stage.initialization && stage.taken
    }

    fn predecessor_complete(&self, kind: KindV1) -> bool {
        match kind {
            KindV1::Output => self.configuration && self.output_configuration
                && matches!(self.output_profile, Some(OutputProfileV1::Provisioned)),
            KindV1::State => self.configuration && self.output_complete(),
            KindV1::Workspace => self.state.taken && self.retirement,
            KindV1::Issuance => self.workspace.taken,
            KindV1::Trust => self.issuance.taken && self.trust_configuration
                && matches!(self.profile, Some(Ok(StartupProfileV1::HeldNative))),
        }
    }
}

#[derive(Clone, Copy)]
enum KindV1 {
    Output,
    State,
    Workspace,
    Issuance,
    Trust,
}

impl KindV1 {
    fn native_opening_kind(self) -> NativeOpeningKindV1 {
        match self {
            Self::Output => NativeOpeningKindV1::Output,
            Self::State => NativeOpeningKindV1::State,
            Self::Workspace => NativeOpeningKindV1::Workspace,
            Self::Issuance => NativeOpeningKindV1::Issuance,
            Self::Trust => NativeOpeningKindV1::Trust,
        }
    }
}

enum ActualOpenerV1<'cut> {
    Output(&'cut mut StorageOutputCapturedJournalOpenV1),
    State(&'cut mut StorageStateCapturedJournalOpenV1),
    Workspace(&'cut mut StorageWorkspaceCapturedJournalOpenV1),
    Issuance(&'cut mut StorageNativeIssuanceCapturedJournalOpenV1),
    Trust(&'cut mut StorageRequestTrustCapturedJournalOpenV1),
}

impl ActualOpenerV1<'_> {
    fn kind(&self) -> KindV1 {
        match self {
            Self::Output(_) => KindV1::Output,
            Self::State(_) => KindV1::State,
            Self::Workspace(_) => KindV1::Workspace,
            Self::Issuance(_) => KindV1::Issuance,
            Self::Trust(_) => KindV1::Trust,
        }
    }

    fn fixed_demand(
        &self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<ResourceVector, StorageReceivingClosedV1> {
        match self {
            Self::Output(_) => StorageOutputCapturedJournalOpenV1::fixed_preparation_demand()
                .map_err(|error| receiving.retain_native_geometry_refusal_v1(error)),
            Self::State(_) => StorageStateCapturedJournalOpenV1::fixed_preparation_demand()
                .map_err(|error| receiving.retain_native_geometry_refusal_v1(error)),
            Self::Workspace(_) => StorageWorkspaceCapturedJournalOpenV1::fixed_preparation_demand()
                .map_err(|error| receiving.retain_native_geometry_refusal_v1(error)),
            Self::Issuance(_) => StorageNativeIssuanceCapturedJournalOpenV1::fixed_preparation_demand()
                .map_err(|error| receiving.retain_native_geometry_refusal_v1(error)),
            Self::Trust(_) => StorageRequestTrustCapturedJournalOpenV1::fixed_preparation_demand(receiving),
        }
    }

    fn extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        match self {
            Self::Output(opener) => opener.captured_extent(),
            Self::State(opener) => opener.captured_extent(),
            Self::Workspace(opener) => opener.captured_extent(),
            Self::Issuance(opener) => opener.captured_extent(),
            Self::Trust(opener) => opener.captured_extent(),
        }
    }

    fn prepare(
        &mut self,
        limits: JournalLimits,
        mode: CapturedJournalOpenModeV1,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
    ) {
        match self {
            Self::Output(opener) => opener.prepare_once(limits, mode),
            Self::State(opener) => opener.prepare_once(limits, mode),
            Self::Workspace(opener) => opener.prepare_once(limits, mode),
            Self::Issuance(opener) => opener.prepare_once(limits, mode),
            Self::Trust(opener) => opener.prepare_once(limits, mode, receiving),
        }
    }

    fn replay(&mut self) {
        match self {
            Self::Output(opener) => opener.replay_once(),
            Self::State(opener) => opener.replay_once(),
            Self::Workspace(opener) => opener.replay_once(),
            Self::Issuance(opener) => opener.replay_once(),
            Self::Trust(opener) => opener.replay_once(),
        }
    }

    fn ready(&self) -> bool {
        match self {
            Self::Output(opener) => opener.replay_ready(),
            Self::State(opener) => opener.replay_ready(),
            Self::Workspace(opener) => opener.replay_ready(),
            Self::Issuance(opener) => opener.replay_ready(),
            Self::Trust(opener) => opener.replay_ready(),
        }
    }

    fn owner_link(&self) -> Option<&crate::journal::StorageNativeOpeningOwnerLinkV1> {
        match self {
            Self::Output(opener) => opener.opening_owner_link_v1(),
            Self::State(opener) => opener.opening_owner_link_v1(),
            Self::Workspace(opener) => opener.opening_owner_link_v1(),
            Self::Issuance(opener) => opener.opening_owner_link_v1(),
            Self::Trust(opener) => opener.opening_owner_link_v1(),
        }
    }

    fn take(&mut self) -> Option<(crate::Journal, crate::RecoveryReport)> {
        match self {
            Self::Output(opener) => opener.take_opened(),
            Self::State(opener) => opener.take_opened(),
            Self::Workspace(opener) => opener.take_opened(),
            Self::Issuance(opener) => opener.take_opened(),
            Self::Trust(opener) => opener.take_opened(),
        }
    }
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Selects ordinary startup from the same actual captured '-' invocation.
    ///
    /// This selects only payment/order requirements. It creates no key,
    /// issuance, grant or permission to omit active-interest validation.
    ///
    /// # Errors
    /// Refuses reentry, changed original custody or a different measured argv10.
    pub fn select_ordinary_startup_once_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        self.select_startup_once_v1(StartupProfileV1::Ordinary)
    }

    /// Selects full held startup from the actual captured key-profile invocation.
    ///
    /// The full owner still requires its actual signing key and pinned Trust.
    /// No parsed argument or resource vector reconstructs those owners.
    ///
    /// # Errors
    /// Refuses reentry, changed original custody or a different measured argv10.
    pub fn select_held_native_startup_once_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        self.select_startup_once_v1(StartupProfileV1::HeldNative)
    }

    fn select_startup_once_v1(&mut self, profile: StartupProfileV1)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        if receiving.startup.profile.is_some() || receiving.startup.configuration {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let exact_argument = |result: &Option<ParentResult>| {
            result.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|parent| parent.0.arguments().get(10))
                .is_some_and(|argument| argument == profile.argument())
        };
        let joined = exact_argument(&receiving.before) && exact_argument(&receiving.after);
        let output = receiving.before.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(|parent| parent.0.arguments().get(11));
        let output_after = receiving.after.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(|parent| parent.0.arguments().get(11));
        let joined = joined && output.is_some() && output == output_after;
        if joined {
            receiving.startup.output_profile = Some(if output.is_some_and(|value| value == "-") {
                OutputProfileV1::Absent
            } else {
                OutputProfileV1::Provisioned
            });
        }
        receiving.startup.profile = Some(if joined { Ok(profile) } else { Err(StorageReceivingClosedV1) });
        if !joined {
            receiving.first.get_or_insert(Failure::StartupProfile);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Borrows the verified actual authority directory from the same invocation.
    ///
    /// # Errors
    /// Refuses changed originals or absent initial argument/recipient joins.
    pub(crate) fn storage_authority_directory_v1(&mut self)
        -> Result<&std::path::Path, StorageReceivingClosedV1>
    {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        let parent = receiving.before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(StorageReceivingClosedV1)?;
        let directory = parent.0.arguments().get(6).ok_or(StorageReceivingClosedV1)?;
        Ok(std::path::Path::new(directory))
    }

    /// Restricts a protected Trust-file read to the same original argv directory.
    ///
    /// This comparison exports neither its path nor a directory authority.
    /// The fixed Native Trust opener independently borrows that same argument.
    ///
    /// # Errors
    /// Refuses absent/changed original custody or a different raw path argument.
    pub fn require_storage_authority_directory_v1(&mut self, directory: &std::path::Path)
        -> Result<(), StorageReceivingClosedV1>
    {
        if self.storage_authority_directory_v1()?.as_os_str() != directory.as_os_str() {
            self.receiving()?.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Joins bootstrap/resolver DATA to the same captured fixed invocation.
    ///
    /// # Errors
    /// Refuses changed originals or paths different from both actual enclosing
    /// PID1 property observations. No caller index or path grants authority.
    pub fn require_storage_startup_directories_v1(
        &mut self,
        bootstrap: &std::path::Path,
        resolver: Option<&std::path::Path>,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        let joined = [&receiving.before, &receiving.after].into_iter().all(|result| {
            result.as_ref().and_then(|result| result.as_ref().ok())
                .is_some_and(|parent| startup_directories_match_v1(parent.0.arguments(), bootstrap, resolver))
        });
        if !joined {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Consumes the paid Trust preparation entry before its path copy/native IO.
    ///
    /// # Errors
    /// Refuses changed originals, absent preparation payment or a second actual
    /// facade entry. A forgotten outer guard cannot spend this entry twice.
    pub(crate) fn enter_request_trust_fixed_preparation_once_v1(&mut self)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        let predecessor = receiving.startup.issuance.taken;
        let stage = &mut receiving.startup.trust;
        if !predecessor || !stage.fixed || !stage.prepared || stage.native_entered {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        stage.native_entered = true;
        Ok(())
    }

    /// Pays protected authority and bounded bootstrap parsing before loading.
    ///
    /// The upper DATA covers its actual bootstrap model and wire capacities;
    /// Broker's own exact protected-configuration supplier is added here.
    ///
    /// # Errors
    /// Refuses reentry, changed originals or any arithmetic/ceiling refusal.
    pub fn reserve_startup_configuration_once_v1(&mut self, upper: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        if !receiving.template.positive()
            || !matches!(receiving.startup.profile, Some(Ok(_)))
            || receiving.startup.configuration
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let demand = aos_sandbox_broker::ProtectedBrokerAuthorityConfiguration::receiving_demand_v1()
            .and_then(|broker| broker.checked_add(upper));
        let demand = match demand {
            Ok(demand) => demand,
            Err(error) => {
                receiving.arithmetic = Some(error);
                receiving.first.get_or_insert(Failure::Arithmetic);
                return Err(StorageReceivingClosedV1);
            }
        };
        receiving.reserve(demand)?;
        receiving.startup.configuration = true;
        Ok(())
    }

    /// Requires the same paid startup interval and a fresh original observation.
    ///
    /// # Errors
    /// Refuses absent configuration payment, closed originals or currentness debt.
    pub fn require_startup_current_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        if !self.receiving()?.startup.configuration {
            self.receiving()?.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)
    }

    /// Prepays and arms the same original's one owed startup-retirement post.
    ///
    /// This reserves resident upper name custody and the actual observer's full
    /// exclusive operation before forecast or work payment can fail. It does
    /// not authorize retirement or reopen a closed receiving interval.
    ///
    /// # Errors
    /// Refuses absent State ownership, repeat entry, failed original admission
    /// or inability to pay the required post before entering the work interval.
    pub fn reserve_startup_retirement_posts_once_v1(&mut self, names: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if !receiving.startup.state_ready_for_initialization()
            || receiving.startup.retirement_post_reservation.is_some()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.startup.retirement_post_reservation = Some(receiving.reserve(names));
        if !matches!(receiving.startup.retirement_post_reservation, Some(Ok(()))) {
            return Err(StorageReceivingClosedV1);
        }
        if receiving.current.prepare_once_v1(&mut receiving.ledger, &receiving.lifetime).is_err() {
            receiving.first.get_or_insert(Failure::Current);
            return Err(StorageReceivingClosedV1);
        }
        receiving.startup.retirement_post_armed = true;
        Ok(())
    }

    /// Observes the fixed State names into its already prepaid post destination.
    ///
    /// This observation remains available on the continuously held genuine
    /// loan after work/health refusal. It creates no healthy writer authority,
    /// work payment or positive completion, and cannot clear a first failure.
    /// The paid caller destination receives the actual health Result before
    /// physical names are sampled, preserving their exact failure chronology.
    ///
    /// # Errors
    /// Refuses an unarmed/unpaid post, repeated use, another writer recipe or
    /// an actual retained lock/journal name observation failure.
    pub fn observe_startup_retirement_names_once_v1(
        &mut self,
        journal: &crate::Journal,
        originals: &mut crate::journal::ProtectedJournalCurrentnessOriginalsV1,
        health: &mut Option<Result<(), crate::JournalError>>,
    ) -> Result<(), crate::JournalError> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else {
            return Err(crate::JournalError::ProtectedBoundary);
        };
        if !self.original.open || !receiving.startup.retirement_post_armed
            || receiving.startup.retirement_names_entered
            || receiving.startup.retirement_post_entered
            || !matches!(receiving.startup.retirement_post_reservation, Some(Ok(())))
            || health.is_some()
            || !journal.is_fixed_storage_state_post_v1()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(crate::JournalError::ProtectedBoundary);
        }
        receiving.startup.retirement_names_entered = true;
        *health = Some(journal.ensure_healthy());
        let result = journal.observe_held_names_post_retaining_v1(originals);
        if matches!(health, Some(Err(_))) {
            // Keep the actual health Result above. Physical names success is
            // never a healthy authority or positive enclosing completion.
            receiving.first.get_or_insert(Failure::Closed);
            return Err(crate::JournalError::Poisoned);
        }
        if result.is_err() {
            receiving.first.get_or_insert(Failure::Closed);
        }
        result
    }

    /// Executes only the already prepaid owed original post after startup work.
    ///
    /// This observation cannot reserve work, lend authority or clear a prior
    /// financial failure. It uses the same continuously held mutable loan and
    /// consumes the private pending observer flight exactly once.
    ///
    /// # Errors
    /// Refuses an absent/unfunded post, reentry, closed native lifetime or any
    /// actual native, PID1, containment, pair, transport or binding failure.
    pub fn finish_startup_retirement_post_once_v1(&mut self)
        -> Result<(), StorageReceivingClosedV1>
    {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else {
            return Err(StorageReceivingClosedV1);
        };
        if !receiving.startup.retirement_post_armed || receiving.startup.retirement_post_entered {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.startup.retirement_post_entered = true;
        self.observe_prepared_startup_retirement_v1()
    }

    fn observe_prepared_startup_retirement_v1(&mut self)
        -> Result<(), StorageReceivingClosedV1>
    {
        let observation = super::super::StartupObservation::begin(&mut self.original.open)
            .map_err(|_| StorageReceivingClosedV1)?;
        let Some(StorageResourceRecipientCustodyV1::Receiving { component, receiving }) =
            self.original.recipient.as_mut()
        else {
            return Err(StorageReceivingClosedV1);
        };
        if !receiving.startup.retirement_post_armed
            || !matches!(receiving.startup.retirement_post_reservation, Some(Ok(())))
            || !receiving.initial_transports_disposed
            || !receiving.containment.named_verifications_settled_v1()
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let Some(initial) = receiving.before.as_ref().and_then(|result| result.as_ref().ok()) else {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        };
        let result = receiving.current.observe_prepared_once_v1(
            &receiving.lifetime, &self.original.custody, component, initial, &receiving.containment,
        );
        if result.is_err() {
            receiving.first.get_or_insert(Failure::Current);
            return Err(StorageReceivingClosedV1);
        }
        // Restoring the observation latch does not clear receiving.first or
        // the ledger refusal: ordinary positive entries remain closed.
        observation.finish();
        Ok(())
    }

    /// Pays exact authenticated Prepared retirement work before recovery clones.
    ///
    /// The upper supplier borrows actual State records. This value grants no
    /// retirement authority; existing exact-current/expiry checks remain there.
    ///
    /// # Errors
    /// Refuses reentry, absent actual State/init custody or the service ceiling.
    pub fn reserve_startup_retirement_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if !receiving.startup.state_ready_for_initialization()
            || !receiving.startup.retirement_post_armed
            || receiving.startup.retirement_post_entered
            || receiving.startup.retirement_work_entered
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.startup.retirement_work_entered = true;
        // Preserve the original pre-work currentness frontier after the pure
        // forecast. That real flight completes before its sample can be
        // disposed and the separately owed post flight can be armed.
        self.observe_prepared_startup_retirement_v1()?;
        let receiving = self.receiving()?;
        if receiving.current.prepare_once_v1(&mut receiving.ledger, &receiving.lifetime).is_err() {
            receiving.first.get_or_insert(Failure::Current);
            return Err(StorageReceivingClosedV1);
        }
        // The post is now fully funded and pending before this reservation
        // can poison the resident ledger. No work authority follows an Err.
        receiving.reserve(demand)?;
        receiving.startup.retirement = true;
        Ok(())
    }

    /// Pays one retained catalog-observer peak before the first startup flight.
    ///
    /// Storage derives this DATA from its fixed observer implementation. The
    /// same Runtime observer may reuse this resident peak only after its actual
    /// previous response, acknowledgment and exact natural exit have succeeded.
    /// A failed or ambiguous observer retains its original and closes that reuse.
    ///
    /// # Errors
    /// Refuses missing configuration payment, repeat payment, changed original
    /// custody, or an exceeded whole-service receiving envelope.
    pub fn reserve_catalog_observer_peak_once_v1(
        &mut self,
        demand: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_startup_current_v1()?;
        let receiving = self.receiving()?;
        if !receiving.startup.configuration || receiving.catalog_observer_peak_paid {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(demand)?;
        receiving.catalog_observer_peak_paid = true;
        Ok(())
    }

    /// Restricts the optional Output source to the same original measured argv11.
    ///
    /// # Errors
    /// Refuses absent Output configuration, substitution or changed originals.
    pub fn require_storage_output_source_v1(&mut self, source: &std::path::Path)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.require_startup_current_v1()?;
        let receiving = self.receiving()?;
        let exact = [&receiving.before, &receiving.after].into_iter().all(|result| {
            result.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|parent| parent.0.arguments().get(11))
                .is_some_and(|value| value != "-" && std::path::Path::new(value) == source)
        });
        if !exact || !matches!(receiving.startup.output_profile, Some(OutputProfileV1::Provisioned)) {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Requires the same measured Output source on its persistent writer owner.
    ///
    /// # Errors
    /// Refuses missing original payment, a different actual Journal instance,
    /// a substituted source argument or changed/failed service currentness.
    pub fn require_retained_output_journal_v1(
        &mut self,
        journal: &crate::Journal,
        source: &std::path::Path,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.require_storage_output_source_v1(source)?;
        let receiving = self.receiving()?;
        if !receiving.startup.output_currentness_ready_v1(journal) {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Pays the actual fixed Output key/source prefix before its first IO.
    ///
    /// # Errors
    /// Refuses a different source, repeat entry, entered State or exceeded budget.
    pub fn reserve_output_configuration_once_v1(&mut self, source: &std::path::Path, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.require_storage_output_source_v1(source)?;
        let receiving = self.receiving()?;
        if receiving.startup.output_configuration || receiving.startup.state.fixed {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(demand)?;
        receiving.startup.output_configuration = true;
        Ok(())
    }

    /// Borrows the same Output opener after its original fixed-prefix payment.
    ///
    /// # Errors
    /// Refuses missing payment, reentry, a changed original or exceeded budget.
    pub fn borrow_output_startup_once_v1<'cut>(&'cut mut self,
        opener: &'cut mut StorageOutputCapturedJournalOpenV1)
        -> Result<StoragePrepareStartupJournalLoanV1<'cut, 'original>, StorageReceivingClosedV1>
    {
        self.borrow_startup_once_v1(ActualOpenerV1::Output(opener))
    }

    /// Borrows the actual fixed State opener and pays before native preparation.
    ///
    /// # Errors
    /// Refuses reentry, missing original currentness or the service ceiling.
    pub fn borrow_state_startup_once_v1<'cut>(&'cut mut self,
        opener: &'cut mut StorageStateCapturedJournalOpenV1)
        -> Result<StoragePrepareStartupJournalLoanV1<'cut, 'original>, StorageReceivingClosedV1>
    {
        self.borrow_startup_once_v1(ActualOpenerV1::State(opener))
    }

    /// Borrows the actual workspace opener after the original State stage.
    ///
    /// # Errors
    /// Refuses an incomplete predecessor, reentry, original debt or the ceiling.
    pub fn borrow_workspace_startup_once_v1<'cut>(&'cut mut self,
        opener: &'cut mut StorageWorkspaceCapturedJournalOpenV1)
        -> Result<StoragePrepareStartupJournalLoanV1<'cut, 'original>, StorageReceivingClosedV1>
    {
        self.borrow_startup_once_v1(ActualOpenerV1::Workspace(opener))
    }

    /// Borrows the actual Native issuance opener after workspace startup.
    ///
    /// # Errors
    /// Refuses an incomplete predecessor, reentry, original debt or the ceiling.
    pub fn borrow_issuance_startup_once_v1<'cut>(&'cut mut self,
        opener: &'cut mut StorageNativeIssuanceCapturedJournalOpenV1)
        -> Result<StoragePrepareStartupJournalLoanV1<'cut, 'original>, StorageReceivingClosedV1>
    {
        self.borrow_startup_once_v1(ActualOpenerV1::Issuance(opener))
    }

    /// Pays Trust's fixed file/parse custody before its existing file-first read.
    ///
    /// The upper DATA describes its actual fixed owner,312-byte record, paths
    /// and native slots. The later fixed Native facade debit remains separate.
    ///
    /// # Errors
    /// Refuses a missing issuance predecessor, reentry or the service ceiling.
    pub fn reserve_trust_configuration_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.require_startup_current_v1()?;
        let receiving = self.receiving()?;
        if !matches!(receiving.startup.profile, Some(Ok(StartupProfileV1::HeldNative)))
            || !receiving.startup.issuance.taken || receiving.startup.trust_configuration
            || receiving.startup.trust.fixed
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(demand)?;
        receiving.startup.trust_configuration = true;
        Ok(())
    }

    /// Borrows the actual request-trust opener from the joined startup directory.
    ///
    /// # Errors
    /// Refuses an incomplete predecessor, reentry, original debt or the ceiling.
    pub fn borrow_trust_startup_once_v1<'cut>(&'cut mut self,
        opener: &'cut mut StorageRequestTrustCapturedJournalOpenV1)
        -> Result<StoragePrepareStartupJournalLoanV1<'cut, 'original>, StorageReceivingClosedV1>
    {
        self.borrow_startup_once_v1(ActualOpenerV1::Trust(opener))
    }

    fn borrow_startup_once_v1<'cut>(&'cut mut self, opener: ActualOpenerV1<'cut>)
        -> Result<StoragePrepareStartupJournalLoanV1<'cut, 'original>, StorageReceivingClosedV1>
    {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let kind = opener.kind();
        let receiving = self.receiving()?;
        if !receiving.startup.predecessor_complete(kind) || receiving.startup.stage(kind).fixed {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let demand = opener.fixed_demand(self)?;
        let receiving = self.receiving()?;
        receiving.reserve_native_opening_v1(kind.native_opening_kind(), demand,
            demand.get(D::OpenFiles))?;
        receiving.startup.stage(kind).fixed = true;
        Ok(StoragePrepareStartupJournalLoanV1 { receiving: self, opener, kind })
    }
}

/// Keeps one actual startup opener and its same original payer borrowed.
#[must_use]
pub struct StoragePrepareStartupJournalLoanV1<'cut, 'original> {
    receiving: &'cut mut StoragePrepareReceivingLoanV1<'original>,
    opener: ActualOpenerV1<'cut>,
    kind: KindV1,
}

impl StoragePrepareStartupJournalLoanV1<'_, '_> {
    /// Prepares the same fixed Native opener before any variable replay work.
    ///
    /// # Errors
    /// Refuses reentry, missing actual capture or changed original currentness.
    pub fn prepare_once_v1(&mut self, limits: JournalLimits, mode: CapturedJournalOpenModeV1)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.receiving.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving.receiving()?;
        if matches!(self.kind, KindV1::Output) && mode != CapturedJournalOpenModeV1::ExistingOnly {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        if receiving.startup.stage(self.kind).prepared {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.startup.stage(self.kind).prepared = true;
        self.opener.prepare(limits, mode, self.receiving);
        let prepared = self.opener.extent().is_some();
        // This independent original post is owed even when Native preparation
        // retains an error before it can expose a physical prefix.
        let current = self.receiving.original.recheck();
        if !prepared || current.is_err() {
            return self.close();
        }
        Ok(())
    }

    /// Borrows the actual held prefix as DATA for the upper schema supplier.
    pub fn captured_extent_v1(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        self.opener.extent()
    }

    /// Debits upper schema/model capacities before replay or schema decoding.
    ///
    /// # Errors
    /// Refuses missing actual preparation, reentry or an exceeded original.
    pub fn reserve_schema_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving.receiving()?;
        let stage = receiving.startup.stage(self.kind);
        if !stage.prepared || stage.schema { return self.close(); }
        receiving.reserve(demand)?;
        receiving.startup.stage(self.kind).schema = true;
        Ok(())
    }

    /// Debits native/semantic geometry and replays the same held opener once.
    ///
    /// # Errors
    /// Retains native/parser/accounting/currentness failure and closes reuse.
    pub fn replay_once_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        let Some(extent) = self.opener.extent() else { return self.close(); };
        let demand = extent.dominant_native_receiving_demand_v1()
            .and_then(|native| extent.dominant_semantic_receiving_demand_v1()
                .map(|semantic| (native, semantic)));
        let receiving = self.receiving.receiving()?;
        let stage = receiving.startup.stage(self.kind);
        if !stage.schema || stage.replayed { return self.close(); }
        let (native, semantic) = match demand {
            Ok(demand) => demand,
            Err(error) => {
                receiving.shape = Some(error);
                receiving.first.get_or_insert(Failure::Shape);
                return Err(StorageReceivingClosedV1);
            }
        };
        let demand = match native.checked_add(semantic) {
            Ok(demand) => demand,
            Err(error) => {
                receiving.arithmetic = Some(error);
                receiving.first.get_or_insert(Failure::Arithmetic);
                return Err(StorageReceivingClosedV1);
            }
        };
        receiving.reserve(demand)?;
        // Mark before entering the actual parser so Drop/forget cannot rearm it.
        receiving.startup.stage(self.kind).replayed = true;
        self.opener.replay();
        let ready = self.opener.ready();
        let post = self.receiving.original.recheck();
        if !ready || post.is_err() { return self.close(); }
        let Some(owner) = self.opener.owner_link() else { return self.close(); };
        self.receiving.receiving()?.bind_native_opening_owner_v1(
            self.kind.native_opening_kind(), owner,
        )?;
        if matches!(self.kind, KindV1::State) {
            let receiving = self.receiving.receiving()?;
            if receiving.startup.state_identity.is_some() {
                return self.close();
            }
            receiving.startup.state_identity = Some(owner.clone());
        }
        if matches!(self.kind, KindV1::Workspace) {
            let receiving = self.receiving.receiving()?;
            if receiving.startup.workspace_identity.is_some() {
                return self.close();
            }
            // SAME existing Journal Arc, captured only after actual paid
            // Workspace replay and every original/name post stayed positive.
            receiving.startup.workspace_identity = Some(owner.clone());
        }
        if matches!(self.kind, KindV1::Output) {
            let receiving = self.receiving.receiving()?;
            if receiving.startup.output_identity.is_some() {
                return self.close();
            }
            // Reuse the SAME already existing Journal Arc after this borrowed
            // paid replay and all posts; no new identity or heap allocation.
            receiving.startup.output_identity = Some(owner.clone());
        }
        Ok(())
    }

    /// Debits actual post-replay initialization/append growth before Journal take.
    ///
    /// # Errors
    /// Refuses absent positive actual replay, reentry or the original ceiling.
    pub fn reserve_initialization_once_v1(&mut self, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let ready = self.opener.ready();
        let receiving = self.receiving.receiving()?;
        let stage = receiving.startup.stage(self.kind);
        if !ready || !stage.replayed || stage.initialization { return self.close(); }
        receiving.reserve(demand)?;
        receiving.startup.stage(self.kind).initialization = true;
        Ok(())
    }

    /// Moves the same actual positive Journal to its already priced schema owner.
    ///
    /// # Errors
    /// Refuses missing payment, reentry, native final posts or changed originals.
    pub fn take_opened_once_v1(&mut self)
        -> Result<(crate::Journal, crate::RecoveryReport), StorageReceivingClosedV1>
    {
        self.receiving.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving.receiving()?;
        let stage = receiving.startup.stage(self.kind);
        if !stage.initialization || stage.taken { return self.close(); }
        let Some(opened) = self.opener.take() else { return self.close(); };
        self.receiving.receiving()?.startup.stage(self.kind).taken = true;
        Ok(opened)
    }

    fn close<T>(&mut self) -> Result<T, StorageReceivingClosedV1> {
        if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        {
            receiving.first.get_or_insert(Failure::Closed);
        }
        Err(StorageReceivingClosedV1)
    }
}

impl Drop for StoragePrepareStartupJournalLoanV1<'_, '_> {
    fn drop(&mut self) {
        if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        {
            if !receiving.startup.stage(self.kind).taken {
                receiving.first.get_or_insert(Failure::Closed);
            }
        }
    }
}

// These fixed fields come from the unchanged measured twelve-argument producer.
// The comparison is DATA; only the method above joins two original observations.
fn startup_directories_match_v1(
    arguments: &[String],
    bootstrap: &std::path::Path,
    resolver: Option<&std::path::Path>,
) -> bool {
    arguments.get(7).is_some_and(|argument| std::path::Path::new(argument) == bootstrap)
        && arguments.get(8).is_some_and(|argument| match resolver {
            Some(path) => argument != "-" && std::path::Path::new(argument) == path,
            None => argument == "-",
        })
}

#[cfg(test)]
mod directory_argument_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn bootstrap_and_optional_resolver_are_distinct_from_template_and_key_profile() {
        let mut arguments = [
            "/nix/store/storage/bin/aos-storaged", "0", "0", "100000", "64",
            "/nix/store/zfs/sbin/zfs", "/run/credentials/storage", "/bootstrap",
            "/resolver", "/nix/store/guest-template", "-", "-",
        ].map(str::to_owned);

        assert!(startup_directories_match_v1(&arguments, Path::new("/bootstrap"), Some(Path::new("/resolver"))));
        assert!(!startup_directories_match_v1(&arguments, Path::new("/bootstrap"), None));
        assert!(!startup_directories_match_v1(&arguments, Path::new("/nix/store/guest-template"), Some(Path::new("/resolver"))));
        arguments[8] = "-".to_owned();
        assert!(startup_directories_match_v1(&arguments, Path::new("/bootstrap"), None));
        assert!(!startup_directories_match_v1(&arguments[..8], Path::new("/bootstrap"), None));
    }
}

#[cfg(test)]
mod initial_pin_phase_tests {
    //! Exercises only DATA eligibility; these fixtures admit no receiving loan.

    use super::*;

    #[test]
    fn early_cleanup_requires_actual_taken_state_epoch_and_no_later_writer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.journal");
        let (actual, _) = crate::Journal::open(&path, crate::JournalLimits::default()).unwrap();
        let mut startup = StartupJournalStagesV1::new();
        startup.configuration = true;
        startup.profile = Some(Ok(StartupProfileV1::Ordinary));
        startup.output_profile = Some(OutputProfileV1::Absent);
        startup.state_identity = Some(actual.held_session_owner_link_v1());

        assert!(!startup.state_initial_pin_quiescence_ready_v1(&actual));
        startup.state.taken = true;
        assert!(startup.state_initial_pin_quiescence_ready_v1(&actual));
        startup.workspace.fixed = true;
        assert!(!startup.state_initial_pin_quiescence_ready_v1(&actual));

        startup.workspace.fixed = false;
        drop(actual);
        let (reopened, _) = crate::Journal::open(&path, crate::JournalLimits::default()).unwrap();
        assert!(!startup.state_initial_pin_quiescence_ready_v1(&reopened));
    }
}
