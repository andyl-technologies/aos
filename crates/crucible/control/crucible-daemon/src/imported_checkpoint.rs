//! One-use launch selection from a completely authenticated receiver archive.
//!
//! Import proves immutable contents, not a source executor's local execution
//! rows. This module binds a published archive and its durable exact pin to
//! receiver-selected compatibility and resource policy. A fresh admitted
//! Service consumes the result; no source execution identity is fabricated.

use std::sync::Arc;

use crucible_engine::{Configuration, ScenarioDefForm};
use crucible_campaign::{
    AttemptResourceLimits, CampaignArchiveManifestId, CampaignArchivePolicy, CampaignHash,
    CampaignLineageId, CampaignName, CampaignPolicyId, CampaignRepository, CampaignRepositoryError,
    ConfigurationId, ExactCheckpointId,
};
use crucible_store::ram::RamStoreError;
use thiserror::Error;

use crate::crucible_artifact::decode_crucible_configuration_artifact_from_repository;
use crate::executor_supervisor::SelectedExactCheckpointRoot;
use crate::{
    AttemptExecutionContext, CrucibleArtifactError, DirectoryExactPinMaterializationStore,
    ExactCheckpointStore, ExactCheckpointStoreError, ExactPinRetentionAdmin,
    ExactPinRetentionError, decode_crucible_scenario_artifact,
};

/// Receiver-authorized compatibility and semantic execution limits.
pub struct ReceiverCheckpointPolicy {
    /// Compatibility lineage selected by the trusted receiver operator.
    pub lineage: CampaignLineageId,
    /// Immutable campaign policy accepted by the receiver operator.
    pub policy: CampaignPolicyId,
    /// Semantic execution limits for this receiver realization.
    pub resources: AttemptResourceLimits,
    /// Receiver deployment's independent maximum semantic limits.
    pub resource_ceiling: AttemptResourceLimits,
}

/// Borrowed receiver inventories authenticated before a launch claim is issued.
pub struct ImportedCheckpointAdmission<'a, 'owner> {
    /// Receiver repository whose published refs select complete imported data.
    pub repository: Arc<CampaignRepository>,
    /// Checkpoint reader sharing the exact receiver backend allocation.
    pub checkpoints: &'a ExactCheckpointStore,
    /// Durable receiver selection journal populated by archive import.
    pub selections: &'a mut DirectoryExactPinMaterializationStore,
    /// Already published executable archive reference.
    pub archive: &'a str,
    /// Already published receiver campaign naming the archive snapshot.
    pub campaign: &'a CampaignName,
    /// Exact configuration selected by the trusted receiver caller.
    pub configuration: ConfigurationId,
    /// Independently selected receiver compatibility and limits.
    pub policy: ReceiverCheckpointPolicy,
    /// Already admitted owner supervising authentication and retained scratch.
    pub context: &'owner AttemptExecutionContext,
}

/// Non-cloneable archive selection that can authorize one physical launch.
///
/// The selection borrows the admitted authentication owner until a fresh
/// receiver Service accepts the decoded basis. It cannot be duplicated or
/// detached from that owner.
///
/// ```compile_fail
/// use crucible_daemon::imported_checkpoint::AuthenticatedImportedCheckpoint;
/// fn duplicate(claim: AuthenticatedImportedCheckpoint<'_>) {
///     let second_launch = claim.clone();
/// }
/// ```
///
/// ```compile_fail
/// use crucible_daemon::imported_checkpoint::AuthenticatedImportedCheckpoint;
/// fn detach(claim: AuthenticatedImportedCheckpoint<'_>)
///     -> AuthenticatedImportedCheckpoint<'static>
/// {
///     claim
/// }
/// ```
pub struct AuthenticatedImportedCheckpoint<'owner> {
    basis: ImportedCheckpointBasis,
    authentication_owner: &'owner AttemptExecutionContext,
    authentication_operation: crucible_host_resources::host_supervision::HostOperationGuard,
    // Keep this guard last: actual decoded material and the private Transfer
    // must be destroyed before its ordinary alias acknowledgment can occur.
    parent_receiver: AuthenticatedImportReceiver,
}

/// Acknowledges only the actual no-native aliases preceding this last field.
///
/// Normal field destruction is the prerequisite. During unwind the original
/// receiver remains unacknowledged, so a panicking destructor cannot certify
/// closure. Consuming launch handoff moves the same receiver into its capsule.
struct AuthenticatedImportReceiver(Option<crate::ServiceMainReceiver>);

impl AuthenticatedImportReceiver {
    fn take(&mut self) -> Option<crate::ServiceMainReceiver> {
        self.0.take()
    }
}

impl Drop for AuthenticatedImportReceiver {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Dropping an unacknowledged receiver keeps its actual census debt.
            // This deliberately supplies no native or successful-return proof.
            return;
        }
        if let Some(receiver) = self.0.take() {
            match receiver.return_after_alias_destruction() {
                Ok(()) => {}
                // This is an invariant refusal, not a borrow/retry transition.
                // Its Drop retries only the explicitly recorded alias cut;
                // failed acknowledgment still bars reuse of the same role.
                Err(receiver) => drop(receiver),
            }
        }
    }
}

/// Authenticated semantic material retained through receiver world cleanup.
pub(crate) struct ImportedCheckpointBasis {
    pub(crate) repository: Arc<CampaignRepository>,
    pub(crate) archive: CampaignArchiveManifestId,
    pub(crate) checkpoint: ExactCheckpointId,
    pub(crate) source: ScenarioDefForm,
    pub(crate) configuration: Configuration,
    pub(crate) resources: AttemptResourceLimits,
    pub(crate) budgets: crucible_host_resources::host_supervision::HostOperationBudgets,
}

impl<'owner> AuthenticatedImportedCheckpoint<'owner> {
    /// Authenticates a published executable archive under original supervision.
    ///
    /// The caller chooses policy using trusted receiver configuration, before
    /// consuming imported bytes. An untrusted manifest cannot choose its own
    /// compatibility lineage, policy revision, or resource ceiling. The same
    /// receiver backend allocation must back both campaign and checkpoint I/O.
    /// The admitted authentication owner remains borrowed until a fresh receiver
    /// Service takes the decoded material. Its reservation must remain live;
    /// finishing that owner before consuming or dropping the claim is invalid.
    ///
    /// # Errors
    /// Refuses detached ownership, incompatible receiver policy, unpublished or
    /// incomplete archives, absent or changed pins, another backend authority,
    /// unpromoted roots, cancellation, corruption, or an expired boundary.
    pub fn prepare(
        admission: ImportedCheckpointAdmission<'_, 'owner>,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<Self, ImportedCheckpointError> {
        let ImportedCheckpointAdmission {
            repository,
            checkpoints,
            selections,
            archive,
            campaign,
            configuration,
            policy,
            context,
        } = admission;
        if context.host_ram_resource_ceiling().is_none()
            || context.host_operation_supervisor().is_none()
        {
            return Err(
                ImportedCheckpointErrorCause::Binding("receiver owner is not admitted").into(),
            );
        }
        // Retain the actual parent role before a new Transfer or context alias
        // exists. Cloning a selector is not an alias-return acknowledgment.
        let parent_receiver = context
            .retain_service_receiver("authenticate imported checkpoint")
            .map_err(ImportedCheckpointErrorCause::ServiceReceiver)?;
        let mut parent_receiver = AuthenticatedImportReceiver(parent_receiver);
        let result = (|| -> Result<Self, ImportedCheckpointErrorCause> {
            let supervisor = context.host_operation_supervisor().ok_or(
                ImportedCheckpointErrorCause::Binding("receiver supervision is absent"),
            )?;
            let authentication_operation = supervisor
                .begin(crucible_host_resources::host_supervision::HostOperationClass::Transfer)?;
            let mut supervised_boundary = || {
                authentication_operation
                    .wait_slice()
                    .map_err(|_| RamStoreError::Canceled)?;
                boundary()
            };
            let boundary =
                &mut supervised_boundary as &mut dyn FnMut() -> Result<(), RamStoreError>;
            let budgets = supervisor.budgets()?.1;
            // Fresh Replay Services have their own operation starts, with the
            // receiver's accepted allowances. They do not inherit an ended cap.
            budgets.validate(false)?;
            check_resources(policy.resources, policy.resource_ceiling)?;
            boundary()?;
            checkpoints.require_reuse_backend(&repository.blob_backend())?;
            let inspected =
                repository.inspect_campaign_archive_ref_with_boundary(archive, boundary)?;
            if inspected.manifest().policy() != CampaignArchivePolicy::Executable {
                return Err(ImportedCheckpointErrorCause::Binding(
                    "archive is not executable",
                ));
            }
            let head = repository.head(campaign.as_str())?;
            if head.snapshot_id() != inspected.manifest().source_snapshot()
                || head.snapshot().lineage() != policy.lineage
                || head.snapshot().active_policy() != policy.policy
            {
                return Err(ImportedCheckpointErrorCause::Binding(
                    "receiver campaign basis differs",
                ));
            }
            let selection = selections
                .acquire_exact_pin_retention_fence()?
                .selection(campaign, configuration)?
                .ok_or(ImportedCheckpointErrorCause::Binding(
                    "durable exact pin is absent",
                ))?;
            if !inspected
                .manifest()
                .checkpoint_selections()
                .iter()
                .any(|record| {
                    record.configuration() == configuration
                        && record.pin_fact() == selection.pin_fact()
                        && record.checkpoint() == selection.checkpoint()
                })
            {
                return Err(ImportedCheckpointErrorCause::Binding(
                    "archive exact pin differs",
                ));
            }

            // Retain no selection-journal lock across checkpoint or artifact I/O.
            // Both the published snapshot and exact fact are immutable identities.
            let mut pin = None;
            repository.visit_pin_retention_roots_at(head.snapshot_id(), &mut |record| {
                if record.request().change.configuration() == configuration {
                    pin = Some(record);
                }
            })?;
            let pin = pin.ok_or(ImportedCheckpointErrorCause::Binding(
                "snapshot exact pin is absent",
            ))?;
            if pin.fact() != selection.pin_fact()
                || pin.retention() != crucible_campaign::PinRetention::Exact
            {
                return Err(ImportedCheckpointErrorCause::Binding(
                    "snapshot pin fact differs",
                ));
            }
            boundary()?;
            let scenario_artifact = repository.load_scenario_artifact(pin.scenario_artifact())?;
            let source = decode_crucible_scenario_artifact(&scenario_artifact)?;
            let lineage = repository.load_lineage(policy.lineage)?;
            if lineage.scenario_content() != pin.scenario_artifact() {
                return Err(ImportedCheckpointErrorCause::Binding(
                    "scenario lineage differs",
                ));
            }
            let configuration_artifact =
                repository.load_configuration_artifact(pin.configuration_artifact())?;
            let decoded = decode_crucible_configuration_artifact_from_repository(
                &source,
                &scenario_artifact,
                &configuration_artifact,
                &repository,
            )?;
            if ConfigurationId::from_hash(CampaignHash::from_bytes(decoded.id().bytes))
                != configuration
            {
                return Err(ImportedCheckpointErrorCause::Binding(
                    "configuration artifact differs",
                ));
            }
            boundary()?;
            let loaded = checkpoints.load_production_closure_with_cancellation(
                selection.checkpoint(),
                context.cancellation(),
            )?;
            if loaded.scenario() != source.scenario_def().id()
                || loaded.configuration() != decoded.id()
            {
                return Err(ImportedCheckpointErrorCause::Binding(
                    "checkpoint semantic basis differs",
                ));
            }
            let raw = loaded
                .promotion_source()
                .ok_or(ImportedCheckpointErrorCause::Binding(
                    "checkpoint is not promoted",
                ))?;
            crate::exact_checkpoint_restore::authenticate_production_exact_checkpoint_replay_oracle_promotion(
            checkpoints, raw, selection.checkpoint(), &source, context.cancellation(),
        ).map_err(|source| ImportedCheckpointErrorCause::Restore(Box::new(source)))?;
            boundary()?;

            // Recheck mutable publication preconditions at claim issuance. Later
            // launch still authenticates the immutable closure and consumes this
            // claim; it cannot substitute another root or revive canceled authority.
            if repository.head(campaign.as_str())?.snapshot_id() != head.snapshot_id()
                || repository
                    .inspect_campaign_archive_ref_with_boundary(archive, boundary)?
                    .manifest_id()
                    != inspected.manifest_id()
            {
                return Err(ImportedCheckpointErrorCause::Binding(
                    "publication changed during admission",
                ));
            }
            Ok(Self {
                basis: ImportedCheckpointBasis {
                    repository,
                    archive: inspected.manifest_id(),
                    checkpoint: selection.checkpoint(),
                    source,
                    configuration: decoded,
                    resources: policy.resources,
                    budgets,
                },
                authentication_owner: context,
                authentication_operation,
                parent_receiver: AuthenticatedImportReceiver(None),
            })
        })();
        match result {
            Ok(mut imported) => {
                imported.parent_receiver = parent_receiver;
                Ok(imported)
            }
            Err(first) => {
                // The closure has destroyed every local guard/context alias.
                // Preserve a refused acknowledgment alongside the actual cause.
                let receiver_return = parent_receiver.take().and_then(|receiver| {
                    receiver
                        .return_after_alias_destruction()
                        .err()
                        .map(|receiver| {
                            receiver.into_failure("return failed import authentication aliases")
                        })
                });
                Err(ImportedCheckpointError {
                    cause: first,
                    receiver_return,
                })
            }
        }
    }

    pub(crate) fn source(&self) -> &ScenarioDefForm {
        &self.basis.source
    }

    pub(crate) fn repository(&self) -> &Arc<CampaignRepository> {
        &self.basis.repository
    }

    pub(crate) fn authentication_owner(&self) -> &AttemptExecutionContext {
        self.authentication_owner
    }

    pub(crate) fn resources(&self) -> AttemptResourceLimits {
        self.basis.resources
    }

    pub(crate) fn budgets(
        &self,
    ) -> crucible_host_resources::host_supervision::HostOperationBudgets {
        self.basis.budgets
    }

    /// Returns the exact authenticated root selected for the one-use launch.
    pub fn checkpoint(&self) -> ExactCheckpointId {
        self.basis.checkpoint
    }

    /// Returns the completely authenticated published receiver archive identity.
    pub fn archive(&self) -> CampaignArchiveManifestId {
        self.basis.archive
    }

    /// Moves actual imported ownership into the preborn Main startup phase.
    ///
    /// The returned lifetime witness contains only the existing borrow. The
    /// capsule owns the same Transfer and decoded material before startup or
    /// its trailing post can refuse; no closure capture is its only receiver.
    pub(crate) fn into_start_custody(
        mut self,
    ) -> (RetainedImportedCheckpoint, ImportedCheckpointOwner<'owner>) {
        let selected = SelectedExactCheckpointRoot::after_authenticated_import(&self);
        let owner = ImportedCheckpointOwner(self.authentication_owner);
        (
            RetainedImportedCheckpoint {
                basis: Some(self.basis),
                selected: Some(selected),
                owner_custody: self.authentication_owner.clone(),
                operation: self.authentication_operation,
                parent_receiver: self.parent_receiver.take(),
                launch_attempted: false,
                launch_ready: false,
                maintenance: false,
                first: None,
                post: None,
            },
            owner,
        )
    }
}

/// Owns a single authenticated import until successful caller handoff.
///
/// This body is embedded in the already prepaid Service phase. Selection is
/// private until the same original passes its chosen launch transition.
pub struct RetainedImportedCheckpoint {
    basis: Option<ImportedCheckpointBasis>,
    selected: Option<SelectedExactCheckpointRoot>,
    owner_custody: AttemptExecutionContext,
    operation: crucible_host_resources::host_supervision::HostOperationGuard,
    parent_receiver: Option<crate::ServiceMainReceiver>,
    launch_attempted: bool,
    launch_ready: bool,
    maintenance: bool,
    first: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    post: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
}

/// Owns exported import input when the previous Service cannot close.
///
/// The input retains its original parent account and unconsumed Transfer. The
/// report selects the actual genesis Main; neither field is a new reservation.
pub struct ImportedCheckpointHandoffFailure {
    input: UnpublishedImportedInput,
    first: crate::PreparedSourceFailure,
    retirement_refusal: Option<crate::PreparedSourceRefusal>,
    terminal: Option<crate::ProductionVmConstructionPostBody>,
}

impl ImportedCheckpointHandoffFailure {
    pub(crate) fn new(
        input: RetainedImportedCheckpoint,
        first: crate::PreparedSourceFailure,
    ) -> Self {
        Self {
            input: UnpublishedImportedInput::new(input),
            first,
            retirement_refusal: None,
            terminal: None,
        }
    }

    pub(crate) fn retain_retirement_refusal(&mut self, first: crate::PreparedSourceRefusal) {
        if self.retirement_refusal.is_none() {
            self.retirement_refusal = Some(first);
        }
    }

    pub(crate) fn retain_terminal(&mut self, terminal: crate::ProductionVmConstructionPostBody) {
        self.terminal = Some(terminal);
    }

    /// Borrows actual terminal history after the original native body returned.
    #[must_use]
    pub fn terminal_history(&self) -> Option<&crate::ProductionVmConstructionPostBody> {
        self.terminal.as_ref()
    }

    /// Borrows the independent bounded refusal of the same cleanup attempt.
    #[must_use]
    pub fn retirement_refusal(&self) -> Option<&crate::PreparedSourceRefusal> {
        self.retirement_refusal.as_ref()
    }

    /// Borrows the same retained genesis failure without extracting its owner.
    #[must_use]
    pub fn first_error(&self) -> &crate::PreparedSourceFailure {
        &self.first
    }

    /// Returns the actual input through its original cleanup-only transition.
    ///
    /// The result keeps raw Original completion and independent post facts,
    /// including any actual parent receiver whose acknowledgment still refuses.
    #[must_use]
    /// # Errors
    /// Returns this same owning report if its input was already consumed.
    pub fn into_retirement(
        mut self,
    ) -> Result<
        (
            ImportedCheckpointReturn,
            crate::PreparedSourceFailure,
            Option<crate::PreparedSourceRefusal>,
            Option<crate::ProductionVmConstructionPostBody>,
        ),
        Self,
    > {
        let Some(input) = self.input.take() else {
            return Err(self);
        };
        Ok((
            input.retire_unpublished(),
            self.first,
            self.retirement_refusal,
            self.terminal,
        ))
    }
}

/// Returns parent-authenticated input when an unpublished report is discarded.
///
/// This inline guard is for input that has never owned a native World. It uses
/// the same cleanup-only transition and actual physical alias destruction as
/// explicit retirement. It never substitutes a Drop observation for native
/// return or changes an expired Original's historical sign.
pub struct UnpublishedImportedInput(Option<RetainedImportedCheckpoint>);

impl UnpublishedImportedInput {
    pub(crate) fn new(input: RetainedImportedCheckpoint) -> Self {
        Self(Some(input))
    }

    pub(crate) fn take(&mut self) -> Option<RetainedImportedCheckpoint> {
        self.0.take()
    }

    /// Returns the actual unpublished input through its cleanup-only transition.
    ///
    /// # Errors
    /// Returns the same owning guard if the input was already consumed. A raw
    /// Original failure remains in the returned receipt, independently of actual
    /// alias destruction and the ordinary receiver acknowledgment.
    pub fn into_retirement(mut self) -> Result<ImportedCheckpointReturn, Self> {
        match self.0.take() {
            Some(input) => Ok(input.retire_unpublished()),
            None => Err(self),
        }
    }
}

impl std::fmt::Debug for UnpublishedImportedInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnpublishedImportedInput")
            .field("input_present", &self.0.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for UnpublishedImportedInput {
    fn drop(&mut self) {
        if let Some(input) = self.0.take() {
            // retire_unpublished destroys basis/selection/guard/context first.
            // Its return receipt retries only an explicitly recorded ordinary
            // receiver ACK; stale/corrupt custody remains quarantined.
            drop(input.retire_unpublished());
        }
    }
}

impl std::fmt::Debug for ImportedCheckpointHandoffFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportedCheckpointHandoffFailure")
            .field("first", &self.first)
            .field("retirement_refusal", &self.retirement_refusal)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ImportedCheckpointHandoffFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.first, formatter)
    }
}

impl std::error::Error for ImportedCheckpointHandoffFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.terminal.as_ref() {
            Some(terminal) if terminal.first_failure().is_some() => Some(terminal),
            _ => Some(&self.first),
        }
    }
}

/// Preserves the actual borrow required by an imported launch continuation.
pub(crate) struct ImportedCheckpointOwner<'owner>(&'owner AttemptExecutionContext);

impl RetainedImportedCheckpoint {
    pub(crate) fn basis(&self) -> Option<&ImportedCheckpointBasis> {
        self.basis.as_ref()
    }

    pub(crate) fn authentication_owner(&self) -> &AttemptExecutionContext {
        &self.owner_custody
    }

    /// Reports only whether the original launch selection remains untouched.
    pub(crate) fn is_unlaunched(&self) -> bool {
        !self.launch_attempted
            && !self.launch_ready
            && self.first.is_none()
            && self.post.is_none()
            && self.basis.is_some()
            && self.selected.is_some()
    }

    /// Checks the retained authentication Original without consuming selection.
    pub(crate) fn check_original(
        &self,
    ) -> Result<(), crucible_host_resources::host_supervision::HostSupervisionError> {
        self.operation.wait_slice().map(|_| ())
    }

    /// Moves the same parent lease into a child sharing its actual outer cap.
    ///
    /// The child retains this lease through supervisor/watchdog/control closure;
    /// returning only the launch output cannot return those separate aliases.
    pub(crate) fn take_shared_parent_receiver(
        &mut self,
        outer: &crucible_host_resources::host_supervision::HostOperationSupervisor,
    ) -> Option<crate::ServiceMainReceiver> {
        self.owner_custody
            .host_operation_supervisor()
            .filter(|parent| parent.shares_outer_cap(outer))?;
        self.parent_receiver.take()
    }

    /// Applies the same once-only import transition while retaining every error.
    pub(crate) fn prepare_launch(
        &mut self,
        maintenance: bool,
    ) -> Result<
        SelectedExactCheckpointRoot,
        crucible_host_resources::host_supervision::HostSupervisionError,
    > {
        use crucible_host_resources::host_supervision::{HostOperationClass, HostSupervisionError};
        if self.launch_attempted || self.selected.is_none() || self.basis.is_none() {
            return Err(HostSupervisionError::Unavailable);
        }
        self.launch_attempted = true;
        self.maintenance = maintenance;
        let result = if maintenance {
            self.operation
                .verify_operation_class(HostOperationClass::Transfer)
        } else {
            self.operation.complete().map(|_| ())
        };
        self.post = if maintenance {
            self.operation.wait_slice().err()
        } else {
            // Completion is terminal work. Observe its same original status;
            // requiring Running here would reject every successful completion.
            self.operation.status().err()
        };
        if let Err(first) = result {
            self.first = Some(first);
            return Err(first);
        }
        if let Some(first) = self.post {
            self.first = Some(first);
            return Err(first);
        }
        self.launch_ready = true;
        self.selected
            .take()
            .ok_or(HostSupervisionError::Unavailable)
    }

    /// Consumes successful material and returns its completed authentication body.
    pub(crate) fn take_launch_output(
        mut self,
    ) -> Result<(ImportedCheckpointBasis, ImportedCheckpointReturn), Self> {
        if !self.launch_ready || self.maintenance || self.first.is_some() || self.basis.is_none() {
            return Err(self);
        }
        let Some(basis) = self.basis.take() else {
            return Err(self);
        };
        let returned = self.retire_unpublished();
        Ok((basis, returned))
    }

    /// Moves the same live Transfer only into its real successful consumer.
    pub(crate) fn take_maintenance_output<'owner>(
        mut self,
        owner: ImportedCheckpointOwner<'owner>,
    ) -> Result<
        (
            ImportedCheckpointBasis,
            ImportedCheckpointMaintenance<'owner>,
        ),
        (Self, ImportedCheckpointOwner<'owner>),
    > {
        if !self.launch_ready
            || !self.maintenance
            || self.first.is_some()
            || self.owner_custody.host_outer_cap_owner() != owner.0.host_outer_cap_owner()
            || self.owner_custody.host_daemon_epoch() != owner.0.host_daemon_epoch()
            || self.owner_custody.host_operation_supervisor() != owner.0.host_operation_supervisor()
            || self.basis.is_none()
        {
            return Err((self, owner));
        }
        let Some(basis) = self.basis.take() else {
            return Err((self, owner));
        };
        Ok((
            basis,
            ImportedCheckpointMaintenance {
                _owner: owner.0,
                owner_custody: self.owner_custody,
                operation: self.operation,
                parent_receiver: self.parent_receiver,
            },
        ))
    }

    /// Returns unpublished input only after the real no-World/body-return cut.
    pub(crate) fn retire_unpublished(self) -> ImportedCheckpointReturn {
        let completion_attempted = !self.launch_attempted || self.maintenance;
        let completion = completion_attempted
            .then(|| self.operation.complete().err())
            .flatten();
        let post = self.operation.status().err();
        let Self {
            basis,
            selected,
            owner_custody,
            operation,
            parent_receiver,
            first,
            post: launch_post,
            ..
        } = self;
        drop(basis);
        drop(selected);
        drop(operation);
        drop(owner_custody);
        let mut returned = ImportedCheckpointReturn {
            first,
            launch_post,
            completion_attempted,
            completion,
            return_post: post,
            parent_receiver,
            receiver_return_attempted: false,
            receiver_return_refused: false,
        };
        returned.retry_parent_return();
        returned
    }
}

/// Retains raw import facts after actual decoded and operation bodies return.
#[derive(Debug)]
pub struct ImportedCheckpointReturn {
    pub(crate) first: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    pub(crate) launch_post: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    pub(crate) completion_attempted: bool,
    pub(crate) completion: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    pub(crate) return_post: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    parent_receiver: Option<crate::ServiceMainReceiver>,
    receiver_return_attempted: bool,
    receiver_return_refused: bool,
}

impl ImportedCheckpointReturn {
    /// Retries only acknowledgment after the actual owned aliases were destroyed.
    pub fn retry_parent_return(&mut self) -> bool {
        let Some(receiver) = self.parent_receiver.take() else {
            return true;
        };
        self.receiver_return_attempted = true;
        match receiver.return_after_alias_destruction() {
            Ok(()) => true,
            Err(receiver) => {
                self.receiver_return_refused = true;
                self.parent_receiver = Some(receiver);
                false
            }
        }
    }

    /// Borrows the original leaf while preserving independent completion history.
    pub fn first_failure(
        &self,
    ) -> Option<crucible_host_resources::host_supervision::HostSupervisionError> {
        self.first
            .or(self.launch_post)
            .or(self.completion)
            .or(self.return_post)
    }

    /// Reports only actual receiver acknowledgment, independently of raw causes.
    #[must_use]
    pub fn parent_returned(&self) -> bool {
        self.parent_receiver.is_none()
    }
}

fn check_resources(
    resources: AttemptResourceLimits,
    ceiling: AttemptResourceLimits,
) -> Result<(), ImportedCheckpointErrorCause> {
    if resources.maximum_vcpus() > ceiling.maximum_vcpus()
        || resources.maximum_resident_bytes() > ceiling.maximum_resident_bytes()
        || resources.maximum_disk_bytes() > ceiling.maximum_disk_bytes()
        || resources.maximum_execution_quanta() > ceiling.maximum_execution_quanta()
    {
        return Err(ImportedCheckpointErrorCause::Binding(
            "receiver execution limits exceeded",
        ));
    }
    Ok(())
}

/// Retains an initiating import cause and its independent parent-return refusal.
#[derive(Debug)]
pub struct ImportedCheckpointError {
    cause: ImportedCheckpointErrorCause,
    receiver_return: Option<crate::PreparedSourceFailure>,
}

impl ImportedCheckpointError {
    /// Borrows the original typed import cause.
    pub fn cause(&self) -> &ImportedCheckpointErrorCause {
        &self.cause
    }

    /// Borrows custody retained when actual alias-return acknowledgment refused.
    pub fn receiver_return(&self) -> Option<&crate::PreparedSourceFailure> {
        self.receiver_return.as_ref()
    }
}

impl std::fmt::Display for ImportedCheckpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.cause, formatter)
    }
}

impl std::error::Error for ImportedCheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            ImportedCheckpointErrorCause::Binding(_) => None,
            ImportedCheckpointErrorCause::ServiceReceiver(first) => Some(first),
            ImportedCheckpointErrorCause::Repository(first) => Some(first),
            ImportedCheckpointErrorCause::Pin(first) => Some(first),
            ImportedCheckpointErrorCause::Store(first) => Some(first),
            ImportedCheckpointErrorCause::Artifact(first) => Some(first),
            ImportedCheckpointErrorCause::Restore(first) => Some(first.as_ref()),
            ImportedCheckpointErrorCause::Boundary(first) => Some(first),
            ImportedCheckpointErrorCause::Supervision(first) => Some(first),
        }
    }
}

impl From<ImportedCheckpointErrorCause> for ImportedCheckpointError {
    fn from(cause: ImportedCheckpointErrorCause) -> Self {
        Self {
            cause,
            receiver_return: None,
        }
    }
}

/// Typed refusal before receiver process-launch authority is exposed.
#[derive(Debug, Error)]
pub enum ImportedCheckpointErrorCause {
    /// The genuine parent Main role refused its alias census before work.
    #[error(transparent)]
    ServiceReceiver(crate::PreparedSourceFailure),
    /// Receiver trust or publication preconditions did not match.
    #[error("imported checkpoint binding refused: {0}")]
    Binding(&'static str),
    /// Receiver campaign authentication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Durable exact-pin selection authentication failed.
    #[error(transparent)]
    Pin(#[from] ExactPinRetentionError),
    /// Complete exact checkpoint authentication failed.
    #[error(transparent)]
    Store(#[from] ExactCheckpointStoreError),
    /// Scenario or configuration artifacts failed semantic decoding.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// Raw-to-promoted replay-oracle authentication failed.
    #[error("imported checkpoint replay oracle: {0}")]
    Restore(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The original operational boundary expired or was canceled.
    #[error(transparent)]
    Boundary(#[from] RamStoreError),
    /// Receiver budget policy or original supervision could not be observed.
    #[error(transparent)]
    Supervision(#[from] crucible_host_resources::host_supervision::HostSupervisionError),
}

/// Retains the same admitted authentication owner and its running Transfer.
pub(crate) struct ImportedCheckpointMaintenance<'owner> {
    _owner: &'owner AttemptExecutionContext,
    owner_custody: AttemptExecutionContext,
    operation: crucible_host_resources::host_supervision::HostOperationGuard,
    parent_receiver: Option<crate::ServiceMainReceiver>,
}

impl ImportedCheckpointMaintenance<'_> {
    /// Erases only the external lifetime facade for cleanup-only Main custody.
    ///
    /// The same guard/context and basis move together. Selection stays absent,
    /// launch stays attempted, and this capsule cannot authorize fresh work.
    pub(crate) fn into_cleanup_custody(
        self,
        basis: ImportedCheckpointBasis,
    ) -> RetainedImportedCheckpoint {
        RetainedImportedCheckpoint {
            basis: Some(basis),
            selected: None,
            owner_custody: self.owner_custody,
            operation: self.operation,
            parent_receiver: self.parent_receiver,
            launch_attempted: true,
            launch_ready: false,
            maintenance: true,
            first: None,
            post: None,
        }
    }

    pub(crate) fn original(
        &self,
    ) -> &crucible_host_resources::host_supervision::HostOperationGuard {
        &self.operation
    }

    pub(crate) fn check(
        &self,
    ) -> Result<(), crucible_host_resources::host_supervision::HostSupervisionError> {
        // The owner borrow outlives every native process and decoded alias.
        if self.owner_custody.cancellation().is_canceled() {
            self.owner_custody
                .host_operation_supervisor()
                .ok_or(
                    crucible_host_resources::host_supervision::HostSupervisionError::Unavailable,
                )?
                .cancel()?;
        }
        self.operation.wait_slice().map(|_| ())
    }

    /// Consumes the real maintenance aliases and retains both completion facts.
    ///
    /// The owning caller has already destroyed its World and all borrowed
    /// SourceTransfer offers. This cleanup never enters a replacement Transfer.
    pub(crate) fn into_return(self) -> ImportedCheckpointReturn {
        let first = self.check().err();
        let Self {
            owner_custody,
            operation,
            parent_receiver,
            ..
        } = self;
        RetainedImportedCheckpoint {
            basis: None,
            selected: None,
            owner_custody,
            operation,
            parent_receiver,
            launch_attempted: true,
            launch_ready: true,
            maintenance: true,
            first,
            post: None,
        }
        .retire_unpublished()
    }
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;
    use crucible_campaign::{AttemptRetentionPolicyDisposition, ExecutionRetentionIntent};
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
        HostSupervisionError,
    };
    use std::time::Duration;

    #[test]
    fn retained_maintenance_original_stays_running_and_refuses_canceled_completion() {
        // This finite original/field-custody control admits no native World.
        // The unregistered context cannot pass the public receiving entry.
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 2048, 4096, 64)
                .unwrap_or_else(|error| panic!("existing component profile: {error}")),
            ExecutionRetentionIntent::Discard,
            crate::ExecutionCancellation::default(),
            crate::ExecutionCheckpointRequest::default(),
            AttemptRetentionPolicyDisposition::Disabled,
        );
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(300)),
        )
        .unwrap_or_else(|error| panic!("existing finite original: {error}"));
        let maintenance = ImportedCheckpointMaintenance {
            _owner: &context,
            owner_custody: context.clone(),
            parent_receiver: None,
            operation: supervisor
                .begin(HostOperationClass::Transfer)
                .unwrap_or_else(|error| panic!("actual Transfer start: {error}")),
        };
        maintenance
            .check()
            .unwrap_or_else(|error| panic!("same original is live: {error}"));
        assert_eq!(
            maintenance
                .operation
                .status()
                .unwrap_or_else(|error| panic!("actual original state: {error}"))
                .state,
            HostOperationState::Running
        );
        supervisor
            .cancel()
            .unwrap_or_else(|error| panic!("actual cancellation: {error}"));
        assert!(matches!(
            maintenance.check(),
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled,
                ..
            })
        ));
        assert!(matches!(
            maintenance.into_return().completion,
            Some(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled,
                ..
            })
        ));
    }
}

#[cfg(test)]
mod startup_capsule_tests {
    use super::*;
    use crucible_campaign::{AttemptRetentionPolicyDisposition, ExecutionRetentionIntent};
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
        HostSupervisionError,
    };

    fn unregistered_context() -> AttemptExecutionContext {
        AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 2048, 4096, 64).unwrap(),
            ExecutionRetentionIntent::Discard,
            crate::ExecutionCancellation::default(),
            crate::ExecutionCheckpointRequest::default(),
            AttemptRetentionPolicyDisposition::Disabled,
        )
    }

    fn unpublished_capsule(supervisor: &HostOperationSupervisor) -> RetainedImportedCheckpoint {
        // Explicitly no import basis or selected root: this exercises actual
        // Original/body return, and cannot issue a native launch claim.
        RetainedImportedCheckpoint {
            basis: None,
            selected: None,
            owner_custody: unregistered_context(),
            operation: supervisor.begin(HostOperationClass::Transfer).unwrap(),
            parent_receiver: None,
            launch_attempted: false,
            launch_ready: false,
            maintenance: false,
            first: None,
            post: None,
        }
    }

    #[test]
    fn refused_unpublished_launch_keeps_actual_transfer_until_consuming_return() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let mut capsule = unpublished_capsule(&supervisor);
        let id = capsule.operation.status().unwrap().operation_id;

        assert!(matches!(
            capsule.prepare_launch(true),
            Err(HostSupervisionError::Unavailable)
        ));
        assert_eq!(capsule.operation.status().unwrap().operation_id, id);
        assert_eq!(
            capsule.operation.status().unwrap().state,
            HostOperationState::Running
        );
        assert_eq!(supervisor.status_snapshot().unwrap().1.len(), 1);

        let returned = capsule.retire_unpublished();
        assert!(returned.completion_attempted);
        assert!(returned.completion.is_none());
        assert!(returned.return_post.is_none());
        assert!(supervisor.status_snapshot().unwrap().1.is_empty());
    }

    #[test]
    fn canceled_transfer_raw_completion_survives_physical_capsule_return() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let capsule = unpublished_capsule(&supervisor);
        supervisor.cancel().unwrap();

        let returned = capsule.retire_unpublished();

        assert!(returned.completion_attempted);
        assert!(matches!(
            returned.completion,
            Some(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            })
        ));
        assert!(supervisor.status_snapshot().unwrap().1.is_empty());
    }
}
