//! Prepares the distinct complete four-owner native preservation selection.
//!
//! The existing live composition and two-owner preservation interfaces remain
//! separate. Every graph is regenerated from independently installed CPU and
//! Host source policies; native admission and the complete activation barrier
//! are mandatory for both initial and restored execution.

use std::rc::Rc;

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::ActivationRecord,
    node_state::{CaptureEvidence, NativeArchiveRecord, NativeWorldFactory},
};
use crucible_campaign::ExecutionId;
use crucible_node_contract::{ContentRef, Id};

use super::super::{
    InstalledGem5ClosedProfile, InstalledNodeCatalog, InstalledNodeSelection,
    InstalledPreparedWorld, NodeObservedError, execution_text, refused,
};
use super::{
    host_group::{factory::IndependentNativeFactory, profile::IndependentGroupProfile},
    installed::InstalledMixedEngine,
};
use crate::node_scenario::NodeScenario;

/// Owns all inactive original owners and the independently installed capture reader.
pub struct InstalledPreparedIndependentNativeWorld {
    /// Retains the complete inactive graph and one owning all-owner realization.
    pub world: InstalledPreparedWorld,
    /// Retains immutable source policy without granting capture or execution.
    pub preservation: InstalledIndependentNativePreservation,
}

/// Retains the exact full-world installed policy and actual reserved native custody.
pub struct InstalledIndependentNativePreservation {
    factory: Rc<IndependentNativeFactory>,
    #[cfg(test)]
    pub(super) namespace: std::path::PathBuf,
}

/// Retains exact prebirth source handles and future original cleanup credits.
pub(crate) struct PreparedFailureRetirement {
    inner: super::host_group::failure_retirement::FailureRetirementPreparation,
    durable: Option<super::host_group::failure_retirement::DurableFailureSources>,
    history: Option<super::host_group::failure_retirement::OriginalFailureHistory>,
    durable_history: Option<super::host_group::failure_retirement::DurableFailureHistory>,
    retired_verified: bool,
    terminal: Option<Vec<crucible::node_scheduling::InputPayload>>,
    durable_terminal: Option<super::host_group::failure_retirement::DurableFailureHistory>,
}

impl PreparedFailureRetirement {
    /// Places complete original source roots before native preparation effects.
    pub(crate) fn persist_sources(
        &mut self,
        execution: &str,
        blobs: &dyn crucible_cas::content_store::ImmutableBlobBackend,
        refs: &dyn crucible_cas::content_store::MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        if self.durable.is_some() {
            return Err(refused("prebirth source placement was already adopted"));
        }
        self.durable = Some(self.inner.persist_sources(execution, blobs, refs)?);
        self.authenticate_durable_sources(blobs, refs)
    }

    /// Reopens exact complete original bytes without granting cleanup authority.
    pub(crate) fn authenticate_durable_sources(
        &self,
        blobs: &dyn crucible_cas::content_store::ImmutableBlobBackend,
        refs: &dyn crucible_cas::content_store::MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        self.inner.authenticate_durable_sources(
            self.durable
                .as_ref()
                .ok_or_else(|| refused("durable original source holder absent"))?,
            blobs,
            refs,
        )
    }

    /// Retains and places the actual same-runtime failure history without releasing it.
    pub(crate) fn retain_failure_history(
        &mut self,
        runtime: &crucible::node_contract::NodeRuntime,
        activation: &crucible::node_contract::WorldActivation,
        cut: crucible_node_contract::Position,
        ordinal: crucible_node_contract::U64,
        blobs: &dyn crucible_cas::content_store::ImmutableBlobBackend,
        refs: &dyn crucible_cas::content_store::MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        self.authenticate_durable_sources(blobs, refs)?;
        if self.history.is_none() {
            self.history = Some(
                self.inner
                    .retain_history(runtime, activation, cut, ordinal)?,
            );
        }
        let source = self
            .durable
            .as_ref()
            .ok_or_else(|| refused("original durable source absent"))?;
        let original = self
            .history
            .as_ref()
            .ok_or_else(|| refused("original history absent"))?;
        if self.durable_history.is_none() {
            self.durable_history = Some(self.inner.persist_history(source, original, blobs, refs)?);
        }
        self.inner.authenticate_durable_history(
            source,
            original,
            self.durable_history
                .as_ref()
                .ok_or_else(|| refused("durable original history absent"))?,
            blobs,
            refs,
        )
    }
    /// Authenticates original runtime/model bytes before any custody changes.
    pub(crate) fn authenticate_retired_failure(
        &mut self,
        retired: &crucible::node_contract::QuarantinedRuntime,
        activation: &crucible::node_contract::WorldActivation,
        blobs: &dyn crucible_cas::content_store::ImmutableBlobBackend,
        refs: &dyn crucible_cas::content_store::MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        self.authenticate_failure_history(blobs, refs)?;
        self.history
            .as_ref()
            .ok_or_else(|| refused("original failure history absent"))?
            .authenticate_retired(retired, activation)?;
        self.retired_verified = true;
        Ok(())
    }

    /// Reopens the exact held source/model/native bodies without a native command.
    pub(crate) fn authenticate_failure_history(
        &self,
        blobs: &dyn crucible_cas::content_store::ImmutableBlobBackend,
        refs: &dyn crucible_cas::content_store::MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        self.inner.authenticate_durable_history(
            self.durable
                .as_ref()
                .ok_or_else(|| refused("original durable source absent"))?,
            self.history
                .as_ref()
                .ok_or_else(|| refused("original complete history absent"))?,
            self.durable_history
                .as_ref()
                .ok_or_else(|| refused("original durable history absent"))?,
            blobs,
            refs,
        )
    }

    /// Adopts the same actual original Shutdown/reap bodies under prebirth credit.
    pub(crate) fn retain_terminal_failure(
        &mut self,
        records: Vec<(ContentRef, Vec<u8>)>,
        blobs: &dyn crucible_cas::content_store::ImmutableBlobBackend,
        refs: &dyn crucible_cas::content_store::MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        self.authenticate_failure_history(blobs, refs)?;
        if !self.retired_verified || records.len() != 2 {
            return Err(refused("same original terminal scope absent"));
        }
        let terminal = self
            .terminal
            .as_mut()
            .ok_or_else(|| refused("prebirth terminal holder absent"))?;
        if terminal.is_empty() {
            for (reference, bytes) in records {
                if bytes.len() > 64 * 1024 {
                    return Err(refused("fixed terminal body credit differs"));
                }
                reference.verify(&bytes)?;
                terminal.push(crucible::node_scheduling::InputPayload { reference, bytes });
            }
        } else if terminal.len() != records.len()
            || terminal
                .iter()
                .zip(records)
                .any(|(held, (reference, body))| held.reference != reference || held.bytes != body)
        {
            return Err(refused("original terminal reconciliation bytes differ"));
        }
        if self.durable_terminal.is_none() {
            self.durable_terminal = Some(
                self.inner.persist_terminal(
                    self.durable
                        .as_ref()
                        .ok_or_else(|| refused("original source absent"))?,
                    self.history
                        .as_ref()
                        .ok_or_else(|| refused("original history absent"))?,
                    terminal,
                    blobs,
                    refs,
                )?,
            );
        }
        self.inner.authenticate_terminal(
            self.durable
                .as_ref()
                .ok_or_else(|| refused("original source absent"))?,
            terminal,
            self.durable_terminal
                .as_ref()
                .ok_or_else(|| refused("original terminal roots absent"))?,
            blobs,
            refs,
        )
    }

    /// Reauthenticates exact retained terminal bodies before an installed release.
    pub(crate) fn authenticate_terminal_failure(
        &self,
        blobs: &dyn crucible_cas::content_store::ImmutableBlobBackend,
        refs: &dyn crucible_cas::content_store::MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        self.authenticate_failure_history(blobs, refs)?;
        if !self.retired_verified {
            return Err(refused("original retired model was not authenticated"));
        }
        self.inner.authenticate_terminal(
            self.durable
                .as_ref()
                .ok_or_else(|| refused("original source absent"))?,
            self.terminal
                .as_ref()
                .ok_or_else(|| refused("original terminal bodies absent"))?,
            self.durable_terminal
                .as_ref()
                .ok_or_else(|| refused("original terminal roots absent"))?,
            blobs,
            refs,
        )
    }

    pub(crate) fn failure_summary(&self) -> Result<FailureRetirementSummary, NodeObservedError> {
        if !self.retired_verified {
            return Err(refused("complete original retired history absent"));
        }
        let original = self
            .history
            .as_ref()
            .ok_or_else(|| refused("original history absent"))?;
        let native = original.supervision_references()?;
        let terminal = self
            .terminal
            .as_ref()
            .ok_or_else(|| refused("original terminal absent"))?;
        if terminal.len() != 2 {
            return Err(refused("complete actual terminal roster absent"));
        }
        let mut histories = Vec::new();
        histories
            .try_reserve_exact(original.objects().count())
            .map_err(|error| refused(&error.to_string()))?;
        for original in original.objects() {
            histories.push(original.reference.clone());
        }
        Ok(FailureRetirementSummary {
            source_credit: self.inner.reference().clone(),
            source_index: self
                .durable
                .as_ref()
                .ok_or_else(|| refused("original source index absent"))?
                .reference()?,
            metadata: native.metadata,
            histories,
            shutdown: terminal[0].reference.clone(),
            reaping: terminal[1].reference.clone(),
        })
    }
}

/// Names positively retained original operational bodies without release authority.
#[derive(serde::Serialize)]
pub(crate) struct FailureRetirementSummary {
    /// Binds the original source-authored prebirth body/owner credit.
    pub(crate) source_credit: ContentRef,
    /// Names the closed original direct-root source roster.
    pub(crate) source_index: ContentRef,
    /// Names the actual original runtime, scheduler and preparation history.
    pub(crate) metadata: ContentRef,
    /// Retains every positively read original Host/native/private-ACK body.
    pub(crate) histories: Vec<ContentRef>,
    /// Binds the first original Shutdown frame/count/reply record.
    pub(crate) shutdown: ContentRef,
    /// Binds actual original Child/group-empty reaping evidence.
    pub(crate) reaping: ContentRef,
}

/// Holds complete authenticated historical supervision data without live authority.
pub(crate) struct OriginalNativeSupervision {
    inner: Option<super::custody::AuthenticatedSupervision>,
}

/// Owns separately authenticated no-archive supervision of the original capsule.
pub(crate) struct OriginalFailedSupervision {
    inner: Option<super::custody::AuthenticatedFailedSupervision>,
}

/// Retains the actual native supervisor's safe-release fact without a data constructor.
pub(crate) struct OriginalFailedNativeRelease {
    inner: super::custody::NativeFailedRelease,
}

impl OriginalFailedNativeRelease {
    pub(crate) fn authenticates(
        &self,
        target: &ActivationRecord,
        summary: &FailureRetirementSummary,
    ) -> bool {
        self.inner
            .matches(target, &summary.source_credit, &summary.metadata)
    }
}

impl InstalledIndependentNativePreservation {
    /// Reopens complete installed original failure history without a native retry.
    pub(crate) fn authenticate_failed_supervision(
        &self,
        original: &PreparedFailureRetirement,
        target: &ActivationRecord,
        blobs: &dyn crucible_cas::content_store::ImmutableBlobBackend,
        refs: &dyn crucible_cas::content_store::MutableRefBackend,
    ) -> Result<OriginalFailedSupervision, NodeObservedError> {
        self.authenticate_failure_retirement(original)?;
        original.authenticate_failure_history(blobs, refs)?;
        if !original.retired_verified {
            return Err(refused("actual retired Host/runtime conjunction absent"));
        }
        let history = original
            .history
            .as_ref()
            .ok_or_else(|| refused("original complete failure history absent"))?;
        history.authenticate_activation(target)?;
        Ok(OriginalFailedSupervision {
            inner: Some(
                super::custody::AuthenticatedFailedSupervision::from_original(
                    target,
                    original.inner.reference().clone(),
                    history.supervision_references()?,
                )
                .map_err(|error| refused(&error.to_string()))?,
            ),
        })
    }

    /// Transfers the entire original reclaimed native capsule without releasing credit.
    pub(crate) fn supervise_failed_original(
        &self,
        target: &ActivationRecord,
        source: &mut OriginalFailedSupervision,
    ) -> Result<(), NodeObservedError> {
        self.factory
            .failed_queue()
            .supervise_failed_original(target, &mut source.inner)
            .map_err(|error| refused(&error.to_string()))
    }

    /// Reads genuine original first Shutdown and group-empty/reaping bodies.
    pub(crate) fn failed_retirement_records(
        &self,
        target: &ActivationRecord,
        reopened: &OriginalFailedSupervision,
    ) -> Result<Option<super::custody::RetirementRecords>, NodeObservedError> {
        self.factory
            .failed_queue()
            .failed_retirement_records(
                target,
                reopened
                    .inner
                    .as_ref()
                    .ok_or_else(|| refused("fresh original failed source absent"))?,
            )
            .map_err(|error| refused(&error.to_string()))
    }

    /// Releases the same native supervisor after the original caller's durable conjunction.
    pub(crate) fn release_failed_supervised(
        &self,
        target: &ActivationRecord,
        reopened: &OriginalFailedSupervision,
    ) -> Result<OriginalFailedNativeRelease, NodeObservedError> {
        Ok(OriginalFailedNativeRelease {
            inner: self
                .factory
                .failed_queue()
                .release_failed_supervised(
                    target,
                    reopened
                        .inner
                        .as_ref()
                        .ok_or_else(|| refused("fresh original failed source absent"))?,
                )
                .map_err(|error| refused(&error.to_string()))?,
        })
    }

    /// Rechecks the same source-authored operation credit against actual enrollment.
    pub(crate) fn authenticate_capture_credit(
        &self,
        reference: &ContentRef,
    ) -> Result<(), NodeObservedError> {
        self.factory.authenticate_capture_credit(reference)
    }

    /// Conjoins the original prebirth holder with the actual enrolled factory.
    pub(crate) fn authenticate_failure_retirement(
        &self,
        original: &PreparedFailureRetirement,
    ) -> Result<(), NodeObservedError> {
        self.factory
            .authenticate_failure_retirement(&original.inner)
    }

    /// Authenticates complete original settled journals beneath the installed source.
    pub(crate) fn authenticate_supervision(
        &self,
        graph: &crucible::node_admission::AdmittedGraph,
        archive: crucible::node_state::NativeArchiveRecord,
        requirements: crucible::node_state::StateRequirements,
    ) -> Result<OriginalNativeSupervision, NodeObservedError> {
        Ok(OriginalNativeSupervision {
            inner: Some(
                self.factory
                    .authenticate_supervision(graph, archive, requirements)?,
            ),
        })
    }

    /// Transfers original custody without releasing its installed owner credit.
    pub(crate) fn supervise_original(
        &self,
        target: &ActivationRecord,
        source: &mut OriginalNativeSupervision,
    ) -> Result<(), NodeObservedError> {
        self.factory.supervise_original(target, &mut source.inner)
    }

    /// Releases only after complete fresh durable archive and actual proof agreement.
    pub(crate) fn release_supervised(
        &self,
        target: &ActivationRecord,
        reopened: &OriginalNativeSupervision,
    ) -> Result<(), NodeObservedError> {
        self.factory.release_supervised(
            target,
            reopened.inner.as_ref().ok_or_else(|| {
                super::super::refused("fresh supervisor source already transferred")
            })?,
        )
    }

    /// Retains actual original native cleanup evidence under its fixed byte credit.
    ///
    /// # Errors
    /// Refuses an absent original target, malformed native proof or finite allocation.
    pub(crate) fn retirement(
        &self,
        target: &ActivationRecord,
    ) -> Result<Option<(ContentRef, Vec<u8>)>, NodeObservedError> {
        self.factory.retirement(target)
    }

    /// Couples the original complete publication to its actual reserved CPU journal.
    pub(crate) fn initial_publisher(
        &self,
        stored: crate::node_observed_executor::StoredWorldActivationPublisher,
    ) -> impl crucible::node_contract::ActivationPublisher {
        self.factory.initial_publisher(stored)
    }

    /// Checks the original target's positively reclaimed CPU custody.
    ///
    /// # Errors
    /// Refuses absent or foreign original native reservation records.
    pub(crate) fn reclaimed(&self, target: &ActivationRecord) -> Result<bool, NodeObservedError> {
        self.factory.reclaimed(target)
    }

    /// Returns the selected reader; native restoration and activation remain mandatory.
    pub fn factory(&self) -> Rc<dyn NativeWorldFactory> {
        self.factory.clone()
    }

    /// Returns installed immutable closure without creating native capture proofs.
    pub fn immutable(&self) -> Box<dyn CaptureEvidence> {
        Box::new(self.factory.immutable())
    }

    /// Retains original coordinator context while publishing actual fresh owners.
    ///
    /// The returned publisher cannot synthesize node preparation or Ready. The
    /// complete staged native restoration must supply those original resources.
    ///
    /// # Errors
    /// Refuses another installed source world, native owner family or target.
    pub fn restored_publisher(
        &self,
        stored: crate::node_observed_executor::StoredWorldActivationPublisher,
        source: &NativeArchiveRecord,
        target: &ActivationRecord,
    ) -> Result<impl crucible::node_contract::ActivationPublisher, NodeObservedError> {
        self.factory.restored_publisher(stored, source, target)
    }
}

/// Retains one fresh graph, target and inactive original source-image reservation.
pub struct InstalledIndependentNativeRestore {
    /// Borrows the independently admitted complete fresh four-owner graph.
    pub graph: Rc<AdmittedGraph>,
    /// Names the fresh locally owned target; this record grants no permission.
    pub target: ActivationRecord,
    /// Retains the actual inactive archive lease and complete installed policy.
    pub preservation: InstalledIndependentNativePreservation,
}

impl InstalledNodeCatalog {
    /// Keeps original archive reader limits before selected operation admission.
    pub(crate) fn independent_native_archive_reader_limits()
    -> crucible::node_state::NativeArchiveLimits {
        super::host_group::archive_credit::reader_limits()
    }

    /// Derives complete source credits before any inactive owner or native child.
    ///
    /// # Errors
    /// Refuses another selected source, incomplete immutable enrollment, overflow
    /// or a complete operation exceeding the unchanged state interface.
    pub(crate) fn preflight_capability_independent_capture_credit(
        &self,
        resolved: &super::super::ResolvedCapabilityWorld,
        source: Option<&NativeArchiveRecord>,
    ) -> Result<(crucible::node_state::NativeArchiveLimits, ContentRef), NodeObservedError> {
        self.require_behavioral_host_scope()?;
        let selections = resolved.preserving_group_selections()?;
        let installed = InstalledGem5ClosedProfile::built_in()?;
        let profile = match source {
            None => IndependentGroupProfile::build_preserving(installed, self, selections)?,
            Some(source) => {
                let artifacts = super::host_group::artifacts::GroupArtifacts::materialize(
                    self, selections, source,
                )?;
                IndependentGroupProfile::build_preserving_scoped(
                    installed,
                    self,
                    selections,
                    artifacts.registry(),
                )?
            }
        }
        .with_capabilities(resolved)?;
        profile.archive_credit()
    }

    /// Retains the complete source and cleanup history credit before any owner hook.
    pub(crate) fn preflight_capability_failure_retirement(
        &self,
        resolved: &super::super::ResolvedCapabilityWorld,
    ) -> Result<PreparedFailureRetirement, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        let profile = IndependentGroupProfile::build_preserving(
            InstalledGem5ClosedProfile::built_in()?,
            self,
            resolved.preserving_group_selections()?,
        )?
        .with_capabilities(resolved)?;
        let mut terminal = Vec::new();
        terminal
            .try_reserve_exact(2)
            .map_err(|error| refused(&error.to_string()))?;
        Ok(PreparedFailureRetirement {
            inner: super::host_group::failure_retirement::FailureRetirementPreparation::reserve(
                &profile, self,
            )?,
            durable: None,
            history: None,
            durable_history: None,
            retired_verified: false,
            terminal: Some(terminal),
            durable_terminal: None,
        })
    }

    /// Checks the ordinary route's complete publication credit before native birth.
    ///
    /// # Errors
    /// Refuses another roster, missing enrolled script, malformed requests or
    /// an authored output geometry exceeding the fixed portable receipt budget.
    pub(crate) fn preflight_capability_independent_outputs(
        &self,
        resolved: &super::super::ResolvedCapabilityWorld,
        source: Option<&NativeArchiveRecord>,
    ) -> Result<(), NodeObservedError> {
        let selections = resolved.preserving_group_selections()?;
        let selected =
            super::host_group::selection::IndependentGroupSelection::new_preserving(selections)?;
        let super::super::InstalledNodeKind::HostScripted { profile } = &selected.source.kind
        else {
            return Err(refused("preserving original script is absent"));
        };
        let materialized = source
            .map(|source| {
                super::host_group::artifacts::GroupArtifacts::materialize(self, selections, source)
            })
            .transpose()?;
        let registry = materialized
            .as_ref()
            .map_or(&self.artifacts, |artifacts| artifacts.registry());
        let enrolled = registry
            .get(&profile.script.hash.digest)
            .filter(|artifact| artifact.expected == profile.script)
            .ok_or_else(|| refused("ordinary preserving script lacks independent enrollment"))?;
        let bytes = super::super::io::read_artifact(enrolled)?;
        let script = crucible::node_adapters::ScriptedSource::from_script_bytes(&bytes)
            .map_err(|error| refused(&error.reason))?;
        if script.requests().len() > 16 {
            return Err(refused(
                "ordinary original script exceeds sixteen publication pairs",
            ));
        }
        // Every possible original request/response byte is charged here before
        // provider birth. The scheduler retains only these closed source bytes;
        // CPU output and response headers fit the existing fixed overhead. The
        // selected factory independently checks the actual queued sum at capture.
        let mut charged = 128 * 1024_usize;
        for original in script.requests() {
            let request = crucible_device::BlockRequest::decode(&original.payload)
                .map_err(|error| refused(&error.to_string()))?;
            let response = if request.op == crucible_device::BlockOp::Read {
                request.count as usize
            } else {
                0
            };
            charged = charged
                .checked_add(
                    original
                        .payload
                        .len()
                        .checked_add(response)
                        .and_then(|bytes| bytes.checked_mul(10))
                        .and_then(|bytes| bytes.checked_add(16 * 1024))
                        .ok_or_else(|| refused("ordinary publication geometry overflow"))?,
                )
                .ok_or_else(|| refused("ordinary publication credit overflow"))?;
            if charged > 1024 * 1024 {
                return Err(refused(
                    "complete original publications exceed the ordinary receipt credit",
                ));
            }
        }
        Ok(())
    }

    /// Prepares the independently regenerated capability-bearing four-owner world.
    ///
    /// # Errors
    /// Refuses omitted original capture demands, another installed family,
    /// changed raw source selection, native qualification or finite custody.
    pub(crate) fn prepare_capability_independent_native_world(
        &mut self,
        resolved: &super::super::ResolvedCapabilityWorld,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedIndependentNativeWorld, NodeObservedError> {
        resolved.require_preserving_group_action("capture")?;
        let selections = resolved.preserving_group_selections()?;
        let baseline = self.independent_native_scenario(selections)?;
        let expected = resolved.gem5_preserving_scenario(&baseline)?;
        let engine =
            InstalledMixedEngine::with_runtime(self.socket_parent.clone(), self.custody.clone())?;
        let activation = Id::new(format!("activation/{}", execution_text(execution)))?;
        let live = engine.prepare_independent_preserving_capability_group(
            self, selections, &expected, activation, resolved,
        )?;
        let factory = Rc::new(IndependentNativeFactory::for_live(
            &live,
            engine.native.clone(),
        ));
        let graph = Rc::try_unwrap(live.graph)
            .map_err(|_| refused("capability group retained unexpected graph owner aliases"))?;
        Ok(InstalledPreparedIndependentNativeWorld {
            world: InstalledPreparedWorld {
                scenario: live.profile.scenario.clone(),
                graph,
                realization: live.realization,
            },
            preservation: InstalledIndependentNativePreservation {
                factory,
                #[cfg(test)]
                namespace: live.namespace,
            },
        })
    }

    /// Reserves the complete capability source without restoring any native child.
    ///
    /// # Errors
    /// Refuses absent original restart demands, changed independently enrolled
    /// source bodies or world, unavailable complete policy or finite custody.
    pub(crate) fn prepare_capability_independent_native_restore(
        &self,
        resolved: &super::super::ResolvedCapabilityWorld,
        source: NativeArchiveRecord,
    ) -> Result<InstalledIndependentNativeRestore, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        resolved.require_preserving_group_action("durable_restart")?;
        let selections = resolved.preserving_group_selections()?;
        let engine =
            InstalledMixedEngine::with_runtime(self.socket_parent.clone(), self.custody.clone())?;
        let plan =
            engine.prepare_independent_cold_capability_group(self, selections, source, resolved)?;
        let graph = plan.graph.clone();
        let target = plan.target.clone();
        #[cfg(test)]
        let namespace = plan.namespace.clone();
        let factory = Rc::new(IndependentNativeFactory::for_cold(
            plan,
            engine.native.clone(),
        ));
        Ok(InstalledIndependentNativeRestore {
            graph,
            target,
            preservation: InstalledIndependentNativePreservation {
                factory,
                #[cfg(test)]
                namespace,
            },
        })
    }

    /// Regenerates a baseline from independently enrolled live or signed original inputs.
    pub(in crate::node_observed_executor::factory) fn independent_native_source_scenario(
        &self,
        selections: &[InstalledNodeSelection],
        source: Option<&NativeArchiveRecord>,
    ) -> Result<NodeScenario, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        let installed = InstalledGem5ClosedProfile::built_in()?;
        let profile = match source {
            None => IndependentGroupProfile::build_preserving(installed, self, selections)?,
            Some(source) => {
                let artifacts = super::host_group::artifacts::GroupArtifacts::materialize(
                    self, selections, source,
                )?;
                IndependentGroupProfile::build_preserving_scoped(
                    installed,
                    self,
                    selections,
                    artifacts.registry(),
                )?
            }
        };
        Ok(profile.scenario)
    }

    /// Regenerates the distinct complete x86 CPU/Clock and Script/Block scenario.
    ///
    /// # Errors
    /// Refuses another roster, backend or facet, unavailable independently
    /// installed artifacts, incompatible graph geometry or source identity.
    pub fn independent_native_scenario(
        &self,
        selections: &[InstalledNodeSelection],
    ) -> Result<NodeScenario, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        Ok(IndependentGroupProfile::build_preserving(
            InstalledGem5ClosedProfile::built_in()?,
            self,
            selections,
        )?
        .scenario)
    }

    /// Prepares every inactive owner before the one complete native activation.
    ///
    /// The original CPU must pass its installed process-image/native closure
    /// qualifier. Host preparation and native9 custody remain separate from the
    /// existing live-only profile and cannot increase its declared guarantees.
    ///
    /// # Errors
    /// Refuses changed authored demands or source identities, unsupported owners,
    /// insufficient original credits, native preparation or closure qualification.
    pub fn prepare_independent_native_world(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedIndependentNativeWorld, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        let expected = self.independent_native_scenario(selections)?;
        if scenario.canonical_bytes()? != expected.canonical_bytes()? {
            return Err(refused(
                "independent authored preserving world differs from installed source",
            ));
        }
        let engine =
            InstalledMixedEngine::with_runtime(self.socket_parent.clone(), self.custody.clone())?;
        let activation = Id::new(format!("activation/{}", execution_text(execution)))?;
        let live =
            engine.prepare_independent_preserving_group(self, selections, &expected, activation)?;
        let factory = Rc::new(IndependentNativeFactory::for_live(
            &live,
            engine.native.clone(),
        ));
        let graph = Rc::try_unwrap(live.graph)
            .map_err(|_| refused("independent prepared graph retained unexpected owner aliases"))?;
        Ok(InstalledPreparedIndependentNativeWorld {
            world: InstalledPreparedWorld {
                scenario: live.profile.scenario.clone(),
                graph,
                realization: live.realization,
            },
            preservation: InstalledIndependentNativePreservation {
                factory,
                #[cfg(test)]
                namespace: live.namespace,
            },
        })
    }

    /// Reserves a fresh complete source-backed world without allocating a CPU child.
    ///
    /// Original Script/base pathnames may be gone. Their exact independently
    /// enrolled identities must remain; signed archive bytes cannot install a
    /// different source policy. Generic staging must still authenticate the whole
    /// source, reconstruct and qualify actual native owners, and publish one
    /// complete fresh barrier before executing any restored work.
    ///
    /// # Errors
    /// Refuses unavailable independent enrollment, changed signed world, missing
    /// original bodies, stale target identities or exhausted inactive custody.
    pub fn prepare_independent_native_restore(
        &self,
        selections: &[InstalledNodeSelection],
        source: NativeArchiveRecord,
    ) -> Result<InstalledIndependentNativeRestore, NodeObservedError> {
        self.require_behavioral_host_scope()?;
        let engine =
            InstalledMixedEngine::with_runtime(self.socket_parent.clone(), self.custody.clone())?;
        let plan = engine.prepare_independent_cold_group(self, selections, source)?;
        let graph = plan.graph.clone();
        let target = plan.target.clone();
        #[cfg(test)]
        let namespace = plan.namespace.clone();
        let factory = Rc::new(IndependentNativeFactory::for_cold(
            plan,
            engine.native.clone(),
        ));
        Ok(InstalledIndependentNativeRestore {
            graph,
            target,
            preservation: InstalledIndependentNativePreservation {
                factory,
                #[cfg(test)]
                namespace,
            },
        })
    }
}
