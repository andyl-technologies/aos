//! Owns one complete conditional model world and its published activation.
//!
//! This caller consumes actual signed Tape2 through installed model adapters.
//! The runtime reserves and retains every permission, input and native model
//! before callbacks. Capture and fresh restoration are separate installed gates.

// This entire owning caller belongs to the private signed-data test fixture.
#![cfg(test)]

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use crucible::{
    node_adapters::transcript::TranscriptReplayNode,
    node_admission::AdmittedGraph,
    node_contract::{
        BeginResult, NodeRoute, NodeRuntime, OperationToken, RuntimeCustodyQueue,
        RuntimeCustodySlot, RuntimeCustodySupervisor, RuntimeLimits, SimulationNode, Submission,
        WorldActivation,
    },
    node_scheduling::NativePublication,
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend, RefName};
use crucible_node_contract::{Id, Phase, Position, U64};

use crate::node_observed_executor::StoredWorldActivationPublisher;

use super::{
    conditional_admission, conditional_policy::ConditionalPolicy,
    conditional_profile::ConditionalProfile, conditional_source::InspectionError,
};

pub(super) struct ConditionalWorld {
    pub(super) profile: Rc<ConditionalProfile>,
    pub(super) graph: AdmittedGraph,
    pub(super) runtime: Option<NodeRuntime>,
    pub(super) activation: Option<WorldActivation>,
    prefix_body: Option<Vec<u8>>,
    capture_factory: super::conditional_capture_factory::ConditionalCaptureFactory,
    pending_tokens: Vec<OperationToken>,
    capture_attempted: bool,
    capture_export_attempted: bool,
    capture_export_complete: bool,
    capture_retirement_attempted: bool,
    capture_runtime_retired: bool,
    capture_namespace_removal_attempted: bool,
    capture_namespace_gone: bool,
    capture_directory: Option<tempfile::TempDir>,
    capture_archive: Option<crucible::node_state::NativeArchive>,
    capture_record: Option<crucible::node_state::NativeArchiveRecord>,
    capture_reopened_record: Option<crucible::node_state::NativeArchiveRecord>,
    capture_content: Option<crucible::node_state::VerifiedStateContent>,
    capture_pins: Option<Vec<crucible::node_state::PinnedOriginalLineageSource>>,
    pending_slot: Option<Box<dyn RuntimeCustodySlot>>,
    queue: RuntimeCustodyQueue,
    directory: Option<tempfile::TempDir>,
}

impl ConditionalWorld {
    pub(super) fn prepare(profile: Rc<ConditionalProfile>) -> Result<Self, InspectionError> {
        let graph = conditional_admission::admit(&profile)?;
        let queue = RuntimeCustodyQueue::new(1).map_err(text)?;
        let pending_slot = queue
            .reserve_world(&profile.activation, RuntimeLimits::default())
            .map_err(text)?;
        let directory = tempfile::Builder::new()
            .prefix("reader-conditional-")
            .tempdir_in("/tmp")
            .map_err(text)?;
        let mut pending_tokens = Vec::new();
        pending_tokens.try_reserve_exact(9).map_err(text)?;
        let capture_factory =
            super::conditional_capture_factory::ConditionalCaptureFactory::install(
                Rc::clone(&profile),
                &graph,
            )
            .map_err(text)?;
        let mut world = Self {
            profile,
            graph,
            runtime: None,
            activation: None,
            prefix_body: None,
            capture_factory,
            pending_tokens,
            capture_attempted: false,
            capture_export_attempted: false,
            capture_export_complete: false,
            capture_retirement_attempted: false,
            capture_runtime_retired: false,
            capture_namespace_removal_attempted: false,
            capture_namespace_gone: false,
            capture_directory: None,
            capture_archive: None,
            capture_record: None,
            capture_reopened_record: None,
            capture_content: None,
            capture_pins: None,
            pending_slot: Some(pending_slot),
            queue,
            directory: Some(directory),
        };
        let policy = ConditionalPolicy::install(Rc::clone(&world.profile))?;
        let mut models: Vec<Box<dyn SimulationNode>> = Vec::new();
        models.try_reserve_exact(3).map_err(text)?;
        for node in world.graph.node_ids() {
            let binding = world.graph.binding(node).ok_or("target binding absent")?;
            let source = world
                .profile
                .history
                .originals
                .get(node)
                .ok_or("original signed source absent")?;
            let route = NodeRoute {
                node: node.clone(),
                owners: world
                    .profile
                    .activation
                    .owners
                    .iter()
                    .filter(|owner| owner.owner == binding.compatibility.execution_owner.id)
                    .cloned()
                    .collect(),
            };
            let model = TranscriptReplayNode::prepare(
                source.clone(),
                &world.graph,
                route,
                &source.transcript().origin.context,
                &policy,
            )
            .map_err(text)?;
            models.push(Box::new(model));
        }
        let slot = world
            .pending_slot
            .take()
            .ok_or("world reservation absent")?;
        world.runtime = Some(
            NodeRuntime::new(
                &world.graph,
                models,
                world.profile.activation.clone(),
                RuntimeLimits::default(),
                slot,
            )
            .map_err(|failure| text(&failure.error))?,
        );
        Ok(world)
    }

    /// Publishes the actual complete prepared roster before any Stage or Begin.
    pub(super) fn activate(&mut self) -> Result<(), InspectionError> {
        let runtime = self.runtime.as_mut().ok_or("runtime absent")?;
        runtime.arm_all().map_err(text)?;
        let coordinator = runtime
            .initial_coordinator_snapshot(&self.graph, 1024 * 1024)
            .map_err(text)?;
        let prepared = runtime.prepared_node_records().map_err(text)?.to_vec();
        let root = self
            .directory
            .as_ref()
            .ok_or("world directory absent")?
            .path();
        let mut publisher = StoredWorldActivationPublisher::new(
            Arc::new(DirectoryBlobBackend::new(
                "reader-conditional-original",
                root.join("blobs"),
            )),
            Arc::new(DirectoryRefBackend::new(root.join("refs"))),
            RefName::new("node-world-activations/reader-conditional-original").map_err(text)?,
        )
        .map_err(text)?
        .with_prepared_coordinator(self.profile.activation.clone(), prepared, coordinator)
        .map_err(text)?;
        self.activation = Some(runtime.activate(&mut publisher).map_err(text)?);
        Ok(())
    }

    /// Stages the exact original input and admits its genuine runtime permission.
    pub(super) fn begin(
        &mut self,
        node: &Id,
        quantum: u64,
    ) -> Result<OperationToken, InspectionError> {
        if self.pending_tokens.len() == 9 {
            return Err("declared nine-operation model cohort exhausted".into());
        }
        let runtime = self.runtime.as_mut().ok_or("runtime absent")?;
        let activation = self.activation.as_ref().ok_or("activation absent")?;
        let stage = identity(format!("stage/{node}/{quantum}"))?;
        let batch = identity(format!("batch/{node}/{quantum}"))?;
        let input = runtime
            .scheduler(&self.graph, activation)
            .map_err(text)?
            .prepare_input_batch(
                node,
                stage.clone(),
                batch.clone(),
                position(quantum * 1000 + 1, Phase::BoundaryControl),
            )
            .map_err(text)?;
        runtime.stage_inputs(input).map_err(text)?;
        let acknowledgement = runtime
            .recover_input_staging(activation, &stage)
            .map_err(text)?;
        let accepted = runtime
            .commit_input_acknowledgement(acknowledgement)
            .map_err(text)?;
        runtime.commit_input_staging(&accepted).map_err(text)?;
        let grant = runtime
            .scheduler(&self.graph, activation)
            .map_err(text)?
            .admit_quantum(
                node,
                identity(format!("run/{node}/{quantum}"))?,
                identity(format!("window/{node}/{quantum}"))?,
                batch,
            )
            .map_err(text)?;
        match runtime.begin_admitted(grant).map_err(text)? {
            BeginResult::Accepted(token) => {
                self.pending_tokens.push(token.clone());
                Ok(token)
            }
            other => Err(format!("original model Begin was not accepted: {other:?}").into()),
        }
    }

    /// Completes and acknowledges the same accepted original permission.
    pub(super) fn complete(
        &mut self,
        token: &OperationToken,
    ) -> Result<NativePublication, InspectionError> {
        let runtime = self.runtime.as_mut().ok_or("runtime absent")?;
        let mut context = Context::from_waker(Waker::noop());
        if !matches!(runtime.poll(token, &mut context), Poll::Pending) {
            return Err("original model did not retain its accepted pending window".into());
        }
        if runtime.close_quantum(token).map_err(text)? != Submission::Accepted {
            return Err("original model Close was not accepted".into());
        }
        let Poll::Ready(Ok(outcome)) = runtime.poll(token, &mut context) else {
            return Err("original model completion is unavailable".into());
        };
        let scheduling = outcome.scheduling.as_ref().ok_or("scheduling absent")?;
        if scheduling.publications.len() != 1 {
            return Err("original model publication roster differs".into());
        }
        let publication = scheduling.publications[0].clone();
        let receipt = runtime.scheduling_receipt(token).map_err(text)?;
        let commit = runtime.commit_scheduling_receipt(receipt).map_err(text)?;
        runtime
            .acknowledge_scheduled(token, &commit)
            .map_err(text)?;
        Ok(publication)
    }

    /// Signs the actual pending cut and moves every verified body into owned pins.
    pub(super) fn capture_and_pin(&mut self) -> Result<(), InspectionError> {
        use crucible::node_contract::OriginalInputLineageLimits;
        use crucible::node_state::{
            NativeArchive, NativeArchiveLimits, OriginalLineageCaptureRequest, StateLimits,
            StateRequirements, StateRestoreMode,
        };
        use std::os::unix::fs::PermissionsExt;

        if self.capture_attempted || self.pending_tokens.len() != 9 {
            return Err("capture was already attempted or original cut roster differs".into());
        }
        // This marker precedes the signer and all owning source callbacks.
        self.capture_attempted = true;
        self.capture_directory = Some(
            tempfile::Builder::new()
                .prefix("reader-conditional-capture-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in("/tmp")
                .map_err(text)?,
        );
        let directory = self
            .capture_directory
            .as_ref()
            .ok_or("capture namespace absent")?;
        let state = StateLimits {
            maximum_record_bytes: 8 * 1024 * 1024,
            maximum_content_bytes: 256 * 1024 * 1024,
            maximum_total_content_bytes: 384 * 1024 * 1024,
            maximum_content_objects: 4096,
            maximum_dependency_edges: 65_536,
            ..StateLimits::default()
        };
        let mut limits = NativeArchiveLimits {
            state,
            ..NativeArchiveLimits::default()
        };
        limits.native.maximum_record_bytes = 8 * 1024 * 1024;
        limits.native.maximum_total_record_bytes = 384 * 1024 * 1024;
        limits.native.maximum_objects = 4096;
        self.capture_archive = Some(NativeArchive::open(directory.path(), limits).map_err(text)?);
        let archive = self
            .capture_archive
            .as_ref()
            .ok_or("capture signer absent")?;
        let runtime = self.runtime.as_mut().ok_or("original runtime absent")?;
        let activation = self
            .activation
            .as_ref()
            .ok_or("original activation absent")?;
        self.capture_record = Some(archive.capture_original_lineage_world(
            OriginalLineageCaptureRequest {
                graph: &self.graph, runtime, activation,
                cut: position(2000, Phase::BoundaryControl), ordinal: U64::new(6),
                capture_id: identity("conditional/original-runtime7-capture".into())?,
                requirements: StateRequirements {
                    preservation_contract: identity(
                        crucible::node_adapters::transcript::TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE.into()
                    )?,
                    exact_model_continuation: true, deterministic: false,
                    restore_mode: StateRestoreMode::DurableRestart,
                },
                immutable: &self.capture_factory, factory: &self.capture_factory,
                lineage_limits: OriginalInputLineageLimits::default(),
            }
        ).map_err(text)?);

        // Store each actual opaque result before subsequent allocation or copies.
        let record = self
            .capture_record
            .as_ref()
            .ok_or("signed capture record absent")?;
        self.capture_reopened_record = Some(archive.load(record.artifact()).map_err(text)?);
        let reopened = self
            .capture_reopened_record
            .as_ref()
            .ok_or("reopened signed record absent")?;
        if reopened.artifact() != record.artifact()
            || reopened.manifest() != record.manifest()
            || reopened.owners() != record.owners()
        {
            return Err("independently reopened capture differs from persisted source".into());
        }
        let record = reopened;
        self.capture_content = Some(
            record
                .original_lineage_content(
                    &self.graph,
                    &self.capture_factory,
                    OriginalInputLineageLimits::default(),
                )
                .map_err(text)?,
        );
        let content = self
            .capture_content
            .take()
            .ok_or("verified complete source absent")?;
        match record.pin_original_lineage_world(
            content,
            OriginalInputLineageLimits::default(),
            &self.graph,
            &self.capture_factory,
        ) {
            Ok(pins) => self.capture_pins = Some(pins),
            Err(failure) => {
                let (error, content) = failure.into_parts();
                self.capture_content = Some(content);
                return Err(text(error));
            }
        }
        let pins = self
            .capture_pins
            .as_ref()
            .ok_or("complete source pins absent")?;
        if pins.len() != 3
            || pins.iter().any(|pin| {
                pin.runtime().source_activation
                    != crucible::node_contract::SavedRuntimeActivation::from(
                        &self.profile.activation,
                    )
                    || pin.runtime().capture_cut != position(2000, Phase::BoundaryControl)
            })
        {
            return Err("complete pinned source roster or cut differs".into());
        }
        Ok(())
    }

    /// Persists complete verified pin bytes before removing their signed namespace.
    pub(super) fn export_pinned_bodies(&mut self) -> Result<(), InspectionError> {
        use std::collections::BTreeMap;
        use std::io::{Read, Write};
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

        if self.capture_export_attempted || self.capture_namespace_gone {
            return Err("pinned source export is repeated or namespace already removed".into());
        }
        let pins = self
            .capture_pins
            .as_ref()
            .ok_or("complete pinned source absent")?;
        let [first, _, _] = pins.as_slice() else {
            return Err("complete pinned source roster differs".into());
        };
        if first.content().object_count() > 4096
            || first.content().total_bytes() > 384 * 1024 * 1024
            || first
                .original_objects()
                .any(|(_, body)| body.len() > 256 * 1024 * 1024)
        {
            return Err("signed source body export exceeds declared archive credit".into());
        }
        self.capture_export_attempted = true;
        let root = self
            .directory
            .as_ref()
            .ok_or("owning evidence directory absent")?
            .path();
        let body_root = root.join("pinned-original-bodies");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&body_root)
            .map_err(text)?;
        let mut inventory = Vec::new();
        inventory
            .try_reserve_exact(first.content().object_count())
            .map_err(text)?;
        let mut written = BTreeMap::new();
        for (reference, bytes) in first.original_objects() {
            reference.verify(bytes).map_err(text)?;
            // Typed aliases share the already verified bytes; the index retains
            // every full reference while the inert body export writes it once.
            let name = format!("body-{}.bin", reference.hash.digest);
            if let Some(original) = written.get(&name) {
                if *original != bytes {
                    return Err("pinned body filename collides with different bytes".into());
                }
            } else {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(body_root.join(&name))
                    .map_err(text)?;
                file.write_all(bytes).map_err(text)?;
                file.sync_all().map_err(text)?;
                written.insert(name.clone(), bytes);
            }
            inventory.push((reference, name));
        }
        // This exact filename is the native archive's signed index wire. It is
        // retained as inert evidence after operational MAC load, never decoded
        // by the installed policy and never used to reopen an original image.
        let record = self
            .capture_reopened_record
            .as_ref()
            .ok_or("MAC-loaded record absent")?;
        let archive_root = self
            .capture_directory
            .as_ref()
            .ok_or("signed source namespace absent")?
            .path();
        let envelope_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(archive_root.join(format!("{}.native-index-v1", record.artifact().hash.digest)))
            .map_err(text)?;
        let metadata = envelope_file.metadata().map_err(text)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 8 * 1024 * 1024 {
            return Err("native signed envelope exceeds fixed private file credit".into());
        }
        let mut envelope = Vec::new();
        envelope
            .try_reserve_exact(metadata.len() as usize)
            .map_err(text)?;
        envelope_file
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut envelope)
            .map_err(text)?;
        if envelope.len() as u64 != metadata.len() {
            return Err("native signed envelope changed during inert export".into());
        }
        let envelope_ref =
            crucible_node_contract::canonical::content_ref(&envelope, "application/json")
                .map_err(text)?;
        let mut envelope_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("signed-original-source-envelope.json"))
            .map_err(text)?;
        envelope_file.write_all(&envelope).map_err(text)?;
        envelope_file.sync_all().map_err(text)?;

        #[derive(serde::Serialize)]
        struct Export<'a> {
            schema: &'static str,
            source_artifact: &'a crucible_node_contract::ContentRef,
            signed_envelope: crucible_node_contract::ContentRef,
            runtime: &'a crucible_node_contract::ContentRef,
            source_activation: &'a crucible::node_contract::SavedRuntimeActivation,
            cut: Position,
            owners: Vec<Id>,
            objects: Vec<(&'a crucible_node_contract::ContentRef, String)>,
            scope: &'static str,
        }
        let mut owners = Vec::new();
        owners.try_reserve_exact(3).map_err(text)?;
        owners.extend(pins.iter().map(|pin| pin.source().owner().owner.clone()));
        let export = Export {
            schema: "crucible.reader-conditional-owned-source-export.v1",
            source_artifact: first.source_artifact(),
            signed_envelope: envelope_ref,
            runtime: first.runtime_reference(),
            source_activation: &first.runtime().source_activation,
            cut: first.runtime().capture_cut,
            owners,
            objects: inventory,
            scope: "inert complete signed body export; no archive key, native image lease, Ready or class",
        };
        struct Credit(usize);

        impl Write for Credit {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len())
                    .filter(|total| *total <= 8 * 1024 * 1024)
                    .ok_or_else(|| {
                        std::io::Error::other("owned source export index credit exhausted")
                    })?;
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Credit(0), &export).map_err(text)?;
        let bytes = super::conditional_profile::encode(&export)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("pinned-original-source-index.json"))
            .map_err(text)?;
        file.write_all(&bytes).map_err(text)?;
        file.sync_all().map_err(text)?;
        self.capture_export_complete = true;
        Ok(())
    }

    /// Reclaims the actual captured model roster before any fresh branch is built.
    pub(super) fn retire_captured_models(&mut self) -> Result<(), InspectionError> {
        if self.capture_retirement_attempted
            || !self.capture_namespace_gone
            || self
                .capture_pins
                .as_ref()
                .is_none_or(|pins| pins.len() != 3)
        {
            return Err("captured model retirement is repeated or source pins incomplete".into());
        }
        // Quarantine may cross owning source callbacks; a refusal cannot redispatch.
        self.capture_retirement_attempted = true;
        drop(self.runtime.take());
        drop(self.pending_slot.take());
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..32 {
            if let Poll::Ready(Err(error)) = self.queue.poll_reclamation(&mut context) {
                return Err(text(error));
            }
            if self.queue.reserved_worlds() == 0 {
                self.capture_runtime_retired = true;
                return Ok(());
            }
        }
        Err("captured original runtime remains under owning quarantine".into())
    }

    /// Transfers complete pins only after the actual source runtime has retired.
    pub(super) fn take_complete_source_pins(
        &mut self,
    ) -> Result<Vec<crucible::node_state::PinnedOriginalLineageSource>, InspectionError> {
        if !self.capture_runtime_retired || !self.capture_namespace_gone {
            return Err("actual captured source is not retired and namespace-gone".into());
        }
        self.capture_pins
            .take()
            .ok_or_else(|| "complete original pin roster absent".into())
    }

    /// Removes only the newly signed namespace after complete body transfer.
    pub(super) fn remove_capture_namespace(&mut self) -> Result<(), InspectionError> {
        if self.capture_namespace_removal_attempted
            || !self.capture_export_complete
            || self.capture_pins.as_ref().is_none_or(|p| p.len() != 3)
        {
            return Err("capture namespace removal is repeated or complete pins absent".into());
        }
        self.capture_namespace_removal_attempted = true;
        let directory = self
            .capture_directory
            .as_ref()
            .ok_or("capture namespace absent")?;
        std::fs::remove_dir_all(directory.path()).map_err(text)?;
        if directory.path().try_exists().map_err(text)? {
            return Err("original capture namespace still exists".into());
        }
        self.capture_namespace_gone = true;
        Ok(())
    }

    /// Retains both fresh complete branches beside the actual retired source.
    pub(super) fn restore_complete_twins(&mut self) -> Result<(), InspectionError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let pins = self.take_complete_source_pins()?;
        // This outer slot owns the complete transfer before any source callback.
        // The borrowed SOURCE graph and factory remain in this same owning stack.
        let mut capsule = Some(super::conditional_twins::ConditionalTwins::new(
            Rc::clone(&self.profile),
            &self.graph,
            &self.capture_factory,
            pins,
        ));
        let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), InspectionError> {
            let twins = capsule.as_mut().ok_or("owning twins capsule absent")?;
            twins.restore()?;
            twins.complete_suffixes()?;
            twins.retain_suffix_witnesses()?;
            let witnesses = twins.suffix_witnesses().collect::<Vec<_>>();
            if witnesses.len() != 2 {
                return Err("complete fresh state witness roster differs".into());
            }
            let witnesses = witnesses
                .iter()
                .map(|(activation, runtime, scheduling)| {
                    (
                        crucible::node_contract::SavedRuntimeActivation::from(*activation),
                        *runtime,
                        *scheduling,
                    )
                })
                .collect::<Vec<_>>();
            let results = twins.results().collect::<Vec<_>>();
            if results.len() != 2 || results.iter().any(|(_, outputs)| outputs.len() != 3) {
                return Err("actual complete twin result roster differs".into());
            }
            let results = results
                .iter()
                .map(|(activation, publications)| {
                    (
                        crucible::node_contract::SavedRuntimeActivation::from(*activation),
                        *publications,
                    )
                })
                .collect::<Vec<_>>();
            // The fixed roster is checked before saving or encoding its state.
            struct ResultCredit(usize);

            impl Write for ResultCredit {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    self.0 = self
                        .0
                        .checked_add(bytes.len())
                        .filter(|total| *total <= 1024 * 1024)
                        .ok_or_else(|| {
                            std::io::Error::other("twin result evidence credit exhausted")
                        })?;
                    Ok(bytes.len())
                }

                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            serde_json::to_writer(ResultCredit(0), &results).map_err(text)?;
            let bytes = super::conditional_profile::encode(&results)?;
            if bytes.len() > 1024 * 1024 {
                return Err("actual twin result encoding exceeds fixed evidence credit".into());
            }
            let root = self
                .directory
                .as_ref()
                .ok_or("source evidence directory absent")?
                .path();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("original-complete-twin-results.json"))
                .map_err(text)?;
            file.write_all(&bytes).map_err(text)?;
            file.sync_all().map_err(text)?;
            serde_json::to_writer(ResultCredit(0), &witnesses).map_err(text)?;
            let bytes = super::conditional_profile::encode(&witnesses)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("original-complete-twin-state-witnesses.json"))
                .map_err(text)?;
            file.write_all(&bytes).map_err(text)?;
            file.sync_all().map_err(text)?;
            twins.retire()?;
            Ok(())
        }));
        match result {
            Ok(Ok(())) => Ok(()),
            failure => {
                // A returned error or unwind cannot drop the sole complete pins.
                // Best-effort diagnostics run inside a second fence; all owning
                // state stays parked even if evidence encoding itself refuses.
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    if let Some(directory) = &self.directory {
                        let detail = match &failure {
                            Ok(Err(error)) => format!("{error:?}"),
                            _ => "fresh twin callback unwound".to_owned(),
                        };
                        let _ = std::fs::write(directory.path().join("twins-refusal.txt"), detail);
                    }
                }));
                loop {
                    std::thread::park();
                }
            }
        }
    }

    /// Retains one exact reference-only prefix before its inert write-once export.
    pub(super) fn export_prefix(&mut self) -> Result<(), InspectionError> {
        use super::conditional_profile::encode;
        use crucible::node_contract::OriginalInputLineageLimits;
        use std::io::Write;

        if self.pending_tokens.len() != 9 || self.prefix_body.is_some() {
            return Err("original prefix roster differs or export was already attempted".into());
        }
        let runtime = self.runtime.as_ref().ok_or("runtime absent")?;
        let record = runtime
            .original_lineage_runtime_snapshot(
                position(2000, Phase::BoundaryControl),
                U64::new(6),
                OriginalInputLineageLimits::default(),
                8 * 1024 * 1024,
            )
            .map_err(text)?;
        // Retain the actual inert record even if its installed validator refuses.
        self.prefix_body = Some(encode(&record)?);
        let body = self.prefix_body.as_ref().ok_or("prefix body absent")?;
        let root = self
            .directory
            .as_ref()
            .ok_or("world directory absent")?
            .path();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("original-prefix-runtime7.json"))
            .map_err(text)?;
        file.write_all(body).map_err(text)?;
        file.sync_all().map_err(text)?;
        self.capture_factory
            .authenticate_prefix(&self.graph, &record)
            .map_err(text)?;

        super::conditional_prefix_controls::receipt_roles(
            &self.profile,
            &self.graph,
            &self.capture_factory,
            &record,
            body.len(),
        )?;
        let mut control = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("original-receipt-role-controls.txt"))
            .map_err(text)?;
        control.write_all(b"exact scheduling and delivered Measurements accepted; original Stop and same-digest altered-media views independently refused for both roles\n").map_err(text)?;
        control.sync_all().map_err(text)?;

        // This readonly owning sample remains inert evidence; signed capture
        // independently samples and authenticates the same original scheduler.
        let scheduler = runtime
            .original_lineage_scheduler_snapshot(
                self.activation
                    .as_ref()
                    .ok_or("original activation absent")?,
                position(2000, Phase::BoundaryControl),
                U64::new(6),
            )
            .map_err(text)?;
        let scheduler_body = encode(&scheduler)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("original-prefix-scheduler1.json"))
            .map_err(text)?;
        file.write_all(&scheduler_body).map_err(text)?;
        file.sync_all().map_err(text)?;
        super::conditional_prefix_controls::scheduler_roster(
            &self.profile,
            &record,
            &scheduler,
            scheduler_body.len(),
        )?;
        let mut controls = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("original-scheduler-role-controls.txt"))
            .map_err(text)?;
        controls.write_all(b"exact Stage+Run union, pending Delivery bodies and Publication end accepted; missing/foreign Stage, missing/altered Delivery and changed end phase refused\n").map_err(text)?;
        controls.sync_all().map_err(text)?;
        Ok(())
    }
}

impl Drop for ConditionalWorld {
    fn drop(&mut self) {
        // A source callback cannot unwind past the complete owning world fence.
        let settled = catch_unwind(AssertUnwindSafe(|| {
            drop(self.runtime.take());
            drop(self.pending_slot.take());
            let mut context = Context::from_waker(Waker::noop());
            for _ in 0..32 {
                let _ = self.queue.poll_reclamation(&mut context);
                if self.queue.reserved_worlds() == 0 {
                    return true;
                }
            }
            false
        }))
        .unwrap_or(false);
        if let Some(directory) = self.capture_directory.take() {
            // An already removed namespace is never revisited by TempDir Drop.
            let root = directory.keep();
            if !self.capture_namespace_gone {
                eprintln!("conditional capture namespace retained: {}", root.display());
            }
        }
        if let Some(directory) = self.directory.take() {
            let root = directory.keep();
            eprintln!("conditional original world retained: {}", root.display());
        }
        if !settled {
            loop {
                std::thread::park();
            }
        }
    }
}

fn identity(value: String) -> Result<Id, InspectionError> {
    Id::new(value).map_err(text)
}

fn position(tick: u64, phase: Phase) -> Position {
    Position::new(U64::new(tick), U64::new(0), phase)
}

fn text(error: impl std::fmt::Debug) -> InspectionError {
    format!("{error:?}").into()
}
