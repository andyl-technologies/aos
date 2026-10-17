//! Preserves genuine Root images and original public/common control ancestry.
//!
//! The selected envelope owns raw control packets as separately referenced
//! bodies. Original native paths are inert reconstruction lineage, never source
//! filesystem inputs. A failed post-capture wrapper retains its exact image and
//! reports uncertain knowledge; an identical retry does not capture again.

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
};

use crucible_node_contract::{ContentRef, Extensions, Id, SchemaRef, U64, canonical};
use crucible_node_provider::gem5::{
    ArmRootCapturedImage, ArmRootControlKind, ArmRootHistoricalSource, ArmRootProcessClosure,
    Gem5CapturedArtifactRole,
};
use serde::{Deserialize, Serialize};

use crate::{
    node_adapters::preparation_state::OriginalWorldPreparation, node_contract::*,
    node_scheduling::InputPayload,
};

use super::{ARM_ROOT_IMPLEMENTATION, QualifiedArmRootNode, encoding, refusal};

/// Names the distinct preparation-bearing Root process preservation profile.
pub const ARM_ROOT_PRESERVATION_PROFILE: &str = "gem5/arm-root-public-preservation-v2";
/// Defines complete original Root state without claiming generic Linux device admission.
pub const ARM_ROOT_CONTINUATION_SPECIFICATION: &str = "crucible/gem5-arm-root-public-native-continuation-v2: authentic fixed parent-zero Root Serial model; complete opaque process/config/image/resource roster; actual original common grants and ordered successful/refused native raw response bodies; exact raw Ready/control/admin ACK and preparation transcripts; original whole-world public preparations/coordinator/publication bodies; selected mechanical callback limit 262144 per subordinate Poll; direct raw 1THz native tick to common picosecond mapping with authentic initial native tick zero; exact original bootstrap permission history; common capture cut separate from latent native callback frontier; bounded eight-generation exact original signed preparation and prefix ancestry; original supplementary-files root is inert authenticated relocation data; imported historical data grants no current execution or initial preparation authority; each reconstructed native peer retains Restored provenance and independently recaptures/audits its own current closure before fresh public mapping";

/// Returns the selected Root codec identity without issuing capture authority.
///
/// # Errors
/// Refuses invalid schema identities or content-reference construction failure.
pub fn arm_root_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("crucible/gem5-arm-root-public-native-continuation-v2")
            .map_err(|error| refusal(&error.to_string()))?,
        version: 2,
        definition: canonical::content_ref(
            ARM_ROOT_CONTINUATION_SPECIFICATION.as_bytes(),
            "text/plain",
        )
        .map_err(|error| refusal(&error.to_string()))?,
        extensions: Extensions::new(),
    })
}

/// Retains source-owned private roots beneath the selected complete Root codec.
pub struct ArmRootArchiveInstallation {
    /// Contains the actual native resource, image, temporary and audit namespaces.
    pub owned_scope: PathBuf,
    /// Owns the private empty child namespaces used for original captures.
    pub captures_root: PathBuf,
    /// Bounds unrecycled original native capture attempts, including failures.
    pub maximum_captures: usize,
}

impl ArmRootArchiveInstallation {
    pub(super) fn validate(
        &self,
        native: &crucible_node_provider::gem5::ArmRootNativeProcess,
    ) -> Result<(), OperationFailure> {
        if self.maximum_captures == 0
            || self.maximum_captures > 8
            || !self.captures_root.starts_with(&self.owned_scope)
            || !native
                .launch()
                .map_err(|error| refusal(&error.to_string()))?
                .resource_root()
                .starts_with(&self.owned_scope)
        {
            return Err(refusal(
                "ARM archive lacks bounded complete private native custody",
            ));
        }
        for root in [&self.owned_scope, &self.captures_root] {
            let metadata =
                std::fs::symlink_metadata(root).map_err(|error| refusal(&error.to_string()))?;
            if !metadata.is_dir()
                || metadata.mode() & 0o777 != 0o700
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || std::fs::canonicalize(root).map_err(|error| refusal(&error.to_string()))?
                    != *root
            {
                return Err(refusal(
                    "ARM archive root is not owned canonical private storage",
                ));
            }
        }
        Ok(())
    }
}

pub(super) struct RootCapture {
    pub source: RuntimeSnapshot,
    pub activation: WorldActivation,
    pub root: PathBuf,
    pub image: Option<ArmRootCapturedImage>,
    pub closure: Option<ArmRootProcessClosure>,
    pub installed: Option<InstalledNativeCapture>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PacketWire {
    pub kind: ArmRootControlKind,
    pub body: ContentRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionWire {
    pub token: Id,
    pub packet: ContentRef,
    pub transcript: ContentRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrefixWire {
    pub body: ContentRef,
    pub activation: SavedRuntimeActivation,
    pub route: NodeRoute,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationWire {
    pub original: SavedRuntimeOperation,
    pub prefixes: Vec<PrefixWire>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactWire {
    pub role: Id,
    pub name: String,
    pub content: ContentRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootWire {
    pub format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    pub node: Id,
    pub source_activation: SavedRuntimeActivation,
    pub common_cut: crucible_node_contract::Position,
    pub owners: Vec<OwnerIdentity>,
    pub capture: Id,
    pub source: ArmRootHistoricalSource,
    pub supplementary_files_root: String,
    pub native_boundary: crucible_node_provider::gem5::Gem5Boundary,
    pub maximum_microsteps: U64,
    pub maximum_events_per_poll: U64,
    pub output_sequence: U64,
    pub operations: Vec<OperationWire>,
    pub native_outcomes: Vec<ContentRef>,
    pub control_schema: String,
    pub packets: Vec<PacketWire>,
    pub sessions: Vec<SessionWire>,
    #[serde(deserialize_with = "required_nullable")]
    pub pending: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub last_acknowledged: Option<Id>,
    pub closure: ContentRef,
    pub world_preparation: ContentRef,
    pub ready: ContentRef,
    pub native_ready: ContentRef,
    pub native_session: ContentRef,
    #[serde(deserialize_with = "required_nullable")]
    pub previous: Option<ContentRef>,
    pub observations: Vec<ContentRef>,
    pub artifacts: Vec<ArtifactWire>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl QualifiedArmRootNode {
    pub(super) fn capture_root(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        validate_limits(limits)?;
        if self.quarantined
            || !self.same_world(activation)
            || source.schema_version != 1
            || source.source_activation != SavedRuntimeActivation::from(activation.record())
            || source
                .inputs
                .iter()
                .any(|input| input.node == self.preparation.route.node)
        {
            return Err(refusal(
                "ARM complete capture has foreign or unsupported original runtime custody",
            ));
        }
        if self
            .restored
            .as_ref()
            .is_some_and(|source| source.ancestry.len() >= 7)
        {
            return Err(refusal(
                "ARM selected preparation ancestry depth is exhausted before capture",
            ));
        }
        encoding::record(source, limits.maximum_record_bytes)?;
        let archive = self
            .archive
            .as_ref()
            .ok_or_else(|| refusal("ARM preparation-bearing capture is not selected"))?;
        archive.validate(&self.preparation.native)?;
        let own: Vec<_> = source
            .operations
            .iter()
            .filter(|operation| operation.route.node == self.preparation.route.node)
            .collect();
        if own.len() != self.ledger.operations.len() {
            return Err(refusal("ARM source runtime omits an original native grant"));
        }
        for saved in &own {
            let original = self
                .ledger
                .operations
                .iter()
                .find(|old| old.admission.token().operation() == &saved.operation)
                .ok_or_else(|| refusal("ARM source runtime invented an original grant"))?;
            let result_matches = match (&saved.result, &original.outcome) {
                (SavedRuntimeResult::Pending, None) => !original.acknowledged,
                (SavedRuntimeResult::Complete(saved), Some(actual)) => {
                    !original.acknowledged && saved == actual
                }
                (SavedRuntimeResult::Acknowledged(saved), Some(actual)) => {
                    original.acknowledged && saved == actual
                }
                _ => false,
            };
            if saved.route != self.preparation.route
                || saved.request != *original.admission.request()
                || saved.input_batch.is_some()
                || saved.close_submission.is_some()
                || saved.submission_effects.is_some()
                || original.failure.is_some()
                || !self.same_world(original.admission.activation())
                || !result_matches
            {
                return Err(refusal(
                    "ARM capture changes original request, result, output or ACK custody",
                ));
            }
        }
        if let Some(index) = self
            .captures
            .iter()
            .position(|old| old.source.capture_ordinal == source.capture_ordinal)
        {
            if self.captures[index].source != *source {
                return Err(refusal(
                    "ARM identical capture retry changed original complete source",
                ));
            }
            if let Some(installed) = &self.captures[index].installed {
                return copy_capture(installed, limits);
            }
            if self.captures[index].image.is_none() {
                return Err(unknown(
                    "ARM original capture attempt retains unresolved native custody",
                ));
            }
            return self.finish_capture(index, limits).map_err(uncertainty);
        }
        if self.captures.len() >= archive.maximum_captures {
            return Err(refusal("ARM original capture slots are exhausted"));
        }
        // The selected native mechanism bounds each image at 2GiB and complete
        // artifacts at 4GiB with 8192 files. Credit is reserved before DMTCP runs.
        if limits.maximum_artifact_bytes < 2 * 1024 * 1024 * 1024
            || limits.maximum_total_artifact_bytes < 4 * 1024 * 1024 * 1024
            || limits.maximum_objects < 8193
        {
            return Err(refusal(
                "ARM complete mechanism backing credit is insufficient before capture",
            ));
        }
        let captures_root = archive.captures_root.clone();
        let mapping = self
            .mapping
            .as_ref()
            .ok_or_else(|| refusal("ARM source capture omits original public preparation"))?;
        let (world, record, coordinator, publication) =
            OriginalWorldPreparation::capture(activation, limits.maximum_record_bytes)?;
        let original = world.node(&self.preparation.route.node)?;
        if original.ready_receipt != mapping.ready.ready_receipt
            || original.prepared_owners.as_slice() != std::slice::from_ref(&mapping.owner)
        {
            return Err(refusal(
                "ARM public source barrier differs from actually retained native preparation",
            ));
        }
        self.ledger.retain_standalone(&[
            (&record.reference, &record.bytes),
            (&coordinator.reference, &coordinator.bytes),
            (&publication.reference, &publication.bytes),
        ])?;
        self.preflight_evidence(limits)?;
        let digest = canonical::json_hash(
            "crucible.gem5.arm-root-capture.v1",
            &(
                &source.source_activation,
                source.capture_ordinal,
                &self.preparation.route,
            ),
        )
        .map_err(|error| refusal(&error.to_string()))?;
        let capture = Id::new(format!("arm-root-capture/{}", digest.digest))
            .map_err(|error| refusal(&error.to_string()))?;
        let root = captures_root.join(&digest.digest);
        let index = self.captures.len();
        self.captures
            .try_reserve_exact(1)
            .map_err(|_| refusal("ARM original capture owning slot is unavailable"))?;
        self.captures.push(RootCapture {
            source: source.clone(),
            activation: activation.clone(),
            root: root.clone(),
            image: None,
            closure: None,
            installed: None,
        });
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|error| refusal(&error.to_string()))?;
        let image = self
            .preparation
            .native
            .capture(capture, &root)
            .map_err(|error| unknown(&error.to_string()))?;
        // Move the actual image into its already reserved owner before auditing,
        // serialization, descriptor opening or any fallible returned-copy work.
        self.captures[index].image = Some(image);
        self.finish_capture(index, limits).map_err(uncertainty)
    }

    fn preflight_evidence(&self, limits: NativeCaptureLimits) -> Result<(), OperationFailure> {
        let history = self
            .preparation
            .native
            .control_history()
            .map_err(|error| refusal(&error.to_string()))?;
        let mut original_bytes = 0usize;
        let mut original_objects = 0usize;
        for bytes in
            self.ledger
                .standalone
                .iter()
                .map(|body| body.bytes.as_slice())
                .chain(self.ledger.operations.iter().flat_map(|operation| {
                    operation.evidence.iter().map(|body| body.bytes.as_slice())
                }))
                .chain(history.packets.iter().map(|packet| packet.bytes.as_slice()))
                .chain(
                    history
                        .sessions
                        .iter()
                        .map(|session| session.transcript_bytes.as_slice()),
                )
        {
            if bytes.len() > limits.maximum_record_bytes {
                return Err(refusal(
                    "ARM original receipt exceeds selected per-record credit",
                ));
            }
            original_bytes = original_bytes
                .checked_add(bytes.len())
                .filter(|total| *total <= limits.maximum_total_record_bytes)
                .ok_or_else(|| refusal("ARM original capture receipt credit is exhausted"))?;
            original_objects += 1;
        }
        // Duplicate original roles conservatively consume this preflight. The
        // final signed inventory still deduplicates only equal full references.
        if original_objects + 8193 > limits.maximum_objects {
            return Err(refusal(
                "ARM complete original artifact/receipt reservation is exhausted",
            ));
        }
        // Reserve the complete selected source-installed audit body and the
        // final envelope, plus three bounded raw capture/reconnect frames.
        let reserved = limits
            .maximum_record_bytes
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(3 * crucible_node_provider::gem5::GEM5_NATIVE_FRAME_BYTES)
            })
            .ok_or_else(|| refusal("ARM capture envelope credit overflow"))?;
        let total = original_bytes
            .checked_add(reserved)
            .filter(|total| *total <= limits.maximum_total_record_bytes)
            .ok_or_else(|| {
                refusal("ARM original capture has insufficient aggregate receipt credit")
            })?;
        let _reserved_total = total;
        Ok(())
    }

    fn finish_capture(
        &mut self,
        index: usize,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        let archive = self
            .archive
            .as_ref()
            .ok_or_else(|| refusal("ARM retained capture installation is absent"))?;
        if self.captures[index].closure.is_none() {
            let image = self.captures[index]
                .image
                .as_ref()
                .ok_or_else(|| refusal("ARM actual retained image is absent"))?;
            let closure = self
                .preparation
                .native
                .qualify_capture(image, &archive.owned_scope)
                .map_err(|error| unknown(&error.to_string()))?;
            self.captures[index].closure = Some(closure);
        }
        let retained = &self.captures[index];
        let image = retained
            .image
            .as_ref()
            .ok_or_else(|| refusal("ARM actual image custody is absent"))?;
        let closure = retained
            .closure
            .as_ref()
            .ok_or_else(|| refusal("ARM current original capture audit is absent"))?;
        let record = image
            .archive_record()
            .map_err(|error| unknown(&error.to_string()))?;
        if !retained.root.starts_with(&archive.captures_root)
            || record
                .artifacts
                .iter()
                .any(|artifact| !artifact.artifact.path.starts_with(&retained.root))
        {
            return Err(unknown(
                "ARM retained image left its original reserved capture namespace",
            ));
        }
        let (world, world_record, coordinator, publication) =
            OriginalWorldPreparation::capture(&retained.activation, limits.maximum_record_bytes)?;
        if world.activation != retained.source.source_activation {
            return Err(refusal(
                "ARM captured world preparation differs from its original source",
            ));
        }
        let mapping = self
            .mapping
            .as_ref()
            .ok_or_else(|| refusal("ARM retained mapping is absent"))?;
        let mut evidence = BTreeMap::new();
        for body in self.ledger.standalone.iter().chain(
            self.ledger
                .operations
                .iter()
                .flat_map(|operation| &operation.evidence),
        ) {
            add_evidence(&mut evidence, body, limits)?;
        }
        for body in [&world_record, &coordinator, &publication] {
            add_evidence(&mut evidence, body, limits)?;
        }
        let mut packets = Vec::new();
        for packet in &record.control_history.packets {
            let reference = canonical::content_ref(&packet.bytes, "application/json")
                .map_err(|error| refusal(&error.to_string()))?;
            add_evidence(
                &mut evidence,
                &InputPayload {
                    reference: reference.clone(),
                    bytes: packet.bytes.clone(),
                },
                limits,
            )?;
            packets.push(PacketWire {
                kind: packet.kind,
                body: reference,
            });
        }
        let mut sessions = Vec::new();
        for session in &record.control_history.sessions {
            add_evidence(
                &mut evidence,
                &InputPayload {
                    reference: session.transcript.clone(),
                    bytes: session.transcript_bytes.clone(),
                },
                limits,
            )?;
            sessions.push(SessionWire {
                token: session.token.clone(),
                packet: session.packet.clone(),
                transcript: session.transcript.clone(),
            });
        }
        let mut native_outcomes = Vec::new();
        for bytes in &record.original_outcomes {
            let reference = canonical::content_ref(bytes, "application/json")
                .map_err(|error| refusal(&error.to_string()))?;
            add_evidence(
                &mut evidence,
                &InputPayload {
                    reference: reference.clone(),
                    bytes: bytes.clone(),
                },
                limits,
            )?;
            native_outcomes.push(reference);
        }
        let (proof, bytes) = closure.evidence();
        add_evidence(
            &mut evidence,
            &InputPayload {
                reference: proof.clone(),
                bytes: bytes.to_vec(),
            },
            limits,
        )?;
        let operations = retained
            .source
            .operations
            .iter()
            .filter(|saved| saved.route.node == self.preparation.route.node)
            .map(|saved| {
                let original = self
                    .ledger
                    .operations
                    .iter()
                    .find(|original| original.admission.token().operation() == &saved.operation)
                    .ok_or_else(|| {
                        refusal("ARM original common operation disappeared during wrapping")
                    })?;
                Ok(OperationWire {
                    original: saved.clone(),
                    prefixes: original
                        .prefixes
                        .iter()
                        .map(|prefix| PrefixWire {
                            body: prefix.proof.clone(),
                            activation: prefix.activation.clone(),
                            route: prefix.route.clone(),
                        })
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?;
        let mut artifact_bytes = 0u64;
        let mut artifacts = Vec::new();
        for file in &record.artifacts {
            let role = match file.role {
                Gem5CapturedArtifactRole::Image => "image",
                Gem5CapturedArtifactRole::Resource => "resource",
            };
            let relative = file
                .relative
                .to_str()
                .ok_or_else(|| refusal("ARM original artifact name is not portable text"))?;
            let length = file.artifact.content.length.get();
            artifact_bytes = artifact_bytes
                .checked_add(length)
                .filter(|total| {
                    length <= limits.maximum_artifact_bytes
                        && *total <= limits.maximum_total_artifact_bytes
                })
                .ok_or_else(|| refusal("ARM complete streamed artifact credit is exhausted"))?;
            if artifacts.len() + evidence.len() + 1 >= limits.maximum_objects {
                return Err(refusal("ARM complete artifact object credit is exhausted"));
            }
            let descriptor: File = OpenOptions::new()
                .read(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&file.artifact.path)
                .map_err(|error| refusal(&error.to_string()))?;
            artifacts.push(NativeCaptureArtifact::from_file(
                Id::new(role).map_err(|error| refusal(&error.to_string()))?,
                format!("{role}/{relative}"),
                file.artifact.content.clone(),
                descriptor,
            )?);
        }
        let wire = RootWire {
            format: "crucible.gem5.arm-root-public-native-continuation".to_owned(),
            schema_version: 2,
            node: self.preparation.route.node.clone(),
            source_activation: retained.source.source_activation.clone(),
            common_cut: retained.source.capture_cut,
            owners: self.preparation.route.owners.clone(),
            capture: record.capture,
            source: record.source,
            supplementary_files_root: record
                .source_supplementary_files_root
                .to_str()
                .ok_or_else(|| refusal("ARM original supplementary root is not portable"))?
                .to_owned(),
            native_boundary: record.boundary,
            maximum_microsteps: self.authority.maximum_microsteps(),
            maximum_events_per_poll: self.resources.maximum_events_per_poll,
            output_sequence: self.sequence.into(),
            operations,
            native_outcomes,
            control_schema: record.control_history.schema,
            packets,
            sessions,
            pending: record.pending,
            last_acknowledged: record.last_acknowledged,
            closure: proof.clone(),
            world_preparation: world_record.reference,
            ready: mapping.ready.ready_receipt.clone(),
            native_ready: mapping.original_packet.clone(),
            native_session: mapping.original_session.clone(),
            previous: self
                .restored
                .as_ref()
                .map(|source| source.envelope.reference.clone()),
            observations: self.observations.clone(),
            artifacts: artifacts
                .iter()
                .map(|file| ArtifactWire {
                    role: file.role().clone(),
                    name: file.name().to_owned(),
                    content: file.reference().clone(),
                })
                .collect(),
        };
        let bytes = encoding::record(&wire, limits.maximum_record_bytes)?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| refusal(&error.to_string()))?;
        let extent = evidence
            .values()
            .try_fold(bytes.len(), |total, body| {
                total.checked_add(body.bytes.len())
            })
            .filter(|total| *total <= limits.maximum_total_record_bytes)
            .ok_or_else(|| refusal("ARM complete record aggregate exceeds reserved credit"))?;
        let _original_extent = extent;
        let installed = InstalledNativeCapture {
            owner: self.preparation.route.owners[0].owner.clone(),
            participants: vec![self.preparation.route.node.clone()],
            key: NativeStateKey {
                implementation: Id::new(ARM_ROOT_IMPLEMENTATION)
                    .map_err(|error| refusal(&error.to_string()))?,
                profile: Id::new(ARM_ROOT_PRESERVATION_PROFILE)
                    .map_err(|error| refusal(&error.to_string()))?,
                schema: arm_root_continuation_schema()?,
            },
            cut: retained.source.capture_cut,
            state: InputPayload { reference, bytes },
            evidence: evidence.into_values().collect(),
            artifacts,
        };
        self.captures[index].installed = Some(installed);
        copy_capture(
            self.captures[index]
                .installed
                .as_ref()
                .ok_or_else(|| refusal("ARM original capture seal disappeared"))?,
            limits,
        )
    }
}

fn add_evidence(
    objects: &mut BTreeMap<ContentRef, InputPayload>,
    body: &InputPayload,
    limits: NativeCaptureLimits,
) -> Result<(), OperationFailure> {
    if body.bytes.len() > limits.maximum_record_bytes {
        return Err(refusal(
            "ARM original small object exceeds per-record credit",
        ));
    }
    body.reference
        .verify(&body.bytes)
        .map_err(|error| refusal(&error.to_string()))?;
    if let Some(old) = objects.get(&body.reference) {
        if old.bytes != body.bytes {
            return Err(refusal("ARM original same-role immutable body changed"));
        }
        return Ok(());
    }
    let extent = objects
        .values()
        .try_fold(body.bytes.len(), |total, object| {
            total.checked_add(object.bytes.len())
        })
        .filter(|total| *total <= limits.maximum_total_record_bytes)
        .ok_or_else(|| refusal("ARM original evidence aggregate is exhausted"))?;
    let _original_extent = extent;
    if objects.len() + 1 >= limits.maximum_objects {
        return Err(refusal("ARM original evidence object credit is exhausted"));
    }
    objects.insert(body.reference.clone(), body.clone());
    Ok(())
}

fn copy_capture(
    original: &InstalledNativeCapture,
    limits: NativeCaptureLimits,
) -> Result<InstalledNativeCapture, OperationFailure> {
    let mut extent = 0usize;
    for body in std::iter::once(original.state()).chain(original.evidence()) {
        body.reference
            .verify(&body.bytes)
            .map_err(|error| unknown(&error.to_string()))?;
        if body.bytes.len() > limits.maximum_record_bytes {
            return Err(unknown(
                "ARM original capture copy exceeds per-record credit",
            ));
        }
        extent = extent
            .checked_add(body.bytes.len())
            .filter(|total| *total <= limits.maximum_total_record_bytes)
            .ok_or_else(|| unknown("ARM original capture copy exceeds aggregate record credit"))?;
    }
    if original
        .artifacts()
        .len()
        .checked_add(original.evidence().len())
        .and_then(|count| count.checked_add(1))
        .is_none_or(|count| count > limits.maximum_objects)
    {
        return Err(unknown(
            "ARM original returned capture copy exceeds object credit",
        ));
    }
    let mut artifact_extent = 0u64;
    for artifact in original.artifacts() {
        let length = artifact.reference().length.get();
        if length > limits.maximum_artifact_bytes {
            return Err(unknown(
                "ARM original capture copy exceeds individual artifact credit",
            ));
        }
        artifact_extent = artifact_extent
            .checked_add(length)
            .filter(|total| *total <= limits.maximum_total_artifact_bytes)
            .ok_or_else(|| unknown("ARM original capture copy exceeds complete artifact credit"))?;
    }
    let copy = |body: &InputPayload| -> Result<InputPayload, OperationFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(body.bytes.len())
            .map_err(|_| unknown("ARM original capture copy allocation is unavailable"))?;
        bytes.extend_from_slice(&body.bytes);
        Ok(InputPayload {
            reference: body.reference.clone(),
            bytes,
        })
    };
    let state = copy(original.state())?;
    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(original.evidence().len())
        .map_err(|_| unknown("ARM original capture evidence slots are unavailable"))?;
    for body in original.evidence() {
        evidence.push(copy(body)?);
    }
    let mut artifacts = Vec::new();
    artifacts
        .try_reserve_exact(original.artifacts().len())
        .map_err(|_| unknown("ARM original capture artifact slots are unavailable"))?;
    artifacts.extend(original.artifacts().iter().cloned());
    Ok(InstalledNativeCapture {
        owner: original.owner().clone(),
        participants: original.participants().to_vec(),
        key: original.key().clone(),
        cut: original.cut(),
        state,
        evidence,
        artifacts,
    })
}

fn validate_limits(limits: NativeCaptureLimits) -> Result<(), OperationFailure> {
    if limits.maximum_record_bytes == 0
        || limits.maximum_record_bytes > 16 * 1024 * 1024
        || limits.maximum_total_record_bytes < limits.maximum_record_bytes
        || limits.maximum_total_record_bytes > 256 * 1024 * 1024
        || limits.maximum_objects == 0
        || limits.maximum_objects > 65_536
    {
        return Err(refusal("ARM complete native record credit is invalid"));
    }
    Ok(())
}

fn unknown(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: reason.to_owned(),
    }
}
fn uncertainty(error: OperationFailure) -> OperationFailure {
    unknown(&error.reason)
}
