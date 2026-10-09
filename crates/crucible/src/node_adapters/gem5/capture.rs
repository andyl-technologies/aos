//! Backend-bound unchanged native cuts and streamed process-image custody.
//!
//! Native diagnostic summaries remain commitments inside the selected receipt
//! codec. They are not complete typed state nor independent blob access grants.
//! Complete preservation comes from the actual independently audited image and
//! its complete private-resource roster, retained separately from small ledgers.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    rc::Rc,
};

use crucible_node_contract::{ContentRef, Id, SchemaRef, canonical};
use crucible_node_provider::gem5::{
    Gem5CapturedArtifactRole, Gem5CapturedImage, Gem5ExactProfileVerifier, Gem5LaunchArtifact,
    Gem5ProcessClosure,
};
use serde::Serialize;

use crate::{node_contract::*, node_scheduling::InputPayload};

use super::{GEM5_OPAQUE_PRESERVATION_PROFILE, QualifiedGem5Node, node::native_refusal, refusal};

/// Defines the backend-specific small ledger and complete native artifact codec.
pub const GEM5_NATIVE_CONTINUATION_SPECIFICATION: &str = "crucible/gem5-native-continuation-v1: bounded canonical source world activation and original common operation scopes; each actual native Poll prefix and immutable native stdout payload is a separately hash-bound original evidence object; native image and resource files preserve their exact role and relative reconstruction name and stream separately. Source coordinator cut and actual native full-position frontier are distinct when an original operation is pending. Native receipt diagnostic summaries are commitment leaves, not typed completeness claims or blob access authority. Complete state authority requires authentic original parked process capture and independent installed full-process closure. Fresh native incarnation and coordinator permissions are never serialized authority and require installed unchanged-cut restoration and genuine fresh opaque reattachment.";

/// Supplies installed independent capture policy and preallocated private roots.
///
/// The verifier must authenticate a source-owned implemented model and guest
/// policy. Neither operator hashes nor an image filename qualify that policy.
pub struct Gem5ArchiveInstallation {
    /// Measures the actual installed complete-process auditor.
    pub auditor: Gem5LaunchArtifact,
    /// Authenticates known installed native source, model, guest and mediation.
    pub verifier: Rc<dyn Gem5ExactProfileVerifier>,
    /// Contains all actual native runtime, image and archive resource roots.
    pub owned_scope: PathBuf,
    /// Names a canonical private parent reserved for independent captures.
    pub captures_root: PathBuf,
    /// Bounds retained immutable images and original capture retries; at most 64.
    pub maximum_captures: usize,
}

impl Gem5ArchiveInstallation {
    pub(super) fn validate(
        &self,
        native: &crucible_node_provider::gem5::Gem5NativeProcess,
        cap: crucible_node_contract::U64,
    ) -> Result<(), OperationFailure> {
        if self.maximum_captures == 0
            || self.maximum_captures > 64
            || !self.captures_root.starts_with(&self.owned_scope)
            || !native.launch().resource_root.starts_with(&self.owned_scope)
        {
            return Err(refusal(
                "gem5 archive installation lacks a finite complete private scope",
            ));
        }
        for directory in [&self.owned_scope, &self.captures_root] {
            let metadata = std::fs::symlink_metadata(directory)
                .map_err(|error| refusal(&error.to_string()))?;
            if !metadata.is_dir()
                || metadata.mode() & 0o077 != 0
                || std::fs::canonicalize(directory).map_err(|error| refusal(&error.to_string()))?
                    != *directory
            {
                return Err(refusal(
                    "gem5 archive root is not a canonical private directory",
                ));
            }
        }
        self.verifier
            .verify_opaque_profile(native.launch(), &self.auditor)
            .map_err(native_refusal)?;
        self.verifier
            .verify_superdense_mapping(native.launch(), cap)
            .map_err(native_refusal)
    }
}

pub(super) struct RetainedCapture {
    pub source: RuntimeSnapshot,
    pub native: Gem5NativeContinuation,
}

struct CaptureRequest<'a> {
    activation: &'a WorldActivation,
    source: &'a RuntimeSnapshot,
    capture: Id,
    preserved_root: &'a Path,
    owned_scope: &'a Path,
    auditor: &'a Gem5LaunchArtifact,
    verifier: &'a dyn Gem5ExactProfileVerifier,
    limits: NativeCaptureLimits,
}

/// Returns the source-owned native codec identity without issuing capture authority.
///
/// # Errors
/// Returns a portable identity or content construction failure.
pub fn gem5_native_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("crucible/gem5-native-continuation-v1")
            .map_err(|error| refusal(&error.to_string()))?,
        version: 1,
        definition: canonical::content_ref(
            GEM5_NATIVE_CONTINUATION_SPECIFICATION.as_bytes(),
            "text/plain",
        )
        .map_err(|error| refusal(&error.to_string()))?,
        extensions: BTreeMap::new(),
    })
}

/// Retains genuine independently qualified image custody alongside its small codec.
///
/// This value is created only from a live native capture. Imported records cannot
/// construct it, and its source certificate cannot arm a fresh native incarnation.
pub struct Gem5NativeContinuation {
    pub(super) image: Gem5CapturedImage,
    pub(super) closure: Gem5ProcessClosure,
    pub(super) installed: InstalledNativeCapture,
}

impl Gem5NativeContinuation {
    /// Borrows the original genuine native image, including all private resources.
    pub fn image(&self) -> &Gem5CapturedImage {
        &self.image
    }
    /// Borrows independent complete original-cut process closure.
    pub fn closure(&self) -> &Gem5ProcessClosure {
        &self.closure
    }
    /// Borrows streamed archive objects without turning references into authority.
    pub fn installed_capture(&self) -> &InstalledNativeCapture {
        &self.installed
    }
}

#[derive(Serialize)]
struct OperationWire<'a> {
    original: &'a SavedRuntimeOperation,
    prefixes: Vec<ContentRef>,
    prefix_scopes: Vec<super::ledger::PrefixScope>,
}

#[derive(Serialize)]
struct ArtifactWire<'a> {
    role: &'a Id,
    name: &'a str,
    content: &'a ContentRef,
}

impl QualifiedGem5Node {
    pub(super) fn capture_installed(
        &mut self,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        validate_limits(limits)?;
        if self.quarantined || !self.same_world(activation) {
            return Err(refusal(
                "gem5 installed capture has foreign or quarantined native custody",
            ));
        }
        if let Some(previous) = self
            .captures
            .iter()
            .find(|capture| capture.source.capture_ordinal == source.capture_ordinal)
        {
            if previous.source != *source {
                return Err(refusal(
                    "gem5 retry changed the original unchanged-cut capture",
                ));
            }
            return copy_installed(&previous.native.installed, limits);
        }
        let archive = self
            .archive
            .as_ref()
            .ok_or_else(|| refusal("gem5 complete native capture is not installed"))?;
        if self.capture_roots.len() >= archive.maximum_captures {
            return Err(refusal("gem5 native image retention slots exhausted"));
        }
        // The driver owns a bounded 2GiB image, 1GiB resource and 4GiB/capture
        // mechanism. Retaining at most 64 captures bounds native backing at
        // 256GiB; smaller installed capture limits lower that finite ceiling.
        // Smaller archive budgets must fail before generating or copying images.
        if limits.maximum_artifact_bytes < 2 * 1024 * 1024 * 1024
            || limits.maximum_total_artifact_bytes < 4 * 1024 * 1024 * 1024
            || limits.maximum_objects < 8193
        {
            return Err(refusal(
                "gem5 native capture credits are smaller than its installed mechanism bounds",
            ));
        }
        let identity = canonical::json_hash("crucible.gem5.native-capture.v1", &serde_json::json!({"node":self.preparation.route.node,"owners":self.preparation.route.owners,"activation":source.source_activation,"ordinal":source.capture_ordinal}))
            .map_err(|error| refusal(&error.to_string()))?;
        let capture = Id::new(format!("gem5-capture/{}", identity.digest))
            .map_err(|error| refusal(&error.to_string()))?;
        let root = archive.captures_root.join(&identity.digest);
        let owned_scope = archive.owned_scope.clone();
        let auditor = archive.auditor.clone();
        let verifier = Rc::clone(&archive.verifier);
        // Reserve the owning retention entry before any native capture callback.
        // A failed capture keeps this private root and its original native child.
        self.capture_roots
            .try_reserve(1)
            .map_err(|_| refusal("gem5 owning capture root slot allocation refused"))?;
        self.captures
            .try_reserve(1)
            .map_err(|_| refusal("gem5 owning capture seal slot allocation refused"))?;
        self.capture_roots.push(root.clone());
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|error| refusal(&error.to_string()))?;
        let native = self.capture_original_continuation(CaptureRequest {
            activation,
            source,
            capture,
            preserved_root: &root,
            owned_scope: &owned_scope,
            auditor: &auditor,
            verifier: verifier.as_ref(),
            limits,
        })?;
        let installed = copy_installed(&native.installed, limits)?;
        self.captures.push(RetainedCapture {
            source: source.clone(),
            native,
        });
        Ok(installed)
    }

    fn capture_original_continuation(
        &mut self,
        request: CaptureRequest<'_>,
    ) -> Result<Gem5NativeContinuation, OperationFailure> {
        let CaptureRequest {
            activation,
            source,
            capture,
            preserved_root,
            owned_scope,
            auditor,
            verifier,
            limits,
        } = request;
        validate_limits(limits)?;
        if self.quarantined
            || !self.same_world(activation)
            || source.source_activation != SavedRuntimeActivation::from(activation.record())
            || source
                .inputs
                .iter()
                .any(|input| input.node == self.preparation.route.node)
        {
            return Err(refusal(
                "gem5 native capture lacks original closed world and input custody",
            ));
        }
        let own: Vec<_> = source
            .operations
            .iter()
            .filter(|operation| operation.route.node == self.preparation.route.node)
            .collect();
        if own.len() != self.ledger.operations().len() || own.len() > limits.maximum_objects {
            return Err(refusal(
                "gem5 source runtime omitted or invented an original native operation",
            ));
        }
        let mut operations = Vec::new();
        let mut evidence = BTreeMap::new();
        for ((identity, native), saved) in self.ledger.operations().zip(own) {
            let saved_result_matches = match (&saved.result, &native.outcome) {
                (SavedRuntimeResult::Pending, None) => !native.acknowledged,
                (SavedRuntimeResult::Complete(saved), Some(actual)) => {
                    !native.acknowledged && saved == actual
                }
                (SavedRuntimeResult::Acknowledged(saved), Some(actual)) => {
                    native.acknowledged && saved == actual
                }
                _ => false,
            };
            if identity != &saved.operation
                || saved.route != self.preparation.route
                || saved.request != *native.original.request()
                || !self.same_world(native.original.activation())
                || saved.input_batch.is_some()
                || saved.close_submission.is_some()
                || saved.submission_effects.is_some()
                || native.failure.is_some()
                || !saved_result_matches
            {
                return Err(refusal(
                    "gem5 capture changed original native request, prefix, result or ACK scope",
                ));
            }
            let mut prefixes = Vec::new();
            if native.prefixes.len() != native.prefix_scopes.len() {
                return Err(refusal(
                    "gem5 native prefix submission scope inventory is incomplete",
                ));
            }
            for prefix in &native.prefixes {
                self.preparation
                    .native
                    .validate_completion(prefix)
                    .map_err(native_refusal)?;
                let bytes = bounded_canonical(prefix, limits.maximum_record_bytes)?;
                let reference = canonical::content_ref(&bytes, "application/json")
                    .map_err(|error| refusal(&error.to_string()))?;
                if !native
                    .evidence
                    .iter()
                    .any(|object| object.reference == reference && object.bytes == bytes)
                {
                    return Err(refusal(
                        "gem5 capture lost an immutable original Poll receipt",
                    ));
                }
                prefixes.push(reference);
            }
            for object in &native.evidence {
                insert_evidence(&mut evidence, object, limits)?;
            }
            operations.push(OperationWire {
                original: saved,
                prefixes,
                prefix_scopes: native.prefix_scopes.clone(),
            });
        }
        // Capture and independent audit are administrative operations only. The
        // genuine driver proves the exact preexisting event/ACK frontier stayed
        // unchanged, and retains uncertain capture custody on any native failure.
        let image = self
            .preparation
            .native
            .capture(capture, preserved_root)
            .map_err(|error| self.capture_failure(error.to_string()))?;
        let closure = self
            .preparation
            .native
            .qualify_capture(&image, owned_scope, auditor, verifier)
            .map_err(|error| self.capture_failure(error.to_string()))?;
        let (proof, proof_bytes) = closure.evidence();
        insert_evidence(
            &mut evidence,
            &InputPayload {
                reference: proof.clone(),
                bytes: proof_bytes.to_vec(),
            },
            limits,
        )?;
        // The actual opaque image also preserves native administrative prefixes
        // preceding common enrollment. Their original receipts remain explicit.
        for prefix in image.completed_prefixes() {
            let bytes = bounded_canonical(prefix, limits.maximum_record_bytes)?;
            let reference = canonical::content_ref(&bytes, "application/json")
                .map_err(|error| refusal(&error.to_string()))?;
            insert_evidence(&mut evidence, &InputPayload { reference, bytes }, limits)?;
        }
        let mut artifacts = Vec::new();
        let mut artifact_bytes = 0u64;
        for file in image.artifact_inventory() {
            if artifacts
                .len()
                .checked_add(evidence.len())
                .is_none_or(|count| count >= limits.maximum_objects)
            {
                return Err(refusal(
                    "gem5 complete artifact roster exceeds preallocated object credit",
                ));
            }
            let role = match file.role {
                Gem5CapturedArtifactRole::Image => "image",
                Gem5CapturedArtifactRole::Resource => "resource",
            };
            let relative = file
                .relative
                .to_str()
                .ok_or_else(|| refusal("gem5 reconstruction name is not portable text"))?;
            let name = format!("{role}/{relative}");
            let length = file.artifact.content.length.get();
            artifact_bytes = artifact_bytes
                .checked_add(length)
                .filter(|total| {
                    length <= limits.maximum_artifact_bytes
                        && *total <= limits.maximum_total_artifact_bytes
                })
                .ok_or_else(|| {
                    refusal("gem5 complete streamed image/resource bytes exceed credit")
                })?;
            let descriptor =
                File::open(&file.artifact.path).map_err(|error| refusal(&error.to_string()))?;
            artifacts.push(NativeCaptureArtifact::from_file(
                Id::new(role).map_err(|error| refusal(&error.to_string()))?,
                name,
                file.artifact.content.clone(),
                descriptor,
            )?);
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            schema_version: u16,
            source_activation: &'a SavedRuntimeActivation,
            common_cut: crucible_node_contract::Position,
            native_boundary: &'a crucible_node_provider::gem5::Gem5Boundary,
            guest_isa: &'a str,
            source_layout_root: &'a str,
            maximum_microsteps: crucible_node_contract::U64,
            node: &'a Id,
            owners: &'a [OwnerIdentity],
            capture: &'a Id,
            closure: &'a ContentRef,
            operations: Vec<OperationWire<'a>>,
            native_prefixes: Vec<ContentRef>,
            native_pending: Option<&'a Id>,
            native_acknowledged: Option<&'a Id>,
            output_sequence: crucible_node_contract::U64,
            artifacts: Vec<ArtifactWire<'a>>,
        }
        let native_prefixes = image
            .completed_prefixes()
            .map(|prefix| {
                let bytes = bounded_canonical(prefix, limits.maximum_record_bytes)?;
                canonical::content_ref(&bytes, "application/json")
                    .map_err(|error| refusal(&error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let wire =
            Wire {
                schema_version: 1,
                source_activation: &source.source_activation,
                common_cut: source.capture_cut,
                native_boundary: image.boundary(),
                guest_isa: &image.source().guest_isa,
                // DMTCP stores original native filenames inside its opaque image.
                // This spelling is only an authenticated reconstruction mapping
                // hint; it never authorizes opening an old source-host path.
                source_layout_root: image.source().resource_root.to_str().ok_or_else(|| {
                    refusal("gem5 original native layout root is not portable text")
                })?,
                maximum_microsteps: self.authority.maximum_microsteps(),
                node: &self.preparation.route.node,
                owners: &self.preparation.route.owners,
                capture: image.capture_id(),
                closure: proof,
                operations,
                native_prefixes,
                native_pending: image.pending_completion().map(|prefix| &prefix.operation),
                native_acknowledged: image.last_acknowledged(),
                output_sequence: self.sequence.into(),
                artifacts: artifacts
                    .iter()
                    .map(|artifact| ArtifactWire {
                        role: artifact.role(),
                        name: artifact.name(),
                        content: artifact.reference(),
                    })
                    .collect(),
            };
        let bytes = bounded_canonical(&wire, limits.maximum_record_bytes)?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| refusal(&error.to_string()))?;
        let total = evidence.values().try_fold(bytes.len(), |total, object| {
            total
                .checked_add(object.bytes.len())
                .filter(|total| *total <= limits.maximum_total_record_bytes)
                .ok_or_else(|| {
                    refusal("gem5 complete small capture objects exceed preallocated byte credit")
                })
        })?;
        if total > limits.maximum_total_record_bytes {
            return Err(refusal(
                "gem5 native state object exceeds total capture credit",
            ));
        }
        let installed = InstalledNativeCapture {
            owner: self.preparation.route.owners[0].owner.clone(),
            participants: vec![self.preparation.route.node.clone()],
            key: NativeStateKey {
                implementation: self
                    .preparation
                    .binding
                    .compatibility
                    .implementation
                    .implementation_id
                    .clone(),
                profile: Id::new(GEM5_OPAQUE_PRESERVATION_PROFILE)
                    .map_err(|error| refusal(&error.to_string()))?,
                schema: gem5_native_continuation_schema()?,
            },
            cut: source.capture_cut,
            state: InputPayload { reference, bytes },
            evidence: evidence.into_values().collect(),
            artifacts,
        };
        Ok(Gem5NativeContinuation {
            image,
            closure,
            installed,
        })
    }

    fn capture_failure(&mut self, reason: String) -> OperationFailure {
        self.quarantine_resources();
        OperationFailure {
            effects: EffectKnowledge::Unknown,
            reason,
        }
    }
}

fn copy_installed(
    source: &InstalledNativeCapture,
    limits: NativeCaptureLimits,
) -> Result<InstalledNativeCapture, OperationFailure> {
    let records = std::iter::once(&source.state).chain(&source.evidence);
    let mut bytes = 0usize;
    for record in records {
        bytes = bytes
            .checked_add(record.bytes.len())
            .filter(|bytes| {
                *bytes <= limits.maximum_total_record_bytes
                    && record.bytes.len() <= limits.maximum_record_bytes
            })
            .ok_or_else(|| refusal("gem5 retained capture retry exceeds record credit"))?;
    }
    let mut total = 0u64;
    for artifact in &source.artifacts {
        total = total
            .checked_add(artifact.reference().length.get())
            .filter(|total| {
                *total <= limits.maximum_total_artifact_bytes
                    && artifact.reference().length.get() <= limits.maximum_artifact_bytes
            })
            .ok_or_else(|| refusal("gem5 retained capture retry exceeds artifact credit"))?;
    }
    if source
        .artifacts
        .len()
        .checked_add(source.evidence.len())
        .and_then(|count| count.checked_add(1))
        .is_none_or(|count| count > limits.maximum_objects)
    {
        return Err(refusal("gem5 retained capture retry exceeds object credit"));
    }
    Ok(InstalledNativeCapture {
        owner: source.owner.clone(),
        participants: source.participants.clone(),
        key: source.key.clone(),
        cut: source.cut,
        state: source.state.clone(),
        evidence: source.evidence.clone(),
        artifacts: source.artifacts.clone(),
    })
}

fn validate_limits(limits: NativeCaptureLimits) -> Result<(), OperationFailure> {
    if limits.maximum_record_bytes == 0
        || limits.maximum_record_bytes > 16 * 1024 * 1024
        || limits.maximum_total_record_bytes == 0
        || limits.maximum_total_record_bytes > 256 * 1024 * 1024
        || limits.maximum_objects == 0
        || limits.maximum_objects > 65_536
        || limits.maximum_artifact_bytes == 0
        || limits.maximum_total_artifact_bytes == 0
    {
        return Err(refusal(
            "gem5 native capture requires finite preallocated object and byte credits",
        ));
    }
    Ok(())
}

fn insert_evidence(
    objects: &mut BTreeMap<ContentRef, InputPayload>,
    object: &InputPayload,
    limits: NativeCaptureLimits,
) -> Result<(), OperationFailure> {
    object
        .reference
        .verify(&object.bytes)
        .map_err(|error| refusal(&error.to_string()))?;
    if objects.contains_key(&object.reference) {
        return Ok(());
    }
    let current = objects.values().try_fold(0usize, |total, value| {
        total
            .checked_add(value.bytes.len())
            .ok_or_else(|| refusal("gem5 native evidence byte overflow"))
    })?;
    if objects.len() >= limits.maximum_objects
        || object.bytes.len() > limits.maximum_record_bytes
        || current
            .checked_add(object.bytes.len())
            .is_none_or(|size| size > limits.maximum_total_record_bytes)
    {
        return Err(refusal(
            "gem5 native evidence exceeds preallocated capture credit",
        ));
    }
    objects.insert(object.reference.clone(), object.clone());
    Ok(())
}

fn bounded_canonical(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, OperationFailure> {
    let mut count = CountWriter { remaining: maximum };
    serde_json::to_writer(&mut count, value).map_err(|error| refusal(&error.to_string()))?;
    let value = serde_json::to_value(value).map_err(|error| refusal(&error.to_string()))?;
    let bytes = canonical::canonical_json(&value).map_err(|error| refusal(&error.to_string()))?;
    if bytes.len() > maximum {
        return Err(refusal(
            "gem5 native canonical object exceeds preallocation credit",
        ));
    }
    Ok(bytes)
}

struct CountWriter {
    remaining: usize,
}

impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("gem5 native object exceeds preallocation credit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_record_credit_is_checked_before_value_buffering() {
        let value = serde_json::json!({"body":"a".repeat(1024)});
        assert!(bounded_canonical(&value, 1024).is_err());
        assert_eq!(
            bounded_canonical(&value, 2048).unwrap(),
            canonical::canonical_json(&value).unwrap()
        );
    }
}
