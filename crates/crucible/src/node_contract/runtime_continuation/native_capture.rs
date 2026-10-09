//! Installed native capture seals and bounded descriptor-backed artifact streams.
//!
//! Native metadata contains only backend/schema identities and content references.
//! Large image bytes remain under owned file descriptors and are copied through
//! bounded streams. Neither native pointers nor installation paths are wire data.

use std::{
    fs::File,
    io::{self, Read},
    os::unix::fs::FileExt,
    sync::Arc,
};

use crucible_node_contract::{
    ContentRef, Id, NodeBinding, NodeDescriptor, Position, SchemaRef, Validate,
};
use serde::{Deserialize, Serialize};

use super::*;

/// Bounds one unchanged-cut native capture before allocating retained metadata.
#[derive(Clone, Copy, Debug)]
pub struct NativeCaptureLimits {
    /// Bounds each complete small native ledger and receipt object.
    pub maximum_record_bytes: usize,
    /// Bounds all distinct small native objects retained by the world.
    pub maximum_total_record_bytes: usize,
    /// Bounds the complete native object and artifact inventory.
    pub maximum_objects: usize,
    /// Bounds each separately streamed native image or resource file.
    pub maximum_artifact_bytes: u64,
    /// Bounds all separately streamed files across the complete world.
    pub maximum_total_artifact_bytes: u64,
}

/// Keys native state to its actual implementation, installed profile and codec.
///
/// ```json
/// {"implementation":"gem5/native-process-v1","profile":"installed/exact",
///  "schema":{"id":"native/codec","version":1,"schema_hash":{}}}
/// ```
/// The abbreviated schema hash denotes the complete public hash record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeStateKey {
    /// Names the actual backend implementation selected by the sealed binding.
    pub implementation: Id,
    /// Names the independently qualified native preservation profile.
    pub profile: Id,
    /// Binds the complete selected native continuation codec.
    pub schema: SchemaRef,
}

/// Retains one original artifact through an owned, authenticated file descriptor.
///
/// The handle retains verified data, rather than capture authority. Logical
/// names are checked relative reconstruction names; absolute host paths never
/// become identities. Installed adapters separately seal actual native custody.
#[derive(Clone)]
pub struct NativeCaptureArtifact {
    role: Id,
    name: String,
    reference: ContentRef,
    file: Arc<File>,
}

impl NativeCaptureArtifact {
    /// Retains verified file bytes as data without issuing capture authority.
    ///
    /// The installed native adapter must separately authenticate ownership and
    /// complete state coverage before placing this artifact in a capture seal.
    ///
    /// # Errors
    /// Refuses unsafe reconstruction names, nonregular files, changed byte
    /// geometry, unreadable content or a complete digest mismatch.
    pub fn from_file(
        role: Id,
        name: String,
        reference: ContentRef,
        file: File,
    ) -> Result<Self, OperationFailure> {
        reference.validate().map_err(failure)?;
        validate_name(&name)?;
        let metadata = file.metadata().map_err(failure)?;
        if !metadata.is_file() || metadata.len() != reference.length.get() {
            return Err(failure(
                "native artifact descriptor type or geometry differs",
            ));
        }
        let artifact = Self {
            role,
            name,
            reference,
            file: Arc::new(file),
        };
        artifact.verify()?;
        Ok(artifact)
    }

    /// Returns the installed role of this native preservation artifact.
    pub fn role(&self) -> &Id {
        &self.role
    }

    /// Returns its checked relative reconstruction name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the complete authenticated byte identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Opens an independent bounded reader without allocating the complete file.
    pub fn reader(&self) -> impl Read + '_ {
        ArtifactReader {
            file: &self.file,
            position: 0,
            length: self.reference.length.get(),
        }
    }

    /// Verifies complete current bytes under the original descriptor custody.
    ///
    /// # Errors
    /// Refuses changed length, unreadable bytes, early EOF or a digest mismatch.
    pub fn verify(&self) -> Result<(), OperationFailure> {
        if self.file.metadata().map_err(failure)?.len() != self.reference.length.get() {
            return Err(failure(
                "native artifact changed length under retained custody",
            ));
        }
        let mut reader = self.reader();
        let digest = hash_stream(&mut reader, self.reference.length.get()).map_err(failure)?;
        if digest != self.reference.hash.digest
            || self.file.metadata().map_err(failure)?.len() != self.reference.length.get()
        {
            return Err(failure("native artifact changed under retained custody"));
        }
        Ok(())
    }
}

struct ArtifactReader<'a> {
    file: &'a File,
    position: u64,
    length: u64,
}

impl Read for ArtifactReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .length
            .checked_sub(self.position)
            .ok_or_else(|| io::Error::other("native artifact reader escaped its byte cut"))?;
        let count = usize::try_from(remaining.min(bytes.len() as u64))
            .map_err(|_| io::Error::other("native artifact read length overflow"))?;
        if count == 0 {
            return Ok(0);
        }
        let read = self.file.read_at(&mut bytes[..count], self.position)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "native artifact truncated",
            ));
        }
        self.position = self
            .position
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("native artifact reader offset overflow"))?;
        Ok(read)
    }
}

pub(crate) fn hash_stream(reader: &mut dyn Read, length: u64) -> io::Result<String> {
    // The framing is exactly canonical::hash("cnp.blob.v1", bytes), without a
    // whole-image allocation. Keep this implementation covered by known vectors.
    let domain = b"cnp.blob.v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&(domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    hasher.update(&length.to_be_bytes());
    let mut remaining = length;
    let mut buffer = [0u8; 64 * 1024];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("native stream length overflow"))?;
        reader.read_exact(&mut buffer[..count])?;
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut excess = [0u8; 1];
    if reader.read(&mut excess)? != 0 {
        return Err(io::Error::other(
            "native stream exceeds its original byte cut",
        ));
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub(crate) fn validate_name(name: &str) -> Result<(), OperationFailure> {
    if name.is_empty()
        || name.len() > 4096
        || name.contains('\\')
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || name.bytes().any(|byte| !(0x20..=0x7e).contains(&byte))
    {
        return Err(failure(
            "native artifact reconstruction name is not a bounded relative name",
        ));
    }
    Ok(())
}

/// Seals a genuine installed native owner capture without granting execution.
///
/// Construction is restricted to installed adapters in this crate. Provider
/// descriptors, image filenames and content hashes cannot create this seal.
pub struct InstalledNativeCapture {
    pub(crate) owner: Id,
    pub(crate) participants: Vec<Id>,
    pub(crate) key: NativeStateKey,
    pub(crate) cut: Position,
    pub(crate) state: InputPayload,
    pub(crate) evidence: Vec<InputPayload>,
    pub(crate) artifacts: Vec<NativeCaptureArtifact>,
}

impl InstalledNativeCapture {
    /// Returns the authoritative owner captured exactly once.
    pub fn owner(&self) -> &Id {
        &self.owner
    }

    /// Borrows the complete original participant roster sharing this owner.
    pub fn participants(&self) -> &[Id] {
        &self.participants
    }

    /// Returns the backend-bound installed continuation identity.
    pub fn key(&self) -> &NativeStateKey {
        &self.key
    }

    /// Returns the unchanged common coordinator capture cut.
    ///
    /// A pending original prefix may have a later parked native cursor. Its
    /// native codec must preserve that actual cursor and the original grant
    /// lineage separately; capture never drains work to align the cursors.
    pub fn cut(&self) -> Position {
        self.cut
    }

    /// Borrows the bounded complete native ledger metadata.
    pub fn state(&self) -> &InputPayload {
        &self.state
    }

    /// Borrows original small receipt and payload evidence under custody.
    pub fn evidence(&self) -> &[InputPayload] {
        &self.evidence
    }

    /// Borrows retained large native image and resource streams.
    pub fn artifacts(&self) -> &[NativeCaptureArtifact] {
        &self.artifacts
    }

    pub(crate) fn from_host(
        host: HostNativeCapture,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
        cut: Position,
    ) -> Result<Self, OperationFailure> {
        let schema = binding
            .compatibility
            .implementation
            .formats
            .iter()
            .find(|schema| {
                schema.id.as_str() == "host/native-continuation-v1" && schema.version == 1
            })
            .ok_or_else(|| failure("installed host native continuation schema absent"))?
            .clone();
        if host.node != descriptor.id
            || host.profile.as_str() != crate::node_adapters::HOST_EXACT_PROFILE
            || binding.compatibility.capture_owner.participant_ids != vec![host.node.clone()]
        {
            return Err(failure(
                "host capture cannot qualify another native backend or shared owner",
            ));
        }
        Ok(Self {
            owner: binding.compatibility.capture_owner.id.clone(),
            participants: vec![host.node],
            key: NativeStateKey {
                implementation: binding
                    .compatibility
                    .implementation
                    .implementation_id
                    .clone(),
                profile: host.profile,
                schema,
            },
            cut,
            state: host.state,
            evidence: host.evidence,
            artifacts: Vec::new(),
        })
    }
}

impl NodeRuntime {
    /// Captures each authoritative native owner once at an authenticated world cut.
    ///
    /// The actual native hook must retain latent original prefixes and its
    /// stopped native cursor without executing work to match coordinator time.
    /// This read issues no archive signature or fresh execution authority.
    ///
    /// # Errors
    /// Refuses foreign activation or source ledgers, unsupported native codecs,
    /// incomplete participant ownership, changed state or finite limit excess.
    pub fn capture_installed_native(
        &mut self,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &WorldActivation,
        source: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<Vec<InstalledNativeCapture>, RuntimePollFailure> {
        self.validate_activation(activation)
            .map_err(RuntimePollFailure::Admission)?;
        if graph.world_binding_hash() != &source.source_activation.world_binding_hash
            || self
                .runtime_snapshot(
                    source.capture_cut,
                    source.capture_ordinal,
                    limits.maximum_record_bytes,
                )
                .map_err(RuntimePollFailure::Admission)?
                != *source
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        let mut captures = Vec::new();
        captures
            .try_reserve_exact(graph.ownership_policy().capture_owners.len())
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(graph.ownership_policy().capture_owners.len())
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        for policy in &graph.ownership_policy().capture_owners {
            let participants: Vec<_> = graph
                .node_ids()
                .filter(|node| {
                    graph.binding(node).is_some_and(|binding| {
                        binding.compatibility.capture_owner.id == policy.owner_id
                    })
                })
                .cloned()
                .collect();
            let representative = participants
                .first()
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
            // The selected representative must positively attest the complete
            // shared-owner roster. Selection alone never establishes ownership.
            for participant in &participants {
                let binding = graph
                    .binding(participant)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
                let node = self
                    .nodes
                    .get(participant)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
                if binding.compatibility.capture_owner.participant_ids != participants
                    || binding.compatibility.implementation.formats.is_empty()
                    || binding.compatibility.operating_contract.facets.is_empty()
                    || node.binding() != binding
                    || graph.descriptor(participant) != Some(node.descriptor())
                {
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
                if !node.thread_affinity().permits_current_thread() {
                    return Err(RuntimePollFailure::Admission(RuntimeError::ThreadAffinity));
                }
            }
            groups.push((
                policy.owner_id.clone(),
                representative.clone(),
                participants,
            ));
        }

        let mut remaining = limits;
        for (owner, representative, participants) in groups {
            // Every capture contains at least its native state object. Refuse
            // exhausted world credits before entering another native hook.
            if remaining.maximum_objects == 0 {
                return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
            }
            remaining.maximum_record_bytes = remaining
                .maximum_record_bytes
                .min(remaining.maximum_total_record_bytes);
            remaining.maximum_artifact_bytes = remaining
                .maximum_artifact_bytes
                .min(remaining.maximum_total_artifact_bytes);
            let node = self
                .nodes
                .get_mut(&representative)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            let captured = node
                .capture_native_continuation(activation, source, remaining)
                .map_err(RuntimePollFailure::Native)?;
            if captured.owner != owner
                || captured.participants != participants
                || captured.cut != source.capture_cut
            {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            let mut bytes = 0usize;
            let mut artifacts = 0u64;
            let mut objects = 0usize;
            for participant in &participants {
                let binding = graph
                    .binding(participant)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
                if captured.key.implementation
                    != binding.compatibility.implementation.implementation_id
                    || !binding
                        .compatibility
                        .operating_contract
                        .facets
                        .iter()
                        .any(|facet| facet.id == captured.key.profile)
                    || !binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(&captured.key.schema)
                {
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
            }
            for object in std::iter::once(&captured.state).chain(&captured.evidence) {
                if object.bytes.len() > remaining.maximum_record_bytes {
                    return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
                }
                object
                    .reference
                    .verify(&object.bytes)
                    .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
                bytes = bytes
                    .checked_add(object.bytes.len())
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
                objects = objects
                    .checked_add(1)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            }
            let mut names = std::collections::BTreeSet::new();
            for artifact in &captured.artifacts {
                if artifact.reference.length.get() > remaining.maximum_artifact_bytes
                    || !names.insert((artifact.role.clone(), artifact.name.clone()))
                {
                    return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
                }
                artifact.verify().map_err(RuntimePollFailure::Native)?;
                artifacts = artifacts
                    .checked_add(artifact.reference.length.get())
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
                objects = objects
                    .checked_add(1)
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            }
            remaining.maximum_total_record_bytes = remaining
                .maximum_total_record_bytes
                .checked_sub(bytes)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            remaining.maximum_objects = remaining
                .maximum_objects
                .checked_sub(objects)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            remaining.maximum_total_artifact_bytes = remaining
                .maximum_total_artifact_bytes
                .checked_sub(artifacts)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            captures.push(captured);
        }
        if self
            .runtime_snapshot(
                source.capture_cut,
                source.capture_ordinal,
                limits.maximum_record_bytes,
            )
            .map_err(RuntimePollFailure::Admission)?
            != *source
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        Ok(captures)
    }
}

fn failure(error: impl std::fmt::Display) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: error.to_string(),
    }
}
