//! Decodes bounded operator-pinned declarations without creating source authority.
//!
//! ```text
//! {schema:"crucible.complete-scene.installation/1", participants:[declaration;3],
//!  measurements:[files;3], host:selection, coordinator:installation,
//!  world:binding, requirements:scenario, content:[{reference,bytes},...],
//!  resources:limits, maximum_initial_bytes:n, maximum_native_rows:n,
//!  maximum_operations:n, maximum_retained_outputs:n, write_watchdog_ms:n}
//! ```
//!
//! Edition seven additionally requires the explicit `maximum_coordinator_records`
//! lifetime policy. The original and fresh Source rosters bind that exact policy;
//! older editions omit the field entirely.

mod mechanism;
pub(super) use mechanism::CompleteMechanism;

use super::*;
use crucible::node_adapters::cnp::CnpSemanticInstallation;
use crucible::node_admission::ScenarioRequirements;
use crucible::node_contract::{FacetKind, HostSchedulingSelection};
use crucible_node_contract::*;
use crucible_node_provider::{
    bodies::RealizeRequest,
    reference_packet::{
        control::PacketNative5StorageSelection,
        coordinator::PacketNative5CoordinatorInstallation,
        service::{
            PacketConnectedSourceProgram, PacketNative5CaptureProfile,
            PacketNative5ProtocolMetadataLimits,
        },
    },
};
use serde::Deserialize;
use std::{
    collections::BTreeMap, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path,
};

const MAXIMUM_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) schema: String,
    #[serde(default)]
    pub(super) mechanism: Option<CompleteMechanism>,
    pub(super) measurements: [Measurement; 3],
    pub(super) participants: [Participant; 3],
    pub(super) host: HostSchedulingSelection,
    pub(super) world: WorldBinding,
    pub(super) requirements: ScenarioRequirements,
    pub(super) coordinator: PacketNative5CoordinatorInstallation,
    pub(super) content: Vec<Content>,
    pub(super) resources: ResourceLimits,
    pub(super) maximum_initial_bytes: usize,
    pub(super) maximum_native_rows: usize,
    pub(super) maximum_operations: usize,
    pub(super) maximum_retained_outputs: usize,
    /// Bounds cumulative coordinator records for the explicit edition-seven World.
    #[serde(default)]
    pub(super) maximum_coordinator_records: Option<usize>,
    pub(super) write_watchdog_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Measurement {
    pub(super) peer: FileSelection,
    pub(super) host: ContentRef,
    pub(super) sources: Vec<FileSelection>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileSelection {
    pub(super) role: String,
    pub(super) path: PathBuf,
    pub(super) content: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Content {
    pub(super) reference: ContentRef,
    pub(super) bytes: Bytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Participant {
    pub(super) installation: NativeSelection,
    pub(super) program: PacketConnectedSourceProgram,
    pub(super) storage: PacketNative5StorageSelection,
    pub(super) capture_profile: PacketNative5CaptureProfile,
    pub(super) protocol_metadata: PacketNative5ProtocolMetadataLimits,
}

// The generic installation intentionally has no decoder. This local declaration
// is not an implementation of any evidence trait; only the concrete compiled
// source constructors below can turn it into a collecting source allocation.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeSelection {
    provider: ProviderManifest,
    profile: NodeManifest,
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    capabilities: CapabilityProfile,
    exact_facet: FacetSelection,
    guarantees: GuaranteeProfile,
    owner: OwnerBinding,
    realize: RealizeRequest,
    admission: Id,
    transaction: Id,
    gate: Id,
    admission_receipt: ContentRef,
    world_binding_hash: HashRef,
    receipt_schema: SchemaRef,
    maximum_operations: usize,
    maximum_result_bytes: usize,
    maximum_authorization_bytes: usize,
    maximum_semantic_bytes: usize,
}

impl NativeSelection {
    pub(super) fn into_source_selection(self) -> CnpSemanticInstallation {
        CnpSemanticInstallation {
            provider: self.provider,
            profile: self.profile,
            descriptor: self.descriptor,
            binding: self.binding,
            capabilities: self.capabilities,
            exact_facet: self.exact_facet,
            guarantees: self.guarantees,
            owner: self.owner,
            realize: self.realize,
            admission: self.admission,
            transaction: self.transaction,
            gate: self.gate,
            admission_receipt: self.admission_receipt,
            world_binding_hash: self.world_binding_hash,
            facets: vec![FacetKind::ExactExecution, FacetKind::Preservation],
            receipt_schema: self.receipt_schema,
            maximum_operations: self.maximum_operations,
            maximum_result_bytes: self.maximum_result_bytes,
            maximum_authorization_bytes: self.maximum_authorization_bytes,
            maximum_semantic_bytes: self.maximum_semantic_bytes,
        }
    }
}

pub(super) fn validate_pin(path: &Path, expected: &ContentRef) -> Result<(), QualificationError> {
    expected.validate()?;
    if !path.is_absolute()
        || expected.length.get() == 0
        || expected.length.get() > MAXIMUM_MANIFEST_BYTES as u64
        || expected.media_type != "application/json"
    {
        return Err(refused());
    }
    Ok(())
}

pub(super) fn load(pin: &InstalledCompleteSceneManifest) -> Result<Manifest, QualificationError> {
    validate_pin(&pin.path, &pin.expected)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&pin.path)
        .map_err(|_| refused())?;
    let before = file.metadata().map_err(|_| refused())?;
    if !before.is_file() || before.len() != pin.expected.length.get() {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAXIMUM_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    pin.expected.verify(&bytes)?;
    let after = file.metadata().map_err(|_| refused())?;
    use std::os::unix::fs::MetadataExt;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
        before.mtime(),
        before.mtime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
        after.mtime(),
        after.mtime_nsec(),
    ) {
        return Err(refused());
    }
    let value = canonical::parse_json(&bytes, MAXIMUM_MANIFEST_BYTES)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(refused());
    }
    mechanism::authenticate_edition_data(&value)?;
    let selected: Manifest =
        serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
    validate_declaration(&selected)?;
    Ok(selected)
}

fn validate_declaration(selected: &Manifest) -> Result<(), QualificationError> {
    selected.resources.validate()?;
    mechanism::authenticate_selection_data(&selected.schema, selected.mechanism)?;
    mechanism::authenticate_profile_declaration_data(selected)?;
    match (
        selected.schema.as_str(),
        selected.maximum_coordinator_records,
    ) {
        ("crucible.complete-scene.installation/7", Some(maximum))
            if maximum >= 2 && u64::try_from(maximum).is_ok() => {}
        ("crucible.complete-scene.installation/7", _) | (_, Some(_)) => return Err(refused()),
        (_, None) => {}
    }
    if selected.content.len() > 128
        || selected.maximum_initial_bytes == 0
        || selected.maximum_initial_bytes > 64 * 1024 * 1024
        || selected.maximum_native_rows == 0
        || selected.maximum_native_rows > 8192
        || selected.maximum_operations == 0
        || selected.maximum_operations > 256
        || selected.maximum_retained_outputs == 0
        || selected.maximum_retained_outputs > 256
        || !(1..=60_000).contains(&selected.write_watchdog_ms)
        || selected.resources.processes.get() < 3
        || selected.resources.descriptors.get() < 11
        || selected.resources.maximum_operations.get() < selected.maximum_operations as u64
        || selected.resources.memory_bytes.get() < selected.maximum_initial_bytes as u64
        || selected.resources.content_bytes.get() < selected.maximum_initial_bytes as u64
    {
        return Err(refused());
    }
    for measurement in &selected.measurements {
        for selected in std::iter::once(&measurement.peer).chain(measurement.sources.iter()) {
            if !selected.path.is_absolute()
                || selected.path.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
                || std::fs::canonicalize(&selected.path).map_err(|_| refused())? != selected.path
                || !std::fs::symlink_metadata(&selected.path)
                    .map_err(|_| refused())?
                    .is_file()
            {
                return Err(refused());
            }
        }
    }
    for participant in &selected.participants {
        participant.storage.validate().map_err(|_| refused())?;
        if !matches!(
            participant.capture_profile,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) {
            return Err(refused());
        }
    }
    Ok(())
}

pub(super) fn content(
    rows: Vec<Content>,
) -> Result<BTreeMap<ContentRef, Vec<u8>>, QualificationError> {
    let mut result = BTreeMap::new();
    let mut total = 0usize;
    for row in rows {
        row.reference.verify(row.bytes.as_slice())?;
        let bytes = row.bytes.as_slice();
        total = total.checked_add(bytes.len()).ok_or_else(refused)?;
        if bytes.len() > 1024 * 1024
            || total > 2 * 1024 * 1024
            || result.contains_key(&row.reference)
        {
            return Err(refused());
        }
        result.insert(row.reference, row.bytes.into_vec());
    }
    Ok(result)
}
