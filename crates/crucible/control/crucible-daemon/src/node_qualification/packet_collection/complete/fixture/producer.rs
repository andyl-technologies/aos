//! Produces measured collecting-scene DATA for ordinary process controls.
//!
//! The input names real independently built executables and eight source files.
//! The output is a closed portable configuration/1 containing logical inputs.
//! It contains no coordinator, Host prepared token, Source, accepted class,
//! runtime witness or activation authority.
//!
//! ```json
//! {"host_executable":"/nix/store/.../bin/crucible",
//!  "peer_executable":"/nix/store/.../bin/crucible-reference-packet-provider",
//!  "sources":{"adapter_source":"/nix/store/.../adapter.rs"},
//!  "resources":{"memory_bytes":"4294967296"},"maximum_coordinator_records":256}
//! ```
//!
//! The example abbreviates the complete eight-role roster and ResourceLimits.
//! The builder writes `configuration.json` into a new directory. A separate
//! measurement invocation pins the finished configuration bytes. The owning
//! actor constructs its genuine Host and coordinator before derived hashes.

use super::super::{fixture_configuration::World, records};
use crate::node_qualification::{PacketFixtureArtifact, PacketFixtureMeasurements};
use crucible_node_format::{ContentRef, ResourceLimits, U64, Validate, canonical};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    error::Error,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Names actual build inputs and the finite collecting policy for one fixture.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteSceneFixtureInputs {
    /// Names the actual later host executable, not this fixture producer.
    pub host_executable: PathBuf,
    /// Names the separately source-built ordinary packet provider executable.
    pub peer_executable: PathBuf,
    /// Maps the exact eight source roles to separately retained original files.
    pub sources: BTreeMap<String, PathBuf>,
    /// Declares the ordinary scene policy, without asserting that it fits.
    pub resources: ResourceLimits,
    /// Bounds actual lifetime coordinator records for the complete7 declaration.
    pub maximum_coordinator_records: usize,
}

type Failure = Box<dyn Error>;
const SOURCE_ROLES: [&str; 8] = [
    "adapter_source",
    "build_closure",
    "contract_source",
    "harness_source",
    "native_source",
    "program_source",
    "provider_source",
    "recipe",
];

/// Writes a canonical portable collecting configuration from real measured files.
///
/// The caller subsequently measures `configuration.json` independently and pins
/// that result in local operational policy. The file contains no prepared Host
/// token or coordinator. Actual closed decoding and local Host/coordinator
/// construction validate the full declaration before this function succeeds.
///
/// # Errors
/// Refuses missing/extra roles, nonoriginal or changing files, invalid policy,
/// invalid compiled declarations, occupied output directories or write failure.
///
/// # Panics
/// Panics if an internal compiled fixture contract or fixed scenario invariant
/// is inconsistent. Runtime file and local policy failures return errors.
pub fn write_complete_scene_fixture(
    inputs: CompleteSceneFixtureInputs,
    output: &Path,
) -> Result<(), Failure> {
    inputs.resources.validate()?;
    if inputs.sources.len() != SOURCE_ROLES.len()
        || !inputs.sources.keys().map(String::as_str).eq(SOURCE_ROLES)
        || inputs.maximum_coordinator_records < 2
        || !output.is_absolute()
    {
        return Err("invalid complete-scene fixture inputs".into());
    }
    let host = measure(&inputs.host_executable, "application/octet-stream", true)?;
    let peer = measure(&inputs.peer_executable, "application/octet-stream", true)?;
    let mut sources = Vec::with_capacity(SOURCE_ROLES.len());
    for role in SOURCE_ROLES {
        let path = &inputs.sources[role];
        sources.push(PacketFixtureArtifact {
            role: role.into(),
            path: path.clone(),
            content: measure(path, "application/octet-stream", false)?,
        });
    }
    let measurements = PacketFixtureMeasurements {
        peer: PacketFixtureArtifact {
            role: "executable".into(),
            path: inputs.peer_executable,
            content: peer.clone(),
        },
        host: host.clone(),
        sources,
    };
    let proof = records::packet_complete_measured_graph_proof(&[
        measurements.clone(),
        measurements.clone(),
        measurements.clone(),
    ])?;
    let mut world = World::with_import18_fixture(peer, host, proof);
    let interpretation = records::packet_complete_independent_graph_contract()?;
    world.content.insert(
        canonical::content_ref(&interpretation, "application/json")?,
        interpretation,
    );
    // The builder has already selected full18 provider and full17 Host definitions;
    // all provider/binding/world/coordinator hashes therefore name those bodies.
    let storage = storage_selection()?;
    let mut participants = Vec::with_capacity(3);
    for member in 0..3 {
        let one = &world.members[member]
            .as_ref()
            .ok_or("missing fixture member")?
            .installation;

        participants.push(serde_json::json!({
            "installation": {
                "provider": one.provider,
                "profile": one.profile,
                "descriptor": one.descriptor,
                "binding": one.binding,
                "capabilities": one.capabilities,
                "exact_facet": one.exact_facet,
                "guarantees": one.guarantees,
                "owner": one.owner,
                "realize": one.realize,
                "admission": one.admission,
                "transaction": one.transaction,
                "gate": one.gate,
                "admission_receipt": one.admission_receipt,
                "world_binding_hash": one.world_binding_hash,
                "receipt_schema": one.receipt_schema,
                "maximum_operations": one.maximum_operations,
                "maximum_result_bytes": one.maximum_result_bytes,
                "maximum_authorization_bytes": one.maximum_authorization_bytes,
                "maximum_semantic_bytes": one.maximum_semantic_bytes
            },
            "program": world.programmes[member],
            "storage": storage,
            "capture_profile":
                crucible_node_transport::reference_packet::service::PacketNative5CaptureProfile::
                    OwnedProtocol11 {
                        native_before_protocol_bytes: U64::new(1024 * 1024),
                        native_after_protocol_bytes: U64::new(1024 * 1024),
                        host_protocol_bytes: U64::new(1024 * 1024)
                    },
            "protocol_metadata":
                crucible_node_transport::reference_packet::service::
                    PacketNative5ProtocolMetadataLimits {
                        native_before_rows: U64::new(8192),
                        native_after_rows: U64::new(8192)
                    }
        }));
    }

    let content: Vec<_> = world
        .content
        .iter()
        .map(|(reference, bytes)| {
            serde_json::json!({
                "reference": reference,
                "bytes": crucible_node_format::Bytes::new(bytes.clone())
            })
        })
        .collect();

    // This assertion compares DATA identities only, never native currentness.
    if world.activation.world_binding_hash != world.world.identity()? {
        return Err("fixture activation differs from its constructed world".into());
    }

    let configuration = serde_json::json!({
        "schema": "crucible.complete-scene.configuration/1",
        "mechanism": "SourceSignedImport18",
        "restoration": {
            "complete_restore": "SourceSignedTransfer12",
            "restore_input_emitter": "CanonicalSdkRestoreInputs12",
            "fresh_restore_allocation": "completed_admit13"
        },
        "measurements": [measurements, measurements, measurements],
        "participants": participants,
        "host": world.host_source.selection(),
        "world": world.world,
        "requirements": world.requirements,
        "content": content,
        "initial": {
            "activation_id": "packet-connected-whole-world-activation",
            "generation": U64::new(1),
            "native_prepared_tokens": [
                "packet-native-prepared-0",
                "packet-native-prepared-1",
                "packet-native-prepared-2"
            ]
        },
        "resources": inputs.resources,
        "maximum_initial_bytes": 64 * 1024 * 1024,
        "maximum_native_rows": 8192,
        "maximum_operations": 64,
        "maximum_retained_outputs": 3,
        "maximum_coordinator_records": inputs.maximum_coordinator_records,
        "write_watchdog_ms": 1000
    });

    // The shared ordinary fixture also constructs its own coordinator DATA.
    // It is never read or used as an input to this portable configuration.
    drop(world.coordinator);
    let bytes = canonical::canonical_json(&configuration)?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    std::fs::create_dir(output)?;
    let path = output.join("configuration.json");
    std::fs::write(&path, bytes)?;
    let pin = super::super::InstalledCompleteSceneManifest::new(path, reference)?;
    super::super::installed::validate_fixture_manifest_data(&pin)?;
    Ok(())
}

fn measure(path: &Path, media_type: &str, executable: bool) -> Result<ContentRef, Failure> {
    if !path.is_absolute() || std::fs::canonicalize(path)? != path {
        return Err("fixture input must be an original absolute path".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > 512 * 1024 * 1024 {
        return Err("fixture input is not a finite regular file".into());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(before.len() + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let facts = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.ctime(),
            m.ctime_nsec(),
            m.mtime(),
            m.mtime_nsec(),
        )
    };
    if facts(&before) != facts(&after)
        || u64::try_from(bytes.len())? != before.len()
        || (executable && (before.mode() & 0o111 == 0 || !bytes.starts_with(b"\x7fELF")))
    {
        return Err("fixture input changed or is not an executable ELF".into());
    }
    Ok(canonical::content_ref(&bytes, media_type)?)
}

fn storage_selection() -> Result<
    crucible_node_transport::reference_packet::control::PacketNative5StorageSelection,
    Failure,
> {
    use crucible_node_transport::{
        handshake::Limits,
        reference_packet::{
            control::PacketNative5StorageSelection, service::PacketNative5StorageLimits,
        },
    };
    let hello_bytes =
        crucible_node_transport::native_hello::OriginalNativeHelloJournal::
            reservation_requested_storage_data(65_536)?;

    Ok(PacketNative5StorageSelection {
        storage: PacketNative5StorageLimits {
            snapshot_bytes: U64::new(65536),
            control_snapshot_bytes: U64::new(65536),
            protocol_snapshot_bytes: U64::new(1024 * 1024),
            frame_bank_bytes: U64::new(1024 * 1024),
            frames_per_direction: U64::new(64),
            hello_bytes: U64::new(u64::try_from(hello_bytes)?),
            settlement_bytes: U64::new(1024 * 1024),
        },
        limits: Limits {
            frame_bytes: U64::new(65536),
            nesting: U64::new(64),
            requests: U64::new(64),
            journal_entries: U64::new(64),
            blob_chunk_bytes: U64::new(4096),
        },
    })
}
