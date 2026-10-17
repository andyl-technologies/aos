//! Reserves complete original failure-retirement source and history before birth.
//!
//! This closed operational record is distinct from a capture or continuation.
//! Exact source definitions stay owned; each independently measured installed
//! artifact is held by its original descriptor. History credit bounds later
//! actual runtime, Host/COW/pending, native prefix/private ACK and reap records.
//! Nothing here certifies those future records or permits supervisor release.
//!
//! ```json
//! {"schema":"crucible.independent-group.failure-retirement-credit.v2",
//!  "source_world":{},"archive_credit":{},"source_members":[]}
//! ```

use std::{collections::BTreeMap, fs::File, os::unix::fs::FileExt};

use crucible_node_contract::{ContentRef, HashRef, Validate, canonical};
use serde::{Serialize, ser::SerializeSeq};

use super::super::super::{InstalledNodeCatalog, NodeObservedError, refused};
use super::profile::IndependentGroupProfile;

mod history;
mod persistence;

pub(in crate::node_observed_executor::factory::native_state) use history::OriginalFailureHistory;
pub(in crate::node_observed_executor::factory::native_state) use persistence::DurableFailureHistory;
pub(in crate::node_observed_executor::factory::native_state) use persistence::DurableFailureSources;

const MAXIMUM_SOURCE_OBJECTS: usize = 20_000;
const MAXIMUM_SOURCE_BODY: usize = 512 * 1024 * 1024;
const MAXIMUM_TOTAL_BYTES: usize = 2 * 1024 * 1024 * 1024;
const RUNTIME_BYTES: usize = 16 * 1024 * 1024;
const HOST_RECORD_BYTES: usize = 16 * 1024 * 1024;
const NATIVE_RECORD_BYTES: usize = 64 * 1024 * 1024;
// Binary history includes nine per-attempt count/flag bytes and its header,
// independently of the already reserved fixed request/reply holders.
const PRIVATE_ACK_BYTES: usize = 65_536 * (2 * 516 + 128 + 9) + 64;
const INDEX_BYTES: usize = 1024 * 1024;
const TERMINAL_BYTES: usize = 256 * 1024;
const HISTORY_ROOTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    SourceDefinition,
    InstalledArtifact,
}

#[derive(Serialize)]
struct Member<'a> {
    reference: &'a ContentRef,
    role: Role,
}

#[derive(Serialize)]
struct CreditRecord<'a> {
    schema: &'static str,
    source_world: &'a HashRef,
    archive_credit: &'a ContentRef,
    source_members: Members<'a>,
    runtime_bytes: usize,
    host_owners: usize,
    host_record_bytes: usize,
    native_record_bytes: usize,
    private_ack_bytes: usize,
    index_bytes: usize,
    source_index_bytes: usize,
    terminal_bytes: usize,
    maximum_history_roots: usize,
    complete_retained_bytes: usize,
}

enum SourceBody {
    Definition { bytes: Vec<u8> },
    Artifact { file: File },
}

struct OriginalMember {
    reference: ContentRef,
    body: SourceBody,
}

/// Keeps exact installed source handles and finite future history credit.
pub(in crate::node_observed_executor::factory::native_state) struct FailureRetirementPreparation {
    world: HashRef,
    archive_credit: ContentRef,
    members: Vec<OriginalMember>,
    reference: ContentRef,
    body: Vec<u8>,
    total_bytes: usize,
}

impl FailureRetirementPreparation {
    pub(in crate::node_observed_executor::factory::native_state) fn reference(
        &self,
    ) -> &ContentRef {
        &self.reference
    }

    pub(in crate::node_observed_executor::factory::native_state) fn reserve(
        profile: &IndependentGroupProfile,
        catalog: &InstalledNodeCatalog,
    ) -> Result<Self, NodeObservedError> {
        if !profile.preserving || profile.scenario.owners.len() != 4 {
            return Err(refused(
                "failure retirement requires the complete original four-owner source",
            ));
        }
        let (_, archive_credit) = profile.archive_credit()?;
        let credit_body = profile
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.credit_body(&archive_credit))
            .ok_or_else(|| refused("original archive credit body is absent"))?;

        // Complete source geometry is charged on borrowed definitions and exact
        // installed references before copying bodies or opening held handles.
        let mut source = BTreeMap::new();
        if profile.scenario.content.len() > MAXIMUM_SOURCE_OBJECTS.saturating_sub(12) {
            return Err(refused(
                "failure-retirement source reference inventory exhausted",
            ));
        }
        for object in &profile.scenario.content {
            object.reference.verify(&object.bytes)?;
            source.insert(
                object.reference.clone(),
                (Role::SourceDefinition, Some(object.bytes.as_slice()), None),
            );
        }
        source.insert(
            archive_credit.clone(),
            (Role::SourceDefinition, Some(credit_body), None),
        );
        for (reference, path) in [
            (&catalog.host_identity, catalog.host_executable.as_path()),
            (
                &catalog.device_identity,
                catalog.device_executable.as_path(),
            ),
        ] {
            insert_artifact(&mut source, reference, path)?;
        }
        let mut artifacts = Vec::new();
        artifacts
            .try_reserve_exact(9)
            .map_err(|error| refused(&error.to_string()))?;
        for name in [
            "native_executable",
            "controller",
            "model",
            "dmtcp_launch",
            "dmtcp_restart",
            "mtcp_restart",
            "image_guard",
            "auditor",
        ] {
            artifacts.push(profile.native.installed.artifact(name)?);
        }
        artifacts.push(profile.native.installed.guest(&profile.native.isa)?);
        for artifact in &artifacts {
            insert_artifact(&mut source, &artifact.content, &artifact.path)?;
        }
        let total_bytes = geometry(
            source.keys().map(|reference| reference.length.get()),
            MAXIMUM_TOTAL_BYTES,
        )?;
        let world = profile.scenario.world.identity()?;
        let record = CreditRecord {
            schema: "crucible.independent-group.failure-retirement-credit.v2",
            source_world: &world,
            archive_credit: &archive_credit,
            source_members: Members(&source),
            runtime_bytes: RUNTIME_BYTES,
            host_owners: 3,
            host_record_bytes: HOST_RECORD_BYTES,
            native_record_bytes: NATIVE_RECORD_BYTES,
            private_ack_bytes: PRIVATE_ACK_BYTES,
            index_bytes: INDEX_BYTES,
            source_index_bytes: INDEX_BYTES,
            terminal_bytes: TERMINAL_BYTES,
            maximum_history_roots: HISTORY_ROOTS,
            complete_retained_bytes: total_bytes,
        };
        // Borrowed counting serializes no body bytes and retains no JSON tree.
        // The subsequent canonical allocation is bounded by this exact index.
        serde_json::to_writer(IndexCredit(INDEX_BYTES), &record)?;
        let body = canonical::canonical_json(&serde_json::to_value(record)?)?;
        if body.len() > INDEX_BYTES {
            return Err(refused(
                "failure-retirement source index exceeds reserved credit",
            ));
        }
        let reference = canonical::content_ref(&body, "application/json")?;
        let mut members = Vec::new();
        members
            .try_reserve_exact(source.len())
            .map_err(|error| refused(&error.to_string()))?;
        for (reference, (_, bytes, path)) in source {
            let body = match (bytes, path) {
                (Some(bytes), None) => SourceBody::Definition {
                    bytes: bytes.to_vec(),
                },
                (None, Some(path)) => {
                    let file = File::open(path).map_err(|error| refused(&error.to_string()))?;
                    authenticate_file(&file, &reference)?;
                    SourceBody::Artifact { file }
                }
                _ => return Err(refused("failure-retirement source role is ambiguous")),
            };
            members.push(OriginalMember { reference, body });
        }
        Ok(Self {
            world,
            archive_credit,
            members,
            reference,
            body,
            total_bytes,
        })
    }

    pub(in crate::node_observed_executor::factory::native_state) fn authenticate(
        &self,
        profile: &IndependentGroupProfile,
    ) -> Result<(), NodeObservedError> {
        if self.world != profile.scenario.world.identity()?
            || profile.archive_credit()?.1 != self.archive_credit
            || self.members.is_empty()
            || self.total_bytes > MAXIMUM_TOTAL_BYTES
        {
            return Err(refused(
                "failure-retirement holder differs from actual selected source",
            ));
        }
        self.reference.verify(&self.body)?;
        // The same owned member bodies/handles remain live through all worker
        // refusal and storage retries. No pathname is reopened after birth.
        for member in &self.members {
            match &member.body {
                SourceBody::Definition { bytes } => member.reference.verify(bytes)?,
                SourceBody::Artifact { file } => {
                    authenticate_file(file, &member.reference)?;
                }
            }
        }
        Ok(())
    }
}

type BorrowedSource<'a> =
    BTreeMap<ContentRef, (Role, Option<&'a [u8]>, Option<&'a std::path::Path>)>;

struct Members<'a>(&'a BorrowedSource<'a>);

impl Serialize for Members<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (reference, (role, _, _)) in self.0 {
            sequence.serialize_element(&Member {
                reference,
                role: *role,
            })?;
        }
        sequence.end()
    }
}

struct IndexCredit(usize);

impl std::io::Write for IndexCredit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.checked_sub(bytes.len()).ok_or_else(|| {
            std::io::Error::other("complete failure-retirement index credit exhausted")
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn insert_artifact<'a>(
    source: &mut BorrowedSource<'a>,
    reference: &ContentRef,
    path: &'a std::path::Path,
) -> Result<(), NodeObservedError> {
    if let Some((role, _, _)) = source.get(reference) {
        if *role != Role::InstalledArtifact {
            return Err(refused(
                "source artifact conflicts with an authored definition role",
            ));
        }
    } else {
        source.insert(
            reference.clone(),
            (Role::InstalledArtifact, None, Some(path)),
        );
    }
    Ok(())
}

fn geometry(
    lengths: impl Iterator<Item = u64>,
    maximum: usize,
) -> Result<usize, NodeObservedError> {
    let mut count = 0usize;
    let mut bytes = RUNTIME_BYTES
        .checked_add(3 * HOST_RECORD_BYTES)
        .and_then(|value| value.checked_add(NATIVE_RECORD_BYTES))
        .and_then(|value| value.checked_add(PRIVATE_ACK_BYTES))
        .and_then(|value| value.checked_add(INDEX_BYTES))
        .and_then(|value| value.checked_add(INDEX_BYTES))
        .and_then(|value| value.checked_add(TERMINAL_BYTES))
        .ok_or_else(|| refused("failure-retirement history credit overflow"))?;
    for length in lengths {
        count = count
            .checked_add(1)
            .ok_or_else(|| refused("failure-retirement source count overflow"))?;
        let length = usize::try_from(length)
            .map_err(|_| refused("failure-retirement source length overflow"))?;
        if count > MAXIMUM_SOURCE_OBJECTS || length > MAXIMUM_SOURCE_BODY {
            return Err(refused(
                "failure-retirement source geometry exceeds selected interface",
            ));
        }
        bytes = bytes
            .checked_add(length)
            .ok_or_else(|| refused("failure-retirement total credit overflow"))?;
    }
    if count == 0 || bytes > maximum || maximum > MAXIMUM_TOTAL_BYTES {
        return Err(refused(
            "complete failure-retirement source/history credit exhausted",
        ));
    }
    Ok(bytes)
}

fn authenticate_file(file: &File, reference: &ContentRef) -> Result<(), NodeObservedError> {
    reference.validate()?;
    if reference.hash.domain != "cnp.blob.v1"
        || reference.hash.algorithm != "blake3-256"
        || !file
            .metadata()
            .map_err(|error| refused(&error.to_string()))?
            .is_file()
        || file
            .metadata()
            .map_err(|error| refused(&error.to_string()))?
            .len()
            != reference.length.get()
    {
        return Err(refused(
            "failure-retirement artifact has another exact source identity",
        ));
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&(reference.hash.domain.len() as u32).to_be_bytes());
    hash.update(reference.hash.domain.as_bytes());
    hash.update(&reference.length.get().to_be_bytes());
    let mut remaining = reference.length.get();
    let mut buffer = [0; 64 * 1024];
    while remaining != 0 {
        let maximum = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|error| refused(&error.to_string()))?;
        let count = file
            .read_at(&mut buffer[..maximum], reference.length.get() - remaining)
            .map_err(|error| refused(&error.to_string()))?;
        if count == 0 {
            return Err(refused(
                "held original artifact ended before exact source length",
            ));
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if file
        .read_at(&mut buffer[..1], reference.length.get())
        .map_err(|error| refused(&error.to_string()))?
        != 0
        || hash.finalize().to_hex().as_str() != reference.hash.digest
    {
        return Err(refused(
            "held original artifact differs from complete installed source",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "failure_retirement_tests.rs"]
mod tests;
