//! Places exact prebirth source bytes under direct durable member roots.
//!
//! Every member is an independently selected definition or held installed file.
//! A root exists for each body, so collection needs no inferred JSON edges.
//! The small closed index correlates those roots and supplies no native authority.
//! Actual complete reads reauthenticate both CAS identity and full CNP content.
//!
//! ```json
//! {"schema":"crucible.independent-group.failed-source-index.v1",
//!  "credit":{},"members":[{"reference":{},"identity":"trace.1.digest"}]}
//! ```

use std::{
    io::{Cursor, Read},
    sync::Arc,
};

use crucible_cas::content_store::{
    BlobHandle, BlobSource, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind,
    RefCasOutcome, RefName, StoreError,
};
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Serialize)]
struct Mapping {
    reference: ContentRef,
    identity: String,
}

#[derive(Serialize)]
struct Index<'a> {
    schema: &'static str,
    credit: &'a ContentRef,
    members: &'a [Mapping],
}

/// Keeps the exact originally published source roots without granting release.
pub(in crate::node_observed_executor::factory::native_state) struct DurableFailureSources {
    execution: String,
    members: Vec<Mapping>,
    body: Vec<u8>,
    identity: ContentId,
}

impl DurableFailureSources {
    pub(in crate::node_observed_executor::factory::native_state) fn reference(
        &self,
    ) -> Result<ContentRef, NodeObservedError> {
        canonical::content_ref(&self.body, "application/json").map_err(Into::into)
    }
}

/// Owns the exact original operational history roots without cleanup permission.
pub(in crate::node_observed_executor::factory::native_state) struct DurableFailureHistory {
    execution: String,
    members: Vec<Mapping>,
}

impl FailureRetirementPreparation {
    pub(in crate::node_observed_executor::factory::native_state) fn persist_terminal(
        &self,
        source: &DurableFailureSources,
        history: &OriginalFailureHistory,
        terminal: &[crucible::node_scheduling::InputPayload],
        blobs: &dyn ImmutableBlobBackend,
        refs: &dyn MutableRefBackend,
    ) -> Result<DurableFailureHistory, NodeObservedError> {
        self.authenticate_durable_sources(source, blobs, refs)?;
        if terminal.len() != 2 || history.objects().count() + terminal.len() + 1 > HISTORY_ROOTS {
            return Err(refused(
                "original terminal proof exceeds its prebirth root credit",
            ));
        }
        let mut members = Vec::new();
        members.try_reserve_exact(terminal.len()).map_err(error)?;
        let _publication = refs.acquire_publication_guard().map_err(error)?;
        for original in terminal {
            if original.bytes.len() > 64 * 1024 {
                return Err(refused(
                    "original terminal proof exceeds fixed record credit",
                ));
            }
            original.reference.verify(&original.bytes)?;
            let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &original.bytes);
            blobs
                .put_if_absent(identity, &BlobHandle::from_bytes(original.bytes.clone()))
                .map_err(error)?;
            place_root(refs, &history_root(&source.execution, identity)?, identity)?;
            authenticate_body(blobs, identity, &original.reference)?;
            members.push(Mapping {
                reference: original.reference.clone(),
                identity: identity.encode(),
            });
        }
        Ok(DurableFailureHistory {
            execution: source.execution.clone(),
            members,
        })
    }

    pub(in crate::node_observed_executor::factory::native_state) fn authenticate_terminal(
        &self,
        source: &DurableFailureSources,
        original: &[crucible::node_scheduling::InputPayload],
        retained: &DurableFailureHistory,
        blobs: &dyn ImmutableBlobBackend,
        refs: &dyn MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        self.authenticate_durable_sources(source, blobs, refs)?;
        if original.len() != 2
            || retained.execution != source.execution
            || retained.members.len() != original.len()
        {
            return Err(refused("original terminal complete roster differs"));
        }
        for (mapping, actual) in retained.members.iter().zip(original) {
            let identity = ContentId::parse(&mapping.identity).map_err(error)?;
            if mapping.reference != actual.reference
                || identity != ContentId::for_bytes(ObjectKind::Trace, 1, &actual.bytes)
                || refs
                    .read_ref(&history_root(&source.execution, identity)?)
                    .map_err(error)?
                    != Some(identity)
            {
                return Err(refused("same original durable terminal body differs"));
            }
            authenticate_body(blobs, identity, &actual.reference)?;
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::factory::native_state) fn persist_sources(
        &self,
        execution: &str,
        blobs: &dyn ImmutableBlobBackend,
        refs: &dyn MutableRefBackend,
    ) -> Result<DurableFailureSources, NodeObservedError> {
        if !refs.capabilities().durable || !blobs.capabilities().durable {
            return Err(refused("prebirth failure source requires durable storage"));
        }
        // Per-world geometry is finite independently of lifetime persistent
        // roots. The shared quota below never recycles original history cells.
        if self.members.len() > 4096 {
            return Err(refused("prebirth direct source-root credit exhausted"));
        }
        reserve_roots(
            blobs,
            refs,
            self.members
                .len()
                .checked_add(2 + HISTORY_ROOTS)
                .ok_or_else(|| refused("original source-root count overflow"))?,
        )?;
        let mut members = Vec::new();
        members
            .try_reserve_exact(self.members.len() + 1)
            .map_err(error)?;
        let _publication = refs.acquire_publication_guard().map_err(error)?;
        for original in &self.members {
            let source: Arc<dyn BlobSource> = match &original.body {
                SourceBody::Definition { bytes } => {
                    original.reference.verify(bytes)?;
                    Arc::new(DefinitionSource(Arc::from(bytes.as_slice())))
                }
                SourceBody::Artifact { file } => {
                    authenticate_file(file, &original.reference)?;
                    Arc::new(OriginalFileSource {
                        file: Arc::new(file.try_clone().map_err(error)?),
                        length: original.reference.length.get(),
                    })
                }
            };
            let identity =
                ContentId::for_source(ObjectKind::Trace, 1, source.as_ref()).map_err(error)?;
            blobs
                .put_if_absent(identity, &BlobHandle::new(source))
                .map_err(error)?;
            place_root(refs, &member_root(execution, identity)?, identity)?;
            authenticate_body(blobs, identity, &original.reference)?;
            members.push(Mapping {
                reference: original.reference.clone(),
                identity: identity.encode(),
            });
        }
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &self.body);
        blobs
            .put_if_absent(identity, &BlobHandle::from_bytes(self.body.clone()))
            .map_err(error)?;
        place_root(refs, &member_root(execution, identity)?, identity)?;
        authenticate_body(blobs, identity, &self.reference)?;
        members.push(Mapping {
            reference: self.reference.clone(),
            identity: identity.encode(),
        });
        let index = Index {
            schema: "crucible.independent-group.failed-source-index.v1",
            credit: &self.reference,
            members: &members,
        };
        serde_json::to_writer(IndexCredit(INDEX_BYTES), &index)?;
        let body = canonical::canonical_json(&serde_json::to_value(index)?)?;
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &body);
        blobs
            .put_if_absent(identity, &BlobHandle::from_bytes(body.clone()))
            .map_err(error)?;
        place_root(refs, &index_root(execution)?, identity)?;
        Ok(DurableFailureSources {
            execution: execution.to_owned(),
            members,
            body,
            identity,
        })
    }

    pub(in crate::node_observed_executor::factory::native_state) fn authenticate_durable_sources(
        &self,
        original: &DurableFailureSources,
        blobs: &dyn ImmutableBlobBackend,
        refs: &dyn MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        if original.members.len() != self.members.len() + 1
            || refs
                .read_ref(&index_root(&original.execution)?)
                .map_err(error)?
                != Some(original.identity)
            || blobs
                .read(original.identity, None)
                .map_err(error)?
                .read_all(INDEX_BYTES as u64)
                .map_err(error)?
                != original.body
        {
            return Err(refused("durable original failure-source index differs"));
        }
        for (mapping, expected) in original.members.iter().zip(
            self.members
                .iter()
                .map(|member| &member.reference)
                .chain(std::iter::once(&self.reference)),
        ) {
            let identity = ContentId::parse(&mapping.identity).map_err(error)?;
            if &mapping.reference != expected
                || refs
                    .read_ref(&member_root(&original.execution, identity)?)
                    .map_err(error)?
                    != Some(identity)
            {
                return Err(refused("durable original failure-source member differs"));
            }
            authenticate_body(blobs, identity, expected)?;
        }
        Ok(())
    }

    pub(in crate::node_observed_executor::factory::native_state) fn persist_history(
        &self,
        source: &DurableFailureSources,
        original: &OriginalFailureHistory,
        blobs: &dyn ImmutableBlobBackend,
        refs: &dyn MutableRefBackend,
    ) -> Result<DurableFailureHistory, NodeObservedError> {
        self.authenticate_durable_sources(source, blobs, refs)?;
        let count = original.objects().count();
        if count == 0 || count > HISTORY_ROOTS {
            return Err(refused(
                "original operational history exceeds prebirth root credit",
            ));
        }
        // All future direct roots were charged alongside source roots before
        // native birth. Original partial placements reconcile identical bodies;
        // no quota or dispatch permission is minted after original effects.
        let mut members = Vec::new();
        members.try_reserve_exact(count).map_err(error)?;
        let _publication = refs.acquire_publication_guard().map_err(error)?;
        for original in original.objects() {
            original.reference.verify(&original.bytes)?;
            let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &original.bytes);
            blobs
                .put_if_absent(identity, &BlobHandle::from_bytes(original.bytes.clone()))
                .map_err(error)?;
            place_root(refs, &history_root(&source.execution, identity)?, identity)?;
            authenticate_body(blobs, identity, &original.reference)?;
            members.push(Mapping {
                reference: original.reference.clone(),
                identity: identity.encode(),
            });
        }
        Ok(DurableFailureHistory {
            execution: source.execution.clone(),
            members,
        })
    }

    pub(in crate::node_observed_executor::factory::native_state) fn authenticate_durable_history(
        &self,
        source: &DurableFailureSources,
        original: &OriginalFailureHistory,
        retained: &DurableFailureHistory,
        blobs: &dyn ImmutableBlobBackend,
        refs: &dyn MutableRefBackend,
    ) -> Result<(), NodeObservedError> {
        self.authenticate_durable_sources(source, blobs, refs)?;
        if retained.execution != source.execution
            || retained.members.len() != original.objects().count()
        {
            return Err(refused(
                "durable original history scope or complete roster differs",
            ));
        }
        for (mapping, actual) in retained.members.iter().zip(original.objects()) {
            let identity = ContentId::parse(&mapping.identity).map_err(error)?;
            if mapping.reference != actual.reference
                || identity != ContentId::for_bytes(ObjectKind::Trace, 1, &actual.bytes)
                || refs
                    .read_ref(&history_root(&retained.execution, identity)?)
                    .map_err(error)?
                    != Some(identity)
            {
                return Err(refused("durable original history member differs"));
            }
            authenticate_body(blobs, identity, &mapping.reference)?;
        }
        Ok(())
    }
}

struct DefinitionSource(Arc<[u8]>);

impl BlobSource for DefinitionSource {
    fn logical_length(&self) -> u64 {
        self.0.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(Cursor::new(self.0.clone())))
    }
}

struct OriginalFileSource {
    file: Arc<File>,
    length: u64,
}

impl BlobSource for OriginalFileSource {
    fn logical_length(&self) -> u64 {
        self.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(OriginalFileReader {
            file: self.file.clone(),
            offset: 0,
            length: self.length,
        }))
    }
}

struct OriginalFileReader {
    file: Arc<File>,
    offset: u64,
    length: u64,
}

impl Read for OriginalFileReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.offset == self.length {
            let mut extra = [0];
            if self.file.read_at(&mut extra, self.offset)? != 0 {
                return Err(std::io::Error::other("held original file grew"));
            }
            return Ok(0);
        }
        let maximum = bytes
            .len()
            .min(usize::try_from(self.length - self.offset).map_err(std::io::Error::other)?);
        let count = self.file.read_at(&mut bytes[..maximum], self.offset)?;
        if count == 0 {
            return Err(std::io::Error::other("held original file ended early"));
        }
        self.offset += count as u64;
        Ok(count)
    }
}

fn authenticate_body(
    blobs: &dyn ImmutableBlobBackend,
    identity: ContentId,
    reference: &ContentRef,
) -> Result<(), NodeObservedError> {
    reference.validate()?;
    if reference.hash.algorithm != "blake3-256" || reference.hash.domain != "cnp.blob.v1" {
        return Err(refused(
            "durable failure-source identity has another content grammar",
        ));
    }
    let source = blobs.read(identity, None).map_err(error)?;
    if source.logical_length() != reference.length.get() {
        return Err(refused("durable failure-source extent differs"));
    }
    let mut input = source.open().map_err(error)?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&(reference.hash.domain.len() as u32).to_be_bytes());
    hash.update(reference.hash.domain.as_bytes());
    hash.update(&reference.length.get().to_be_bytes());
    let mut count = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        // Reaching EOF is mandatory: the backend's full CAS identity and our
        // independently selected CNP identity must both authenticate the stream.
        let read = input.read(&mut buffer).map_err(error)?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| refused("durable source length overflow"))?;
        if count > reference.length.get() {
            return Err(refused("durable source exceeded original length"));
        }
        hash.update(&buffer[..read]);
    }
    if count != reference.length.get() || hash.finalize().to_hex().as_str() != reference.hash.digest
    {
        return Err(refused(
            "durable source differs from complete original content",
        ));
    }
    Ok(())
}

fn place_root(
    refs: &dyn MutableRefBackend,
    name: &RefName,
    identity: ContentId,
) -> Result<(), NodeObservedError> {
    match refs.compare_exchange(name, None, identity).map_err(error)? {
        RefCasOutcome::Advanced { next } if next == identity => Ok(()),
        RefCasOutcome::Conflict {
            current: Some(current),
            ..
        } if current == identity => Ok(()),
        _ => Err(refused(
            "original failure source requires same-byte root reconciliation",
        )),
    }
}

fn member_root(execution: &str, identity: ContentId) -> Result<RefName, NodeObservedError> {
    RefName::new(format!(
        "node-capability-failure-source/{execution}/{}",
        identity.encode()
    ))
    .map_err(error)
}

fn index_root(execution: &str) -> Result<RefName, NodeObservedError> {
    RefName::new(format!("node-capability-failure-source/{execution}/index")).map_err(error)
}

fn history_root(execution: &str, identity: ContentId) -> Result<RefName, NodeObservedError> {
    RefName::new(format!(
        "node-capability-failure-source/{execution}/history/{}",
        identity.encode()
    ))
    .map_err(error)
}

fn error(value: impl std::fmt::Display) -> NodeObservedError {
    refused(&value.to_string())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootQuota {
    format: String,
    version: u16,
    consumed: usize,
}

fn reserve_roots(
    blobs: &dyn ImmutableBlobBackend,
    refs: &dyn MutableRefBackend,
    requested: usize,
) -> Result<(), NodeObservedError> {
    if requested == 0 || requested > 4098 + HISTORY_ROOTS {
        return Err(refused("original failure-source root reservation differs"));
    }
    let name = RefName::new("node-capability-failure-source-quota").map_err(error)?;
    let _publication = refs.acquire_publication_guard().map_err(error)?;
    for _ in 0..128 {
        let current = refs.read_ref(&name).map_err(error)?;
        let consumed = match current {
            Some(identity) => {
                let bytes = blobs
                    .read(identity, None)
                    .map_err(error)?
                    .read_all(1024)
                    .map_err(error)?;
                let value = canonical::parse_json(&bytes, 1024)?;
                if canonical::canonical_json(&value)? != bytes {
                    return Err(refused("original failure-source quota is not canonical"));
                }
                let quota: RootQuota = serde_json::from_value(value)?;
                if quota.format != "crucible.failure-source-root-quota"
                    || quota.version != 1
                    || quota.consumed > 65_536
                {
                    return Err(refused("original failure-source quota has another scope"));
                }
                quota.consumed
            }
            None => 0,
        };
        let consumed = consumed
            .checked_add(requested)
            .filter(|count| *count <= 65_536)
            .ok_or_else(|| refused("durable original source-root lifetime credit exhausted"))?;
        let quota = RootQuota {
            format: "crucible.failure-source-root-quota".into(),
            version: 1,
            consumed,
        };
        let bytes = canonical::canonical_json(&serde_json::to_value(quota)?)?;
        let next = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        blobs
            .put_if_absent(next, &BlobHandle::from_bytes(bytes))
            .map_err(error)?;
        if matches!(refs.compare_exchange(&name, current, next).map_err(error)?, RefCasOutcome::Advanced { next: actual } if actual == next)
        {
            return Ok(());
        }
    }
    Err(refused(
        "original source-root reservation exceeded bounded CAS contention",
    ))
}

#[cfg(test)]
#[path = "persistence_tests.rs"]
mod persistence_tests;
