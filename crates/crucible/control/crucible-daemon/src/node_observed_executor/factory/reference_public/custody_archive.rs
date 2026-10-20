//! Retains one private file attempt until exact original bytes are durable.
//!
//! The private operational file is versioned and never becomes public content:
//!
//! ```json
//! {"schema":"crucible.private-cnp-retirement-custody.v2",
//!  "scope":[],"negotiation":[],"peer":{"runtime":[],"controller":[]},"source_manifest":[]}
//! ```
//! The abbreviated arrays retain complete original records and secret bytes.
//! The JSON header is followed by the source-custody marker and sorted source
//! segments: an eight-byte big-endian header length, that JSON path/content
//! header, and exactly the committed source payload length.
//!
//! This format grants no restored runtime or owner authority.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
};

use crucible_node_transport::ProviderError;
use rustix::fs::{Mode, OFlags};

use super::{Entry, ReclaimedPublicPeer};

pub(super) struct OriginalArchiveAttempt {
    identity: crucible_node_format::U64,
    source: Option<std::rc::Rc<super::super::package::OriginalPackageSourceCustody>>,
    bytes: Vec<u8>,
    directory: File,
    file: Option<File>,
    attempted: bool,
    complete: bool,
}

impl OriginalArchiveAttempt {
    pub(super) fn prepare(entry: &Entry) -> Result<Self, ProviderError> {
        let peer = entry.custody.as_ref().ok_or(ProviderError::Correlation(
            "original reclaimed peer absent from durable custody",
        ))?;
        let scope = &entry.scope;
        if !entry.reclaimed
            || scope.publication
                != Some(crucible_engine::node_contract::PublicationStatus::Committed)
            || scope.connection_incident.borrow().is_some()
        {
            return Err(ProviderError::Correlation(
                "original peer publication or incident disposition unresolved",
            ));
        }
        let source = scope
            .source_custody
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "complete original package source custody absent",
            ))?
            .clone();
        let mut bytes = OriginalArchiveBuffer(Vec::new());
        bytes
            .write_all(b"{\"schema\":\"crucible.private-cnp-retirement-custody.v2\",\"scope\":")?;
        serde_json::to_writer(
            &mut bytes,
            &(
                entry.identity,
                (
                    scope.activation.generation,
                    &scope.activation.activation_id,
                    &scope.activation.world_binding_hash,
                    &scope.activation.owners,
                    scope.activation.boundary,
                ),
                &scope.owner,
                &scope.implementation,
                &scope.source_roots,
                "committed",
                &scope.private_launch,
                &scope.original_hello,
            ),
        )
        .map_err(crucible_node_format::ContractError::from)?;
        bytes.write_all(b",\"negotiation\":")?;
        match (&scope.ordinary_negotiation, &scope.collecting_negotiation) {
            (Some(original), None) => original
                .try_borrow()
                .map_err(|_| ProviderError::Correlation("ordinary negotiation remains borrowed"))?
                .write_attached_originals(&mut bytes)?,
            (None, Some(original)) => original
                .try_borrow()
                .map_err(|_| ProviderError::Correlation("collecting negotiation remains borrowed"))?
                .write_attached_transport(&mut bytes)?,
            _ => {
                return Err(ProviderError::Correlation(
                    "exact original transport custody unavailable",
                ));
            }
        }
        bytes.write_all(b",\"peer\":")?;
        let semantic =
            peer.write_resolved_originals(&scope.activation, &scope.owner, &mut bytes)?;
        if !semantic.belongs_to(peer) {
            return Err(ProviderError::Correlation(
                "semantic seal belongs to another original peer",
            ));
        }
        bytes.write_all(b",\"source_manifest\":")?;
        serde_json::to_writer(&mut bytes, &source.document())
            .map_err(crucible_node_format::ContractError::from)?;
        bytes.write_all(b"}\nCRUCIBLE_PRIVATE_SOURCE_CUSTODY_V1\n")?;
        let bytes = bytes.0;
        let directory = peer.duplicate_private_directory()?;
        authenticate_directory(&directory)?;
        Ok(Self {
            identity: entry.identity,
            source: Some(source),
            bytes,
            directory,
            file: None,
            attempted: false,
            complete: false,
        })
    }

    /// Reconciles this same original file; a failed attempt cannot choose another path.
    pub(super) fn poll(&mut self) -> Result<bool, ProviderError> {
        authenticate_directory(&self.directory)?;
        if !self.attempted {
            self.attempted = true;
            let name = format!("resolved-original-custody-{}.custody", self.identity.get());
            let file = File::from(
                rustix::fs::openat(
                    &self.directory,
                    name,
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(std::io::Error::from)?,
            );
            // Retain the original descriptor before any fallible authentication.
            self.file = Some(file);
        }
        let file = self.file.as_mut().ok_or(ProviderError::Correlation(
            "original private archive creation remains unresolved",
        ))?;
        authenticate_file_at(&self.directory, self.identity, file)?;
        // Re-read an uncertain short write from the SAME descriptor. Only the
        // exact original prefix permits continuation; no truncation or replacement.
        let length = file.metadata()?.len();
        let expected = (self.bytes.len() as u64)
            .checked_add(
                self.source
                    .as_ref()
                    .map_or(0, |source| source.archive_bytes()),
            )
            .ok_or(ProviderError::ResourceExhausted(
                "complete original archive extent",
            ))?;
        if length > expected {
            return Err(ProviderError::Correlation(
                "private original archive extent changed",
            ));
        }
        file.seek(SeekFrom::Start(0))?;
        {
            let mut replay = OriginalFileReplay {
                file,
                retained: length,
                position: 0,
                append: true,
            };
            replay.write_all(&self.bytes)?;
            if let Some(source) = &self.source {
                source.write_originals(&mut replay)?;
            }
            if replay.position != expected {
                return Err(ProviderError::Correlation(
                    "original source archive extent differs",
                ));
            }
        }
        file.sync_all()?;
        self.directory.sync_all()?;
        authenticate_file_at(&self.directory, self.identity, file)?;
        if file.metadata()?.len() != expected {
            return Err(ProviderError::Correlation(
                "private original archive incomplete after synchronization",
            ));
        }
        file.seek(SeekFrom::Start(0))?;
        {
            let mut replay = OriginalFileReplay {
                file,
                retained: expected,
                position: 0,
                append: false,
            };
            replay.write_all(&self.bytes)?;
            if let Some(source) = &self.source {
                source.write_originals(&mut replay)?;
            }
            if replay.position != expected {
                return Err(ProviderError::Correlation(
                    "complete original source readback differs",
                ));
            }
        }
        self.complete = true;
        Ok(true)
    }

    pub(super) fn complete_for(&self, identity: crucible_node_format::U64) -> bool {
        self.complete && self.identity == identity
    }

    pub(super) fn acknowledge(
        self,
        identity: crucible_node_format::U64,
        original: ReclaimedPublicPeer,
    ) -> RetainedResolvedPeer {
        RetainedResolvedPeer {
            identity,
            _original: original,
            _archive: self,
        }
    }
}

/// Keeps the exact reclaimed capsule alongside its acknowledged private file.
pub(super) struct RetainedResolvedPeer {
    identity: crucible_node_format::U64,
    _original: ReclaimedPublicPeer,
    _archive: OriginalArchiveAttempt,
}

impl RetainedResolvedPeer {
    pub(super) fn belongs_to(
        &self,
        record: &crucible_engine::node_contract::ActivationRecord,
        owner: &crucible_engine::node_contract::OwnerIdentity,
    ) -> bool {
        self._original.scope.activation == *record
            && self._original.scope.owner == *owner
            && self._original.scope.publication
                == Some(crucible_engine::node_contract::PublicationStatus::Committed)
            && self._archive.complete_for(self.identity)
    }

    pub(super) fn confirm_original(&mut self) -> Result<(), ProviderError> {
        self._archive.poll()?;
        Ok(())
    }
}

fn authenticate_directory(directory: &File) -> Result<(), ProviderError> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(ProviderError::Correlation(
            "private archive directory custody changed",
        ));
    }
    Ok(())
}

fn authenticate_file(file: &File) -> Result<(), ProviderError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ProviderError::Correlation(
            "private original archive file custody changed",
        ));
    }
    Ok(())
}

fn compare_original(file: &mut File, bytes: &[u8]) -> Result<(), ProviderError> {
    let mut buffer = [0u8; 16384];
    for chunk in bytes.chunks(buffer.len()) {
        file.read_exact(&mut buffer[..chunk.len()])?;
        if buffer[..chunk.len()] != *chunk {
            return Err(ProviderError::Correlation(
                "private original archive bytes changed",
            ));
        }
    }
    Ok(())
}

struct OriginalArchiveBuffer(Vec<u8>);

impl Write for OriginalArchiveBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|total| total > 96 * 1024 * 1024)
        {
            return Err(std::io::Error::other(
                "complete private original archive credit",
            ));
        }
        self.0
            .try_reserve(bytes.len())
            .map_err(|_| std::io::Error::other("complete private original archive allocation"))?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn authenticate_file_at(
    directory: &File,
    identity: crucible_node_format::U64,
    file: &File,
) -> Result<(), ProviderError> {
    authenticate_file(file)?;
    let name = format!("resolved-original-custody-{}.custody", identity.get());
    let named = File::from(
        rustix::fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    let actual = file.metadata()?;
    let linked = named.metadata()?;
    if actual.dev() != linked.dev() || actual.ino() != linked.ino() {
        return Err(ProviderError::Correlation(
            "private original archive directory entry changed",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "custody_archive_tests.rs"]
mod tests;

struct OriginalFileReplay<'a> {
    file: &'a mut File,
    retained: u64,
    position: u64,
    append: bool,
}

impl Write for OriginalFileReplay<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let prefix = self
            .retained
            .saturating_sub(self.position)
            .min(bytes.len() as u64) as usize;
        if prefix != 0 {
            compare_original(self.file, &bytes[..prefix])
                .map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        if prefix != bytes.len() {
            if !self.append {
                return Err(std::io::Error::other(
                    "original archive readback is incomplete",
                ));
            }
            self.file.write_all(&bytes[prefix..])?;
        }
        self.position = self
            .position
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("original archive cursor overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
