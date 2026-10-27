//! Publishes one canonical checkpoint while preserving the displaced empty inode.
//!
//! Source separates stage durability, fresh name validation, atomic exchange and
//! directory durability with independent currentness checks. Every failed prefix
//! remains resident; neither file is unlinked, truncated or silently replaced.

use std::os::unix::fs::FileExt as _;

use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::SIDECAR_NAME_V1;

use super::*;

struct NameOriginal {
    open: Option<Result<File, rustix::io::Errno>>,
    metadata: [Option<io::Result<Metadata>>; 2],
    read: FixedRoleCredentialReadV1,
    bytes: Option<Vec<u8>>,
    result: Option<Result<(), JournalError>>,
}

impl NameOriginal {
    fn new() -> Self {
        Self {
            open: None,
            metadata: [None, None],
            read: FixedRoleCredentialReadV1::prearmed(),
            bytes: None,
            result: None,
        }
    }

    fn capture(&mut self, main: &Journal, name: &str, uid: u32) {
        self.open = Some(
            main.native
                .native_operations()
                .open_named_child(name)
                .map(File::from),
        );
        self.result = Some((|| {
            if self.missing() {
                return Ok(());
            }
            let file = self
                .open
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            self.metadata[0] = Some(file.metadata());
            let metadata = self.metadata[0]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            require_file(metadata, uid, true)?;
            let before = FileIdentity::from_metadata_data_v1(metadata);
            let length =
                usize::try_from(metadata.len()).map_err(|_| JournalError::ProtectedBoundary)?;
            self.read.read_exact_at_once(file.as_fd(), length);
            self.bytes = self.read.take_success_bytes_once();
            self.metadata[1] = Some(file.metadata());
            if self.identity() != Some(before) || self.bytes.is_none() {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })());
    }

    fn missing(&self) -> bool {
        matches!(self.open, Some(Err(rustix::io::Errno::NOENT)))
    }

    fn identity(&self) -> Option<FileIdentity> {
        self.metadata[1]
            .as_ref()?
            .as_ref()
            .ok()
            .map(FileIdentity::from_metadata_data_v1)
    }

    fn metadata(&self) -> Option<&Metadata> {
        self.metadata[1].as_ref()?.as_ref().ok()
    }

    fn require(&self, bytes: &[u8], uid: u32) -> Result<FileIdentity, JournalError> {
        let metadata = self.metadata().ok_or(JournalError::ProtectedBoundary)?;
        if !matches!(self.result, Some(Ok(())))
            || self.bytes.as_deref() != Some(bytes)
            || metadata.uid() != uid
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.identity().ok_or(JournalError::ProtectedBoundary)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.open)
            .filter(|_| !self.missing())
            .or_else(|| error(&self.metadata[0]))
            .or_else(|| self.read.failure())
            .or_else(|| error(&self.metadata[1]))
            .or_else(|| error(&self.result))
    }
}

fn require_file(metadata: &Metadata, uid: u32, allow_root: bool) -> Result<(), JournalError> {
    if !metadata.is_file()
        || (metadata.uid() != uid && !(allow_root && metadata.uid() == 0))
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > FRAMED_BYTES as u64
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) struct InitialCheckpointPublicationOriginal {
    quote: Option<Result<ResourceVector, JournalError>>,
    main: approval_currentness::ApprovalCurrentnessOriginalV1,
    install_main: approval_currentness::ApprovalCurrentnessOriginalV1,
    uid: Option<u32>,
    empty_floor: Option<FileIdentity>,
    before: [NameOriginal; 2],
    stage: Option<Result<File, rustix::io::Errno>>,
    metadata: [Option<io::Result<Metadata>>; 3],
    prefix_read: FixedRoleCredentialReadV1,
    prefix: Option<Vec<u8>>,
    ownership: Option<Result<(), rustix::io::Errno>>,
    write: Option<io::Result<usize>>,
    file_sync: Option<io::Result<()>>,
    ready_read: FixedRoleCredentialReadV1,
    ready: Option<Vec<u8>>,
    preparation: Option<Result<(), JournalError>>,
    validated: [NameOriginal; 2],
    validation: Option<Result<(), JournalError>>,
    exchange: Option<Result<(), rustix::io::Errno>>,
    directory_sync: Option<Result<(), rustix::io::Errno>>,
    after: [NameOriginal; 2],
    post: Option<Result<(), JournalError>>,
    closed: Option<JournalError>,
}

impl InitialCheckpointPublicationOriginal {
    pub(super) fn new() -> Self {
        Self {
            quote: None,
            main:
                approval_currentness::ApprovalCurrentnessOriginalV1::for_fixed_sibling_publication(),
            install_main:
                approval_currentness::ApprovalCurrentnessOriginalV1::for_fixed_sibling_publication(),
            uid: None,
            empty_floor: None,
            before: std::array::from_fn(|_| NameOriginal::new()),
            stage: None,
            metadata: [None, None, None],
            prefix_read: FixedRoleCredentialReadV1::prearmed(),
            prefix: None,
            ownership: None,
            write: None,
            file_sync: None,
            ready_read: FixedRoleCredentialReadV1::prearmed(),
            ready: None,
            preparation: None,
            validated: std::array::from_fn(|_| NameOriginal::new()),
            validation: None,
            exchange: None,
            directory_sync: None,
            after: std::array::from_fn(|_| NameOriginal::new()),
            post: None,
            closed: None,
        }
    }

    pub(super) fn quote_once(
        &mut self,
        main: &Journal,
        replayed: FileIdentity,
    ) -> Option<ResourceVector> {
        if self.quote.is_some() || self.preparation.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.quote = Some((|| {
            // Six named readbacks and two held-stage readers retain their own
            // native failures. Encoded checkpoint DATA was paid at capture.
            let memory = 2 * std::mem::size_of::<Self>() + 32 * (FRAMED_BYTES + 1) + 4096;
            let native = ResourceVector::ZERO
                .with(
                    D::MemoryBytes,
                    u64::try_from(memory).map_err(|_| JournalError::ProtectedBoundary)?,
                )
                .with(D::OpenFiles, 20)
                .with(D::MetadataEntries, 192)
                .with(D::StorageBytes, FRAMED_BYTES as u64)
                .with(D::PublicationStagingBytes, FRAMED_BYTES as u64)
                .with(D::OutputBytes, (16 * (FRAMED_BYTES + 1)) as u64);
            native
                .checked_add(
                    self.main
                        .quote_once(main, replayed)
                        .ok_or(JournalError::ProtectedBoundary)?,
                )
                .map_err(|_| JournalError::ProtectedBoundary)?
                .checked_add(
                    self.install_main
                        .quote_once(main, replayed)
                        .ok_or(JournalError::ProtectedBoundary)?,
                )
                .map_err(|_| JournalError::ProtectedBoundary)
        })());
        self.quote.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn prepare_once(
        &mut self,
        main: &Journal,
        empty_floor: FileIdentity,
        expected: &[u8; FRAMED_BYTES],
        captured: Option<FileIdentity>,
        captured_prefix: Option<&[u8]>,
    ) -> Result<(), JournalError> {
        if self.preparation.is_some() || self.closed.is_some() || !matches!(self.quote, Some(Ok(_)))
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.empty_floor = Some(empty_floor);
        self.uid = main.native.protected_uid();
        self.preparation = Some(self.prepare(main, expected, captured, captured_prefix));
        if matches!(self.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn prepare(
        &mut self,
        main: &Journal,
        expected: &[u8; FRAMED_BYTES],
        captured: Option<FileIdentity>,
        captured_prefix: Option<&[u8]>,
    ) -> Result<(), JournalError> {
        self.main.before_once(main)?;
        let uid = self.uid.ok_or(JournalError::ProtectedBoundary)?;
        for (original, name) in self.before.iter_mut().zip([STAGE, SIDECAR_NAME_V1]) {
            original.capture(main, name, uid);
        }
        if self
            .before
            .iter()
            .any(|original| !matches!(original.result, Some(Ok(()))))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let floor = self.before[1].require(&[], uid)?;
        if Some(floor) != self.empty_floor {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let missing = self.before[0].missing();
        if (captured.is_none() != missing)
            || captured != self.before[0].identity()
            || captured_prefix != self.before[0].bytes.as_deref()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let prefix = captured_prefix.unwrap_or_default();
        if !expected.starts_with(prefix) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.stage = Some(
            main.native
                .native_operations()
                .open_resumable_stage(STAGE, missing)
                .map(File::from),
        );
        let file = self
            .stage
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.metadata[0] = Some(file.metadata());
        let metadata = self.metadata[0]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        require_file(metadata, uid, true)?;
        if metadata.len() != prefix.len() as u64
            || (!missing && Some(FileIdentity::from_metadata_data_v1(metadata)) != captured)
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.prefix_read
            .read_exact_at_once(file.as_fd(), prefix.len());
        self.prefix = self.prefix_read.take_success_bytes_once();
        if self.prefix.as_deref() != Some(prefix) {
            return Err(JournalError::ProtectedBoundary);
        }
        if metadata.uid() != uid {
            self.ownership = Some(rustix::fs::fchown(
                file,
                Some(rustix::process::Uid::from_raw(uid)),
                None,
            ));
            if !matches!(self.ownership, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        if prefix.len() < FRAMED_BYTES {
            self.write = Some(file.write_at(&expected[prefix.len()..], prefix.len() as u64));
            if !matches!(self.write, Some(Ok(length)) if length == FRAMED_BYTES - prefix.len()) {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        self.file_sync = Some(file.sync_all());
        if !matches!(self.file_sync, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.metadata[1] = Some(file.metadata());
        self.ready_read
            .read_exact_at_once(file.as_fd(), FRAMED_BYTES);
        self.ready = self.ready_read.take_success_bytes_once();
        self.metadata[2] = Some(file.metadata());
        let identity = |index: usize| {
            self.metadata[index]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .map(FileIdentity::from_metadata_data_v1)
        };
        let metadata = self.metadata[2]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        require_file(metadata, uid, false)?;
        if self.ready.as_deref() != Some(expected.as_slice()) || identity(1) != identity(2) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(super) fn validate_once(
        &mut self,
        main: &Journal,
        expected: &[u8; FRAMED_BYTES],
    ) -> Result<(), JournalError> {
        if self.validation.is_some()
            || self.exchange.is_some()
            || self.closed.is_some()
            || !matches!(self.preparation, Some(Ok(())))
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        let uid = self.uid.ok_or(JournalError::ProtectedBoundary)?;
        for (original, name) in self.validated.iter_mut().zip([STAGE, SIDECAR_NAME_V1]) {
            original.capture(main, name, uid);
        }
        self.validation = Some((|| {
            let stage = self.validated[0].require(expected, uid)?;
            let ready = self.metadata[2]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .map(FileIdentity::from_metadata_data_v1);
            if Some(stage) != ready
                || Some(self.validated[1].require(&[], uid)?) != self.empty_floor
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            // Stage fsync and named readbacks may have waited. Observe the
            // original replayed main again at this actual exchange frontier.
            self.install_main.before_once(main)?;
            Ok(())
        })());
        if matches!(self.validation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn exchange_once(&mut self, main: &Journal) -> Result<(), JournalError> {
        if self.exchange.is_some()
            || self.closed.is_some()
            || !matches!(self.validation, Some(Ok(())))
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.exchange = Some(
            main.native
                .native_operations()
                .exchange_named_children(STAGE, SIDECAR_NAME_V1),
        );
        if matches!(self.exchange, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn sync_after_owed(&mut self, main: &Journal) -> Result<(), JournalError> {
        if self.preparation.is_none() {
            return Ok(());
        }
        if self.directory_sync.is_none() {
            self.directory_sync = Some(main.native.native_operations().sync_directory());
        }
        if matches!(self.directory_sync, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn finish_after_owed(
        &mut self,
        main: &Journal,
        expected: &[u8; FRAMED_BYTES],
    ) -> Result<(), JournalError> {
        if self.preparation.is_none() {
            return Ok(());
        }
        if self.post.is_none() {
            // Both name readbacks remain owed after the independent main post,
            // even if that post or an earlier stage, exchange or fsync failed.
            let install_after = self.install_main.finish_after_owed(main);
            let main_after = self.main.finish_after_owed(main);
            if let Some(uid) = self.uid {
                for (original, name) in self.after.iter_mut().zip([STAGE, SIDECAR_NAME_V1]) {
                    original.capture(main, name, uid);
                }
            }
            self.post = Some((|| {
                install_after?;
                main_after?;
                let uid = self.uid.ok_or(JournalError::ProtectedBoundary)?;
                if !matches!(self.preparation, Some(Ok(())))
                    || !matches!(self.validation, Some(Ok(())))
                    || !matches!(self.exchange, Some(Ok(())))
                    || !matches!(self.directory_sync, Some(Ok(())))
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                let displaced = self.after[0].require(&[], uid)?;
                let installed = self.after[1].require(expected, uid)?;
                let previous_stage = self.validated[0]
                    .identity()
                    .ok_or(JournalError::ProtectedBoundary)?;
                // Rename changes ctime. Exact bytes and fresh full metadata
                // bookends protect each new name; physical pairs bind the swap.
                if Some(displaced.physical_pair())
                    != self.empty_floor.map(|identity| identity.physical_pair())
                    || installed.physical_pair() != previous_stage.physical_pair()
                {
                    return Err(JournalError::StaleAuthoritySnapshot);
                }
                Ok(())
            })());
        }
        if self.failure().is_none() && matches!(self.post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.quote)
            .or_else(|| self.main.before_failure())
            .or_else(|| self.before.iter().find_map(NameOriginal::failure))
            .or_else(|| error(&self.stage))
            .or_else(|| error(&self.metadata[0]))
            .or_else(|| self.prefix_read.failure())
            .or_else(|| error(&self.ownership))
            .or_else(|| error(&self.write))
            .or_else(|| error(&self.file_sync))
            .or_else(|| error(&self.metadata[1]))
            .or_else(|| self.ready_read.failure())
            .or_else(|| error(&self.metadata[2]))
            .or_else(|| error(&self.preparation))
            .or_else(|| self.validated.iter().find_map(NameOriginal::failure))
            .or_else(|| self.install_main.before_failure())
            .or_else(|| error(&self.validation))
            .or_else(|| error(&self.exchange))
            .or_else(|| error(&self.directory_sync))
            .or_else(|| self.install_main.after_failure())
            .or_else(|| self.main.after_failure())
            .or_else(|| self.after.iter().find_map(NameOriginal::failure))
            .or_else(|| error(&self.post))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

#[cfg(test)]
mod tests;
