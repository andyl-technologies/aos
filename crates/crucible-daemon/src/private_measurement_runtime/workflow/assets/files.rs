//! Pins actual immutable files before original postchecks and buffer admission.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use crucible::owned_decode::{DecodeBudget, DecodeDescriptorLoan, DecodeScratch};

use super::{ArtifactCause, ArtifactRefusal, ArtifactWork, checked};

pub(super) struct PinnedInput {
    pub(super) file: Option<File>,
    pub(super) bytes: Option<Vec<u8>>,
    // Actual files and buffers close before either external loan's controls.
    descriptor: Option<DecodeDescriptorLoan>,
    buffer: Option<DecodeScratch>,
}

impl PinnedInput {
    pub(super) fn reserved(budget: &DecodeBudget) -> Result<Self, ArtifactCause> {
        Ok(Self {
            file: None,
            bytes: None,
            descriptor: Some(budget.reserve_descriptors(1)?),
            buffer: None,
        })
    }

    pub(super) fn open(
        &mut self,
        path: &std::path::Path,
        check: &ArtifactWork<'_, '_>,
    ) -> Result<std::fs::Metadata, ArtifactRefusal> {
        self.open_for_owner(path, 0, check)
    }

    #[cfg(test)]
    pub(super) fn open_fixture(
        &mut self,
        path: &std::path::Path,
        check: &ArtifactWork<'_, '_>,
    ) -> Result<std::fs::Metadata, ArtifactRefusal> {
        let owner = path
            .parent()
            .ok_or_else(|| check.error(ArtifactCause::Identity))?
            .metadata()
            .map_err(|source| check.error(source.into()))?
            .uid();
        self.open_for_owner(path, owner, check)
    }

    fn open_for_owner(
        &mut self,
        path: &std::path::Path,
        owner: u32,
        check: &ArtifactWork<'_, '_>,
    ) -> Result<std::fs::Metadata, ArtifactRefusal> {
        checked(
            check,
            (|| {
                check.verify_original()?;
                // The successful kernel return is owned before the first postcut.
                self.file = Some(
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                        .open(path)?,
                );
                Ok(())
            })(),
        )?;
        checked(check, check.verify_original().map_err(Into::into))?;
        let metadata = checked(
            check,
            self.file
                .as_ref()
                .ok_or(ArtifactCause::Identity)
                .and_then(|file| file.metadata().map_err(Into::into)),
        )?;
        if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o222 != 0 {
            return checked(check, Err(ArtifactCause::Identity));
        }
        Ok(metadata)
    }

    pub(super) fn authenticate_stream(
        &mut self,
        expected_length: u64,
        expected_digest: &str,
        check: &ArtifactWork<'_, '_>,
    ) -> Result<[u8; 4], ArtifactRefusal> {
        let expected = blake3::Hash::from_hex(expected_digest)
            .map_err(|_| check.error(ArtifactCause::Identity))?;
        let mut hasher = blake3::Hasher::new();
        // This fixed local buffer belongs to the authored main-thread stack
        // case. It is not an inferred heap or native callback grant.
        let mut buffer = [0; 4096];
        let mut length = 0_u64;
        let mut prefix = [0; 4];
        loop {
            checked(check, check.verify_original().map_err(Into::into))?;
            let read = checked(
                check,
                self.file
                    .as_mut()
                    .ok_or(ArtifactCause::Identity)
                    .and_then(|file| file.read(&mut buffer).map_err(Into::into)),
            )?;
            if read == 0 {
                break;
            }
            if length < prefix.len() as u64 {
                let offset =
                    usize::try_from(length).map_err(|_| check.error(ArtifactCause::Identity))?;
                let copied = read.min(prefix.len() - offset);
                prefix[offset..offset + copied].copy_from_slice(&buffer[..copied]);
            }
            length = length
                .checked_add(read as u64)
                .filter(|length| *length <= expected_length)
                .ok_or_else(|| check.error(ArtifactCause::Identity))?;
            hasher.update(&buffer[..read]);
        }
        checked(
            check,
            if length == expected_length && hasher.finalize() == expected {
                Ok(prefix)
            } else {
                Err(ArtifactCause::Identity)
            },
        )
    }

    pub(super) fn read_compact(
        &mut self,
        length: u64,
        expected_digest: &str,
        budget: &DecodeBudget,
        check: &ArtifactWork<'_, '_>,
    ) -> Result<(), ArtifactRefusal> {
        let work = (|| {
            let length = usize::try_from(length)
                .ok()
                .filter(|length| *length != 0 && *length <= 32 * 1024 * 1024)
                .ok_or(ArtifactCause::Identity)?;
            self.buffer = Some(budget.reserve_scratch_bytes(length as u64)?);
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length)?;
            bytes.resize(length, 0);
            self.bytes = Some(bytes);
            Ok(())
        })();
        checked(check, work)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| check.error(ArtifactCause::Identity))?;
        let bytes = self
            .bytes
            .as_mut()
            .ok_or_else(|| check.error(ArtifactCause::Identity))?;
        checked(check, check.verify_original().map_err(Into::into))?;
        checked(check, file.read_exact(bytes).map_err(Into::into))?;
        let mut trailing = [0];
        checked(check, check.verify_original().map_err(Into::into))?;
        let tail = checked(check, file.read(&mut trailing).map_err(Into::into))?;
        let digest = blake3::Hash::from_hex(expected_digest)
            .map_err(|_| check.error(ArtifactCause::Identity))?;
        checked(
            check,
            if tail == 0 && blake3::hash(bytes) == digest {
                Ok(())
            } else {
                Err(ArtifactCause::Identity)
            },
        )
    }

    pub(super) fn close(&mut self) {
        drop(self.file.take());
        drop(self.bytes.take());
        drop(self.descriptor.take());
        drop(self.buffer.take());
    }
}
