//! Retains the prepaid protected final P/O unit profile and its native posts.
//!
//! AOSNWP02 contains final configuration DATA. This owner neither invents
//! native limits nor turns a header, digest or file into Source permission.

use super::*;
use std::fs::{File, Metadata};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use rustix::fs::{OFlags, StatFs};
use rustix::io::FdFlags;

const PROFILE_BYTES: usize = 8208;
const ROW_BYTES: usize = 4096;
const PROFILE_PATH: &str = "/etc/aos/sandbox-network-worker-profile-v2";

#[derive(Clone, Copy)]
enum First { Order, Before, Quote, Funding, Open, Metadata, Filesystem, Flags,
    DescriptorFlags, Physical, Read, Syntax, MetadataAfter, FilesystemAfter,
    FlagsAfter, DescriptorFlagsAfter, PhysicalAfter, ParentAfter }

pub(super) struct ProfileOriginalV2 {
    entered: bool,
    before: Option<Result<(), FixedServiceOperationClosedV4>>,
    quote: Option<Result<ResourceVector, AccountingError>>,
    funding: Option<Result<(), FixedServiceOperationClosedV4>>,
    file: Option<std::io::Result<File>>,
    metadata: Option<std::io::Result<Metadata>>,
    filesystem: Option<Result<StatFs, rustix::io::Errno>>,
    flags: Option<Result<OFlags, rustix::io::Errno>>,
    descriptor_flags: Option<Result<FdFlags, rustix::io::Errno>>,
    read: Option<std::io::Result<()>>,
    metadata_after: Option<std::io::Result<Metadata>>,
    filesystem_after: Option<Result<StatFs, rustix::io::Errno>>,
    flags_after: Option<Result<OFlags, rustix::io::Errno>>,
    descriptor_flags_after: Option<Result<FdFlags, rustix::io::Errno>>,
    parent_after: Option<Result<(), FixedServiceOperationClosedV4>>,
    bytes: [u8; PROFILE_BYTES],
    first: Option<First>,
    complete: bool,
}

impl ProfileOriginalV2 {
    pub(super) const fn new() -> Self {
        Self { entered: false, before: None, quote: None, funding: None,
            file: None, metadata: None, filesystem: None, flags: None,
            descriptor_flags: None, read: None, metadata_after: None,
            filesystem_after: None, flags_after: None, descriptor_flags_after: None,
            parent_after: None, bytes: [0; PROFILE_BYTES], first: None, complete: false }
    }

    fn demand() -> Result<ResourceVector, AccountingError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * 2048))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Sha256>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        // One actual retained OFD; all fixed parser/readback backing is inline.
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, 1)
            .with(D::MetadataEntries, 1))
    }

    pub(super) fn capture_once(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        if self.entered { return self.refuse(First::Order); }
        self.entered = true;
        let _ = self.capture_inner(loan);

        // These are separate obligations, including after failed read/syntax.
        if let Some(Ok(file)) = self.file.as_ref() {
            self.metadata_after = Some(file.metadata());
            self.filesystem_after = Some(rustix::fs::fstatfs(file));
            self.flags_after = Some(rustix::fs::fcntl_getfl(file));
            self.descriptor_flags_after = Some(rustix::io::fcntl_getfd(file));
            if !matches!(self.metadata_after, Some(Ok(_))) { self.first.get_or_insert(First::MetadataAfter); }
            if !matches!(self.filesystem_after, Some(Ok(_))) { self.first.get_or_insert(First::FilesystemAfter); }
            if !matches!(self.flags_after, Some(Ok(_))) { self.first.get_or_insert(First::FlagsAfter); }
            if !matches!(self.descriptor_flags_after, Some(Ok(_))) { self.first.get_or_insert(First::DescriptorFlagsAfter); }
            if !self.physical(true) { self.first.get_or_insert(First::PhysicalAfter); }
        }
        self.parent_after = Some(loan.require_network_worker_current_v4());
        if !matches!(self.parent_after, Some(Ok(()))) { self.first.get_or_insert(First::ParentAfter); }
        self.complete = self.first.is_none();
        if self.complete { Ok(()) } else { Err(FixedServiceOperationClosedV4) }
    }

    fn capture_inner(&mut self, loan: &mut FixedServiceOperationLoanV4<'_>)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        self.before = Some(loan.require_network_worker_current_v4());
        if !matches!(self.before, Some(Ok(()))) { return self.refuse(First::Before); }
        self.quote = Some(Self::demand());
        let demand = match self.quote.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(demand) => demand,
            None => return self.refuse(First::Quote),
        };
        self.funding = Some(loan.require_additional_representation_v4(demand));
        if !matches!(self.funding, Some(Ok(()))) { return self.refuse(First::Funding); }

        self.file = Some(File::open(PROFILE_PATH));
        self.read_once()
    }

    fn read_once(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        let Some(Ok(file)) = self.file.as_ref() else { return self.refuse(First::Open); };
        self.metadata = Some(file.metadata());
        self.filesystem = Some(rustix::fs::fstatfs(file));
        self.flags = Some(rustix::fs::fcntl_getfl(file));
        self.descriptor_flags = Some(rustix::io::fcntl_getfd(file));
        if !matches!(self.metadata, Some(Ok(_))) { return self.refuse(First::Metadata); }
        if !matches!(self.filesystem, Some(Ok(_))) { return self.refuse(First::Filesystem); }
        if !matches!(self.flags, Some(Ok(_))) { return self.refuse(First::Flags); }
        if !matches!(self.descriptor_flags, Some(Ok(_))) { return self.refuse(First::DescriptorFlags); }
        if !self.physical(false) { return self.refuse(First::Physical); }
        let Some(Ok(file)) = self.file.as_ref() else { return self.refuse(First::Open); };
        self.read = Some(file.read_exact_at(&mut self.bytes, 0));
        if !matches!(self.read, Some(Ok(()))) { return self.refuse(First::Read); }
        if !syntax(&self.bytes) { return self.refuse(First::Syntax); }
        Ok(())
    }

    fn physical(&self, after: bool) -> bool {
        let (metadata, filesystem, flags, descriptor_flags) = if after {
            (&self.metadata_after, &self.filesystem_after, &self.flags_after, &self.descriptor_flags_after)
        } else { (&self.metadata, &self.filesystem, &self.flags, &self.descriptor_flags) };
        let (Some(Ok(metadata)), Some(Ok(filesystem)), Some(Ok(flags)), Some(Ok(descriptor_flags)))
            = (metadata, filesystem, flags, descriptor_flags) else { return false; };
        if !metadata.is_file() || metadata.uid() != 0 || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o444 || metadata.len() != PROFILE_BYTES as u64
            || filesystem.f_type as u64 != 0xe0f5_e1e2
            || flags.intersects(OFlags::PATH | OFlags::WRONLY | OFlags::RDWR | OFlags::APPEND)
            || !descriptor_flags.contains(FdFlags::CLOEXEC) { return false; }
        if after {
            let Some(Ok(before)) = self.metadata.as_ref() else { return false; };
            if metadata.dev() != before.dev() || metadata.ino() != before.ino()
                || metadata.ctime() != before.ctime() || metadata.ctime_nsec() != before.ctime_nsec()
            { return false; }
        }
        true
    }

    pub(super) fn limits(&self, purpose: NetworkWorkerBirthPurposeV2) -> Option<[u64; 3]> {
        if !self.complete { return None; }
        let row = &self.bytes[16 + (purpose as usize - 1) * ROW_BYTES..];
        Some([u64_at(row, 8)?, u64_at(row, 16)?, u64_at(row, 24)?])
    }

    pub(super) fn argument_count(&self, purpose: NetworkWorkerBirthPurposeV2) -> Option<usize> {
        if !self.complete { return None; }
        let offset = 16 + (purpose as usize - 1) * ROW_BYTES;
        Some(usize::from(u16::from_be_bytes([self.bytes[offset + 2], self.bytes[offset + 3]])))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Before => self.before.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Quote => self.quote.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Open => self.file.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Metadata => self.metadata.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Filesystem => self.filesystem.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Flags => self.flags.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::DescriptorFlags => self.descriptor_flags.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Read => self.read.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::MetadataAfter => self.metadata_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::FilesystemAfter => self.filesystem_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::FlagsAfter => self.flags_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::DescriptorFlagsAfter => self.descriptor_flags_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ParentAfter => self.parent_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            _ => None,
        };
        cause.or(Some(&FixedServiceOperationClosedV4))
    }

    pub(super) fn parent_failure_selected(&self) -> bool {
        matches!(self.first, Some(First::Before | First::Funding | First::ParentAfter))
    }

    fn refuse(&mut self, first: First) -> Result<(), FixedServiceOperationClosedV4> {
        self.first.get_or_insert(first);
        Err(FixedServiceOperationClosedV4)
    }
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}

fn syntax(bytes: &[u8; PROFILE_BYTES]) -> bool {
    if &bytes[..8] != b"AOSNWP02" || bytes[8..12] != [0, 2, 0, 2]
        || bytes[12..16] != (PROFILE_BYTES as u32).to_be_bytes() { return false; }
    let names: [&[u8]; 2] = [b"aos-sandbox-network-worker@.service",
        b"aos-sandbox-network-observation-worker@.service"];
    for (index, name) in names.into_iter().enumerate() {
        let row = &bytes[16 + index * ROW_BYTES..16 + (index + 1) * ROW_BYTES];
        let argc = usize::from(u16::from_be_bytes([row[2], row[3]]));
        let name_len = usize::from(u16::from_be_bytes([row[4], row[5]]));
        let text_len = usize::from(u16::from_be_bytes([row[6], row[7]]));
        if row[0] as usize != index + 1 || row[1] != 0 || argc == 0
            || name_len != name.len() || text_len == 0 || text_len > 2048
            || row[96..96 + name_len] != *name || row[96 + name_len..224].iter().any(|byte| *byte != 0)
            || row[224 + text_len..].iter().any(|byte| *byte != 0)
            || row[32..64].iter().all(|byte| *byte == 0)
            || (8..32).step_by(8).any(|offset| u64_at(row, offset).is_none_or(|value| value == 0))
        { return false; }
        let command = &row[224..224 + text_len];
        if Sha256::digest(command).as_slice() != &row[64..96] { return false; }
        let Ok(command) = std::str::from_utf8(command) else { return false; };
        // This bounded normalization and its full backing were prepaid before
        // the file opened; it matches the producer's literal path grammar.
        let normalized = command.replace("\\\n", " ");
        let mut count = 0usize;
        for argument in normalized.split_ascii_whitespace() {
            if !argument.starts_with('/')
                || !argument.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"/_+.,/@:=~-".contains(&byte))
                || argument.split('/').any(|part| matches!(part, "." | ".."))
            { return false; }
            count += 1;
        }
        if count != argc { return false; }
    }
    true
}
