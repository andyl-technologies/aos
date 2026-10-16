//! Reconciles bounded bindings against independently verified native content.
//!
//! The existing portable binding parser remains authoritative for its private
//! format. Record names never supply a content claim. Unknown, orphaned, pending
//! state stays unresolved, without deletion or replacement. Manifest claims keep
//! their actual verified metadata pack/index and native custody through finish.

use super::*;
use std::os::unix::fs::MetadataExt;
use terrane::host::publication::{FsPublicationState, PublicationState, VerityBinding};

// Record capacity, retained canonical metadata and decoded payloads share one
// budget. Entry counts separately bound fixed rows/FDs. Sequential rechecks use
// at most two bounded record buffers; pack verification scratch is not retained.
const MAX_RECORD: usize = 65536;

fn add_retained(used: usize, bytes: usize) -> io::Result<usize> {
    used.checked_add(bytes)
        .filter(|total| *total <= HostReadLimits::default().max_allocation_bytes)
        .ok_or_else(|| invalid("publication-state retained byte budget exceeded"))
}

fn retain_source_budget(used: usize, claim: &PublicationClaim) -> io::Result<usize> {
    let Some(manifest) = claim.manifest() else {
        return Ok(used);
    };
    // NativeManifestSource obtains the canonical buffer through the bounded
    // TokioLocalFs exact-range allocation. The decoded chunk Vec can retain
    // spare capacity, so charge that capacity rather than just initialized rows.
    let used = add_retained(used, claim.canonical_manifest().map_or(0, <[u8]>::len))?;
    let chunks = manifest
        .chunks
        .capacity()
        .checked_mul(std::mem::size_of::<terrane_core::manifest::ChunkRef>())
        .ok_or_else(|| invalid("retained manifest chunk allocation overflow"))?;
    let used = add_retained(used, chunks)?;
    let used = add_retained(
        used,
        manifest.media_type.as_ref().map_or(0, String::capacity),
    )?;
    // Charge a conservative stable row allowance for the small registered hash
    // map in addition to each owned name/digest buffer, not allocator RSS.
    manifest
        .hashes
        .iter()
        .try_fold(used, |used, (name, digest)| {
            let used = add_retained(used, 128)?;
            let used = add_retained(used, name.capacity())?;
            add_retained(used, digest.capacity())
        })
}

struct Body {
    parent: File,
    name: String,
    file: File,
    observed: std::fs::Metadata,
    measured: VerityBinding,
    verified: SealedClaim,
}

struct Record {
    name: String,
    file: File,
    observed: std::fs::Metadata,
    bytes: Vec<u8>,
    body: Option<Body>,
}

/// Retains exhaustive private records and verified sources through reconciliation.
pub(super) struct StateInventory {
    directory: File,
    records: Vec<Record>,
    retained_bytes: usize,
}

fn same_inode_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

impl StateInventory {
    /// Captures bounded physical records without deriving claims from them.
    ///
    /// # Errors
    /// Rejects unknown names, unsafe inodes, changed bytes or exhausted budgets.
    pub(super) fn open(
        inventory: &NativeInventory,
        directory: File,
        budget: &mut usize,
    ) -> io::Result<Self> {
        let mut records = Vec::new();
        let mut retained_bytes = 0usize;
        for name in names(&directory, *budget)? {
            charge(budget)?;
            // This only classifies an existing private name. Its exact match to
            // an independently reconstructed claim is required separately.
            let (domain, content) = name
                .strip_suffix(".toml")
                .and_then(|stem| stem.split_once('-'))
                .ok_or_else(|| invalid("unresolved publication-state record name"))?;
            digest(domain, 32)?;
            digest(content, 32)?;
            let mut file = open(&directory, &name, false)?;
            inventory.check(&file, Custody::Publisher, InodeKind::File)?;
            let observed = file.metadata()?;
            let canonical = bytes(&mut file, MAX_RECORD)?;
            retained_bytes = add_retained(retained_bytes, canonical.capacity())?;
            if !same_inode_snapshot(&observed, &file.metadata()?) {
                return Err(invalid("publication-state record changed during capture"));
            }
            records.push(Record {
                name,
                file,
                observed,
                bytes: canonical,
                body: None,
            });
        }
        Ok(Self {
            directory,
            records,
            retained_bytes,
        })
    }

    fn recheck_record(
        directory: &File,
        inventory: &NativeInventory,
        record: &mut Record,
    ) -> io::Result<()> {
        let mut named = open(directory, &record.name, false)?;
        inventory.check(&named, Custody::Publisher, InodeKind::File)?;
        if !same_inode_snapshot(&record.observed, &named.metadata()?)
            || !same_inode_snapshot(&record.observed, &record.file.metadata()?)
            || bytes(&mut named, MAX_RECORD)? != record.bytes
            || bytes(&mut record.file, MAX_RECORD)? != record.bytes
        {
            return Err(invalid("publication-state inode or bytes changed"));
        }
        Ok(())
    }

    /// Matches an existing record to actual verified inline or manifest content.
    ///
    /// # Errors
    /// Rejects changed custody, invalid content, malformed state or seal conflict.
    pub(super) async fn reconcile(
        &mut self,
        inventory: &NativeInventory,
        parent: &File,
        name: &str,
        file: &mut File,
        verified: SealedClaim,
    ) -> io::Result<()> {
        let claim = verified.claim();
        verified.recheck(inventory)?;
        inventory.check(file, Custody::Publisher, InodeKind::File)?;
        let observed = file.metadata()?;
        if observed.mode() & 0o222 != 0 || observed.len() != claim.plaintext_size() {
            return Err(invalid("unsafe canonical inventory inode"));
        }
        let measured = crate::verity::measure(file)?;
        file.seek(SeekFrom::Start(0))?;
        // The manifest identity authenticates canonical metadata, never assembled
        // bytes. This separately checks exact length, ordered chunks and every
        // required whole-file hash under that authenticated claim.
        claim.verify_reader(file)?;
        verified.recheck(inventory)?;
        if !same_inode_snapshot(&observed, &file.metadata()?)
            || crate::verity::measure(file)? != measured
        {
            return Err(invalid(
                "canonical inventory inode changed during verification",
            ));
        }
        // Only the actual retained private directory supplies this parser path.
        // No request path or private record bytes can create a claim authority.
        let state = FsPublicationState::new(
            TokioLocalFs,
            std::path::PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd())),
        );
        let path = state.binding_record_path(claim);
        let expected_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("binding parser produced an invalid record name"))?;
        let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.name == expected_name)
        else {
            // State loss is reconstructed by later actual adoption, never by
            // interpreting an absent record as an existing durable binding.
            return Ok(());
        };
        if record.body.is_some() {
            return Err(invalid(
                "publication-state record matched multiple canonical bodies",
            ));
        }
        let retained_bytes = retain_source_budget(self.retained_bytes, claim)?;
        Self::recheck_record(&self.directory, inventory, record)?;
        let recorded = state
            .binding(claim)
            .await?
            .ok_or_else(|| invalid("retained publication binding disappeared"))?;
        Self::recheck_record(&self.directory, inventory, record)?;
        if recorded != measured {
            return Err(invalid(
                "publication-state binding contradicts actual kernel seal",
            ));
        }
        let body = Body {
            parent: parent.try_clone()?,
            name: name.to_owned(),
            file: file.try_clone()?,
            observed,
            measured,
            verified,
        };
        Self::recheck_body(inventory, &body)?;
        record.body = Some(body);
        self.retained_bytes = retained_bytes;
        Ok(())
    }

    fn recheck_body(inventory: &NativeInventory, body: &Body) -> io::Result<()> {
        body.verified.recheck(inventory)?;
        inventory.check(&body.parent, Custody::Publisher, InodeKind::Directory)?;
        let current = open(&body.parent, &body.name, false)?;
        inventory.check(&current, Custody::Publisher, InodeKind::File)?;
        inventory.check(&body.file, Custody::Publisher, InodeKind::File)?;
        if !same_inode_snapshot(&body.observed, &current.metadata()?)
            || !same_inode_snapshot(&body.observed, &body.file.metadata()?)
            || crate::verity::measure(&current)? != body.measured
            || crate::verity::measure(&body.file)? != body.measured
        {
            return Err(invalid("canonical binding body or seal changed"));
        }
        body.verified.recheck(inventory)
    }

    /// Rechecks exhaustive state and synchronizes actual matched record custody.
    ///
    /// # Errors
    /// Rejects unmatched records, changed physical entries or durability failure.
    pub(super) fn finish(&mut self, inventory: &NativeInventory) -> io::Result<()> {
        for record in &mut self.records {
            let body = record
                .body
                .as_ref()
                .ok_or_else(|| invalid("unreconciled publication-state record"))?;
            Self::recheck_body(inventory, body)?;
            Self::recheck_record(&self.directory, inventory, record)?;
            // No model callback acknowledges durability: these are the retained
            // actual record inode and its actual private containing directory.
            record.file.sync_all()?;
        }
        self.directory.sync_all()?;
        for record in &mut self.records {
            let body = record
                .body
                .as_ref()
                .ok_or_else(|| invalid("unreconciled publication-state record"))?;
            Self::recheck_body(inventory, body)?;
            Self::recheck_record(&self.directory, inventory, record)?;
        }
        let actual = names(&self.directory, MAX_CANDIDATES)?;
        let mut expected: Vec<_> = self
            .records
            .iter()
            .map(|record| record.name.clone())
            .collect();
        expected.sort();
        if actual != expected {
            return Err(invalid("publication-state physical record set changed"));
        }
        for record in &self.records {
            let body = record
                .body
                .as_ref()
                .ok_or_else(|| invalid("unreconciled publication-state record"))?;
            Self::recheck_body(inventory, body)?;
        }
        Ok(())
    }
}
