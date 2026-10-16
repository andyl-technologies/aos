//! Reconciles bounded inline bindings against independently verified native bytes.
//!
//! The existing portable binding parser remains authoritative for its private
//! format. Record names never supply a content claim. Unknown, orphaned, pending
//! and manifest-backed state stays unresolved, without deletion or replacement.

use super::*;
use std::os::unix::fs::MetadataExt;
use terrane::host::publication::{FsPublicationState, PublicationState};

// Retained Vec capacity is charged, not just initialized payload length. Each
// sequential recheck additionally performs at most two bounded record reads;
// none of those bounded scratch allocations survives the synchronous recheck.
const MAX_RECORD: usize = 65536;

struct Body {
    parent: File,
    name: String,
    file: File,
}

struct Record {
    name: String,
    file: File,
    observed: std::fs::Metadata,
    bytes: Vec<u8>,
    body: Option<Body>,
}

/// Retains exhaustive private records until inline reconciliation completes.
pub(super) struct StateInventory {
    directory: File,
    records: Vec<Record>,
}

fn same_inode_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
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
            retained_bytes = retained_bytes
                .checked_add(canonical.capacity())
                .filter(|total| *total <= HostReadLimits::default().max_allocation_bytes)
                .ok_or_else(|| invalid("publication-state retained byte budget exceeded"))?;
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
        Ok(Self { directory, records })
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

    /// Matches one existing record to independently verified inline content.
    ///
    /// # Errors
    /// Rejects changed custody, invalid content, malformed state or seal conflict.
    pub(super) async fn reconcile_inline(
        &mut self,
        inventory: &NativeInventory,
        parent: &File,
        name: &str,
        file: &mut File,
        key: &NativeBodyKey,
    ) -> io::Result<()> {
        let NativeBodyKey::Sealed { descriptor } = key else {
            return Err(invalid("binding reconciliation requires a sealed key"));
        };
        if TERRANE_V1.kind(descriptor.domain()).map_err(source)? != IdentityKind::Chunk {
            // A matching Manifest filename cannot be accepted by this inline
            // case; the exhaustive final match check keeps it unresolved.
            return Ok(());
        }
        let claim = PublicationClaim::new(
            inventory.location.domain().to_owned(),
            PublicationRecipe::Inline {
                chunk: descriptor.clone(),
            },
            inventory.location.chunk_profile(),
        )?;
        // Only the actual retained private directory supplies this parser path.
        // No request path or private record bytes can create a claim authority.
        let state = FsPublicationState::new(
            TokioLocalFs,
            std::path::PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd())),
        );
        let path = state.binding_record_path(&claim);
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
        inventory.check(file, Custody::Publisher, InodeKind::File)?;
        let measured = crate::verity::measure(file)?;
        file.seek(SeekFrom::Start(0))?;
        claim.verify_reader(file)?;
        let body = Body {
            parent: parent.try_clone()?,
            name: name.to_owned(),
            file: file.try_clone()?,
        };
        Self::recheck_record(&self.directory, inventory, record)?;
        let recorded = state
            .binding(&claim)
            .await?
            .ok_or_else(|| invalid("retained publication binding disappeared"))?;
        Self::recheck_record(&self.directory, inventory, record)?;
        if recorded != measured {
            return Err(invalid(
                "publication-state binding contradicts actual kernel seal",
            ));
        }
        record.body = Some(body);
        Ok(())
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
            let current = open(&body.parent, &body.name, false)?;
            inventory.check(&current, Custody::Publisher, InodeKind::File)?;
            let expected = body.file.metadata()?;
            let actual = current.metadata()?;
            if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) {
                return Err(invalid("canonical binding body incarnation changed"));
            }
            Self::recheck_record(&self.directory, inventory, record)?;
            // No model callback acknowledges durability: these are the retained
            // actual record inode and its actual private containing directory.
            record.file.sync_all()?;
        }
        self.directory.sync_all()?;
        for record in &mut self.records {
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
        Ok(())
    }
}
