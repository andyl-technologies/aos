//! Associates bounded publication state with retained native candidates.
//!
//! The existing portable binding parser remains authoritative for its private
//! format. Record names never supply a content claim. Known historical leases
//! remain checked metadata without supplying a body, pin or current deadline.
//! Unknown, orphaned binding and incomplete state stays unresolved, without
//! deletion or replacement. Manifest claims keep their actual verified metadata
//! pack/index and native custody through finish. A well-formed conflicting
//! binding remains an unchanged candidate for funded adoption to quarantine;
//! an absent seal, writable mode or plaintext mismatch remains adoption work.
//! Names-only inventory never grants binding or serving authority.

use super::*;
use std::os::unix::fs::MetadataExt;
use terrane_sdk::host::publication::MAX_RETIREMENT_RECORD_BYTES;
use terrane_sdk::host::publication::{FsPublicationState, PublicationState, VerityBinding};

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
        .checked_mul(std::mem::size_of::<terrane_format::manifest::ChunkRef>())
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
    seal: Option<VerityBinding>,
    claim: SealedClaim,
}

/// Records actual kernel seal presence without treating other query errors as absence.
fn observed_seal(file: &File) -> io::Result<Option<VerityBinding>> {
    match crate::verity::measure(file) {
        Ok(binding) => Ok(Some(binding)),
        Err(error) if error.raw_os_error() == Some(libc::ENODATA) => Ok(None),
        Err(error) => Err(error),
    }
}

struct Record {
    name: String,
    file: File,
    observed: std::fs::Metadata,
    bytes: Vec<u8>,
    kind: RecordKind,
    body: Option<Body>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RecordKind {
    Binding,
    Retirement,
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
            let kind = if name.starts_with("retirement-") {
                RecordKind::Retirement
            } else {
                let (domain, content) = name
                    .strip_suffix(".toml")
                    .and_then(|stem| stem.split_once('-'))
                    .ok_or_else(|| invalid("unresolved publication-state record name"))?;
                digest(domain, 32)?;
                digest(content, 32)?;
                RecordKind::Binding
            };
            let mut file = open(&directory, &name, false)?;
            inventory.check(&file, Custody::Publisher, InodeKind::File)?;
            let observed = file.metadata()?;
            let bound = if kind == RecordKind::Retirement {
                MAX_RETIREMENT_RECORD_BYTES
            } else {
                MAX_RECORD
            };
            let canonical = bytes(&mut file, bound)?;
            if kind == RecordKind::Retirement {
                // A valid historical lease is metadata, never an existing
                // body, pin, current expiry or recovery-completion receipt.
                lease_records::validate(inventory, &name, &canonical)?;
            }
            retained_bytes = add_retained(retained_bytes, canonical.capacity())?;
            if !same_inode_snapshot(&observed, &file.metadata()?) {
                return Err(invalid("publication-state record changed during capture"));
            }
            records.push(Record {
                name,
                file,
                observed,
                bytes: canonical,
                kind,
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
        let bound = if record.kind == RecordKind::Retirement {
            MAX_RETIREMENT_RECORD_BYTES
        } else {
            MAX_RECORD
        };
        if !same_inode_snapshot(&record.observed, &named.metadata()?)
            || !same_inode_snapshot(&record.observed, &record.file.metadata()?)
            || bytes(&mut named, bound)? != record.bytes
            || bytes(&mut record.file, bound)? != record.bytes
        {
            return Err(invalid("publication-state inode or bytes changed"));
        }
        Ok(())
    }

    /// Associates a parsed record with an independently reconstructed content claim.
    ///
    /// A matching private record supplies no seal or plaintext authority. Funded
    /// native adoption verifies the actual inode and quarantines a rejection.
    ///
    /// # Errors
    /// Rejects changed sources/custody, invalid claim metadata, malformed state,
    /// uncertain or changed kernel observations and exhausted retained-metadata
    /// budgets. Actual plaintext, mode and seal validity remain adoption work.
    pub(super) async fn reconcile(
        &mut self,
        inventory: &NativeInventory,
        parent: &File,
        name: &str,
        file: &mut File,
        reconstructed: SealedClaim,
    ) -> io::Result<()> {
        let claim = reconstructed.claim();
        reconstructed.recheck(inventory)?;
        inventory.check_sealed_candidate(file)?;
        let observed = file.metadata()?;
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
            // This remains an unadopted candidate, not a verified body or
            // reconstructed binding. Actual funded adoption must verify its
            // plaintext and quarantine a mismatch while retaining metadata.
            reconstructed.recheck(inventory)?;
            if !same_inode_snapshot(&observed, &file.metadata()?) {
                return Err(invalid("unbound inventory candidate changed"));
            }
            return Ok(());
        };
        if record.kind != RecordKind::Binding || record.body.is_some() {
            return Err(invalid(
                "publication-state record matched multiple canonical bodies",
            ));
        }
        let seal = observed_seal(file)?;
        reconstructed.recheck(inventory)?;
        if !same_inode_snapshot(&observed, &file.metadata()?) || observed_seal(file)? != seal {
            return Err(invalid(
                "canonical inventory inode changed during observation",
            ));
        }
        let retained_bytes = retain_source_budget(self.retained_bytes, claim)?;
        Self::recheck_record(&self.directory, inventory, record)?;
        // Parse the exact retained record against the independently reconstructed
        // claim. Inventory returns keys only: rejecting a well-formed measurement
        // conflict here would prevent funded adoption from quarantining the actual
        // inode under HOST-7. Adoption still compares the original stored binding
        // with the kernel measurement before any backing descriptor can escape.
        let _recorded = state
            .binding(claim)
            .await?
            .ok_or_else(|| invalid("retained publication binding disappeared"))?;
        Self::recheck_record(&self.directory, inventory, record)?;
        let body = Body {
            parent: parent.try_clone()?,
            name: name.to_owned(),
            file: file.try_clone()?,
            observed,
            seal,
            claim: reconstructed,
        };
        Self::recheck_body(inventory, &body)?;
        record.body = Some(body);
        self.retained_bytes = retained_bytes;
        Ok(())
    }

    fn recheck_body(inventory: &NativeInventory, body: &Body) -> io::Result<()> {
        body.claim.recheck(inventory)?;
        inventory.check(&body.parent, Custody::Publisher, InodeKind::Directory)?;
        let current = open(&body.parent, &body.name, false)?;
        inventory.check_sealed_candidate(&current)?;
        inventory.check_sealed_candidate(&body.file)?;
        if !same_inode_snapshot(&body.observed, &current.metadata()?)
            || !same_inode_snapshot(&body.observed, &body.file.metadata()?)
            || observed_seal(&current)? != body.seal
            || observed_seal(&body.file)? != body.seal
        {
            return Err(invalid("canonical binding body or seal changed"));
        }
        body.claim.recheck(inventory)
    }

    fn recheck_binding(inventory: &NativeInventory, record: &Record) -> io::Result<()> {
        match (record.kind, record.body.as_ref()) {
            (RecordKind::Binding, Some(body)) => Self::recheck_body(inventory, body),
            (RecordKind::Retirement, None) => Ok(()),
            _ => Err(invalid("unreconciled publication-state record")),
        }
    }

    /// Rechecks exhaustive state and synchronizes actual matched record custody.
    ///
    /// # Errors
    /// Rejects unmatched records, changed physical entries or durability failure.
    pub(super) fn finish(&mut self, inventory: &NativeInventory) -> io::Result<()> {
        for record in &mut self.records {
            Self::recheck_binding(inventory, record)?;
            Self::recheck_record(&self.directory, inventory, record)?;
            // No model callback acknowledges durability: these are the retained
            // actual record inode and its actual private containing directory.
            record.file.sync_all()?;
        }
        self.directory.sync_all()?;
        for record in &mut self.records {
            Self::recheck_binding(inventory, record)?;
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
            Self::recheck_binding(inventory, record)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use terrane_format::chunking::ChunkProfile;
    use terrane_format::manifest::{ChunkRef, Manifest};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn retained_manifest_budget_includes_canonical_and_decoded_payloads() {
        let profile = ChunkProfile::new(16, 32, 64, 48, 2, [0; 32]).unwrap();
        let plaintext: Vec<u8> = (0..70).collect();
        let manifest = Manifest {
            size: plaintext.len() as u64,
            chunks: [&plaintext[..40], &plaintext[40..]]
                .into_iter()
                .map(|bytes| ChunkRef {
                    digest: TERRANE_V1
                        .calculate(IdentityKind::Chunk, bytes)
                        .unwrap()
                        .terrane_v1_digest()
                        .unwrap(),
                    length: bytes.len() as u64,
                })
                .collect(),
            media_type: Some("application/octet-stream".into()),
            hashes: BTreeMap::from([(
                "blake3".into(),
                blake3::hash(&plaintext).as_bytes().to_vec(),
            )]),
        };
        let canonical = manifest.encode(&profile).unwrap();
        let identity = manifest.identity(&profile).unwrap();
        let claim = PublicationClaim::new(
            "public".into(),
            PublicationRecipe::Manifest {
                object: Descriptor::from_identity(&TERRANE_V1, &identity, &canonical).unwrap(),
                canonical_manifest: canonical,
            },
            &profile,
        )
        .unwrap();

        let charge = retain_source_budget(0, &claim).unwrap();
        let canonical_bytes = claim.canonical_manifest().unwrap().len();
        assert!(charge > canonical_bytes);
        let limit = HostReadLimits::default().max_allocation_bytes;
        assert_eq!(retain_source_budget(limit - charge, &claim).unwrap(), limit);
        // A record-only budget would fit, but retaining the real reconstruction
        // claim must refuse before it becomes part of the inventory snapshot.
        assert!(retain_source_budget(limit - canonical_bytes, &claim).is_err());
        assert!(retain_source_budget(limit - charge + 1, &claim).is_err());
        assert!(add_retained(usize::MAX, 1).is_err());
    }

    #[test]
    fn retained_snapshot_rejects_mode_links_and_canonical_inode_replacement() {
        let root = std::env::temp_dir().join(format!(
            "terrane-inventory-binding-snapshot-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("body");
        std::fs::write(&path, b"retained body").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let retained = File::open(&path).unwrap();
        let expected = retained.metadata().unwrap();

        assert!(same_inode_snapshot(
            &expected,
            &retained.metadata().unwrap()
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!same_inode_snapshot(
            &expected,
            &retained.metadata().unwrap()
        ));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let before_link = retained.metadata().unwrap();
        std::fs::hard_link(&path, root.join("alias")).unwrap();
        assert!(!same_inode_snapshot(
            &before_link,
            &retained.metadata().unwrap()
        ));

        std::fs::rename(&path, root.join("old-body")).unwrap();
        std::fs::write(&path, b"retained body").unwrap();
        assert!(!same_inode_snapshot(
            &retained.metadata().unwrap(),
            &std::fs::metadata(path).unwrap()
        ));

        drop(retained);
        std::fs::remove_dir_all(root).unwrap();
    }
}
