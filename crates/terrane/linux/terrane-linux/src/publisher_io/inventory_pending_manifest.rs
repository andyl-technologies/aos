//! Reconstructs inventory claims from original pending metadata pairs.
//!
//! These read-only sources grant no adoption, pin or serving authority. Recovery
//! must still restore the actual pair, repeat canonical inspection and fund
//! adoption before resuming. Private publication records never supply content.

use super::*;
use std::collections::BTreeMap;
use std::fs::Metadata;
use terrane_format::identity::Identity;
use terrane_sdk::{
    host::cache::reconstruct_pack_index,
    pack::{EntryKind, PackId, PackReader},
    repository::MetadataValidator,
};

struct Member {
    name: String,
    file: File,
    observed: Metadata,
    identity: Identity,
}

/// Retains both independently verified original pending files for inventory.
pub(super) struct PendingManifest {
    parent: File,
    pack: Member,
    index: Member,
    claim: PublicationClaim,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Member {
    fn capture(
        inventory: &NativeInventory,
        parent: &File,
        name: String,
        identity: Identity,
        limit: usize,
    ) -> io::Result<(Self, Vec<u8>)> {
        let mut file = open(parent, &name, false)?;
        inventory.check(&file, Custody::Content, InodeKind::File)?;
        let observed = file.metadata()?;
        if observed.nlink() != 1 || !matches!(observed.mode() & 0o7777, 0o640 | 0o660) {
            return Err(invalid("pending metadata has unsafe links or mode"));
        }
        let canonical = bytes(&mut file, limit)?;
        TERRANE_V1.verify(&identity, &canonical).map_err(source)?;
        if !state::same_inode_snapshot(&observed, &file.metadata()?) {
            return Err(invalid("pending metadata changed during capture"));
        }
        Ok((
            Self {
                name,
                file,
                observed,
                identity,
            },
            canonical,
        ))
    }

    fn recheck(&self, inventory: &NativeInventory, parent: &File) -> io::Result<()> {
        let mut named = open(parent, &self.name, false)?;
        for file in [&named, &self.file] {
            inventory.check(file, Custody::Content, InodeKind::File)?;
            if !state::same_inode_snapshot(&self.observed, &file.metadata()?) {
                return Err(invalid("pending metadata original incarnation changed"));
            }
        }
        let canonical = bytes(&mut named, HostReadLimits::default().max_allocation_bytes)?;
        TERRANE_V1
            .verify(&self.identity, &canonical)
            .map_err(source)?;
        if !state::same_inode_snapshot(&self.observed, &named.metadata()?) {
            return Err(invalid("pending metadata changed during recheck"));
        }
        Ok(())
    }
}

impl PendingManifest {
    pub(super) fn claim(&self) -> &PublicationClaim {
        &self.claim
    }

    /// Checks the actual pending namespace, custody, original files and bytes.
    ///
    /// # Errors
    /// Refuses replaced parents, names, inodes, project assignments or content.
    pub(super) fn recheck(&self, inventory: &NativeInventory) -> io::Result<()> {
        let current = open(&inventory.root, "pending-delete", true)?;
        inventory.check(&current, Custody::Publisher, InodeKind::Directory)?;
        let expected = self.parent.metadata()?;
        let actual = current.metadata()?;
        if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) {
            return Err(invalid("pending metadata parent incarnation changed"));
        }
        self.pack.recheck(inventory, &current)?;
        self.index.recheck(inventory, &current)
    }
}

/// Finds exact canonical manifest bytes in a completely verified pending pair.
///
/// # Errors
/// Refuses absence, malformed metadata, mismatching original indexes, unsafe
/// native custody, changed physical state or exhausted allocation/name bounds.
pub(super) fn find(
    inventory: &NativeInventory,
    identity: &Identity,
) -> io::Result<PendingManifest> {
    let parent = open(&inventory.root, "pending-delete", true)?;
    inventory.check(&parent, Custody::Publisher, InodeKind::Directory)?;
    let limits = HostReadLimits::default();
    for name in names(&parent, MAX_CANDIDATES)? {
        let mut candidate = open(&parent, &name, false)?;
        if candidate.metadata()?.uid() != inventory.content_uid {
            continue;
        }
        inventory.check(&candidate, Custody::Content, InodeKind::File)?;
        let mut header = [0; HEADER_SIZE];
        match candidate.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => continue,
            Err(error) => return Err(error),
        }
        let Ok(header) = Header::decode(&header) else {
            continue;
        };
        if !header.is_meta() {
            continue;
        }
        // Pack and index share a header. Only the actual complete-pack digest
        // selects a pack candidate; neither the filename nor its header alone
        // proves a metadata body or an authoritative manifest length.
        if candidate.metadata()?.len() > limits.max_allocation_bytes as u64 {
            return Err(invalid("pending metadata exceeds bounded read window"));
        }
        let pack_identity = TERRANE_V1
            .from_digest(IdentityKind::Pack, &digest(&name, 32)?)
            .map_err(source)?;
        if crate::publisher_io::bodies::content_digest(&candidate, IdentityKind::Pack)? != name {
            continue;
        }
        let (pack, canonical) = Member::capture(
            inventory,
            &parent,
            name,
            pack_identity,
            limits.max_allocation_bytes,
        )?;
        let profile = inventory.location.chunk_profile();
        let verified = reconstruct_pack_index(
            &canonical,
            PackId::from_random_bytes(*header.id()),
            profile,
            &MetadataValidator::new(profile.clone()),
            &BTreeMap::new(),
            limits,
        )
        .map_err(source)?;
        let reader = PackReader::open(&canonical).map_err(source)?;
        let Some(record) = reader.entries().iter().find(|record| {
            record.kind() == EntryKind::Manifest && record.hash().as_slice() == identity.digest()
        }) else {
            continue;
        };
        let index_identity = TERRANE_V1
            .calculate(IdentityKind::Index, verified.bytes())
            .map_err(source)?;
        let (index, index_bytes) = Member::capture(
            inventory,
            &parent,
            hex(index_identity.digest()),
            index_identity,
            limits
                .max_allocation_bytes
                .checked_sub(canonical.len())
                .ok_or_else(|| invalid("pending metadata pair exceeds read window"))?,
        )?;
        if index_bytes != verified.bytes() {
            return Err(invalid("pending index differs from verified complete pack"));
        }
        let start = usize::try_from(record.offset()).map_err(source)?;
        let end = start
            .checked_add(record.body_len() as usize)
            .ok_or_else(|| invalid("pending manifest range overflow"))?;
        let manifest = canonical
            .get(start..end)
            .ok_or_else(|| invalid("pending manifest body range is absent"))?;
        let claim = PublicationClaim::new(
            inventory.location.domain().to_owned(),
            PublicationRecipe::Manifest {
                object: Descriptor::from_identity(&TERRANE_V1, identity, manifest)
                    .map_err(source)?,
                canonical_manifest: manifest.to_vec(),
            },
            profile,
        )?;
        let retained = PendingManifest {
            parent,
            pack,
            index,
            claim,
        };
        retained.recheck(inventory)?;
        return Ok(retained);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no independently verified pending manifest metadata pair",
    ))
}
