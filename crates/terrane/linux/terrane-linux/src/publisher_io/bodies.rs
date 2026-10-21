//! Retains encoded-body namespace custody independently of content verification.
//!
//! Chunk bytes remain untrusted until the cache performs HOST-14 verification.
//! A pack token retains both pack and detached-index inodes as one unit.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_format::pack_format::{HEADER_SIZE, Header};
use terrane_sdk::host::publication::RetirementInode;

use super::{NativeBodyKey, NativePublisherConfig};

pub(super) struct BodyIo {
    chunks: File,
    objects: File,
    pending: File,
    quarantine: File,
    uid: u32,
    gid: u32,
    device: u64,
    #[cfg(feature = "native-test-fixtures")]
    finish_first_unlink: std::sync::Mutex<Option<super::worker::WorkerGate>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Location {
    Canonical,
    Pending,
    Quarantined,
}

struct Member {
    file: File,
    parent: File,
    canonical: String,
    pending: String,
    location: Location,
    // A pack/index unit's independent leases distinguish its two members.
    lease_class: u8,
}

pub(super) struct EncodedUnit {
    members: Vec<Member>,
    missing: Option<MissingMember>,
}

/// Retains absence to recheck before removing the surviving retirement member.
#[derive(Clone, Copy, Eq, PartialEq)]
struct MissingMember {
    pack_id: [u8; 16],
    kind: IdentityKind,
}

pub(super) struct LeaseInput {
    pub key: Vec<u8>,
    pub incarnation: RetirementInode,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn readonly(parent: &File, name: &str, directory: bool) -> io::Result<File> {
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    Ok(File::from(fs::openat(parent, name, flags, Mode::empty())?))
}

impl BodyIo {
    pub(super) fn open(config: &NativePublisherConfig) -> io::Result<Self> {
        let open = |name: &str| -> io::Result<File> {
            Ok(File::from(fs::openat2(
                fs::CWD,
                config.layout_root.join(name),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )?))
        };
        let chunks = open("chunks")?;
        let device = chunks.metadata()?.dev();
        Ok(Self {
            chunks,
            objects: open("objects")?,
            pending: open("pending-delete")?,
            quarantine: open("quarantine")?,
            uid: config.content_uid,
            gid: config.content_gid,
            device,
            #[cfg(feature = "native-test-fixtures")]
            finish_first_unlink: std::sync::Mutex::new(None),
        })
    }

    #[cfg(feature = "native-test-fixtures")]
    pub(super) fn with_finish_gate(mut self, gate: Option<super::worker::WorkerGate>) -> Self {
        self.finish_first_unlink = std::sync::Mutex::new(gate);
        self
    }

    #[cfg(feature = "native-test-fixtures")]
    fn wait_finish_gate(&self) -> io::Result<()> {
        let gate = self
            .finish_first_unlink
            .lock()
            .map_err(|_| io::Error::other("finish gate poisoned"))?
            .take();
        if let Some(gate) = gate {
            gate.wait()?;
        }
        Ok(())
    }

    fn check(&self, file: &File, directory: bool) -> io::Result<()> {
        let metadata = file.metadata()?;
        if metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.dev() != self.device
            || metadata.mode() & 0o002 != 0
            || (directory && (!metadata.is_dir() || metadata.mode() & 0o2020 != 0o2020))
            || (!directory && !metadata.is_file())
        {
            return Err(invalid("unsafe encoded-body inode custody"));
        }
        let expected = crate::host_quota::NativeProject::inspect(&self.chunks)?;
        let actual = crate::host_quota::NativeProject::inspect(file)?;
        if actual.project_id != expected.project_id {
            return Err(invalid("encoded-body inode has a foreign charge owner"));
        }
        Ok(())
    }

    pub(super) fn check_manifest_pack(&self, file: &File) -> io::Result<()> {
        self.check(file, false)?;
        let expected = crate::host_quota::NativeProject::inspect(&self.chunks)?;
        let actual = crate::host_quota::NativeProject::inspect(file)?;
        if actual.device != expected.device
            || actual.project_id != expected.project_id
            || crate::host_quota::filesystem_uuid(file)?
                != crate::host_quota::filesystem_uuid(&self.chunks)?
        {
            return Err(invalid(
                "manifest metadata pack belongs to another configured quota domain",
            ));
        }
        Ok(())
    }

    pub(super) fn inspect_chunk(
        &self,
        descriptor: &Descriptor,
        codec: u8,
        pending: bool,
    ) -> io::Result<EncodedUnit> {
        let digest = hex(descriptor.digest());
        let parent = readonly(&self.chunks, &digest[..2], true)?;
        self.check(&parent, true)?;
        if pending {
            parent.sync_all()?;
            self.pending.sync_all()?;
        }
        let canonical = format!("{digest}.{codec}");
        let file = if pending {
            readonly(&self.pending, &digest, false)?
        } else {
            readonly(&parent, &canonical, false)?
        };
        self.check(&file, false)?;
        if pending {
            let mut prefix = [0];
            let mut reader = &file;
            reader.read_exact(&mut prefix)?;
            if prefix != [codec] {
                return Err(invalid("pending chunk codec disagrees with its typed key"));
            }
            reader.seek(SeekFrom::Start(0))?;
        }
        // The descriptor's plaintext size/hash is deliberately not accepted as
        // verified here. Dictionary resolution belongs to the cache verifier.
        Ok(EncodedUnit {
            missing: None,
            members: vec![Member {
                file,
                parent,
                canonical,
                pending: digest,
                location: if pending {
                    Location::Pending
                } else {
                    Location::Canonical
                },
                lease_class: 0,
            }],
        })
    }

    pub(super) fn inspect_pack(
        &self,
        pack_id: &[u8; 16],
        pending: bool,
    ) -> io::Result<EncodedUnit> {
        let id = hex(pack_id);
        let packs = readonly(&self.objects, "pack", true)?;
        self.check(&packs, true)?;
        let parent = readonly(&packs, &id[..2], true)?;
        self.check(&parent, true)?;
        parent.sync_all()?;
        self.pending.sync_all()?;
        let mut members = Vec::new();
        let mut missing = None;
        for (extension, kind, lease_class) in [
            ("pack", IdentityKind::Pack, 0),
            ("idx", IdentityKind::Index, 1),
        ] {
            let canonical = format!("{id}.{extension}");
            let canonical_file = match readonly(&parent, &canonical, false) {
                Ok(file) => Some(file),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            let pending_file = self.find_pending_pack(pack_id, kind)?;
            let (file, pending_name, location) = match (canonical_file, pending_file) {
                (Some(_), Some(_)) => return Err(invalid("pack member exists in both namespaces")),
                (Some(file), None) => {
                    // Canonical filenames bind the unit's namespace, not the
                    // validity of encoded bytes or their content identities.
                    self.check(&file, false)?;
                    let digest = content_digest(&file, kind)?;
                    (file, digest, Location::Canonical)
                }
                (None, Some((file, name))) => (file, name, Location::Pending),
                (None, None) if pending => {
                    missing = Some(MissingMember {
                        pack_id: *pack_id,
                        kind,
                    });
                    continue;
                }
                (None, None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "pack retirement requires both real pack and detached-index members",
                    ));
                }
            };
            members.push(Member {
                file,
                parent: parent.try_clone()?,
                canonical,
                pending: pending_name,
                location,
                lease_class,
            });
        }
        let mut unit = EncodedUnit { members, missing };
        if pending {
            if !unit.any_pending() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "pack unit is not pending",
                ));
            }
            // A crash can leave only one member renamed. Reconcile both actual
            // members before granting a lifecycle token or changing service.
            unit.retire(self)?;
        } else if unit.any_pending() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "pack pair requires pending reconciliation",
            ));
        }
        unit.sync_names(self)?;
        Ok(unit)
    }

    fn require_member_absent(&self, missing: MissingMember) -> io::Result<()> {
        let id = hex(&missing.pack_id);
        let extension = match missing.kind {
            IdentityKind::Pack => "pack",
            IdentityKind::Index => "idx",
            _ => return Err(invalid("invalid missing pack-member kind")),
        };
        let packs = readonly(&self.objects, "pack", true)?;
        self.check(&packs, true)?;
        let parent = readonly(&packs, &id[..2], true)?;
        self.check(&parent, true)?;
        parent.sync_all()?;
        self.pending.sync_all()?;
        match readonly(&parent, &format!("{id}.{extension}"), false) {
            Ok(_) => {
                return Err(invalid(
                    "missing pack member became canonical; inspect the pair again",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if self
            .find_pending_pack(&missing.pack_id, missing.kind)?
            .is_some()
        {
            return Err(invalid(
                "missing pack member became pending; inspect the pair again",
            ));
        }
        Ok(())
    }

    fn find_pending_pack(
        &self,
        pack_id: &[u8; 16],
        kind: IdentityKind,
    ) -> io::Result<Option<(File, String)>> {
        let mut found = None;
        for entry in fs::Dir::read_from(&self.pending)? {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes.len() != 64
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                continue;
            }
            let name = std::str::from_utf8(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let file = readonly(&self.pending, name, false)?;
            let metadata = file.metadata()?;
            // Sealed and chunk entries share this grammar, but have different
            // custody/header/identity domains. They are not pack candidates.
            if metadata.uid() != self.uid || metadata.gid() != self.gid || !metadata.is_file() {
                continue;
            }
            let mut reader = &file;
            let mut header_bytes = [0; HEADER_SIZE];
            match reader.read_exact(&mut header_bytes) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => continue,
                Err(error) => return Err(error),
            }
            match Header::decode(&header_bytes) {
                Ok(header) if header.id() == pack_id => {}
                _ => continue,
            }
            if content_digest(&file, kind)? != name {
                continue;
            }
            self.check(&file, false)?;
            if found.is_some() {
                return Err(invalid("duplicate pending pack member"));
            }
            found = Some((file, name.to_owned()));
        }
        Ok(found)
    }
}

impl EncodedUnit {
    pub(super) fn handle(&self) -> io::Result<File> {
        self.members
            .first()
            .ok_or_else(|| invalid("empty encoded body unit"))?
            .file
            .try_clone()
    }

    pub(super) fn same_inode(&self, other: &Self) -> io::Result<bool> {
        if self.members.len() != other.members.len() || self.missing != other.missing {
            return Ok(false);
        }
        for (left, right) in self.members.iter().zip(&other.members) {
            if left.lease_class != right.lease_class {
                return Ok(false);
            }
            let left = left.file.metadata()?;
            let right = right.file.metadata()?;
            if left.dev() != right.dev() || left.ino() != right.ino() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn any_pending(&self) -> bool {
        self.members
            .iter()
            .any(|member| member.location == Location::Pending)
    }

    pub(super) fn lease_inputs(&self, key: &NativeBodyKey) -> io::Result<Vec<LeaseInput>> {
        let mut encoding = match key {
            NativeBodyKey::Chunk { descriptor, codec } => {
                let mut bytes = vec![1, *codec];
                bytes.extend_from_slice(&descriptor.encode());
                bytes
            }
            NativeBodyKey::Pack { pack_id } => {
                let mut bytes = vec![2];
                bytes.extend_from_slice(pack_id);
                bytes
            }
            NativeBodyKey::Sealed { .. } => return Err(invalid("sealed body used encoded leases")),
        };
        let mut leases = Vec::new();
        for member in &self.members {
            let metadata = member.file.metadata()?;
            encoding.push(member.lease_class);
            leases.push(LeaseInput {
                key: encoding.clone(),
                incarnation: RetirementInode {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    changed_seconds: metadata.ctime(),
                    changed_nanoseconds: metadata.ctime_nsec(),
                },
            });
            encoding.pop();
        }
        Ok(leases)
    }

    pub(super) fn sync_names(&self, io: &BodyIo) -> io::Result<()> {
        for member in &self.members {
            member.parent.sync_all()?;
        }
        io.pending.sync_all()
    }

    /// Moves every original member into quarantine without content verification.
    ///
    /// Both names of a pack/index pair are checked before the first effect.
    /// Any partial progress remains in this unit for recovery; this operation
    /// never restores, deletes or replaces an inode after a failed exchange.
    ///
    /// # Errors
    /// Refuses missing members, foreign custody, changed canonical inodes,
    /// existing quarantine destinations or actual rename/synchronization errors.
    pub(super) fn quarantine(&mut self, io: &BodyIo, token: &[u8; 32]) -> io::Result<()> {
        if self.missing.is_some() || self.members.is_empty() {
            return Err(invalid("quarantine requires every original encoded member"));
        }
        io.check(&io.quarantine, true)?;
        let names = self
            .members
            .iter()
            .map(|member| format!("encoded.{}.{}", member.canonical, hex(token)))
            .collect::<Vec<_>>();
        for (member, name) in self.members.iter().zip(&names) {
            if member.location != Location::Canonical {
                return Err(invalid("encoded quarantine requires canonical originals"));
            }
            io.check(&member.parent, true)?;
            io.check(&member.file, false)?;
            compare(
                &member.file,
                &readonly(&member.parent, &member.canonical, false)?,
            )?;
            match fs::statat(&io.quarantine, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "encoded quarantine destination exists",
                    ));
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error.into()),
            }
        }
        for (member, name) in self.members.iter_mut().zip(&names) {
            // Recheck the exact original immediately before each no-replace move.
            compare(
                &member.file,
                &readonly(&member.parent, &member.canonical, false)?,
            )?;
            fs::renameat_with(
                &member.parent,
                member.canonical.as_str(),
                &io.quarantine,
                name.as_str(),
                fs::RenameFlags::NOREPLACE,
            )?;
            member.location = Location::Quarantined;
            member.parent.sync_all()?;
            io.quarantine.sync_all()?;
        }
        Ok(())
    }

    pub(super) fn retire(&mut self, io: &BodyIo) -> io::Result<()> {
        for member in &mut self.members {
            if member.location == Location::Pending {
                compare(
                    &member.file,
                    &readonly(&io.pending, &member.pending, false)?,
                )?;
                continue;
            }
            if member.location != Location::Canonical {
                return Err(invalid("quarantined encoded member cannot retire"));
            }
            compare(
                &member.file,
                &readonly(&member.parent, &member.canonical, false)?,
            )?;
            fs::renameat_with(
                &member.parent,
                member.canonical.as_str(),
                &io.pending,
                member.pending.as_str(),
                fs::RenameFlags::NOREPLACE,
            )?;
            // Retain the actual intermediate location even when fsync fails.
            member.location = Location::Pending;
            member.parent.sync_all()?;
            io.pending.sync_all()?;
        }
        Ok(())
    }

    pub(super) fn restore(&mut self, io: &BodyIo) -> io::Result<()> {
        if self.missing.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "incomplete pack unit cannot restore or establish a missing member",
            ));
        }
        for member in &mut self.members {
            if member.location == Location::Canonical {
                compare(
                    &member.file,
                    &readonly(&member.parent, &member.canonical, false)?,
                )?;
                continue;
            }
            if member.location != Location::Pending {
                return Err(invalid("quarantined encoded member cannot restore"));
            }
            compare(
                &member.file,
                &readonly(&io.pending, &member.pending, false)?,
            )?;
            fs::renameat_with(
                &io.pending,
                member.pending.as_str(),
                &member.parent,
                member.canonical.as_str(),
                fs::RenameFlags::NOREPLACE,
            )?;
            member.location = Location::Canonical;
            io.pending.sync_all()?;
            member.parent.sync_all()?;
        }
        Ok(())
    }

    pub(super) fn finish(&mut self, io: &BodyIo) -> io::Result<()> {
        if let Some(missing) = self.missing {
            // A surviving member grants no missing-peer validity. Recheck both
            // namespaces immediately before removing the original survivor.
            io.require_member_absent(missing)?;
        }
        if self
            .members
            .iter()
            .any(|member| member.location != Location::Pending)
        {
            return Err(invalid(
                "pack/chunk retirement has not reconciled every member",
            ));
        }
        // Validate the entire unit before removing its first name.
        for member in &self.members {
            compare(
                &member.file,
                &readonly(&io.pending, &member.pending, false)?,
            )?;
        }
        for member in &self.members {
            fs::unlinkat(&io.pending, member.pending.as_str(), AtFlags::empty())?;
            io.pending.sync_all()?;
            #[cfg(feature = "native-test-fixtures")]
            if member.lease_class == 0 && self.members.len() > 1 {
                // The fixture can now cause a genuine second unlink failure.
                // It supplies no success result, state acknowledgment or proof.
                io.wait_finish_gate()?;
            }
        }
        Ok(())
    }
}

fn compare(expected: &File, actual: &File) -> io::Result<()> {
    let expected = expected.metadata()?;
    let actual = actual.metadata()?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(invalid("encoded-body incarnation changed"));
    }
    Ok(())
}

pub(super) fn content_digest(file: &File, kind: IdentityKind) -> io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(
        TERRANE_V1
            .domain(kind)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .as_bytes(),
    );
    hasher.update(&[0]);
    let mut reader = file;
    reader.seek(SeekFrom::Start(0))?;
    let mut buffer = [0; 65536];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    reader.seek(SeekFrom::Start(0))?;
    Ok(hasher.finalize().to_hex().to_string())
}
