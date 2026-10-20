//! Seeds actual pack/index retirement candidates before either native role starts.
//!
//! Administrative inputs include both pending, split and surviving-member cases.
//! No lease, adoption receipt or cache policy is manufactured by this fixture.

use super::{Fixture, Inputs, directory, hex, invalid, require_seed_capabilities, write};
use rustix::process::{Gid, Uid};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_linux::host_quota::NativeProject;
use terrane_sdk::pack::{EntryKind, PackClass, PackId, PackWriter};

#[derive(Clone, Copy)]
enum Case {
    Expired,
    Unknown,
    PackPending,
    IndexPending,
    OrphanIndex,
    OrphanPack,
    Foreign,
}

impl Case {
    fn from_domain(domain: &str) -> io::Result<Self> {
        match domain {
            "tenant:pending-pack-expired" => Ok(Self::Expired),
            "tenant:pending-pack-unknown" => Ok(Self::Unknown),
            "tenant:pending-pack-split-pack" => Ok(Self::PackPending),
            "tenant:pending-pack-split-index" => Ok(Self::IndexPending),
            "tenant:pending-pack-orphan-index" => Ok(Self::OrphanIndex),
            "tenant:pending-pack-orphan-pack" => Ok(Self::OrphanPack),
            "tenant:pending-pack-foreign" => Ok(Self::Foreign),
            _ => Err(invalid(
                "pending pack fixture requires its isolated native domain",
            )),
        }
    }
}

/// Checks the exact isolated pack-case domain without granting native authority.
///
/// # Errors
/// Refuses every domain outside the explicit administrative fixture cases.
pub(super) fn require_domain(inputs: &Inputs) -> io::Result<()> {
    Case::from_domain(&inputs.domain).map(|_| ())
}

/// Seeds real encoded pack members without fabricating a retirement decision.
///
/// # Errors
/// Refuses unexpected administration, domain, ownership, project inheritance,
/// existing names or failed native write/synchronization effects.
pub(crate) fn seed() -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid("pending pack seed requires root administration"));
    }
    require_seed_capabilities()?;
    let inputs = Inputs::load()?;
    let case = Case::from_domain(&inputs.domain)?;
    let fixture = Fixture::new()?;
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let id = PackId::from_random_bytes(random);
    let mut writer = PackWriter::new(id, PackClass::Meta, false);
    writer
        .append_raw(EntryKind::Manifest, &fixture.manifest)
        .map_err(io::Error::other)?;
    let pack = writer.seal().map_err(io::Error::other)?;

    let packs = inputs.root.join("objects/pack");
    directory(&packs, 840, 845, 0o2770)?;
    let parent = packs.join(format!("{:02x}", id.as_bytes()[0]));
    directory(&parent, 840, 845, 0o2770)?;
    for (kind, bytes, canonical) in [
        (
            IdentityKind::Pack,
            pack.bytes(),
            inputs.root.join(id.pack_key()),
        ),
        (
            IdentityKind::Index,
            pack.index_object(),
            inputs.root.join(id.index_key()),
        ),
    ] {
        if matches!(
            (case, kind),
            (Case::OrphanIndex, IdentityKind::Pack) | (Case::OrphanPack, IdentityKind::Index)
        ) {
            continue;
        }
        let canonical_member = matches!(
            (case, kind),
            (Case::PackPending | Case::Foreign, IdentityKind::Index)
                | (Case::IndexPending, IdentityKind::Pack)
        );
        let path = if canonical_member {
            canonical
        } else {
            let identity = TERRANE_V1
                .calculate(kind, bytes)
                .map_err(io::Error::other)?;
            inputs
                .root
                .join("pending-delete")
                .join(hex(identity.digest()))
        };
        if matches!((case, kind), (Case::Foreign, IdentityKind::Pack)) {
            foreign_member(&inputs, &path, bytes, id)?;
        } else {
            write(&inputs, &path, bytes, 840, 845, 0o640)?;
        }
    }
    for path in [
        &parent,
        &packs,
        &inputs.root.join("objects"),
        &inputs.root.join("pending-delete"),
    ] {
        File::open(path)?.sync_all()?;
    }
    println!("SEEDED actual pending pack/index candidates; no content or retirement authority");
    Ok(())
}

fn foreign_member(inputs: &Inputs, target: &Path, bytes: &[u8], id: PackId) -> io::Result<()> {
    // The explicit host administrator injects a preexisting foreign charge
    // owner by moving an inherited inode, never by changing its project ID.
    let root = std::env::var_os("TERRANE_CLEANUP_FOREIGN_ROOT")
        .ok_or_else(|| invalid("missing explicit foreign seed root"))?;
    let source_parent = std::path::PathBuf::from(root).join("chunks");
    let source = source_parent.join(format!("pending-pack-{id}"));
    let foreign: u32 = std::env::var("TERRANE_CLEANUP_FOREIGN_PROJECT")
        .map_err(io::Error::other)?
        .parse()
        .map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&source)?;
    let project = NativeProject::inspect(&file)?;
    if project.project_id != foreign || project.project_id == inputs.project {
        return Err(invalid(
            "foreign seed lost its original inherited charge owner",
        ));
    }
    file.write_all(bytes)?;
    rustix::fs::fchown(&file, Some(Uid::from_raw(840)), Some(Gid::from_raw(845)))?;
    file.set_permissions(fs::Permissions::from_mode(0o640))?;
    file.sync_all()?;
    drop(file);
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &source,
        rustix::fs::CWD,
        target,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(&source_parent)?.sync_all()?;
    if NativeProject::inspect(&File::open(target)?)?.project_id != foreign {
        return Err(invalid(
            "foreign seed changed project during namespace transfer",
        ));
    }
    Ok(())
}
