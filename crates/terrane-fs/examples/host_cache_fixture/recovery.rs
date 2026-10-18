//! Seeds untrusted cold files and exercises actual manifest recovery in the guest.
//!
//! Explicit root administration seeds canonical metadata and a kernel-sealed
//! candidate before either role starts. These files confer no publication or
//! recovery authority. A separate confined actor invokes the genuine owner,
//! Inspector and publisher channel; only their actual result permits Resume.

use super::config::{HARD_LIMIT, HOLD, Inputs, STATE};
use rustix::process::{Gid, Uid};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use terrane::{
    host::cache::CacheState,
    pack::{EntryKind, PackClass, PackId, PackWriter},
    store::TokioLocalFs,
};
use terrane_core::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_fs::{host_cache::NativeMetadataOwner, host_quota::NativeProject};

struct Fixture {
    plaintext: Vec<u8>,
    manifest: Vec<u8>,
    manifest_hash: String,
    chunks: Vec<ChunkRef>,
}

impl Fixture {
    fn new() -> io::Result<Self> {
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let plaintext = vec![0x5a; profile.minimum() + 1];
        let chunks = profile
            .ranges(&plaintext)
            .map(|range| {
                let identity = TERRANE_V1
                    .calculate(IdentityKind::Chunk, &plaintext[range.clone()])
                    .map_err(io::Error::other)?;
                Ok(ChunkRef {
                    digest: identity.terrane_v1_digest().map_err(io::Error::other)?,
                    length: range.len() as u64,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let manifest = Manifest {
            size: plaintext.len() as u64,
            chunks: chunks.clone(),
            hashes: BTreeMap::from([(
                "blake3".into(),
                blake3::hash(&plaintext).as_bytes().to_vec(),
            )]),
            media_type: None,
        }
        .encode(&profile)
        .map_err(io::Error::other)?;
        let identity = TERRANE_V1
            .calculate(IdentityKind::Manifest, &manifest)
            .map_err(io::Error::other)?;
        Ok(Self {
            plaintext,
            manifest,
            manifest_hash: hex(identity.digest()),
            chunks,
        })
    }
}

/// Seeds actual untrusted files through an explicit administrative fixture action.
///
/// # Errors
/// Refuses a non-root caller, another domain, existing names, wrong project
/// inheritance, failed native writes, synchronization or kernel fs-verity.
pub(super) fn seed(mode: &str) -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid(
            "cold fixture seeding requires explicit root administration",
        ));
    }
    let inputs = Inputs::load()?;
    require_domain(&inputs, mode == "seed-bad-manifest")?;
    let mut fixture = Fixture::new()?;
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let id = PackId::from_random_bytes(random);
    let mut writer = PackWriter::new(id, PackClass::Meta, false);
    writer
        .append_raw(EntryKind::Manifest, &fixture.manifest)
        .map_err(io::Error::other)?;
    let pack = writer.seal().map_err(io::Error::other)?;

    directory(&inputs.root.join("objects/pack"), 840, 845, 0o2770)?;
    let pack_parent = inputs
        .root
        .join("objects/pack")
        .join(format!("{:02x}", id.as_bytes()[0]));
    directory(&pack_parent, 840, 845, 0o2770)?;
    write(
        &inputs,
        &inputs.root.join(id.pack_key()),
        pack.bytes(),
        840,
        845,
        0o660,
    )?;
    write(
        &inputs,
        &inputs.root.join(id.index_key()),
        pack.index_object(),
        840,
        845,
        0o660,
    )?;
    File::open(&pack_parent)?.sync_all()?;
    File::open(inputs.root.join("objects/pack"))?.sync_all()?;
    File::open(inputs.root.join("objects"))?.sync_all()?;

    let sealed_parent = inputs.root.join("sealed").join(&fixture.manifest_hash[..2]);
    directory(&sealed_parent, 841, 841, 0o755)?;
    let sealed = sealed_parent.join(&fixture.manifest_hash);
    if mode == "seed-bad-manifest" {
        fixture.plaintext[0] ^= 1;
    }
    write(&inputs, &sealed, &fixture.plaintext, 841, 841, 0o400)?;
    // The only writer is closed before the actual permanent kernel seal.
    let retained = File::open(&sealed)?;
    terrane_fs::verity::enable(&retained)?;
    retained.sync_all()?;
    File::open(&sealed_parent)?.sync_all()?;
    File::open(inputs.root.join("sealed"))?.sync_all()?;
    println!("SEEDED actual cold manifest candidate; no publication or recovery authority");
    Ok(())
}

fn directory(path: &Path, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    fs::create_dir(path)?;
    let file = File::open(path)?;
    rustix::fs::fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn write(
    inputs: &Inputs,
    path: &Path,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if NativeProject::inspect(&file)?.project_id != inputs.project {
        return Err(invalid("seeded candidate lacks actual project inheritance"));
    }
    file.write_all(bytes)?;
    rustix::fs::fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()
}

/// Exercises genuine manifest reconciliation, including a plaintext mismatch control.
///
/// # Errors
/// Refuses unexpected policy, missing retained funding, changed faulted custody,
/// a mismatching candidate accepted as complete, or failed genuine Resume.
pub(super) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    let bad = mode == "refuse-manifest";
    require_domain(inputs, bad)?;
    if original.is_some() {
        return Err(invalid("manifest recovery requires absent embedded state"));
    }
    let result = runtime.block_on(owner.recover());
    if bad {
        let error = result
            .err()
            .ok_or_else(|| invalid("mismatching plaintext completed recovery"))?;
        println!("REFUSED actual mismatching manifest candidate: {error}");
        check_policy(runtime, inputs, false)?;
        let funded = fs::read(inputs.root.join("state/cache/records.toml"))?;
        let error = runtime
            .block_on(owner.recover())
            .err()
            .ok_or_else(|| invalid("faulted manifest owner completed recovery"))?;
        if error.kind() != io::ErrorKind::WouldBlock
            || error.to_string() != "failed physical work requires native reconciliation"
            || fs::read(inputs.root.join("state/cache/records.toml"))? != funded
        {
            return Err(invalid(
                "manifest refusal lost original funded faulted custody",
            ));
        }
        println!(
            "PASS actual manifest mismatch retained metadata funding and faulted custody; no Resume"
        );
        return Ok(());
    }
    let completed = result?;
    completed.check_current()?;
    if completed.future_hold_bytes() != 2 * HOLD
        || completed.charged_reserved_bytes() > HARD_LIMIT
        || completed.synchronized_retained_inode_bytes() == 0
    {
        return Err(invalid("nonempty recovery lacks actual bounded accounting"));
    }
    check_policy(runtime, inputs, true)?;
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    if fs::read(inputs.root.join("state/cache/records.toml"))? != before {
        return Err(invalid(
            "manifest Resume changed its durable recovery policy",
        ));
    }
    println!(
        "PASS actual manifest recovery reconstructed verified residences and acknowledged Resume; no Ready"
    );
    Ok(())
}

fn check_policy(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    recovered: bool,
) -> io::Result<()> {
    let fixture = Fixture::new()?;
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("manifest recovery snapshot missing"))?;
    let ids: BTreeSet<_> = state.reservations.iter().map(|row| &row.id).collect();
    let expected_pins =
        BTreeSet::from([fixture.manifest_hash.clone(), metadata_pack_hash(inputs)?]);
    let actual_pins: BTreeSet<_> = state.pins.iter().map(|pin| pin.hash.clone()).collect();
    if state.reservations.len() != 2
        || ids.len() != 2
        || state
            .reservations
            .iter()
            .any(|row| row.owner != inputs.owner || row.bytes != HOLD)
        || state.leases.len() != 1
        || state.pins.len() != 2
        || state.leases[0].expires != i64::MAX as u64
        || state
            .pins
            .iter()
            .any(|pin| pin.owner != state.leases[0].owner || pin.expires != i64::MAX as u64)
        || actual_pins != expected_pins
        || !ids
            .iter()
            .any(|id| format!("metadata:{id}") == state.leases[0].owner)
        || state.residences.len() != if recovered { fixture.chunks.len() } else { 0 }
    {
        return Err(invalid("manifest recovery retained policy closure differs"));
    }
    let mut offset = 0;
    if recovered {
        for chunk in &fixture.chunks {
            let matching = state
                .residences
                .iter()
                .filter(|row| {
                    row.chunk == hex(&chunk.digest)
                        && row.object == fixture.manifest_hash
                        && row.offset == offset
                        && row.length == chunk.length
                })
                .count();
            if matching != 1 {
                return Err(invalid("reconstructed ordered manifest residence differs"));
            }
            offset += chunk.length;
        }
    }
    Ok(())
}

// The expected pin names come from the actual ordinary pack bytes, independently
// of embedded policy. This read creates no native retention or content authority.
fn metadata_pack_hash(inputs: &Inputs) -> io::Result<String> {
    let mut paths = Vec::new();
    for shard in fs::read_dir(inputs.root.join("objects/pack"))? {
        for entry in fs::read_dir(shard?.path())? {
            let path = entry?.path();
            if path.extension().is_some_and(|suffix| suffix == "pack") {
                paths.push(path);
            }
        }
    }
    let [path] = paths.as_slice() else {
        return Err(invalid(
            "manifest fixture requires exactly one actual metadata pack",
        ));
    };
    let bytes = fs::read(path)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Pack, &bytes)
        .map_err(io::Error::other)?;
    Ok(hex(identity.digest()))
}

fn require_domain(inputs: &Inputs, bad: bool) -> io::Result<()> {
    let expected = if bad {
        "tenant:manifest-mismatch"
    } else {
        "tenant:manifest-recovery"
    };
    if inputs.domain != expected {
        return Err(invalid("manifest fixture requires its dedicated domain"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
