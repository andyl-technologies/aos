//! Seeds untrusted cold files and exercises actual manifest recovery in the guest.
//!
//! Explicit root administration seeds canonical metadata and actual candidate
//! files, including malformed or unsealed controls, before either role starts.
//! These files confer no publication or recovery authority. A separate confined
//! actor invokes the genuine owner, Inspector and publisher channel; only their
//! actual result permits Resume.

#[path = "recovery/indexes.rs"]
mod indexes;
#[path = "recovery/inline.rs"]
mod inline;
#[path = "recovery/pending.rs"]
pub(super) mod pending;
#[path = "recovery/pending_packs.rs"]
pub(super) mod pending_packs;
#[path = "recovery/reuse.rs"]
mod reuse;

use super::config::{HARD_LIMIT, HOLD, Inputs, STATE};
use rustix::process::{Gid, Uid};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_linux::{host_cache::NativeMetadataOwner, host_quota::NativeProject};
use terrane_sdk::{
    host::cache::CacheState,
    pack::{EntryKind, PackClass, PackId, PackWriter},
    store::TokioLocalFs,
};

const INLINE_BYTES: &[u8] = b"independent inline cold candidate";

#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureCase {
    MissingIndex,
    DisabledIndexRepair,
    BoundedIndexRepair,
    MismatchingIndex,
    Verified,
    Mismatch,
    Unsealed,
    WritableUnsealed,
    Truncated,
    WritableVerified,
    MixedVerified,
    MixedMismatch,
}

impl FixtureCase {
    fn from_mode(mode: &str) -> io::Result<Self> {
        match mode {
            "seed-index-recovery" | "recover-index-recovery" => Ok(Self::MissingIndex),
            "seed-index-disabled" | "refuse-index-disabled" => Ok(Self::DisabledIndexRepair),
            "seed-index-bound" | "refuse-index-bound" => Ok(Self::BoundedIndexRepair),
            "seed-index-mismatch" | "refuse-index-mismatch" => Ok(Self::MismatchingIndex),
            "seed-manifest" | "recover-manifest" => Ok(Self::Verified),
            "seed-bad-manifest" | "refuse-manifest" => Ok(Self::Mismatch),
            "seed-unsealed-manifest" | "refuse-unsealed-manifest" => Ok(Self::Unsealed),
            "seed-unsealed-writable-manifest" | "refuse-unsealed-writable-manifest" => {
                Ok(Self::WritableUnsealed)
            }
            "seed-truncated-manifest" | "refuse-truncated-manifest" => Ok(Self::Truncated),
            "seed-writable-manifest" | "recover-writable-manifest" => Ok(Self::WritableVerified),
            "seed-mixed-manifest" | "recover-mixed-manifest" => Ok(Self::MixedVerified),
            "seed-mixed-bad-manifest" | "refuse-mixed-manifest" => Ok(Self::MixedMismatch),
            _ => Err(invalid("unknown manifest fixture selector")),
        }
    }

    fn domain(self) -> &'static str {
        match self {
            Self::MissingIndex => "tenant:index-recovery",
            Self::DisabledIndexRepair => "tenant:index-disabled",
            Self::BoundedIndexRepair => "tenant:index-bound",
            Self::MismatchingIndex => "tenant:index-mismatch",
            Self::Verified => "tenant:manifest-recovery",
            Self::Mismatch => "tenant:manifest-mismatch",
            Self::Unsealed => "tenant:manifest-unsealed",
            Self::WritableUnsealed => "tenant:manifest-unsealed-writable",
            Self::Truncated => "tenant:manifest-truncated",
            Self::WritableVerified => "tenant:manifest-sealed-writable",
            Self::MixedVerified => "tenant:manifest-mixed",
            Self::MixedMismatch => "tenant:manifest-mixed-mismatch",
        }
    }

    fn refusal_label(self) -> &'static str {
        match self {
            Self::Mismatch => "manifest mismatch",
            Self::Unsealed => "unsealed manifest",
            Self::WritableUnsealed => "unsealed writable manifest",
            Self::Truncated => "truncated manifest",
            Self::MixedMismatch => "mixed manifest mismatch",
            Self::Verified | Self::WritableVerified | Self::MixedVerified | Self::MissingIndex => {
                "valid manifest"
            }
            Self::DisabledIndexRepair => "disabled index repair",
            Self::BoundedIndexRepair => "bounded index repair",
            Self::MismatchingIndex => "mismatching detached index",
        }
    }

    fn recovers(self) -> bool {
        matches!(
            self,
            Self::Verified | Self::WritableVerified | Self::MixedVerified | Self::MissingIndex
        )
    }

    fn mixed(self) -> bool {
        matches!(self, Self::MixedVerified | Self::MixedMismatch)
    }
}

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
/// Refuses a non-root caller, unexpected administrative capabilities, another
/// domain, existing names, wrong project inheritance, failed native writes,
/// synchronization or kernel fs-verity.
pub(super) fn seed(mode: &str) -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid(
            "cold fixture seeding requires explicit root administration",
        ));
    }
    require_seed_capabilities()?;
    let inputs = Inputs::load()?;
    let case = FixtureCase::from_mode(mode)?;
    require_domain(&inputs, case)?;
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
    if matches!(case, FixtureCase::Mismatch | FixtureCase::MixedMismatch) {
        fixture.plaintext[0] ^= 1;
    } else if case == FixtureCase::Truncated {
        fixture
            .plaintext
            .pop()
            .ok_or_else(|| invalid("cannot truncate an empty fixture"))?;
    }
    let mode = if matches!(
        case,
        FixtureCase::WritableUnsealed | FixtureCase::WritableVerified
    ) {
        0o600
    } else {
        0o400
    };
    write(&inputs, &sealed, &fixture.plaintext, 841, 841, mode)?;
    // The only writer is closed before any actual permanent kernel seal.
    let retained = File::open(&sealed)?;
    if matches!(case, FixtureCase::Unsealed | FixtureCase::WritableUnsealed) {
        match terrane_linux::verity::measure(&retained) {
            Err(error) if error.raw_os_error() == Some(libc::ENODATA) => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(invalid("unsealed fixture already has a kernel seal")),
        }
    } else {
        terrane_linux::verity::enable(&retained)?;
    }
    if case == FixtureCase::WritableVerified {
        // Mode0600 and root DAC_OVERRIDE permit this open; fs-verity itself
        // must deny it. Permission bits never substitute for the kernel seal.
        match OpenOptions::new().write(true).open(&sealed) {
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(invalid("kernel-sealed fixture permitted a write open")),
        }
    } else if case == FixtureCase::WritableUnsealed {
        // Close this actual writer before any role starts or recovery runs.
        drop(OpenOptions::new().write(true).open(&sealed)?);
    }
    retained.sync_all()?;
    File::open(&sealed_parent)?.sync_all()?;
    if case.mixed() {
        let hash = inline_hash()?;
        let parent = inputs.root.join("sealed").join(&hash[..2]);
        if parent != sealed_parent {
            directory(&parent, 841, 841, 0o755)?;
        }
        let path = parent.join(hash);
        write(&inputs, &path, INLINE_BYTES, 841, 841, 0o400)?;
        let inline = File::open(path)?;
        terrane_linux::verity::enable(&inline)?;
        inline.sync_all()?;
        File::open(parent)?.sync_all()?;
    }
    File::open(inputs.root.join("sealed"))?.sync_all()?;
    println!("SEEDED actual cold manifest candidate; no publication or recovery authority");
    Ok(())
}

fn require_seed_capabilities() -> io::Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    // CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER and CAP_FSETID permit this
    // root-only administrative seed. No quota mutation capability is present.
    for (field, expected) in [
        ("CapInh", "0000000000000000"),
        ("CapPrm", "000000000000001b"),
        ("CapEff", "000000000000001b"),
        ("CapBnd", "000000000000001b"),
        ("CapAmb", "0000000000000000"),
    ] {
        let expected_line = format!("{field}:\t{expected}");
        if !status.lines().any(|line| line == expected_line) {
            return Err(invalid(
                "unexpected actual administrative seed capabilities",
            ));
        }
    }
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

/// Exercises genuine manifest reconciliation and actual rejected-file controls.
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
    let case = FixtureCase::from_mode(mode)?;
    require_domain(inputs, case)?;
    let cold = matches!(
        case,
        FixtureCase::WritableVerified | FixtureCase::MixedVerified
    );
    if original.is_some() != cold {
        return Err(invalid(
            "manifest recovery fixture has unexpected cold policy presence",
        ));
    }
    let result = runtime.block_on(owner.recover());
    if matches!(
        case,
        FixtureCase::DisabledIndexRepair
            | FixtureCase::BoundedIndexRepair
            | FixtureCase::MismatchingIndex
    ) {
        return indexes::refuse(case, result, owner, runtime, inputs);
    }
    if !case.recovers() {
        let error = result
            .err()
            .ok_or_else(|| invalid("rejected manifest candidate completed recovery"))?;
        println!("REFUSED actual {} candidate: {error}", case.refusal_label());
        check_policy(runtime, inputs, case, false)?;
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
        refuse_resident_source(owner, runtime, inputs)?;
        if case.mixed() {
            inline::refuse(owner, runtime, inputs)?;
        }
        println!(
            "PASS actual {} retained metadata funding and faulted custody; no Resume",
            case.refusal_label()
        );
        return Ok(());
    }
    let completed = result?;
    completed.check_current()?;
    if completed.future_hold_bytes()
        != (2 + u64::from(case == FixtureCase::WritableVerified)) * HOLD
        || completed.charged_reserved_bytes() > HARD_LIMIT
        || completed.synchronized_retained_inode_bytes() == 0
    {
        return Err(invalid("nonempty recovery lacks actual bounded accounting"));
    }
    check_policy(runtime, inputs, case, true)?;
    if case == FixtureCase::MissingIndex {
        println!(
            "PASS actual startup index repair retained only bootstrap and verified metadata funding before Resume"
        );
    }
    refuse_resident_source(owner, runtime, inputs)?;
    if case.mixed() {
        inline::refuse(owner, runtime, inputs)?;
    }
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    if cold {
        println!(
            "PASS actual cold consumer pins, leases and holds reconciled with verified native backing; original records retained"
        );
    }
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    if fs::read(inputs.root.join("state/cache/records.toml"))? != before {
        return Err(invalid(
            "manifest Resume changed its durable recovery policy",
        ));
    }
    read_recovered_sources(owner, runtime, inputs)?;
    admit_after_recovery(owner, runtime, inputs)?;
    read_recovered_sources(owner, runtime, inputs)?;
    println!(
        "PASS actual recovered ranges survived a new Running admission; original metadata retained"
    );
    if case == FixtureCase::Verified {
        reuse::run(owner, runtime, inputs)?;
    } else if case == FixtureCase::MixedVerified {
        inline::run(owner, runtime, inputs)?;
    }
    if case.mixed() {
        println!(
            "PASS actual mixed recovery adopted inline and manifest bytes and acknowledged Resume; no Ready"
        );
    } else {
        println!(
            "PASS actual manifest recovery reconstructed verified residences and acknowledged Resume; no Ready"
        );
    }
    Ok(())
}

fn admit_after_recovery(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let bytes = b"distinct new chunk after acknowledged manifest recovery";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, bytes)
        .map_err(io::Error::other)?;
    let descriptor =
        terrane_format::identity::Descriptor::from_identity(&TERRANE_V1, &identity, bytes)
            .map_err(io::Error::other)?;
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    let prior = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("post-recovery original snapshot absent"))?;
    let prior_holds = prior.reservations.iter().try_fold(0_u64, |sum, hold| {
        sum.checked_add(hold.bytes)
            .ok_or_else(|| invalid("fixture original holds overflow"))
    })?;
    let admitted = runtime
        .block_on(owner.admit_chunk(
            descriptor.clone(),
            terrane_sdk::store::ChunkPosition::Final,
            [b"\0".as_slice(), bytes.as_slice()].concat(),
        ))
        .map_err(io::Error::other)?;
    if admitted.descriptor() != &descriptor
        || admitted.future_hold_bytes() != HOLD + bytes.len() as u64 + 1
        || admitted.charged_reserved_bytes() > HARD_LIMIT
        || admitted.synchronized_chunk_bytes() == 0
        || fs::read(inputs.root.join("state/cache/records.toml"))? == before
    {
        return Err(invalid(
            "post-recovery admission lacks actual durable funding",
        ));
    }
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("post-recovery admission snapshot missing"))?;
    if state.reservations.len() != prior.reservations.len() + 1
        || state
            .reservations
            .iter()
            .map(|hold| hold.bytes)
            .sum::<u64>()
            != prior_holds + HOLD + bytes.len() as u64 + 1
    {
        return Err(invalid(
            "post-recovery owner total differs from retained operation holds",
        ));
    }
    drop(admitted);
    Ok(())
}

fn refuse_resident_source(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let fixture = Fixture::new()?;
    let range = ChunkProfile::cdc_1m([0; 32])
        .ranges(&fixture.plaintext)
        .next()
        .ok_or_else(|| invalid("recovery fixture has no actual chunk"))?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &fixture.plaintext[range])
        .map_err(io::Error::other)?;
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    if runtime
        .block_on(owner.retain_resident_chunk(identity))
        .is_ok()
        || fs::read(inputs.root.join("state/cache/records.toml"))? != before
    {
        return Err(invalid(
            "recovery issued a resident source without acknowledged Resume",
        ));
    }
    println!("PASS actual recovered source refused without acknowledged Resume; policy unchanged");
    Ok(())
}

fn read_recovered_sources(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let fixture = Fixture::new()?;
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    for range in ChunkProfile::cdc_1m([0; 32]).ranges(&fixture.plaintext) {
        let bytes = &fixture.plaintext[range.clone()];
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, bytes)
            .map_err(io::Error::other)?;
        let source = runtime.block_on(owner.retain_resident_chunk(identity))?;
        let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
        let actual = source.read_verified()?;
        drop(stalled);
        if actual != bytes
            || source.span().offset != range.start as u64
            || source.span().length != bytes.len()
            || source.span().final_chunk != (range.end == fixture.plaintext.len())
        {
            return Err(invalid(
                "actual recovered source differs from verified manifest range",
            ));
        }
    }
    if fs::read(inputs.root.join("state/cache/records.toml"))? != before {
        return Err(invalid(
            "recovered source read changed durable recovery custody",
        ));
    }
    println!(
        "PASS actual recovered manifest ranges read while embedded policy held; original custody unchanged"
    );
    Ok(())
}

fn check_policy(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    case: FixtureCase,
    recovered: bool,
) -> io::Result<()> {
    let fixture = Fixture::new()?;
    let mut state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("manifest recovery snapshot missing"))?;
    if matches!(
        case,
        FixtureCase::WritableVerified | FixtureCase::MixedVerified
    ) {
        let hash = if case == FixtureCase::WritableVerified {
            fixture.manifest_hash.clone()
        } else {
            inline_hash()?
        };
        let pins: Vec<_> = state
            .pins
            .iter()
            .filter(|row| row.owner == "fixture-cold-consumer")
            .collect();
        let leases: Vec<_> = state
            .leases
            .iter()
            .filter(|row| row.owner == "fixture-cold-consumer")
            .collect();
        if pins.len() != 1
            || leases.len() != 1
            || pins[0].hash != hash
            || pins[0].expires != i64::MAX as u64
            || leases[0].expires != i64::MAX as u64
        {
            return Err(invalid("cold consumer pin or lease was changed or lost"));
        }
        if case == FixtureCase::WritableVerified {
            let holds: Vec<_> = state
                .reservations
                .iter()
                .filter(|row| row.id == "fixture-cold-hold")
                .collect();
            if holds.len() != 1 || holds[0].owner != inputs.owner || holds[0].bytes != HOLD {
                return Err(invalid("cold future hold was changed or lost"));
            }
        }
        // Remove only independently checked expected cold rows from this local
        // fixture copy, then apply the unchanged exact new-operation assertions.
        state
            .pins
            .retain(|row| row.owner != "fixture-cold-consumer");
        state
            .leases
            .retain(|row| row.owner != "fixture-cold-consumer");
        state
            .reservations
            .retain(|row| row.id != "fixture-cold-hold");
    }
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
        || state.residences.len()
            != if recovered {
                fixture.chunks.len() + usize::from(case.mixed())
            } else {
                0
            }
    {
        return Err(invalid("manifest recovery retained policy closure differs"));
    }
    let mut offset = 0;
    if recovered {
        if case.mixed() {
            let hash = inline_hash()?;
            if state
                .residences
                .iter()
                .filter(|row| {
                    row.chunk == hash
                        && row.object == hash
                        && row.offset == 0
                        && row.length == INLINE_BYTES.len() as u64
                })
                .count()
                != 1
            {
                return Err(invalid("mixed recovery omitted its exact inline residence"));
            }
        }
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

fn require_domain(inputs: &Inputs, case: FixtureCase) -> io::Result<()> {
    if inputs.domain != case.domain() {
        return Err(invalid("manifest fixture requires its dedicated domain"));
    }
    Ok(())
}

fn inline_hash() -> io::Result<String> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, INLINE_BYTES)
        .map_err(io::Error::other)?;
    Ok(hex(identity.digest()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
