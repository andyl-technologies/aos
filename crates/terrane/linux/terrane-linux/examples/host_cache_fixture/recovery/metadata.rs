//! Checks an original admitted pair beside independently adopted sealed content.

use super::*;
use std::{os::unix::fs::MetadataExt, path::PathBuf, time::UNIX_EPOCH};
use terrane_sdk::{pack::SealedPack, store::Clock};

/// Names the isolated native control domain.
pub(super) const DOMAIN: &str = "tenant:manifest-extra-metadata";

fn pair(manifest: &[u8]) -> io::Result<SealedPack> {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let mut orphan = Manifest::decode(manifest, &profile).map_err(io::Error::other)?;
    // Keep this metadata distinct from the manifest needed to adopt the body.
    orphan.media_type = Some("application/x-terrane-recovery-orphan".into());
    let orphan = orphan.encode(&profile).map_err(io::Error::other)?;
    let mut writer = PackWriter::new(PackId::from_random_bytes([113; 16]), PackClass::Meta, false);
    writer
        .append_raw(EntryKind::Manifest, &orphan)
        .map_err(io::Error::other)?;
    writer.seal().map_err(io::Error::other)
}

fn paths(inputs: &Inputs) -> [PathBuf; 2] {
    let id = PackId::from_random_bytes([113; 16]);
    [
        inputs.root.join(id.index_key()),
        inputs.root.join(id.pack_key()),
    ]
}

/// Seeds a distinct real metadata pair without any recovery or pin authority.
///
/// # Errors
/// Refuses conflicting names, wrong native custody and failed synchronization.
pub(super) fn seed(inputs: &Inputs, manifest: &[u8]) -> io::Result<()> {
    let pair = pair(manifest)?;
    let [index, pack] = paths(inputs);
    let parent = pack
        .parent()
        .ok_or_else(|| invalid("orphan metadata shard absent"))?;
    if !parent.exists() {
        directory(parent, 840, 845, 0o2770)?;
    }
    write(inputs, &index, pair.index_object(), 840, 845, 0o640)?;
    write(inputs, &pack, pair.bytes(), 840, 845, 0o640)?;
    File::open(parent)?.sync_all()?;
    File::open(inputs.root.join("objects/pack"))?.sync_all()
}

struct Original {
    path: PathBuf,
    inode: (u64, u64),
    bytes: Vec<u8>,
}

/// Captures comparison data without retaining hidden native source descriptors.
pub(super) struct Observation {
    policy: CacheState,
    originals: Vec<Original>,
    started: u64,
}

fn now() -> io::Result<u64> {
    let elapsed = terrane_sdk::store::TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    // The physical handoff rounds its 30-second grace up to durable Unix
    // seconds. Bracket that same rounding at both observations; truncating the
    // upper observation wrongly rejects every subsecond handoff in that tick.
    elapsed
        .as_secs()
        .checked_add(u64::from(elapsed.subsec_nanos() != 0))
        .ok_or_else(|| invalid("metadata observation clock overflows"))
}

fn policy(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("mixed metadata policy absent"))
}

impl Observation {
    /// Captures actual original files and funded policy before acknowledged Resume.
    ///
    /// # Errors
    /// Refuses unreadable original files or missing actual synchronized policy.
    pub(super) fn capture(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<Self> {
        let originals = paths(inputs)
            .into_iter()
            .map(|path| {
                let value = fs::metadata(&path)?;
                let bytes = fs::read(&path)?;
                Ok(Original {
                    path,
                    inode: (value.dev(), value.ino()),
                    bytes,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            policy: policy(runtime, inputs)?,
            originals,
            started: now()?,
        })
    }

    /// Checks actual original pair custody and only the newly funded cache grace.
    ///
    /// # Errors
    /// Refuses replaced or changed sources, hidden descriptors, changed original
    /// promises, missing grace, leaked future holds or failed duplicate protection.
    pub(super) fn check(
        self,
        owner: &NativeMetadataOwner,
        runtime: &tokio::runtime::Runtime,
        inputs: &Inputs,
    ) -> io::Result<()> {
        let after = policy(runtime, inputs)?;
        let graces = after
            .leases
            .iter()
            .filter(|lease| lease.owner.starts_with("admission-grace:"))
            .collect::<Vec<_>>();
        let [grace] = graces.as_slice() else {
            return Err(invalid("mixed metadata omitted its unique actual grace"));
        };
        let pack = pair(&Fixture::new()?.manifest)?;
        let mut hashes = BTreeSet::from([hex(TERRANE_V1
            .calculate(IdentityKind::Pack, pack.bytes())
            .map_err(io::Error::other)?
            .digest())]);
        hashes.extend(
            terrane_sdk::pack::PackReader::open(pack.bytes())
                .map_err(io::Error::other)?
                .entries()
                .iter()
                .map(|entry| hex(entry.hash())),
        );
        let pins = after
            .pins
            .iter()
            .filter(|pin| pin.owner == grace.owner)
            .collect::<Vec<_>>();
        let earliest = self
            .started
            .checked_add(30)
            .ok_or_else(|| invalid("metadata grace start overflows"))?;
        let latest = now()?
            .checked_add(30)
            .ok_or_else(|| invalid("metadata grace deadline overflows"))?;
        if grace.expires < earliest
            || grace.expires > latest
            || pins.len() != hashes.len()
            || pins
                .iter()
                .any(|pin| pin.expires != grace.expires || !hashes.contains(&pin.hash))
            || after.pins.len() != self.policy.pins.len() + hashes.len()
            || after.leases.len() != self.policy.leases.len() + 1
            || !same_original(&self.policy, &after)
        {
            eprintln!(
                "mixed metadata policy mismatch: before={:?} after={after:?} expected_hashes={hashes:?} earliest={earliest} latest={latest}",
                self.policy
            );
            return Err(invalid(
                "mixed metadata changed original policy or lost actual funded grace",
            ));
        }
        for original in self.originals {
            let value = fs::metadata(&original.path)?;
            let mut descriptions = 0;
            for entry in fs::read_dir("/proc/self/fd")? {
                let value = match fs::metadata(entry?.path()) {
                    Ok(value) => value,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                descriptions += usize::from((value.dev(), value.ino()) == original.inode);
            }
            if (value.dev(), value.ino()) != original.inode
                || fs::read(original.path)? != original.bytes
                || descriptions != 1
            {
                return Err(invalid(
                    "mixed metadata lost original pair or retained hidden cold descriptors",
                ));
            }
        }
        let snapshot = inputs.root.join("state/cache/records.toml");
        let before = fs::read(&snapshot)?;
        let duplicate = runtime.block_on(owner.admit_metadata_pack(
            PackId::from_random_bytes([113; 16]),
            pack.bytes().to_vec(),
            pack.index_object().to_vec(),
        ));
        if !matches!(duplicate, Err(terrane_linux::host_cache::NativeMetadataAdmissionError::Accepted(error)) if error.kind() == io::ErrorKind::AlreadyExists)
            || fs::read(snapshot)? != before
        {
            return Err(invalid(
                "mixed metadata duplicate changed original cache funding",
            ));
        }
        println!(
            "PASS additional metadata pair retained original inodes and actual cache grace beside recovered sealed content; no hidden cold descriptors or duplicate funding"
        );
        Ok(())
    }
}

fn same_original(before: &CacheState, after: &CacheState) -> bool {
    before.reservations.len() == after.reservations.len()
        && before.residences.len() == after.residences.len()
        && before.reservations.iter().all(|old| {
            after
                .reservations
                .iter()
                .any(|new| old.id == new.id && old.owner == new.owner && old.bytes == new.bytes)
        })
        && before.residences.iter().all(|old| {
            after.residences.iter().any(|new| {
                old.chunk == new.chunk
                    && old.object == new.object
                    && old.offset == new.offset
                    && old.length == new.length
            })
        })
        && before.pins.iter().all(|old| {
            after.pins.iter().any(|new| {
                old.owner == new.owner && old.hash == new.hash && old.expires == new.expires
            })
        })
        && before.leases.iter().all(|old| {
            after
                .leases
                .iter()
                .any(|new| old.owner == new.owner && old.expires == new.expires)
        })
}
