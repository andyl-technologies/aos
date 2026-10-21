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
    mode: u32,
    bytes: Vec<u8>,
}

struct OriginalPair {
    pack: SealedPack,
    hashes: BTreeSet<String>,
    originals: Vec<Original>,
    descriptions: usize,
}

/// Captures exact seeded pairs and policy without retaining extra native handles.
pub(super) struct Observation {
    policy: CacheState,
    pairs: Vec<OriginalPair>,
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
    /// Captures every exact seeded metadata pair before acknowledged Resume.
    ///
    /// # Errors
    /// Refuses unexpected fixture bytes, missing originals or synchronized policy.
    pub(super) fn capture(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<Self> {
        let mut pairs = Vec::new();
        for shard in fs::read_dir(inputs.root.join("objects/pack"))? {
            for entry in fs::read_dir(shard?.path())? {
                let path = entry?.path();
                if path.extension().is_none_or(|extension| extension != "pack") {
                    continue;
                }
                let bytes = fs::read(&path)?;
                let reader = PackReader::open(&bytes).map_err(io::Error::other)?;
                let id = reader.header().id();
                let orphan = id == PackId::from_random_bytes([113; 16]);
                let pack = if orphan {
                    pair(&Fixture::new()?.manifest)?
                } else {
                    let mut writer = PackWriter::new(id, PackClass::Meta, false);
                    writer
                        .append_raw(EntryKind::Manifest, &Fixture::new()?.manifest)
                        .map_err(io::Error::other)?;
                    writer.seal().map_err(io::Error::other)?
                };
                let mut hashes = BTreeSet::from([hex(TERRANE_V1
                    .calculate(IdentityKind::Pack, pack.bytes())
                    .map_err(io::Error::other)?
                    .digest())]);
                hashes.extend(reader.entries().iter().map(|entry| hex(entry.hash())));
                let mut originals = Vec::new();
                for (path, expected) in [
                    (inputs.root.join(id.index_key()), pack.index_object()),
                    (inputs.root.join(id.pack_key()), pack.bytes()),
                ] {
                    let metadata = fs::metadata(&path)?;
                    let bytes = fs::read(&path)?;
                    if bytes != expected {
                        return Err(invalid(
                            "cold metadata fixture differs from its seeded original pair",
                        ));
                    }
                    originals.push(Original {
                        path,
                        inode: (metadata.dev(), metadata.ino()),
                        mode: metadata.mode() & 0o7777,
                        bytes,
                    });
                }
                // Referenced pairs have one reconstruction source and one
                // retained native verification result, plus the running import.
                // An unreferenced pair has only its actual running admission.
                pairs.push(OriginalPair {
                    pack,
                    hashes,
                    originals,
                    descriptions: if orphan { 1 } else { 3 },
                });
            }
        }
        let expected = if inputs.domain == DOMAIN { 2 } else { 1 };
        if pairs.len() != expected {
            return Err(invalid("cold metadata fixture pair inventory differs"));
        }
        Ok(Self {
            policy: policy(runtime, inputs)?,
            pairs,
            started: now()?,
        })
    }

    /// Checks every new exact cache grace while preserving all original promises.
    ///
    /// # Errors
    /// Refuses changed original inodes, modes, bytes or policy, hidden descriptors,
    /// missing/extra grace closures, leaked holds or failed duplicate protection.
    pub(super) fn check(
        self,
        owner: &NativeMetadataOwner,
        runtime: &tokio::runtime::Runtime,
        inputs: &Inputs,
    ) -> io::Result<()> {
        let after = policy(runtime, inputs)?;
        let mut graces = after
            .leases
            .iter()
            .filter(|lease| {
                lease.owner.starts_with("admission-grace:")
                    && !self
                        .policy
                        .leases
                        .iter()
                        .any(|old| old.owner == lease.owner && old.expires == lease.expires)
            })
            .collect::<Vec<_>>();
        let added_pins = self
            .pairs
            .iter()
            .map(|pair| pair.hashes.len())
            .sum::<usize>();
        if graces.len() != self.pairs.len()
            || after.pins.len() != self.policy.pins.len() + added_pins
            || after.leases.len() != self.policy.leases.len() + self.pairs.len()
            || !same_original(&self.policy, &after)
        {
            return Err(invalid(
                "cold metadata import changed original policy or its exact new cache closure",
            ));
        }
        let earliest = self
            .started
            .checked_add(30)
            .ok_or_else(|| invalid("metadata grace start overflows"))?;
        let latest = now()?
            .checked_add(30)
            .ok_or_else(|| invalid("metadata grace deadline overflows"))?;
        for pair in self.pairs {
            let position = graces
                .iter()
                .position(|grace| {
                    let pins = after
                        .pins
                        .iter()
                        .filter(|pin| pin.owner == grace.owner)
                        .collect::<Vec<_>>();
                    pins.len() == pair.hashes.len()
                        && pins.iter().all(|pin| {
                            pin.expires == grace.expires && pair.hashes.contains(&pin.hash)
                        })
                })
                .ok_or_else(|| {
                    invalid("cold metadata pair lacks its exact original-container grace")
                })?;
            let grace = graces.remove(position);
            if grace.expires < earliest || grace.expires > latest {
                return Err(invalid(
                    "cold metadata cache grace escaped its original deadline bounds",
                ));
            }
            for original in pair.originals {
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
                    || value.mode() & 0o7777 != original.mode
                    || fs::read(original.path)? != original.bytes
                    || descriptions != pair.descriptions
                {
                    eprintln!(
                        "cold metadata retained descriptions={descriptions} expected={}",
                        pair.descriptions
                    );
                    return Err(invalid(
                        "cold metadata import changed original pair or retained hidden cold descriptors",
                    ));
                }
            }
            let snapshot = inputs.root.join("state/cache/records.toml");
            let before = fs::read(&snapshot)?;
            let duplicate = runtime.block_on(
                owner.admit_metadata_pack(
                    PackReader::open(pair.pack.bytes())
                        .map_err(io::Error::other)?
                        .header()
                        .id(),
                    pair.pack.bytes().to_vec(),
                    pair.pack.index_object().to_vec(),
                ),
            );
            if !matches!(duplicate, Err(terrane_linux::host_cache::NativeMetadataAdmissionError::Accepted(error)) if error.kind() == io::ErrorKind::AlreadyExists)
                || fs::read(snapshot)? != before
            {
                return Err(invalid(
                    "cold metadata duplicate changed original cache funding",
                ));
            }
            if inputs.domain == DOMAIN {
                let reader = PackReader::open(pair.pack.bytes()).map_err(io::Error::other)?;
                let entry = reader
                    .entries()
                    .first()
                    .ok_or_else(|| invalid("cold metadata fixture has no manifest"))?;
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Manifest, entry.hash())
                    .map_err(io::Error::other)?;
                let start = usize::try_from(entry.offset()).map_err(io::Error::other)?;
                let end = start
                    .checked_add(usize::try_from(entry.body_len()).map_err(io::Error::other)?)
                    .ok_or_else(|| invalid("cold metadata fixture range overflows"))?;
                let expected = pair
                    .pack
                    .bytes()
                    .get(start..end)
                    .ok_or_else(|| invalid("cold metadata original manifest range absent"))?;
                let expires = now()?
                    .checked_add(90)
                    .ok_or_else(|| invalid("cold metadata read deadline overflows"))?;
                let lease = runtime.block_on(owner.pin_resident_metadata(identity, expires))?;
                if lease.read_verified()? != expected || lease.read_encoded()? != expected {
                    return Err(invalid(
                        "cold metadata consumer changed original canonical bytes",
                    ));
                }
                runtime.block_on(owner.release_consumer_lease(&lease))?;
                println!(
                    "PASS actual cold metadata consumer reads original imported pair and releases its durable lease"
                );
            }
        }
        if inputs.domain == DOMAIN {
            println!(
                "PASS additional metadata pair retained original inodes and actual cache grace beside recovered sealed content; no hidden cold descriptors or duplicate funding"
            );
        }
        println!(
            "PASS actual referenced cold metadata imported original pair with exact cache grace, unchanged reconstruction funding and original modes before serving grants"
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
