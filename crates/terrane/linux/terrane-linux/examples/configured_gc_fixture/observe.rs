//! Checks selected records and exact native absence without granting authority.

use std::{collections::BTreeMap, os::unix::ffi::OsStrExt, path::Path};

use terrane_format::gc::{
    DeleteOperation, DeletePhase, GcLease, GcRoots, GcState,
    publication::{PortableCurrent, PortableSnapshot},
};
use terrane_sdk::pack::PackId;

use super::{FixtureResult, fs};

pub(super) fn find_pack(bucket: &Path, hash: [u8; 32]) -> FixtureResult<PackId> {
    let mut selected = None;
    for shard in fs::read_dir(bucket.join("objects/pack"))? {
        for entry in fs::read_dir(shard?.path())? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "idx") {
                continue;
            }
            let (header, records) =
                terrane_format::pack_format::decode_detached_index(&fs::read(path)?)?;
            if records.iter().any(|record| record.hash == hash)
                && selected
                    .replace(PackId::from_random_bytes(*header.id()))
                    .is_some()
            {
                return Err("orphan identity appears in multiple physical packs".into());
            }
        }
    }
    selected.ok_or_else(|| "native orphan pack missing".into())
}

fn projection(bucket: &Path) -> FixtureResult<BTreeMap<String, Option<Vec<u8>>>> {
    let mut current = PortableCurrent::decode(&fs::read(bucket.join("publication/PORTABLE"))?)?;
    let mut selected = BTreeMap::new();
    let mut previous_revision = None;
    loop {
        let bytes = fs::read(bucket.join(&current.key))?;
        current.check_snapshot(&bytes)?;
        let snapshot = PortableSnapshot::decode(&bytes)?;
        if previous_revision.is_some_and(|previous| snapshot.revision >= previous) {
            return Err("portable predecessor revisions are not decreasing".into());
        }
        previous_revision = Some(snapshot.revision);
        for row in snapshot.projection {
            selected.entry(row.key).or_insert(row.value);
        }
        match snapshot.predecessor {
            Some(previous) => current = previous,
            None => return Ok(selected),
        }
    }
}

pub(super) fn verify_deletion(root: &Path) -> FixtureResult<()> {
    let bucket = root.join("bucket");
    let pack: [u8; 16] = fs::read(root.join("expected.pack"))?
        .try_into()
        .map_err(|_| "invalid saved native pack identity")?;
    let id = PackId::from_random_bytes(pack);
    for key in [id.pack_key(), id.index_key()] {
        if bucket.join(key).try_exists()? {
            return Err("native orphan pair still present".into());
        }
    }
    let selected = projection(&bucket)?;
    let lease = GcLease::decode(
        selected
            .get("gc/lease")
            .and_then(Option::as_deref)
            .ok_or("missing selected collector lease")?,
    )?;
    let mut cycles = Vec::new();
    for (key, value) in &selected {
        if !key.starts_with("gc/") || !key.ends_with("/roots") {
            continue;
        }
        let roots = GcRoots::decode(value.as_deref().ok_or("absent registered root snapshot")?)?;
        let state = GcState::decode(
            selected
                .get(&format!("gc/{}/state", roots.cycle))
                .and_then(Option::as_deref)
                .ok_or("missing selected traversal checkpoint")?,
        )?;
        if roots.epoch != lease.epoch || state.epoch != lease.epoch {
            return Err("fresh cycles did not retain their original whole lease".into());
        }
        cycles.push(roots.cycle);
    }
    if cycles.len() < 2 {
        return Err("collector did not start a fresh second cycle".into());
    }

    let digest = blake3::hash(bucket.as_os_str().as_bytes()).to_hex();
    let control = bucket.with_file_name(format!(".terrane-control:{digest}"));
    let mut matching = 0;
    for cycle in fs::read_dir(control.join("gc"))? {
        let directory = cycle?.path().join("delete").join(id.to_string());
        if !directory.try_exists()? {
            continue;
        }
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let key = path
                .strip_prefix(&control)?
                .to_str()
                .ok_or("non-UTF-8 operation key")?;
            let operation = DeleteOperation::decode(&fs::read(&path)?, key)?;
            if operation.authorization.pack_id != pack {
                return Err("another pack in exact native intent directory".into());
            }
            if operation.phase != DeletePhase::Done
                || operation.authorization.deletion_seconds != 60
                || operation.authorization.elapsed_ns < 60_000_000_000
                || operation.authorization.original_lease.holder != lease.holder
                || operation.authorization.original_lease.epoch != lease.epoch
                || operation.current_lease.holder != lease.holder
                || operation.current_lease.epoch != lease.epoch
                || operation.current_lease.expiry > lease.expiry
                || bucket
                    .join(format!("trash/{}/{id}", operation.authorization.cycle))
                    .try_exists()?
            {
                return Err("exact native Done or full-D witness missing".into());
            }
            matching += 1;
        }
    }
    if matching != 1 {
        return Err("expected exactly one genuine native deletion operation".into());
    }
    Ok(())
}
