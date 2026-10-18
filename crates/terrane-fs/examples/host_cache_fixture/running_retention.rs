//! Checks metadata pinning after actual Resume and abandoned retention waiters.
//!
//! Both metadata members are admitted through the real owner. Retention must
//! preserve those exact ordinary inodes and synchronize its distinct holds and
//! manifest/pack pins without using an old completed-recovery predicate.

use super::config::{HOLD, Inputs, STATE};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    future::Future,
    io::{self, BufRead, Read, Write},
    os::unix::fs::{FileExt, MetadataExt},
    task::{Context, Poll, Waker},
};
use terrane::{
    host::cache::CacheState,
    pack::{EntryKind, PackClass, PackId, PackWriter},
    store::TokioLocalFs,
};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_fs::{
    host_cache::{NativeMetadataOwner, RetainedManifest},
    host_quota::synchronized_allocated_bytes,
};

/// Runs real ordinary metadata admission followed by acknowledged Running retention.
///
/// # Errors
/// Refuses premature or incorrect retention, changed inodes, absent durable
/// funding, lost abandoned work, stale earlier receipts or altered metadata.
pub(super) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    let case = match mode {
        "retain-running" => "tenant:retention-running",
        "retain-running-cancel" => "tenant:retention-running-cancel",
        _ => return Err(invalid("unknown Running retention selector")),
    };
    if inputs.domain != case || original.is_some() {
        return Err(invalid(
            "Running retention requires its fresh dedicated domain",
        ));
    }
    let manifest = super::admission::manifest(71)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Manifest, &manifest)
        .map_err(io::Error::other)?;
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let id = PackId::from_random_bytes(random);
    let mut writer = PackWriter::new(id, PackClass::Meta, false);
    writer
        .append_raw(EntryKind::Manifest, &manifest)
        .map_err(io::Error::other)?;
    let sealed = writer.seal().map_err(io::Error::other)?;
    let pack = sealed.bytes().to_vec();
    let index = sealed.index_object().to_vec();
    let pack_identity = TERRANE_V1
        .calculate(IdentityKind::Pack, &pack)
        .map_err(io::Error::other)?;

    let completed = runtime.block_on(owner.recover())?;
    completed.check_current()?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    if runtime
        .block_on(owner.retain_manifest(identity.clone()))
        .is_ok()
        || fs::read(inputs.root.join("state/cache/records.toml"))? != before
    {
        return Err(invalid("missing Running metadata changed durable policy"));
    }

    let admitted = runtime
        .block_on(owner.admit_metadata_pack(id, pack.clone(), index.clone()))
        .map_err(io::Error::other)?;
    let prefix = inputs
        .root
        .join(format!("objects/pack/{:02x}", id.as_bytes()[0]));
    let pack_path = prefix.join(format!("{id}.pack"));
    let index_path = prefix.join(format!("{id}.idx"));
    let original_pair = (
        fs::metadata(&pack_path)?.ino(),
        fs::metadata(&index_path)?.ino(),
    );

    let first = if mode == "retain-running-cancel" {
        emit(
            "READY actual metadata admission and Resume; wait for stopped-helper retention control",
        )?;
        control("enqueue")?;
        let mut pending = Box::pin(owner.retain_manifest(identity.clone()));
        if !matches!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return Err(invalid(
                "stopped helper did not retain a pending metadata waiter",
            ));
        }
        drop(pending);
        emit("CANCELLED accepted metadata retention waiter; physical owner retained")?;
        control("resumed")?;
        None
    } else {
        let retained = runtime.block_on(owner.retain_manifest(identity.clone()))?;
        check_receipt(
            &retained,
            inputs,
            &identity,
            &manifest,
            id,
            &pack_path,
            &index_path,
        )?;
        Some(retained)
    };

    // This valid command is serialized behind any abandoned one. Both distinct
    // completed pin registrations must remain, even though the first reply died.
    let second = runtime.block_on(owner.retain_manifest(identity.clone()))?;
    check_receipt(
        &second,
        inputs,
        &identity,
        &manifest,
        id,
        &pack_path,
        &index_path,
    )?;
    if let Some(first) = &first {
        first.check_current()?;
        if first.retention_id() == second.retention_id() {
            return Err(invalid(
                "later Running retention reused the earlier operation identity",
            ));
        }
        check_receipt(
            first,
            inputs,
            &identity,
            &manifest,
            id,
            &pack_path,
            &index_path,
        )?;
    }

    let actual_pair = (
        fs::metadata(&pack_path)?.ino(),
        fs::metadata(&index_path)?.ino(),
    );
    if actual_pair != original_pair
        || fs::read(&pack_path)? != pack
        || fs::read(&index_path)? != index
        || admitted.pack_id() != id
        || admitted.synchronized_pair_bytes() == 0
    {
        return Err(invalid(
            "Running retention rewrote or replaced ordinary metadata members",
        ));
    }
    check_policy(
        runtime,
        inputs,
        &identity,
        &pack_identity,
        pack.len() + index.len(),
    )?;
    emit(
        "PASS actual Running metadata retention kept both original inodes and distinct durable pins across later work; no Ready",
    )
}

fn check_receipt(
    receipt: &RetainedManifest,
    inputs: &Inputs,
    identity: &Identity,
    manifest: &[u8],
    id: PackId,
    pack_path: &std::path::Path,
    index_path: &std::path::Path,
) -> io::Result<()> {
    receipt.check_current()?;
    let metadata = receipt.metadata_file().metadata()?;
    let actual = fs::metadata(pack_path)?;
    let flags = rustix::fs::fcntl_getfl(receipt.metadata_file())?;
    let index = File::open(index_path)?;
    if receipt.claim().domain() != inputs.domain
        || receipt.claim().canonical_manifest() != Some(manifest)
        || receipt.claim().descriptor().digest() != identity.digest()
        || receipt.pack_id() != id
        || (metadata.dev(), metadata.ino()) != (actual.dev(), actual.ino())
        || flags.intersects(
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH,
        )
        || receipt.synchronized_source_bytes()
            != synchronized_allocated_bytes(receipt.metadata_file())?
                + synchronized_allocated_bytes(&index)?
        || receipt.synchronized_policy_bytes()? == 0
    {
        return Err(invalid(
            "Running metadata receipt differs from actual source custody",
        ));
    }
    let mut actual_body = vec![0; manifest.len()];
    receipt
        .metadata_file()
        .read_exact_at(&mut actual_body, receipt.manifest_range().start)?;
    if actual_body != manifest || receipt.manifest_range().length != manifest.len() as u64 {
        return Err(invalid(
            "retained manifest range differs from canonical metadata bytes",
        ));
    }
    Ok(())
}

fn check_policy(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    manifest: &Identity,
    pack: &Identity,
    payload: usize,
) -> io::Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("Running metadata snapshot absent"))?;
    let hashes = BTreeSet::from([hex(manifest.digest()), hex(pack.digest())]);
    if state.reservations.len() != 4
        || state.leases.len() != 3
        || state.pins.len() != 6
        || !state.residences.is_empty()
    {
        return Err(invalid(
            "Running retention lost the exact metadata policy closure",
        ));
    }
    let mut kinds = [0_usize; 3];
    for row in &state.reservations {
        let admission = format!("admission:{}", row.id);
        let retention = format!("metadata:{}", row.id);
        let owner = if state.leases.iter().any(|lease| lease.owner == admission) {
            kinds[0] += 1;
            if row.bytes != HOLD + payload as u64 {
                return Err(invalid("metadata admission hold changed"));
            }
            Some(admission)
        } else if state.leases.iter().any(|lease| lease.owner == retention) {
            kinds[1] += 1;
            if row.bytes != HOLD {
                return Err(invalid("metadata retention hold changed"));
            }
            Some(retention)
        } else {
            kinds[2] += 1;
            if row.bytes != HOLD {
                return Err(invalid("metadata bootstrap hold changed"));
            }
            None
        };
        if row.owner != inputs.owner {
            return Err(invalid("metadata reservation has another charge owner"));
        }
        if let Some(owner) = owner {
            let observed = state
                .pins
                .iter()
                .filter(|pin| pin.owner == owner && pin.expires == i64::MAX as u64)
                .map(|pin| pin.hash.clone())
                .collect::<BTreeSet<_>>();
            if observed != hashes
                || !state
                    .leases
                    .iter()
                    .any(|lease| lease.owner == owner && lease.expires == i64::MAX as u64)
            {
                return Err(invalid("metadata durable pin and lease closure changed"));
            }
        }
    }
    if kinds != [1, 2, 1] {
        return Err(invalid(
            "distinct Running metadata retentions did not complete",
        ));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn emit(message: &str) -> io::Result<()> {
    println!("{message}");
    io::stdout().flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim() != expected {
        return Err(invalid("unexpected metadata retention control"));
    }
    Ok(())
}
