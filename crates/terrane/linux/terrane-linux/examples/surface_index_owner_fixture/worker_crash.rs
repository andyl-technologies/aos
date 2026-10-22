//! Retains an original worker mapping across administrative owner SIGKILL.
//!
//! The outer guest supervisor kills actual processes using original pidfds.
//! Neither EOF nor a public PID is treated as physical closure evidence.

use super::{
    Result, config, exposure,
    repository_fixture::{MAIN, RepositoryFixture},
    scoped_worker::{self, Launched},
};
use std::{fs, io, io::Write, os::unix::fs::MetadataExt, time::Duration};
use terrane_format::{
    identity::{IdentityKind, TERRANE_V1},
    surface::ViewTarget,
};
use terrane_linux::{
    host_cache::NativeMetadataOwner, structural_index::MappedIndex,
    worker_channel::RequestedBacking,
};
use terrane_sdk::host::cache::{ExposureBackingKind, ExposurePhase};

/// Runs the real owner until the administrative supervisor kills it.
///
/// # Errors
/// Refuses failed scoped grants, changed original backing, lost custody, or
/// absence of the expected administrative kill within the bounded fixture wait.
pub(super) fn run(
    launched: Launched,
    runtime: &tokio::runtime::Runtime,
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
) -> Result<()> {
    runtime.block_on(Box::pin(prepare(launched, owner, inputs)))
}

async fn prepare(
    mut launched: Launched,
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
) -> Result<()> {
    let body = b"forced owner crash with independently retained original index";
    let fixture = RepositoryFixture::new(&inputs.domain).await?;
    fixture.commit(body).await?;
    let target = ViewTarget::Ref(MAIN.parse()?);
    let selection = fixture
        .repository
        .prepare_root_read(
            &target,
            fixture.authority.token(),
            "sdk",
            exposure::limits(),
        )
        .await?;
    let served = owner.prepare_surface_mapping(selection).await?;
    let key = served.key();
    let lease = owner
        .retain_surface_exposure(&served, exposure::now()? + 90)
        .await?;
    let id = lease.id().to_owned();
    let mut channel = launched.bind(&lease)?;
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, body)?;
    launched.send_context(&lease, identity.digest().try_into()?)?;
    scoped_worker::readable(&channel)?;
    let selection = fixture
        .repository
        .prepare_root_read(
            &target,
            fixture.authority.token(),
            "sdk",
            exposure::limits(),
        )
        .await?;
    channel
        .receive()?
        .grant_index(owner, &served, selection)
        .await?;
    let held = launched.acknowledgment()?;
    let before = exposure::snapshot(inputs).await?;
    let row = before
        .exposures
        .iter()
        .find(|row| row.id == id)
        .ok_or("crash fixture lost original exposure")?;
    let backing = row
        .backings
        .iter()
        .find(|row| row.kind == ExposureBackingKind::Index)
        .ok_or("crash fixture lost original index binding")?;
    if held != format!("HELD {} {}\n", backing.device, backing.inode) {
        return Err("crash worker mapped another inode".into());
    }
    let original_backings = row.backings.clone();

    owner.drain_surface_exposure(&lease).await?;
    drop(channel);
    drop(served);
    drop(lease);
    if !owner.retire_draining_surface_index(key).await?
        || super::canonical_path(inputs, key.root()).exists()
    {
        return Err("crash fixture failed checked original index retirement".into());
    }
    let retained = exposure::snapshot(inputs).await?;
    if !retained.exposures.iter().any(|row| {
        row.id == id && row.phase == ExposurePhase::Draining && row.backings == original_backings
    }) {
        return Err("retirement discarded original worker custody before crash".into());
    }
    println!("PASS original worker holds retired index mapping before forced owner death");
    io::stdout().flush()?;
    // This is a bounded crash fixture rendezvous, not a service implementation.
    // Keep the actual child and original owner alive until the outer supervisor
    // delivers SIGKILL; ordinary Drop would not qualify the intended crash.
    tokio::time::sleep(Duration::from_secs(30)).await;
    drop(launched);
    Err("administrative owner SIGKILL did not arrive".into())
}

/// Holds the genuine mapped index independently of the original owner process.
///
/// # Errors
/// Refuses invalid context, a mismatched index or absence of administrative kill.
#[allow(clippy::disallowed_methods)]
pub(super) fn child() -> Result<()> {
    let (mut client, root, _) = scoped_worker::child_context()?;
    let index = scoped_worker::reply(&mut client.request(RequestedBacking::Index)?)?.into_file();
    let metadata = index.metadata()?;
    let seal = terrane_linux::verity::measure(&index)?;
    let mapping = MappedIndex::open(index.into(), root, &seal, 65536)?;
    if mapping.index().lookup(b"file").is_none() {
        return Err("crash worker did not map the signed root".into());
    }
    println!("HELD {} {}", metadata.dev(), metadata.ino());
    io::stdout().flush()?;
    // Retain the mapping despite EOF on both sockets after owner death. Only
    // actual process death closes these kernel references in this scenario.
    std::thread::sleep(Duration::from_secs(30));
    drop(mapping);
    Err("administrative worker SIGKILL did not arrive".into())
}

/// Checks actual cold refusal or funded recovery after forced process death.
///
/// # Errors
/// Refuses mutated policy on incomplete closure, a missing original draining
/// exposure, failed recovery, or discharge extending beyond that exposure.
pub(super) fn recover(
    mode: &str,
    runtime: &tokio::runtime::Runtime,
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
) -> Result<()> {
    let path = inputs.root.join("state/cache/records.toml");
    let bytes = fs::read(&path)?;
    let before = runtime.block_on(exposure::snapshot(inputs))?;
    if before.exposures.len() != 1
        || before.exposures[0].phase != ExposurePhase::Draining
        || before.exposures[0].backings.len() != 1
        || before.exposures[0].backings[0].kind != ExposureBackingKind::Index
    {
        return Err("crash recovery requires the original single retired exposure".into());
    }
    let row = &before.exposures[0];
    let canonical = inputs.root.join("objects").join(format!(
        ".terrane-surface:{}:{}",
        row.index_version, row.root
    ));
    if canonical.exists() {
        return Err("crash recovery found a resurrected canonical index".into());
    }
    if mode == "crash-refuse" {
        match runtime.block_on(owner.recover()) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err("owner death discarded custody of a surviving worker mapping".into());
            }
        }
        if fs::read(&path)? != bytes {
            return Err("cold refusal changed original durable policy bytes".into());
        }
        println!(
            "PASS forced owner death preserves exact policy while original worker mapping survives"
        );
        return Ok(());
    }
    let completed = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match owner.recover().await {
                    Ok(completed) => return Ok::<_, Box<dyn std::error::Error>>(completed),
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && fs::read(&path)? == bytes =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await
    })??;
    // A genuine recovery retains its newly funded metadata bootstrap after
    // Resume. Compare this one new hold separately; it grants no native authority.
    let recovered = runtime.block_on(exposure::snapshot(inputs))?;
    let new_holds: Vec<_> = recovered
        .reservations
        .iter()
        .filter(|hold| !before.reservations.iter().any(|old| old.id == hold.id))
        .collect();
    let config = inputs.owner_config()?;
    let [bootstrap] = new_holds.as_slice() else {
        return Err("forced recovery did not retain exactly one new bootstrap hold".into());
    };
    if bootstrap.owner != config.quota_owner
        || bootstrap.bytes != config.metadata_sync_hold_bytes
        || bootstrap.id.len() != 32
        || !bootstrap
            .id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || before
            .reservations
            .iter()
            .try_fold(bootstrap.bytes, |sum, hold| sum.checked_add(hold.bytes))
            .ok_or("recovery hold sum overflows")?
            != completed.future_hold_bytes()
    {
        return Err("forced recovery changed its funded metadata bootstrap".into());
    }
    let bootstrap = (*bootstrap).clone();
    runtime.block_on(owner.resume_recovered(completed))?;
    let after = runtime.block_on(exposure::snapshot(inputs))?;
    let mut expected = before;
    expected.reservations.push(bootstrap);
    let pin_owner = expected.exposures[0].pin_owner();
    expected.exposures.clear();
    expected.pins.retain(|pin| pin.owner != pin_owner);
    expected.leases.retain(|lease| lease.owner != pin_owner);
    // The fixture compares every typed field, including the private snapshot
    // version, without introducing an alternate cache-state encoder.
    if format!("{after:?}") != format!("{expected:?}") || canonical.exists() {
        eprintln!(
            "CRASH_RECOVERY expected={expected:?} actual={after:?} canonical_exists={}",
            canonical.exists()
        );
        return Err("forced crash recovery changed obligations beyond original exposure".into());
    }
    println!(
        "PASS actual worker death permits authenticated closure and funded recovery before Resume"
    );
    Ok(())
}
