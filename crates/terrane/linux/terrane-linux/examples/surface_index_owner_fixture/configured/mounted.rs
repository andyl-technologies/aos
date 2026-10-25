//! Drives genuine configured cold reads from actual coalesced kernel opens.
//!
//! The guest administrator mounts the original worker device. Serve holds only
//! its configured native owner and retained local service; no fabricated native
//! readiness or prepublished fixture backing enters this scenario.

use super::{
    NativeCachePlan, Result, paused_lower::PausedLower, quota_confinement,
    require_empty_capabilities,
};
use crate::{
    exposure::{limits, now},
    repository_fixture::RepositoryFixture,
    scoped_worker,
};
use std::{
    fs, io,
    os::fd::AsFd,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use terrane_format::{
    identity::{IdentityKind, TERRANE_V1},
    surface::ViewTarget,
    tree_format::ContentRef,
};
use terrane_linux::{
    host_cache::NativeReadPolicy,
    structural_index::Kind,
    worker_channel::service::{Context, Options, Service},
};
use terrane_sdk::{
    config::Config,
    host::cache::{CacheState, ExposurePhase, ReassemblyMode, StateLimits},
    store::TokioLocalFs,
};
use tokio::{sync::Notify, task::LocalSet, time::timeout};

/// Selects the original mounted cold-read lifecycle exercised by this guest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scenario {
    /// Drains explicitly after original coalesced reads complete.
    Ordinary,
    /// Expires kernel opens while retaining their original cold preparation.
    Late,
    /// Waits for the actual durable exposure lease to expire without stop.
    Expiry,
    /// Resolves a genuine signed multi-chunk manifest only when the kernel opens it.
    Manifest,
}

const BODY: &[u8] = b"actual scoped worker backing through serialized owner Send";

/// Starts the fixture child before dropping privilege and recovering real caches.
///
/// # Errors
/// Refuses invalid configuration, child identity, confinement, native recovery,
/// original request lifetime, cache handoff or final disclosure behavior.
pub(crate) fn run(scenario: Scenario) -> Result<()> {
    let mut arguments = std::env::args().skip(2);
    let path = PathBuf::from(arguments.next().ok_or("missing worker configuration")?);
    if arguments.next().is_some() {
        return Err("unexpected configured worker argument".into());
    }
    let launched = if scenario == Scenario::Late {
        scoped_worker::mounted::launch_late()?
    } else {
        scoped_worker::mounted::launch()?
    };
    require_empty_capabilities()?;
    let config = Config::parse(&fs::read_to_string(&path)?)?;
    let host = config
        .host_tier()
        .ok_or("missing configured worker host tier")?;
    let plan = NativeCachePlan::from_host(host, Default::default())?;
    let confinement = Arc::new(quota_confinement::install()?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = LocalSet::new();
    runtime.block_on(async {
        let result = local
            .run_until(Box::pin(verify(
                &local,
                launched,
                scenario,
                plan,
                confinement,
                host,
                path.parent().ok_or("worker configuration has no parent")?,
            )))
            .await;
        if let Err(error) = &result {
            eprintln!("configured mounted owner failed before runtime drain: {error}");
        }
        // Even a failed assertion must drive an accepted service through drain
        // and its bounded publication before the fixture tears down its runtime.
        local.await;
        result
    })
}

async fn verify(
    local: &LocalSet,
    mut launched: scoped_worker::Launched,
    scenario: Scenario,
    plan: NativeCachePlan,
    confinement: Arc<quota_confinement::Installed>,
    host: &terrane_sdk::config::host::HostTier,
    source_parent: &std::path::Path,
) -> Result<()> {
    let started_at = tokio::time::Instant::now();
    let stage = |phase| {
        eprintln!(
            "CONFIGURED_MOUNTED_STAGE phase={phase} elapsed_ms={}",
            started_at.elapsed().as_millis()
        );
    };
    let mut caches = plan.open(confinement).await?;
    let cache = caches
        .remove("public")
        .ok_or("missing original worker cache")?;
    if cache.reassembly() != ReassemblyMode::Always {
        return Err("configured worker requires explicit always policy".into());
    }
    let native = cache.into_content();
    let profile = native.ready().layout().layout().chunk_profile();
    let mut policy = Vec::new();
    terrane_format::cbor::write_text(&mut policy, "always");
    let fixture = Box::pin(RepositoryFixture::new_with_properties(
        "public",
        source_parent,
        vec![("reassembly".into(), policy)],
        profile.seed(),
    ))
    .await?;
    let body = if scenario == Scenario::Manifest {
        manifest_body()
    } else {
        BODY.to_vec()
    };
    let boundaries = profile.boundaries(&body);
    if scenario == Scenario::Manifest && boundaries.len() < 2 {
        return Err("mounted manifest fixture requires actual multi-chunk input".into());
    }
    let mut chunk_hashes = Vec::new();
    for range in &boundaries {
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &body[range.clone()])?;
        let hash: String = identity
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        chunk_hashes.push(hash);
    }
    let commit = Box::pin(fixture.commit(&body)).await?;
    let reads = Arc::new(AtomicUsize::new(0));
    let manifests = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let mut driver = None;
    let read_policy = NativeReadPolicy::new(Duration::from_secs(10), 3, Duration::from_secs(5))?;
    let repository = Rc::new(fixture.repository.with_read_driver(|original| {
        let actual = native.with_lower(
            PausedLower {
                original: original.clone(),
                reads: Arc::clone(&reads),
                manifests: Arc::clone(&manifests),
                started: Arc::clone(&started),
                resume: Arc::clone(&resume),
            },
            read_policy,
        );
        driver = Some(actual.clone());
        actual
    }));
    let driver = driver.ok_or("missing original configured worker driver")?;
    let owner = driver.native().ready().owner();
    let root = &host.domains["public"];
    let resources = root
        .cache
        .as_ref()
        .ok_or("missing worker cache resources")?;
    let state_limits = StateLimits {
        bytes: resources.state_bytes,
        records: resources.state_records,
    };
    let state_path = PathBuf::from(&root.path).join("state/cache");
    let snapshot = || snapshot(&state_path, state_limits);
    let target = ViewTarget::Commit(commit);
    let selected = repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    let served = Rc::new(owner.prepare_surface_mapping(selected).await?);
    let content = match served.index().lookup(b"file").map(|entry| entry.kind()) {
        Some(Kind::File { content, size }) if size == body.len() as u64 => content,
        _ => return Err("mounted index lost its original signed file metadata".into()),
    };
    if matches!(content, ContentRef::Manifest(_)) != (scenario == Scenario::Manifest)
        || reads.load(Ordering::Relaxed) != 0
        || manifests.load(Ordering::Relaxed) != 0
    {
        return Err(
            "structural index compilation fetched content or changed its signed kind".into(),
        );
    }
    let content = match content {
        ContentRef::Inline(hash) | ContentRef::Manifest(hash) => hash,
    };
    let expires = now()? + if scenario == Scenario::Expiry { 20 } else { 90 };
    let lease = owner.retain_surface_exposure(&served, expires).await?;
    owner.check_running().await?;
    stage("index-and-exposure-ready");
    println!(
        "PASS configured native owner completes actual recovery and acknowledged Resume before mounted worker startup"
    );
    send(b"PREPARED")?;
    let channel = launched.bind(&lease)?;
    launched.send_context(&lease, content)?;
    let mut service = Service::start(
        local,
        channel,
        Context {
            repository: Rc::clone(&repository),
            served: Rc::clone(&served),
            driver: driver.clone(),
            token: fixture.authority.token().to_vec(),
            surface: "sdk".into(),
            options: Options {
                metadata_budget: Duration::from_secs(5),
                fetch_budget: Duration::from_secs(10),
                reassembly: ReassemblyMode::Always,
                file_expires: expires,
                root_limits: limits(),
            },
        },
    )?;

    phase(&mut service, launched.receive_control(b"READY")).await??;
    stage("kernel-ready");
    send(b"READY")?;
    phase(
        &mut service,
        timeout(Duration::from_secs(5), started.notified()),
    )
    .await??;
    phase(&mut service, launched.receive_control(b"COALESCED")).await??;
    stage("first-lower-read-paused-and-opens-coalesced");
    send(b"FETCH")?;
    if scenario == Scenario::Late {
        phase(&mut service, launched.receive_control(b"EXPIRED")).await??;
        phase(&mut service, launched.receive_control(b"EXPIRED")).await??;
        if service.is_finished() || reads.load(Ordering::Relaxed) != 1 {
            return Err("expired kernel opens cancelled their original retained cold work".into());
        }
        send(b"EXPIRED")?;
        // The next actual kernel open must join the still accepted original
        // request before its lower read is released; it cannot start a retry.
        phase(&mut service, launched.receive_control(b"COALESCED")).await??;
    }
    phase(&mut service, receive(b"G")).await??;
    stage("original-lower-read-resumed");
    resume.notify_one();
    phase(&mut service, receive(b"D")).await??;
    stage("kernel-reads-complete");

    let before = snapshot().await?;
    let original = before
        .exposures
        .iter()
        .find(|row| row.id == lease.id())
        .ok_or("mounted configured worker lost its original exposure")?;
    let identity_hash: String = content.iter().map(|byte| format!("{byte:02x}")).collect();
    if original.phase != ExposurePhase::Active
        || original.backings.len() != 2
        || reads.load(Ordering::Relaxed) != boundaries.len()
        || manifests.load(Ordering::Relaxed) != usize::from(scenario == Scenario::Manifest)
        || chunk_hashes
            .iter()
            .any(|hash| !before.residences.iter().any(|row| row.chunk == *hash))
        || before.pins.iter().any(|row| {
            (chunk_hashes.contains(&row.hash) || row.hash == identity_hash)
                && row.owner.starts_with("publication:")
        })
    {
        return Err(
            "mounted configured reads omitted original cache handoff or backing custody".into(),
        );
    }

    if scenario == Scenario::Expiry {
        let result = timeout(Duration::from_secs(25), service.wait()).await?;
        if now()? < expires
            || !matches!(result, Err(terrane_sdk::repository::Error::Io(ref error))
            if error.kind() == io::ErrorKind::PermissionDenied)
        {
            return Err(
                format!("expired original exposure returned another result: {result:?}").into(),
            );
        }
    } else {
        service.stop().await?;
    }
    // The retained service closes its original channel only after durable
    // drain. The idle worker must observe that closure without a kernel open
    // or a second supervisor control causing its device to abort.
    launched.receive_control(b"STOPPED").await?;
    launched.wait_for_exit().await?;
    let after = snapshot().await?;
    let retained = after
        .exposures
        .iter()
        .find(|row| row.id == lease.id())
        .ok_or("mounted configured stop erased original exposure custody")?;
    // Consumer grace may expire while this scenario waits for the actual lease
    // deadline. Its exposure pins still protect every retained kernel backing.
    let exposure_owner = format!("exposure:{}", lease.id());
    let original_pins = before
        .pins
        .iter()
        .filter(|pin| scenario != Scenario::Expiry || pin.owner == exposure_owner)
        .map(|pin| (&pin.owner, &pin.hash, pin.expires))
        .collect::<Vec<_>>();
    let retained_pins = after
        .pins
        .iter()
        .filter(|pin| scenario != Scenario::Expiry || pin.owner == exposure_owner)
        .map(|pin| (&pin.owner, &pin.hash, pin.expires))
        .collect::<Vec<_>>();
    let mut expected_exposure = original.clone();
    expected_exposure.phase = ExposurePhase::Draining;
    if retained != &expected_exposure || original_pins.is_empty() || original_pins != retained_pins
    {
        return Err(
            "mounted configured stop inferred physical release from connection closure".into(),
        );
    }
    println!(
        "PASS actual signed-owner index and verified backing serve coalesced kernel opens through the production worker"
    );
    println!(
        "PASS durable drain stops the mounted production worker while retaining original physical bindings and pins"
    );
    println!(
        "PASS configured production worker opens fetch and seal original signed cold backing through retained service before kernel reads"
    );
    if scenario == Scenario::Late {
        println!(
            "PASS actual kernel open deadlines return EIO while original configured cold work survives and a later open joins the same fetch before sealed handoff"
        );
    }
    if scenario == Scenario::Expiry {
        println!(
            "PASS actual durable exposure expiry autonomously drains retained service and disconnects idle mounted worker while preserving original kernel backing custody"
        );
    }
    if scenario == Scenario::Manifest {
        println!(
            "PASS actual kernel opens resolve original signed multi-chunk manifest only after metadata index compilation and retain one sealed backing through coalesced reads and drain"
        );
    }
    send(b"DRAINED")?;
    Ok(())
}

async fn snapshot(path: &std::path::Path, limits: StateLimits) -> Result<CacheState> {
    CacheState::load(&TokioLocalFs, path, limits)
        .await?
        .ok_or_else(|| "missing original mounted configured state".into())
}

async fn phase<T>(
    service: &mut Service,
    future: impl std::future::Future<Output = T>,
) -> Result<T> {
    tokio::select! {
        result = service.wait() => Err(format!("retained service ended before mounted phase: {result:?}").into()),
        result = future => Ok(result),
    }
}

fn send(bytes: &[u8]) -> Result<()> {
    if rustix::net::send(
        io::stdout().as_fd(),
        bytes,
        rustix::net::SendFlags::NOSIGNAL | rustix::net::SendFlags::DONTWAIT,
    )? != bytes.len()
    {
        return Err("incomplete mounted configured supervisor control".into());
    }
    Ok(())
}

async fn receive(expected: &[u8]) -> Result<()> {
    scoped_worker::mounted::receive_async(io::stdout().as_fd(), expected).await
}

/// Produces deterministic nonrepeating data spanning several original CDC chunks.
fn manifest_body() -> Vec<u8> {
    let mut state = 7_u32;
    (0..2_097_153)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}
