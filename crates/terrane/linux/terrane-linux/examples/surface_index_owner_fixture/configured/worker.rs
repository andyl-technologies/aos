//! Retains an actual configured cold request through cancelled waits and drain.

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
    os::{fd::AsFd, unix::fs::FileExt},
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
    surface::{View, ViewTarget},
};
use terrane_linux::{
    host_cache::NativeReadPolicy,
    structural_index::Kind,
    worker_channel::{
        RequestedBacking,
        service::{Context, Options, Service},
    },
};
use terrane_sdk::{
    config::Config,
    host::cache::{CacheState, ExposurePhase, ReassemblyMode, StateLimits},
    store::{StoreErrorKind, TokioLocalFs},
};
use tokio::{sync::Notify, task::LocalSet, time::timeout};

const BODY: &[u8] = b"retained configured cold worker completes original cache handoff";

/// Starts the fixture child before dropping privilege and recovering real caches.
///
/// # Errors
/// Refuses invalid configuration, child identity, confinement, native recovery,
/// original request lifetime, cache handoff or final disclosure behavior.
pub(crate) fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(2);
    let path = PathBuf::from(arguments.next().ok_or("missing worker configuration")?);
    if arguments.next().is_some() {
        return Err("unexpected configured worker argument".into());
    }
    let launched = scoped_worker::launch_configured()?;
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
                plan,
                confinement,
                host,
                path.parent().ok_or("worker configuration has no parent")?,
            )))
            .await;
        // Even a failed assertion must drive an accepted service through drain
        // and its bounded publication before the fixture tears down its runtime.
        local.await;
        result
    })
}

async fn verify(
    local: &LocalSet,
    mut launched: scoped_worker::Launched,
    plan: NativeCachePlan,
    confinement: Arc<quota_confinement::Installed>,
    host: &terrane_sdk::config::host::HostTier,
    source_parent: &std::path::Path,
) -> Result<()> {
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
    let commit = Box::pin(fixture.commit(BODY)).await?;
    let content: [u8; 32] = TERRANE_V1
        .calculate(IdentityKind::Chunk, BODY)?
        .digest()
        .try_into()?;
    let reads = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let mut driver = None;
    let read_policy = NativeReadPolicy::new(Duration::from_secs(10), 3, Duration::from_secs(5))?;
    let repository = Rc::new(fixture.repository.with_read_driver(|original| {
        let actual = native.with_lower(
            PausedLower {
                original: original.clone(),
                reads: Arc::clone(&reads),
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
    let expires = now()? + 90;
    let lease = owner.retain_surface_exposure(&served, expires).await?;
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

    {
        let waiting = service.wait();
        tokio::pin!(waiting);
        timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut waiting => Err(format!("worker ended before withheld cold read: {result:?}")),
                _ = started.notified() => Ok(()),
            }
        }).await??;
    }
    let original = snapshot()
        .await?
        .exposures
        .into_iter()
        .find(|row| row.id == lease.id())
        .ok_or("worker omitted original exposure")?;
    if original.phase != ExposurePhase::Active
        || service.is_finished()
        || reads.load(Ordering::Relaxed) != 1
    {
        return Err("cancelled supervisor wait cancelled or drained original preparation".into());
    }

    let stopped = service.stop();
    tokio::pin!(stopped);
    timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                result = &mut stopped => return Err(format!("worker stopped before withheld read resumed: {result:?}").into()),
                result = snapshot() => {
                    let state = result?;
                    if state.exposures.iter().any(|row| row.id == lease.id() && row.phase == ExposurePhase::Draining) {
                        return Ok::<_, Box<dyn std::error::Error>>(());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    resume.notify_one();
    if !matches!(timeout(Duration::from_secs(10), &mut stopped).await?,
        Err(terrane_sdk::repository::Error::Store(ref error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    {
        return Err("drained cold request did not preserve its exact disclosure refusal".into());
    }
    if launched.acknowledgment()? != "CANCELLED\n" {
        return Err("original worker received unexpected disclosure".into());
    }
    launched.wait_for_exit().await?;
    let view = View {
        target,
        subtree: Vec::new(),
        policy: None,
    };
    let selection = repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    let warm = driver
        .prepare_file_backing(
            selection,
            ReassemblyMode::Always,
            Duration::from_secs(10),
            now()? + 30,
        )
        .await?;
    let file = fs::File::from(warm.as_fd().try_clone_to_owned()?);
    terrane_linux::verity::measure(&file)?;
    let mut bytes = vec![0; BODY.len()];
    file.read_exact_at(&mut bytes, 0)?;
    if bytes != BODY
        || file.metadata()?.len() != BODY.len() as u64
        || reads.load(Ordering::Relaxed) != 1
    {
        return Err("retained cold handoff lost sealed plaintext or refetched warm content".into());
    }
    owner.release_sealed_object_lease(warm.lease()).await?;
    let state = snapshot().await?;
    let hash: String = content.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut expected = original;
    expected.phase = ExposurePhase::Draining;
    if !state.residences.iter().any(|row| row.chunk == hash)
        || state
            .pins
            .iter()
            .any(|row| row.hash == hash && row.owner.starts_with("publication:"))
        || state.exposures.iter().find(|row| row.id == lease.id()) != Some(&expected)
    {
        return Err(
            "retained request omitted cache handoff or changed original draining custody".into(),
        );
    }
    println!(
        "PASS retained configured worker service completes original cold cache handoff after cancelled wait and acknowledged drain without disclosing backing"
    );
    Ok(())
}

async fn snapshot(path: &std::path::Path, limits: StateLimits) -> Result<CacheState> {
    CacheState::load(&TokioLocalFs, path, limits)
        .await?
        .ok_or_else(|| "missing original configured worker state".into())
}

/// Requests original signed backing from the actual distinct worker identity.
///
/// # Errors
/// Refuses a changed mapped root, successful post-drain disclosure or any errno
/// other than the channel's exact refused-handoff result.
pub(crate) fn child() -> Result<()> {
    let (mut client, _, content) = scoped_worker::child_context()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mapping = client.request_index_bounded(65536, Duration::from_secs(10)).await?;
        if !mapping.index().lookup(b"file").is_some_and(|entry| {
            matches!(entry.kind(), Kind::File { content: selected, size } if selected == content && size == BODY.len() as u64)
        }) {
            return Err("configured worker mapped another signed file".into());
        }
        if !matches!(client.request_bounded(RequestedBacking::File { path: b"file".to_vec(), content }, Duration::from_secs(10)).await,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied) {
            return Err("configured worker disclosed cold backing after acknowledged drain".into());
        }
        if mapping.index().lookup(b"file").is_none() {
            return Err("drain invalidated the original retained index".into());
        }
        println!("CANCELLED");
        Ok(())
    })
}
