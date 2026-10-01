//! Connected phase-major orchestration around direct publication barriers.

use super::*;

struct Barrier {
    log: UploadLog,
    refuse: bool,
}

#[async_trait::async_trait]
impl VisibilityBarrier for Barrier {
    async fn finish(&self) -> Result<()> {
        self.log
            .lock()
            .unwrap()
            .push(("direct".into(), "barrier".into()));
        if self.refuse {
            bail!("private-provider-credential-canary");
        }
        Ok(())
    }
}

async fn run(
    refuse: bool,
    broken_payload: bool,
) -> (Vec<StaticOriginFile>, UploadLog, Vec<String>) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("origin");
    write_fixture_origin(&root);
    let files = collect_static_origin_files(&root).unwrap();
    let log = UploadLog::default();
    let backend = RecordingBackend::new("generic", &log);
    let backend = if broken_payload {
        backend.failing_on("objects/aa/object")
    } else {
        backend
    };
    let destinations: Vec<(&str, Box<dyn CacheBackend>)> = vec![("generic", Box::new(backend))];
    let barriers: Vec<Box<dyn VisibilityBarrier>> = vec![Box::new(Barrier {
        log: log.clone(),
        refuse,
    })];
    let printer = Printer::new(0, true, false);
    let progress = printer.transfer("test direct barrier", total_bytes(&files).unwrap());
    let (failures, _) = upload_phase_major_with_barriers(
        &files,
        &destinations,
        true,
        true,
        &barriers,
        &printer,
        &progress,
    )
    .await;
    progress.finish();
    (files, log, failures)
}

#[tokio::test]
async fn direct_barrier_runs_after_all_generic_prerequisites_before_any_generic_visibility() {
    let (files, log, failures) = run(false, false).await;
    assert!(failures.is_empty());
    let events = log.lock().unwrap();
    let barrier = events
        .iter()
        .position(|(_, path)| path == "barrier")
        .unwrap();
    let prerequisites = files
        .iter()
        .filter(|file| file.class != StaticOriginClass::Mutable)
        .count();
    assert_eq!(barrier, prerequisites);
    for (_, path) in &events[..barrier] {
        assert_ne!(
            files
                .iter()
                .find(|file| file.relative_path == *path)
                .unwrap()
                .class,
            StaticOriginClass::Mutable
        );
    }
    for (_, path) in &events[barrier + 1..] {
        assert_eq!(
            files
                .iter()
                .find(|file| file.relative_path == *path)
                .unwrap()
                .class,
            StaticOriginClass::Mutable
        );
    }
}

#[tokio::test]
async fn refused_direct_barrier_keeps_generic_roots_stale_and_redacts_provider_error() {
    let (files, log, failures) = run(true, false).await;
    assert_eq!(failures.len(), 1);
    assert!(!failures[0].contains("private-provider-credential-canary"));
    let events = log.lock().unwrap();
    assert_eq!(
        events.iter().filter(|(_, path)| path == "barrier").count(),
        1
    );
    for (_, path) in events.iter().filter(|(_, path)| path != "barrier") {
        assert_ne!(
            files
                .iter()
                .find(|file| file.relative_path == *path)
                .unwrap()
                .class,
            StaticOriginClass::Mutable
        );
    }
}

#[tokio::test]
async fn failed_generic_payload_suppresses_direct_commit_and_every_generic_root() {
    let (files, log, failures) = run(false, true).await;
    assert!(!failures.is_empty());
    let events = log.lock().unwrap();
    assert!(!events.iter().any(|(_, path)| path == "barrier"));
    for (_, path) in events.iter() {
        assert_ne!(
            files
                .iter()
                .find(|file| file.relative_path == *path)
                .unwrap()
                .class,
            StaticOriginClass::Mutable
        );
    }
}
