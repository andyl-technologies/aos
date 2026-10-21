//! Exercises configured publication on actual separately enrolled domain owners.

#[path = "publisher/content.rs"]
mod content;

use super::config::{Case, DOMAINS, LIMIT, OWNERS, SEED};
use std::{io, path::PathBuf, sync::Arc};
use terrane_sdk::config::host::{
    DomainDirectory, DomainPublisher, HostTier, Publisher, Quota, Reassembly, Wipe,
};

pub(super) fn socket() -> PathBuf {
    PathBuf::from("/run/terrane-initial-publisher/publisher.sock")
}

pub(super) fn run() -> io::Result<()> {
    run_with(30_000)
}

pub(super) fn run_reassembly() -> io::Result<()> {
    run_with(1_000)
}

fn run_with(retirement_grace_ms: u64) -> io::Result<()> {
    super::reader::actual_identity(841, &[845])?;
    let case = Case::existing("positive")?;
    let host = configuration(&case, retirement_grace_ms, 30);
    terrane_linux::configured::run_configured_publisher(&host)
}

fn configuration(
    case: &Case,
    retirement_grace_ms: u64,
    consumer_release_grace_seconds: u64,
) -> HostTier {
    HostTier {
        path: case.path.to_string_lossy().into_owned(),
        size_bytes: 2 * LIMIT,
        reassembly: Reassembly::Never,
        domains: (0..2)
            .map(|owner| {
                (
                    DOMAINS[owner].to_owned(),
                    DomainDirectory {
                        cache: Some(terrane_sdk::config::host::cache::DomainCache {
                            state_gid: 844,
                            capacity_bytes: 24 * 1024 * 1024,
                            low_watermark_bytes: 16 * 1024 * 1024,
                            probation_bytes: 65536,
                            release_grace_seconds: consumer_release_grace_seconds,
                            scan_limit: 64,
                            max_read_bytes: 2 * 1024 * 1024,
                            state_bytes: 65536,
                            state_records: 64,
                            inventory_entries: 128,
                            queued_commands: 4,
                            metadata_sync_hold_bytes: 256 * 1024,
                            index_repair: None,
                            publisher_wait_budget_ms: 10_000,
                            consumer_lease_seconds: 30,
                            portable: terrane_sdk::config::host::cache::PortableLimits {
                                max_file_bytes: 64 * 1024 * 1024,
                                max_input_bytes: 256 * 1024 * 1024,
                                max_files: 4096,
                                max_selected_bytes: 32 * 1024 * 1024,
                            },
                        }),
                        path: case.root(owner).to_string_lossy().into_owned(),
                        administrative_root: Some(
                            case.administrative(owner).to_string_lossy().into_owned(),
                        ),
                        wipe: Wipe::None,
                        quota_owner_id: Some(OWNERS[owner].to_owned()),
                        publisher: Some(DomainPublisher {
                            retirement_grace_ms,
                            chunk_profile: "cdc-1m".to_owned(),
                            chunk_seed: SEED,
                        }),
                    },
                )
            })
            .collect(),
        publisher: Some(Publisher {
            socket_path: socket().to_string_lossy().into_owned(),
            serve_uid: 840,
            publish_uid: 841,
            content_uid: 840,
            content_gid: 845,
            max_connections: 8,
        }),
        quota: Some(Quota {
            socket_path: case.socket().to_string_lossy().into_owned(),
            configuration_epoch: 1u128.to_be_bytes(),
        }),
    }
}

pub(super) fn prepare() -> io::Result<()> {
    prepare_with(Preparation::Content)
}

pub(super) fn prepare_objects() -> io::Result<()> {
    prepare_with(Preparation::Objects)
}

pub(super) fn prepare_reassembly() -> io::Result<()> {
    prepare_with(Preparation::Reassembly)
}

#[derive(Clone, Copy)]
enum Preparation {
    Content,
    Objects,
    Reassembly,
}

fn prepare_with(preparation: Preparation) -> io::Result<()> {
    super::reader::actual_identity(840, &[844, 845])?;
    use terrane_format::chunking::ChunkProfile;
    use terrane_linux::configured::NativeCachePlan;

    let case = Case::existing("positive")?;
    // The separate reassembly scenario exercises an explicit one-second
    // retirement policy. Original enrollment keeps its thirty-second policy.
    let retirement_grace_ms = if matches!(preparation, Preparation::Reassembly) {
        1_000
    } else {
        30_000
    };
    let consumer_release_grace_seconds = if matches!(preparation, Preparation::Reassembly) {
        1
    } else {
        30
    };
    let mut host = configuration(&case, retirement_grace_ms, consumer_release_grace_seconds);
    if matches!(preparation, Preparation::Reassembly) {
        host.reassembly = Reassembly::Always;
    }
    let plan = NativeCachePlan::from_host(&host, terrane_format::refs::Locality::default())?;
    let confinement = Arc::new(terrane_linux::quota_confinement::install()?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut stores = runtime.block_on(plan.open(Arc::clone(&confinement)))?;
    assert_eq!(stores.len(), DOMAINS.len());
    for (owner, domain) in DOMAINS.iter().enumerate() {
        let configured = stores
            .remove(*domain)
            .ok_or_else(|| io::Error::other("configured native domain missing"))?;
        let store = configured.content();
        runtime.block_on(store.ready().validate_portable())?;
        assert_eq!(
            store
                .ready()
                .layout()
                .directory_binding("administrative-root")?,
            {
                use std::os::unix::fs::MetadataExt;
                let original = std::fs::metadata(case.administrative(owner))?;
                (original.dev(), original.ino())
            }
        );
        println!(
            "PASS actual portable validation, native recovery and publisher Resume for {} with private distinct administrative custody",
            domain
        );
        let profile = ChunkProfile::cdc_1m(SEED);
        match preparation {
            Preparation::Objects => runtime.block_on(content::exercise_objects(store, &profile))?,
            Preparation::Reassembly => {
                runtime.block_on(content::exercise_reassembly(&configured, &profile))?
            }
            Preparation::Content => {
                // Exercise direct sealing on the first genuine Running owner.
                // Another cold reopen would add an unrelated recovery workload
                // to this deliberately bounded 64-record content fixture.
                runtime.block_on(content::exercise_sealed(&configured))?;
                runtime.block_on(content::exercise(store, &profile))?;
            }
        }
        runtime.block_on(store.ready().validate_portable())?;
        if matches!(preparation, Preparation::Objects) {
            println!(
                "PASS actual reopened native chunked object reads and original grant renewal for {}",
                domain
            );
        } else if matches!(preparation, Preparation::Content) {
            println!(
                "PASS actual native ContentStore chunk and metadata admission, verified reads, ranges, membership and invalid deduplication context for {}",
                domain
            );
        }
    }
    confinement.check_current()
}
