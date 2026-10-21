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
    super::reader::actual_identity(841, &[845])?;
    let case = Case::existing("positive")?;
    let host = HostTier {
        path: case.path.to_string_lossy().into_owned(),
        size_bytes: 2 * LIMIT,
        reassembly: Reassembly::Never,
        domains: (0..2)
            .map(|owner| {
                (
                    DOMAINS[owner].to_owned(),
                    DomainDirectory {
                        path: case.root(owner).to_string_lossy().into_owned(),
                        administrative_root: Some(
                            case.administrative(owner).to_string_lossy().into_owned(),
                        ),
                        wipe: Wipe::None,
                        quota_owner_id: Some(OWNERS[owner].to_owned()),
                        publisher: Some(DomainPublisher {
                            retirement_grace_ms: 30_000,
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
    };
    terrane_linux::configured::run_configured_publisher(&host)
}

pub(super) fn prepare() -> io::Result<()> {
    prepare_with(Preparation::Content)
}

pub(super) fn prepare_objects() -> io::Result<()> {
    prepare_with(Preparation::Objects)
}

pub(super) fn prepare_sealed() -> io::Result<()> {
    prepare_with(Preparation::Sealed)
}

#[derive(Clone, Copy)]
enum Preparation {
    Content,
    Objects,
    Sealed,
}

fn prepare_with(preparation: Preparation) -> io::Result<()> {
    super::reader::actual_identity(840, &[844, 845])?;
    use std::time::Duration;
    use terrane_format::chunking::ChunkProfile;
    use terrane_linux::{
        host_cache::{NativeCacheOwnerConfig, NativeContentStore, NativeReady},
        host_quota::{filesystem_uuid, open_host_path},
        publisher_local::{client::ClientConfig, socket::RoleIdentities},
    };
    use terrane_sdk::bucket::portable_reader::PortableReadLimits;
    use terrane_sdk::host::cache::{HostDomainLocation, HostReadLimits, PolicyConfig, StateLimits};

    let case = Case::existing("positive")?;
    let confinement = Arc::new(terrane_linux::quota_confinement::install()?);
    for owner in 0..2 {
        let config = NativeCacheOwnerConfig {
            location: HostDomainLocation::new(
                case.root(owner),
                DOMAINS[owner].to_owned(),
                ChunkProfile::cdc_1m(SEED),
            )
            .map_err(super::source_error)?,
            administrative_root: Some(case.administrative(owner)),
            publisher: ClientConfig {
                socket_path: socket(),
                identities: RoleIdentities {
                    serve_uid: 840,
                    publish_uid: 841,
                },
                chunk_profile_name: "cdc-1m".to_owned(),
                wait_budget_ms: 10_000,
            },
            quota_socket: case.socket(),
            quota_epoch: 1u128.to_be_bytes(),
            quota_owner: OWNERS[owner].to_owned(),
            filesystem_uuid: filesystem_uuid(&open_host_path(&case.root(owner), true)?)?,
            project_id: case.project(owner),
            project_hard_limit_bytes: LIMIT,
            project_hard_inode_limit: 0,
            content_uid: 840,
            content_gid: 845,
            state_gid: 844,
            tier_charge_budget_bytes: 2 * LIMIT,
            policy: PolicyConfig {
                capacity: 24 * 1024 * 1024,
                low_watermark: 16 * 1024 * 1024,
                probation_bytes: 65536,
                release_grace: Duration::from_secs(30),
                scan_limit: 64,
            },
            retirement_interval: Duration::from_secs(30),
            reads: HostReadLimits {
                max_allocation_bytes: 2 * 1024 * 1024,
            },
            state: StateLimits {
                bytes: 65536,
                records: 64,
            },
            inventory_entries: 128,
            queued_commands: 4,
            metadata_sync_hold_bytes: 256 * 1024,
            index_repair: None,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let ready = runtime.block_on(NativeReady::open(
            config,
            case.bucket(owner, SEED),
            PortableReadLimits::default(),
            confinement.clone(),
        ))?;
        runtime.block_on(ready.validate_portable())?;
        assert_eq!(ready.layout().directory_binding("administrative-root")?, {
            use std::os::unix::fs::MetadataExt;
            let original = std::fs::metadata(case.administrative(owner))?;
            (original.dev(), original.ino())
        });
        println!(
            "PASS actual portable validation, native recovery and publisher Resume for {} with private distinct administrative custody",
            DOMAINS[owner]
        );
        let store =
            NativeContentStore::new(ready, Duration::from_secs(30)).map_err(super::source_error)?;
        let profile = ChunkProfile::cdc_1m(SEED);
        match preparation {
            Preparation::Objects => {
                runtime.block_on(content::exercise_objects(&store, &profile))?
            }
            Preparation::Content => runtime.block_on(content::exercise(&store, &profile))?,
            Preparation::Sealed => runtime.block_on(content::exercise_sealed(&store))?,
        }
        runtime.block_on(store.ready().validate_portable())?;
        if matches!(preparation, Preparation::Objects) {
            println!(
                "PASS actual reopened native chunked object reads and original grant renewal for {}",
                DOMAINS[owner]
            );
        } else if matches!(preparation, Preparation::Content) {
            println!(
                "PASS actual native ContentStore chunk and metadata admission, verified reads, ranges, membership and invalid deduplication context for {}",
                DOMAINS[owner]
            );
        }
    }
    confinement.check_current()
}
