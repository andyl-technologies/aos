//! Composes native publication and cache owners from explicit host configuration.
//!
//! Configuration is checked for every domain before confinement or filesystem
//! effects. Authenticated quota observations are then bound to retained native
//! roots before publication startup can allocate. No repository credentials or
//! read tokens participate in the publisher role. [`NativeCachePlan`] shares the
//! configured domain partition but obtains its own actual recovered cache custody.

#![cfg(feature = "tokio")]

mod administrative;
mod cache;

pub use cache::{NativeCacheDomainSettings, NativeCachePlan, NativeConfiguredCache};

use administrative::AdministrativeRoot;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    os::fd::OwnedFd,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use terrane_sdk::config::host::{HostTier, Wipe};

use crate::{
    host_quota::{
        DomainProvisioningGuard, HostQuotaClient, NativeProject, ROOT_LABELS,
        VerifiedQuotaObservation, filesystem_uuid, open_host_path,
    },
    publisher_io::{
        NativeCommandContext, NativeCommandResult, NativeOperation, NativePublicationWorker,
        NativePublisherConfig, NativeRetirementPolicy, NativeWipePolicy,
    },
    publisher_local::{
        server::{DomainPublisher, Server, ServerConfig},
        socket::{RoleIdentities, retain_listener_parent},
    },
};

/// Runs the actual configured native publisher until its listener fails.
///
/// Validates every domain before installing one irreversible process boundary.
/// Actual authenticated quota/root evidence precedes all native startup writes;
/// each prepared owner and accepted command retains that evidence. The role
/// never opens a Store, repository, read token or backend credential.
///
/// Callers invoke this synchronous entry in a fresh single-threaded process.
/// Failure after confinement installation requires process exit, never fallback
/// to another role or an unconfined retry. Manifest retention and cache recovery
/// authorization remain unavailable without their actual cache-owner bridges.
///
/// # Errors
///
/// Rejects incomplete/invalid configuration, another process identity, unsafe
/// socket ancestry, unsupported wipe, failed confinement, unavailable quota
/// evidence, root/project/budget mismatches, preparation/recovery errors, a
/// failed actual seal probe or listener/connection-owner startup failures.
/// Publisher confinement also rejects inherited undeclared or network descriptors
/// and a kernel socket restriction that fails its actual startup probes.
pub fn run_configured_publisher(host: &HostTier) -> io::Result<()> {
    let config = preflight(host)?;
    let network = Arc::new(crate::quota_confinement::install_publisher()?);
    let confinement = Arc::clone(network.quota());
    let socket_ancestors =
        retain_listener_parent(&config.endpoint.socket_path, config.endpoint.identities)
            .map_err(io::Error::other)?;
    let quotas = check_quotas(&config)?;
    let custody = Arc::new(ConfiguredPublisherCustody {
        confinement: confinement.clone(),
        network,
        quotas,
        _socket_ancestors: socket_ancestors,
        quota_path: config.quota_path.clone(),
        quota_epoch: config.quota_epoch,
    });

    // Preparation is readonly and retains actual roots. No domain starts
    // allocation until every configured owner passed these same checks.
    let mut prepared_domains = Vec::with_capacity(config.domains.len());
    for domain in config.domains {
        let mut prepared = domain.native.prepare(confinement.clone())?;
        prepared.retain_configured_custody(custody.clone())?;
        prepared_domains.push((prepared, domain.profile_name));
    }
    let mut domains = Vec::with_capacity(prepared_domains.len());
    for (prepared, profile_name) in prepared_domains {
        let domain = prepared.configuration().domain.clone();
        let profile = prepared.configuration().profile.clone();
        let worker = NativePublicationWorker::start_prepared(prepared)?;
        domains.push(DomainPublisher {
            domain,
            chunk_profile_name: profile_name,
            chunk_profile: profile,
            worker,
        });
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut bootstrap_incarnation = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bootstrap_incarnation)?;
    for domain in &domains {
        let context = NativeCommandContext {
            domain: domain.domain.clone(),
            cache_incarnation: bootstrap_incarnation,
        };
        match runtime.block_on(
            domain
                .worker
                .execute(context.clone(), NativeOperation::Drain),
        )? {
            NativeCommandResult::Complete => {}
            _ => return Err(invalid("unexpected native startup drain result")),
        }
        match runtime.block_on(domain.worker.execute(context, NativeOperation::Probe))? {
            NativeCommandResult::Probe { probe } => {
                let measured = crate::verity::measure(probe.handle())?;
                if measured.algorithm != probe.binding().algorithm
                    || measured.digest != probe.binding().digest
                {
                    return Err(invalid("native startup seal measurement changed"));
                }
            }
            _ => return Err(invalid("unexpected native startup probe result")),
        }
    }
    drop(runtime);
    confinement.check_current()?;
    Server::bind(config.endpoint, domains)
        .map_err(io::Error::other)?
        .with_configured_custody(custody)
        .run()
        .map_err(io::Error::other)
}

struct Preflight {
    endpoint: ServerConfig,
    domains: Vec<Domain>,
    quota_path: PathBuf,
    quota_epoch: [u8; 16],
    tier_budget: u64,
}

struct Domain {
    native: NativePublisherConfig,
    profile_name: String,
    owner_id: String,
    administrative_root: Option<PathBuf>,
}

// These actual files, observations and shared guards remain together. A wire
// boolean or successful configuration parse cannot construct this custody.
struct CheckedQuota {
    observation: VerifiedQuotaObservation,
    roots: Vec<File>,
    publication_state: File,
    administrative: Option<AdministrativeRoot>,
    _guard: DomainProvisioningGuard,
}

/// Retains actual configured-role enforcement and allocation-root custody.
///
/// Only this module constructs the value after native checks. Concrete socket
/// owners retain it until all accepted physical work finishes, even if the
/// listening service exits first.
pub(crate) struct ConfiguredPublisherCustody {
    confinement: Arc<crate::quota_confinement::Installed>,
    network: Arc<crate::quota_confinement::PublisherInstalled>,
    quotas: Vec<CheckedQuota>,
    quota_path: PathBuf,
    quota_epoch: [u8; 16],
    _socket_ancestors: Vec<OwnedFd>,
}

impl ConfiguredPublisherCustody {
    /// Rechecks the actual quota partition and process for a prepared root.
    ///
    /// # Errors
    ///
    /// Rejects another confinement receipt, a changed process, an uncovered
    /// domain or any live root/project/UUID mismatch.
    pub(crate) fn check_domain(
        &self,
        domain: &str,
        root: &File,
        confinement: &Arc<crate::quota_confinement::Installed>,
    ) -> io::Result<()> {
        if !Arc::ptr_eq(&self.confinement, confinement) {
            return Err(invalid("prepared owner uses another confinement receipt"));
        }
        self.network.check_current()?;
        let checked = self
            .quotas
            .iter()
            .find(|checked| checked.observation.observation().domain == domain)
            .ok_or_else(|| invalid("prepared domain lacks authenticated quota custody"))?;
        let observation = checked.observation.observation();
        let expected_root = observation
            .roots
            .iter()
            .find(|root| root.role_directory == "layout-root")
            .ok_or_else(|| invalid("quota domain root missing"))?;
        let actual_root = NativeProject::inspect(root)?;
        if actual_root.device != expected_root.device || actual_root.inode != expected_root.inode {
            return Err(invalid(
                "prepared root differs from authenticated quota root",
            ));
        }
        let state = open_publication_state(root)?;
        let actual_state = NativeProject::inspect(&state)?;
        let retained_state = NativeProject::inspect(&checked.publication_state)?;
        if actual_state.device != retained_state.device
            || actual_state.inode != retained_state.inode
            || actual_state.project_id != observation.project_id
            || !actual_state.inherit
            || filesystem_uuid(&state)?.as_slice() != observation.filesystem_uuid
        {
            return Err(invalid(
                "publication state differs from authenticated charge owner",
            ));
        }
        if let Some(administrative) = &checked.administrative {
            administrative.check_current()?;
            // The publisher cannot read the root-only administrative directory.
            // Requery actual privileged project/UUID facts while retaining its
            // independent O_PATH inode and the domain's shared provisioning guard.
            let mut helper = HostQuotaClient::connect(&self.quota_path, 0, self.quota_epoch)?;
            let fresh = helper.query(&observation.owner_id, &observation.domain)?;
            check_same_partition(observation, fresh.observation())?;
            administrative.check_current()?;
        }
        for (file, expected) in checked.roots.iter().zip(
            observation
                .roots
                .iter()
                .filter(|root| root.role_directory != "administrative-root"),
        ) {
            let actual = NativeProject::inspect(file)?;
            if actual.device != expected.device
                || actual.inode != expected.inode
                || actual.project_id != observation.project_id
                || !actual.inherit
                || filesystem_uuid(file)?.as_slice() != observation.filesystem_uuid
            {
                return Err(invalid("retained quota root assignment changed"));
            }
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn preflight(host: &HostTier) -> io::Result<Preflight> {
    preflight_role(host, ProcessRole::Publish)
}

#[derive(Clone, Copy)]
enum ProcessRole {
    Publish,
    Serve,
}

fn preflight_role(host: &HostTier, role: ProcessRole) -> io::Result<Preflight> {
    let publisher = host
        .publisher
        .as_ref()
        .ok_or_else(|| invalid("publisher configuration required"))?;
    let quota = host
        .quota
        .as_ref()
        .ok_or_else(|| invalid("authenticated quota helper required"))?;
    if host.domains.is_empty()
        || host.size_bytes == 0
        || !(1..=1024).contains(&publisher.max_connections)
        || [
            publisher.serve_uid,
            publisher.publish_uid,
            publisher.content_uid,
            publisher.content_gid,
        ]
        .contains(&u32::MAX)
        || publisher.serve_uid == publisher.publish_uid
        || publisher.content_uid == publisher.publish_uid
    {
        return Err(invalid(
            "invalid publisher identities, domains or resource policy",
        ));
    }
    let expected_uid = match role {
        ProcessRole::Publish => publisher.publish_uid,
        ProcessRole::Serve => publisher.serve_uid,
    };
    if rustix::process::geteuid().as_raw() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "configured native role identity mismatch",
        ));
    }
    normalized_path(&host.path)?;
    let socket_path = normalized_path(&publisher.socket_path)?;
    let quota_path = normalized_path(&quota.socket_path)?;
    rustix::net::SocketAddrUnix::new(&socket_path)?;
    rustix::net::SocketAddrUnix::new(&quota_path)?;
    if socket_path == quota_path {
        return Err(invalid("publisher and quota endpoints must be distinct"));
    }
    let mut domains = Vec::with_capacity(host.domains.len());
    let mut paths = Vec::<PathBuf>::new();
    let mut owners = BTreeSet::new();
    for (label, directory) in &host.domains {
        crate::host_quota::validate_domain_label(label)?;
        if directory.wipe != Wipe::None {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "publisher wipe policy unsupported",
            ));
        }
        let policy = directory
            .publisher
            .as_ref()
            .ok_or_else(|| invalid("domain publisher policy required"))?;
        let profile = policy.profile().map_err(io::Error::other)?;
        let retirement =
            NativeRetirementPolicy::new(Duration::from_millis(policy.retirement_grace_ms))?;
        let path = normalized_path(&directory.path)?;
        if paths
            .iter()
            .any(|other| path.starts_with(other) || other.starts_with(&path))
        {
            return Err(invalid("publisher domain roots overlap"));
        }
        paths.push(path.clone());
        let owner_id = directory
            .quota_owner_id
            .as_ref()
            .ok_or_else(|| invalid("domain quota owner required"))?;
        if owner_id.is_empty() || owner_id.len() > 256 || !owners.insert(owner_id.clone()) {
            return Err(invalid("invalid or duplicate domain quota owner"));
        }
        domains.push(Domain {
            native: NativePublisherConfig {
                domain: label.clone(),
                profile,
                layout_root: path,
                wipe: NativeWipePolicy::None,
                retirement,
                content_uid: publisher.content_uid,
                content_gid: publisher.content_gid,
            },
            profile_name: policy.chunk_profile.clone(),
            owner_id: owner_id.clone(),
            administrative_root: directory
                .administrative_root
                .as_deref()
                .map(normalized_path)
                .transpose()?,
        });
    }
    // Administrative allocations belong to exactly one physical domain. Check
    // the entire partition before confinement, quota connections or native IO.
    for (index, domain) in domains.iter().enumerate() {
        if let Some(root) = &domain.administrative_root
            && (domains.iter().any(|other| {
                root.starts_with(&other.native.layout_root)
                    || other.native.layout_root.starts_with(root)
            }) || domains[..index].iter().any(|other| {
                other
                    .administrative_root
                    .as_ref()
                    .is_some_and(|other| root.starts_with(other) || other.starts_with(root))
            }))
        {
            return Err(invalid("administrative allocations overlap another owner"));
        }
    }
    Ok(Preflight {
        endpoint: ServerConfig {
            socket_path,
            identities: RoleIdentities {
                serve_uid: publisher.serve_uid,
                publish_uid: publisher.publish_uid,
            },
            max_connections: publisher.max_connections,
        },
        domains,
        quota_path,
        quota_epoch: quota.configuration_epoch,
        tier_budget: host.size_bytes,
    })
}

fn normalized_path(text: &str) -> io::Result<PathBuf> {
    let path = Path::new(text);
    let normalized: PathBuf = path.components().collect();
    if text.as_bytes().contains(&0)
        || !path.is_absolute()
        || path == Path::new("/")
        || normalized.as_os_str() != path.as_os_str()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(
            "publisher configuration requires normalized absolute paths",
        ));
    }
    Ok(path.to_path_buf())
}

fn check_quotas(config: &Preflight) -> io::Result<Vec<CheckedQuota>> {
    let mut helper = HostQuotaClient::connect(&config.quota_path, 0, config.quota_epoch)?;
    let mut checked = Vec::with_capacity(config.domains.len());
    let mut projects = BTreeSet::new();
    let mut actual_roots = BTreeSet::new();
    let mut limit_sum = 0u64;
    let mut ledger_sum = None;
    for domain in &config.domains {
        let root = open_host_path(&domain.native.layout_root, true)?;
        let guard = DomainProvisioningGuard::shared(&root)?;
        let verified = helper.query(&domain.owner_id, &domain.native.domain)?;
        let observation = verified.observation();
        if !observation.accounting
            || !observation.enforcement
            || observation.project_id == 0
            || observation.hard_limit_bytes == 0
            || observation.hard_limit_bytes > config.tier_budget
            || observation.charged_reserved_bytes > observation.hard_limit_bytes
            || observation.tier_charge_budget_bytes != config.tier_budget
            || observation.configured_limit_sum_bytes > config.tier_budget
            || observation.configured_limit_sum_bytes < observation.hard_limit_bytes
            || ledger_sum.is_some_and(|sum| sum != observation.configured_limit_sum_bytes)
            || !projects.insert((observation.filesystem_uuid.clone(), observation.project_id))
        {
            return Err(invalid(
                "quota enforcement or configured partition budget mismatch",
            ));
        }
        ledger_sum = Some(observation.configured_limit_sum_bytes);
        limit_sum = limit_sum
            .checked_add(observation.hard_limit_bytes)
            .ok_or_else(|| invalid("quota partition sum overflow"))?;
        let mut labels = BTreeSet::new();
        let mut roots = Vec::new();
        let mut administrative = None;
        for expected in &observation.roots {
            if !labels.insert(expected.role_directory.as_str()) {
                return Err(invalid("duplicate quota root"));
            }
            let file = match expected.role_directory.as_str() {
                "layout-root" => root.try_clone()?,
                "administrative-root" => {
                    let path = domain.administrative_root.as_ref().ok_or_else(|| {
                        invalid("quota administrative root requires explicit domain configuration")
                    })?;
                    if !expected.project_inherit
                        || !actual_roots.insert((expected.device, expected.inode))
                    {
                        return Err(invalid("invalid administrative quota root"));
                    }
                    administrative = Some(AdministrativeRoot::open(
                        path,
                        expected.device,
                        expected.inode,
                    )?);
                    continue;
                }
                label if ROOT_LABELS.contains(&label) => File::from(rustix::fs::openat(
                    &root,
                    label,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )?),
                _ => return Err(invalid("unknown quota allocation root")),
            };
            let actual = NativeProject::inspect(&file)?;
            if actual.device != expected.device
                || actual.inode != expected.inode
                || actual.project_id != observation.project_id
                || !actual.inherit
                || !expected.project_inherit
                || filesystem_uuid(&file)?.as_slice() != observation.filesystem_uuid
                || !actual_roots.insert((actual.device, actual.inode))
            {
                return Err(invalid(
                    "quota root differs from live native allocation custody",
                ));
            }
            roots.push(file);
        }
        if administrative.is_some() != domain.administrative_root.is_some() {
            return Err(invalid("quota administrative allocation coverage mismatch"));
        }
        if ROOT_LABELS.iter().any(|label| !labels.contains(label)) {
            return Err(invalid("quota observation lacks allocation root coverage"));
        }
        let publication_state = open_publication_state(&root)?;
        let state_project = NativeProject::inspect(&publication_state)?;
        if state_project.project_id != observation.project_id
            || !state_project.inherit
            || state_project.device != NativeProject::inspect(&root)?.device
            || filesystem_uuid(&publication_state)?.as_slice() != observation.filesystem_uuid
            || !actual_roots.insert((state_project.device, state_project.inode))
        {
            return Err(invalid(
                "publication state lacks actual quota root coverage",
            ));
        }
        checked.push(CheckedQuota {
            observation: verified,
            roots,
            publication_state,
            administrative,
            _guard: guard,
        });
    }
    if limit_sum > ledger_sum.unwrap_or(0) {
        return Err(invalid(
            "configured owners exceed authenticated ledger partition",
        ));
    }
    Ok(checked)
}

// Compare immutable authenticated configuration; measured usage may change as
// genuine work allocates. A current over-budget observation always fails closed.
fn check_same_partition(
    expected: &crate::host_quota::QuotaObservation,
    current: &crate::host_quota::QuotaObservation,
) -> io::Result<()> {
    if current.configuration_epoch != expected.configuration_epoch
        || current.owner_id != expected.owner_id
        || current.domain != expected.domain
        || current.filesystem_uuid != expected.filesystem_uuid
        || current.project_id != expected.project_id
        || !current.accounting
        || !current.enforcement
        || current.hard_limit_bytes != expected.hard_limit_bytes
        || current.hard_inode_limit != expected.hard_inode_limit
        || current.tier_charge_budget_bytes != expected.tier_charge_budget_bytes
        || current.configured_limit_sum_bytes != expected.configured_limit_sum_bytes
        || current.roots != expected.roots
        || current.charged_reserved_bytes > current.hard_limit_bytes
        || (current.hard_inode_limit != 0 && current.charged_inodes > current.hard_inode_limit)
    {
        return Err(invalid("live administrative quota partition changed"));
    }
    Ok(())
}

fn open_publication_state(root: &File) -> io::Result<File> {
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let state = rustix::fs::openat(root, "state", flags, rustix::fs::Mode::empty())?;
    Ok(File::from(rustix::fs::openat(
        &state,
        "publication",
        flags,
        rustix::fs::Mode::empty(),
    )?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use terrane_sdk::config::host::{
        DomainDirectory, DomainPublisher, Publisher, Quota, Reassembly,
    };

    fn configuration() -> HostTier {
        let publish_uid = rustix::process::geteuid().as_raw();
        let serve_uid = if publish_uid == 1001 { 1002 } else { 1001 };
        HostTier {
            path: "/var/lib/terrane".into(),
            size_bytes: 1 << 30,
            reassembly: Reassembly::Never,
            domains: ["public", "private:fixture"]
                .into_iter()
                .enumerate()
                .map(|(index, label)| {
                    (
                        label.into(),
                        DomainDirectory {
                            cache: None,
                            path: format!("/var/lib/terrane/domain-{index}"),
                            administrative_root: Some(format!(
                                "/var/lib/terrane-admin/domain-{index}"
                            )),
                            wipe: Wipe::None,
                            publisher: Some(DomainPublisher {
                                retirement_grace_ms: 30_000,
                                chunk_profile: "cdc-1m".into(),
                                chunk_seed: [index as u8; 32],
                            }),
                            quota_owner_id: Some(format!("owner-{index}")),
                        },
                    )
                })
                .collect(),
            publisher: Some(Publisher {
                socket_path: "/run/terrane-publish/publisher.sock".into(),
                serve_uid,
                publish_uid,
                content_uid: serve_uid,
                content_gid: 1003,
                max_connections: 32,
            }),
            quota: Some(Quota {
                socket_path: "/run/terrane-host-helper/quota.sock".into(),
                configuration_epoch: [1; 16],
            }),
        }
    }

    #[test]
    fn configured_preflight_requires_real_quota_inputs_before_startup() {
        let mut config = configuration();
        assert!(preflight(&config).is_ok());
        config.quota = None;
        assert_eq!(
            preflight(&config).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );

        let mut config = configuration();
        config.domains.get_mut("public").unwrap().quota_owner_id = None;
        assert_eq!(
            preflight(&config).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn configured_preflight_rejects_later_domain_policy_before_any_open() {
        let mut config = configuration();
        config
            .domains
            .get_mut("public")
            .unwrap()
            .publisher
            .as_mut()
            .unwrap()
            .chunk_profile = "unknown".into();
        assert_eq!(
            preflight(&config).err().unwrap().kind(),
            io::ErrorKind::Other
        );

        let mut config = configuration();
        config.domains.get_mut("public").unwrap().wipe = Wipe::Zero;
        assert_eq!(
            preflight(&config).err().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn configured_preflight_refuses_overlapping_roots_and_aliasing_endpoints() {
        let mut config = configuration();
        let private_path = config.domains["private:fixture"].path.clone();
        config.domains.get_mut("public").unwrap().path = format!("{private_path}/child");
        assert_eq!(
            preflight(&config).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );

        let mut config = configuration();
        config.publisher.as_mut().unwrap().socket_path =
            config.quota.as_ref().unwrap().socket_path.clone();
        assert_eq!(
            preflight(&config).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn configured_preflight_binds_distinct_explicit_administrative_roots() {
        let config = configuration();
        let checked = preflight(&config).unwrap();
        assert_ne!(
            checked.domains[0].administrative_root,
            checked.domains[1].administrative_root
        );

        for root in [
            config.domains["private:fixture"].path.clone(),
            format!("{}/child", config.domains["private:fixture"].path),
            "/var/lib/terrane-admin".into(),
        ] {
            let mut config = configuration();
            config
                .domains
                .get_mut("public")
                .unwrap()
                .administrative_root = Some(root);
            assert!(preflight(&config).is_err());
        }

        let mut config = configuration();
        config
            .domains
            .get_mut("public")
            .unwrap()
            .administrative_root = None;
        let checked = preflight(&config).unwrap();
        assert!(
            checked
                .domains
                .iter()
                .find(|domain| domain.native.domain == "public")
                .unwrap()
                .administrative_root
                .is_none()
        );
    }

    #[test]
    fn configured_preflight_rejects_unrepresentable_unix_socket() {
        let mut config = configuration();
        config.publisher.as_mut().unwrap().socket_path = format!("/run/{}", "x".repeat(128));
        assert!(preflight(&config).is_err());
    }

    fn cache_configuration() -> (
        HostTier,
        std::collections::BTreeMap<String, NativeCacheDomainSettings>,
    ) {
        use terrane_sdk::{
            bucket::{FileBucketConfig, portable_reader::PortableReadLimits},
            host::cache::{HostReadLimits, PolicyConfig, StateLimits},
        };

        let mut host = configuration();
        let publisher = host.publisher.as_mut().unwrap();
        std::mem::swap(&mut publisher.serve_uid, &mut publisher.publish_uid);
        publisher.content_uid = publisher.serve_uid;
        let domains = host
            .domains
            .iter()
            .map(|(label, domain)| {
                (
                    label.clone(),
                    NativeCacheDomainSettings {
                        portable: FileBucketConfig {
                            root: domain.path.clone().into(),
                            chunk_profile_name: "cdc-1m".into(),
                            chunk_profile: domain.publisher.as_ref().unwrap().profile().unwrap(),
                            locality: terrane_format::refs::Locality::default(),
                            publication_control: None,
                        },
                        portable_limits: PortableReadLimits::default(),
                        state_gid: 1004,
                        policy: PolicyConfig {
                            capacity: 64 * 1024 * 1024,
                            low_watermark: 32 * 1024 * 1024,
                            probation_bytes: 1024 * 1024,
                            release_grace: Duration::from_secs(30),
                            scan_limit: 64,
                        },
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
                        surface_index: None,
                        publisher_wait_budget_ms: 10_000,
                        consumer_lease_duration: Duration::from_secs(30),
                    },
                )
            })
            .collect();
        (host, domains)
    }

    #[test]
    fn configured_cache_plan_checks_all_domains_without_opening_missing_helper() {
        if rustix::process::geteuid().is_root() {
            let (host, domains) = cache_configuration();
            assert!(NativeCachePlan::new(&host, domains).is_err());

            // Package checks run as namespace root. The owning native VM also
            // executes this exact case as UID 842 with every capability dropped,
            // preserving the positive preflight without nested user namespaces.
            return;
        }

        let (host, domains) = cache_configuration();
        assert!(NativeCachePlan::new(&host, domains).is_ok());

        let (host, mut domains) = cache_configuration();
        domains.get_mut("public").unwrap().surface_index =
            Some(crate::host_cache::SurfaceIndexPolicy {
                max_entries: 64,
                max_node_bytes: 131072,
                max_index_bytes: 65536,
                capacity_bytes: 1048576,
                future_hold_bytes: 327680,
            });
        let result = NativeCachePlan::new(&host, domains);
        if cfg!(feature = "surface-fuse") {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Unsupported);
        }

        let (host, mut domains) = cache_configuration();
        domains.get_mut("public").unwrap().portable.root = "/another/domain".into();
        assert_eq!(
            NativeCachePlan::new(&host, domains).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );

        let (host, mut domains) = cache_configuration();
        domains.get_mut("public").unwrap().portable.chunk_profile =
            terrane_format::chunking::ChunkProfile::cdc_1m([99; 32]);
        assert_eq!(
            NativeCachePlan::new(&host, domains).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn configured_cache_plan_requires_exact_resource_domain_coverage() {
        let (host, mut domains) = cache_configuration();
        domains.remove("public");
        assert_eq!(
            NativeCachePlan::new(&host, domains).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );

        let (host, mut domains) = cache_configuration();
        let resources = domains.remove("public").unwrap();
        domains.insert("private:other".into(), resources);
        assert_eq!(
            NativeCachePlan::new(&host, domains).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn configured_cache_plan_refuses_later_invalid_resources_before_native_startup() {
        let (host, mut domains) = cache_configuration();
        domains.get_mut("public").unwrap().consumer_lease_duration = Duration::from_millis(1500);
        assert_eq!(
            NativeCachePlan::new(&host, domains).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );

        let (host, mut domains) = cache_configuration();
        domains.get_mut("public").unwrap().state_gid = host.publisher.as_ref().unwrap().content_gid;
        assert_eq!(
            NativeCachePlan::new(&host, domains).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );

        let (host, mut domains) = cache_configuration();
        domains.get_mut("public").unwrap().index_repair =
            Some(crate::host_cache::IndexRepairPolicy {
                max_index_bytes: 65536,
                future_hold_bytes: 1,
            });
        assert_eq!(
            NativeCachePlan::new(&host, domains).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
