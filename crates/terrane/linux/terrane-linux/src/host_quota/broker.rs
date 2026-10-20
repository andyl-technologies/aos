//! Owns configured project partitions and authenticated read-only query sessions.

use super::native::filesystem_uuid;
use super::socket::PacketSocket;
use super::{NativeProject, NativeQuota, QuotaObservation, QuotaQuery, QuotaRoot};
use prost::Message;
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Identifies every allocation class in a single compatible project.
pub const ROOT_LABELS: [&str; 8] = [
    "chunks",
    "objects",
    "sealed",
    "staging",
    "quarantine",
    "pending-delete",
    "state",
    "layout-root",
];

/// Retains one root and its provisioned native identity.
pub struct ConfiguredRoot {
    /// Registered allocation-class label.
    pub role_directory: String,
    /// Retained root descriptor, never supplied by a query caller.
    pub directory: File,
    /// Ledger-bound native device.
    pub device: u64,
    /// Ledger-bound native inode.
    pub inode: u64,
}

/// Retains a provisioned internal directory without inventing a wire root label.
pub struct ConfiguredScaffold {
    /// Retained native directory descriptor.
    pub directory: File,
    /// Retained ledger-bound parent directory.
    pub parent: File,
    /// Exact single-component name beneath that parent.
    pub name: std::ffi::OsString,
    /// Ledger-bound device identity.
    pub device: u64,
    /// Ledger-bound inode identity.
    pub inode: u64,
}

/// Binds one immutable disclosure-domain charge owner to its complete roots.
pub struct ConfiguredOwner {
    /// Durable host-global claim for precisely this filesystem and project.
    /// An administrative pre-provisioning owner may leave this absent; the
    /// broker rejects every owner without an actual retained claim.
    pub claim: Option<super::RetainedProjectClaim>,
    /// Stable host-assigned identifier.
    pub owner_id: String,
    /// Canonical disclosure domain.
    pub domain: String,
    /// Host ledger filesystem UUID.
    pub filesystem_uuid: [u8; 16],
    /// Stable nonzero project assignment.
    pub project_id: u32,
    /// Finite configured byte limit checked against live kernel state.
    pub hard_limit_bytes: u64,
    /// Kernel identities allowed to query this owner.
    pub allowed_client_uids: BTreeSet<u32>,
    /// Every root assigned to this owner.
    pub roots: Vec<ConfiguredRoot>,
    /// Complete ledger-bound internal directory skeleton for this owner.
    pub scaffolding: Vec<ConfiguredScaffold>,
}

impl ConfiguredOwner {
    fn inspect(&self) -> io::Result<(NativeQuota, Vec<QuotaRoot>)> {
        self.claim
            .as_ref()
            .ok_or_else(|| io::Error::other("owner has no durable project claim"))?
            .verify(&self.filesystem_uuid, self.project_id)?;
        terrane_format::properties::Domain::parse(&self.domain)
            .map_err(|_| io::Error::other("invalid configured disclosure domain"))?;
        if self.owner_id.is_empty()
            || self.owner_id.len() > 256
            || self.domain.is_empty()
            || self.domain.len() > 256
            || self.project_id == 0
            || !(ROOT_LABELS.len()..=ROOT_LABELS.len() + 1).contains(&self.roots.len())
        {
            return Err(io::Error::other("invalid owner partition"));
        }
        let mut labels = BTreeSet::new();
        let mut roots = Vec::new();
        for root in &self.roots {
            let actual = NativeProject::inspect(&root.directory)?;
            if (!ROOT_LABELS.contains(&root.role_directory.as_str())
                && root.role_directory != "administrative-root")
                || !labels.insert(&root.role_directory)
                || actual.project_id != self.project_id
                || !actual.inherit
                || actual.device != root.device
                || actual.inode != root.inode
                || filesystem_uuid(&root.directory)? != self.filesystem_uuid
            {
                return Err(io::Error::other("native root binding mismatch"));
            }
            roots.push(QuotaRoot {
                role_directory: root.role_directory.clone(),
                device: actual.device,
                inode: actual.inode,
                project_inherit: actual.inherit,
            });
        }
        if !ROOT_LABELS
            .iter()
            .all(|label| labels.iter().any(|actual| actual.as_str() == *label))
        {
            return Err(io::Error::other("incomplete owner allocation coverage"));
        }
        for scaffold in &self.scaffolding {
            let named = super::open_directory_child(&scaffold.parent, &scaffold.name)?;
            let named = named.metadata()?;
            if named.dev() != scaffold.device || named.ino() != scaffold.inode {
                return Err(io::Error::other(
                    "native scaffold pathname incarnation changed",
                ));
            }
            let actual = NativeProject::inspect(&scaffold.directory)?;
            if actual.project_id != self.project_id
                || !actual.inherit
                || actual.device != scaffold.device
                || actual.inode != scaffold.inode
                || filesystem_uuid(&scaffold.directory)? != self.filesystem_uuid
            {
                return Err(io::Error::other("native scaffold binding mismatch"));
            }
        }
        let quota = NativeQuota::query(&self.roots[0].directory, self.project_id)?;
        if quota.hard_limit_bytes != self.hard_limit_bytes {
            return Err(io::Error::other("native project limit mismatch"));
        }
        Ok((quota, roots))
    }
}

/// Serves only host-configured read-only project quota observations.
pub struct HostQuotaBroker {
    socket: PacketSocket,
    epoch: [u8; 16],
    budget: u64,
    owners: Vec<ConfiguredOwner>,
}

impl HostQuotaBroker {
    /// Binds a fresh socket after validating the complete native partition.
    ///
    /// The host must provide a protected socket parent and set access permissions
    /// before accepting clients. Existing sockets are never unlinked implicitly.
    ///
    /// # Errors
    /// Returns errors for native mismatches, overlapping owners or excess budget.
    pub fn bind(
        path: &Path,
        epoch: [u8; 16],
        budget: u64,
        owners: Vec<ConfiguredOwner>,
    ) -> io::Result<Self> {
        let mut projects = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut sum = 0u64;
        if owners.is_empty() || budget == 0 {
            return Err(io::Error::other("empty quota partition"));
        }
        for owner in &owners {
            owner.inspect()?;
            if !projects.insert((owner.filesystem_uuid, owner.project_id))
                || !identities.insert((&owner.owner_id, &owner.domain))
            {
                return Err(io::Error::other("duplicate project or owner"));
            }
            for root in &owner.roots {
                if !roots.insert((root.device, root.inode)) {
                    return Err(io::Error::other("root shared by charge owners"));
                }
            }
            sum = sum
                .checked_add(owner.hard_limit_bytes)
                .ok_or_else(|| io::Error::other("partition limit overflow"))?;
        }
        if sum > budget {
            return Err(io::Error::other("partition exceeds quota budget"));
        }
        Ok(Self {
            socket: PacketSocket::bind(path)?,
            epoch,
            budget,
            owners,
        })
    }

    /// Serves one authenticated connection until it closes or sends an invalid packet.
    ///
    /// # Errors
    /// Returns transport or protocol errors; malformed sessions are closed.
    pub fn serve_connection(&self) -> io::Result<()> {
        let socket = self.socket.accept()?;
        let uid = socket.peer_uid()?;
        if !self
            .owners
            .iter()
            .any(|owner| owner.allowed_client_uids.contains(&uid))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unauthorized quota client",
            ));
        }
        let mut sequence = 0u64;
        loop {
            let request = QuotaQuery::decode_strict(&socket.receive()?)?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| io::Error::other("quota sequence exhausted"))?;
            let mut response = QuotaObservation {
                version: 1,
                request_id: request.request_id,
                configuration_epoch: self.epoch.to_vec(),
                owner_id: request.owner_id.clone(),
                domain: request.domain.clone(),
                query_sequence: sequence,
                result: 4,
                ..QuotaObservation::default()
            };
            if request.configuration_epoch != self.epoch {
                response.result = 5;
            } else if let Some(owner) = self.owners.iter().find(|owner| {
                owner.owner_id == request.owner_id
                    && owner.domain == request.domain
                    && owner.allowed_client_uids.contains(&uid)
            }) {
                // Re-query the entire configured partition each time. A startup
                // snapshot cannot establish current enforcement or budget coverage.
                let mut sum = 0u64;
                let mut selected = None;
                let mut valid = true;
                for configured in &self.owners {
                    match configured.inspect() {
                        Ok((quota, roots)) => {
                            match sum.checked_add(quota.hard_limit_bytes) {
                                Some(value) => sum = value,
                                None => {
                                    valid = false;
                                    break;
                                }
                            }
                            if configured.owner_id == owner.owner_id
                                && configured.domain == owner.domain
                            {
                                selected = Some((quota, roots));
                            }
                        }
                        Err(_) => {
                            valid = false;
                            break;
                        }
                    }
                }
                if valid
                    && sum <= self.budget
                    && let Some((quota, roots)) = selected
                {
                    response.result = 0;
                    response.filesystem_uuid = owner.filesystem_uuid.to_vec();
                    response.project_id = owner.project_id;
                    response.accounting = true;
                    response.enforcement = true;
                    response.hard_limit_bytes = quota.hard_limit_bytes;
                    response.charged_reserved_bytes = quota.charged_reserved_bytes;
                    response.hard_inode_limit = quota.hard_inode_limit;
                    response.charged_inodes = quota.charged_inodes;
                    response.roots = roots;
                    response.tier_charge_budget_bytes = self.budget;
                    response.configured_limit_sum_bytes = sum;
                }
            } else {
                response.result = 2;
            }
            socket.send(&response.encode_to_vec())?;
        }
    }
}

/// Contains an observation received from the root-owned native quota helper.
///
/// Only the authenticated query client can construct this evidence. The wire
/// representation remains available separately for diagnostics and protocol tests.
pub struct VerifiedQuotaObservation(QuotaObservation);

impl VerifiedQuotaObservation {
    /// Borrows the authenticated observation for native root and limit checks.
    pub fn observation(&self) -> &QuotaObservation {
        &self.0
    }
}

/// Retains a configured authenticated endpoint for bounded read-only queries.
///
/// Each query authenticates its own connection. Idle periods therefore retain no
/// socket that the helper's bounded receive loop may have closed. A connection
/// carries exactly one request and response; request IDs remain client-wide.
pub struct HostQuotaClient {
    endpoint: PathBuf,
    epoch: [u8; 16],
    request_id: u64,
}

impl HostQuotaClient {
    /// Authenticates a host helper using kernel peer identity.
    ///
    /// # Errors
    /// Returns unsafe host/parent custody, connection errors or a helper identity mismatch.
    pub fn connect(path: &Path, helper_uid: u32, epoch: [u8; 16]) -> io::Result<Self> {
        if helper_uid != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native quota helper must be root",
            ));
        }
        // Authenticate startup before retaining only host configuration. Query
        // custody is acquired separately immediately before its actual send.
        authenticated_query_socket(path)?;
        Ok(Self {
            endpoint: path.to_owned(),
            epoch,
            request_id: 0,
        })
    }

    /// Queries an authorized owner without accepting caller paths or project IDs.
    ///
    /// # Errors
    /// Returns fresh connection/authentication, transport, correlation,
    /// stale-epoch or unavailable-quota errors.
    pub fn query(&mut self, owner_id: &str, domain: &str) -> io::Result<VerifiedQuotaObservation> {
        self.request_id = self
            .request_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("quota request IDs exhausted"))?;
        let request = QuotaQuery {
            version: 1,
            request_id: self.request_id,
            configuration_epoch: self.epoch.to_vec(),
            owner_id: owner_id.to_owned(),
            domain: domain.to_owned(),
        };
        QuotaQuery::decode_strict(&request.encode_to_vec())?;
        // Acquire a fresh authenticated channel before submission. A failed
        // send or receive propagates directly; this query is never resubmitted.
        let socket = authenticated_query_socket(&self.endpoint)?;
        socket.send(&request.encode_to_vec())?;
        let response = QuotaObservation::decode_strict(&socket.receive()?)?;
        // Sequences increase within a connection/epoch. This fresh connection
        // admits one response; the client-wide request ID correlates it across
        // queries, while the sequence must be nonzero on this connection.
        if response.request_id != self.request_id
            || response.configuration_epoch != self.epoch
            || response.owner_id != owner_id
            || response.domain != domain
            || response.query_sequence == 0
        {
            return Err(io::Error::other("quota response correlation mismatch"));
        }
        if response.result != 0 {
            return Err(io::Error::other("host quota observation unavailable"));
        }
        Ok(VerifiedQuotaObservation(response))
    }
}

/// Authenticates the protected host endpoint for one actual query lifetime.
fn authenticated_query_socket(path: &Path) -> io::Result<PacketSocket> {
    super::require_host_root_namespace_boundary()?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("quota socket has no parent"))?;
    let parent = super::open_host_path(parent, true)?;
    let metadata = parent.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other(
            "quota socket parent lacks protected host custody",
        ));
    }
    let socket = PacketSocket::connect(path)?;
    if socket.peer_uid()? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "quota helper identity mismatch",
        ));
    }
    Ok(socket)
}
