//! Authenticates bounded project-census queries without mutating native custody.

use super::{
    ConfiguredOwner, HostQuotaBroker, HostQuotaClient, QuotaObservation, authenticated_query_socket,
};
use crate::host_quota::{
    CensusInode, CensusObservation, CensusQuery, ProjectCensusLimits, ProjectInode,
    observe_project_closure,
};
use prost::Message;
use std::{io, path::Path, sync::Mutex};

pub(super) struct CensusService {
    limits: ProjectCensusLimits,
    active: Mutex<()>,
}

impl HostQuotaBroker {
    /// Binds a fresh quota socket with administrator-selected census bounds.
    ///
    /// A single census retains descriptors at a time. Contending requests return
    /// unavailable rather than multiplying the configured descriptor budget.
    /// Bounds do not guarantee full namespace coverage or successful closure.
    ///
    /// # Errors
    /// Refuses invalid bounds before binding, native partition mismatches and
    /// socket setup failures. The caller must protect the socket parent.
    pub fn bind_with_project_census(
        path: &Path,
        epoch: [u8; 16],
        budget: u64,
        owners: Vec<ConfiguredOwner>,
        limits: ProjectCensusLimits,
    ) -> io::Result<Self> {
        if !(1..=65536).contains(&limits.retained_inodes)
            || !(1..=1_048_576).contains(&limits.directory_entries)
            || !(1..=256).contains(&limits.depth)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid project census bounds",
            ));
        }
        let mut broker = Self::bind(path, epoch, budget, owners)?;
        broker.census = Some(CensusService {
            limits,
            active: Mutex::new(()),
        });
        Ok(broker)
    }

    pub(super) fn census_observation(
        &self,
        uid: u32,
        sequence: u64,
        request: CensusQuery,
    ) -> CensusObservation {
        let mut quota = self.quota_observation(uid, sequence, &request.quota_query());
        let mut response = CensusObservation {
            version: 2,
            request_id: request.request_id,
            configuration_epoch: self.epoch.to_vec(),
            owner_id: request.owner_id.clone(),
            domain: request.domain.clone(),
            query_sequence: sequence,
            result: quota.result,
            ..CensusObservation::default()
        };
        if quota.result != 0 {
            return response;
        }
        let Some(service) = &self.census else {
            response.result = 3;
            return response;
        };
        response.result = 4;
        let Ok(_active) = service.active.try_lock() else {
            return response;
        };
        let Some(owner) = self.owners.iter().find(|owner| {
            owner.owner_id == request.owner_id
                && owner.domain == request.domain
                && owner.allowed_client_uids.contains(&uid)
        }) else {
            return response;
        };
        let roots: Vec<_> = owner.roots.iter().map(|root| &root.directory).collect();
        let excluded: Vec<_> = request.excluded.iter().map(ProjectInode::from).collect();
        let Ok(observed) = observe_project_closure(&roots, &excluded, service.limits) else {
            return response;
        };
        if observed.filesystem_uuid() != &owner.filesystem_uuid
            || observed.project_id() != owner.project_id
            || observed.excluded() != excluded
            || observed.quota().hard_limit_bytes != owner.hard_limit_bytes
        {
            return response;
        }

        // These charges were queried while every counted inode was still held.
        // A later independent quota sample cannot replace that comparison.
        quota.hard_limit_bytes = observed.quota().hard_limit_bytes;
        quota.charged_reserved_bytes = observed.quota().charged_reserved_bytes;
        quota.hard_inode_limit = observed.quota().hard_inode_limit;
        quota.charged_inodes = observed.quota().charged_inodes;
        response.result = 0;
        response.quota = Some(quota);
        response.excluded = request.excluded;
        response.retained_inodes = observed.retained_inodes();
        response
    }
}

/// Retains census evidence obtained only from the authenticated host helper.
///
/// The physical owner must bind the exact exclusions, filesystem, project and
/// epoch to its original serialized retirement. This is neither serving
/// authority nor permission to release a different inode or policy obligation.
pub struct VerifiedProjectCensus {
    observation: CensusObservation,
    quota: QuotaObservation,
}

impl VerifiedProjectCensus {
    /// Borrows the exact correlated census response from the actual helper.
    pub fn observation(&self) -> &CensusObservation {
        &self.observation
    }

    /// Borrows the project observation measured while counted inodes were held.
    pub fn quota(&self) -> &QuotaObservation {
        &self.quota
    }

    /// Reports that none of the exact excluded identities remained charged.
    ///
    /// A false result retains every unresolved obligation. Equality does not
    /// identify kernel holders or authorize unrelated physical release.
    pub fn all_excluded_closed(&self) -> bool {
        self.observation.retained_inodes == self.quota.charged_inodes
    }
}

impl HostQuotaClient {
    /// Observes exact original inode closure through a fresh authenticated helper.
    ///
    /// Only the configured owner selects roots and project. A caller supplies no
    /// filesystem path, project assignment, native descriptor or scan budget.
    /// Failed submissions are never automatically retried.
    ///
    /// # Errors
    /// Refuses malformed identities, authentication or correlation failures,
    /// stale configuration, disabled census, exhausted bounds and native errors.
    pub fn query_project_census(
        &mut self,
        owner_id: &str,
        domain: &str,
        excluded: &[ProjectInode],
    ) -> io::Result<VerifiedProjectCensus> {
        if excluded.is_empty()
            || excluded.len() > crate::host_quota::MAX_CENSUS_EXCLUSIONS
            || owner_id.is_empty()
            || owner_id.len() > 256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid census request bounds",
            ));
        }
        crate::host_quota::validate_domain_label(domain)?;
        self.request_id = self
            .request_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("quota request IDs exhausted"))?;
        let request = CensusQuery {
            version: 2,
            request_id: self.request_id,
            configuration_epoch: self.epoch.to_vec(),
            owner_id: owner_id.to_owned(),
            domain: domain.to_owned(),
            excluded: excluded.iter().copied().map(CensusInode::from).collect(),
        };
        let encoded = request.encode_to_vec();
        CensusQuery::decode_strict(&encoded)?;
        let socket = authenticated_query_socket(&self.endpoint)?;
        socket.send(&encoded)?;
        let response = CensusObservation::decode_strict(&socket.receive()?)?;
        if response.request_id != self.request_id
            || response.configuration_epoch != self.epoch
            || response.owner_id != owner_id
            || response.domain != domain
            || response.query_sequence == 0
        {
            return Err(io::Error::other("project census correlation mismatch"));
        }
        if response.result != 0 || response.excluded != request.excluded {
            return Err(io::Error::other("host project census unavailable"));
        }
        let quota = response
            .quota
            .as_ref()
            .ok_or_else(|| io::Error::other("project census lacks quota observation"))?
            .clone();
        Ok(VerifiedProjectCensus {
            observation: response,
            quota,
        })
    }
}
