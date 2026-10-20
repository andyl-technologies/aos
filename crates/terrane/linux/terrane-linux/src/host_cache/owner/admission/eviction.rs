//! Captures original encoded allocations for the native eviction planner.
//!
//! Chunk envelopes own one inode; a cached pack and its detached index own one
//! allocation unit with two distinct inodes. Durable rows protect these units
//! but never construct one. Capturing a unit grants neither a consumer lease
//! nor permission to rename or remove its members.

mod lifecycle;
pub(in crate::host_cache::owner) mod turn;

pub(in crate::host_cache::owner) use lifecycle::{
    DueRetirements, Runtime, contains_key, due_retirements, finish_due, pending_keys, restore_for,
    restore_pack, retire,
};

use super::{AdmissionJob, Input, backing, io as native, reconcile, state};
use crate::{
    host_cache::owner::{
        consumer::state as policy,
        retention::{Custody, NativeOwnerExecutor},
    },
    host_quota::synchronized_allocated_bytes,
    publisher_local::wire::{BodyKey, BodyKind},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
};

/// Retains a complete original encoded allocation without granting retirement.
pub(in crate::host_cache::owner) struct EncodedAllocation {
    order: u64,
    key: String,
    body: BodyKey,
    members: Vec<Arc<Mutex<AdmissionJob>>>,
    inodes: Vec<(u64, u64, u64)>,
    files: Vec<File>,
    hashes: BTreeSet<String>,
    allocated: u64,
    protected: bool,
}

/// Restores actual pending backing before retaining new reconstruction metadata.
///
/// # Errors
/// Refuses changed original custody and failed or uncertain publisher exchanges.
pub(in crate::host_cache::owner) fn restore_identity(
    executor: &mut NativeOwnerExecutor,
    identity: &terrane_format::identity::Identity,
) -> io::Result<()> {
    restore_for(executor, &state::hex(identity.digest()))
}

/// Bounds simultaneous census and retained transition headers per original job.
pub(super) fn storage_bytes() -> usize {
    2 * std::mem::size_of::<EncodedAllocation>()
        + lifecycle::storage_bytes()
        + std::mem::size_of::<crate::publisher_local::client::EncodedCacheReceipt>()
        + std::mem::size_of::<crate::publisher_local::client::EncodedCacheCompletion>()
        + std::mem::size_of::<crate::publisher_local::socket::ReceivedPacket>()
        + 12 * std::mem::size_of::<File>()
        + 8 * std::mem::size_of::<(u64, u64, u64)>()
        + 1024 // Generated keys, bounded descriptors, map nodes and Arc headers.
}

impl EncodedAllocation {
    /// Returns the earliest actual admission among this allocation's originals.
    pub(in crate::host_cache::owner) fn order(&self) -> u64 {
        self.order
    }
    /// Borrows the process-local allocation identity shared with read activity.
    pub(in crate::host_cache::owner) fn key(&self) -> &str {
        &self.key
    }

    /// Returns synchronized blocks of the original members, counted once each.
    pub(in crate::host_cache::owner) fn allocated(&self) -> u64 {
        self.allocated
    }

    /// Reports protection observed from actual dependencies and durable promises.
    pub(in crate::host_cache::owner) fn protected(&self) -> bool {
        self.protected
    }

    /// Borrows the registered key derived from the actual completed input.
    pub(in crate::host_cache::owner) fn body_key(&self) -> &BodyKey {
        &self.body
    }

    /// Borrows direct content identities, excluding a chunk's dictionary source.
    pub(in crate::host_cache::owner) fn hashes(&self) -> &BTreeSet<String> {
        &self.hashes
    }

    fn has_protection(&self, executor: &NativeOwnerExecutor, owner: &Custody) -> io::Result<bool> {
        let dependency_owners = self
            .members
            .iter()
            .map(|resource| {
                backing::lock(resource).map(|job| format!("cache-dependency:{}", job.token))
            })
            .collect::<io::Result<BTreeSet<_>>>()?;
        if owner
            .state
            .pins
            .iter()
            .any(|pin| self.hashes.contains(&pin.hash) && !dependency_owners.contains(&pin.owner))
        {
            return Ok(true);
        }
        for dependent in executor.admission_jobs() {
            if self
                .members
                .iter()
                .any(|member| Arc::ptr_eq(member, dependent))
            {
                continue;
            }
            let dependent = backing::lock(dependent)?;
            if dependent.complete
                && dependent.dependencies.iter().any(|dictionary| {
                    self.members
                        .iter()
                        .any(|member| Arc::ptr_eq(member, dictionary))
                })
            {
                return Ok(true);
            }
        }
        for consumer in executor.consumer_jobs() {
            let consumer = consumer
                .lock()
                .map_err(|_| invalid("encoded eviction consumer poisoned"))?;
            if self
                .members
                .iter()
                .any(|member| consumer.retains_admission(member))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn check_unprotected(&self, executor: &NativeOwnerExecutor) -> io::Result<()> {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded eviction custody poisoned"))?;
        for resource in &self.members {
            if backing::lock(resource)?.cached.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "encoded allocation retains original producer custody",
                ));
            }
        }
        if self.has_protection(executor, &owner)? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "encoded allocation retains actual consumers, dependencies or promises",
            ));
        }
        Ok(())
    }

    fn check_held(&self, executor: &NativeOwnerExecutor, removed: bool) -> io::Result<()> {
        executor.check_physical_worker()?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded eviction custody poisoned"))?;
        for resource in &self.members {
            check_registered(executor, resource)?;
            let job = backing::lock(resource)?;
            if !job.complete
                || !Arc::ptr_eq(&job.custody, executor.custody())
                || body_key(&job)? != self.body
                || original_inodes(&job)? != self.inodes
            {
                return Err(invalid("encoded eviction lost original held allocation"));
            }
            state::check_registration(&owner, &job)?;
            for (index, file) in self.files.iter().enumerate() {
                if inode(file)? != self.inodes[index] {
                    return Err(invalid("encoded eviction changed retained inode"));
                }
                let bytes = input_bytes(&job, index)?;
                if removed {
                    native::verify_unlinked_bytes(&owner, file, bytes)?;
                } else {
                    native::verify_custodied_bytes(&owner, file, bytes)?;
                }
            }
        }
        Ok(())
    }

    fn check_received(&self, executor: &NativeOwnerExecutor, received: &[File]) -> io::Result<()> {
        self.check_canonical(executor)?;
        if received.len() != self.inodes.len() {
            return Err(invalid(
                "encoded inspection returned an incomplete allocation",
            ));
        }
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded eviction custody poisoned"))?;
        let resource = self
            .members
            .first()
            .ok_or_else(|| invalid("encoded inspection lost original job"))?;
        let job = backing::lock(resource)?;
        let mut seen = BTreeSet::new();
        for file in received {
            let identity = inode(file)?;
            let index = self
                .inodes
                .iter()
                .position(|expected| *expected == identity)
                .ok_or_else(|| invalid("encoded inspection returned another inode"))?;
            if !seen.insert(identity)
                || rustix::fs::fcntl_getfl(file)?.intersects(
                    rustix::fs::OFlags::WRONLY
                        | rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::PATH,
                )
            {
                return Err(invalid(
                    "encoded inspection duplicated or returned writable custody",
                ));
            }
            native::verify_custodied_bytes(&owner, file, input_bytes(&job, index)?)?;
        }
        Ok(())
    }

    /// Checks original registration and canonical members without granting retirement.
    ///
    /// # Errors
    /// Refuses another worker, lost original jobs, changed allocation or input,
    /// stale funding, unsafe native bytes and noncanonical or replaced members.
    pub(in crate::host_cache::owner) fn check_canonical(
        &self,
        executor: &NativeOwnerExecutor,
    ) -> io::Result<()> {
        executor.check_physical_worker()?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded eviction custody poisoned"))?;
        for resource in &self.members {
            check_registered(executor, resource)?;
            let job = backing::lock(resource)?;
            if !job.complete
                || !Arc::ptr_eq(&job.custody, executor.custody())
                || body_key(&job)? != self.body
                || original_inodes(&job)? != self.inodes
            {
                return Err(invalid("encoded eviction changed original allocation"));
            }
            reconcile::verify(&owner, &job)?;
        }
        for (file, expected) in self.files.iter().zip(&self.inodes) {
            if inode(file)? != *expected {
                return Err(invalid("encoded eviction lost its retained descriptor"));
            }
        }
        Ok(())
    }
}

/// Captures complete chunks and pack/index pairs under physical exclusion.
///
/// Synchronization runs after releasing embedded custody. The original jobs,
/// their exact input class and every actual inode remain retained throughout.
/// A partially overlapping pair is refused rather than counted as two units.
///
/// # Errors
/// Refuses stale Running custody, incomplete or changed native allocations,
/// inconsistent aliases, shared members, exhausted storage and failed native IO.
pub(in crate::host_cache::owner) fn capture(
    executor: &NativeOwnerExecutor,
) -> io::Result<Vec<EncodedAllocation>> {
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let mut units = Vec::<EncodedAllocation>::new();
    units
        .try_reserve_exact(executor.admission_jobs().len())
        .map_err(io::Error::other)?;
    let mut by_inode = BTreeMap::new();
    {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded eviction custody poisoned"))?;
        policy::check_ready(executor, &owner)?;
        policy::check_bootstrap(&owner, &running)?;

        for resource in executor.admission_jobs() {
            if lifecycle::contains_resource(executor, resource)?
                || super::super::publication::retirement::retains_retired_admission(
                    executor, &owner, resource,
                )?
            {
                continue;
            }
            let job = backing::lock(resource)?;
            if !job.complete {
                continue;
            }
            if !Arc::ptr_eq(&job.custody, executor.custody()) {
                return Err(invalid(
                    "encoded eviction admission belongs to another owner",
                ));
            }
            reconcile::verify(&owner, &job)?;
            let body = body_key(&job)?;
            let inodes = original_inodes(&job)?;
            let primary = inodes
                .last()
                .ok_or_else(|| invalid("encoded eviction allocation has no members"))?;
            let identity = (primary.0, primary.1);
            let index = if let Some(index) = by_inode.get(&identity) {
                *index
            } else {
                let index = units.len();
                for &(device, number, _) in &inodes {
                    if by_inode.insert((device, number), index).is_some() {
                        return Err(invalid("encoded eviction units share a native member"));
                    }
                }
                let mut files = Vec::new();
                files
                    .try_reserve_exact(job.files.len())
                    .map_err(io::Error::other)?;
                for member in &job.files {
                    files.push(
                        member
                            .readonly
                            .as_ref()
                            .ok_or_else(|| invalid("encoded eviction member absent"))?
                            .try_clone()?,
                    );
                }
                let hashes = match &job.input {
                    Input::Chunk { descriptor, .. } => {
                        BTreeSet::from([state::hex(descriptor.digest())])
                    }
                    Input::Metadata { .. } => job.hashes.iter().cloned().collect(),
                };
                units.push(EncodedAllocation {
                    order: job.order,
                    key: format!("{}:{}", primary.0, primary.1),
                    body: body.clone(),
                    members: Vec::new(),
                    inodes: inodes.clone(),
                    files,
                    hashes,
                    allocated: 0,
                    protected: false,
                });
                index
            };
            let unit = &mut units[index];
            unit.order = unit.order.min(job.order);
            if unit.body != body || unit.inodes != inodes {
                return Err(invalid(
                    "encoded eviction aliases disagree about their unit",
                ));
            }
            unit.members.try_reserve(1).map_err(io::Error::other)?;
            unit.members.push(Arc::clone(resource));
        }

        for unit in &mut units {
            // A chunk's dictionary is a distinct allocation. Its own dependency
            // promise must not pin the dependent merely because both happen to
            // have the same plaintext identity. Other owners' promises still do.
            unit.protected = unit.has_protection(executor, &owner)?;
        }
    }

    // Quota release is never inferred from these scoped member measurements.
    // Complete-project charged-and-reserved usage remains a separate query.
    for unit in &mut units {
        unit.allocated = unit.files.iter().try_fold(0_u64, |sum, file| {
            sum.checked_add(synchronized_allocated_bytes(file)?)
                .ok_or_else(|| invalid("encoded eviction allocation overflows"))
        })?;
        unit.check_canonical(executor)?;
    }
    running.check_current().map_err(io::Error::other)?;
    Ok(units)
}

fn check_registered(
    executor: &NativeOwnerExecutor,
    resource: &Arc<Mutex<AdmissionJob>>,
) -> io::Result<()> {
    if !executor
        .admission_jobs()
        .iter()
        .any(|job| Arc::ptr_eq(job, resource))
    {
        return Err(invalid(
            "encoded eviction lost its original admission registry",
        ));
    }
    Ok(())
}

fn original_inodes(job: &AdmissionJob) -> io::Result<Vec<(u64, u64, u64)>> {
    job.files
        .iter()
        .map(|member| {
            member
                .readonly
                .as_ref()
                .ok_or_else(|| invalid("encoded eviction member absent"))
                .and_then(inode)
        })
        .collect()
}

fn inode(file: &File) -> io::Result<(u64, u64, u64)> {
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino(), metadata.len()))
}

fn input_bytes(job: &AdmissionJob, index: usize) -> io::Result<&[u8]> {
    match (&job.input, index) {
        (Input::Chunk { encoded, .. }, 0) => Ok(encoded),
        (Input::Metadata { index, .. }, 0) => Ok(index),
        (Input::Metadata { pack, .. }, 1) => Ok(pack),
        _ => Err(invalid(
            "encoded allocation member differs from original input",
        )),
    }
}

fn body_key(job: &AdmissionJob) -> io::Result<BodyKey> {
    let expected = if matches!(job.input, Input::Chunk { .. }) {
        1
    } else {
        2
    };
    if job.files.len() != expected {
        return Err(invalid("encoded eviction allocation is incomplete"));
    }
    key_for_input(&job.input)
}

/// Derives a registered allocation key from the original retained input.
///
/// # Errors
/// Refuses an absent chunk envelope before constructing its codec selector.
pub(super) fn key_for_input(input: &Input) -> io::Result<BodyKey> {
    match input {
        Input::Chunk {
            descriptor,
            encoded,
            ..
        } => Ok(BodyKey {
            kind: BodyKind::Chunk as i32,
            descriptor: descriptor.encode(),
            codec: encoded
                .first()
                .copied()
                .map(u32::from)
                .ok_or_else(|| invalid("encoded eviction envelope absent"))?,
            ..Default::default()
        }),
        Input::Metadata { expected_id, .. } => Ok(BodyKey {
            kind: BodyKind::Pack as i32,
            pack_id: expected_id.as_bytes().to_vec(),
            ..Default::default()
        }),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
