//! Selects original sealed or encoded backing for independent consumer grants.
//!
//! Encoded grants retain their actual completed admission jobs and pin every
//! one-hop dependency. The public producer residence source stays sealed-only.

use super::invalid;
use crate::host_cache::{
    NativeChunkSpan, NativeResidentChunkSource,
    owner::{
        admission::{AdmissionJob, reads::AdmittedRead},
        publication::{
            self,
            eviction::{ReadActivities, ReadActivity},
        },
        retention::{Custody, NativeOwnerExecutor},
    },
};
use std::{
    io,
    sync::{Arc, Mutex},
};
use terrane_format::{
    identity::{Identity, TERRANE_V1},
    properties::Domain,
};
use terrane_sdk::{
    host::cache::DomainHostLayout,
    store::{StoreErrorKind, StoreFailure},
};

/// Retains one actual immutable backing and its exact durable protection set.
pub(super) struct ConsumerSource {
    backing: Backing,
    hashes: Vec<String>,
}

enum Backing {
    Sealed(NativeResidentChunkSource),
    Encoded {
        source: Box<AdmittedRead>,
        activity: ReadActivities,
    },
}

/// Separates actual sealed-file allocation from total original backing allocation.
pub(super) struct Allocation {
    /// Allocated bytes of the original fs-verity inode, or zero for encoded backing.
    pub(super) sealed: u64,
    /// Allocated bytes of distinct original inodes needed by this source.
    pub(super) backing: u64,
}

impl ConsumerSource {
    /// Binds a shared residence to its actual sealed source before reading bytes.
    ///
    /// # Errors
    /// Refuses encoded backing, private domains, or a different root or profile.
    pub(super) fn shared_span(
        &self,
        layout: &DomainHostLayout,
    ) -> Result<NativeChunkSpan, StoreFailure> {
        let Backing::Sealed(source) = &self.backing else {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        };
        let location = source.location();
        if matches!(Domain::parse(location.domain()), Ok(Domain::Private(_)))
            || location.domain() != layout.domain_binding().domain
            || location.root() != layout.root()
            || location.chunk_profile() != layout.chunk_profile()
        {
            return Err(StoreFailure::new(StoreErrorKind::Denied {
                verb: "read",
                pattern: layout.domain_binding().reference.clone(),
            }));
        }
        Ok(source.span())
    }

    /// Selects actual sealed custody or an original admitted cache body.
    ///
    /// Residence rows select a source class only. A present sealed residence
    /// must pass its complete native checks; a failed sealed check cannot fall
    /// back to another copy.
    ///
    /// # Errors
    /// Refuses changed sealed custody, absent actual cache admission or native errors.
    pub(super) async fn prepare(
        executor: &mut NativeOwnerExecutor,
        identity: Identity,
    ) -> io::Result<Self> {
        let sealed = {
            let owner = executor
                .custody()
                .lock()
                .map_err(|_| invalid("consumer source custody poisoned"))?;
            let hash = super::state::hex(identity.digest());
            owner.state.residences.iter().any(|row| row.chunk == hash)
        };
        if sealed {
            let source = publication::residence::prepare(executor, identity).await?;
            let hashes = vec![super::state::hex(source.protected_object_digest())];
            return Ok(Self {
                backing: Backing::Sealed(source),
                hashes,
            });
        }
        let source = AdmittedRead::prepare(executor, identity)?;
        let activity = executor.admission_read_activity(&source)?;
        let mut hashes: Vec<_> = source.digests().map(super::state::hex).collect();
        hashes.sort();
        hashes.dedup();
        Ok(Self {
            backing: Backing::Encoded {
                source: Box::new(source),
                activity,
            },
            hashes,
        })
    }

    /// Borrows the independently verified original chunk identity.
    pub(super) fn identity(&self) -> &Identity {
        match &self.backing {
            Backing::Sealed(source) => source.identity(),
            Backing::Encoded { source, .. } => source.identity(),
        }
    }

    /// Borrows every body/dependency hash requiring this consumer's own durable pin.
    pub(super) fn protected_hashes(&self) -> &[String] {
        &self.hashes
    }

    /// Checks original producer protection before the independent grant is durable.
    ///
    /// # Errors
    /// Refuses changed backing or lost original producer funding and dependencies.
    pub(super) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        match &self.backing {
            Backing::Sealed(source) => source.check_protected(owner),
            Backing::Encoded { source, .. } => source.check_protected(owner),
        }
    }

    /// Checks actual backing under an independently verified consumer pin.
    ///
    /// # Errors
    /// Refuses changed original native descriptors or a foreign layout binding.
    pub(super) fn check_consumer_backing(&self, owner: &Custody) -> io::Result<()> {
        match &self.backing {
            Backing::Sealed(source) => source.check_consumer_backing(owner),
            Backing::Encoded { source, .. } => source.check_consumer_backing(owner),
        }
    }

    /// Reads actual verified bytes without an owner queue or embedded mutex.
    ///
    /// # Errors
    /// Refuses changed bytes/backing, revoked sealed views or bounded read failures.
    pub(super) fn read_verified(&self) -> io::Result<Vec<u8>> {
        match &self.backing {
            Backing::Sealed(source) => source.read_verified(),
            Backing::Encoded { source, activity } => {
                let bytes = source.read_verified()?;
                activity.record()?;
                Ok(bytes)
            }
        }
    }

    /// Synchronizes and measures original backing without an embedded mutex.
    ///
    /// # Errors
    /// Refuses changed native resources, actual sync/measurement errors or overflow.
    pub(super) fn synchronize_pin_backing(&self) -> io::Result<Allocation> {
        match &self.backing {
            Backing::Sealed(source) => {
                let allocated = source.synchronize_pin_backing()?;
                Ok(Allocation {
                    sealed: allocated,
                    backing: allocated,
                })
            }
            Backing::Encoded { source, .. } => Ok(Allocation {
                sealed: 0,
                backing: source.synchronize_pin_backing()?,
            }),
        }
    }

    /// Recognizes original admitted resources until the consumer job is reclaimed.
    pub(super) fn retains(&self, job: &Arc<Mutex<AdmissionJob>>) -> bool {
        matches!(&self.backing, Backing::Encoded { source, .. } if source.retains(job))
    }
}

/// Bounds extra consumer source, dependency and label storage per finite job.
///
/// # Errors
/// Refuses overflow in checked retained descriptors and simultaneous decode windows.
pub(in crate::host_cache::owner) fn storage_bytes(
    records: usize,
    reads: usize,
    window: usize,
    domain: usize,
) -> io::Result<usize> {
    let per_job = std::mem::size_of::<ConsumerSource>()
        .checked_add(AdmittedRead::storage_bytes(domain)?)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::view::ReadView>()))
        // A verified encoded read records both actual body and dictionary units.
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Arc<ReadActivity>>()))
        // The consumer view owns one additional verified identity clone.
        .and_then(|bytes| bytes.checked_add(TERRANE_V1.name().len() + TERRANE_V1.digest_len()))
        // The sorted protection set owns two hash strings and their Vec slots.
        .and_then(|bytes| bytes.checked_add(2 * (64 + std::mem::size_of::<String>())))
        .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
        .ok_or_else(|| invalid("consumer backing storage overflow"))?;
    records
        .checked_add(1)
        .and_then(|count| count.checked_mul(per_job))
        // Encoded envelope, dictionary decode/copy and body decode/copy overlap.
        // Each read and the one serialized preparation own at most five windows.
        .and_then(|bytes| {
            bytes.checked_add(reads.checked_add(1)?.checked_mul(window)?.checked_mul(5)?)
        })
        .ok_or_else(|| invalid("consumer decode storage overflow"))
}
