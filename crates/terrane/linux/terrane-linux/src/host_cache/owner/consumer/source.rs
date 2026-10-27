//! Selects original sealed, encoded or metadata backing for consumer grants.
//!
//! Encoded grants retain their actual completed admission jobs and pin every
//! dictionary dependency. The public producer residence source stays sealed-only.

use super::invalid;
use crate::host_cache::{
    NativeChunkSpan, NativeResidentChunkSource,
    owner::{
        admission::{AdmissionJob, metadata_reads::AdmittedMetadataRead, reads::AdmittedRead},
        publication::{
            self,
            eviction::{ReadActivities, ReadActivity},
            object_source::SealedObjectSource,
        },
        retention::{Custody, NativeOwnerExecutor},
    },
};
use std::{
    io,
    sync::{Arc, Mutex},
};
use terrane_format::{
    identity::{Identity, IdentityKind, TERRANE_V1},
    properties::Domain,
};
use terrane_sdk::{
    host::cache::DomainHostLayout,
    store::{StoreErrorKind, StoreFailure},
};

/// Retains one actual immutable backing and its exact durable protection set.
///
/// The physical publisher may borrow this source within its own executor turn
/// under original producer custody. This source alone grants no consumer lease.
pub(in crate::host_cache::owner) struct ConsumerSource {
    backing: Backing,
    hashes: Vec<String>,
}

enum Backing {
    Sealed(NativeResidentChunkSource),
    Object(Box<SealedObjectSource>),
    Metadata {
        source: Box<AdmittedMetadataRead>,
        activity: ReadActivities,
    },
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
    /// Selects a complete sealed file independently of chunk and metadata reads.
    ///
    /// # Errors
    /// Refuses unsupported identities, absent completed publication custody,
    /// failed restoration and native integrity errors.
    pub(in crate::host_cache::owner) async fn prepare_object(
        executor: &mut NativeOwnerExecutor,
        identity: Identity,
    ) -> io::Result<Self> {
        let source = SealedObjectSource::prepare(executor, identity).await?;
        let hashes = vec![super::state::hex(source.identity().digest())];
        Ok(Self {
            backing: Backing::Object(Box::new(source)),
            hashes,
        })
    }

    /// Duplicates only a complete sealed-object source for an owning read guard.
    ///
    /// # Errors
    /// Refuses other source kinds, changed native backing and descriptor IO.
    pub(super) fn duplicate_object_backing(&self) -> io::Result<std::os::fd::OwnedFd> {
        let Backing::Object(source) = &self.backing else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "consumer grant does not protect a complete sealed object",
            ));
        };
        source.duplicate_backing()
    }

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
    pub(in crate::host_cache::owner) async fn prepare(
        executor: &mut NativeOwnerExecutor,
        identity: Identity,
    ) -> io::Result<Self> {
        if identity.kind() != IdentityKind::Chunk {
            let source = AdmittedMetadataRead::prepare(executor, identity)?;
            let activity = executor.metadata_read_activity(&source)?;
            let mut hashes: Vec<_> = source.digests().map(super::state::hex).collect();
            hashes.sort();
            hashes.dedup();
            return Ok(Self {
                backing: Backing::Metadata {
                    source: Box::new(source),
                    activity,
                },
                hashes,
            });
        }
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

    /// Borrows the independently verified original content identity.
    pub(super) fn identity(&self) -> &Identity {
        match &self.backing {
            Backing::Sealed(source) => source.identity(),
            Backing::Object(source) => source.identity(),
            Backing::Encoded { source, .. } => source.identity(),
            Backing::Metadata { source, .. } => source.identity(),
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
            Backing::Object(source) => source.check_protected(owner),
            Backing::Encoded { source, .. } => source.check_protected(owner),
            Backing::Metadata { source, .. } => source.check_protected(owner),
        }
    }

    /// Checks actual backing under an independently verified consumer pin.
    ///
    /// # Errors
    /// Refuses changed original native descriptors or a foreign layout binding.
    pub(super) fn check_consumer_backing(&self, owner: &Custody) -> io::Result<()> {
        match &self.backing {
            Backing::Sealed(source) => source.check_consumer_backing(owner),
            Backing::Object(source) => source.check_consumer_backing(owner),
            Backing::Encoded { source, .. } => source.check_consumer_backing(owner),
            Backing::Metadata { source, .. } => source.check_consumer_backing(owner),
        }
    }

    /// Reads actual verified bytes without an owner queue or embedded mutex.
    ///
    /// # Errors
    /// Refuses changed bytes/backing, revoked sealed views or bounded read failures.
    pub(in crate::host_cache::owner) fn read_verified(&self) -> io::Result<Vec<u8>> {
        match &self.backing {
            Backing::Sealed(source) => source.read_verified(),
            Backing::Object(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "whole-object grants expose sealed backing, not metadata or chunk bytes",
            )),
            Backing::Metadata { source, activity } => {
                let bytes = source.read_verified()?;
                activity.record()?;
                Ok(bytes)
            }
            Backing::Encoded { source, activity } => {
                let bytes = source.read_verified()?;
                activity.record()?;
                Ok(bytes)
            }
        }
    }

    /// Returns verified encoded bytes under the same original backing custody.
    ///
    /// # Errors
    /// Refuses changed/revoked backing, codec/identity/boundary failures and
    /// exhausted allocation bounds. Encoded reads record actual cache activity.
    pub(in crate::host_cache::owner) fn read_encoded(&self) -> io::Result<Vec<u8>> {
        match &self.backing {
            Backing::Sealed(source) => source.read_encoded(),
            Backing::Object(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "whole-object grants do not expose encoded content",
            )),
            Backing::Metadata { source, activity } => {
                let bytes = source.read_verified()?;
                activity.record()?;
                Ok(bytes)
            }
            Backing::Encoded { source, activity } => {
                let encoded = source.read_encoded()?;
                activity.record()?;
                Ok(encoded)
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
            Backing::Object(source) => {
                let allocated = source.synchronize_pin_backing()?;
                Ok(Allocation {
                    sealed: allocated,
                    backing: allocated,
                })
            }
            Backing::Metadata { source, .. } => Ok(Allocation {
                sealed: 0,
                backing: source.synchronize_pin_backing()?,
            }),
            Backing::Encoded { source, .. } => Ok(Allocation {
                sealed: 0,
                backing: source.synchronize_pin_backing()?,
            }),
        }
    }

    /// Recognizes original admitted resources until the consumer job is reclaimed.
    pub(super) fn retains(&self, job: &Arc<Mutex<AdmissionJob>>) -> bool {
        match &self.backing {
            Backing::Sealed(_) | Backing::Object(_) => false,
            Backing::Encoded { source, .. } => source.retains(job),
            Backing::Metadata { source, .. } => source.retains(job),
        }
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
        .checked_add(
            AdmittedRead::storage_bytes(domain, records)?
                .max(AdmittedMetadataRead::storage_bytes()?)
                .max(SealedObjectSource::storage_bytes()),
        )
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::view::ReadView>()))
        // Each whole-object lease can retain one delegated descriptor owner.
        // Its scoped wrapper additionally owns the closing selection's fixed
        // commit/root/size metadata and a clone of the same physical grant.
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::NativeFileBacking>()))
        // Every original member can retain its own actual read activity.
        .and_then(|bytes| {
            bytes.checked_add(records.checked_mul(std::mem::size_of::<Arc<ReadActivity>>())?)
        })
        // The consumer view owns one additional verified identity clone.
        .and_then(|bytes| bytes.checked_add(TERRANE_V1.name().len() + TERRANE_V1.digest_len()))
        // Independent consumer protection closes over the complete chain.
        .and_then(|bytes| {
            bytes.checked_add(records.checked_mul(64 + std::mem::size_of::<String>())?)
        })
        .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
        .ok_or_else(|| invalid("consumer backing storage overflow"))?;
    records
        .checked_add(1)
        .and_then(|count| count.checked_mul(per_job))
        // Metadata pair verification uses an additional fixed scratch window.
        .and_then(|bytes| bytes.checked_add(reads.checked_add(1)?.checked_mul(8192)?))
        // Encoded envelope, dictionary decode/copy and body decode/copy overlap.
        // Each read and the one serialized preparation own at most five windows.
        .and_then(|bytes| {
            bytes.checked_add(reads.checked_add(1)?.checked_mul(window)?.checked_mul(5)?)
        })
        .ok_or_else(|| invalid("consumer decode storage overflow"))
}
