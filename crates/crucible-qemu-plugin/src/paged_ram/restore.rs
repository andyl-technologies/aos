//! SPDX-License-Identifier: GPL-2.0-or-later
//! Authenticates and stages a lazy restore before any guest mapping is discarded.
//!
//! The retained source serves immutable pages and proofs independently of guest
//! locks. A prepared identity is not an executable restore: the mapping owner
//! must first reserve, drain, and register real stable arenas. Only that owner's
//! destructive commit may publish the prepared cache while retaining source and
//! registration authority through every failure and eventual process reap.

use crate::ram_error::RamError;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use crucible_protocol::ram_page::{
    RAM_PAGE_MAX_PROOF_BYTES, RAM_PAGE_MAX_RESPONSE_BYTES, RamPageBinding,
};
use crucible_ram::{
    Limits, MetadataBudget, MetadataReservation, PageDigest, PageProof, RamRootDigest, RamSnapshot,
    RegionDescriptor, RootRecord, Topology,
};

use super::PAGE_BYTES;
use super::source::{
    LazyPageSource, NativePageHasher, SourceOperationClass, SourceOperationFactory,
};
use crate::ram_fingerprint::{PreparedRestoreCache, RamProofSource};

mod native;
pub(crate) use native::{
    PreparedRestoreMapping, RestoreMappingOwner, install, rebind_cold_child, rebind_resident,
};

/// A source connection retained by both fault service and immutable RAM identity.
pub(crate) struct RestorePageSource {
    record: RootRecord,
    root: RamRootDigest,
    connection: Mutex<LazyPageSource>,
    operations: Arc<dyn SourceOperationFactory>,
    _reservation: MetadataReservation,
}

impl RestorePageSource {
    /// Reports borrowed active endpoint roles without I/O or authority transfer.
    ///
    /// # Errors
    /// Refuses active or already transferred descriptor custody.
    pub(crate) fn endpoint_descriptors(&self) -> io::Result<[std::os::fd::RawFd; 2]> {
        self.connection
            .try_lock()
            .map_err(|_| io::Error::other("source endpoint active"))?
            .endpoint_descriptors()
    }

    /// Transfers inherited endpoint-close custody after actual child source rebind.
    ///
    /// # Errors
    /// Refuses active or already disposed source ownership.
    pub(crate) fn disarm_inherited(&self) -> io::Result<[std::os::fd::RawFd; 2]> {
        self.connection
            .try_lock()
            .map_err(|_| io::Error::other("inherited source is active"))?
            .disarm_inherited_endpoint()
    }

    /// Fetches one authenticated original page without entering the observer.
    ///
    /// # Errors
    /// Returns an error for unavailable source ownership, expired/canceled I/O,
    /// a poisoned endpoint, or invalid page bytes or proof authority.
    pub(crate) fn fetch(
        &self,
        region_ordinal: u32,
        page_index: u64,
        output: &mut [u8; PAGE_BYTES],
    ) -> io::Result<(u32, PageDigest)> {
        self.fetch_with_class(
            region_ordinal,
            page_index,
            output,
            SourceOperationClass::PageIn,
        )
    }

    /// Fetches original bytes under the live fingerprint operation allowance.
    ///
    /// # Errors
    /// Returns unavailable source ownership, transport, cancellation or proof errors.
    pub(crate) fn fetch_for_observation(
        &self,
        region_ordinal: u32,
        page_index: u64,
        output: &mut [u8; PAGE_BYTES],
    ) -> io::Result<(u32, PageDigest)> {
        self.fetch_with_class(
            region_ordinal,
            page_index,
            output,
            SourceOperationClass::FingerprintUpdate,
        )
    }

    /// Authenticates an observation inside its original source operation.
    ///
    /// # Errors
    /// Returns unavailable source custody, transport, proof, or hashing errors.
    pub(super) fn fetch_with_borrowed_hasher(
        &self,
        region_ordinal: u32,
        page_index: u64,
        output: &mut [u8; PAGE_BYTES],
        hasher: Option<&NativePageHasher>,
    ) -> io::Result<(u32, PageDigest)> {
        let operation = self
            .operations
            .begin(SourceOperationClass::FingerprintUpdate)?;
        self.connection
            .try_lock()
            .map_err(|_| io::Error::other("restore source ownership uncertain"))?
            .fetch_with_borrowed_hasher(
                region_ordinal,
                page_index,
                operation.as_ref(),
                output,
                hasher,
            )
            .map(|(length, digest, _)| (length, digest))
    }

    fn fetch_with_class(
        &self,
        region_ordinal: u32,
        page_index: u64,
        output: &mut [u8; PAGE_BYTES],
        class: SourceOperationClass,
    ) -> io::Result<(u32, PageDigest)> {
        let operation = self.operations.begin(class)?;
        self.connection
            .try_lock()
            .map_err(|_| io::Error::other("restore source ownership uncertain"))?
            .fetch_with_proof_supervised(region_ordinal, page_index, operation.as_ref(), output)
            .map(|(length, digest, _)| (length, digest))
    }
}

impl RamProofSource for RestorePageSource {
    fn source_record(&self) -> &RootRecord {
        &self.record
    }

    fn source_root(&self) -> RamRootDigest {
        self.root
    }

    fn proof(&self, region_id: &str, page_index: u64) -> Result<PageProof, RamError> {
        let ordinal = self
            .record
            .topology()
            .regions()
            .binary_search_by(|region| region.id().cmp(region_id))
            .map_err(|_| RamError::Invariant("restore proof region is absent"))?;
        let ordinal = u32::try_from(ordinal)
            .map_err(|_| RamError::Invariant("restore proof ordinal overflow"))?;
        let mut scratch = [0; PAGE_BYTES];
        let operation = self
            .operations
            .begin(SourceOperationClass::FingerprintUpdate)?;
        let (_, _, proof) = self
            .connection
            .try_lock()
            .map_err(|_| RamError::Invariant("restore source ownership uncertain"))?
            .fetch_with_proof_supervised(ordinal, page_index, operation.as_ref(), &mut scratch)?;
        Ok(proof)
    }
}

/// Fully authenticated source and opaque snapshot, before mapping admission.
///
/// Construction reads descriptors and bounded root metadata only. It never
/// touches guest bytes, clears tracking obligations, or claims cold activation.
pub(crate) struct ValidatedRestoreSource {
    pub(crate) topology_generation: u64,
    pub(crate) native_regions: Vec<RegionDescriptor>,
    pub(crate) budget: MetadataBudget,
    pub(crate) source: Arc<RestorePageSource>,
    snapshot: RamSnapshot,
    inventory_reservation: MetadataReservation,
}

impl ValidatedRestoreSource {
    /// Validates the source against the actual paused native inventory.
    ///
    /// The caller authenticates these descriptor roles during native setup and
    /// retains its writer fence. Descriptor numbers themselves are not identity;
    /// imported child descriptors can differ from the initial fixed source fd.
    ///
    /// # Errors
    /// Refuses invalid bounds or source identity, native inventory mismatch,
    /// unavailable capture authority, and exhausted shared metadata admission.
    pub(crate) fn bind(
        stream: UnixStream,
        cancellation: OwnedFd,
        binding: RamPageBinding,
        root_bytes: &[u8],
        expected_topology: [u8; 32],
        operations: Arc<dyn SourceOperationFactory>,
    ) -> Result<Self, RamError> {
        if root_bytes.is_empty() || root_bytes.len() > Limits::default().max_record_bytes {
            return Err(RamError::Invariant(
                "restore root record exceeds its bounded format",
            ));
        }
        let (topology_generation, native_regions, budget, inventory_reservation) =
            crate::ram_fingerprint::capture_restore_inventory()?;
        if topology_generation == 0 {
            return Err(RamError::Invariant(
                "restore native topology generation is empty",
            ));
        }
        let logical_bytes = native_regions.iter().try_fold(0_u64, |total, region| {
            total
                .checked_add(region.logical_length())
                .ok_or(RamError::Invariant("restore native byte count overflow"))
        })?;
        // Charge source decoder/retained roots and the bounded exchange scratch
        // before allocating them. The same account includes the old live view,
        // opaque snapshot, cache records, manager staging and in-flight proofs.
        let metadata = root_bytes
            .len()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RestorePageSource>()))
            .and_then(|bytes| {
                bytes.checked_add(
                    RAM_PAGE_MAX_RESPONSE_BYTES + PAGE_BYTES + 2 * RAM_PAGE_MAX_PROOF_BYTES,
                )
            })
            .ok_or("restore source metadata charge overflow")?;
        let reservation = budget.reserve_bytes(
            u64::try_from(metadata)
                .map_err(|_| RamError::Invariant("restore metadata size overflow"))?,
        )?;
        let limits = Limits {
            max_regions: native_regions.len(),
            max_logical_bytes: logical_bytes,
            max_record_bytes: Limits::default().max_record_bytes,
        };
        let native_topology = Topology::new(native_regions.clone(), limits)?;
        if native_topology.digest().as_bytes() != &expected_topology {
            return Err(RamError::Invariant(
                "restore source does not select the actual native topology",
            ));
        }
        let connection = LazyPageSource::bind(
            stream,
            cancellation,
            binding,
            root_bytes,
            expected_topology,
            limits,
        )?;
        if connection.root().topology() != &native_topology {
            return Err(RamError::Invariant(
                "restore source region ownership differs from native mappings",
            ));
        }
        let snapshot = RamSnapshot::from_root_record(connection.root(), &budget)?;
        let record = connection.root().clone();
        let root = record.digest();
        let source = Arc::new(RestorePageSource {
            record,
            root,
            connection: Mutex::new(connection),
            operations,
            _reservation: reservation,
        });
        Ok(Self {
            topology_generation,
            native_regions,
            budget,
            source,
            snapshot,
            inventory_reservation,
        })
    }

    /// Authenticates a staged fork baseline without observing or replacing current RAM.
    ///
    /// The actual engine must compare this exact source record and topology epoch
    /// with its retained original source before accepting a child arena receipt.
    /// The shared budget is the parent's existing native-admitted account.
    ///
    /// # Errors
    /// Refuses malformed namespaces/roots, insufficient metadata, invalid source
    /// transport or a nonpositive parent topology generation.
    pub(crate) fn bind_fork_source(
        topology_generation: u64,
        budget: MetadataBudget,
        stream: UnixStream,
        cancellation: OwnedFd,
        binding: RamPageBinding,
        root_bytes: &[u8],
        operations: Arc<dyn SourceOperationFactory>,
    ) -> Result<Self, RamError> {
        if topology_generation == 0
            || root_bytes.is_empty()
            || root_bytes.len() > Limits::default().max_record_bytes
        {
            return Err(RamError::Invariant(
                "fork source exceeds admitted metadata bounds",
            ));
        }
        let bytes = root_bytes
            .len()
            .checked_mul(4)
            .and_then(|bytes| {
                bytes.checked_add(
                    RAM_PAGE_MAX_RESPONSE_BYTES + PAGE_BYTES + 2 * RAM_PAGE_MAX_PROOF_BYTES,
                )
            })
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RestorePageSource>()))
            .ok_or("fork source metadata overflow")?;
        let reservation = budget.reserve_bytes(bytes as u64)?;
        let record = RootRecord::decode(root_bytes, Limits::default())?;
        let expected_topology = *record.topology().digest().as_bytes();
        let native_regions = record.topology().regions().to_vec();
        let connection = LazyPageSource::bind(
            stream,
            cancellation,
            binding,
            root_bytes,
            expected_topology,
            Limits::default(),
        )?;
        let snapshot = RamSnapshot::from_root_record(&record, &budget)?;
        let inventory_bytes = native_regions.iter().try_fold(
            std::mem::size_of::<Vec<RegionDescriptor>>() as u64,
            |bytes, region| {
                bytes
                    .checked_add(
                        (std::mem::size_of::<RegionDescriptor>() + region.id().len()) as u64,
                    )
                    .ok_or("fork source inventory overflow")
            },
        )?;
        let inventory_reservation = budget.reserve_bytes(inventory_bytes)?;
        let source = Arc::new(RestorePageSource {
            root: record.digest(),
            record,
            connection: Mutex::new(connection),
            operations,
            _reservation: reservation,
        });
        Ok(Self {
            topology_generation,
            native_regions,
            budget,
            source,
            snapshot,
            inventory_reservation,
        })
    }

    /// Transfers an authenticated immutable source without preparing a new cache.
    ///
    /// This is used by a separately certified fork handoff whose current identity
    /// remains inherited while its immutable original page source is rebound.
    pub(crate) fn into_page_source(self) -> Arc<RestorePageSource> {
        self.source
    }

    /// Precomputes all identity records after real arena preparation succeeds.
    ///
    /// The mapping owner must retain this source and its UFFD registrations
    /// before calling this method. Dropping/aborting the receipt before mutation
    /// releases only the candidate identity. After the first mapping mutation,
    /// failure invalidates execution and never releases fault authority.
    ///
    /// # Errors
    /// Refuses a stale transaction, uncertain observer exclusion, incompatible
    /// topology/root identity, or exhausted metadata admission.
    pub(crate) fn prepare_cache(self, transaction: u64) -> Result<PreparedRestoreSource, RamError> {
        let proof_source: Arc<dyn RamProofSource> = self.source.clone();
        let cache = crate::ram_fingerprint::prepare_restore(
            transaction,
            self.topology_generation,
            &self.native_regions,
            self.budget.clone(),
            self.snapshot,
            self.source.root,
            proof_source,
        )?;
        // The prepared cache owns its admitted inventory copy and proof source;
        // the arena owner separately retains the fault connection. Release this
        // temporary decoder inventory and its matching charge together.
        drop(self.native_regions);
        drop(self.inventory_reservation);
        Ok(PreparedRestoreSource {
            topology_generation: self.topology_generation,
            cache: Some(cache),
            commit_started: false,
        })
    }
}

/// Candidate identity retained beside the mapping owner's actual prepared arenas.
pub(crate) struct PreparedRestoreSource {
    pub(crate) topology_generation: u64,
    cache: Option<PreparedRestoreCache>,
    commit_started: bool,
}

impl PreparedRestoreSource {
    /// Marks the irreversible boundary before the first native discard syscall.
    ///
    /// # Errors
    /// Refuses repeated entry into the destructive transaction boundary.
    pub(crate) fn begin_mapping_commit(&mut self) -> Result<(), RamError> {
        if self.commit_started {
            return Err(RamError::Invariant(
                "restore mapping commit already started",
            ));
        }
        self.commit_started = true;
        Ok(())
    }

    /// Publishes prepared identity only after the mapping owner's cold commit.
    ///
    /// This consumes no source/registration ownership; the owner retains `self`
    /// through a publication error and prevents execution until process reap.
    ///
    /// # Errors
    /// Refuses publication before destructive commit, a disposed receipt, or
    /// loss of the prepared cache's exact generation/exclusion authority.
    pub(crate) fn publish_after_mapping_commit(&mut self) -> Result<(), RamError> {
        if !self.commit_started {
            return Err(RamError::Invariant(
                "restore identity cannot publish before mapping commit",
            ));
        }
        self.cache
            .take()
            .ok_or("restore identity already disposed")?
            .commit()
    }

    /// Releases the candidate identity before any destructive mapping operation.
    ///
    /// The mapping owner first undoes inactive registrations while guest RAM is
    /// still intact. This method cannot restore bytes after commit has started.
    ///
    /// # Errors
    /// Returns the owned transaction if destructive commit has started or cache
    /// rollback cannot prove its exclusion, preserving source and fault leases.
    pub(crate) fn abort_before_mapping_commit(mut self) -> Result<(), Self> {
        if self.commit_started {
            return Err(self);
        }
        if let Some(cache) = self.cache.take()
            && let Err(cache) = cache.abort()
        {
            self.cache = Some(cache);
            return Err(self);
        }
        Ok(())
    }
}
