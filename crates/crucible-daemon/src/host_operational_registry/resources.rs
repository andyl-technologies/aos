//! Authored registry service capacity and final physical cleanup custody.
//!
//! Registry bookkeeping has fixed owner and protocol bounds. Its whole service
//! entitlement is reserved before filesystem access, independently of guest
//! allocations. The retained permit outlives the writer and all indexed state.

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};

use super::*;

const CONTROL_REQUESTS: usize = 16;
const JOURNAL_BUFFER_BYTES: usize = 8192;
// Receipt matching is serialized. Its retained evidence is bounded per owner;
// hashing, typed JSON parsing and kernel notes share one transient allowance.
const QUALIFICATION_RECEIPT_BYTES: usize = 4096;
const QUALIFICATION_SCRATCH_BYTES: usize = 256 * 1024;
const QUALIFICATION_DESCRIPTOR_PEAK: u64 = 2;
// Two root/temporary directory authorities (two descriptors each), the bound
// writer lock (four), three concurrent anchored files (three each), two parent
// lookups, and two nested pathname verification authorities (three each).
const HISTORY_DESCRIPTOR_PEAK: u64 = 2 * 2 + 4 + 3 * 3 + 2 + 2 * 3;

struct Retirement {
    owner: [u8; 32],
    authority: Mutex<Option<Box<dyn RegistryRetirementAuthority>>>,
}

impl Drop for Retirement {
    fn drop(&mut self) {
        let authority = match self.authority.get_mut() {
            Ok(authority) => authority.take(),
            Err(poisoned) => {
                if let Some(retained) = poisoned.into_inner().take() {
                    std::mem::forget(retained);
                }
                return;
            }
        };
        if let Some(mut retained) = authority
            && retained.retire_after_cleanup(self.owner).is_err()
        {
            // Keep the original charged actor when final disposition is
            // uncertain. Dropping a wrapper is never cleanup evidence.
            std::mem::forget(retained);
        }
    }
}

pub(super) struct RegistryResources {
    pub(super) entitlement: HostResourceVector,
    services: HostServiceAllocator,
    metadata: HostServiceAllocator,
    _lease: HostServiceLease,
    _metadata_floor: HostServiceLease,
    // Last-field destruction releases the original actor only after its actual
    // descriptor and resident permits have been returned by the field above.
    retirement: Retirement,
}

struct RegistryMetadataCredit {
    _resident: HostServiceLease,
    _metadata: HostServiceLease,
    // Last: the original actor cannot retire while this receipt still owns
    // resident or metadata permits, including DecodeBudget's initial receipt.
    _resources: Arc<RegistryResources>,
}

struct RegistryMetadataAuthority {
    resources: Arc<RegistryResources>,
    _credit: RegistryMetadataCredit,
}

impl RegistryResources {
    fn reserve_metadata(
        self: &Arc<Self>,
        bytes: u64,
    ) -> Result<RegistryMetadataCredit, DecodeAdmissionError> {
        let bytes = bytes
            .checked_add(std::mem::size_of::<RegistryMetadataCredit>() as u64)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>() as u64))
            .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes()))
            .ok_or_else(|| DecodeAdmissionError::new(HostOperationalError::Unavailable))?;
        let resident = self
            .services
            .reserve_resources(0, 0, bytes)
            .map_err(DecodeAdmissionError::new)?;
        let metadata = self
            .metadata
            .reserve_resources(0, 0, bytes)
            .map_err(DecodeAdmissionError::new)?;
        Ok(RegistryMetadataCredit {
            _resident: resident,
            _metadata: metadata,
            _resources: Arc::clone(self),
        })
    }
}

impl DecodeResourceAuthority for RegistryMetadataAuthority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        // Both banks and terminal actor custody belong to these SAME retained
        // RegistryResources. No replacement or detached allocator is consulted.
        self.resources
            .services
            .verify_live()
            .map_err(DecodeAdmissionError::new)?;
        self.resources
            .metadata
            .verify_live()
            .map_err(DecodeAdmissionError::new)
    }

    fn reserve(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
        Ok(crucible_cas::owned_decode::ResourceLoan::new(
            self.resources.reserve_metadata(bytes)?,
        ))
    }
}

impl HostOperationalRegistry {
    /// Creates response metadata custody within the original registry service.
    ///
    /// Both retained responses and concurrent decoders draw from the same
    /// resident allocator and independently authored metadata subset. The
    /// authority retains final registry retirement until their last close.
    ///
    /// # Errors
    /// Refuses missing original admission, exhausted subset capacity, or
    /// unavailable accounting. No detached allowance is inferred.
    pub(crate) fn metadata_budget(&self) -> Result<DecodeBudget, HostOperationalError> {
        if let Some(resources) = &self.shared.resources {
            let maximum = resources
                .entitlement
                .metadata_bytes
                .checked_sub(registry_resource_floor()?.metadata_bytes)
                .ok_or(HostOperationalError::Unavailable)?;
            let authority_bytes = (std::mem::size_of::<RegistryMetadataAuthority>()
                + 2 * std::mem::size_of::<usize>()) as u64;
            let credit = resources
                .reserve_metadata(authority_bytes)
                .map_err(|source| HostOperationalError::Admission { source })?;
            let authority = Arc::new(RegistryMetadataAuthority {
                resources: Arc::clone(resources),
                _credit: credit,
            });
            return DecodeBudget::new(authority, maximum)
                .map_err(|source| HostOperationalError::Admission { source });
        }
        #[cfg(test)]
        if let Some(budget) = self
            .shared
            .component_metadata
            .lock()
            .map_err(unavailable)?
            .as_ref()
        {
            return budget
                .child()
                .map_err(|source| HostOperationalError::Admission { source });
        }
        Err(HostOperationalError::Unavailable)
    }

    /// Attaches explicitly supplied finite metadata authority to a component.
    ///
    /// This supports isolated protocol fixtures. It cannot replace an admitted
    /// registry service or attach another account to an existing component.
    ///
    /// # Errors
    /// Refuses existing admission, an earlier attachment, or failed accounting.
    #[cfg(test)]
    pub(crate) fn with_component_metadata_budget(
        self,
        budget: DecodeBudget,
    ) -> Result<Self, HostOperationalError> {
        if self.shared.resources.is_some() {
            return Err(HostOperationalError::Unavailable);
        }
        budget
            .check()
            .map_err(|source| HostOperationalError::Admission { source })?;
        {
            let mut slot = self.shared.component_metadata.lock().map_err(unavailable)?;
            if slot.is_some() {
                return Err(HostOperationalError::Unavailable);
            }
            *slot = Some(budget);
        }
        Ok(self)
    }

    /// Validates the complete fixed-roster service before any namespace I/O.
    ///
    /// # Errors
    /// Refuses missing ownership, insufficient metadata, scratch or descriptors,
    /// and resident subset overflow. This performs no filesystem access.
    pub(crate) fn validate_service_resources(
        owner: [u8; 32],
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        if owner == [0; 32]
            || !registry_resource_floor()?.fits(resources)
            || resources
                .metadata_bytes
                .checked_add(resources.staging_bytes)
                .is_none_or(|resident| resident > resources.resident_peak_bytes)
        {
            return Err(HostOperationalError::Unavailable);
        }
        Ok(())
    }

    /// Returns the audited registry allocation floor without opening its namespace.
    pub(crate) fn minimum_service_resources() -> Result<HostResourceVector, HostOperationalError> {
        registry_resource_floor()
    }

    /// Returns the genuine baseline service identity and immutable entitlement.
    pub(crate) fn admitted_registry_service(&self) -> Option<([u8; 32], HostResourceVector)> {
        self.shared
            .resources
            .as_ref()
            .map(|resources| (resources.retirement.owner, resources.entitlement))
    }

    /// Opens a registry beneath an already retained complete service charge.
    ///
    /// The caller must reserve `resources` on its existing executor actor before
    /// calling this method. The backing entitlement includes all durable
    /// history; attachment must not charge that history a second time.
    ///
    /// # Errors
    /// Refuses an empty owner, an incomplete fixed-roster allocation, a corrupt
    /// history, a competing writer, or uncertain physical descriptor ownership.
    #[cfg(test)]
    pub(crate) fn open_admitted(
        path: &Path,
        owner: [u8; 32],
        resources: HostResourceVector,
    ) -> Result<Self, HostOperationalError> {
        let allocator = HostServiceAllocator::new(
            resources.task_slots,
            resources.file_descriptors,
            resources.resident_peak_bytes,
        )
        .map_err(unavailable)?;
        Self::open_admitted_with_services(path, owner, resources, allocator)
    }

    /// Opens history using the original startup service allocator.
    ///
    /// # Errors
    /// Refuses a different allocator ceiling, exhausted physical permits, or unsafe history.
    pub(crate) fn open_admitted_with_services(
        path: &Path,
        owner: [u8; 32],
        resources: HostResourceVector,
        allocator: HostServiceAllocator,
    ) -> Result<Self, HostOperationalError> {
        Self::validate_service_resources(owner, resources)?;
        if allocator.maximum_tasks() != resources.task_slots
            || allocator.maximum_file_descriptors() != resources.file_descriptors
            || allocator.maximum_resident_bytes() != resources.resident_peak_bytes
        {
            return Err(HostOperationalError::Unavailable);
        }
        let floor = registry_resource_floor()?;
        let lease = allocator
            .reserve_resources(0, floor.file_descriptors, floor.resident_peak_bytes)
            .map_err(unavailable)?;
        // This counter tracks only the metadata subset; it is paired with the
        // same resident allocator for every loan, never a second entitlement.
        let metadata =
            HostServiceAllocator::new(1, 1, resources.metadata_bytes).map_err(unavailable)?;
        let metadata_floor = metadata
            .reserve_resources(0, 0, floor.metadata_bytes)
            .map_err(unavailable)?;
        let history = history::History::open(path, resources.backing_peak_bytes)?;
        Ok(Self::from_history_and_resources(
            Some(history),
            Some(RegistryResources {
                entitlement: resources,
                services: allocator,
                metadata,
                _lease: lease,
                _metadata_floor: metadata_floor,
                retirement: Retirement {
                    owner,
                    authority: Mutex::new(None),
                },
            }),
        ))
    }

    /// Transfers the original terminal actor into final registry custody.
    ///
    /// # Errors
    /// Refuses an unadmitted registry, replacement authority, or uncertain
    /// synchronization. The caller retains the original actor on refusal.
    pub(crate) fn retain_retirement_authority(
        &self,
        authority: Box<dyn RegistryRetirementAuthority>,
    ) -> Result<(), Box<dyn RegistryRetirementAuthority>> {
        let Some(resources) = &self.shared.resources else {
            return Err(authority);
        };
        let Ok(mut slot) = resources.retirement.authority.lock() else {
            return Err(authority);
        };
        if slot.is_some() {
            return Err(authority);
        }
        *slot = Some(authority);
        Ok(())
    }
}

/// Calculates fixed-roster metadata and bounded protocol scratch requirements.
///
/// The two public-frame envelopes per owner cover bounded map nodes, retained
/// targets, controller/catalog index entries and dynamic observation storage.
/// Native controller descriptors and catalog payloads retain their independent
/// node or catalog service charges and are not charged twice here.
fn registry_resource_floor() -> Result<HostResourceVector, HostOperationalError> {
    let record = std::mem::size_of::<Owner>()
        .checked_add(std::mem::size_of::<CapOwner>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HostRamTarget>()))
        .and_then(|bytes| bytes.checked_add(2 * HOST_OPERATIONAL_MAX_BYTES))
        .and_then(|bytes| bytes.checked_add(QUALIFICATION_RECEIPT_BYTES))
        .ok_or(HostOperationalError::Unavailable)?;
    let metadata = record
        .checked_mul(MAX_OWNERS)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Shared>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RegistryResources>()))
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
        .and_then(|bytes| bytes.checked_add(HostServiceAllocator::metadata_bytes() as usize))
        .and_then(|bytes| bytes.checked_add(2 * HostServiceLease::metadata_bytes() as usize))
        .and_then(|bytes| {
            bytes.checked_add(
                MAX_PRINCIPALS
                    * (std::mem::size_of::<PrincipalRate>()
                        + 64
                        + 4 * std::mem::size_of::<usize>()),
            )
        })
        .ok_or(HostOperationalError::Unavailable)?;
    let scratch = CONTROL_REQUESTS
        .checked_mul(std::mem::size_of::<HostRamStatus>() + 3 * HOST_OPERATIONAL_MAX_BYTES)
        .and_then(|bytes| bytes.checked_add(3 * JOURNAL_BUFFER_BYTES))
        .and_then(|bytes| bytes.checked_add(QUALIFICATION_SCRATCH_BYTES))
        .ok_or(HostOperationalError::Unavailable)?;
    let metadata = u64::try_from(metadata).map_err(unavailable)?;
    let staging = u64::try_from(scratch).map_err(unavailable)?;
    Ok(HostResourceVector {
        resident_peak_bytes: metadata
            .checked_add(staging)
            .ok_or(HostOperationalError::Unavailable)?,
        backing_peak_bytes: history::FIXED_HISTORY_CHARGE,
        metadata_bytes: metadata,
        staging_bytes: staging,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 1,
        file_descriptors: HISTORY_DESCRIPTOR_PEAK + QUALIFICATION_DESCRIPTOR_PEAK,
    })
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- resource and actual descriptor fixtures panic at failed ownership assumptions.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct CleanupWitness {
        lock: std::path::PathBuf,
        retired: Arc<AtomicBool>,
    }

    impl RegistryRetirementAuthority for CleanupWitness {
        fn retire_after_cleanup(&mut self, owner: [u8; 32]) -> Result<(), HostOperationalError> {
            assert_eq!(owner, [7; 32]);
            let file = std::fs::File::open(&self.lock).map_err(unavailable)?;
            let _lock = crate::owned_advisory_lock::OwnedAdvisoryLock::try_exclusive(file)
                .map_err(unavailable)?;
            self.retired.store(true, Ordering::Release);
            Ok(())
        }
    }

    struct ResponseCleanupWitness {
        descriptors: CleanupWitness,
        services: HostServiceAllocator,
    }

    impl RegistryRetirementAuthority for ResponseCleanupWitness {
        fn retire_after_cleanup(&mut self, owner: [u8; 32]) -> Result<(), HostOperationalError> {
            // Whole-capacity reuse proves both baseline and escaped response
            // permits closed before final original-actor retirement begins.
            let _closed = self
                .services
                .reserve_resources(
                    self.services.maximum_tasks(),
                    self.services.maximum_file_descriptors(),
                    self.services.maximum_resident_bytes(),
                )
                .map_err(unavailable)?;
            self.descriptors.retire_after_cleanup(owner)
        }
    }

    fn resources_with_response_headroom() -> HostResourceVector {
        let mut resources = registry_resource_floor().unwrap();
        resources.metadata_bytes += 8192;
        resources.resident_peak_bytes += 8192;
        resources
    }

    #[test]
    fn response_custody_keeps_original_retirement_until_its_last_close() {
        let directory = tempfile::tempdir().unwrap();
        let registry = HostOperationalRegistry::open_admitted(
            directory.path(),
            [7; 32],
            resources_with_response_headroom(),
        )
        .unwrap();
        let retired = Arc::new(AtomicBool::new(false));
        assert!(
            registry
                .retain_retirement_authority(Box::new(ResponseCleanupWitness {
                    descriptors: CleanupWitness {
                        lock: directory.path().join("writer.lock"),
                        retired: Arc::clone(&retired),
                    },
                    services: registry.shared.resources.as_ref().unwrap().services.clone(),
                }))
                .is_ok()
        );
        let budget = registry.metadata_budget().unwrap();
        budget.verify_live().unwrap();
        let scope = budget.enter();
        let response = HostOperationalResponse::admit(|| {
            Ok(HostOperationalResponse::Targets {
                target: HostRamOwnerTarget {
                    daemon_epoch: [1; 32],
                    owner_id: [7; 32],
                },
                targets: Vec::new(),
                next: None,
            })
        })
        .unwrap();
        let wire = crucible_api::host_operational::codec::encode_owned_response(&response).unwrap();
        {
            let _wire_scope = wire.enter_original_scope().unwrap();
            crucible::owned_decode::charge_bytes(
                (std::mem::size_of_val(&wire) + 2 * std::mem::size_of::<usize>()) as u64,
            )
            .unwrap();
        }
        let wire = Arc::new(wire);
        let final_reader = Arc::clone(&wire);

        drop(scope);
        drop(budget);
        drop(response);
        drop(wire);
        drop(registry);
        assert!(!retired.load(Ordering::Acquire));
        assert!(!final_reader.value().is_empty());
        {
            let _scope = final_reader.enter_original_scope().unwrap();
            crucible::owned_decode::current_budget()
                .unwrap()
                .verify_live()
                .unwrap();
        }
        assert!(!retired.load(Ordering::Acquire));

        drop(final_reader);
        assert!(retired.load(Ordering::Acquire));
    }

    #[test]
    fn concurrent_response_accounts_share_the_authored_metadata_peak() {
        let directory = tempfile::tempdir().unwrap();
        let registry = HostOperationalRegistry::open_admitted(
            directory.path(),
            [7; 32],
            resources_with_response_headroom(),
        )
        .unwrap();
        let first = registry.metadata_budget().unwrap();
        first.charge_bytes(6000).unwrap();
        let second = registry.metadata_budget().unwrap();
        assert!(second.charge_bytes(2000).is_err());
        first.verify_live().unwrap();
        assert!(second.verify_live().is_err());

        drop(second);
        drop(first);
        let replacement = registry.metadata_budget().unwrap();
        replacement.charge_bytes(6000).unwrap();
    }

    #[test]
    fn component_metadata_requires_an_explicit_original_account() {
        assert!(
            HostOperationalRegistry::default()
                .metadata_budget()
                .is_err()
        );
        let _scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
        let budget = crucible::owned_decode::current_budget().unwrap();
        let registry = HostOperationalRegistry::default()
            .with_component_metadata_budget(budget.clone())
            .unwrap();
        registry
            .metadata_budget()
            .unwrap()
            .charge_bytes(128)
            .unwrap();
        assert!(registry.with_component_metadata_budget(budget).is_err());

        let directory = tempfile::tempdir().unwrap();
        let registry = HostOperationalRegistry::open_admitted(
            directory.path(),
            [7; 32],
            resources_with_response_headroom(),
        )
        .unwrap();
        assert!(
            registry
                .with_component_metadata_budget(crucible::owned_decode::current_budget().unwrap())
                .is_err()
        );
    }

    #[test]
    fn insufficient_registry_metadata_refuses_before_filesystem_creation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unopened");
        let mut resources = registry_resource_floor().unwrap();
        resources.metadata_bytes -= 1;

        assert!(HostOperationalRegistry::open_admitted(&path, [7; 32], resources).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn final_registry_clone_closes_writer_before_terminal_actor_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let resources = registry_resource_floor().unwrap();
        let registry =
            HostOperationalRegistry::open_admitted(directory.path(), [7; 32], resources).unwrap();
        let retired = Arc::new(AtomicBool::new(false));
        let authority = CleanupWitness {
            lock: directory.path().join("writer.lock"),
            retired: Arc::clone(&retired),
        };
        assert!(
            registry
                .retain_retirement_authority(Box::new(authority))
                .is_ok()
        );
        let final_borrower = registry.clone();

        drop(registry);
        assert!(!retired.load(Ordering::Acquire));
        assert!(history::History::open(directory.path(), resources.backing_peak_bytes).is_err());

        drop(final_borrower);
        assert!(retired.load(Ordering::Acquire));
    }

    #[test]
    fn authored_registry_fixture_covers_the_computed_fixed_roster_floor() {
        let authored = HostResourceVector {
            resident_peak_bytes: 128 * 1024 * 1024,
            backing_peak_bytes: 16 * 1024 * 1024,
            metadata_bytes: 64 * 1024 * 1024,
            staging_bytes: 8 * 1024 * 1024,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 128,
        };
        assert!(registry_resource_floor().unwrap().fits(authored));
    }

    #[test]
    fn qualification_matching_requires_admission_and_preserves_expiry() {
        let invoked = AtomicBool::new(false);
        let mut live = || Ok(());
        let detached = HostOperationalRegistry::default();
        assert!(
            detached
                .with_paging_qualification_match(&mut live, |_| {
                    invoked.store(true, Ordering::Release);
                    Ok(())
                })
                .is_err()
        );
        assert!(!invoked.load(Ordering::Acquire));

        let directory = tempfile::tempdir().unwrap();
        let registry = HostOperationalRegistry::open_admitted(
            directory.path(),
            [7; 32],
            registry_resource_floor().unwrap(),
        )
        .unwrap();
        registry
            .with_paging_qualification_match(&mut live, |boundary| {
                boundary()?;
                invoked.store(true, Ordering::Release);
                Ok(())
            })
            .unwrap();
        assert!(invoked.load(Ordering::Acquire));

        invoked.store(false, Ordering::Release);
        let mut expired = || {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original setup deadline expired",
            ))
        };
        assert!(
            registry
                .with_paging_qualification_match(&mut expired, |_| {
                    invoked.store(true, Ordering::Release);
                    Ok(())
                })
                .is_err()
        );
        assert!(!invoked.load(Ordering::Acquire));
    }

    #[test]
    fn contended_qualification_matching_expires_the_original_setup_operation() {
        use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationClass};

        let directory = tempfile::tempdir().unwrap();
        let registry = HostOperationalRegistry::open_admitted(
            directory.path(),
            [7; 32],
            registry_resource_floor().unwrap(),
        )
        .unwrap();
        let _matching = registry.shared.qualification_match.lock().unwrap();
        let mut budgets = HostOperationBudgets::default();
        budgets.classes[HostOperationClass::Setup as usize].total_timeout =
            Some(Duration::from_millis(1));
        let supervisor =
            HostOperationSupervisor::new(budgets, Some(Duration::from_secs(1))).unwrap();
        let setup = supervisor.begin_control(HostOperationClass::Setup).unwrap();
        let mut boundary = || {
            setup
                .wait_slice()
                .map(|_| ())
                .map_err(std::io::Error::other)
        };
        let invoked = AtomicBool::new(false);

        assert!(
            registry
                .with_paging_qualification_match(&mut boundary, |_| {
                    invoked.store(true, Ordering::Release);
                    Ok(())
                })
                .is_err()
        );
        assert!(!invoked.load(Ordering::Acquire));
    }
}
