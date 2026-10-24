//! Borrows trusted bundle framing and prices its closed Genesis decode carriers.
//!
//! Geometry is DATA. It neither opens the protected source nor grants import or
//! Replay authority; import still performs every existing canonical, semantic,
//! native and exact final-readback check.

use crate::protected_transaction::ProtectedDomainJournalErrorV1;

use super::*;


/// Carries bounded import buffers derived from one exact borrowed credential.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CacheBootstrapImportGeometryV1 {
    encoded_bytes: usize,
    manifest_bytes: usize,
    partitions: usize,
    largest_projects: usize,
    largest_manifest: usize,
}

impl CacheBootstrapImportGeometryV1 {
    /// Checks framing and the existing closed Genesis shape without allocation.
    ///
    /// # Errors
    /// Refuses invalid framing, checksum, manifest envelopes, Genesis shapes,
    /// count limits or truncation. Complete canonical validation follows in
    /// the existing importer; successful geometry alone is not valid evidence.
    pub(crate) fn from_bundle(bytes: &[u8]) -> Result<Self, CacheReplayControllerBootstrapErrorV1> {
        let view = ControllerBundleViewV1::new(bytes).map_err(map_bootstrap_history_data_error_v1)?;
        let mut geometry = Self {
            encoded_bytes: bytes.len(),
            manifest_bytes: 0,
            partitions: view.count(),
            largest_projects: 0,
            largest_manifest: 0,
        };
        for manifest in view.manifests() {
            let manifest = manifest.map_err(map_bootstrap_history_data_error_v1)?;
            let projects = genesis_manifest_project_count(manifest, CacheRecoveryLimitsV1::default())
                .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
            geometry.manifest_bytes = geometry.manifest_bytes.checked_add(manifest.len())
                .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)?;
            geometry.largest_projects = geometry.largest_projects.max(projects);
            geometry.largest_manifest = geometry.largest_manifest.max(manifest.len());
        }
        Ok(geometry)
    }

    /// Measures the largest complete import append using the Native geometry owner.
    ///
    /// Existing partitions can reduce this bound; the admitted original keeps
    /// the complete all-missing append charged. Native framing is linear in
    /// present value bytes, so adding their exact aggregate avoids constructing
    /// record/value copies or a second framing engine.
    ///
    /// # Errors
    /// Refuses unrepresentable Native geometry or aggregate byte overflow.
    pub(crate) fn maximum_native_append_bytes(&self) -> Result<u64, CacheReplayControllerBootstrapErrorV1> {
        use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
        let empty_values = encoded_transaction_append_bytes((0..self.partitions).map(|_| RecordShape {
            key_bytes: SOURCE_KEY_PREFIX.len() + 32, value_bytes: Some(0),
        })).map_err(JournalError::from)?;
        empty_values.checked_add(u64::try_from(self.manifest_bytes)
            .map_err(|_| CacheReplayControllerBootstrapErrorV1::InvalidSource)?)
            .ok_or(CacheReplayControllerBootstrapErrorV1::InvalidSource)
    }

    // The exact closed bundle's all-missing native member count is DATA.
    pub(super) const fn maximum_native_append_records(&self) -> usize {
        self.partitions
    }

    /// Counts import-owned carriers beyond Native source and Runtime owners.
    pub(crate) fn dominant_import_metadata_entries(&self) -> Option<usize> {
        self.partitions.checked_add(self.quota_carrier_count())?.checked_mul(3)
    }

    // A first successful push can allocate four carriers even for one quota.
    // Four is a conservative initial floor for these nonzero-sized models;
    // the existing three-way allowance also covers subsequent Vec growth.
    fn quota_carrier_count(&self) -> usize {
        if self.largest_projects == 0 {
            return 0;
        }
        self.largest_projects.max(4)
    }

    /// Counts import-owned buffers beyond the already-retained Runtime bundle.
    ///
    /// This excludes the actual opened Native source, its existing-record map
    /// clone and replay/preflight work, which the original baseline separately prices from its real file
    /// geometry. It includes requested, missing-TX and final reopened manifest
    /// maps; their key/carrier copies; and the largest sequential Genesis decode
    /// with canonical encoding and quota/accounting carriers. No decode retains
    /// complete typed inventories for all bundle partitions simultaneously.
    pub(crate) fn dominant_import_memory_bytes(&self) -> Option<usize> {
        let manifest_carrier = std::mem::size_of::<(ObjectDigest, Vec<u8>, [usize; 4])>()
            .checked_add(std::mem::size_of::<JournalRecord>())?
            .checked_add(SOURCE_KEY_PREFIX.len() + 32)?;
        let quota_carrier = std::mem::size_of::<ProjectCacheQuotaV1>()
            .checked_add(std::mem::size_of::<([u8; 16], ProjectCacheQuotaV1, [usize; 4])>())?;
        // Three full manifest maps/record sets coexist across import and final
        // reopen. Two encoded component buffers cover validation/round-trip;
        // doubling their logical extents covers ordinary Vec growth capacity.
        self.encoded_bytes.checked_mul(3)?
            .checked_add(self.partitions.checked_mul(manifest_carrier)?.checked_mul(3)?)?
            .checked_add(self.largest_manifest.checked_mul(4)?)?
            // One decoded quota Vec and the two accounting/projection maps
            // may coexist during typed-checkpoint validation.
            .checked_add(self.quota_carrier_count().checked_mul(quota_carrier)?.checked_mul(3)?)?
            // The same recovery locals cross their existing authority check in
            // two inline assembly carriers; no additional model map is cloned.
            .checked_add(aos_sandbox_protocol::cache_state::recovery::recovery_assembly_inline_bytes_v1().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Self>())
    }
}


pub(super) use aos_sandbox_protocol::cache_state::replay_evidence::{ControllerBundleViewV1, BundleManifestIterV1};

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use aos_sandbox_model::{CacheDomainId, ProjectId};
    use aos_sandbox_model::model::{CacheDomain, CacheDomainKind};
    use aos_sandbox_protocol::cache_state::{
        BackingIsolationV1, CacheIsolationPolicyV1, CacheNodeIdV1,
        ProtectedBackingIdentityV1, ResidencyEnforcementV1,
    };

    pub(in crate::controller_bootstrap) fn manifest() -> Vec<u8> {
        let project = ProjectId::from_bytes([1; 16]);
        let node = CacheNodeIdV1::from_bytes([2; 16]).unwrap();
        let backing = ProtectedBackingIdentityV1::new(
            ObjectDigest::from_bytes([3; 32]), ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]), ObjectDigest::from_bytes([6; 32]),
        ).unwrap();
        let domain = CacheDomain::new(
            CacheDomainKind::Project, CacheDomainId::from_bytes(*project.as_bytes()),
        );
        let isolation = CacheIsolationPolicyV1 {
            backing: BackingIsolationV1::SeparateFilesystemOrDataset,
            residency: ResidencyEnforcementV1::HardIsolatedResidency,
            reflink_or_clone: false, block_deduplication: false,
            shared_page_cache: false, fetch_coalescing: false, strict: true, revision: 1,
        };
        let partition = PhysicalPartitionId::from_policy(node, backing, domain, isolation).unwrap();
        let node_quota = NodeCacheQuotaV1 {
            partition, maximum_physical_bytes: 1024 * 1024,
            maximum_resident_objects: 16, maximum_logical_pins: 16,
            maximum_source_retentions: 16, maximum_kernel_references: 16,
            maximum_backing_registrations: 16, recovery_reserve_bytes: 4096,
            high_water_bytes: 768 * 1024, low_water_bytes: 512 * 1024,
        };
        let quota = ProjectCacheQuotaV1 {
            project, partition, maximum_charged_bytes: 1024 * 1024,
            maximum_logical_pins: 16, maximum_source_retentions: 16,
            maximum_kernel_references: 16, maximum_backing_registrations: 16,
        };
        encode_cache_replay_genesis_manifest_v1(partition, node_quota, vec![quota], 100).unwrap()
    }

    fn bundle_unvalidated(manifest: &[u8]) -> Vec<u8> {
        // This helper deliberately avoids the production encoder's complete
        // validation so malformed authenticated credential bytes reach preflight.
        let mut bundle = b"AOSCRB01\0\x01\0\x01\0\0\0\0".to_vec();
        bundle.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        bundle.extend_from_slice(manifest);
        let digest = Sha256::new().chain_update(BUNDLE_DOMAIN).chain_update(&bundle).finalize();
        bundle.extend_from_slice(&digest);
        bundle
    }

    #[test]
    fn geometry_agrees_with_complete_genesis_import_and_counts_real_quota_carriers() {
        let manifest = manifest();
        let bundle = encode_cache_replay_controller_bundle_v1([manifest.clone()]).unwrap();
        let geometry = CacheBootstrapImportGeometryV1::from_bundle(&bundle).unwrap();
        let decoded = decode_controller_bundle(&bundle).unwrap();

        assert_eq!(geometry.partitions, decoded.len());
        assert_eq!(geometry.largest_projects, 1);
        assert_eq!(geometry.largest_manifest, manifest.len());
        assert!(geometry.dominant_import_memory_bytes().unwrap() > 3 * bundle.len());
        assert_eq!(decoded.values().next().unwrap(), &manifest);
        let measured = aos_sandbox_journal::geometry::encoded_transaction_append_bytes(
            [aos_sandbox_journal::geometry::RecordShape {
                key_bytes: SOURCE_KEY_PREFIX.len() + 32, value_bytes: Some(manifest.len()),
            }].into_iter(),
        ).unwrap();
        assert_eq!(geometry.maximum_native_append_bytes().unwrap(), measured);
    }

    #[test]
    #[cfg(unix)]
    fn actual_initializer_rows_choose_genesis_and_foreign_state_chooses_general() {
        use std::fs;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use crate::CacheReplayManifestGeometryV1;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let open = |fixture| {
            Journal::open_cache_ordinary_fixture_v1(
                directory.path(),
                fixture,
                controller_cache_journal_limits(),
                uid,
            )
            .unwrap()
            .0
        };
        let mut source = open(crate::journal::CacheOrdinaryFixtureV1::GeometrySource);
        let mut authority = open(crate::journal::CacheOrdinaryFixtureV1::GeometryAuthority);
        let mut state = open(crate::journal::CacheOrdinaryFixtureV1::GeometryState);
        let manifest = manifest();
        let partition = borrow_cache_replay_manifest(&manifest, CacheRecoveryLimitsV1::default())
            .unwrap().partition.digest();
        let mut manifest_key = super::super::super::protected_owner::CACHE_MANIFEST_KEY_PREFIX.to_vec();
        manifest_key.extend_from_slice(partition.as_bytes());
        for (journal, key) in [(&mut source, source_key(partition)), (&mut authority, manifest_key)] {
            let transaction = JournalTransaction::new([1; 16], vec![JournalRecord::put(
                RecordNamespace::DesiredState, key, manifest.clone(),
            )]).unwrap();
            journal.claim_cache_authority_v1()
                .unwrap().commit(&transaction).unwrap();
        }

        let limits = CacheRecoveryLimitsV1::default();
        let source_geometry = CacheReplayManifestGeometryV1::from_source_journal(&source, limits).unwrap();
        assert!(source_geometry.genesis_manifest_validation_bound().unwrap().is_some());
        // No state observation was supplied at this earlier causal frontier.
        assert!(source_geometry.genesis_initial_inventory_bound().unwrap().is_none());
        assert_eq!(source_geometry.encoded_bytes(), manifest.len());
        assert_eq!(source_geometry.partition_bound(), 1);
        let geometry = CacheReplayManifestGeometryV1::from_initial_journals(&authority, &state, limits).unwrap();
        assert!(geometry.genesis_initial_inventory_bound().unwrap().is_some());
        drop(geometry);

        let foreign = JournalTransaction::new([2; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, b"foreign-state".to_vec(), vec![1, 2, 3],
        )]).unwrap();
        state.claim_cache_authority_v1()
            .unwrap().commit(&foreign).unwrap();
        let changed = CacheReplayManifestGeometryV1::from_initial_journals(&authority, &state, limits).unwrap();
        assert!(changed.genesis_initial_inventory_bound().unwrap().is_none());
        assert!(changed.genesis_manifest_validation_bound().unwrap().is_none());
        assert!(changed.encoded_bytes() > manifest.len());

        drop(source_geometry);
        let malformed = JournalTransaction::new([3; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, source_key(ObjectDigest::from_bytes([99; 32])), vec![0],
        )]).unwrap();
        source.claim_cache_authority_v1()
            .unwrap().commit(&malformed).unwrap();
        let malformed = CacheReplayManifestGeometryV1::from_source_journal(&source, limits).unwrap();
        assert!(malformed.genesis_manifest_validation_bound().unwrap().is_none());
        assert_eq!(malformed.encoded_bytes(), manifest.len() + 1);
        assert_eq!(malformed.partition_bound(), 2);
    }

    #[test]
    fn advertised_non_genesis_and_truncated_quota_counts_refuse_before_general_decode() {
        let original = manifest();
        let key_bytes = usize::from(u16::from_be_bytes(original[545..547].try_into().unwrap()));
        let checkpoint_start = 555 + key_bytes;
        // The typed checkpoint contains header16, checkpoint-length4, fixed
        // checkpoint328, then baseline-count4 and family-head-count4.
        for offset in [checkpoint_start + 348, checkpoint_start + 352] {
            let mut changed = original.clone();
            changed[offset..offset + 4].copy_from_slice(&65_536_u32.to_be_bytes());
            assert!(CacheBootstrapImportGeometryV1::from_bundle(&bundle_unvalidated(&changed)).is_err());
            assert!(decode_controller_bundle(&bundle_unvalidated(&changed)).is_err());
        }

        // global begins after the typed header and the fixed checkpoint and
        // empty count fields; its projects follow header16+partition32+node72.
        let quota_count = checkpoint_start + 360 + 120;
        let mut changed = original;
        changed[quota_count..quota_count + 4].copy_from_slice(&65_536_u32.to_be_bytes());
        assert!(CacheBootstrapImportGeometryV1::from_bundle(&bundle_unvalidated(&changed)).is_err());
    }

    #[test]
    fn tiny_quota_sets_keep_initial_vector_capacity_charged() {
        let mut geometry = CacheBootstrapImportGeometryV1 {
            encoded_bytes: 0,
            manifest_bytes: 0,
            partitions: 0,
            largest_projects: 0,
            largest_manifest: 0,
        };
        let empty = geometry.dominant_import_memory_bytes().unwrap();
        let quota_carrier = std::mem::size_of::<ProjectCacheQuotaV1>()
            + std::mem::size_of::<([u8; 16], ProjectCacheQuotaV1, [usize; 4])>();

        for count in 1..=4 {
            geometry.largest_projects = count;
            assert_eq!(geometry.dominant_import_memory_bytes(), Some(empty + 12 * quota_carrier));
            assert_eq!(geometry.dominant_import_metadata_entries(), Some(12));
        }
        geometry.largest_projects = 5;
        assert_eq!(geometry.dominant_import_memory_bytes(), Some(empty + 15 * quota_carrier));
        assert_eq!(geometry.dominant_import_metadata_entries(), Some(15));
    }

    #[test]
    fn import_geometry_arithmetic_refuses_overflow() {
        let geometry = CacheBootstrapImportGeometryV1 {
            encoded_bytes: usize::MAX, manifest_bytes: usize::MAX, partitions: usize::MAX,
            largest_projects: usize::MAX, largest_manifest: usize::MAX,
        };
        assert!(geometry.dominant_import_memory_bytes().is_none());
        assert!(geometry.dominant_import_metadata_entries().is_none());
    }

    #[test]
    fn bundle_checksum_count_truncation_and_trailing_bytes_keep_exact_framing() {
        let manifest = manifest();
        let original = bundle_unvalidated(&manifest);
        for length in 0..original.len() {
            assert!(CacheBootstrapImportGeometryV1::from_bundle(&original[..length]).is_err());
        }
        let mut wrong_checksum = original.clone();
        *wrong_checksum.last_mut().unwrap() ^= 1;
        assert!(CacheBootstrapImportGeometryV1::from_bundle(&wrong_checksum).is_err());

        let mut extra = original[..original.len() - 32].to_vec();
        extra.push(0);
        let digest = Sha256::new().chain_update(BUNDLE_DOMAIN).chain_update(&extra).finalize();
        extra.extend_from_slice(&digest);
        assert!(CacheBootstrapImportGeometryV1::from_bundle(&extra).is_err());
    }
}
