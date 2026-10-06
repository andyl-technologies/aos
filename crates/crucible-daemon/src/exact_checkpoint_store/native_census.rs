//! Bounded native-fixture census under the existing live storage and host owner.
//!
//! Counts are authenticated logical pages and object reads by position, not a
//! claim about the number of distinct physical objects in a durable catalog.

use super::*;
use crucible_cas::ram::{RamRetention, RamStoreError};
use crucible_linux_resource::host_supervision::{HostOperationClass, HostOperationSupervisor};

/// Counters for one authenticated RAM closure read while its actual owner lives.
#[derive(Default)]
pub(crate) struct NativeRamClosureCensus {
    /// Number of complete RAM roots in the selected whole-world checkpoint.
    pub(crate) roots: u64,
    /// Number of canonical page positions authenticated, including repeats.
    pub(crate) pages: u64,
    /// Number of valid logical page bytes authenticated.
    pub(crate) logical_bytes: u64,
    /// Bounded tree and page reads performed by complete verification.
    pub(crate) object_reads: u64,
}

impl NativeRamClosureCensus {
    /// Prints bounded logical verification counters for the actual fixture lane.
    pub(crate) fn print_evidence(&self, lane: &str) {
        // crucible-lint: allow direct-diagnostic -- the disposable native VM receipt binds these counters to its authenticated lane.
        println!("authenticated_ram_closure_lane={lane}");
        // crucible-lint: allow direct-diagnostic -- the receipt records complete roots verified under the original live Service.
        println!("authenticated_ram_closure_roots={}", self.roots);
        // crucible-lint: allow direct-diagnostic -- the receipt records bounded authenticated logical page positions, including repeats.
        println!("authenticated_ram_closure_pages={}", self.pages);
        // crucible-lint: allow direct-diagnostic -- the receipt records verified logical bytes without claiming physical allocation.
        println!(
            "authenticated_ram_closure_logical_bytes={}",
            self.logical_bytes
        );
        // crucible-lint: allow direct-diagnostic -- the receipt records bounded verification reads without claiming unique physical objects.
        println!(
            "authenticated_ram_closure_object_reads={}",
            self.object_reads
        );
    }
}

impl ExactCheckpointStore {
    /// Authenticates RAM closure visits using the configured actual catalog owner.
    ///
    /// Root metadata loans and reader claims are released as each root closes.
    /// The supplied supervisor retains the calling Service's original cap.
    ///
    /// # Errors
    /// Returns storage, integrity, resource admission, or original supervision
    /// failures without publishing an audit success or deleting any object.
    pub(crate) fn native_ram_closure_census(
        &self,
        checkpoint: ExactCheckpointId,
        supervisor: &HostOperationSupervisor,
    ) -> Result<NativeRamClosureCensus, ExactCheckpointStoreError> {
        let guard = supervisor.begin(HostOperationClass::CheckpointCapture)?;
        guard.wait_slice()?;
        let loaded = self.load_production_closure(checkpoint)?;
        guard.wait_slice()?;
        let mut census = NativeRamClosureCensus::default();
        for (ordinal, id) in loaded.paged_ram_root_ids().iter().enumerate() {
            let mut supervision_failure = None;
            let mut boundary = || match guard.wait_slice() {
                Ok(_) => Ok(()),
                Err(error) => {
                    supervision_failure = Some(error);
                    Err(RamStoreError::Canceled)
                }
            };
            let verify = (|| {
                let retention = self.ram_retention.acquire()?;
                let lease = retention.retain_root(*id)?;
                let (store, root) = loaded.open_paged_ram(ordinal, lease, &mut boundary)?;
                drop(retention);
                store
                    .verify(&root, &mut boundary)
                    .map_err(ExactCheckpointStoreError::from)
            })();
            if let Some(error) = supervision_failure {
                return Err(error.into());
            }
            let report = verify?;
            census.roots = census
                .roots
                .checked_add(1)
                .ok_or_else(|| invalid_root("native census root count overflow"))?;
            census.pages = census
                .pages
                .checked_add(report.pages)
                .ok_or_else(|| invalid_root("native census page count overflow"))?;
            census.logical_bytes = census
                .logical_bytes
                .checked_add(report.logical_bytes)
                .ok_or_else(|| invalid_root("native census page byte count overflow"))?;
            census.object_reads = census
                .object_reads
                .checked_add(report.object_visits)
                .ok_or_else(|| invalid_root("native census object read count overflow"))?;
        }
        guard.complete()?;
        Ok(census)
    }
}
