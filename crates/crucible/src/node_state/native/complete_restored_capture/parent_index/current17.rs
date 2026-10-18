//! Reads one signed ancestor's current17 header without creating a local archive.
//!
//! The owner preserves actual decode products and refusals. Its borrowed view
//! supplies only immutable parent facts; native MACs, Source history, parent
//! lineage and fresh live admission remain separate mandatory conjunctions.

use super::*;
use crate::node_contract::{HostSchedulingContinuationLimits, SavedRuntimeResult};
use crate::node_state::{native::core_decode_credit, schema};
use crucible_node_contract::{CaptureManifest, Id, canonical};
use std::thread::ThreadId;

#[path = "current17/terminal.rs"]
mod admission;
#[path = "current17/storage.rs"]
mod allocation;
#[path = "current17/join.rs"]
mod join;
#[path = "current17/projection.rs"]
mod projection;

use super::super::terminal::RestoredArchive17Current17HeaderWork as Work;
use admission::ParentHeaderTerminal17;

const COORDINATOR: usize = 0;
const HOST: usize = 1;
const ADMINISTRATIVE: usize = 2;

#[derive(Default)]
struct HeaderRecord17 {
    value: Option<Value>,
    canonical: Option<Vec<u8>>,
}

/// Retains this exact parent's header and every initialized refused product.
///
/// Completion describes the checked header only. It cannot supply a native
/// owner, Source read, archive receipt, restored context or current World.
pub(in super::super) struct ParentCurrent17HeaderAttempt {
    process: u32,
    thread: ThreadId,
    parent_index: Option<ContentRef>,
    parent_manifest: Option<ContentRef>,
    records: [HeaderRecord17; 3],
    checkpoint: Option<CoordinatorCommitmentCheckpoint17>,
    host: Option<HostSchedulingRestoredContinuationRecord17>,
    administrative: Option<RuntimeOriginalCaptureJournal>,
    maximum: usize,
    verified: bool,
}

/// Lends the checked ancestor's own cut and inventory without relabeling origin.
pub(in super::super) struct ParentCurrent17ArchiveData<'borrow, 'scope, 'archive> {
    parent: &'borrow ParentArchive17ReadScope<'scope, 'archive>,
    header: &'borrow ParentCurrent17HeaderAttempt,
}

impl ParentCurrent17HeaderAttempt {
    /// Reads a real current17 parent under separately admitted constructor keys.
    ///
    /// The caller's prior cache includes the inline output header. Every body is
    /// borrowed from the same actual parent Index; no selected top-generation
    /// key or graph is substituted for an ancestor's data.
    ///
    /// # Errors
    /// Refuses another format, repeated output or phase, exceeded depth/record/
    /// storage bounds, malformed header or changed full-reference correspondence.
    /// Initialized products remain in `output` on every refusal.
    pub(in super::super) fn read_into(
        parent: &ParentArchive17ReadScope<'_, '_>,
        current: &CompleteRestoredSettledArchiveValidation<'_>,
        source: RestoredArchive17SourceIndex,
        depth: usize,
        prior_cache: usize,
        additional: usize,
        output: &mut Option<Self>,
    ) -> Result<usize, StateError> {
        let terminal =
            ParentHeaderTerminal17::new_data(current, parent, source, depth, prior_cache)?;
        terminal.begin_data(Work::Header, 0)?;
        if output.is_some() {
            return Err(refused("current17 parent header attempt is already spent"));
        }
        let limits = parent.limits_data()?;
        if depth >= limits.state.maximum_dependency_depth {
            return Err(refused("current17 parent header exceeds dependency depth"));
        }
        let maximum = allocation::maximum_data(limits)?;
        let manifest = parent.manifest_data()?;
        if manifest.preservation_contract.as_str() != "source-owned.packet-complete-original-lineage/5"
            || manifest.coordinator_state_ref.media_type != crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA
        {
            return Err(refused("ancestor is not a current17 header family"));
        }
        let growth = NodeRuntime::capture_reference_storage(parent.index_reference_data()?)
            .map_err(schema)?
            .checked_add(
                NodeRuntime::capture_reference_storage(parent.manifest_reference_data()?)
                    .map_err(schema)?,
            )
            .ok_or_else(|| refused("current17 parent identity storage overflow"))?;
        allocation::admit_empty_data(parent, additional, growth, maximum)?;
        terminal.construct_data(growth, 0, Self::counter_scratch_data())?;
        *output = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            parent_index: None,
            parent_manifest: None,
            records: std::array::from_fn(|_| HeaderRecord17::default()),
            checkpoint: None,
            host: None,
            administrative: None,
            maximum,
            verified: false,
        });
        let owner = output
            .as_mut()
            .ok_or_else(|| refused("current17 parent header absent"))?;
        owner.parent_index = Some(parent.index_reference_data()?.clone());
        owner.parent_manifest = Some(parent.manifest_reference_data()?.clone());
        owner.authenticate_parent_data(parent)?;
        terminal.finish_data(owner, parent)?;

        owner.read_checkpoint_data(parent, &terminal, additional)?;
        owner.read_host_data(parent, &terminal, additional)?;
        owner.read_administrative_data(parent, &terminal, additional)?;
        owner.join_data(parent, &terminal, additional)?;
        owner.verified = true;
        terminal.completed_cache_data()
    }

    fn read_checkpoint_data(
        &mut self,
        parent: &ParentArchive17ReadScope<'_, '_>,
        terminal: &ParentHeaderTerminal17<'_, '_>,
        additional: usize,
    ) -> Result<(), StateError> {
        terminal.begin_data(Work::Coordinator, 0)?;
        let reference = &parent.manifest_data()?.coordinator_state_ref;
        let bytes = allocation::body_data(parent, reference)?;
        let (raw, canonical) = allocation::raw_storage_data(bytes, self.maximum)?;
        let typed =
            CoordinatorCommitmentCheckpoint17::prospective_storage_data(bytes.len(), self.maximum)
                .map_err(schema)?;
        let growth = allocation::sum_data(
            [raw, canonical, typed.retained_requested_bytes_data()],
            self.maximum,
        )?;
        let transient = allocation::sum_data(
            [
                raw,
                canonical,
                typed.maximum_simultaneous_transient_bytes_data(),
            ],
            self.maximum,
        )?;
        self.admit_data(parent, additional, growth, transient)?;
        terminal.construct_data(growth, transient, typed.counter_scratch_bytes_data())?;
        self.records[COORDINATOR].read_data(bytes, allocation::record_maximum_data(parent)?)?;
        self.checkpoint = Some(decode_record(
            bytes,
            allocation::record_maximum_data(parent)?,
        )?);
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| refused("parent coordinator absent"))?;
        let manifest = parent.manifest_data()?;
        checkpoint
            .authenticate_structure_data(
                &checkpoint.safe_point.runtime,
                manifest.cut,
                manifest.event_ordinal,
            )
            .map_err(schema)?;
        checkpoint.authenticate_prefix_data().map_err(schema)?;
        terminal.finish_data(self, parent)
    }

    fn read_host_data(
        &mut self,
        parent: &ParentArchive17ReadScope<'_, '_>,
        terminal: &ParentHeaderTerminal17<'_, '_>,
        additional: usize,
    ) -> Result<(), StateError> {
        terminal.begin_data(Work::Host, 0)?;
        let native = parent.current17_host_owner_data()?;
        let bytes = allocation::body_data(parent, &native.state)?;
        let limits = HostSchedulingContinuationLimits {
            maximum_record_bytes: allocation::record_maximum_data(parent)?,
            lineage: parent.lineage_limits_data(),
        };
        let (raw, canonical) = allocation::raw_storage_data(bytes, self.maximum)?;
        let typed =
            core_decode_credit::preflight_restored_host17(bytes, self.maximum).map_err(schema)?;
        let validation = core_decode_credit::validation_storage(&typed, limits).map_err(schema)?;
        let growth = allocation::sum_data(
            [raw, canonical, typed.total().map_err(schema)?],
            self.maximum,
        )?;
        let transient = allocation::sum_data(
            [raw, canonical, typed.total().map_err(schema)?, validation],
            self.maximum,
        )?;
        self.admit_data(parent, additional, growth, transient)?;
        terminal.construct_data(growth, transient, Self::counter_scratch_data())?;
        self.records[HOST].read_data(bytes, limits.maximum_record_bytes)?;
        self.host = Some(
            HostSchedulingRestoredContinuationRecord17::decode(bytes, limits).map_err(schema)?,
        );
        terminal.finish_data(self, parent)
    }

    fn read_administrative_data(
        &mut self,
        parent: &ParentArchive17ReadScope<'_, '_>,
        terminal: &ParentHeaderTerminal17<'_, '_>,
        additional: usize,
    ) -> Result<(), StateError> {
        terminal.begin_data(Work::Administrative, 0)?;
        let reference = parent.original_capture_journal_reference_data()?;
        if reference.media_type != crate::node_state::native::complete_original_index::JOURNAL_MEDIA
        {
            return Err(refused(
                "parent administrative full-reference media differs",
            ));
        }
        let bytes = allocation::body_data(parent, reference)?;
        let (raw, canonical) = allocation::raw_storage_data(bytes, self.maximum)?;
        let typed = core_decode_credit::preflight_archive(bytes, self.maximum).map_err(schema)?;
        let growth = allocation::sum_data(
            [raw, canonical, typed.total().map_err(schema)?],
            self.maximum,
        )?;
        self.admit_data(parent, additional, growth, growth)?;
        terminal.construct_data(growth, growth, Self::counter_scratch_data())?;
        self.records[ADMINISTRATIVE].read_data(bytes, allocation::record_maximum_data(parent)?)?;
        self.administrative = Some(decode_record(
            bytes,
            allocation::record_maximum_data(parent)?,
        )?);
        terminal.finish_data(self, parent)
    }

    fn authenticate_parent_data(
        &self,
        parent: &ParentArchive17ReadScope<'_, '_>,
    ) -> Result<(), StateError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || self.parent_index.as_ref() != Some(parent.index_reference_data()?)
            || self.parent_manifest.as_ref() != Some(parent.manifest_reference_data()?)
        {
            return Err(refused("current17 parent header origin differs"));
        }
        Ok(())
    }
}

impl HeaderRecord17 {
    fn read_data(&mut self, bytes: &[u8], maximum_record: usize) -> Result<(), StateError> {
        if self.value.is_some() || self.canonical.is_some() {
            return Err(refused("parent header raw record is already spent"));
        }
        self.value = Some(canonical::parse_json(bytes, maximum_record).map_err(schema)?);
        self.canonical = Some(
            canonical::canonical_json(
                self.value
                    .as_ref()
                    .ok_or_else(|| refused("parent header DOM absent"))?,
            )
            .map_err(schema)?,
        );
        if self.canonical.as_deref() != Some(bytes) {
            return Err(refused("parent header body is not canonical"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noncanonical_raw_input_keeps_its_partial_and_cannot_restart() {
        let mut record = HeaderRecord17::default();
        let input = br#" {"retained":"DATA"} "#;

        assert!(record.read_data(input, 4096).is_err());
        assert!(record.value.is_some());
        assert_eq!(
            record.canonical.as_deref(),
            Some(br#"{"retained":"DATA"}"#.as_slice())
        );
        assert!(record.read_data(br#"{}"#, 4096).is_err());
        assert_eq!(
            record.canonical.as_deref(),
            Some(br#"{"retained":"DATA"}"#.as_slice())
        );
    }

    #[test]
    fn refused_header_census_keeps_empty_spare_banks_and_exact_boundary() {
        // This is an incomplete private cache, never a checked parent or grant.
        let mut owner = ParentCurrent17HeaderAttempt {
            process: std::process::id(),
            thread: std::thread::current().id(),
            parent_index: None,
            parent_manifest: None,
            records: std::array::from_fn(|_| HeaderRecord17::default()),
            checkpoint: None,
            host: None,
            administrative: None,
            maximum: usize::MAX,
            verified: false,
        };
        let empty = owner.retained_requested_storage_data(usize::MAX).unwrap();
        owner.records[HOST].canonical = Some(Vec::with_capacity(113));
        let backing = owner.records[HOST].canonical.as_ref().unwrap().capacity();
        let expected = empty + backing;

        assert_eq!(
            owner.retained_requested_storage_data(expected).unwrap(),
            expected
        );
        assert!(owner.retained_requested_storage_data(expected - 1).is_err());
        assert!(!owner.verified);
    }
}
