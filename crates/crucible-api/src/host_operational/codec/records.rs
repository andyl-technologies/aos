//! Checked canonical field records for the host operational wire codec.
//!
//! Readers never allocate from an unchecked length or expose host-native clocks.
//! Writers validate every independently bounded roster before publication.

use super::super::*;
use super::{Result, SCHEMA, admit_bytes, admitted_vec, invalid};
use crucible_linux_resource::host_supervision::{
    HOST_OPERATION_CLASS_COUNT, HostEffectiveDeadline, HostOperationState,
};

pub(super) struct Writer {
    bytes: Vec<u8>,
    overflow: bool,
    written: usize,
    validation_only: bool,
}

impl Writer {
    pub(super) fn validation() -> Self {
        Self {
            bytes: Vec::new(),
            overflow: false,
            written: std::mem::size_of::<u32>(),
            validation_only: true,
        }
    }

    pub(super) fn bounded() -> Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(HOST_OPERATIONAL_MAX_BYTES)
            .map_err(|source| HostOperationalError::Admission {
                source: crucible::owned_decode::DecodeAdmissionError::new(source),
            })?;
        bytes.extend_from_slice(&SCHEMA.to_be_bytes());
        Ok(Self {
            bytes,
            overflow: false,
            written: std::mem::size_of::<u32>(),
            validation_only: false,
        })
    }

    pub(super) fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    pub(super) fn bytes(&mut self, value: &[u8]) {
        if self.overflow || value.len() > HOST_OPERATIONAL_MAX_BYTES.saturating_sub(self.written) {
            self.overflow = true;
            return;
        }
        self.written += value.len();
        if !self.validation_only {
            self.bytes.extend_from_slice(value);
        }
    }

    pub(super) fn optional_u64(&mut self, value: Option<u64>) {
        self.u8(u8::from(value.is_some()));
        if let Some(value) = value {
            self.u64(value);
        }
    }

    pub(super) fn duration(&mut self, value: Duration, allow_zero: bool) -> Result<()> {
        if !allow_zero && (value.is_zero() || !value.subsec_nanos().is_multiple_of(1_000_000)) {
            return Err(invalid("duration must be exact nonzero milliseconds"));
        }
        let mut millis =
            u64::try_from(value.as_millis()).map_err(|_| invalid("duration overflow"))?;
        if allow_zero && !value.subsec_nanos().is_multiple_of(1_000_000) {
            millis = millis
                .checked_add(1)
                .ok_or_else(|| invalid("remaining duration overflow"))?;
        }
        self.u64(millis);
        Ok(())
    }

    pub(super) fn optional_duration(
        &mut self,
        value: Option<Duration>,
        allow_zero: bool,
    ) -> Result<()> {
        self.u8(u8::from(value.is_some()));
        if let Some(value) = value {
            self.duration(value, allow_zero)?;
        }
        Ok(())
    }

    pub(super) fn target(&mut self, target: HostRamTarget) -> Result<()> {
        if target.owner_generation == 0 || target.arena_generation == 0 {
            return Err(invalid("zero ownership generation"));
        }
        self.bytes(&target.daemon_epoch);
        self.bytes(&target.owner_id);
        self.bytes(&target.node_id);
        self.u64(target.owner_generation);
        self.u64(target.arena_generation);
        self.u8(u8::from(target.retained_template));
        Ok(())
    }

    pub(super) fn outer_cap_target(&mut self, target: HostOuterCapTarget) -> Result<()> {
        if target.owner_generation == 0 {
            return Err(invalid("zero outer cap ownership generation"));
        }
        self.bytes(&target.daemon_epoch);
        match target.owner {
            HostOuterCapOwner::Execution(owner) => {
                self.u8(0);
                self.bytes(&owner);
            }
            HostOuterCapOwner::Service(owner) => {
                self.u8(1);
                self.bytes(&owner);
            }
        }
        self.u64(target.owner_generation);
        self.bytes(&target.cap_id);
        Ok(())
    }

    pub(super) fn policy(&mut self, policy: HostRamPolicy) -> Result<()> {
        if policy.eviction_preference > 100
            || policy.writeback_bytes_per_second == 0
            || policy.maximum_paging_io_in_flight == 0
        {
            return Err(invalid("invalid policy range"));
        }
        self.u8(policy.mode as u8);
        self.u64(policy.resident_target_bytes);
        self.u8(policy.eviction_preference);
        self.u64(policy.writeback_bytes_per_second);
        self.u32(policy.maximum_paging_io_in_flight);
        self.u8(u8::from(policy.prefetch_on_increase));
        for budget in policy.latency.classes {
            self.duration(budget.poll_interval, false)?;
            self.optional_duration(budget.progress_timeout, false)?;
            self.optional_duration(budget.total_timeout, false)?;
        }
        Ok(())
    }

    pub(super) fn resources(&mut self, resources: HostResourceVector) {
        for value in [
            resources.resident_peak_bytes,
            resources.backing_peak_bytes,
            resources.metadata_bytes,
            resources.staging_bytes,
            resources.paging_io_slots,
            resources.cpu_slots,
            resources.task_slots,
            resources.file_descriptors,
        ] {
            self.u64(value);
        }
    }

    pub(super) fn qualification(&mut self, value: HostRamQualification) -> Result<()> {
        let qualified = value.authenticated_pages
            || value.fault_safe_progress
            || value.bounded_execution_peak
            || value.hot_fork
            || value.lazy_restore
            || value.authenticated_transfer;
        if (qualified && value.evidence.is_none())
            || (value.bounded_execution_peak && !value.fault_safe_progress)
            || (value.fault_safe_progress && value.backend != HostRamBackend::StrictPager)
            || (value.backend == HostRamBackend::StrictPager
                && (!value.authenticated_pages
                    || !value.fault_safe_progress
                    || !value.bounded_execution_peak))
        {
            return Err(invalid("unproven or inconsistent backend qualification"));
        }
        self.u8(value.backend as u8);
        for flag in [
            value.authenticated_pages,
            value.fault_safe_progress,
            value.bounded_execution_peak,
            value.hot_fork,
            value.lazy_restore,
            value.authenticated_transfer,
        ] {
            self.u8(u8::from(flag));
        }
        self.u8(u8::from(value.evidence.is_some()));
        if let Some(evidence) = value.evidence {
            self.bytes(&evidence);
        }
        Ok(())
    }

    pub(super) fn state(&mut self, state: HostOperationState) {
        self.u8(match state {
            HostOperationState::Running => 0,
            HostOperationState::Completed => 1,
            HostOperationState::Expired => 2,
            HostOperationState::Canceled => 3,
        });
    }

    pub(super) fn outer_cap(&mut self, cap: &HostOuterCapStatus) -> Result<()> {
        self.u64(cap.revision);
        self.optional_duration(cap.allowance, false)?;
        self.optional_duration(cap.remaining, true)?;
        self.state(cap.state);
        Ok(())
    }

    pub(super) fn operation(&mut self, operation: &HostOperationStatus) -> Result<()> {
        self.u64(operation.operation_id);
        self.u8(operation.class as u8);
        self.u64(operation.started_policy_revision);
        self.u64(operation.applied_policy_revision);
        self.u64(operation.completed_work_units);
        self.u64(operation.outstanding_work_units);
        self.u8(operation.progress_kind as u8);
        self.state(operation.state);
        self.u8(u8::from(operation.effective_deadline.is_some()));
        if let Some(deadline) = &operation.effective_deadline {
            self.duration(deadline.remaining, true)?;
            if deadline.sources.is_empty() || deadline.sources.len() > 3 {
                return Err(invalid("invalid deadline source count"));
            }
            self.u8(deadline.sources.len() as u8);
            let mut previous = None;
            for source in &deadline.sources {
                let (tag, revision) = match source {
                    HostDeadlineSource::Progress(revision) => (0, *revision),
                    HostDeadlineSource::Total(revision) => (1, *revision),
                    HostDeadlineSource::Outer { revision, .. } => (2, *revision),
                };
                if previous.is_some_and(|previous| previous >= tag) {
                    return Err(invalid("unordered deadline sources"));
                }
                previous = Some(tag);
                self.u8(tag);
                if let HostDeadlineSource::Outer { cap_id, .. } = source {
                    self.bytes(cap_id);
                }
                self.u64(revision);
            }
        }
        Ok(())
    }

    pub(super) fn status(&mut self, status: &HostRamStatus) -> Result<()> {
        validate_placement(status)?;
        self.target(status.target)?;
        self.u64(status.observation_sequence);
        self.u64(status.policy_revision);
        self.u64(status.applied_policy_revision);
        self.u64(status.reservation_revision);
        self.policy(status.requested_policy)?;
        self.policy(status.applied_policy)?;
        self.u8(u8::from(status.placement_receipt.is_some()));
        if let Some(receipt) = status.placement_receipt {
            self.u8(receipt.mode as u8);
            for value in [
                receipt.policy_revision,
                receipt.topology_generation,
                receipt.placement_epoch,
                receipt.locked_bytes,
                receipt.disk_preserved_logical_pages,
                receipt.disk_preserved_logical_bytes,
                receipt.ram_write_generation_at_cut,
            ] {
                self.u64(value);
            }
        }
        self.u64(status.effective_resident_target_bytes);
        self.u64(status.effective_floor_bytes);
        if status.limitation_reasons.len() > HOST_OPERATIONAL_MAX_REASONS {
            return Err(invalid("too many limitation reasons"));
        }
        self.u32(status.limitation_reasons.len() as u32);
        for reason in &status.limitation_reasons {
            if reason.is_empty() || reason.len() > 128 || reason.chars().any(char::is_control) {
                return Err(invalid("invalid limitation reason"));
            }
            self.u32(reason.len() as u32);
            self.bytes(reason.as_bytes());
        }
        self.u8(u8::from(status.measurements_available));
        self.u8(u8::from(status.activity.is_some()));
        if let Some(activity) = status.activity {
            for value in [
                activity.successful_missing_installs,
                activity.successful_missing_read_installs,
                activity.successful_missing_write_installs,
                activity.write_protect_transitions,
                activity.preservation_reads,
                activity.preservation_writes,
                activity.physical_discards,
                activity.prefetched_pages,
            ] {
                self.u64(value);
            }
        }
        for value in [
            status.private_resident_bytes,
            status.shared_resident_bytes_observed,
            status.preserved_backing_bytes,
            status.private_dirty_bytes,
            status.writeback_pending_bytes,
        ] {
            if !status.measurements_available && value != 0 {
                return Err(invalid(
                    "unavailable physical measurement must not carry a counter",
                ));
            }
            self.u64(value);
        }
        self.u8(status.convergence as u8);
        self.u64(status.accepted_unique_update_count);
        self.u64(status.remaining_unique_update_capacity);
        self.u64(status.history_disk_bytes);
        self.optional_u64(status.transition);
        self.resources(status.admitted_resources);
        if status.outer_caps.len() > HOST_OPERATIONAL_MAX_OUTER_CAPS {
            return Err(invalid("too many outer caps"));
        }
        self.u32(status.outer_caps.len() as u32);
        let mut previous = None;
        for cap in &status.outer_caps {
            if previous.is_some_and(|target| target >= cap.target) {
                return Err(invalid("unordered outer cap owners"));
            }
            previous = Some(cap.target);
            self.outer_cap_target(cap.target)?;
            self.u8(cap.class as u8);
            self.outer_cap(&cap.status)?;
        }
        if status.outstanding_operations.len() > HOST_OPERATIONAL_MAX_OPERATIONS {
            return Err(invalid("too many outstanding operations"));
        }
        self.u32(status.outstanding_operations.len() as u32);
        let mut previous = 0;
        for operation in &status.outstanding_operations {
            if operation.operation_id <= previous {
                return Err(invalid("unordered operation identities"));
            }
            previous = operation.operation_id;
            if let Some(deadline) = &operation.effective_deadline {
                for source in &deadline.sources {
                    if let HostDeadlineSource::Outer { cap_id, revision } = source
                        && !status.outer_caps.iter().any(|cap| {
                            cap.target.cap_id == *cap_id && cap.status.revision == *revision
                        })
                    {
                        return Err(invalid(
                            "limiting cap source is absent from coherent status",
                        ));
                    }
                }
            }
            self.operation(operation)?;
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Result<Vec<u8>> {
        if self.overflow {
            return Err(invalid("message size limit"));
        }
        Ok(self.bytes)
    }
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > HOST_OPERATIONAL_MAX_BYTES {
            return Err(invalid("message size limit"));
        }
        let mut reader = Self { bytes, offset: 0 };
        if reader.u32()? != SCHEMA {
            return Err(invalid("unsupported schema"));
        }
        Ok(reader)
    }

    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| invalid("length overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated message"))?;
        self.offset = end;
        Ok(bytes)
    }

    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid("invalid fixed-width value"))
    }

    pub(super) fn u8(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }

    pub(super) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    pub(super) fn boolean(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("unknown boolean/optional tag")),
        }
    }

    pub(super) fn optional_u64(&mut self) -> Result<Option<u64>> {
        if self.boolean()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }

    pub(super) fn duration(&mut self, allow_zero: bool) -> Result<Duration> {
        let millis = self.u64()?;
        if !allow_zero && millis == 0 {
            return Err(invalid("zero configured duration"));
        }
        Ok(Duration::from_millis(millis))
    }

    pub(super) fn optional_duration(&mut self, allow_zero: bool) -> Result<Option<Duration>> {
        if self.boolean()? {
            Ok(Some(self.duration(allow_zero)?))
        } else {
            Ok(None)
        }
    }

    pub(super) fn target(&mut self) -> Result<HostRamTarget> {
        let target = HostRamTarget {
            daemon_epoch: self.fixed()?,
            owner_id: self.fixed()?,
            node_id: self.fixed()?,
            owner_generation: self.u64()?,
            arena_generation: self.u64()?,
            retained_template: self.boolean()?,
        };
        if target.owner_generation == 0 || target.arena_generation == 0 {
            return Err(invalid("zero ownership generation"));
        }
        Ok(target)
    }

    pub(super) fn outer_cap_target(&mut self) -> Result<HostOuterCapTarget> {
        let daemon_epoch = self.fixed()?;
        let owner = match self.u8()? {
            0 => HostOuterCapOwner::Execution(self.fixed()?),
            1 => HostOuterCapOwner::Service(self.fixed()?),
            _ => return Err(invalid("unknown outer cap owner namespace")),
        };
        let owner_generation = self.u64()?;
        if owner_generation == 0 {
            return Err(invalid("zero outer cap ownership generation"));
        }
        Ok(HostOuterCapTarget {
            daemon_epoch,
            owner,
            owner_generation,
            cap_id: self.fixed()?,
        })
    }

    pub(super) fn policy(&mut self) -> Result<HostRamPolicy> {
        let mode = match self.u8()? {
            0 => HostRamMode::Managed,
            1 => HostRamMode::DiskOriented,
            2 => HostRamMode::ResidentRequired,
            _ => return Err(invalid("unknown residency mode")),
        };
        let resident_target_bytes = self.u64()?;
        let eviction_preference = self.u8()?;
        let writeback_bytes_per_second = self.u64()?;
        let maximum_paging_io_in_flight = self.u32()?;
        let prefetch_on_increase = self.boolean()?;
        let mut classes = [HostOperationBudget::unlimited_quantum(); HOST_OPERATION_CLASS_COUNT];
        for budget in &mut classes {
            *budget = HostOperationBudget {
                poll_interval: self.duration(false)?,
                progress_timeout: self.optional_duration(false)?,
                total_timeout: self.optional_duration(false)?,
            };
        }
        if eviction_preference > 100
            || writeback_bytes_per_second == 0
            || maximum_paging_io_in_flight == 0
        {
            return Err(invalid("invalid policy range"));
        }
        Ok(HostRamPolicy {
            mode,
            resident_target_bytes,
            eviction_preference,
            writeback_bytes_per_second,
            maximum_paging_io_in_flight,
            prefetch_on_increase,
            latency: HostOperationBudgets { classes },
        })
    }

    pub(super) fn resources(&mut self) -> Result<HostResourceVector> {
        Ok(HostResourceVector {
            resident_peak_bytes: self.u64()?,
            backing_peak_bytes: self.u64()?,
            metadata_bytes: self.u64()?,
            staging_bytes: self.u64()?,
            paging_io_slots: self.u64()?,
            cpu_slots: self.u64()?,
            task_slots: self.u64()?,
            file_descriptors: self.u64()?,
        })
    }

    pub(super) fn qualification(&mut self) -> Result<HostRamQualification> {
        let backend = match self.u8()? {
            0 => HostRamBackend::FullyResident,
            1 => HostRamBackend::KernelSwapMeasurement,
            2 => HostRamBackend::PausedPager,
            3 => HostRamBackend::StrictPager,
            _ => return Err(invalid("unknown RAM backend")),
        };
        Ok(HostRamQualification {
            backend,
            authenticated_pages: self.boolean()?,
            fault_safe_progress: self.boolean()?,
            bounded_execution_peak: self.boolean()?,
            hot_fork: self.boolean()?,
            lazy_restore: self.boolean()?,
            authenticated_transfer: self.boolean()?,
            evidence: if self.boolean()? {
                Some(self.fixed()?)
            } else {
                None
            },
        })
    }

    pub(super) fn state(&mut self) -> Result<HostOperationState> {
        match self.u8()? {
            0 => Ok(HostOperationState::Running),
            1 => Ok(HostOperationState::Completed),
            2 => Ok(HostOperationState::Expired),
            3 => Ok(HostOperationState::Canceled),
            _ => Err(invalid("unknown operation state")),
        }
    }

    pub(super) fn disposition(&mut self) -> Result<HostOperationalDisposition> {
        match self.u8()? {
            0 => Ok(HostOperationalDisposition::Accepted),
            1 => Ok(HostOperationalDisposition::Replayed),
            2 => Ok(HostOperationalDisposition::RevisionConflict),
            3 => Ok(HostOperationalDisposition::NotCurrent),
            4 => Ok(HostOperationalDisposition::Unsupported),
            5 => Ok(HostOperationalDisposition::AdmissionRefused),
            6 => Ok(HostOperationalDisposition::HistoryCapacityRefused),
            7 => Ok(HostOperationalDisposition::RateLimited),
            8 => Ok(HostOperationalDisposition::Unavailable),
            9 => Ok(HostOperationalDisposition::Terminal),
            _ => Err(invalid("unknown update disposition")),
        }
    }

    pub(super) fn outer_cap(&mut self) -> Result<HostOuterCapStatus> {
        Ok(HostOuterCapStatus {
            revision: self.u64()?,
            allowance: self.optional_duration(false)?,
            remaining: self.optional_duration(true)?,
            state: self.state()?,
        })
    }

    pub(super) fn operation(&mut self) -> Result<HostOperationStatus> {
        let operation_id = self.u64()?;
        let class = HostOperationClass::ALL
            .get(self.u8()? as usize)
            .copied()
            .ok_or_else(|| invalid("unknown operation class"))?;
        let started_policy_revision = self.u64()?;
        let applied_policy_revision = self.u64()?;
        let completed_work_units = self.u64()?;
        let outstanding_work_units = self.u64()?;
        let progress_kind = match self.u8()? {
            0 => HostProgressKind::ValidatedPhase,
            1 => HostProgressKind::GuestBoundary,
            2 => HostProgressKind::AuthenticatedPage,
            3 => HostProgressKind::PreservedPage,
            4 => HostProgressKind::MerkleLeaf,
            5 => HostProgressKind::DurableObject,
            6 => HostProgressKind::ForkBarrier,
            _ => return Err(invalid("unknown operation progress kind")),
        };
        let state = self.state()?;
        let effective_deadline = if self.boolean()? {
            let remaining = self.duration(true)?;
            let count = self.u8()?;
            if count == 0 || count > 3 {
                return Err(invalid("invalid deadline source count"));
            }
            let mut sources = admitted_vec(count as usize)?;
            for _ in 0..count {
                let tag = self.u8()?;
                let cap_id = if tag == 2 { Some(self.fixed()?) } else { None };
                let revision = self.u64()?;
                sources.push(match tag {
                    0 => HostDeadlineSource::Progress(revision),
                    1 => HostDeadlineSource::Total(revision),
                    2 => HostDeadlineSource::Outer {
                        cap_id: cap_id.ok_or_else(|| invalid("missing outer cap identity"))?,
                        revision,
                    },
                    _ => return Err(invalid("unknown deadline source")),
                });
            }
            Some(HostEffectiveDeadline { remaining, sources })
        } else {
            None
        };
        Ok(HostOperationStatus {
            operation_id,
            class,
            started_policy_revision,
            applied_policy_revision,
            completed_work_units,
            outstanding_work_units,
            progress_kind,
            state,
            effective_deadline,
        })
    }

    pub(super) fn count(&mut self, maximum: usize) -> Result<usize> {
        let count = self.u32()? as usize;
        if count > maximum {
            return Err(invalid("roster count limit"));
        }
        Ok(count)
    }

    pub(super) fn status(&mut self) -> Result<HostRamStatus> {
        let target = self.target()?;
        let observation_sequence = self.u64()?;
        let policy_revision = self.u64()?;
        let applied_policy_revision = self.u64()?;
        let reservation_revision = self.u64()?;
        let requested_policy = self.policy()?;
        let applied_policy = self.policy()?;
        let placement_receipt = if self.boolean()? {
            let mode = match self.u8()? {
                1 => HostRamMode::DiskOriented,
                2 => HostRamMode::ResidentRequired,
                _ => return Err(invalid("unknown strict placement mode")),
            };
            Some(HostRamPlacementReceipt {
                mode,
                policy_revision: self.u64()?,
                topology_generation: self.u64()?,
                placement_epoch: self.u64()?,
                locked_bytes: self.u64()?,
                disk_preserved_logical_pages: self.u64()?,
                disk_preserved_logical_bytes: self.u64()?,
                ram_write_generation_at_cut: self.u64()?,
            })
        } else {
            None
        };
        let effective_resident_target_bytes = self.u64()?;
        let effective_floor_bytes = self.u64()?;
        let count = self.count(HOST_OPERATIONAL_MAX_REASONS)?;
        let mut limitation_reasons = admitted_vec(count)?;
        for _ in 0..count {
            let length = self.count(128)?;
            let reason = std::str::from_utf8(self.take(length)?)
                .map_err(|_| invalid("invalid UTF-8 reason"))?;
            if reason.is_empty() || reason.chars().any(char::is_control) {
                return Err(invalid("invalid limitation reason"));
            }
            admit_bytes(length as u64)?;
            let mut owned = String::new();
            owned
                .try_reserve_exact(length)
                .map_err(|source| HostOperationalError::Admission {
                    source: crucible::owned_decode::DecodeAdmissionError::new(source),
                })?;
            owned.push_str(reason);
            limitation_reasons.push(owned);
        }
        let measurements_available = self.boolean()?;
        let activity = if self.boolean()? {
            Some(HostRamActivity {
                successful_missing_installs: self.u64()?,
                successful_missing_read_installs: self.u64()?,
                successful_missing_write_installs: self.u64()?,
                write_protect_transitions: self.u64()?,
                preservation_reads: self.u64()?,
                preservation_writes: self.u64()?,
                physical_discards: self.u64()?,
                prefetched_pages: self.u64()?,
            })
        } else {
            None
        };
        let private_resident_bytes = self.u64()?;
        let shared_resident_bytes_observed = self.u64()?;
        let preserved_backing_bytes = self.u64()?;
        let private_dirty_bytes = self.u64()?;
        let writeback_pending_bytes = self.u64()?;
        let convergence = match self.u8()? {
            0 => HostRamConvergence::Stable,
            1 => HostRamConvergence::Applying,
            2 => HostRamConvergence::Evicting,
            3 => HostRamConvergence::Prefetching,
            4 => HostRamConvergence::Blocked,
            5 => HostRamConvergence::Failed,
            6 => HostRamConvergence::Quarantined,
            _ => return Err(invalid("unknown convergence state")),
        };
        let accepted_unique_update_count = self.u64()?;
        let remaining_unique_update_capacity = self.u64()?;
        let history_disk_bytes = self.u64()?;
        let transition = self.optional_u64()?;
        let admitted_resources = self.resources()?;
        let count = self.count(HOST_OPERATIONAL_MAX_OUTER_CAPS)?;
        let mut outer_caps = admitted_vec(count)?;
        for _ in 0..count {
            let target = self.outer_cap_target()?;
            let class = match self.u8()? {
                0 => HostOuterCapClass::Assignment,
                1 => HostOuterCapClass::Preparation,
                2 => HostOuterCapClass::ServiceShutdown,
                3 => HostOuterCapClass::Operator,
                _ => return Err(invalid("unknown outer cap class")),
            };
            outer_caps.push(HostOuterCapObservation {
                target,
                class,
                status: self.outer_cap()?,
            });
        }
        let count = self.count(HOST_OPERATIONAL_MAX_OPERATIONS)?;
        let mut outstanding_operations = admitted_vec(count)?;
        for _ in 0..count {
            outstanding_operations.push(self.operation()?);
        }
        let status = HostRamStatus {
            target,
            observation_sequence,
            policy_revision,
            applied_policy_revision,
            reservation_revision,
            requested_policy,
            applied_policy,
            placement_receipt,
            effective_resident_target_bytes,
            effective_floor_bytes,
            limitation_reasons,
            measurements_available,
            activity,
            private_resident_bytes,
            shared_resident_bytes_observed,
            preserved_backing_bytes,
            private_dirty_bytes,
            writeback_pending_bytes,
            convergence,
            accepted_unique_update_count,
            remaining_unique_update_capacity,
            history_disk_bytes,
            transition,
            admitted_resources,
            outer_caps,
            outstanding_operations,
        };
        validate_placement(&status)?;
        Ok(status)
    }

    pub(super) fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(invalid("trailing message bytes"));
        }
        Ok(())
    }
}

fn validate_placement(status: &HostRamStatus) -> Result<()> {
    if status.applied_policy_revision > status.policy_revision {
        return Err(invalid("applied placement exceeds accepted revision"));
    }
    let Some(receipt) = status.placement_receipt else {
        return Ok(());
    };
    if receipt.policy_revision == 0
        || receipt.policy_revision != status.applied_policy_revision
        || receipt.mode != status.applied_policy.mode
        || receipt.topology_generation == 0
        || receipt.placement_epoch == 0
    {
        return Err(invalid("strict placement receipt identity mismatch"));
    }
    let valid = match receipt.mode {
        HostRamMode::Managed => false,
        HostRamMode::ResidentRequired => {
            receipt.locked_bytes > 0
                && receipt.locked_bytes.is_multiple_of(4096)
                && receipt.disk_preserved_logical_pages == 0
                && receipt.disk_preserved_logical_bytes == 0
                && receipt.ram_write_generation_at_cut == 0
        }
        HostRamMode::DiskOriented => {
            let minimum = receipt.disk_preserved_logical_bytes.div_ceil(4096);
            receipt.locked_bytes == 0
                && receipt.disk_preserved_logical_bytes > 0
                && receipt.disk_preserved_logical_pages >= minimum
                && receipt.disk_preserved_logical_pages <= minimum.saturating_add(4095)
        }
    };
    if !valid {
        return Err(invalid("invalid strict placement guarantee"));
    }
    Ok(())
}
