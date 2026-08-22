//! Capability-negotiated facade over the local executor supervisor.
//!
//! Immutable compatibility and configured ceilings are supplied once at
//! construction. Volatile capacity is recomputed from exact active
//! reservations for each bounded `WatchCapacity` poll.

use std::collections::BTreeSet;

use crucible_campaign::{
    CampaignCodecError, CancelAttemptExecutionRequest, CancelAttemptExecutionResponse,
    CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse,
    ExecutorCapabilityService, ExecutorCapacityReport, ExecutorControlService, ExecutorDescription,
    ExecutorMaterializationLocality, ExecutorResumeService, ExecutorService, ExecutorStatusService,
    GetAttemptExecutionRequest, GetAttemptExecutionResponse, ResumeAttemptExecutionRequest,
    ResumeAttemptExecutionResponse, SubmitAttemptRequest, SubmitAttemptResponse,
    WatchExecutorCapacityRequest,
};

use crate::{
    AssignmentLedger, AttemptAdmissionValidator, LocalExecutorError, LocalExecutorSupervisor,
};

/// Capability-negotiated service over one sole-writer local supervisor.
pub struct LocalExecutorCapabilityService<L, V> {
    supervisor: LocalExecutorSupervisor<L, V>,
    description: ExecutorDescription,
    sequence: u64,
    locality: BTreeSet<ExecutorMaterializationLocality>,
}

impl<L, V> LocalExecutorCapabilityService<L, V> {
    /// Binds immutable advertised facts to the exact supervisor configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the daemon epoch, slot ceiling, or
    /// aggregate CPU/memory/disk/quanta ceilings differ. This fail-closed check
    /// prevents placement from relying on a capability the supervisor does not
    /// enforce.
    pub fn new(
        supervisor: LocalExecutorSupervisor<L, V>,
        description: ExecutorDescription,
    ) -> Result<Self, CampaignCodecError> {
        validate_description(&supervisor, &description)?;
        Ok(Self {
            supervisor,
            description,
            sequence: 0,
            locality: BTreeSet::new(),
        })
    }

    /// Returns the underlying supervisor.
    #[must_use]
    pub const fn supervisor(&self) -> &LocalExecutorSupervisor<L, V> {
        &self.supervisor
    }

    /// Returns mutable access to the underlying supervisor actor state.
    #[must_use]
    pub const fn supervisor_mut(&mut self) -> &mut LocalExecutorSupervisor<L, V> {
        &mut self.supervisor
    }

    /// Returns the immutable executor description.
    #[must_use]
    pub const fn description(&self) -> &ExecutorDescription {
        &self.description
    }

    /// Replaces bounded coarse materialization locality for future reports.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the set is oversized or includes a
    /// materialization tier not present in the immutable capability set.
    pub fn replace_locality(
        &mut self,
        locality: BTreeSet<ExecutorMaterializationLocality>,
    ) -> Result<(), CampaignCodecError> {
        let availability = self.supervisor.availability();
        let report = ExecutorCapacityReport::new(
            self.supervisor.daemon_epoch(),
            self.description.capabilities().digest(),
            self.sequence.max(1),
            availability.slots(),
            availability.vcpus(),
            availability.resident_bytes(),
            availability.disk_bytes(),
            locality.clone(),
        )?;
        report.validate_for(&self.description, None)?;
        self.locality = locality;
        Ok(())
    }

    /// Consumes the facade and returns the underlying supervisor.
    #[must_use]
    pub fn into_supervisor(self) -> LocalExecutorSupervisor<L, V> {
        self.supervisor
    }
}

impl<L, V> ExecutorService for LocalExecutorCapabilityService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    type Error = LocalExecutorError<L::Error>;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.supervisor.submit_attempt(request)
    }
}

impl<L, V> ExecutorStatusService for LocalExecutorCapabilityService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.supervisor.get_attempt_execution(request)
    }
}

impl<L, V> ExecutorControlService for LocalExecutorCapabilityService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        self.supervisor.checkpoint_attempt_execution(request)
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        self.supervisor.cancel_attempt_execution(request)
    }
}

impl<L, V> ExecutorResumeService for LocalExecutorCapabilityService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        self.supervisor.resume_attempt_execution(request)
    }
}

impl<L, V> ExecutorCapabilityService for LocalExecutorCapabilityService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error> {
        Ok(self.description.clone())
    }

    fn watch_capacity(
        &mut self,
        request: &WatchExecutorCapacityRequest,
    ) -> Result<ExecutorCapacityReport, Self::Error> {
        validate_request(request, &self.description)?;
        if request
            .after_sequence()
            .is_some_and(|after| after > self.sequence)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "watch capacity cursor is ahead of executor sequence",
            }
            .into());
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "executor capacity sequence is exhausted",
            })?;
        let availability = self.supervisor.availability();
        let report = ExecutorCapacityReport::new(
            self.supervisor.daemon_epoch(),
            self.description.capabilities().digest(),
            sequence,
            availability.slots(),
            availability.vcpus(),
            availability.resident_bytes(),
            availability.disk_bytes(),
            self.locality.clone(),
        )?;
        report.validate_for(&self.description, request.after_sequence())?;
        self.sequence = sequence;
        Ok(report)
    }
}

fn validate_description<L, V>(
    supervisor: &LocalExecutorSupervisor<L, V>,
    description: &ExecutorDescription,
) -> Result<(), CampaignCodecError> {
    if supervisor.daemon_epoch() != description.daemon_epoch() {
        return Err(CampaignCodecError::InvalidValue {
            reason: "executor description daemon epoch does not match supervisor",
        });
    }
    let configured = supervisor.capacity();
    let capabilities = description.capabilities();
    let advertised = capabilities.resource_ceiling();
    if capabilities.maximum_slots() != configured.maximum_concurrent_executions()
        || advertised.maximum_vcpus() != configured.maximum_vcpus()
        || advertised.maximum_resident_bytes() != configured.maximum_resident_bytes()
        || advertised.maximum_disk_bytes() != configured.maximum_disk_bytes()
        || advertised.maximum_execution_quanta() != configured.maximum_execution_quanta()
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "executor description ceilings do not match supervisor",
        });
    }
    Ok(())
}

fn validate_request(
    request: &WatchExecutorCapacityRequest,
    description: &ExecutorDescription,
) -> Result<(), CampaignCodecError> {
    if request.daemon_epoch() != description.daemon_epoch() {
        return Err(CampaignCodecError::InvalidValue {
            reason: "watch capacity request daemon epoch is stale",
        });
    }
    if request.capability_digest() != description.capabilities().digest() {
        return Err(CampaignCodecError::InvalidValue {
            reason: "watch capacity request capability digest is stale",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::{BTreeMap, BTreeSet};

    use crucible_campaign::{
        AssignmentId, AttemptId, AttemptResourceLimits, CampaignHash, CampaignLineageId,
        DaemonEpoch, ExecutionRetentionIntent, ExecutorCapabilitySet, ExecutorClient,
        ExecutorCompatibilityProfile, ExecutorMaterializationCapability, SubmitAttemptDisposition,
        SubmitAttemptRequest,
    };

    use super::*;
    use crate::{AllowAllAttemptAdmission, ExecutorCapacity, MemoryAssignmentLedger};

    #[test]
    fn capacity_reports_track_exact_supervisor_reservations() {
        let epoch = DaemonEpoch::from_bytes([0x31; 16]).expect("epoch");
        let supervisor = LocalExecutorSupervisor::new(
            MemoryAssignmentLedger::default(),
            AllowAllAttemptAdmission,
            epoch,
            capacity(),
        );
        let mut client = ExecutorClient::new(
            LocalExecutorCapabilityService::new(supervisor, description(epoch))
                .expect("matching capability facade"),
        );
        let described = client.describe_executor().expect("description");
        let initial = client
            .watch_capacity(&described, None)
            .expect("initial capacity");
        assert_eq!(initial.sequence(), 1);
        assert_eq!(initial.available_slots(), 2);
        assert_eq!(initial.available_vcpus(), 4);

        let accepted = client
            .submit_attempt(&request(epoch, 0x41))
            .expect("accepted assignment");
        assert!(matches!(
            accepted.disposition(),
            SubmitAttemptDisposition::Accepted { .. }
        ));
        let reserved = client
            .watch_capacity(&described, Some(initial.sequence()))
            .expect("reserved capacity");
        assert_eq!(reserved.sequence(), 2);
        assert_eq!(reserved.available_slots(), 1);
        assert_eq!(reserved.available_vcpus(), 3);
        assert_eq!(reserved.available_resident_bytes(), 3072);
        assert_eq!(reserved.available_disk_bytes(), 6144);
    }

    #[test]
    fn lagging_watchers_never_reuse_a_sequence_for_changed_capacity() {
        let epoch = DaemonEpoch::from_bytes([0x33; 16]).expect("epoch");
        let supervisor = LocalExecutorSupervisor::new(
            MemoryAssignmentLedger::default(),
            AllowAllAttemptAdmission,
            epoch,
            capacity(),
        );
        let mut client = ExecutorClient::new(
            LocalExecutorCapabilityService::new(supervisor, description(epoch))
                .expect("matching capability facade"),
        );
        let described = client.describe_executor().expect("description");
        let initial = client
            .watch_capacity(&described, None)
            .expect("initial capacity");

        client
            .submit_attempt(&request(epoch, 0x42))
            .expect("first reservation");
        let first_client = client
            .watch_capacity(&described, Some(initial.sequence()))
            .expect("first client poll");
        assert_eq!(first_client.sequence(), 2);
        assert_eq!(first_client.available_slots(), 1);

        client
            .submit_attempt(&request(epoch, 0x43))
            .expect("second reservation");
        let lagging_client = client
            .watch_capacity(&described, Some(initial.sequence()))
            .expect("lagging client poll");
        assert_eq!(lagging_client.sequence(), 3);
        assert_eq!(lagging_client.available_slots(), 0);
        assert_ne!(lagging_client, first_client);

        let current_client = client
            .watch_capacity(&described, Some(lagging_client.sequence()))
            .expect("current client poll");
        assert_eq!(current_client.sequence(), 4);
        assert_eq!(current_client.available_slots(), 0);
    }

    #[test]
    fn capability_facade_rejects_mismatched_advertisement() {
        let epoch = DaemonEpoch::from_bytes([0x32; 16]).expect("epoch");
        let supervisor = LocalExecutorSupervisor::new(
            MemoryAssignmentLedger::default(),
            AllowAllAttemptAdmission,
            epoch,
            ExecutorCapacity::new(1, 4, 4096, 8192, 64).expect("mismatched capacity"),
        );
        assert!(matches!(
            LocalExecutorCapabilityService::new(supervisor, description(epoch)),
            Err(CampaignCodecError::InvalidValue {
                reason: "executor description ceilings do not match supervisor"
            })
        ));
    }

    fn capacity() -> ExecutorCapacity {
        ExecutorCapacity::new(2, 4, 4096, 8192, 64).expect("capacity")
    }

    fn description(epoch: DaemonEpoch) -> ExecutorDescription {
        let compatibility = ExecutorCompatibilityProfile::new(
            "crucible-v1",
            "qemu-build-v1",
            BTreeMap::from([(String::from("control"), 1)]),
            1,
            1,
        )
        .expect("compatibility");
        let capabilities = ExecutorCapabilitySet::new(
            compatibility,
            "x86_64",
            BTreeSet::from([String::from("deterministic-tcg-v1")]),
            BTreeSet::from([
                ExecutorMaterializationCapability::ThinReplay,
                ExecutorMaterializationCapability::ExactRestore,
            ]),
            2,
            AttemptResourceLimits::new(4, 4096, 8192, 64).expect("resource ceiling"),
            BTreeSet::from([CampaignHash::derive(
                "crucible.test.local-executor-namespace.v1",
                b"local",
            )]),
        )
        .expect("capabilities");
        ExecutorDescription::new(epoch, capabilities).expect("description")
    }

    fn request(epoch: DaemonEpoch, byte: u8) -> SubmitAttemptRequest {
        SubmitAttemptRequest::new(
            AssignmentId::from_bytes([byte; 16]).expect("assignment"),
            epoch,
            CampaignLineageId::parse(&typed_id(
                "crucible.campaign.lineage",
                "campaign-fact",
                0x51,
            ))
            .expect("lineage"),
            AttemptId::parse(&typed_id(
                "crucible.campaign.attempt",
                "campaign-fact",
                byte,
            ))
            .expect("attempt"),
            AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
            ExecutionRetentionIntent::Discard,
        )
        .expect("request")
    }

    fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
        format!("{tag}@{kind}.1.{}", encode_hex(&[byte; 32]))
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }
}
