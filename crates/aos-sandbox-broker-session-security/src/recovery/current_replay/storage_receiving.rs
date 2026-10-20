//! Prepays canonical Session validation and retains genuine native failures.
//!
//! Exclusive pure format scratch may drop after refusal. Its full debit and
//! first typed returned error stay. Native endpoint/peer/metadata originals
//! remain here; existing pending/CAS/native floor owners retain effect ambiguity.

use super::*;
use aos_sandbox::journal::{JournalError, ProtectedJournalPreopenReplayExtentV1};
use aos_sandbox_core::{ResourceDimension, ResourceVector};
use std::mem::size_of;

#[derive(Default)]
pub(in crate::recovery) struct StorageSessionReplayArchiveV3 {
    failed: Option<Box<ValidationOriginal>>,
    demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    funding: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    closed: Option<BrokerSessionSecurityError>,
}

#[derive(Default)]
struct ValidationOriginal {
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    context: journal::CurrentContextOriginalsV1,
    peer: journal::CurrentPeerOriginalsV1,
    outcome: journal::OutcomeCurrentOriginalsV1,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
}

#[derive(Clone, Copy)]
enum Purpose { Context, Peer, Outcome, Read, Replay }

impl ValidationOriginal {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        failure(&self.metadata).or_else(|| failure(&self.extent))
            .or_else(|| failure(&self.demand)).or_else(|| self.context.failure())
            .or_else(|| self.peer.failure()).or_else(|| self.outcome.failure())
            .or_else(|| failure(&self.returned))
    }

    fn demand(&self, purpose: Purpose) -> Result<ResourceVector, BrokerSessionSecurityError> {
        let endpoint = crate::endpoint::RetainedEndpointRevalidationOriginalV1::receiving_demand_v1()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (memory, endpoints) = match purpose {
            Purpose::Context => (journal::CurrentContextOriginalsV1::receiving_footprint_v1()
                .ok_or(BrokerSessionSecurityError::Currentness)?.0, 2),
            Purpose::Peer => (journal::CurrentPeerOriginalsV1::receiving_footprint_v1()
                .ok_or(BrokerSessionSecurityError::Currentness)?.0, 2),
            Purpose::Outcome => (journal::OutcomeCurrentOriginalsV1::receiving_footprint_v1()
                .ok_or(BrokerSessionSecurityError::Currentness)?.0, 6),
            Purpose::Read | Purpose::Replay => (0, 0),
        };
        let mut demand = ResourceVector::ZERO.with(ResourceDimension::MemoryBytes,
            u64::try_from(memory).map_err(|_| BrokerSessionSecurityError::Currentness)?);
        for _ in 0..endpoints {
            demand = demand.checked_add(endpoint).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        if matches!(purpose, Purpose::Outcome | Purpose::Read | Purpose::Replay) {
            let extent = self.extent.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let format = aos_sandbox::journal::broker_session_receiving::schema_demand(extent)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            demand = demand.checked_add(format).map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if matches!(purpose, Purpose::Outcome) {
                let traffic = aos_sandbox::journal::broker_session_receiving::storage_retained_traffic_reconstruction_demand_v1(extent)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                demand = demand.checked_add(traffic).map_err(|_| BrokerSessionSecurityError::Currentness)?;
            }
        }
        Ok(demand)
    }
}

impl StorageSessionReplayArchiveV3 {
    pub(in crate::recovery) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Admission precedes entry. Preserve its financial projection so the
        // actual service can lend the same original F's typed ledger cause.
        failure(&self.demand).or_else(|| failure(&self.funding))
            .or_else(|| self.failed.as_ref().and_then(|original| original.failure()))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(in crate::recovery) fn dispose_positive(&mut self) {
        if self.failure().is_none() {
            self.demand = None;
            self.funding = None;
        }
    }

    fn admit(&mut self, journal: &aos_sandbox::Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2, active: ResourceVector,
    ) -> Result<(), BrokerSessionSecurityError> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<ValidationOriginal>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(BrokerSessionSecurityError::Currentness)?;
        self.demand = Some(active.checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
            .map_err(|_| BrokerSessionSecurityError::Currentness));
        let complete = self.demand.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(BrokerSessionSecurityError::Currentness)?;
        self.funding = Some(receiving.reserve_session_replay_v3(journal, complete));
        if matches!(self.funding, Some(Ok(()))) { Ok(()) }
        else { Err(BrokerSessionSecurityError::Currentness) }
    }

    fn run<T>(&mut self, authority: &mut ProtectedBrokerSessionJournalV1,
        receiving: &mut dyn StorageFloorFinancialSourceV2, purpose: Purpose,
        operation: impl FnOnce(&mut ValidationOriginal, &mut ProtectedBrokerSessionJournalV1,
            &mut dyn StorageFloorFinancialSourceV2) -> Result<T, BrokerSessionSecurityError>,
    ) -> Result<T, BrokerSessionSecurityError> {
        if self.failure().is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.admit(authority.retained_storage_main_v3()?, receiving, ResourceVector::ZERO)?;
        let mut original = Box::new(ValidationOriginal::default());
        let result = (|| {
            if matches!(purpose, Purpose::Outcome | Purpose::Read | Purpose::Replay) {
                original.extent = Some(authority.retained_storage_main_v3()?
                    .held_session_receiving_extent_v1(&mut original.metadata));
            }
            original.demand = Some(original.demand(purpose));
            let demand = original.demand.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(BrokerSessionSecurityError::Currentness)?;
            self.admit(authority.retained_storage_main_v3()?, receiving, demand)?;
            operation(&mut original, authority, receiving)
        })();
        original.returned = Some(result.as_ref().map(|_| ()).map_err(|cause| cause.clone()));
        if result.is_err() { self.failed = Some(original); }
        // A complete positive observation has no ambiguous effect. Its scratch
        // drops here; the SAME F complete-bound debit is never refunded.
        result
    }

    pub(in crate::recovery) fn context(&mut self, authority: &mut ProtectedBrokerSessionJournalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1, receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.run(authority, receiving, Purpose::Context, |original, journal, source| {
            original.context.observe_with_storage_receiving_v3(journal, transcript, Some(source))?;
            original.context.value().cloned().ok_or(BrokerSessionSecurityError::Currentness)
        })
    }

    pub(in crate::recovery) fn peer(&mut self, authority: &mut ProtectedBrokerSessionJournalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1, peer: &ConnectionPeerIdentity,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<ObservedBrokerPeerExecutionV1, BrokerSessionSecurityError> {
        self.run(authority, receiving, Purpose::Peer, |original, journal, _source| {
            original.peer.observe_once(journal, transcript, peer)?;
            let observed = original.peer.value().ok_or(BrokerSessionSecurityError::Currentness)?;
            Ok(ObservedBrokerPeerExecutionV1 { uid: observed.uid, gid: observed.gid,
                pid: observed.pid, process_execution_id: observed.process_execution_id })
        })
    }

    pub(in crate::recovery) fn outcome(&mut self, authority: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.run(authority, receiving, Purpose::Outcome, |original, journal, source| {
            original.outcome.observe_storage_receiving_v3(journal, owner, peer, source)
        })
    }

    pub(in crate::recovery) fn observe_optional(&mut self,
        authority: &mut ProtectedBrokerSessionJournalV1, protocol: BrokerSessionProtocolV1,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<Option<journal::StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        self.run(authority, receiving, Purpose::Read, |_original, journal, source| {
            journal.read_optional_in_storage_validation_v3(protocol, source)
        })
    }

    pub(in crate::recovery) fn observe(&mut self, authority: &mut ProtectedBrokerSessionJournalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1, context: &ProtectedBrokerSessionVerificationContextV1,
        peer: &ObservedBrokerPeerExecutionV1, receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1,
        ProtectedBrokerSessionJournalSnapshotV1), BrokerSessionSecurityError> {
        self.run(authority, receiving, Purpose::Replay, |_original, journal, source| {
            reopen_prepaid_with_storage_receiving_v3(journal, transcript, context, peer, source)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn financial_refusal_precedes_its_coarse_validation_projection() {
        let mut owner = StorageSessionReplayArchiveV3::default();
        owner.funding = Some(Err(aos_sandbox::StorageReceivingClosedV1));
        let mut original = Box::new(ValidationOriginal::default());
        original.returned = Some(Err(BrokerSessionSecurityError::Currentness));
        owner.failed = Some(original);

        let first = owner.failure().unwrap();

        assert!(first.is::<aos_sandbox::StorageReceivingClosedV1>());
        owner.dispose_positive();
        assert!(owner.failure().unwrap().is::<aos_sandbox::StorageReceivingClosedV1>());
    }

    #[test]
    fn failed_native_original_survives_positive_disposal_attempt() {
        let mut original = Box::new(ValidationOriginal::default());
        original.metadata = Some(std::fs::metadata("/nonexistent/rfc21-native-original"));
        assert!(matches!(original.metadata, Some(Err(_))));
        let mut owner = StorageSessionReplayArchiveV3::default();
        owner.failed = Some(original);
        let first = owner.failure().unwrap() as *const dyn std::error::Error;

        owner.dispose_positive();

        assert!(std::ptr::addr_eq(first, owner.failure().unwrap() as *const dyn std::error::Error));
        assert!(owner.failed.is_some());
    }
}
