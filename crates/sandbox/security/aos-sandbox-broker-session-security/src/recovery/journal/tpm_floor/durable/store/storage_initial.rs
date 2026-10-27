//! Joins Storage's actual fixed floor capture before its private store move.
//!
//! The same F/main remains held. Native acquisition/replay and the full typed
//! shape come from their sole existing engines; no decoded scalar or caller
//! path can substitute for the actual fixed sidecar owner.

use super::*;
use aos_sandbox_controller_domain::{Journal, RecoveryReport, StoragePrepareReceivingLoanV1, StorageReceivingClosedV1};
use aos_sandbox_controller_domain::journal::StorageBrokerFloorCapturedJournalOpenV2;
use aos_sandbox_model::{AccountingError, ResourceVector};

#[derive(Clone, Copy)]
enum First { Before, Native, Shape, Missing, After, Coordinates }

pub(in crate::recovery::journal::tpm_floor::durable) struct StorageSidecarOpenOriginalV2 {
    native: StorageBrokerFloorCapturedJournalOpenV2,
    fixed: Option<Result<ResourceVector, AccountingError>>,
    payment: Option<Result<(), StorageReceivingClosedV1>>,
    before: Option<Result<(), crate::BrokerSessionSecurityError>>,
    shape: Option<Result<aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::FloorSidecarDecodeShapeV1, FloorErrorV1>>,
    opened: Option<(Journal, RecoveryReport)>,
    after: Option<Result<(), crate::BrokerSessionSecurityError>>,
    coordinates: Option<Result<(), FloorErrorV1>>,
    report: Option<RecoveryReport>,
    entered: bool,
    closed: Option<FloorErrorV1>,
    first: Option<First>,
}

impl StorageSidecarOpenOriginalV2 {
    pub(in crate::recovery::journal::tpm_floor::durable) fn new(fixed: Result<ResourceVector, AccountingError>,
        payment: Result<(), StorageReceivingClosedV1>) -> Self
    {
        Self {
            native: StorageBrokerFloorCapturedJournalOpenV2::new(),
            fixed: Some(fixed), payment: Some(payment), before: None, shape: None,
            opened: None, after: None, coordinates: None, report: None,
            entered: false, closed: None, first: None,
        }
    }

    fn upper_memory() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add("/var/lib/aos/sandbox-storage/broker-session".len().checked_mul(2)?)
    }

    pub(in crate::recovery::journal::tpm_floor::durable) fn fixed_demand() -> Result<ResourceVector, AccountingError> {
        let bytes = Self::upper_memory().ok_or(AccountingError::ArithmeticOverflow {
            dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
        })?;
        StorageBrokerFloorCapturedJournalOpenV2::fixed_preparation_demand_v2(bytes)
    }

    pub(in crate::recovery::journal::tpm_floor::durable) fn capture_once(&mut self,
        owner: &mut crate::recovery::journal::ProtectedBrokerSessionJournalV1,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>) -> Result<(), FloorErrorV1>
    {
        if self.entered || self.failure().is_some() {
            self.closed.get_or_insert(FloorErrorV1::Unavailable);
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.coordinates = Some(if owner.owner == JournalOwnerV1::RootBroker
            && owner.endpoint.role() == aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Broker
            && owner.endpoint.protected_protocol_and_node().0 == aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage
            && owner.directory == Path::new("/var/lib/aos/sandbox-storage/broker-session")
            && owner.name == "session.journal"
        { Ok(()) } else { Err(FloorErrorV1::Provisioning) });
        if !matches!(self.coordinates, Some(Ok(()))) {
            self.first = Some(First::Coordinates);
            return Err(FloorErrorV1::Provisioning);
        }
        self.before = Some(owner.endpoint.revalidate());
        let result = if matches!(self.before, Some(Ok(()))) {
            self.capture_inner(owner, receiving)
        } else {
            self.first = Some(First::Before);
            Err(FloorErrorV1::Unavailable)
        };
        // The independent endpoint post is owed even when native capture or
        // schema admission refused. No healthy sidecar reentry occurs here.
        self.after = Some(owner.endpoint.revalidate());
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        if result.is_ok() && matches!(self.after, Some(Ok(()))) { Ok(()) }
        else { Err(FloorErrorV1::Unavailable) }
    }

    fn capture_inner(&mut self,
        owner: &mut crate::recovery::journal::ProtectedBrokerSessionJournalV1,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>) -> Result<(), FloorErrorV1>
    {
        let main = owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        self.native.prepare_once(main, receiving, Self::upper_memory().ok_or(FloorErrorV1::Encoding)?);
        if self.native.failure().is_some() {
            self.first = Some(First::Native);
            return Err(FloorErrorV1::Unavailable);
        }
        self.shape = Some(self.native.captured_extent().and_then(|extent|
            crate::tpm_nv_custody::BrokerFloorReadOriginalV1::receiving_shape_v1(
                main.configured_limits_data_v1(), extent,
            )).ok_or(FloorErrorV1::Encoding));
        let Some(Ok(shape)) = self.shape.as_ref() else {
            self.first = Some(First::Shape);
            return Err(FloorErrorV1::Encoding);
        };
        self.native.replay_once(main, receiving, *shape);
        self.opened = self.native.take_opened(main, receiving);
        if self.opened.is_none() {
            self.first = Some(if self.native.failure().is_some() { First::Native } else { First::Missing });
            self.closed.get_or_insert(FloorErrorV1::Unavailable);
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(in crate::recovery::journal::tpm_floor::durable) fn finish_into(&mut self,
        owner: &crate::recovery::journal::ProtectedBrokerSessionJournalV1,
        target: &mut Option<FloorStoreV1>) -> Result<(), FloorErrorV1>
    {
        if self.failure().is_some() || !matches!(self.after, Some(Ok(()))) || target.is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        let main = owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        // Directory clone and whole-store carrier were included before capture.
        // Keep the same custody and sole typed-store engine; do not parse again.
        let directory = owner.directory.clone();
        let Some((journal, report)) = self.opened.take() else { return Err(FloorErrorV1::Unavailable); };
        self.report = Some(report);
        *target = Some(FloorStoreV1 { inner: BrokerSidecarStoreV1::from_broker(BrokerSidecarCustodyV1 {
            journal,
            main_limits: main.configured_limits_data_v1(),
            custody: StoreCustodyV1::Production { owner: owner.owner, directory },
            name: SidecarNameV1::Broker,
            currentness: owner.floor_currentness.clone(),
        }) });
        Ok(())
    }

    pub(in crate::recovery::journal::tpm_floor::durable) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first {
            Some(First::Before) => error(&self.before),
            Some(First::Native) => self.native.failure(),
            Some(First::Shape) => error(&self.shape),
            Some(First::After) => error(&self.after),
            Some(First::Coordinates) => error(&self.coordinates),
            Some(First::Missing) | None => None,
        }.or_else(|| self.closed.as_ref().map(|cause| cause as _))
            .or_else(|| error(&self.fixed)).or_else(|| error(&self.payment))
    }
}
