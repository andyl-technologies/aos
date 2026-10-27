//! Retains the actual captured Controller floor before the private store move.
//!
//! The genuine B original owns admission. This private consumer accepts only
//! that existing loan and actual Security main; it never adopts an arbitrary
//! Journal, path, UID, configured limit, decoded floor or resource vector.

use std::error::Error;
use std::mem::size_of;
use std::path::{Path, PathBuf};

use aos_sandbox_controller_domain::{ControllerInitialBrokerSessionCaptureShapeV1,
    ControllerInitialBrokerSessionClosedV1, ControllerInitialBrokerSessionReceivingLoanV1,
    ControllerInitialBrokerSessionRoleV1, Journal, RecoveryReport};
use aos_sandbox_controller_domain::journal::{ControllerStorageFloorCapturedJournalOpenV1,
    ProtectedJournalPreopenReplayExtentV1};
use aos_sandbox_broker_session_protocol::{BrokerSessionDurableEndpointV1, BrokerSessionProtocolV1};
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::FloorSidecarDecodeShapeV1;

use super::{BrokerSidecarCustodyV1, BrokerSidecarStoreV1, FloorErrorV1, FloorStoreV1,
    JournalOwnerV1, SidecarNameV1, StoreCustodyV1};
use crate::recovery::journal::ProtectedBrokerSessionJournalV1;
use crate::BrokerSessionSecurityError;

const DIRECTORY: &str = "/var/lib/aos/sandboxd/broker-session/storage";

#[derive(Clone, Copy)]
enum FirstV1 { Coordinates(usize), Returned, Association, Before, Native, Shape, Prefix, Missing, After, Transfer, Reentry }

pub(in crate::recovery::journal::tpm_floor::durable) struct ControllerSidecarOpenOriginalV1 {
    native: ControllerStorageFloorCapturedJournalOpenV1,
    coordinates: [Option<Result<(), FloorErrorV1>>; 2],
    association: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    before: Option<Result<(), BrokerSessionSecurityError>>,
    extent: Option<ProtectedJournalPreopenReplayExtentV1>,
    shape: Option<Result<FloorSidecarDecodeShapeV1, FloorErrorV1>>,
    prefix: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    opened: Option<(Journal, RecoveryReport)>,
    after: Option<Result<(), BrokerSessionSecurityError>>,
    transfer: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    directory: Option<PathBuf>,
    report: Option<RecoveryReport>,
    returned: Option<Result<(), FloorErrorV1>>,
    closed: Option<FloorErrorV1>,
    attempted: bool,
    complete: bool,
    first: Option<FirstV1>,
}

impl ControllerSidecarOpenOriginalV1 {
    pub(in crate::recovery::journal::tpm_floor::durable) fn new() -> Self {
        Self {
            native: ControllerStorageFloorCapturedJournalOpenV1::new(),
            coordinates: [None; 2],
            association: None, before: None, extent: None, shape: None, prefix: None,
            opened: None, after: None, transfer: None, directory: None, report: None,
            returned: None, closed: None, attempted: false, complete: false, first: None,
        }
    }

    /// Counts only this actual upper owner; Native separately adds its facade.
    pub(in crate::recovery::journal::tpm_floor::durable) fn fixed_shape_v1()
        -> Option<ControllerInitialBrokerSessionCaptureShapeV1>
    {
        // The native facade owns the actual fixed path namespace. This
        // upper shell and its directory copy add bytes, not distinct names.
        Some(ControllerInitialBrokerSessionCaptureShapeV1 {
            inline_bytes: size_of::<Self>().checked_mul(2)?,
            heap_bytes: DIRECTORY.len().checked_mul(2)?,
            open_files: 0,
            metadata_cells: 0,
        })
    }

    fn require_coordinates(owner: &ProtectedBrokerSessionJournalV1,
        receiving: &ControllerInitialBrokerSessionReceivingLoanV1<'_>) -> Result<(), FloorErrorV1>
    {
        if receiving.role_v1() != ControllerInitialBrokerSessionRoleV1::Storage
            || owner.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || owner.endpoint.protected_protocol_and_node() !=
                (BrokerSessionProtocolV1::Storage,
                 receiving.expected_node_v1().map_err(|_| FloorErrorV1::Unavailable)?)
            || !matches!(owner.owner, JournalOwnerV1::ServiceClient(_))
            || owner.directory != Path::new(DIRECTORY)
            || owner.name != "session.journal"
        {
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(())
    }

    pub(in crate::recovery::journal::tpm_floor::durable) fn capture_once(
        &mut self,
        owner: &mut ProtectedBrokerSessionJournalV1,
        receiving: &mut ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        if self.attempted {
            self.closed.get_or_insert(FloorErrorV1::Unavailable);
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(FloorErrorV1::Unavailable);
        }
        self.attempted = true;
        self.returned = Some(self.capture_inner(owner, receiving));
        if matches!(self.returned, Some(Err(_))) {
            self.first.get_or_insert(FirstV1::Returned);
        }
        // The fixed stage entered both real endpoint bookends. Once the first
        // was reached, its independent post runs even on sidecar/schema refusal.
        if self.before.is_some() {
            self.after = Some(owner.endpoint.revalidate());
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(FirstV1::After);
            }
        }
        if matches!(self.returned, Some(Ok(()))) && matches!(self.after, Some(Ok(())))
            && self.first.is_none()
        {
            self.complete = true;
            Ok(())
        } else {
            Err(self.returned.as_ref().and_then(|result| result.as_ref().err())
                .copied().unwrap_or(FloorErrorV1::Unavailable))
        }
    }

    fn capture_inner(&mut self, owner: &mut ProtectedBrokerSessionJournalV1,
        receiving: &mut ControllerInitialBrokerSessionReceivingLoanV1<'_>) -> Result<(), FloorErrorV1>
    {
        self.coordinates[0] = Some(Self::require_coordinates(owner, receiving));
        if let Some(Err(cause)) = self.coordinates[0] {
            self.first = Some(FirstV1::Coordinates(0));
            return Err(cause);
        }
        let Some(main) = owner.journal.as_ref() else {
            self.closed = Some(FloorErrorV1::Unavailable);
            self.first = Some(FirstV1::Missing);
            return Err(FloorErrorV1::Unavailable);
        };
        self.association = Some(receiving.require_opened_journal_v1(main));
        if !matches!(self.association, Some(Ok(()))) {
            self.first = Some(FirstV1::Association);
            return Err(FloorErrorV1::Unavailable);
        }
        self.before = Some(owner.endpoint.revalidate());
        if !matches!(self.before, Some(Ok(()))) {
            self.first = Some(FirstV1::Before);
            return Err(FloorErrorV1::Unavailable);
        }
        self.native.prepare_once(main, receiving);
        if self.native.failure().is_some() {
            self.first = Some(FirstV1::Native);
            return Err(FloorErrorV1::Unavailable);
        }
        self.extent = self.native.captured_extent().copied();
        self.shape = Some(self.extent.as_ref().and_then(|extent|
            crate::tpm_nv_custody::BrokerFloorReadOriginalV1::receiving_shape_v1(
                main.configured_limits_data_v1(), extent,
            )).ok_or(FloorErrorV1::Encoding));
        let shape = match self.shape {
            Some(Ok(shape)) => shape,
            _ => {
                self.first = Some(FirstV1::Shape);
                return Err(FloorErrorV1::Encoding);
            }
        };
        self.prefix = Some(receiving.admit_storage_floor_captured_prefix_once_v1(
            main, &self.native, shape,
        ));
        if !matches!(self.prefix, Some(Ok(()))) {
            self.first = Some(FirstV1::Prefix);
            return Err(FloorErrorV1::Unavailable);
        }
        self.native.replay_once(main, receiving);
        if self.native.failure().is_some() {
            self.first = Some(FirstV1::Native);
            return Err(FloorErrorV1::Unavailable);
        }
        // Keep the actual returned tuple before endpoint posts or store moves.
        self.opened = self.native.take_opened(main, receiving);
        if self.opened.is_none() {
            self.closed = Some(FloorErrorV1::Unavailable);
            self.first = Some(if self.native.failure().is_some() { FirstV1::Native } else { FirstV1::Missing });
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(in crate::recovery::journal::tpm_floor::durable) fn finish_into(
        &mut self, owner: &ProtectedBrokerSessionJournalV1,
        receiving: &mut ControllerInitialBrokerSessionReceivingLoanV1<'_>,
        target: &mut Option<FloorStoreV1>,
    ) -> Result<(), FloorErrorV1> {
        if !self.complete || self.failure().is_some() || target.is_some()
            || self.opened.is_none() || self.transfer.is_some()
        {
            return Err(FloorErrorV1::Unavailable);
        }
        self.coordinates[1] = Some(Self::require_coordinates(owner, receiving));
        if let Some(Err(cause)) = self.coordinates[1] {
            self.first = Some(FirstV1::Coordinates(1));
            return Err(cause);
        }
        let Some(main) = owner.journal.as_ref() else {
            self.closed = Some(FloorErrorV1::Unavailable);
            self.first = Some(FirstV1::Missing);
            return Err(FloorErrorV1::Unavailable);
        };
        let Some((sidecar, _)) = self.opened.as_ref() else {
            self.closed = Some(FloorErrorV1::Unavailable);
            self.first = Some(FirstV1::Missing);
            return Err(FloorErrorV1::Unavailable);
        };
        self.transfer = Some(receiving.require_storage_floor_journal_v1(main, sidecar));
        if !matches!(self.transfer, Some(Ok(()))) {
            self.first = Some(FirstV1::Transfer);
            return Err(FloorErrorV1::Unavailable);
        }
        self.directory = Some(owner.directory.clone());
        // All fallible joins precede the same Journal/custody move. The report
        // and emptied native facade remain with this actual attachment forever.
        let (Some((journal, report)), Some(directory)) = (self.opened.take(), self.directory.take()) else {
            std::process::abort()
        };
        self.report = Some(report);
        *target = Some(FloorStoreV1 { inner: BrokerSidecarStoreV1::from_broker(BrokerSidecarCustodyV1 {
            journal, main_limits: main.configured_limits_data_v1(),
            custody: StoreCustodyV1::Production { owner: owner.owner, directory },
            name: SidecarNameV1::Broker,
            currentness: owner.floor_currentness.clone(),
        }) });
        Ok(())
    }

    pub(in crate::recovery::journal::tpm_floor::durable) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
        }
        match self.first {
            Some(FirstV1::Coordinates(index)) => self.coordinates[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(FirstV1::Returned) => cause(&self.returned),
            Some(FirstV1::Association) => cause(&self.association),
            Some(FirstV1::Before) => cause(&self.before),
            Some(FirstV1::Native) => self.native.failure(),
            Some(FirstV1::Shape) => cause(&self.shape),
            Some(FirstV1::Prefix) => cause(&self.prefix),
            Some(FirstV1::Missing | FirstV1::Reentry) => self.closed.as_ref().map(|cause| cause as _),
            Some(FirstV1::After) => cause(&self.after),
            Some(FirstV1::Transfer) => cause(&self.transfer),
            None => None,
        }.or_else(|| cause(&self.returned))
    }
}
