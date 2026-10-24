//! Borrows the actual paid State or Session stage for a physical worker call.
//!
//! This private adapter contains references to real Native guards and writers.
//! Method/length/vector DATA cannot construct either upstream guard. Each
//! concrete worker derives its own reached footprint and obtains one exclusive
//! flight before encoding, cloning a request, connecting or observing recovery.

use aos_sandbox_controller_domain::Journal;
use aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1;
use aos_sandbox_controller_domain::StoragePhysicalWorkerLoanV1;
use aos_sandbox_controller_domain::StorageReceivingClosedV1;
use aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1;
use aos_sandbox_controller_domain::StorageStateRecoveryEncodingLoanV1;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

/// Keeps a real model-paid domain stage borrowed through one worker call.
pub(crate) enum StoragePhysicalWorkerStageV1<'stage, 'cut, 'original> {
    GuestRootPublication31 {
        guard: &'stage mut StorageStateRecoveryEncodingLoanV1<'cut, 'original>,
        journal: &'stage Journal,
        request: &'stage aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    },
    Candidate {
        guard: &'stage mut StorageLifecycleSessionLoanV1<'cut, 'original>,
        journal: &'stage Journal,
        socket: &'stage SeqpacketSocket,
        request: &'stage aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    },
    Inventory {
        receiving: &'stage mut StoragePrepareReceivingLoanV1<'original>,
        journal: &'stage Journal,
    },
    RootExport {
        receiving: &'stage mut aos_sandbox_controller_domain::StorageRootLaunchExportReceivingLoanV2<'cut, 'original>,
        journal: &'stage Journal,
    },
    State {
        guard: &'stage mut StorageStateRecoveryEncodingLoanV1<'cut, 'original>,
        journal: &'stage Journal,
    },
    Domain {
        guard: &'stage mut StorageLifecycleSessionLoanV1<'cut, 'original>,
        journal: &'stage Journal,
        socket: &'stage SeqpacketSocket,
    },
}

impl<'stage, 'cut, 'original> StoragePhysicalWorkerStageV1<'stage, 'cut, 'original> {
    pub(crate) fn guest_root_publication_v2(
        guard: &'stage mut StorageStateRecoveryEncodingLoanV1<'cut, 'original>,
        journal: &'stage Journal,
        request: &'stage aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Self {
        Self::GuestRootPublication31 { guard, journal, request }
    }

    pub(crate) fn borrow_guest_root_publication_v2<'flight>(
        &'flight mut self,
        actual: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        match self {
            Self::GuestRootPublication31 { guard, journal, request } => {
                guard.borrow_guest_root_publication_worker_v2(journal, request, actual)
            }
            _ => Err(StorageReceivingClosedV1),
        }
    }

    pub(super) fn is_candidate_v1(&self) -> bool {
        matches!(self, Self::Candidate { .. })
    }

    pub(crate) fn candidate_v1(guard: &'stage mut StorageLifecycleSessionLoanV1<'cut, 'original>,
        journal: &'stage Journal, socket: &'stage SeqpacketSocket,
        request: &'stage aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Self { Self::Candidate { guard, journal, socket, request } }

    /// Borrows the genuine paid Inventory turn and its same retained State writer.
    ///
    /// The Native entry checks actual paid stages and writer identity when
    /// the concrete catalog callee requests its full physical demand.
    pub(crate) fn inventory(
        receiving: &'stage mut StoragePrepareReceivingLoanV1<'original>,
        journal: &'stage Journal,
    ) -> Self {
        Self::Inventory { receiving, journal }
    }

    /// Borrows the occupied same-F root-export turn for catalog observation.
    ///
    /// This financial arm does not construct a Host grant, canary job or
    /// workspace authority and cannot lend mutation/effect worker methods.
    pub(crate) fn root_export_v2(
        receiving: &'stage mut aos_sandbox_controller_domain::StorageRootLaunchExportReceivingLoanV2<'cut, 'original>,
        journal: &'stage Journal,
    ) -> Self {
        Self::RootExport { receiving, journal }
    }

    /// Borrows the same model-paid State writer and its genuine stage.
    pub(crate) fn state(
        guard: &'stage mut StorageStateRecoveryEncodingLoanV1<'cut, 'original>,
        journal: &'stage Journal,
    ) -> Self {
        Self::State { guard, journal }
    }

    /// Borrows the same Session writer/socket and its actual Domain stage.
    pub(crate) fn domain(
        guard: &'stage mut StorageLifecycleSessionLoanV1<'cut, 'original>,
        journal: &'stage Journal,
        socket: &'stage SeqpacketSocket,
    ) -> Self {
        Self::Domain { guard, journal, socket }
    }

    pub(super) fn borrow_zfs_v1<'flight>(
        &'flight mut self,
        actual: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        match self {
            Self::Candidate { guard, journal, socket, request } => guard.borrow_candidate_worker_flight_v1(journal, socket, request, actual),
            // This closed Inventory view lends only the catalog/pin carrier.
            // It cannot select the generic ZFS mutation/atomic worker port.
            Self::Inventory { .. } | Self::RootExport { .. } | Self::GuestRootPublication31 { .. } => Err(StorageReceivingClosedV1),
            Self::State { guard, journal } => guard.borrow_zfs_worker_flight_v1(journal, actual),
            Self::Domain { guard, journal, socket } => {
                guard.borrow_zfs_worker_flight_v1(journal, socket, actual)
            }
        }
    }

    /// Lends an effect/observation pin flight only from State or Domain.
    ///
    /// The separately paid Inventory view can call the catalog port, but
    /// cannot select an effect or repair exchange through this stage.
    pub(crate) fn borrow_effect_pin_v1<'flight>(
        &'flight mut self,
        actual: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        match self {
            Self::Candidate { .. } | Self::GuestRootPublication31 { .. } => Err(StorageReceivingClosedV1),
            Self::Inventory { .. } | Self::RootExport { .. } => Err(StorageReceivingClosedV1),
            Self::State { guard, journal } => guard.borrow_pin_worker_flight_v1(journal, actual),
            Self::Domain { guard, journal, socket } => {
                guard.borrow_pin_worker_flight_v1(journal, socket, actual)
            }
        }
    }

    pub(crate) fn borrow_pin_v1<'flight>(
        &'flight mut self,
        actual: ResourceVector,
    ) -> Result<StoragePhysicalWorkerLoanV1<'flight, 'original>, StorageReceivingClosedV1> {
        match self {
            Self::Candidate { .. } => Err(StorageReceivingClosedV1),
            Self::GuestRootPublication31 { guard, journal, request } => {
                guard.borrow_guest_root_catalog_worker_v2(journal, request, actual)
            }
            Self::Inventory { receiving, journal } => {
                receiving.borrow_inventory_catalog_worker_flight_v1(journal, actual)
            }
            Self::RootExport { receiving, journal } => receiving.borrow_catalog_worker_flight_v2(journal, actual),
            Self::State { guard, journal } => guard.borrow_pin_worker_flight_v1(journal, actual),
            Self::Domain { guard, journal, socket } => {
                guard.borrow_pin_worker_flight_v1(journal, socket, actual)
            }
        }
    }
}
