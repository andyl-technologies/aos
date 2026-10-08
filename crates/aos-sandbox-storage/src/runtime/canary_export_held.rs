//! Resident, nonadmitting canary-prefix custody under the actual Storage runtime.
//!
//! The installed Host-only receiver donates its original socket and packet
//! before selected parsing. Complete primary/native loans use the sole Core
//! parser and lending cursor. A marker is same-history debt, never a floor:
//! neither its absence nor complete local history permits fresh creation,
//! dispatch, sidecar writes, generation0, positive ACK or Launch.
//!
//! The existing-only sidecar uses the proposed private DATA format:
//!
//! ```text
//! AOSRCH01 | version1 | phase1..4 | length1040 |
//! request402 | response240 | ACK192 | confirmation184 | zero6
//! ```
//!
//! Completed fields never change; unobserved suffixes are zero padding, not
//! zero resources. Four exact rows still do not reconstruct an old worker or
//! prove quiescence, bootstrap currentness, parent funding or rollback absence.

use std::fs::File;
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox::{Journal, JournalLimits, StorageNativeIssuanceEdgeDataV1};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_protocol::storage_root_export::{
    StorageCanaryExportAcknowledgmentV1, StorageCanaryExportConfirmationV1,
    StorageCanaryExportRequestV1, StorageCanaryExportResponseV1,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::repair_worker_drain::RepairWorkerDispatchGate;
use crate::native_issuance::{StorageNativeIssuanceErrorV1, StorageNativeIssuanceLedgerV1};
use crate::peer::HostRootExportPeerVerifier;
use crate::pin_worker::boottime_now_nanoseconds;
use crate::{StorageAdmissionCoordinator, StorageBrokerError, ZfsWorkerError};

const MAXIMUM_ORIGINAL_NANOSECONDS: u64 = 300_000_000_000;
const PRIMARY_HISTORY_DOMAIN: &[u8] = b"aos.sandbox.storage.canary-primary-history.v1\0";
const NATIVE_HISTORY_DOMAIN: &[u8] = b"aos.sandbox.storage.canary-native-history.v1\0";
const HOLD_DOMAIN: &[u8] = b"aos.sandbox.storage.canary-prefix-negative-hold.v1\0";
const SIDECAR_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.storage.canary-export-held-transaction.v1\0";
const SIDECAR_HISTORY_DOMAIN: &[u8] = b"aos.sandbox.storage.canary-sidecar-history.v1\0";
const SIDECAR_LIMITS: JournalLimits = JournalLimits {
    maximum_journal_bytes: 16_384,
    maximum_record_bytes: 2048,
    maximum_key_bytes: 32,
    maximum_records_per_transaction: 1,
    maximum_transaction_bytes: 4096,
    maximum_transactions: 4,
    maximum_materialized_bytes: 2048,
    maximum_materialized_records: 1,
};

#[derive(Debug, thiserror::Error)]
pub(super) enum CanaryPrefixCause {
    #[error("canary prefix instance is already closed")]
    Closed,
    #[error("canary prefix observation was interrupted")]
    Interrupted,
    #[error("canary prefix original binding was rejected")]
    Binding,
    #[error("independent attempt-bound floor and complete components are missing")]
    MissingProducer,
    #[error(transparent)]
    Request(aos_sandbox_protocol::storage_root_export::StorageRootExportProtocolErrorV1),
    #[error(transparent)]
    Socket(aos_sandbox_linux::seqpacket::RecordBindingError),
    #[error(transparent)]
    Kernel(aos_sandbox_linux::Error),
    #[error(transparent)]
    Clock(ZfsWorkerError),
    #[error("both original canary clock observations failed")]
    PairedClock {
        #[source]
        boot: aos_sandbox_linux::Error,
        boottime: ZfsWorkerError,
    },
    #[error(transparent)]
    Primary(StorageBrokerError),
    #[error(transparent)]
    Native(StorageNativeIssuanceErrorV1),
    #[error(transparent)]
    History(aos_sandbox::StorageNativeIssuanceHistoryErrorV1),
    #[error(transparent)]
    PrimaryHistory(aos_sandbox::journal::StorageCanaryExportHistoryErrorV1),
    #[error(transparent)]
    Sidecar(aos_sandbox::JournalError),
    #[error(transparent)]
    Startup(crate::activation::StorageOriginalWorkerStartupCauseV3),
    #[error(transparent)]
    Descriptor(rustix::io::Errno),
    #[error(transparent)]
    Transport(aos_sandbox_linux::seqpacket::SeqpacketError),
    #[error(transparent)]
    JobRead(aos_sandbox_linux::protected_file::ExactReadFailure),
    #[error(transparent)]
    Job(aos_sandbox_protocol::host_canary_job::HostCanaryJobDataErrorV1),
    #[error("canary independent public delivery was rejected")]
    PublicTrust,
    #[error(transparent)]
    PublicObservation(CanaryPublicInputCauseV2),
    #[error("the resident marker preparation Result failed")]
    MarkerPreparation,
    #[error("the resident marker native commit Result failed")]
    MarkerCommit,
    #[error("the resident canonical inventory Result failed")]
    Inventory,
    #[error(transparent)]
    Publication(crate::guest_root_inventory::GuestRootInventoryErrorV1),
    #[error(transparent)]
    InventoryWire(aos_sandbox_protocol::ProtocolValidationError),
    #[error(transparent)]
    PublisherWire(aos_sandbox_protocol::runtime_deployment::DeploymentWireErrorV1),
}

/// Owns completed historical observations, not self-borrowed Journal loans.
struct OriginalHistoryCut {
    digest: [u8; 32],
    limits: JournalLimits,
    physical_bytes: u64,
    next_sequence: u64,
    transactions: usize,
    records: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CanarySelectedPhaseV2 {
    Capturing,
    PreparedCut,
    PublisherReturned,
    Committed,
    Failed,
}

/// Lends only the two concrete phases of this same resident child.
///
/// Its private owner reference cannot be constructed from marker/head DATA.
/// The State writer uses it only while every original carrier and cut stays
/// resident. No borrow is held across publisher or helper transport.
pub(crate) struct CanaryBootstrapOriginalLoanV2<'owner> {
    owner: &'owner CanaryExportHeldV1,
}

impl CanaryBootstrapOriginalLoanV2<'_> {
    /// Samples only the original job's boot and exclusive signed window.
    pub(crate) fn require_effect_clock(&self) -> Result<(), crate::StorageStateError> {
        let boot = KernelBootId::current();
        let now = boottime_now_nanoseconds();
        let (boot, now) = match (boot, now) {
            (Ok(boot), Ok(now)) => (boot, now),
            (Err(boot), Err(boottime)) => {
                return Err(crate::StorageStateError::CanaryPairedClock {
                    boot,
                    boottime
                });
            }
            (Err(error), Ok(_)) => return Err(crate::StorageStateError::CanaryKernel(error)),
            (Ok(_), Err(error)) => return Err(crate::StorageStateError::CanaryClock(error)),
        };
        let job = self.owner.job.as_ref().ok_or(crate::StorageStateError::InvalidTransition)?;
        if boot.into_bytes() != job.boot_id || now < job.not_before || now >= job.deadline {
            return Err(crate::StorageStateError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn require_prepared_cut(&self) -> Result<(), crate::StorageStateError> {
        if self.owner.selected_phase != Some(CanarySelectedPhaseV2::PreparedCut)
            || self.owner.first_failure.is_some() || self.owner.marker.is_some()
            || self.owner.public_inputs.as_ref().is_none_or(|inputs| !inputs.ready)
            || self.owner.primary.is_none() || self.owner.native.is_none()
            || self.owner.sidecar_cut.is_none() || self.owner.job.is_none()
        {
            return Err(crate::StorageStateError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn primary_next(&self) -> Result<u64, crate::StorageStateError> {
        self.owner.primary.as_ref().map(|cut| cut.next_sequence)
            .ok_or(crate::StorageStateError::InvalidTransition)
    }

    pub(crate) fn marker_fields(&self) -> Result<[[u8; 32]; 5], crate::StorageStateError> {
        self.require_prepared_cut()?;
        let missing = || crate::StorageStateError::InvalidTransition;

        let fields = [
            self.owner.request.as_ref().ok_or_else(missing)?.digest()
                .map_err(|_| crate::StorageStateError::InvalidValue)?,
            self.owner.hold_identity.ok_or_else(missing)?,
            self.owner.primary.as_ref().ok_or_else(missing)?.digest,
            self.owner.native.as_ref().ok_or_else(missing)?.digest,
            self.owner.job.as_ref().ok_or_else(missing)?.digest,
        ];
        if fields.contains(&[0; 32]) {
            return Err(crate::StorageStateError::InvalidValue);
        }
        Ok(fields)
    }

    /// Reuses the sole native cursor and the existing primary edge hash recipe.
    pub(crate) fn compare_primary_history(
        &self,
        history: &mut aos_sandbox::journal::StorageCanaryBootstrapPrimaryHistoryDataV1<'_>,
    ) -> Result<(), crate::StorageStateError> {
        let original = self.owner.primary.as_ref()
            .ok_or(crate::StorageStateError::InvalidTransition)?;
        if self.owner.first_failure.is_some() || self.owner.marker.is_some()
            || history.opened_limits() != original.limits
            || history.physical_bytes() != original.physical_bytes
            || history.next_sequence() != original.next_sequence
        {
            return Err(crate::StorageStateError::InvalidTransition);
        }

        let mut hash = Sha256::new();
        hash.update(PRIMARY_HISTORY_DOMAIN);
        let mut count = 0usize;
        let mut records = 0usize;
        let mut cursor = history.replay()?;
        while let Some(edge) = cursor.next_edge().map_err(
            |error| crate::StorageStateError::CanaryHistory(error.into()),
        )? {
            hash_edge(&mut hash, &edge);
            count = count.checked_add(1).ok_or(crate::StorageStateError::InvalidValue)?;
            records = records.checked_add(edge.transaction().records().len())
                .ok_or(crate::StorageStateError::InvalidValue)?;
        }
        cursor.finish().map_err(|error| crate::StorageStateError::CanaryHistory(error.into()))?;
        if <[u8; 32]>::from(hash.finalize()) != original.digest
            || count != original.transactions || records != original.records
        {
            return Err(crate::StorageStateError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn authenticated_saved_marker(
        &self,
    ) -> Result<&crate::state::StorageCanaryBootstrapMarkerV2, crate::StorageStateError> {
        let missing = || crate::StorageStateError::InvalidTransition;
        if self.owner.selected_phase != Some(CanarySelectedPhaseV2::PublisherReturned)
            || self.owner.first_failure.is_some()
        {
            return Err(missing());
        }
        let marker = self.owner.prepared_marker.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(missing)?;
        let association = self.owner.association.as_ref().ok_or_else(missing)?;
        let current = self.owner.current.as_ref().ok_or_else(missing)?;
        let fields = association.fields();
        let coordinates = marker.primary_coordinates();
        if fields.marker_transaction != *marker.transaction().id()
            || fields.marker_digest != <[u8; 32]>::from(Sha256::digest(marker.bytes()))
            || fields.storage.catalog_digest != coordinates.0
            || fields.storage.catalog_generation != coordinates.1
            || fields.storage.primary_next != coordinates.2
            || fields.storage.primary_head != coordinates.3
            || fields.held_identity != self.owner.hold_identity.ok_or_else(missing)?
            || current.fields().association != association.digest()
        {
            return Err(missing());
        }
        Ok(marker)
    }
}

const CANARY_PUBLIC_NAMES_V2: [&str; 3] = [
    "runtime-deployment-genesis-v1",
    "runtime-deployment-provisioner-pin-v1",
    "runtime-deployment-canary-purpose-v2",
];
const CANARY_PUBLIC_WIDTHS_V2: [usize; 3] = [468, 32, 496];
const CANARY_CREDENTIAL_CONTEXT_V2: &[u8] =
    b"system_u:object_r:aos_sandbox_storage_credential_t";

#[derive(Debug, thiserror::Error)]
pub(super) enum CanaryPublicInputCauseV2 {
    #[error("canary public credential native observation failed")]
    Descriptor(#[from] rustix::io::Errno),
    #[error("canary public credential metadata failed")]
    Io(#[from] std::io::Error),
    #[error("canary public credential mount observation failed")]
    Kernel(#[from] aos_sandbox_linux::Error),
    #[error("canary public credential read failed")]
    Read(#[from] aos_sandbox_linux::protected_file::ExactReadFailure),
    #[error("canary public credential canonical authentication failed")]
    Wire(#[from] aos_sandbox_protocol::runtime_deployment::DeploymentWireErrorV1),
    #[error("canary public credential PID1 delivery differs")]
    Delivery(#[from] aos_sandbox::RuntimeDeploymentStartupErrorV1),
    #[error("canary public credential custody is incomplete, changed or fenced")]
    Changed,
}

type PublicFileIdentityV2 = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

struct CanaryPublicBytesV2 {
    genesis: Zeroizing<[u8; 468]>,
    provisioner: Zeroizing<[u8; 32]>,
    purpose: Zeroizing<[u8; 496]>,
}

impl CanaryPublicBytesV2 {
    fn new() -> Self {
        Self {
            genesis: Zeroizing::new([0; 468]),
            provisioner: Zeroizing::new([0; 32]),
            purpose: Zeroizing::new([0; 496]),
        }
    }

    fn role_mut(&mut self, index: usize) -> Result<&mut [u8], CanaryPublicInputCauseV2> {
        match index {
            0 => Ok(&mut self.genesis[..]),
            1 => Ok(&mut self.provisioner[..]),
            2 => Ok(&mut self.purpose[..]),
            _ => Err(CanaryPublicInputCauseV2::Changed),
        }
    }

    fn equals(&self, original: &Self) -> bool {
        self.genesis == original.genesis && self.provisioner == original.provisioner
            && self.purpose == original.purpose
    }
}

/// Keeps independent public delivery separate from packet/projection authority.
///
/// Four ancestors and three regular leaves remain resident in each original
/// and named-comparison set. Three complete byte sets total 2988 fixed bytes;
/// this component inventory is neither whole-call funding nor physical Drain.
struct CanaryPublicInputsV2 {
    originals: [Option<File>; 7],
    named: [Option<File>; 7],
    identities: [Option<PublicFileIdentityV2>; 7],
    mount: Option<aos_sandbox_linux::inventory::MountId>,
    bytes: CanaryPublicBytesV2,
    readback: CanaryPublicBytesV2,
    named_readback: CanaryPublicBytesV2,
    delivery: Option<aos_sandbox::RuntimeDeploymentStorageDeliveryReadbackV2>,
    compared_delivery: Option<aos_sandbox::RuntimeDeploymentStorageDeliveryReadbackV2>,
    genesis: Option<aos_sandbox_protocol::runtime_deployment::DeploymentGenesisV1>,
    purpose: Option<aos_sandbox_protocol::runtime_deployment::canary::CanaryPurposeV2>,
    attempted: bool,
    ready: bool,
    first_failure: Option<CanaryPublicInputCauseV2>,
    post_debt: [Option<CanaryPublicInputCauseV2>; 4],
}

impl CanaryPublicInputsV2 {
    fn new() -> Self {
        Self {
            originals: std::array::from_fn(|_| None),
            named: std::array::from_fn(|_| None),
            identities: [None; 7],
            mount: None,
            bytes: CanaryPublicBytesV2::new(),
            readback: CanaryPublicBytesV2::new(),
            named_readback: CanaryPublicBytesV2::new(),
            delivery: None,
            compared_delivery: None,
            genesis: None,
            purpose: None,
            attempted: false,
            ready: false,
            first_failure: None,
            post_debt: std::array::from_fn(|_| None),
        }
    }

    fn capture_once(&mut self) -> Result<(), ()> {
        if self.attempted || self.first_failure.is_some() {
            return Err(());
        }
        self.attempted = true;
        self.ready = false;
        let action = self.capture_inner();
        if let Err(cause) = action {
            self.first_failure = Some(cause);
        }

        // These supplemental observations do not readmit a failed credential
        // owner. Park their whole Results before decoding/projecting errors.
        self.compared_delivery = Some(aos_sandbox::observe_canary_storage_delivery_v2());
        let delivery = match (&self.delivery, &self.compared_delivery) {
            (Some(original), Some(compared)) => compared
                .compare_same_original_delivery(original).map_err(CanaryPublicInputCauseV2::from),
            _ => Err(CanaryPublicInputCauseV2::Changed),
        };
        self.retain_post(0, delivery);
        let files = self.compare_returned_originals();
        self.retain_post(1, files);
        if self.first_failure.is_some() {
            return Err(());
        }

        // The actual runtime's separate startup/peer/writer/final-clock posts
        // still precede positive use. Comparison Files are released only by
        // the outer completed bookend, never by this local capture.
        self.ready = true;
        Ok(())
    }

    fn capture_inner(&mut self) -> Result<(), CanaryPublicInputCauseV2> {
        self.delivery = Some(aos_sandbox::observe_canary_storage_delivery_v2());
        self.delivery.as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?
            .require_fixed_delivery()?;
        open_canary_public_ancestry_v2(&mut self.originals)?;
        for index in 0..4 {
            let file = self.originals[index].as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
            self.identities[index] = Some(public_file_identity_v2(file)?);
        }
        let directory = self.originals[3].as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
        require_canary_public_protection_v2(directory, None)?;
        self.mount = Some(aos_sandbox_linux::inventory::MountId::from_fd(directory.as_fd())?);

        for index in 0..CANARY_PUBLIC_NAMES_V2.len() {
            let directory = self.originals[3].as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
            self.originals[index + 4] = Some(File::from(
                aos_sandbox_linux::protected_file::open_nofollow_child(
                    directory, CANARY_PUBLIC_NAMES_V2[index],
                )?,
            ));
            let file = self.originals[index + 4].as_ref()
                .ok_or(CanaryPublicInputCauseV2::Changed)?;
            require_canary_public_protection_v2(file, Some(CANARY_PUBLIC_WIDTHS_V2[index]))?;
            if Some(aos_sandbox_linux::inventory::MountId::from_fd(file.as_fd())?) != self.mount {
                return Err(CanaryPublicInputCauseV2::Changed);
            }
            self.identities[index + 4] = Some(public_file_identity_v2(file)?);
            aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
                file, self.bytes.role_mut(index)?,
            )?;
        }

        // Public configuration authenticity is independent provisioning, not
        // inferred from root DAC, PID1 metadata or the sender's own packet.
        let provisioner = ed25519_dalek::VerifyingKey::from_bytes(&self.bytes.provisioner)
            .map_err(|_| CanaryPublicInputCauseV2::Changed)?;
        if provisioner.is_weak() {
            return Err(CanaryPublicInputCauseV2::Changed);
        }
        self.genesis = Some(aos_sandbox_protocol::runtime_deployment::DeploymentGenesisV1::decode(
            &self.bytes.genesis[..404],
        )?);
        let genesis = self.genesis.as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
        genesis.verify_signature(&provisioner, self.bytes.genesis[404..].try_into()
            .map_err(|_| CanaryPublicInputCauseV2::Changed)?)?;
        self.purpose = Some(aos_sandbox_protocol::runtime_deployment::canary::CanaryPurposeV2::decode(
            &self.bytes.purpose[..], &self.bytes.genesis, genesis, &provisioner,
        )?);
        self.compare_files_and_names()
    }

    /// Starts another comparison only after the outer successful bookend.
    fn recheck(&mut self) -> Result<(), ()> {
        if !self.ready || self.first_failure.is_some() || self.compared_delivery.is_some()
            || self.named.iter().any(Option::is_some)
        {
            return Err(());
        }
        self.ready = false;
        let action = self.compare_files_and_names();
        if let Err(error) = action {
            self.first_failure = Some(error);
        }
        self.compared_delivery = Some(aos_sandbox::observe_canary_storage_delivery_v2());
        let delivery = match (&self.delivery, &self.compared_delivery) {
            (Some(original), Some(compared)) => compared.compare_same_original_delivery(original)
                .map_err(CanaryPublicInputCauseV2::from),
            _ => Err(CanaryPublicInputCauseV2::Changed),
        };
        self.retain_post(2, delivery);
        let originals = self.compare_returned_originals();
        self.retain_post(3, originals);
        if self.first_failure.is_some() {
            return Err(());
        }

        self.ready = true;
        Ok(())
    }

    /// Releases only comparison DATA after the outer final original clock.
    fn finish_comparison(&mut self) {
        if self.ready && self.first_failure.is_none() {
            for file in &mut self.named {
                *file = None;
            }
            self.compared_delivery = None;
            self.readback.genesis.fill(0);
            self.readback.provisioner.fill(0);
            self.readback.purpose.fill(0);
            self.named_readback.genesis.fill(0);
            self.named_readback.provisioner.fill(0);
            self.named_readback.purpose.fill(0);
        }
    }

    fn compare_files_and_names(&mut self) -> Result<(), CanaryPublicInputCauseV2> {
        if self.named.iter().any(Option::is_some) {
            return Err(CanaryPublicInputCauseV2::Changed);
        }
        self.compare_returned_originals()?;
        open_canary_public_ancestry_v2(&mut self.named)?;
        for index in 0..4 {
            let file = self.named[index].as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
            if Some(public_file_identity_v2(file)?) != self.identities[index] {
                return Err(CanaryPublicInputCauseV2::Changed);
            }
            if index == 3 {
                require_canary_public_protection_v2(file, None)?;
                if Some(aos_sandbox_linux::inventory::MountId::from_fd(file.as_fd())?) != self.mount {
                    return Err(CanaryPublicInputCauseV2::Changed);
                }
            }
        }

        for index in 0..CANARY_PUBLIC_NAMES_V2.len() {
            let directory = self.named[3].as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
            self.named[index + 4] = Some(File::from(
                aos_sandbox_linux::protected_file::open_nofollow_child(
                    directory, CANARY_PUBLIC_NAMES_V2[index],
                )?,
            ));
            let named = self.named[index + 4].as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
            require_canary_public_protection_v2(named, Some(CANARY_PUBLIC_WIDTHS_V2[index]))?;
            if Some(public_file_identity_v2(named)?) != self.identities[index + 4]
                || Some(aos_sandbox_linux::inventory::MountId::from_fd(named.as_fd())?) != self.mount
            {
                return Err(CanaryPublicInputCauseV2::Changed);
            }
            let original = self.originals[index + 4].as_ref()
                .ok_or(CanaryPublicInputCauseV2::Changed)?;
            aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
                original, self.readback.role_mut(index)?,
            )?;
            aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
                named, self.named_readback.role_mut(index)?,
            )?;
        }
        if !self.readback.equals(&self.bytes) || !self.named_readback.equals(&self.bytes) {
            return Err(CanaryPublicInputCauseV2::Changed);
        }

        self.compare_returned_originals()
    }

    fn compare_returned_originals(&self) -> Result<(), CanaryPublicInputCauseV2> {
        for (index, original) in self.originals.iter().enumerate() {
            let Some(file) = original else {
                continue;
            };
            let actual = public_file_identity_v2(file)?;
            if self.identities[index].is_some_and(|before| before != actual) {
                return Err(CanaryPublicInputCauseV2::Changed);
            }
            if index >= 3 {
                require_canary_public_protection_v2(
                    file, index.checked_sub(4).map(|role| CANARY_PUBLIC_WIDTHS_V2[role]),
                )?;
                if self.mount.is_some()
                    && Some(aos_sandbox_linux::inventory::MountId::from_fd(file.as_fd())?) != self.mount
                {
                    return Err(CanaryPublicInputCauseV2::Changed);
                }
            }
        }
        Ok(())
    }

    fn retain_post(&mut self, index: usize, result: Result<(), CanaryPublicInputCauseV2>) {
        if let Err(cause) = result {
            self.ready = false;
            if self.first_failure.is_none() {
                self.first_failure = Some(cause);
            } else if let Some(slot) = self.post_debt.get_mut(index) {
                *slot = Some(cause);
            }
        }
    }
}

fn public_file_identity_v2(file: &File) -> Result<PublicFileIdentityV2, CanaryPublicInputCauseV2> {
    let metadata = file.metadata()?;
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.uid(),
        metadata.gid(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec()
    ))
}

/// Parks each original before checking the same fixed protected ancestry.
fn open_canary_public_ancestry_v2(
    slots: &mut [Option<File>; 7],
) -> Result<(), CanaryPublicInputCauseV2> {
    if slots.iter().any(Option::is_some) {
        return Err(CanaryPublicInputCauseV2::Changed);
    }
    let flags = rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    slots[0] = Some(File::from(rustix::fs::open("/", flags, rustix::fs::Mode::empty())?));
    let names = ["run", "credentials", "aos-storaged.service"];
    for index in 0..4 {
        let file = slots[index].as_ref().ok_or(CanaryPublicInputCauseV2::Changed)?;
        let stat = rustix::fs::fstat(file)?;
        if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o022 != 0 {
            return Err(CanaryPublicInputCauseV2::Changed);
        }
        if index < names.len() {
            slots[index + 1] = Some(File::from(rustix::fs::openat(
                file, names[index], flags, rustix::fs::Mode::empty(),
            )?));
        }
    }
    Ok(())
}

fn require_canary_public_protection_v2(
    file: &File,
    leaf_bytes: Option<usize>,
) -> Result<(), CanaryPublicInputCauseV2> {
    let stat = rustix::fs::fstat(file)?;
    let expected = if leaf_bytes.is_some() {
        0o400
    } else {
        0o500
    };
    let kind = if leaf_bytes.is_some() {
        rustix::fs::FileType::RegularFile
    } else {
        rustix::fs::FileType::Directory
    };
    if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o7777 != expected
        || rustix::fs::FileType::from_raw_mode(stat.st_mode) != kind
        || leaf_bytes.is_some_and(|width| stat.st_size != width as i64 || stat.st_nlink != 1)
        || !rustix::fs::fstatvfs(file)?.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY)
    {
        return Err(CanaryPublicInputCauseV2::Changed);
    }
    if leaf_bytes.is_some() {
        let flags = rustix::fs::fcntl_getfl(file)?;
        if flags.contains(rustix::fs::OFlags::PATH)
            || flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        {
            return Err(CanaryPublicInputCauseV2::Changed);
        }
    }
    let mut context = [0; 256];
    let count = rustix::fs::fgetxattr(file, "security.selinux", &mut context)?;
    let actual = context[..count].strip_suffix(&[0]).unwrap_or(&context[..count]);
    if actual != CANARY_CREDENTIAL_CONTEXT_V2 {
        return Err(CanaryPublicInputCauseV2::Changed);
    }
    let mut acl = [0; 4096];
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        match rustix::fs::fgetxattr(file, name, &mut acl) {
            Err(rustix::io::Errno::NODATA) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(CanaryPublicInputCauseV2::Changed),
        }
    }
    Ok(())
}

pub(super) struct CanaryExportHeldV1 {
    attempted: bool,
    socket: Option<DescriptorSubjectSocket>,
    record: Option<ReceivedDescriptorRecord>,
    request: Option<StorageCanaryExportRequestV1>,
    hold_identity: Option<[u8; 32]>,
    primary: Option<OriginalHistoryCut>,
    native: Option<OriginalHistoryCut>,
    sidecar: Option<Journal>,
    sidecar_recovery: Option<aos_sandbox::journal::RecoveryReport>,
    sidecar_rows: [Option<[u8; 1040]>; 4],
    sidecar_cut: Option<OriginalHistoryCut>,
    marker: Option<[u8; 208]>,
    first_failure: Option<CanaryPrefixCause>,
    public_inputs: Option<CanaryPublicInputsV2>,
    job_request: Option<aos_sandbox_protocol::storage_root_export::StorageCanaryJobRequestV2>,
    job: Option<aos_sandbox_protocol::host_canary_job::HostCanaryJobDataV1>,
    job_bytes: Vec<u8>,
    job_readback: Vec<u8>,
    // A failed phase ends the operation. Four cut-local posts plus the nine
    // independent owner posts fit without allocating a later diagnostic log.
    selected_post_debt: [Option<CanaryPrefixCause>; 16],
    selected_phase: Option<CanarySelectedPhaseV2>,
    prepared_marker: Option<Result<crate::state::StorageCanaryBootstrapMarkerV2, StorageBrokerError>>,
    marker_commit: Option<Result<aos_sandbox::journal::CommitResult, StorageBrokerError>>,
    association: Option<aos_sandbox_protocol::runtime_deployment::canary::CanaryAssociationV2>,
    current: Option<aos_sandbox_protocol::runtime_deployment::canary::CanaryCurrentV2>,
    receiver_boot: Option<[u8; 16]>,
    receiver_started: Option<u64>,
    host_execution: Option<aos_sandbox_linux::pidfd::PidFdInfo>,
    pending_receive: Option<Result<ReceivedDescriptorRecord,
        aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
    selected_socket: Option<Result<DescriptorSubjectSocket,
        aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1>>,
    inventory: Option<Result<Vec<u8>, super::StorageRuntimeError>>,
    published_inventory: Option<Result<Vec<u8>, crate::guest_root_inventory::GuestRootInventoryErrorV1>>,
    native_coordinates: Option<Result<(u64, aos_sandbox_core::ObjectDigest), StorageNativeIssuanceErrorV1>>,
    publisher_root: Option<Result<aos_sandbox_linux::cgroup::CgroupV2Root, ZfsWorkerError>>,
    publisher_cgroup: Option<Result<aos_sandbox_linux::cgroup::RetainedCgroupAnchor, aos_sandbox_linux::Error>>,
    publisher_socket: Option<Result<DescriptorSubjectSocket,
        aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1>>,
    publisher_request: Option<aos_sandbox_protocol::runtime_deployment::canary::CanaryPublisherRequestV3>,
    publisher_request_bytes: Option<[u8; 826]>,
    publisher_send: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    publisher_reply: Option<Result<ReceivedDescriptorRecord,
        aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
    marker_readback: Option<Result<(u64, aos_sandbox_core::ObjectDigest), CanaryPrefixCause>>,
}

impl CanaryExportHeldV1 {
    pub(super) const fn new() -> Self {
        Self {
            attempted: false,
            socket: None,
            record: None,
            request: None,
            hold_identity: None,
            primary: None,
            native: None,
            sidecar: None,
            sidecar_recovery: None,
            sidecar_rows: [None; 4],
            sidecar_cut: None,
            marker: None,
            first_failure: None,
            public_inputs: None,
            job_request: None,
            job: None,
            job_bytes: Vec::new(),
            job_readback: Vec::new(),
            selected_post_debt: [const { None }; 16],
            selected_phase: None,
            prepared_marker: None,
            marker_commit: None,
            association: None,
            current: None,
            receiver_boot: None,
            receiver_started: None,
            host_execution: None,
            pending_receive: None,
            selected_socket: None,
            inventory: None,
            published_inventory: None,
            native_coordinates: None,
            publisher_root: None,
            publisher_cgroup: None,
            publisher_socket: None,
            publisher_request: None,
            publisher_request_bytes: None,
            publisher_send: None,
            publisher_reply: None,
            marker_readback: None,
        }
    }

    // The caller checks vacancy before these infallible owner moves. No second
    // packet can recover a failed/interrupted instance or renew its deadline.
    pub(super) fn is_unused(&self) -> bool {
        !self.attempted && self.socket.is_none() && self.record.is_none()
    }

    pub(super) fn park_original(
        &mut self,
        mut socket: DescriptorSubjectSocket,
        record: ReceivedDescriptorRecord,
    ) {
        self.attempted = true;
        socket.begin_original_retention_v1();
        self.socket = Some(socket);
        self.record = Some(record);
    }

    /// Authenticates the fixed installed mode before accepting the wider record.
    ///
    /// The selector merely requests admission. Neither packet magic nor an
    /// environment value can supply the retained startup and PID1 credential
    /// delivery owners used here. A selected refusal never enters Legacy.
    pub(super) fn receive_selected_original_v2(
        &mut self,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener,
        startup: Option<&mut crate::activation::StorageOriginalWorkerStartupV3>,
        verifier: &HostRootExportPeerVerifier,
    ) -> bool {
        let mut observation = CanarySelectedObservationV2 {
            owner: self,
            completed: false
        };
        let mut startup = startup;
        let action = (|| {
            if !observation.owner.prepare_selected_receiver_v2(startup.as_deref_mut())
                || !observation.owner.accept_selected_v2(listener)
            {
                return Err(CanaryPrefixCause::Closed);
            }
            let socket = observation.owner.selected_socket.as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(CanaryPrefixCause::Closed)?;
            observation.owner.host_execution = Some(verifier.verify_connection(socket.peer())
                .map_err(|()| CanaryPrefixCause::Binding)?);
            observation.owner.wait_selected_request_v2()?;
            if !observation.owner.receive_selected_once_v2() {
                return Err(CanaryPrefixCause::Closed);
            }
            observation.owner.compare_selected_host_v2(verifier)?;
            observation.owner.capture_selected_job_v2()
        })();
        observation.owner.retain_selected_post_v2(action);

        // Keep the owning admission/receive error and any partial SCM rights
        // before these independent original observations. No post is a retry
        // or a fresh eligibility proof for an already failed owner.
        let original = startup.as_deref_mut().ok_or(CanaryPrefixCause::MissingProducer)
            .and_then(|startup| startup.recheck().map_err(CanaryPrefixCause::Startup));
        observation.owner.retain_selected_post_v2(original);
        if observation.owner.public_inputs.as_ref().is_some_and(|inputs| inputs.ready) {
            let public = observation.owner.public_inputs.as_mut().ok_or(CanaryPrefixCause::Closed)
                .and_then(|inputs| inputs.recheck().map_err(|()| CanaryPrefixCause::PublicTrust));
            observation.owner.retain_selected_post_v2(public);
        }
        if let Some(inputs) = observation.owner.public_inputs.as_ref() {
            let originals = inputs.compare_returned_originals()
                .map_err(CanaryPrefixCause::PublicObservation);
            observation.owner.retain_selected_post_v2(originals);
        }
        if observation.owner.pending_receive.as_ref().is_some_and(Result::is_ok) {
            let peer = observation.owner.compare_selected_host_v2(verifier);
            observation.owner.retain_selected_post_v2(peer);
        }
        if observation.owner.job.is_some() {
            let job = observation.owner.recheck_selected_job_bytes_v2();
            observation.owner.retain_selected_post_v2(job);
        }

        let clock = observation.owner.require_selected_clock_v2();
        observation.owner.retain_selected_post_v2(clock);
        if observation.owner.first_failure.is_some() {
            return false;
        }
        if let Some(inputs) = observation.owner.public_inputs.as_mut() {
            inputs.finish_comparison();
        }
        observation.completed = true;
        true
    }

    /// Waits without consuming before the single retained receive attempt.
    fn wait_selected_request_v2(&self) -> Result<(), CanaryPrefixCause> {
        let deadline = self.receiver_started.and_then(|started| started.checked_add(5_000_000_000))
            .ok_or(CanaryPrefixCause::Binding)?;
        let socket = self.selected_socket.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        self.wait_selected_readable_v2(socket, deadline)
    }

    /// Reobserves the original clock and socket on every selected poll turn.
    fn wait_selected_readable_v2(
        &self,
        socket: &DescriptorSubjectSocket,
        deadline: u64,
    ) -> Result<(), CanaryPrefixCause> {
        loop {
            self.require_selected_clock_v2()?;
            let remaining = deadline.checked_sub(boottime_now_nanoseconds()
                .map_err(CanaryPrefixCause::Clock)?)
                .filter(|remaining| *remaining != 0).ok_or(CanaryPrefixCause::Binding)?;
            let timeout = rustix::event::Timespec::try_from(
                std::time::Duration::from_nanos(remaining),
            ).map_err(|_| CanaryPrefixCause::Binding)?;
            let fd = socket.as_fd().map_err(CanaryPrefixCause::Transport)?;
            let mut ready = [rustix::event::PollFd::from_borrowed_fd(
                fd, rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut ready, Some(&timeout)) {
                Ok(0) => return Err(CanaryPrefixCause::Binding),
                Ok(_) if ready[0].revents().contains(rustix::event::PollFlags::IN) => return Ok(()),
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(CanaryPrefixCause::Descriptor(error)),
                Ok(_) => return Err(CanaryPrefixCause::Binding),
            }
        }
    }

    fn compare_selected_host_v2(
        &mut self,
        verifier: &HostRootExportPeerVerifier,
    ) -> Result<(), CanaryPrefixCause> {
        let socket = self.selected_socket.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        let record = self.pending_receive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        socket.validate_received_origin_retaining(record).map_err(CanaryPrefixCause::Socket)?;
        verifier.verify_record(self.host_execution.ok_or(CanaryPrefixCause::Closed)?,
            socket.peer(), record.subject()).map_err(|()| CanaryPrefixCause::Binding)
    }

    pub(super) fn selected_deadline_v2(&self) -> Option<u64> {
        if self.first_failure.is_some() {
            return None;
        }
        self.job.as_ref().map(|job| job.deadline)
    }

    /// Parks the genuine complete inventory before the sole publication codec.
    pub(super) fn park_selected_inventory_v2(
        &mut self,
        inventory: Result<Vec<u8>, super::StorageRuntimeError>,
        template: &crate::guest_root_inventory::ProtectedGuestRootTemplateV1,
        broker_instance: &[u8; 16],
    ) -> bool {
        if self.inventory.is_some() || self.published_inventory.is_some() || self.first_failure.is_some() {
            return false;
        }
        self.inventory = Some(inventory);
        let action = (|| {
            let original = self.inventory.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CanaryPrefixCause::Inventory)?;
            self.published_inventory = Some(
                crate::guest_root_inventory::attach_guest_root_publication_readback_v1(original, template),
            );
            let bytes = self.published_inventory.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CanaryPrefixCause::Inventory)?;
            let inventory = aos_sandbox_protocol::decode_storage_resource_inventory_response(
                bytes, aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES,
            ).map_err(CanaryPrefixCause::InventoryWire)?;
            let job = self.job.as_ref().ok_or(CanaryPrefixCause::Closed)?;
            let request = self.request.as_ref().ok_or(CanaryPrefixCause::Closed)?;
            let fence = job.launch.fence();
            if inventory.kernel_boot_id() != &job.boot_id
                || inventory.broker_instance_id() != broker_instance
                || request.proof.sandbox != *fence.sandbox_id()
                || request.proof.incarnation != *fence.incarnation_id()
                || request.proof.assignment_epoch != fence.assignment_epoch()
                || request.proof.assignment_digest != *fence.assignment_digest()
                || !inventory.workspaces().iter().any(|row| {
                    row.workspace_handle() == &request.proof.workspace_handle
                        && row.guest_root_publication_proof() == Some(request.proof)
                })
            {
                return Err(CanaryPrefixCause::Binding);
            }
            Ok(())
        })();
        self.retain_selected_post_v2(action);

        let clock = self.require_selected_clock_v2();
        self.retain_selected_post_v2(clock);
        self.first_failure.is_none()
    }

    /// Prepares only under the same authenticated runtime writer and held gate.
    pub(super) fn prepare_selected_cut_v2(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        native: Option<&mut StorageNativeIssuanceLedgerV1>,
        gate: &RepairWorkerDispatchGate,
        broker_instance: &[u8; 16],
    ) -> bool {
        let mut observation = CanarySelectedObservationV2 {
            owner: self,
            completed: false
        };
        let mut native = native;
        let action = (|| {
            if observation.owner.first_failure.is_some() || observation.owner.inventory.is_none()
                || observation.owner.prepared_marker.is_some() || observation.owner.hold_identity.is_some()
            {
                return Err(CanaryPrefixCause::Closed);
            }
            let request = observation.owner.request.as_ref().ok_or(CanaryPrefixCause::Closed)?;
            let request_digest = request.digest().map_err(CanaryPrefixCause::Request)?;
            observation.owner.hold_identity = Some(Sha256::new().chain_update(HOLD_DOMAIN)
                .chain_update(broker_instance).chain_update(request_digest).finalize().into());
            gate.begin_canary_hold(observation.owner.hold_identity.ok_or(CanaryPrefixCause::Closed)?)
                .map_err(|()| CanaryPrefixCause::Binding)?;
            observation.owner.capture_primary(coordinator)?;
            observation.owner.capture_native(native.as_deref_mut().ok_or(CanaryPrefixCause::MissingProducer)?, coordinator)?;
            observation.owner.capture_sidecar()?;
            if observation.owner.marker.is_some()
                || observation.owner.sidecar_cut.as_ref().is_none_or(|cut| cut.transactions != 0)
            {
                return Err(CanaryPrefixCause::Binding);
            }
            observation.owner.native_coordinates = Some(native.as_deref_mut()
                .ok_or(CanaryPrefixCause::MissingProducer)?.operator_terminal_readback_cut_v4());
            let coordinates = observation.owner.native_coordinates.as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(CanaryPrefixCause::Binding)?;
            if observation.owner.native.as_ref().is_none_or(|cut| cut.next_sequence != coordinates.0) {
                return Err(CanaryPrefixCause::Binding);
            }
            observation.owner.selected_phase = Some(CanarySelectedPhaseV2::PreparedCut);
            let loan = CanaryBootstrapOriginalLoanV2 {
                owner: observation.owner
            };
            let marker = coordinator.prepare_canary_bootstrap_marker_v2(&loan);
            observation.owner.prepared_marker = Some(marker);
            if observation.owner.prepared_marker.as_ref().is_none_or(Result::is_err) {
                return Err(CanaryPrefixCause::MarkerPreparation);
            }
            Ok(())
        })();
        observation.owner.retain_selected_post_v2(action);
        let primary = coordinator.native_metadata_readback_cut(
            std::path::Path::new("/var/lib/aos/sandbox-storage"),
        ).map_err(CanaryPrefixCause::Primary).and_then(|cut| {
            let marker = observation.owner.prepared_marker.as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(CanaryPrefixCause::Closed)?;
            let saved = marker.primary_coordinates();
            if cut.0 != saved.2 || cut.1.as_bytes() != &saved.3 {
                return Err(CanaryPrefixCause::Binding);
            }
            Ok(())
        });
        observation.owner.retain_selected_post_v2(primary);
        if let Some(native) = native.as_deref_mut() {
            let native_cut = native.operator_terminal_readback_cut_v4()
                .map_err(CanaryPrefixCause::Native).and_then(|cut| {
                    if observation.owner.native_coordinates.as_ref().and_then(|result| result.as_ref().ok()) != Some(&cut) {
                        return Err(CanaryPrefixCause::Binding);
                    }
                    Ok(())
                });
            observation.owner.retain_selected_post_v2(native_cut);
        }
        let held = observation.owner.hold_identity.ok_or(CanaryPrefixCause::Closed)
            .and_then(|identity| gate.require_canary_hold(&identity).map_err(|()| CanaryPrefixCause::Binding));
        observation.owner.retain_selected_post_v2(held);

        let clock = observation.owner.require_selected_clock_v2();
        observation.owner.retain_selected_post_v2(clock);
        if observation.owner.first_failure.is_some() {
            return false;
        }
        observation.completed = true;
        true
    }

    /// Delivers the saved request once, then appends only its authentic marker.
    ///
    /// This completes the association producer, not root measurement, gen0,
    /// acknowledgment or Launch. Every native Result remains in this child;
    /// uncertain publication/COMMIT never permits a second exchange or append.
    pub(super) fn complete_selected_bootstrap_v2(
        &mut self,
        coordinator: &mut StorageAdmissionCoordinator,
        native: Option<&mut StorageNativeIssuanceLedgerV1>,
        startup: Option<&mut crate::activation::StorageOriginalWorkerStartupV3>,
        gate: &RepairWorkerDispatchGate,
        verifier: &HostRootExportPeerVerifier,
    ) -> bool {
        let mut observation = CanarySelectedObservationV2 {
            owner: self,
            completed: false
        };
        let mut native = native;
        let mut startup = startup;
        let action = (|| {
            if observation.owner.selected_phase != Some(CanarySelectedPhaseV2::PreparedCut)
                || observation.owner.first_failure.is_some()
                || observation.owner.publisher_socket.is_some() || observation.owner.marker_commit.is_some()
            {
                return Err(CanaryPrefixCause::Closed);
            }
            observation.owner.prepare_publisher_request_v2()?;
            observation.owner.observe_selected_owner_posts_v2(
                coordinator, native.as_deref_mut(), startup.as_deref_mut(), gate, verifier,
            );
            if observation.owner.first_failure.is_some() {
                return Err(CanaryPrefixCause::Closed);
            }
            // All encoding, original-owner checks and allocation precede the
            // final signed clock. The lower connect/send can still straddle D.
            observation.owner.require_selected_clock_v2()?;
            observation.owner.publisher_socket = Some(DescriptorSubjectSocket::connect_retaining(
                std::path::Path::new("/run/aos/sandbox/runtime-deployment.sock"),
            ));
            let socket = observation.owner.publisher_socket.as_mut()
                .and_then(|result| result.as_mut().ok()).ok_or(CanaryPrefixCause::Binding)?;
            socket.begin_original_retention_v1();
            observation.owner.require_publisher_connection_v2()?;
            observation.owner.require_selected_clock_v2()?;
            let socket = observation.owner.publisher_socket.as_mut()
                .and_then(|result| result.as_mut().ok()).ok_or(CanaryPrefixCause::Closed)?;
            let original = observation.owner.pending_receive.as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(CanaryPrefixCause::Closed)?;
            let [descriptor] = original.descriptors() else {
                return Err(CanaryPrefixCause::Binding);
            };
            observation.owner.publisher_send = Some(socket.send_with_descriptors_retaining(
                observation.owner.publisher_request_bytes.as_ref().ok_or(CanaryPrefixCause::Closed)?,
                &[descriptor.as_fd()],
            ));
            if observation.owner.publisher_send.as_ref().is_none_or(Result::is_err) {
                return Err(CanaryPrefixCause::Binding);
            }
            observation.owner.wait_publisher_reply_v2()?;
            let socket = observation.owner.publisher_socket.as_mut()
                .and_then(|result| result.as_mut().ok()).ok_or(CanaryPrefixCause::Closed)?;
            observation.owner.publisher_reply = Some(socket.receive_zero_descriptors_retaining(1144));
            observation.owner.decode_publisher_reply_v2()?;
            observation.owner.observe_selected_owner_posts_v2(
                coordinator, native.as_deref_mut(), startup.as_deref_mut(), gate, verifier,
            );
            if observation.owner.first_failure.is_some() {
                return Err(CanaryPrefixCause::Closed);
            }
            observation.owner.selected_phase = Some(CanarySelectedPhaseV2::PublisherReturned);
            let result = coordinator.append_canary_bootstrap_marker_v2(
                &CanaryBootstrapOriginalLoanV2 { owner: &*observation.owner },
            );
            observation.owner.marker_commit = Some(result);
            if observation.owner.marker_commit.as_ref().is_none_or(Result::is_err) {
                return Err(CanaryPrefixCause::MarkerCommit);
            }
            observation.owner.marker_readback = Some(observation.owner.readback_marker_v2(coordinator));
            if observation.owner.marker_readback.as_ref().is_none_or(Result::is_err) {
                return Err(CanaryPrefixCause::MarkerCommit);
            }
            observation.owner.selected_phase = Some(CanarySelectedPhaseV2::Committed);
            Ok(())
        })();
        observation.owner.retain_selected_post_v2(action);
        observation.owner.observe_selected_owner_posts_v2(
            coordinator, native.as_deref_mut(), startup.as_deref_mut(), gate, verifier,
        );
        if observation.owner.first_failure.is_some() {
            return false;
        }
        if let Some(inputs) = observation.owner.public_inputs.as_mut() {
            inputs.finish_comparison();
        }
        observation.completed = true;
        true
    }

    fn prepare_publisher_request_v2(&mut self) -> Result<(), CanaryPrefixCause> {
        use aos_sandbox_protocol::runtime_deployment::canary::{
            CanaryPublisherRequestV3, StorageCoordinatesV3,
        };
        if self.publisher_request.is_some() || self.publisher_root.is_some() {
            return Err(CanaryPrefixCause::Closed);
        }
        let marker = self.prepared_marker.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::MarkerPreparation)?;
        let saved = marker.primary_coordinates();
        let native = self.native_coordinates.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        let request = self.request.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let job = self.job.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        self.publisher_request = Some(CanaryPublisherRequestV3 {
            nonce: job.nonce,
            boot: job.boot_id,
            not_before: job.not_before,
            deadline: job.deadline,
            job_bytes: self.job_request.as_ref().ok_or(CanaryPrefixCause::Closed)?.job_bytes,
            request: request.encode().map_err(CanaryPrefixCause::Request)?,
            marker: *marker.bytes(),
            storage: StorageCoordinatesV3 {
                catalog_digest: saved.0,
                catalog_generation: saved.1,
                primary_next: saved.2,
                primary_head: saved.3,
                native_next: native.0,
                native_head: *native.1.as_bytes(),
            },
        });
        self.publisher_request_bytes = Some(self.publisher_request.as_ref()
            .ok_or(CanaryPrefixCause::Closed)?.encode().map_err(CanaryPrefixCause::PublisherWire)?);

        self.publisher_root = Some(crate::process::open_cgroup_root());
        let root = self.publisher_root.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Binding)?;
        self.publisher_cgroup = Some(root.resolve(std::path::Path::new(
            "aos.slice/aos-control.slice/aos-sandbox-runtime-publisher.service",
        )));
        self.publisher_cgroup.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Binding)?.validate_current().map_err(CanaryPrefixCause::Kernel)
    }

    fn wait_publisher_reply_v2(&self) -> Result<(), CanaryPrefixCause> {
        let deadline = self.job.as_ref().ok_or(CanaryPrefixCause::Closed)?.deadline;
        let socket = self.publisher_socket.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        self.wait_selected_readable_v2(socket, deadline)
    }

    /// Authenticates the fixed PID1 listener independently of the reply subject.
    fn require_publisher_connection_v2(&self) -> Result<(), CanaryPrefixCause> {
        let socket = self.publisher_socket.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        let peer = socket.peer();
        let info = peer.pidfd().info().map_err(CanaryPrefixCause::Kernel)?;
        if peer.credentials().uid() != 0 || peer.credentials().gid() != 0
            || peer.credentials().pid().get() != 1 || info.pid() != 1 || info.thread_group_id() != 1
            || !peer.is_alive().map_err(CanaryPrefixCause::Kernel)?
        {
            return Err(CanaryPrefixCause::Binding);
        }
        Ok(())
    }

    fn compare_publisher_reply_origin_v2(&mut self) -> Result<(), CanaryPrefixCause> {
        self.require_publisher_connection_v2()?;
        let socket = self.publisher_socket.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        let record = self.publisher_reply.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Binding)?;
        socket.validate_received_origin_retaining(record).map_err(CanaryPrefixCause::Socket)?;
        let service = self.publisher_cgroup.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        let subject = record.subject();
        let info = service.verify_exact_membership(subject.pidfd()).map_err(CanaryPrefixCause::Kernel)?;
        if subject.credentials().uid() != 0 || subject.credentials().gid() != 0
            || subject.credentials().pid().get() != info.pid() || info.thread_group_id() != info.pid()
            || !subject.is_alive().map_err(CanaryPrefixCause::Kernel)? || !record.descriptors().is_empty()
        {
            return Err(CanaryPrefixCause::Binding);
        }
        service.validate_current().map_err(CanaryPrefixCause::Kernel)
    }

    fn decode_publisher_reply_v2(&mut self) -> Result<(), CanaryPrefixCause> {
        use aos_sandbox_protocol::runtime_deployment::canary::{CanaryAssociationV2, CanaryCurrentV2};
        self.compare_publisher_reply_origin_v2()?;
        let public = self.public_inputs.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let genesis = public.genesis.as_ref().ok_or(CanaryPrefixCause::PublicTrust)?;
        let purpose = public.purpose.as_ref().ok_or(CanaryPrefixCause::PublicTrust)?;
        let publisher = ed25519_dalek::VerifyingKey::from_bytes(&genesis.signer)
            .map_err(|_| CanaryPrefixCause::PublicTrust)?;
        let record = self.publisher_reply.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Binding)?;
        if record.payload().len() != 1144 || self.association.is_some() || self.current.is_some() {
            return Err(CanaryPrefixCause::Binding);
        }
        self.association = Some(CanaryAssociationV2::decode(&record.payload()[..776], &publisher)
            .map_err(CanaryPrefixCause::PublisherWire)?);
        let association = self.association.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        association.require_request_v3(self.publisher_request.as_ref().ok_or(CanaryPrefixCause::Closed)?,
            genesis, purpose).map_err(CanaryPrefixCause::PublisherWire)?;
        if association.fields().attempt != self.job.as_ref().ok_or(CanaryPrefixCause::Closed)?.job_id {
            return Err(CanaryPrefixCause::Binding);
        }
        self.current = Some(CanaryCurrentV2::decode(&record.payload()[776..], &publisher, association)
            .map_err(CanaryPrefixCause::PublisherWire)?);
        Ok(())
    }

    /// Replays the actual original COMMIT and its precise physical extent.
    fn readback_marker_v2(
        &self,
        coordinator: &StorageAdmissionCoordinator,
    ) -> Result<(u64, aos_sandbox_core::ObjectDigest), CanaryPrefixCause> {
        let marker = self.prepared_marker.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        let original = self.primary.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let returned = self.marker_commit.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::MarkerCommit)?;
        let append = aos_sandbox::journal::encoded_transaction_append_bytes(marker.transaction())
            .map_err(aos_sandbox::JournalError::from)
            .map_err(CanaryPrefixCause::Sidecar)?;
        let expected_bytes = original.physical_bytes.checked_add(append).ok_or(CanaryPrefixCause::Binding)?;
        let expected_next = original.next_sequence.checked_add(3).ok_or(CanaryPrefixCause::Binding)?;
        let mut history = coordinator.borrow_canary_bootstrap_primary_original().map_err(CanaryPrefixCause::Primary)?;
        if history.opened_limits() != original.limits || history.physical_bytes() != expected_bytes
            || history.next_sequence() != expected_next || returned.durable_bytes != expected_bytes
            || returned.commit_sequence.checked_add(1) != Some(expected_next)
        {
            return Err(CanaryPrefixCause::Binding);
        }
        let mut cursor = history.replay().map_err(CanaryPrefixCause::PrimaryHistory)?;

        let mut hash = Sha256::new();
        hash.update(PRIMARY_HISTORY_DOMAIN);
        let mut transactions = 0usize;
        let mut records = 0usize;
        let mut found = false;
        while let Some(edge) = cursor.next_edge().map_err(CanaryPrefixCause::History)? {
            if transactions < original.transactions {
                hash_edge(&mut hash, &edge);
                records = records.checked_add(edge.transaction().records().len()).ok_or(CanaryPrefixCause::Binding)?;
            } else {
                if found || edge.transaction() != marker.transaction()
                    || edge.begin_sequence() != original.next_sequence
                    || edge.commit_sequence() != returned.commit_sequence
                    || edge.next_sequence() != expected_next
                    || edge.begin_offset() != original.physical_bytes || edge.end_offset() != expected_bytes
                {
                    return Err(CanaryPrefixCause::Binding);
                }
                let [record] = edge.transaction().records() else {
                    return Err(CanaryPrefixCause::Binding);
                };
                if coordinator.observe_canary_bootstrap_marker_original(edge.transaction(), record)
                    .map_err(CanaryPrefixCause::Primary)?.as_ref() != Some(marker.bytes())
                {
                    return Err(CanaryPrefixCause::Binding);
                }
                found = true;
            }
            transactions = transactions.checked_add(1).ok_or(CanaryPrefixCause::Binding)?;
        }
        cursor.finish().map_err(CanaryPrefixCause::History)?;
        if !found || transactions != original.transactions.checked_add(1).ok_or(CanaryPrefixCause::Binding)?
            || records != original.records || <[u8; 32]>::from(hash.finalize()) != original.digest
        {
            return Err(CanaryPrefixCause::Binding);
        }
        coordinator.native_metadata_readback_cut(std::path::Path::new("/var/lib/aos/sandbox-storage"))
            .map_err(CanaryPrefixCause::Primary)
    }

    fn observe_selected_owner_posts_v2(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        native: Option<&mut StorageNativeIssuanceLedgerV1>,
        startup: Option<&mut crate::activation::StorageOriginalWorkerStartupV3>,
        gate: &RepairWorkerDispatchGate,
        verifier: &HostRootExportPeerVerifier,
    ) {
        let startup = startup.ok_or(CanaryPrefixCause::MissingProducer)
            .and_then(|startup| startup.recheck().map_err(CanaryPrefixCause::Startup));
        self.retain_selected_post_v2(startup);
        if let Some(inputs) = self.public_inputs.as_mut() {
            let public = if inputs.ready && inputs.compared_delivery.is_none() {
                inputs.recheck().map_err(|()| CanaryPrefixCause::PublicTrust)
            } else {
                inputs.compare_returned_originals().map_err(CanaryPrefixCause::PublicObservation)
            };
            self.retain_selected_post_v2(public);
        }
        if self.job.is_some() {
            let job = self.recheck_selected_job_bytes_v2();
            self.retain_selected_post_v2(job);
        }
        if self.pending_receive.as_ref().is_some_and(Result::is_ok) {
            let peer = self.compare_selected_host_v2(verifier);
            self.retain_selected_post_v2(peer);
        }
        let primary = coordinator.native_metadata_readback_cut(std::path::Path::new("/var/lib/aos/sandbox-storage"))
            .map_err(CanaryPrefixCause::Primary).and_then(|actual| {
                let expected = if self.marker_commit.as_ref().is_some_and(Result::is_ok) {
                    self.marker_readback.as_ref().and_then(|result| result.as_ref().ok()).copied()
                } else {
                    self.prepared_marker.as_ref().and_then(|result| result.as_ref().ok()).map(|marker| {
                        let saved = marker.primary_coordinates();
                        (saved.2, aos_sandbox_core::ObjectDigest::from_bytes(saved.3))
                    })
                }.ok_or(CanaryPrefixCause::Closed)?;
                if actual != expected {
                    return Err(CanaryPrefixCause::Binding);
                }
                Ok(())
            });
        self.retain_selected_post_v2(primary);
        if let Some(native) = native {
            let cut = native.operator_terminal_readback_cut_v4().map_err(CanaryPrefixCause::Native)
                .and_then(|cut| {
                    if self.native_coordinates.as_ref().and_then(|result| result.as_ref().ok()) != Some(&cut) {
                        return Err(CanaryPrefixCause::Binding);
                    }
                    Ok(())
                });
            self.retain_selected_post_v2(cut);
        }
        if let Some(sidecar) = self.sidecar.as_ref() {
            let sidecar = sidecar.validate_held_root_owned_at(std::path::Path::new("/var/lib/aos/sandbox-storage"),
                "storage-canary-export.journal").map_err(CanaryPrefixCause::Sidecar);
            self.retain_selected_post_v2(sidecar);
        }
        let held = self.hold_identity.ok_or(CanaryPrefixCause::Closed)
            .and_then(|identity| gate.require_canary_hold(&identity).map_err(|()| CanaryPrefixCause::Binding));
        self.retain_selected_post_v2(held);
        if self.publisher_reply.as_ref().is_some_and(Result::is_ok) {
            let peer = self.compare_publisher_reply_origin_v2();
            self.retain_selected_post_v2(peer);
        }
        // This sample is unconditional, including schema poison and action Err.
        let clock = self.require_selected_clock_v2();
        self.retain_selected_post_v2(clock);
        if self.first_failure.is_none() {
            if let Some(inputs) = self.public_inputs.as_mut() {
                inputs.finish_comparison();
            }
        }
    }

    /// Completes failed pre-publication observations without another effect.
    pub(super) fn finish_selected_runtime_observations_v2(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        native: Option<&mut StorageNativeIssuanceLedgerV1>,
        startup: Option<&mut crate::activation::StorageOriginalWorkerStartupV3>,
        gate: &RepairWorkerDispatchGate,
        verifier: &HostRootExportPeerVerifier,
    ) {
        let observation = CanarySelectedObservationV2 {
            owner: self,
            completed: false
        };
        observation.owner.observe_selected_owner_posts_v2(coordinator, native, startup, gate, verifier);
    }

    /// Authenticates selected delivery before enabling any wider native receive.
    pub(super) fn prepare_selected_receiver_v2(
        &mut self,
        startup: Option<&mut crate::activation::StorageOriginalWorkerStartupV3>,
    ) -> bool {
        if self.first_failure.is_some() || self.attempted || self.public_inputs.is_some() {
            return false;
        }
        self.selected_phase = Some(CanarySelectedPhaseV2::Capturing);
        self.public_inputs = Some(CanaryPublicInputsV2::new());
        let mut startup = startup;
        let action = (|| {
            startup.as_deref_mut().ok_or(CanaryPrefixCause::MissingProducer)?
                .recheck().map_err(CanaryPrefixCause::Startup)?;
            self.public_inputs.as_mut().ok_or(CanaryPrefixCause::Closed)?
                .capture_once().map_err(|()| CanaryPrefixCause::PublicTrust)
        })();
        self.retain_selected_post_v2(action);

        let original = startup.as_deref_mut().ok_or(CanaryPrefixCause::MissingProducer)
            .and_then(|startup| startup.recheck().map_err(CanaryPrefixCause::Startup));
        self.retain_selected_post_v2(original);
        // Both native samples run even when an earlier original refused. This
        // pre-request timestamp is DATA, not the signed job's authority window.
        let boot = KernelBootId::current().map_err(CanaryPrefixCause::Kernel);
        let now = boottime_now_nanoseconds().map_err(CanaryPrefixCause::Clock);
        match boot {
            Ok(boot) => self.receiver_boot = Some(boot.into_bytes()),
            Err(error) => self.retain_selected_post_v2(Err(error)),
        }
        match now {
            Ok(now) => self.receiver_started = Some(now),
            Err(error) => self.retain_selected_post_v2(Err(error)),
        }
        if self.first_failure.is_some() {
            self.selected_phase = Some(CanarySelectedPhaseV2::Failed);
            return false;
        }
        if let Some(inputs) = self.public_inputs.as_mut() {
            inputs.finish_comparison();
        }
        true
    }

    /// Parks the whole native admission Result before classification or posts.
    pub(super) fn accept_selected_v2(
        &mut self,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener,
    ) -> bool {
        if self.selected_phase != Some(CanarySelectedPhaseV2::Capturing)
            || self.first_failure.is_some() || self.attempted || self.selected_socket.is_some()
            || self.public_inputs.as_ref().is_none_or(|inputs| !inputs.ready)
        {
            return false;
        }
        self.attempted = true;
        self.selected_socket = Some(listener.accept_descriptor_subject_retaining());
        match self.selected_socket.as_mut() {
            Some(Ok(socket)) => {
                socket.begin_original_retention_v1();
                true
            }
            _ => {
                self.retain_selected_post_v2(Err(CanaryPrefixCause::Binding));
                false
            }
        }
    }

    /// Retains the raw receive Result before classification and owner posts.
    pub(super) fn receive_selected_once_v2(&mut self) -> bool {
        if self.pending_receive.is_some() || self.record.is_some()
            || self.first_failure.is_some()
        {
            return false;
        }
        let Some(Ok(socket)) = self.selected_socket.as_mut() else {
            return false;
        };
        self.pending_receive = Some(socket.receive_optional_descriptor_reply_retaining(418));
        match self.pending_receive.as_ref() {
            Some(Ok(record)) if record.payload().len() == 418
                && record.descriptors().len() == 1 => true,
            _ => {
                // The owning transport failure and any partial rights remain
                // in pending_receive. No second receive or default fallback.
                self.retain_selected_post_v2(Err(CanaryPrefixCause::Binding));
                false
            }
        }
    }

    fn selected_record_v2(&self) -> Result<&ReceivedDescriptorRecord, CanaryPrefixCause> {
        self.pending_receive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)
    }

    fn retain_selected_post_v2(&mut self, result: Result<(), CanaryPrefixCause>) {
        if let Err(error) = result {
            self.selected_phase = Some(CanarySelectedPhaseV2::Failed);
            if self.first_failure.is_none() {
                self.first_failure = Some(error);
            } else if let Some(slot) = self.selected_post_debt.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(error);
            } else {
                // Every closed phase reserves this fixed debt array before
                // crossing. Abort before resident originals can unwind/drop.
                std::process::abort();
            }
        }
    }

    /// Captures independent trust and the same sealed full job before effects.
    fn capture_selected_job_v2(&mut self) -> Result<(), CanaryPrefixCause> {
        if self.public_inputs.as_ref().is_none_or(|inputs| !inputs.ready)
            || self.job_request.is_some() || self.job.is_some()
        {
            return Err(CanaryPrefixCause::Closed);
        }
        let record = self.pending_receive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        self.job_request = Some(
            aos_sandbox_protocol::storage_root_export::StorageCanaryJobRequestV2::decode(record.payload())
                .map_err(CanaryPrefixCause::Request)?,
        );
        let request = self.job_request.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let width = usize::try_from(request.job_bytes).map_err(|_| CanaryPrefixCause::Binding)?;
        require_original_job_descriptor_v2(record, width)?;
        self.job_bytes.try_reserve_exact(width).map_err(|_| CanaryPrefixCause::Binding)?;
        self.job_readback.try_reserve_exact(width).map_err(|_| CanaryPrefixCause::Binding)?;
        self.job_bytes.resize(width, 0);
        self.job_readback.resize(width, 0);
        let [descriptor] = record.descriptors() else {
            return Err(CanaryPrefixCause::Binding);
        };
        aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
            descriptor, &mut self.job_bytes,
        ).map_err(CanaryPrefixCause::JobRead)?;
        let public = self.public_inputs.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let purpose = public.purpose.as_ref().ok_or(CanaryPrefixCause::PublicTrust)?;
        self.job = Some(aos_sandbox_protocol::host_canary_job::decode_host_canary_job_v1(
            &self.job_bytes, &purpose.approval_pin(),
        ).map_err(CanaryPrefixCause::Job)?);
        let job = self.job.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let genesis = public.genesis.as_ref().ok_or(CanaryPrefixCause::PublicTrust)?;
        if job.node_id != genesis.node || job.digest != request.request.job_digest
            || job.nonce != request.request.nonce || job.boot_id != request.request.boot_id
            || job.deadline != request.request.deadline_boottime_nanoseconds
            || Some(job.boot_id) != self.receiver_boot
        {
            return Err(CanaryPrefixCause::Binding);
        }
        self.request = Some(request.request);
        self.require_selected_clock_v2()?;
        self.recheck_selected_job_bytes_v2()
    }

    fn recheck_selected_job_bytes_v2(&mut self) -> Result<(), CanaryPrefixCause> {
        let record = self.pending_receive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CanaryPrefixCause::Closed)?;
        let request = self.job_request.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let width = usize::try_from(request.job_bytes).map_err(|_| CanaryPrefixCause::Binding)?;
        require_original_job_descriptor_v2(record, width)?;
        if self.job_readback.len() != width || self.job_bytes.len() != width {
            return Err(CanaryPrefixCause::Binding);
        }
        let [descriptor] = record.descriptors() else {
            return Err(CanaryPrefixCause::Binding);
        };
        aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
            descriptor, &mut self.job_readback,
        ).map_err(CanaryPrefixCause::JobRead)?;
        if self.job_readback != self.job_bytes {
            return Err(CanaryPrefixCause::Binding);
        }
        Ok(())
    }

    fn require_selected_clock_v2(&self) -> Result<(), CanaryPrefixCause> {
        let boot = KernelBootId::current();
        let now = boottime_now_nanoseconds();
        let (boot, now) = match (boot, now) {
            (Ok(boot), Ok(now)) => (boot.into_bytes(), now),
            (Err(boot), Err(boottime)) => return Err(CanaryPrefixCause::PairedClock {
                boot,
                boottime
            }),
            (Err(error), Ok(_)) => return Err(CanaryPrefixCause::Kernel(error)),
            (Ok(_), Err(error)) => return Err(CanaryPrefixCause::Clock(error)),
        };
        if let Some(job) = self.job.as_ref() {
            if boot != job.boot_id || now < job.not_before || now >= job.deadline {
                return Err(CanaryPrefixCause::Binding);
            }
        } else {
            let started = self.receiver_started.ok_or(CanaryPrefixCause::Binding)?;
            let deadline = started.checked_add(5_000_000_000).ok_or(CanaryPrefixCause::Binding)?;
            if Some(boot) != self.receiver_boot || now < started || now >= deadline {
                return Err(CanaryPrefixCause::Binding);
            }
        }
        Ok(())
    }

    pub(super) fn observe_original(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        native: Option<&mut StorageNativeIssuanceLedgerV1>,
        gate: &RepairWorkerDispatchGate,
        broker_instance_id: &[u8; 16],
        verifier: &HostRootExportPeerVerifier,
    ) {
        // This instance is never reopened, including after a caught unwind.
        let observation = CanaryObservation { owner: self };
        let result = observation.owner.observe_inner(
            coordinator, native, gate, broker_instance_id, verifier,
        );
        observation.owner.first_failure = Some(match result {
            Ok(()) => CanaryPrefixCause::MissingProducer,
            Err(cause) => cause,
        });
    }

    fn observe_inner(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        native: Option<&mut StorageNativeIssuanceLedgerV1>,
        gate: &RepairWorkerDispatchGate,
        broker_instance_id: &[u8; 16],
        verifier: &HostRootExportPeerVerifier,
    ) -> Result<(), CanaryPrefixCause> {
        let socket = self.socket.as_mut().ok_or(CanaryPrefixCause::Closed)?;
        let record = self.record.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        socket.validate_received_origin(record).map_err(CanaryPrefixCause::Socket)?;
        let execution = verifier.verify_connection(socket.peer())
            .map_err(|()| CanaryPrefixCause::Binding)?;
        verifier.verify_record(execution, socket.peer(), record.subject())
            .map_err(|()| CanaryPrefixCause::Binding)?;
        if !record.descriptors().is_empty() {
            return Err(CanaryPrefixCause::Binding);
        }
        self.request = Some(StorageCanaryExportRequestV1::decode(record.payload())
            .map_err(CanaryPrefixCause::Request)?);
        self.require_original_clock()?;

        let request = self.request.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let request_digest = request.digest().map_err(CanaryPrefixCause::Request)?;
        let mut identity = Sha256::new();
        identity.update(HOLD_DOMAIN);
        identity.update(broker_instance_id);
        identity.update(request_digest);
        let identity = identity.finalize().into();
        self.hold_identity = Some(identity);
        gate.begin_canary_hold(identity).map_err(|()| CanaryPrefixCause::Binding)?;

        self.capture_primary(coordinator)?;
        self.require_original_clock()?;
        let native = native.ok_or(CanaryPrefixCause::MissingProducer)?;
        self.capture_native(native, coordinator)?;
        self.require_original_clock()?;
        self.capture_sidecar()?;
        self.require_original_clock()?;
        gate.require_canary_hold(&identity).map_err(|()| CanaryPrefixCause::Binding)?;
        let socket = self.socket.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let record = self.record.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        verifier.verify_record(execution, socket.peer(), record.subject())
            .map_err(|()| CanaryPrefixCause::Binding)?;

        // All observations are DATA. In particular, marker absence does not
        // authenticate an unused cut after whole-primary rollback. No effect,
        // marker write, positive reply or ACK continuation exists in this cut.
        Ok(())
    }

    fn require_original_clock(&self) -> Result<(), CanaryPrefixCause> {
        let request = self.request.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let boot = KernelBootId::current().map_err(CanaryPrefixCause::Kernel)?;
        let now = boottime_now_nanoseconds().map_err(CanaryPrefixCause::Clock)?;
        request.deadline_boottime_nanoseconds.checked_sub(now)
            .filter(|remaining| *remaining != 0 && *remaining <= MAXIMUM_ORIGINAL_NANOSECONDS)
            .ok_or(CanaryPrefixCause::Binding)?;
        if boot.into_bytes() != request.boot_id {
            return Err(CanaryPrefixCause::Binding);
        }
        Ok(())
    }

    fn capture_primary(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
    ) -> Result<(), CanaryPrefixCause> {
        let mut history = coordinator.borrow_canary_bootstrap_primary_original()
            .map_err(CanaryPrefixCause::Primary)?;
        self.require_original_clock()?;
        let limits = history.opened_limits();
        let physical_bytes = history.physical_bytes();
        let next_sequence = history.next_sequence();
        let mut hash = Sha256::new();
        hash.update(PRIMARY_HISTORY_DOMAIN);
        let mut transactions = 0usize;
        let mut records = 0usize;
        let mut cursor = history.replay().map_err(CanaryPrefixCause::PrimaryHistory)?;
        while let Some(edge) = cursor.next_edge().map_err(CanaryPrefixCause::History)? {
            self.require_original_clock()?;
            hash_edge(&mut hash, &edge);
            transactions = transactions.checked_add(1).ok_or(CanaryPrefixCause::Binding)?;
            records = records.checked_add(edge.transaction().records().len())
                .ok_or(CanaryPrefixCause::Binding)?;
            for record in edge.transaction().records() {
                if let Some(marker) = coordinator.observe_canary_bootstrap_marker_original(
                    edge.transaction(), record,
                ).map_err(CanaryPrefixCause::Primary)? {
                    if self.marker.is_some() {
                        return Err(CanaryPrefixCause::Binding);
                    }
                    self.marker = Some(marker);
                }
            }
        }
        cursor.finish().map_err(CanaryPrefixCause::History)?;
        self.primary = Some(OriginalHistoryCut {
            digest: hash.finalize().into(),
            limits,
            physical_bytes,
            next_sequence,
            transactions,
            records,
        });
        Ok(())
    }

    fn capture_native(
        &mut self,
        native: &mut StorageNativeIssuanceLedgerV1,
        coordinator: &StorageAdmissionCoordinator,
    ) -> Result<(), CanaryPrefixCause> {
        let mut history = native.borrow_canary_bootstrap_native_original(coordinator)
            .map_err(CanaryPrefixCause::Native)?;
        self.require_original_clock()?;
        let limits = history.opened_limits();
        let physical_bytes = history.physical_bytes();
        let next_sequence = history.next_sequence();
        let mut hash = Sha256::new();
        hash.update(NATIVE_HISTORY_DOMAIN);
        let mut transactions = 0usize;
        let mut records = 0usize;
        let mut cursor = history.replay().map_err(CanaryPrefixCause::History)?;
        while let Some(edge) = cursor.next_edge().map_err(CanaryPrefixCause::History)? {
            self.require_original_clock()?;
            hash_edge(&mut hash, &edge);
            transactions = transactions.checked_add(1).ok_or(CanaryPrefixCause::Binding)?;
            records = records.checked_add(edge.transaction().records().len())
                .ok_or(CanaryPrefixCause::Binding)?;
        }
        cursor.finish().map_err(CanaryPrefixCause::History)?;
        self.native = Some(OriginalHistoryCut {
            digest: hash.finalize().into(),
            limits,
            physical_bytes,
            next_sequence,
            transactions,
            records,
        });
        Ok(())
    }

    fn capture_sidecar(&mut self) -> Result<(), CanaryPrefixCause> {
        // Existing-only is essential. Missing/torn/ambiguous names retain the
        // actual refusal; this method cannot create, repair or settle a pair.
        self.require_original_clock()?;
        let (journal, recovery) = Journal::open_existing_protected_at(
            std::path::Path::new("/var/lib/aos/sandbox-storage"),
            "storage-canary-export.journal",
            SIDECAR_LIMITS,
        ).map_err(CanaryPrefixCause::Sidecar)?;
        self.sidecar = Some(journal);
        self.sidecar_recovery = Some(recovery);
        self.require_original_clock()?;
        let journal = self.sidecar.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let mut history = journal.capture_storage_canary_export_history_v1()
            .map_err(CanaryPrefixCause::PrimaryHistory)?;
        self.require_original_clock()?;
        let limits = history.opened_limits();
        let physical_bytes = history.physical_bytes();
        let next_sequence = history.next_sequence();
        let mut hash = Sha256::new();
        hash.update(SIDECAR_HISTORY_DOMAIN);
        let mut count = 0usize;
        let mut previous = [0u8; 1040];
        let mut original_key = None;
        let mut phase_three_cut = None;
        let mut cursor = history.replay().map_err(CanaryPrefixCause::PrimaryHistory)?;
        while let Some(edge) = cursor.next_edge().map_err(CanaryPrefixCause::PrimaryHistory)? {
            self.require_original_clock()?;
            if count >= self.sidecar_rows.len() {
                return Err(CanaryPrefixCause::Binding);
            }
            let [record] = edge.transaction().records() else {
                return Err(CanaryPrefixCause::Binding);
            };
            let value: [u8; 1040] = record.value()
                .and_then(|value| value.try_into().ok())
                .ok_or(CanaryPrefixCause::Binding)?;
            // Park each actual row before any private phase/body comparison.
            self.sidecar_rows[count] = Some(value);
            require_sidecar_row(&value, count, &previous, record.key(), phase_three_cut)?;
            let key: [u8; 32] = record.key().try_into()
                .map_err(|_| CanaryPrefixCause::Binding)?;
            if original_key.is_some_and(|original| original != key) {
                return Err(CanaryPrefixCause::Binding);
            }
            original_key = Some(key);
            let mut transaction = Sha256::new();
            transaction.update(SIDECAR_TRANSACTION_DOMAIN);
            transaction.update(Sha256::digest(previous));
            transaction.update(value);
            let transaction = transaction.finalize();
            if edge.transaction().id().as_slice() != &transaction[..16] {
                return Err(CanaryPrefixCause::Binding);
            }
            hash_canary_edge(&mut hash, &edge);
            if count == 2 {
                // The digest excludes phase4, so its stored confirmation does
                // not require a self-digest fixpoint. Only hash state is copied.
                phase_three_cut = Some(hash.clone().finalize().into());
            }
            previous = value;
            count += 1;
        }
        cursor.finish().map_err(CanaryPrefixCause::PrimaryHistory)?;
        self.sidecar_cut = Some(OriginalHistoryCut {
            digest: hash.finalize().into(),
            limits,
            physical_bytes,
            next_sequence,
            transactions: count,
            records: count,
        });
        // Even four exact phases remain historical DATA. No resident worker,
        // independent floor or authenticated bank is synthesized on restart.
        Ok(())
    }
}

/// Fences the resident selected originals on an error or caught unwind.
struct CanarySelectedObservationV2<'owner> {
    owner: &'owner mut CanaryExportHeldV1,
    completed: bool,
}

impl Drop for CanarySelectedObservationV2<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.selected_phase = Some(CanarySelectedPhaseV2::Failed);
            self.owner.first_failure.get_or_insert(CanaryPrefixCause::Interrupted);
            if let Some(Ok(socket)) = &mut self.owner.selected_socket { socket.close(); }
            if let Some(Ok(socket)) = &mut self.owner.publisher_socket { socket.close(); }
        }
    }
}

// A caught unwind cannot leave the selected socket usable. The real panic
// propagates unchanged; Interrupted is a negative marker, not its cause.
struct CanaryObservation<'owner> {
    owner: &'owner mut CanaryExportHeldV1,
}

impl Drop for CanaryObservation<'_> {
    fn drop(&mut self) {
        if self.owner.first_failure.is_none() {
            self.owner.first_failure = Some(CanaryPrefixCause::Interrupted);
        }
        if let Some(socket) = &mut self.owner.socket {
            socket.close();
        }
    }
}

impl Drop for CanaryExportHeldV1 {
    fn drop(&mut self) {
        if let Some(Ok(socket)) = &mut self.selected_socket { socket.close(); }
        if let Some(Ok(socket)) = &mut self.publisher_socket { socket.close(); }
        if let Some(socket) = &mut self.socket {
            socket.close();
        }
        // This shuts down an original channel, not a worker or durable debt.
        // No drop path settles the held gate, writes state or claims Drain.
    }
}

/// Checks the original transferred job description, never adopts a caller FD.
fn require_original_job_descriptor_v2(
    record: &ReceivedDescriptorRecord,
    width: usize,
) -> Result<(), CanaryPrefixCause> {
    use rustix::fs::{FileType, OFlags, SealFlags};
    let [descriptor] = record.descriptors() else { return Err(CanaryPrefixCause::Binding); };
    let stat = rustix::fs::fstat(descriptor).map_err(CanaryPrefixCause::Descriptor)?;
    let flags = rustix::fs::fcntl_getfl(descriptor).map_err(CanaryPrefixCause::Descriptor)?;
    let seals = rustix::fs::fcntl_get_seals(descriptor).map_err(CanaryPrefixCause::Descriptor)?;
    if !(1032..=aos_sandbox_protocol::host_canary_job::MAXIMUM_HOST_CANARY_JOB_BYTES).contains(&width)
        || stat.st_size != width as i64 || stat.st_uid != 0 || stat.st_gid != 0 || stat.st_nlink != 0
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || flags & OFlags::ACCMODE != OFlags::RDONLY || flags.contains(OFlags::PATH)
        || !seals.contains(SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE)
    {
        return Err(CanaryPrefixCause::Binding);
    }
    Ok(())
}

fn hash_edge(hash: &mut Sha256, edge: &StorageNativeIssuanceEdgeDataV1<'_>) {
    hash.update(edge.begin_sequence().to_be_bytes());
    hash.update(edge.commit_sequence().to_be_bytes());
    hash.update(edge.next_sequence().to_be_bytes());
    hash.update(edge.begin_offset().to_be_bytes());
    hash.update(edge.end_offset().to_be_bytes());
    hash.update(edge.transaction().id());
    hash.update((edge.transaction().records().len() as u64).to_be_bytes());
    for record in edge.transaction().records() {
        hash.update([record.namespace() as u8]);
        hash.update((record.key().len() as u64).to_be_bytes());
        hash.update(record.key());
        match record.value() {
            Some(value) => {
                hash.update([1]);
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value);
            }
            None => hash.update([0]),
        }
    }
}

fn hash_canary_edge(
    hash: &mut Sha256,
    edge: &aos_sandbox::journal::StorageCanaryExportEdgeDataV1<'_>,
) {
    hash.update(edge.begin_sequence().to_be_bytes());
    hash.update(edge.commit_sequence().to_be_bytes());
    hash.update(edge.next_sequence().to_be_bytes());
    hash.update(edge.begin_offset().to_be_bytes());
    hash.update(edge.end_offset().to_be_bytes());
    hash.update(edge.transaction().id());
    for record in edge.transaction().records() {
        hash.update(record.key());
        if let Some(value) = record.value() {
            hash.update(value);
        }
    }
}

fn require_sidecar_row(
    value: &[u8; 1040],
    index: usize,
    previous: &[u8; 1040],
    key: &[u8],
    phase_three_cut: Option<[u8; 32]>,
) -> Result<(), CanaryPrefixCause> {
    let phase = u16::try_from(index + 1).map_err(|_| CanaryPrefixCause::Binding)?;
    if &value[..8] != b"AOSRCH01"
        || value[8..10] != 1u16.to_be_bytes()
        || value[10..12] != phase.to_be_bytes()
        || value[12..16] != 1040u32.to_be_bytes()
        || value[1034..] != [0; 6]
        || index > 3
    {
        return Err(CanaryPrefixCause::Binding);
    }
    let request = StorageCanaryExportRequestV1::decode(&value[16..418])
        .map_err(CanaryPrefixCause::Request)?;
    if index > 0 && value[16..418] != previous[16..418] {
        return Err(CanaryPrefixCause::Binding);
    }
    if index == 0 {
        return if value[418..].iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err(CanaryPrefixCause::Binding)
        };
    }
    let response = StorageCanaryExportResponseV1::decode(&value[418..658])
        .map_err(CanaryPrefixCause::Request)?;
    if response.nonce != request.nonce
        || response.held_identity.as_slice() != key
        || response.request_digest != request.digest().map_err(CanaryPrefixCause::Request)?
        || (index > 1 && value[418..658] != previous[418..658])
    {
        return Err(CanaryPrefixCause::Binding);
    }
    if index == 1 {
        return if value[658..].iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err(CanaryPrefixCause::Binding)
        };
    }
    let acknowledgment = StorageCanaryExportAcknowledgmentV1::decode(&value[658..850])
        .map_err(CanaryPrefixCause::Request)?;
    if acknowledgment.nonce != request.nonce
        || acknowledgment.request_digest != response.request_digest
        || acknowledgment.held_identity != response.held_identity
        || acknowledgment.measured_response_digest != response.digest()
            .map_err(CanaryPrefixCause::Request)?
        || acknowledgment.deadline_boottime_nanoseconds != request.deadline_boottime_nanoseconds
        || (index > 2 && value[658..850] != previous[658..850])
    {
        return Err(CanaryPrefixCause::Binding);
    }
    if index == 2 {
        return if value[850..].iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err(CanaryPrefixCause::Binding)
        };
    }
    let confirmation = StorageCanaryExportConfirmationV1::decode(&value[850..1034])
        .map_err(CanaryPrefixCause::Request)?;
    if confirmation.nonce != request.nonce
        || confirmation.request_digest != response.request_digest
        || confirmation.held_identity != response.held_identity
        || confirmation.generation_zero_digest != acknowledgment.generation_zero_digest
        || Some(confirmation.accepted_native_cut_digest) != phase_three_cut
        || confirmation.deadline_boottime_nanoseconds != request.deadline_boottime_nanoseconds
    {
        return Err(CanaryPrefixCause::Binding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slots_do_not_contain_a_floor_or_completed_observation() {
        let owner = CanaryExportHeldV1::new();

        assert!(owner.is_unused());
        assert!(owner.primary.is_none());
        assert!(owner.native.is_none());
        assert!(owner.marker.is_none());
        assert!(owner.first_failure.is_none());
    }

    #[test]
    fn interrupted_observation_is_permanently_negative_without_an_original_socket() {
        let mut owner = CanaryExportHeldV1::new();
        owner.attempted = true;

        drop(CanaryObservation { owner: &mut owner });

        assert!(!owner.is_unused());
        assert!(matches!(owner.first_failure, Some(CanaryPrefixCause::Interrupted)));
        assert!(owner.record.is_none());
    }

    #[test]
    fn sidecar_recipe_retains_all_eight_fixed_ceilings_as_data() {
        assert_eq!(SIDECAR_LIMITS.maximum_journal_bytes, 16_384);
        assert_eq!(SIDECAR_LIMITS.maximum_record_bytes, 2048);
        assert_eq!(SIDECAR_LIMITS.maximum_key_bytes, 32);
        assert_eq!(SIDECAR_LIMITS.maximum_records_per_transaction, 1);
        assert_eq!(SIDECAR_LIMITS.maximum_transaction_bytes, 4096);
        assert_eq!(SIDECAR_LIMITS.maximum_transactions, 4);
        assert_eq!(SIDECAR_LIMITS.maximum_materialized_bytes, 2048);
        assert_eq!(SIDECAR_LIMITS.maximum_materialized_records, 1);
    }
}
