//! Original Controller/PID1 custody of issue-only Source successor inputs.
//!
//! The selected profile, immutable unit and fresh effective PID1 delivery are
//! joined before private seed access. Original directory/file descriptions
//! and final zeroizing buffers stay in the caller's parked owner on failure.
//! No supplied path, FD, property map or signing key constructs this owner.

use aos_sandbox_protocol::publisher_project_authorization::{
    PinnedPublisherProjectAuthorizationIssuerV2,
};

use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_linux::inventory::{MountId, ReadOnlyDirectorySnapshot};
use aos_sandbox_linux::protected_file::{ExactReadError, read_exact_positioned};
use aos_systemd_client::{OwnedValue, Value};
use ed25519_dalek::{Signer as _, SigningKey};
use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, openat2};
use zeroize::{Zeroize as _, Zeroizing};

use super::ProductionControllerNormalRootProfileV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use aos_sandbox_protocol::controller_source_seed::PinnedControllerSourceTreeSeedIssuerV1;
use aos_sandbox_ledger_replay::successor::{
    SourceSuccessorApprovalDataV2, SourceSuccessorIntentDataV2, signature_message,
};
mod executable;
mod native;

use executable::IssueExecutableOriginalV1;
use aos_sandbox_broker::immutable_image::ImmutableFileRevalidationOriginalV1;
use native::CredentialNativePassV1;
use crate::normal_root::{NormalRootStartupErrorV1, service};
use crate::policy_compiler::SourceSuccessorSigningCutV2;
use crate::policy_compiler::SourceSuccessorSigningCutV3;

enum SourceSuccessorSigningRecipeV3<'cut, 'controller, 'source, 'completed, 'flight> {
    StrictV2(&'cut SourceSuccessorSigningCutV2<'cut, 'controller, 'source, 'completed, 'flight>),
    ProjectV3(&'cut SourceSuccessorSigningCutV3<'cut, 'controller, 'source, 'completed, 'flight>),
}

impl SourceSuccessorSigningRecipeV3<'_, '_, '_, '_, '_> {
    fn recheck(&self, body: &[u8], intent: SourceSuccessorIntentDataV2, generation: u64) -> Result<(), SourceGenesisErrorV1> {
        match self {
            Self::StrictV2(cut) => cut.recheck_before_signature(body, intent, generation),
            Self::ProjectV3(cut) => cut.recheck_before_signature(body, intent, generation),
        }
    }
}

use crate::systemd_property_data;

const DIRECTORY: &str = "/run/credentials/aos-sandboxd.service";
const NAMES: [&str; 4] = [
    "controller-source-successor-admin-seed-v2",
    "controller-source-successor-intent-v2",
    "controller-source-tree-seed-issuer-v1",
    "project-authorization-issuer-v2",
];
const SOURCES: [&str; 2] = [
    "/run/credentials/@system/controller-source-successor-admin-seed-v2",
    "/run/credentials/@system/controller-source-successor-intent-v2",
];
const WIDTHS: [usize; 4] = [32, 80, 80, 80];
const CONTEXT: &[u8] = b"system_u:object_r:aos_sandbox_controller_credential_t";
const MAXIMUM_OBSERVATIONS: usize = 24;
// This selected issue recipe admits at most one 64KiB materialized aggregate
// before native body growth. Larger/hostile replies retain the same original
// native refusal. Ordinary/default Systemd observations keep their full lane.
const MATERIALIZATION_BYTES: usize = 64 * 1024;
// Initial delivery and its full recheck coexist until that comparison succeeds.
const OBSERVER_PEAK_ROWS: usize = 2;
const UNIT_PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];
const PROPERTIES: &[&str] = &[
    "Type", "Restart", "ExecStart", "ExecStartPre", "ExecStartPost",
    "LoadCredential", "LoadCredentialEncrypted", "SetCredential",
    "SetCredentialEncrypted", "ImportCredential", "ImportCredentialEx",
];

/// Reports fixed issue-purpose custody refusal without displaying secret bytes.
#[derive(Debug, thiserror::Error)]
pub enum SourceSuccessorCredentialErrorV2 {
    /// The same original selected Controller/PID1 owner no longer matches.
    #[error("original Source successor Controller profile differs")]
    Profile(#[from] NormalRootStartupErrorV1),
    /// The same bounded PID1 receiver retained a constructor/native refusal.
    #[error("original Source successor bounded PID1 observation refused")]
    Observer(#[from] aos_systemd_client::FixedPid1PropertyErrorV1),
    /// Original descriptor or protected fixed-name inspection failed.
    #[error("original Source successor credential I/O failed")]
    Io(#[from] io::Error),
    /// Required fixed delivery, schema, backing, identity or role differs.
    #[error("original Source successor credential custody differs")]
    Rejected,
    /// A final retained buffer was incomplete or had trailing bytes.
    #[error("original Source successor credential read differs: {0:?}")]
    Read(ExactReadError),
    /// Canonical DATA, signature or the borrowed original signing cut differs.
    #[error("Source successor canonical approval differs")]
    Approval(#[from] SourceGenesisErrorV1),
}

impl From<aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2> for SourceSuccessorCredentialErrorV2 {
    fn from(error: aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2) -> Self {
        Self::Approval(SourceGenesisErrorV1::from(error))
    }
}

impl From<rustix::io::Errno> for SourceSuccessorCredentialErrorV2 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(error.raw_os_error()))
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    bytes: u64,
    mtime: (i64, u64),
    ctime: (i64, u64),
    mount: MountId,
}

impl Identity {

    fn require(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
        kind: FileType,
        mode: u32,
    ) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if FileType::from_raw_mode(self.mode) != kind
            || self.mode & 0o7777 != mode
            || self.uid != profile.original.schema().identities[0]
            || self.gid != profile.original.schema().identities[1]
            || self.device == 0
            || self.inode == 0
        {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        Ok(())
    }
}

/// Retains genuine issue-only origin and original private input descriptions.
///
/// Fields remain closed. Parking is available only on the already admitted
/// original Controller profile; bytes cannot be converted into a live owner.
pub struct SourceSuccessorCredentialCustodyV2<'profile> {
    profile: &'profile ProductionControllerNormalRootProfileV1,
    directory_path: Option<File>,
    directory_reader: Option<File>,
    files: Vec<File>,
    directory_identity: Option<Identity>,
    directory_snapshot: Option<ReadOnlyDirectorySnapshot>,
    identities: Vec<Identity>,
    executable: IssueExecutableOriginalV1,
    native_pass: Option<CredentialNativePassV1>,
    fragment_currentness: Option<ImmutableFileRevalidationOriginalV1>,
    observer: aos_systemd_client::FixedPid1PropertyArchiveV1,
    observer_preparation: Option<Result<(), aos_systemd_client::FixedPid1PropertyErrorV1>>,
    observations: Vec<(Arc<Vec<OwnedValue>>, Arc<Vec<OwnedValue>>)>,
    observer_settlements: [Option<Result<(), aos_systemd_client::FixedPid1PropertyErrorV1>>; MAXIMUM_OBSERVATIONS],
    buffers: Vec<[Zeroizing<Vec<u8>>; 4]>,
    admitted: bool,
    ended: bool,
}

impl ProductionControllerNormalRootProfileV1 {
    pub(crate) fn source_successor_issue_receiving_demand_v2<Outer>()
        -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1>
    {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_broker::controller_receiving::ControllerReceivingErrorV1 as Error;
        use aos_systemd_client::FixedPid1PropertyArchiveV1 as Archive;

        let invalid = || Error::Conflict;
        let observer = Archive::fixed_property_geometry_v1(MATERIALIZATION_BYTES)
            .map_err(|_| invalid())?;
        let raw = WIDTHS.iter().try_fold(0usize, |sum, width| sum.checked_add(*width))
            .ok_or_else(invalid)?;
        let retained_slots = MAXIMUM_OBSERVATIONS.checked_next_power_of_two()
            .ok_or_else(invalid)?;
        let observation_bytes = raw.checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<[Zeroizing<Vec<u8>>; 4]>()))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<(Arc<Vec<OwnedValue>>, Arc<Vec<OwnedValue>>)>(),
            ))
            .and_then(|bytes| bytes.checked_add(Archive::entry_bytes_v1()))
            .ok_or_else(invalid)?;
        let flight_controls = crate::policy_compiler::
            root_flight_detached_construction_bytes_v1().ok_or_else(invalid)?;
        let local_bytes = std::mem::size_of::<SourceSuccessorCredentialCustodyV2<'_>>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Outer>().checked_mul(2)?))
            // The original same-C issue debit precedes each sequential flight.
            // This later local flight is not embedded in the input owners.
            .and_then(|bytes| bytes.checked_add(flight_controls))
            .and_then(|bytes| bytes.checked_add(retained_slots.checked_mul(observation_bytes)?))
            // Descriptor/name snapshots, fixed paths and executable hashing
            // stream buffers coexist with the retained property observations.
            .and_then(|bytes| bytes.checked_add(2 * 1024 * 1024))
            .ok_or_else(invalid)?;
        let rows = u64::try_from(MAXIMUM_OBSERVATIONS).map_err(|_| invalid())?;
        let retained_values = Archive::fixed_property_retained_values_bytes_v1(MATERIALIZATION_BYTES)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        let peak_rows = u64::try_from(OBSERVER_PEAK_ROWS).map_err(|_| invalid())?;
        let geometry = crate::public_api_session::ControllerInitialCredentialCustodyV1::
            source_genesis_geometry().ok_or_else(invalid)?;
        let memory_bytes = u64::try_from(local_bytes).map_err(|_| invalid())?
            // All completed decoded tables remain resident. Only raw native
            // rows retire at the whole comparison boundary below; no credit
            // is taken for unperformed cleanup or a failed native original.
            .checked_add(retained_values.checked_mul(rows).ok_or_else(invalid)?)
            .and_then(|bytes| bytes.checked_add(observer.memory_bytes.checked_mul(peak_rows)?))
            .and_then(|bytes| bytes.checked_add(u64::try_from(geometry.memory_bytes).ok()?))
            .ok_or_else(invalid)?;

        // The actual fixed property maps have 11 service and 4 unit names per
        // observation. Rust fields and decoded tuple values are byte carriers.
        let property_names = u64::try_from(PROPERTIES.len() + UNIT_PROPERTIES.len())
            .map_err(|_| invalid())?;
        let metadata_entries = rows.checked_mul(property_names)
            .and_then(|entries| entries.checked_add(u64::try_from(geometry.metadata_entries).ok()?))
            // Fixed credential/source names, credential directory ancestors
            // and the /proc executable locator have a 14-entry bound.
            .and_then(|entries| entries.checked_add(14))
            .ok_or_else(invalid)?;
        // Four originals, two directory handles, executable and at most four
        // named recheck handles coexist with optional genesis inputs.
        let open_files = 12u64
            .checked_add(observer.open_files.checked_mul(peak_rows).ok_or_else(invalid)?)
            .and_then(|files| files.checked_add(u64::try_from(geometry.open_files).ok()?))
            .ok_or_else(invalid)?;
        let wire_bytes = observer.wire_io_bytes.checked_mul(rows).ok_or_else(invalid)?;
        let executable = IssueExecutableOriginalV1::receiving_demand_v1()
            .ok_or_else(invalid)?;
        let (native_bytes, native_files) = CredentialNativePassV1::receiving_footprint_v1()
            .ok_or_else(invalid)?;
        // Existing four temporary-name lanes cover the actual named directory,
        // one named child and one bounded boot read; no field-count metadata.
        if native_files > 4 { return Err(invalid()); }
        let native = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(native_bytes).map_err(|_| invalid())?);
        let demand = ResourceVector::ZERO
            .with(D::MemoryBytes, memory_bytes)
            .with(D::MetadataEntries, metadata_entries)
            .with(D::OpenFiles, open_files)
            .with(D::Pids, 1)
            .with(D::NetworkBytes, wire_bytes)
            .with(D::OutputBytes, wire_bytes)
            .with(D::LogBytes, observer.maximum_log_bytes);
        // The nested owner is already included in Self's compiled width.
        // Its shared native/hash scratch and one executed-file probe remain
        // separate. The measured executable uses the existing base file lane.
        // Both inline fragment destinations are already covered by the two
        // compiled Self copies above. Its canonical hashing scratch is extra;
        // this same-held-file comparison opens no descriptor or namespace.
        let fragment = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()
            .ok_or_else(invalid)?;
        let fragment_inline = u64::try_from(std::mem::size_of::<ImmutableFileRevalidationOriginalV1>())
            .map_err(|_| invalid())?;
        let fragment = fragment.with(D::MemoryBytes,
            fragment.get(D::MemoryBytes).checked_sub(fragment_inline).ok_or_else(invalid)?);
        demand.checked_add(executable)?.checked_add(native)?.checked_add(fragment).map_err(Error::from)
    }
}

impl<'profile> ProductionControllerNormalRootProfileV1 {
    /// Parks issue-only original input custody before any fallible admission.
    ///
    /// # Errors
    /// Rejects a populated slot and every changed or nonissue invocation,
    /// ambiguous delivery, unsafe original descriptor, malformed input or
    /// independent public/private role mismatch. A failed slot remains owned.
    pub fn park_source_successor_credentials_v2(
        &'profile self,
        slot: &mut Option<SourceSuccessorCredentialCustodyV2<'profile>>,
    ) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if slot.is_some() {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        *slot = Some(SourceSuccessorCredentialCustodyV2 {
            profile: self,
            directory_path: None,
            directory_reader: None,
            files: Vec::with_capacity(4),
            directory_identity: None,
            directory_snapshot: None,
            identities: Vec::with_capacity(4),
            executable: IssueExecutableOriginalV1::new(),
            native_pass: Some(CredentialNativePassV1::new()),
            fragment_currentness: None,
            observer: aos_systemd_client::FixedPid1PropertyArchiveV1::with_materialization_limit(
                OBSERVER_PEAK_ROWS, MATERIALIZATION_BYTES,
            ),
            observer_preparation: None,
            observations: Vec::new(),
            observer_settlements: [const { None }; MAXIMUM_OBSERVATIONS],
            buffers: Vec::new(),
            admitted: false,
            ended: false,
        });
        let custody = slot.as_mut().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let result = custody.admit();
        if result.is_err() {
            // Preserve the typed result and originals for the resident caller.
            // Its first-cause latch precedes explicit wiping and termination.
            custody.admitted = false;
            custody.ended = true;
        }
        result
    }
}

impl SourceSuccessorCredentialCustodyV2<'_> {
    /// Borrows the same bounded PID1 failure without releasing its original.
    #[must_use]
    pub fn observer_failure_view_v2(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.observer.failure_view()
    }

    /// Borrows an actual executable acquisition or comparison refusal.
    ///
    /// This performs no IO and leaves the same file and native prefix owned.
    /// Other credential/profile failure sites retain their own diagnostic order.
    #[must_use]
    pub fn executable_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.executable.failure()
    }

    /// Borrows the actual directory, mount, label, ACL or name-prefix refusal.
    ///
    /// This keeps all failed native results and named descriptions resident.
    #[must_use]
    pub fn credential_native_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native_pass.as_ref().and_then(CredentialNativePassV1::failure)
    }

    /// Borrows the actual same-fragment name, mount or hashing refusal.
    ///
    /// The immutable anchor remains on the admitted profile. A failed native
    /// comparison stays here and cannot be overwritten by another observation.
    #[must_use]
    pub fn fragment_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fragment_currentness.as_ref().and_then(ImmutableFileRevalidationOriginalV1::failure)
    }

    fn admit(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        self.observer_preparation = Some(self.observer.prepare_once());
        if !matches!(self.observer_preparation, Some(Ok(()))) {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.profile.recheck()?;
        let executable = self.observe_delivery(true)?;
        self.executable.capture_once(executable)?;

        let native = self.native_pass.as_mut().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        self.directory_path = Some(native::open_directory(true, &mut native.opens)?);
        self.directory_reader = Some(native::open_directory(false, &mut native.opens)?);
        let path = self.directory_path.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let reader = self.directory_reader.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let identity = native::identity(reader.as_fd(), &mut native.identities)?;
        identity.require(self.profile, FileType::Directory, 0o500)?;
        native::label_and_acl(reader.as_fd(), &mut native.labels)?;
        if native::identity(path.as_fd(), &mut native.identities)? != identity {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.directory_snapshot = Some(
            native::snapshot(path.as_fd(), &mut native.snapshots)?,
        );
        self.directory_identity = Some(identity);

        for (name, width) in NAMES.into_iter().zip(WIDTHS) {
            self.files.push(native::open_child(path, name, &mut native.opens)?);
            let file = self.files.last().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
            let identity = native::identity(file.as_fd(), &mut native.identities)?;
            identity.require(self.profile, FileType::RegularFile, 0o400)?;
            if identity.links != 1 || identity.bytes != width as u64 {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            }
            native::read_description(file.as_fd(), &mut native.descriptions)?;
            native::label_and_acl(file.as_fd(), &mut native.labels)?;
            self.identities.push(identity);
        }

        self.capture_bytes()?;
        self.validate_roles()?;
        // Complete initial descriptor/byte/role comparison. Original files and
        // derived snapshots stay held; only these positive native temporaries
        // dispose before the independently entered full recheck below.
        drop(self.native_pass.take());
        self.admitted = true;
        self.recheck()
    }

    /// Rechecks the same original delivery, descriptors and bounded readbacks.
    ///
    /// # Errors
    /// Rejects ended custody, changed profile/mode/invocation/delivery, replaced
    /// names or descriptions, unsafe labels/backing/ACLs, or changed bytes.
    pub fn recheck(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        let result = self.recheck_inner();
        if result.is_err() {
            self.admitted = false;
            self.ended = true;
        }
        result
    }

    fn recheck_inner(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if !self.admitted || self.ended {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.profile.recheck()?;
        let executable = self.observe_delivery(true)?;
        self.executable.recheck(&executable)?;
        self.check_descriptors_and_names()?;
        self.capture_bytes()?;
        self.validate_roles()?;
        self.check_descriptors_and_names()?;
        self.profile.recheck()?;
        self.settle_completed_delivery_once()
    }

    // This is the last step of a complete recheck, after descriptor/name,
    // credential byte/role and independent profile-post comparisons. A failed
    // comparison never enters here and keeps every native row. Successful
    // table Arcs remain in observations after their native archive retires.
    fn settle_completed_delivery_once(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        let index = self.observations.len().checked_sub(1)
            .ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let outcome = self.observer_settlements.get_mut(index)
            .ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        if outcome.is_some() { return Err(SourceSuccessorCredentialErrorV2::Rejected); }
        *outcome = Some(self.observer.settle_positive_once());
        if !matches!(outcome, Some(Ok(()))) {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        // Construction is inert; no fresh row backing, Runtime or socket is
        // prepared until the next already-paid actual delivery observation.
        self.observer = aos_systemd_client::FixedPid1PropertyArchiveV1::with_materialization_limit(
            OBSERVER_PEAK_ROWS, MATERIALIZATION_BYTES,
        );
        self.observer_preparation = None;
        Ok(())
    }

    pub(crate) fn intent(&self) -> Result<SourceSuccessorIntentDataV2, SourceGenesisErrorV1> {
        if !self.admitted || self.ended {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        SourceSuccessorIntentDataV2::from_bytes(
            self.first_buffers()?[1].as_slice(),
        ).map_err(SourceGenesisErrorV1::from)
    }

    /// Returns project comparison DATA from the same already-admitted intent.
    ///
    /// This getter makes no observation and grants no issuer, writer, floor or
    /// clock authority. The selected caller separately retains current owners.
    ///
    /// # Errors
    /// Rejects unadmitted, ended or malformed original credential custody.
    pub fn source_successor_project_data_v3(&self) -> Result<aos_sandbox_model::ProjectId, SourceGenesisErrorV1> {
        self.intent().map(|intent| intent.project())
    }

    pub(crate) fn issuer_generation(&self) -> Result<u64, SourceGenesisErrorV1> {
        Ok(PinnedControllerSourceTreeSeedIssuerV1::decode(
            self.first_buffers()?[2].as_slice(),
        )?.generation())
    }

    pub(crate) fn verify_saved(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        let pin = PinnedControllerSourceTreeSeedIssuerV1::decode(self.first_buffers()?[2].as_slice())?;
        packet.verify_signature(pin.verifying_key()).map_err(SourceGenesisErrorV1::from)
    }

    pub(crate) fn sign_approval(
        &mut self,
        body: &[u8],
        signing_cut: &SourceSuccessorSigningCutV2<'_, '_, '_, '_, '_>,
    ) -> Result<SourceSuccessorApprovalDataV2, SourceSuccessorCredentialErrorV2> {
        self.sign_approval_with_recipe(body, SourceSuccessorSigningRecipeV3::StrictV2(signing_cut))
    }

    pub(crate) fn sign_project_approval_v3(
        &mut self, body: &[u8], signing_cut: &SourceSuccessorSigningCutV3<'_, '_, '_, '_, '_>,
    ) -> Result<SourceSuccessorApprovalDataV2, SourceSuccessorCredentialErrorV2> {
        self.sign_approval_with_recipe(body, SourceSuccessorSigningRecipeV3::ProjectV3(signing_cut))
    }

    fn sign_approval_with_recipe(
        &mut self, body: &[u8], signing_cut: SourceSuccessorSigningRecipeV3<'_, '_, '_, '_, '_>,
    ) -> Result<SourceSuccessorApprovalDataV2, SourceSuccessorCredentialErrorV2> {
        self.recheck()?;
        let intent = self.intent()?;
        let issuer_generation = self.issuer_generation()?;

        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(self.first_buffers()?[0].as_slice());
        let signer = SigningKey::from_bytes(&seed);
        let message = signature_message(body)?;

        let mut packet = vec![0; body.len() + 64];
        packet[..body.len()].copy_from_slice(body);

        // No fallible credential/message preparation or live-owner work may
        // intervene between this genuine current cut and the actual signature.
        signing_cut.recheck(body, intent, issuer_generation)?;
        let signature = signer.sign(&message);
        packet[body.len()..].copy_from_slice(&signature.to_bytes());
        let packet = SourceSuccessorApprovalDataV2::from_record_bytes(&packet)?;

        self.recheck()?;
        self.verify_saved(&packet)?;
        Ok(packet)
    }

    /// Wipes private buffers while retaining the original descriptions.
    ///
    /// This irreversible negative operation grants no retry or next activation.
    pub fn end_failed(&mut self) {
        self.ended = true;
        self.admitted = false;
        wipe_private_buffers(&mut self.buffers);
    }

    fn first_buffers(&self) -> Result<&[Zeroizing<Vec<u8>>; 4], SourceGenesisErrorV1> {
        if self.ended {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        self.buffers.first().ok_or(SourceGenesisErrorV1::Stale)
    }

    fn validate_roles(&self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        let buffers = self.buffers.first().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(buffers[0].as_slice());
        let signer = SigningKey::from_bytes(&seed);
        let admin = PinnedControllerSourceTreeSeedIssuerV1::decode(buffers[2].as_slice())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        let authorization = PinnedPublisherProjectAuthorizationIssuerV2::decode(buffers[3].as_slice())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        if signer.verifying_key() != *admin.verifying_key()
            || admin.verifying_key() == authorization.verifying_key()
        {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        SourceSuccessorIntentDataV2::from_bytes(buffers[1].as_slice())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        Ok(())
    }

    fn capture_bytes(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if self.buffers.len() >= MAXIMUM_OBSERVATIONS || self.files.len() != 4 {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.buffers.push(WIDTHS.map(|width| Zeroizing::new(vec![0; width])));
        let received = self.buffers.last_mut().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        for (file, bytes) in self.files.iter().zip(received.iter_mut()) {
            read_exact_positioned(file, bytes.as_mut_slice())
                .map_err(SourceSuccessorCredentialErrorV2::Read)?;
        }

        let first = self.buffers.first().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let last = self.buffers.last().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        if first != last {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        Ok(())
    }

    fn observe_delivery(&mut self, issue: bool) -> Result<String, SourceSuccessorCredentialErrorV2> {
        if self.observations.len() >= MAXIMUM_OBSERVATIONS {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        if self.observer_preparation.is_none() {
            self.observer_preparation = Some(self.observer.prepare_once());
        }
        if !matches!(self.observer_preparation, Some(Ok(()))) {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.observations.push(self.observer.read(
            super::UNIT, std::process::id(), PROPERTIES, UNIT_PROPERTIES,
        )?);
        let (values, unit) = self.observations.last().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        require_unit_schema(unit)?;
        let observed = service::immutable_observation(service::decode_unit(unit, super::UNIT)?)?;
        service::require_same(self.profile.original.original_unit_observation(), &observed)?;
        if self.fragment_currentness.is_some() {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.fragment_currentness = Some(ImmutableFileRevalidationOriginalV1::new());
        let fragment = self.fragment_currentness.as_mut()
            .ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        self.profile.original.fragment_measurement().revalidate_retaining(fragment)
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        // This complete same-file name/hash comparison has no later temporary
        // anchor duty. Keep the held measured fragment; failed passes stay here.
        drop(self.fragment_currentness.take());

        require_delivery(
            values.get(5..).ok_or(SourceSuccessorCredentialErrorV2::Rejected)?, issue,
        )?;
        let identities = self.profile.original.schema().identities[..2].try_into()
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        let path = require_issue_launch(
            values.get(..5).ok_or(SourceSuccessorCredentialErrorV2::Rejected)?, identities,
        )?;
        Ok(path.to_owned())
    }

    fn check_descriptors_and_names(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if self.native_pass.is_some() { return Err(SourceSuccessorCredentialErrorV2::Rejected); }
        self.native_pass = Some(CredentialNativePassV1::new());
        let native = self.native_pass.as_mut().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let path = self.directory_path.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let reader = self.directory_reader.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let original_snapshot = native::snapshot(path.as_fd(), &mut native.snapshots)?;
        if Some(&native::identity(path.as_fd(), &mut native.identities)?) != self.directory_identity.as_ref()
            || Some(&native::identity(reader.as_fd(), &mut native.identities)?) != self.directory_identity.as_ref()
            || Some(&original_snapshot) != self.directory_snapshot.as_ref()
        {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        native::label_and_acl(reader.as_fd(), &mut native.labels)?;

        native.named_directory = Some(native::open_directory(true, &mut native.opens)?);
        let named_directory = native.named_directory.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let named_snapshot = native::snapshot(named_directory.as_fd(), &mut native.snapshots)?;
        if Some(&native::identity(named_directory.as_fd(), &mut native.identities)?) != self.directory_identity.as_ref()
            || Some(&named_snapshot) != self.directory_snapshot.as_ref()
        {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        for ((file, identity), name) in self.files.iter().zip(&self.identities).zip(NAMES) {
            native.named_leaf = Some(native::open_child(named_directory, name, &mut native.opens)?);
            let named = native.named_leaf.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
            if native::identity(file.as_fd(), &mut native.identities)? != *identity || native::identity(named.as_fd(), &mut native.identities)? != *identity {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            }
            native::read_description(file.as_fd(), &mut native.descriptions)?;
            native::label_and_acl(file.as_fd(), &mut native.labels)?;
            // The held original and exact named comparison have completed;
            // no later leaf borrows this positive temporary description.
            drop(native.named_leaf.take());
        }
        drop(self.native_pass.take());
        Ok(())
    }
}

fn wipe_private_buffers(buffers: &mut [[Zeroizing<Vec<u8>>; 4]]) {
    for observation in buffers {
        observation[0].zeroize();
    }
}

/// Refuses issue-purpose copies and effective delivery before ordinary effects.
///
/// # Errors
/// Rejects either unexpected fixed copy, any selected issue-purpose mapping,
/// or unavailable original PID1/profile observation. Absent legacy delivery
/// without a selected profile remains nonauthorizing and otherwise unchanged.
pub fn require_source_successor_delivery_absent_v2(
    profile: Option<&ProductionControllerNormalRootProfileV1>,
) -> Result<(), SourceSuccessorCredentialErrorV2> {
    for name in &NAMES[..2] {
        match std::fs::symlink_metadata(Path::new(DIRECTORY).join(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(SourceSuccessorCredentialErrorV2::Rejected),
        }
    }
    if let Some(profile) = profile {
        profile.recheck()?;
        let (values, unit) = service::read_properties(super::UNIT, std::process::id(), PROPERTIES)?;
        require_unit_schema(&unit)?;
        let observed = service::immutable_observation(service::decode_unit(&unit, super::UNIT)?)?;
        service::require_same(profile.original.original_unit_observation(), &observed)?;
        require_delivery(values.get(5..).ok_or(SourceSuccessorCredentialErrorV2::Rejected)?, false)?;
        profile.recheck()?;
    }
    Ok(())
}

fn require_issue_launch(
    values: &[OwnedValue],
    identities: [u32; 2],
) -> Result<&str, SourceSuccessorCredentialErrorV2> {
    let [kind, restart, start, pre, post] = values else {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    };
    require_signature(kind, "s")?;
    require_signature(restart, "s")?;
    if <&str>::try_from(kind).ok() != Some("oneshot")
        || <&str>::try_from(restart).ok() != Some("no")
    {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    for commands in [start, pre, post] {
        require_signature(commands, "a(sasbttttuii)")?;
    }
    for commands in [pre, post] {
        if !matches!(&**commands, Value::Array(array) if array.is_empty()) {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
    }

    let command = systemd_property_data::single_exec_start(start).ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
    if command.path.len() > 4096 {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    let expected = [
        command.path.to_owned(),
        identities[0].to_string(),
        identities[1].to_string(),
        "--issue-source-successor".to_owned(),
    ];
    if !command.path.starts_with("/nix/store/")
        || !command.path.ends_with("/bin/aos-sandboxd")
        || command.pid != std::process::id()
        || command.argv.len() != expected.len()
        || command.argv.iter().zip(&expected).any(|(actual, expected)| {
            !matches!(actual, Value::Str(actual) if actual.as_str() == expected)
        })
    {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    Ok(command.path)
}

fn require_signature(
    value: &OwnedValue,
    expected: &str,
) -> Result<(), SourceSuccessorCredentialErrorV2> {
    if value.value_signature().to_string() != expected {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    Ok(())
}

fn require_unit_schema(unit: &[OwnedValue]) -> Result<(), SourceSuccessorCredentialErrorV2> {
    let [fragment, dropins, transient, invocation] = unit else {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    };
    for (value, signature) in [
        (fragment, "s"), (dropins, "as"), (transient, "b"), (invocation, "ay"),
    ] {
        require_signature(value, signature)?;
    }
    Ok(())
}

fn require_delivery(
    values: &[OwnedValue],
    issue: bool,
) -> Result<(), SourceSuccessorCredentialErrorV2> {
    let [load, encrypted, literal, encrypted_literal, import, import_ex] = values else {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    };
    for (value, signature) in [
        (load, "a(ss)"),
        (encrypted, "a(ss)"),
        (literal, "a(say)"),
        (encrypted_literal, "a(say)"),
        (import, "as"),
        (import_ex, "a(ss)"),
    ] {
        require_signature(value, signature)?;
    }

    let mut found = [0_usize; 2];
    for (ordinary, value) in [(true, load), (false, encrypted), (false, literal), (false, encrypted_literal)] {
        let Value::Array(rows) = &**value else {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        };
        if issue && rows.len() > 64 {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        for row in rows.inner() {
            let Value::Structure(row) = row else {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            };
            let [Value::Str(id), content] = row.fields() else {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            };
            if issue && id.as_str().len() > 255 {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            }
            if let Some(index) = NAMES[..2].iter().position(|name| *name == id.as_str()) {
                if !issue || !ordinary || !matches!(content, Value::Str(source) if source.as_str() == SOURCES[index]) {
                    return Err(SourceSuccessorCredentialErrorV2::Rejected);
                }
                found[index] += 1;
            }
            if issue {
                match content {
                    Value::Str(value) if value.as_str().len() <= 4096 => {}
                    Value::Array(value) if value.len() <= 4096 => {}
                    _ => return Err(SourceSuccessorCredentialErrorV2::Rejected),
                }
            }
        }
    }

    for value in [import, import_ex] {
        let Value::Array(rows) = &**value else {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        };
        if issue && !rows.is_empty() {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        // Absent-purpose normal mode preserves unrelated inherited imports.
        // Actual fixed copies are checked separately before ordinary effects;
        // no wildcard expansion or credential-origin authority is inferred.
        for row in rows.inner() {
            let name = match row {
                Value::Str(name) => name.as_str(),
                Value::Structure(row) => match row.fields() {
                    [Value::Str(name), Value::Str(target)] => {
                        if NAMES[..2].contains(&target.as_str()) {
                            return Err(SourceSuccessorCredentialErrorV2::Rejected);
                        }
                        name.as_str()
                    }
                    _ => return Err(SourceSuccessorCredentialErrorV2::Rejected),
                },
                _ => return Err(SourceSuccessorCredentialErrorV2::Rejected),
            };
            if NAMES[..2].contains(&name) {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            }
        }
    }

    if found != [usize::from(issue); 2] {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    Ok(())
}

fn open_directory(path_only: bool) -> Result<File, SourceSuccessorCredentialErrorV2> {
    let access = if path_only { OFlags::PATH } else { OFlags::RDONLY };
    Ok(File::from(openat2(
        CWD, DIRECTORY,
        access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    type Command = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn delivery(issue: bool) -> Vec<OwnedValue> {
        let load = if issue {
            NAMES[..2].iter().copied().zip(SOURCES).collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        vec![
            value(load),
            value(Vec::<(&str, &str)>::new()),
            value(Vec::<(&str, Vec<u8>)>::new()),
            value(Vec::<(&str, Vec<u8>)>::new()),
            value(Vec::<&str>::new()),
            value(Vec::<(&str, &str)>::new()),
        ]
    }

    fn command() -> Command {
        let path = "/nix/store/selected-controller/bin/aos-sandboxd";
        (
            path.into(),
            vec![path.into(), "1001".into(), "1002".into(), "--issue-source-successor".into()],
            false,
            0, 0, 0, 0,
            std::process::id(),
            0, 0,
        )
    }

    fn launch(command: Command) -> Vec<OwnedValue> {
        vec![
            value("oneshot"),
            value("no"),
            value(vec![command]),
            value(Vec::<Command>::new()),
            value(Vec::<Command>::new()),
        ]
    }

    #[test]
    fn exact_issue_delivery_requires_both_unique_fixed_ordinary_sources() {
        let exact = delivery(true);

        assert!(require_delivery(&exact, true).is_ok());
        assert!(require_delivery(&exact, false).is_err());
        assert!(require_delivery(&delivery(false), true).is_err());
        for rows in [
            vec![(NAMES[0], SOURCES[0])],
            vec![(NAMES[0], SOURCES[0]), (NAMES[0], SOURCES[0]), (NAMES[1], SOURCES[1])],
            vec![(NAMES[0], SOURCES[1]), (NAMES[1], SOURCES[0])],
        ] {
            let mut values = delivery(true);
            values[0] = value(rows);
            assert!(require_delivery(&values, true).is_err());
        }
        let mut encrypted = delivery(true);
        encrypted[1] = value(vec![(NAMES[0], SOURCES[0])]);
        assert!(require_delivery(&encrypted, true).is_err());
        let mut literal = delivery(true);
        literal[2] = value(vec![(NAMES[0], vec![1_u8; 32])]);
        assert!(require_delivery(&literal, true).is_err());
        let mut imported = delivery(true);
        imported[4] = value(vec!["*"]);
        assert!(require_delivery(&imported, true).is_err());
    }

    #[test]
    fn normal_absence_preserves_unrelated_imports_and_refuses_issue_names() {
        let mut values = delivery(false);
        values[0] = value(vec![("unrelated-purpose", "/run/credentials/@system/unrelated")]);
        values[4] = value(vec!["unrelated-import"]);
        values[5] = value(vec![("unrelated-import", "other")]);

        assert!(require_delivery(&values, false).is_ok());
        values[4] = value(vec![NAMES[0]]);
        assert!(require_delivery(&values, false).is_err());
        values[4] = value(Vec::<&str>::new());
        values[5] = value(vec![(NAMES[1], "other")]);
        assert!(require_delivery(&values, false).is_err());
    }

    #[test]
    fn exact_schema_precedes_empty_array_and_tuple_inspection() {
        let mut values = delivery(true);
        values[1] = value(Vec::<&str>::new());
        assert!(require_delivery(&values, true).is_err());
        values[1] = value(vec![(NAMES[0],)]);
        assert!(require_delivery(&values, true).is_err());
        let unit = vec![value("/fragment"), value(Vec::<&str>::new()), value(false), value(vec![1_u8; 16])];
        assert!(require_unit_schema(&unit).is_ok());
        let mut wrong = unit;
        wrong[3] = value(vec![1_u16; 16]);
        assert!(require_unit_schema(&wrong).is_err());
    }

    #[test]
    fn issue_launch_requires_exact_command_mode_pid_and_no_auxiliary_commands() {
        let exact = launch(command());

        assert!(require_issue_launch(&exact, [1001, 1002]).is_ok());
        assert!(require_issue_launch(&exact, [1001, 1003]).is_err());
        for index in 0..5 {
            let mut changed = launch(command());
            changed[index] = match index {
                0 => value("notify"),
                1 => value("on-failure"),
                2 => {
                    let mut altered = command();
                    altered.7 = 0;
                    value(vec![altered])
                }
                _ => value(vec![command()]),
            };
            assert!(require_issue_launch(&changed, [1001, 1002]).is_err(), "{index}");
        }
        let mut extra = command();
        extra.1.push("--public-api".into());
        assert!(require_issue_launch(&launch(extra), [1001, 1002]).is_err());
        let mut ignored = command();
        ignored.2 = true;
        assert!(require_issue_launch(&launch(ignored), [1001, 1002]).is_err());
    }

    #[test]
    fn failure_wipes_every_private_readback_but_not_public_context() {
        let mut observations = vec![
            WIDTHS.map(|width| Zeroizing::new(vec![7; width])),
            WIDTHS.map(|width| Zeroizing::new(vec![8; width])),
        ];

        wipe_private_buffers(&mut observations);

        assert!(observations.iter().all(|bytes| bytes[0].is_empty()));
        assert_eq!(observations[0][1].as_slice(), &[7; 80]);
        assert_eq!(observations[1][2].as_slice(), &[8; 80]);
    }
}
