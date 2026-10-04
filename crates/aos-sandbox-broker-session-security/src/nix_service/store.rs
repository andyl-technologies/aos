//! Retains one selected private Store readback and its original physical inputs.
//!
//! The signed snapshot authenticates expected fs-verity measurements, not a
//! current Session. The caller lends the SAME genuine pending method50 around
//! every open/read/process boundary. Portable reconstruction uses the existing
//! Core graph projection and descriptor verifier; NAR uses only the compiled
//! upstream reader. Partial files, child input/output and first causes remain
//! resident on failure. This module neither creates a store nor provisions NV.
//!
//! ```text
//! snapshot: AOSNXV01 | json-length:u32BE | canonical JSON | signature:64
//! reader input: {"version":1,"paths":[{"path":"/nix/store/...","narSize":1}]}
//! ```

use std::collections::TryReserveError;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use aos_sandbox_core::model::{AclEntry, FilesystemMetadata};
use aos_sandbox_core::{ObjectDescriptorVerifier, ObjectDescriptorVerificationError};
use aos_sandbox_linux::immutable_file::{FsVerityBacking, FsVerityDigest, ImmutableFileError};
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::process::{
    FixedProcessBoottimeCutV1, FixedProcessCaptureV1, FixedProcessDrivenInputsV1,
    FixedProcessDrivenProgressV1, FixedProcessDrivenSessionV1, FixedProcessRequest,
    FixedProcessRetainedSessionOutcome, prepare_fixed_process_driven_invocation_v1,
};
use aos_sandbox_linux::{PidFd, PidFdInfo};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::nix_build::NixPreadmittedRecipeV2;
use ed25519_dalek::{Signature, VerifyingKey};
use base64::Engine as _;
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::controller_service::nix_inputs::{
    NixLocalInputErrorV2, NixStoreMemberKindV2, NixStoreMemberV2, project_store_members_v2,
    project_store_output_members_v2,
};
use crate::fixed_role_credential::{
    CredentialOwnerPolicyV1, FixedRoleCredentialErrorV1, read_optional_bounded_role_credential_v1,
};
use crate::handshake::{DormantAuthenticatedBrokerSessionV1, OnlinePostflightV1};
use crate::tpm_nv_custody::{FloorErrorV1, OnlineFloorProfileV1, OnlineFloorRoleV1};
use crate::BrokerSessionSecurityError;

mod compiled {
    include!(env!("AOS_NIX_ONLINE_STORE_READER_HEADER"));
}

const MAXIMUM_INPUTS: usize = 4_096;
const MAXIMUM_BYTES: u64 = 1_073_741_824;
const SNAPSHOT_MAXIMUM: usize = 1_048_576;
const SCRATCH_BYTES: usize = 65_536;
const STORE_LABEL: &[u8] = b"system_u:object_r:aos_nix_online_store_t\0";
const SNAPSHOT_DOMAIN: &[u8] = b"aos.sandbox.nix.online-store.snapshot.v1\0";
const SNAPSHOT_ARTIFACT_DOMAIN: &[u8] = b"aos.sandbox.nix.online-store.snapshot-artifact.v1\0";
const CONTROLS: [(&str, u64); 4] = [
    ("nix/var/nix/db/db.sqlite", 16_777_216),
    ("nix/var/nix/db/schema", 65_536),
    ("nix/var/nix/db/reserved", 0),
    ("etc/nix/nix.conf", 65_536),
];
const CONSTRUCTOR_DIRECTORIES: [&str; 11] = [
    "nix/store", "nix/store/.links", "nix/var/nix", "nix/var/nix/profiles",
    "nix/var/nix/temproots", "nix/var/nix/db", "nix/var/nix/gcroots",
    "nix/var/nix/profiles/per-user", "nix/var/nix/gcroots/per-user", "etc", "etc/nix",
];

// One borrowed observation per held original, plus the four pending
// comparisons and five root/constructor descriptions. The same graph is not
// copied. This bounded diagnostic archive is not a physical-funding proof.
const MAXIMUM_POSTFLIGHT_ORIGINALS: usize = 2 * MAXIMUM_INPUTS + CONTROLS.len()
    + 2 * CONSTRUCTOR_DIRECTORIES.len() + 9;

/// Identifies only the two separately preprovisioned writable GC subtrees.
#[derive(Clone, Copy)]
pub(super) enum GcDirectoryV1 {
    Direct,
    Indirect,
}

impl GcDirectoryV1 {
    pub(super) const fn relative_name(self) -> &'static str {
        match self {
            Self::Direct => "nix/var/nix/gcroots/aos-online",
            Self::Indirect => "nix/var/nix/gcroots/auto",
        }
    }
}

pub(super) const fn domain_root() -> &'static str {
    compiled::DOMAIN_ROOT
}

/// Owns the actual first failure, independent of the process cleanup report.
#[derive(Debug, thiserror::Error)]
pub(super) enum StoreFailureV1 {
    #[error("original online Session failed: {0}")]
    Session(#[from] BrokerSessionSecurityError),
    #[error("independent online provision failed: {0}")]
    Floor(#[from] FloorErrorV1),
    #[error("fixed snapshot credential failed: {0}")]
    Credential(#[from] FixedRoleCredentialErrorV1),
    #[error("physical Store operation failed: {0}")]
    Native(#[from] rustix::io::Errno),
    #[error("physical Store descriptor admission failed: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    #[error("authenticated Store seal failed: {0}")]
    Verity(#[from] ImmutableFileError),
    #[error("canonical portable input failed: {0}")]
    Portable(#[from] NixLocalInputErrorV2),
    #[error("portable Content verification failed: {0}")]
    Content(#[from] ObjectDescriptorVerificationError),
    #[error("bounded Store allocation failed: {0}")]
    Allocation(#[from] TryReserveError),
    #[error("Store DATA decoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("compiled reader image custody failed: {0}")]
    Image(#[from] crate::immutable_image::ImmutableImageErrorV1),
    #[error("original reader attempt stopped; its typed cause/debt remain resident")]
    ReaderStopped,
    #[error("Store snapshot or exact physical metadata mismatched")]
    Mismatch,
    #[error("Store count, byte or name bound exceeded")]
    Bound,
    #[error("Store readback is permanently closed")]
    Closed,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotV1 {
    version: u32,
    node: String,
    deployment: String,
    endpoint: String,
    domain: String,
    domain_commitment: String,
    disclosure: String,
    files: Vec<SnapshotFileV1>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotFileV1 {
    name: String,
    bytes: u64,
    sha256: String,
    verity_sha256: String,
}

enum PhysicalMemberV1 {
    File(FsVerityBacking),
    Directory { path: ResolvedPath, readable: Option<OwnedFd> },
    Symlink { parent: ResolvedPath, link: Option<OwnedFd> },
}

struct RetainedMemberV1 {
    expected: NixStoreMemberV2,
    physical: Option<PhysicalMemberV1>,
}

/// Keeps every returned original before another fallible admission/check.
struct StoreBackingV1 {
    profile: OnlineFloorProfileV1,
    issuer: [u8; 48],
    snapshot_bytes: Option<Vec<u8>>,
    snapshot: Option<SnapshotV1>,
    filesystem_root_raw: Option<OwnedFd>,
    filesystem_root: Option<BeneathRoot>,
    selected_root: Option<ResolvedPath>,
    raw_root: Option<OwnedFd>,
    root: Option<BeneathRoot>,
    constructor_directories: Vec<ResolvedPath>,
    constructor_readers: Vec<OwnedFd>,
    controls: Vec<FsVerityBacking>,
    members: Vec<RetainedMemberV1>,
    comparison_root: Option<ResolvedPath>,
    comparison_file: Option<FsVerityBacking>,
    comparison_path: Option<ResolvedPath>,
    comparison_raw: Option<OwnedFd>,
    scratch: Vec<u8>,
    first_failure: Option<StoreFailureV1>,
    failed: bool,
    admitted: bool,
    output_members: Option<Vec<NixStoreMemberV2>>,
    outputs: bool,
    postflight_debt: Vec<StoreFailureV1>,
    postflight_passes: usize,
    postflight_limit: usize,
    postflight_unavailable: Option<StoreFailureV1>,
}

impl StoreBackingV1 {
    /// Parks independently authenticated comparison DATA, not a floor permit.
    pub(super) fn new(profile: OnlineFloorProfileV1, issuer: [u8; 48]) -> Self {
        Self {
            profile,
            issuer,
            snapshot_bytes: None,
            snapshot: None,
            filesystem_root_raw: None,
            filesystem_root: None,
            selected_root: None,
            raw_root: None,
            root: None,
            constructor_directories: Vec::new(),
            constructor_readers: Vec::new(),
            controls: Vec::new(),
            members: Vec::new(),
            comparison_root: None,
            comparison_file: None,
            comparison_path: None,
            comparison_raw: None,
            scratch: Vec::new(),
            first_failure: None,
            failed: false,
            admitted: false,
            output_members: None,
            outputs: false,
            postflight_debt: Vec::new(),
            postflight_passes: 0,
            postflight_limit: 0,
            postflight_unavailable: None,
        }
    }

    fn reserve_selected_postflight(&mut self, passes: usize) -> Result<(), StoreFailureV1> {
        if self.postflight_limit != 0 || passes == 0
            || passes > crate::handshake::ONLINE_POSTFLIGHT_PASSES_V1
        {
            return Err(StoreFailureV1::Bound);
        }
        // After the first debt only enclosing reader/output/phase returns run:
        // at most three failing passes. Successful unit observations own no
        // data, so twenty successful passes do not consume this archive.
        let capacity = passes.min(3).checked_mul(MAXIMUM_POSTFLIGHT_ORIGINALS)
            .ok_or(StoreFailureV1::Bound)?;
        self.postflight_debt.try_reserve_exact(capacity)?;
        self.postflight_limit = passes;
        Ok(())
    }

    /// Compares available held/named originals, without opening replacements.
    ///
    /// A failed positive owner is not re-admitted. Its inaccessible complete
    /// content/currentness check remains unavailable even when these physical
    /// metadata observations succeed. All owning native causes stay here.
    fn observe_selected_postflight(&mut self) -> bool {
        if self.postflight_passes >= self.postflight_limit {
            self.postflight_unavailable.get_or_insert(StoreFailureV1::Bound);
            return true;
        }
        self.postflight_passes += 1;
        let capacity = self.postflight_debt.capacity().saturating_sub(self.postflight_debt.len());
        if capacity < MAXIMUM_POSTFLIGHT_ORIGINALS {
            self.postflight_unavailable.get_or_insert(StoreFailureV1::Bound);
            return true;
        }

        // Borrow disjoint fields. Each native Result is parked before another
        // original is observed, even after an earlier physical comparison failed.
        let debt = &mut self.postflight_debt;
        let root = self.raw_root.as_ref();
        if let Some(root) = root {
            retain_postflight_result(debt, compare_named_original(
                root.as_fd(), Some((rustix::fs::CWD.as_fd(), Path::new(compiled::DOMAIN_ROOT))),
                None,
            ));
        } else {
            self.postflight_unavailable.get_or_insert(StoreFailureV1::Closed);
        }
        for directory in &self.constructor_directories {
            retain_postflight_result(debt, compare_named_original(directory.as_fd(), None, None));
        }
        for directory in &self.constructor_readers {
            retain_postflight_result(debt, compare_named_original(directory.as_fd(), None, None));
        }
        for (index, control) in self.controls.iter().enumerate() {
            let named = root.zip(CONTROLS.get(index)).map(|(root, (name, _))| {
                (root.as_fd(), Path::new(name))
            });
            retain_postflight_result(debt, compare_named_original(
                control.as_fd(), named, Some((control.identity().device(), control.identity().inode())),
            ));
        }
        for member in &self.members {
            let named = root.map(|root| (root.as_fd(), Path::new(&member.expected.name)));
            let result = match member.physical.as_ref() {
                Some(PhysicalMemberV1::File(file)) => compare_named_original(
                    file.as_fd(), named, Some((file.identity().device(), file.identity().inode())),
                ),
                Some(PhysicalMemberV1::Directory { path, readable }) => {
                    retain_postflight_result(debt, compare_named_original(path.as_fd(), named,
                        Some((path.identity().device, path.identity().inode))));
                    match readable.as_ref() {
                        Some(readable) => compare_named_original(readable.as_fd(), named,
                            Some((path.identity().device, path.identity().inode))),
                        None => {
                            self.postflight_unavailable.get_or_insert(StoreFailureV1::Closed);
                            continue;
                        }
                    }
                }
                Some(PhysicalMemberV1::Symlink { parent, link: Some(link) }) => {
                    retain_postflight_result(debt, compare_named_original(parent.as_fd(), None,
                        Some((parent.identity().device, parent.identity().inode))));
                    let leaf = Path::new(&member.expected.name).file_name();
                    let named = leaf.map(|leaf| (parent.as_fd(), Path::new(leaf)));
                    compare_named_original(link.as_fd(), named, None)
                }
                Some(PhysicalMemberV1::Symlink { parent, link: None }) => {
                    self.postflight_unavailable.get_or_insert(StoreFailureV1::Closed);
                    compare_named_original(parent.as_fd(), None, None)
                }
                None => {
                    self.postflight_unavailable.get_or_insert(StoreFailureV1::Closed);
                    continue;
                }
            };
            retain_postflight_result(debt, result);
        }
        // Pending comparison objects are still originals of this attempt,
        // including a successfully returned File preceding a later refusal.
        if let Some(file) = self.comparison_file.as_ref() {
            retain_postflight_result(debt, compare_named_original(file.as_fd(), None,
                Some((file.identity().device(), file.identity().inode()))));
        }
        for path in [self.selected_root.as_ref(), self.comparison_root.as_ref(),
            self.comparison_path.as_ref()]
        {
            if let Some(path) = path {
                retain_postflight_result(debt, compare_named_original(path.as_fd(), None,
                    Some((path.identity().device, path.identity().inode))));
            }
        }
        for file in [self.filesystem_root_raw.as_ref(), self.comparison_raw.as_ref()] {
            if let Some(file) = file {
                retain_postflight_result(debt, compare_named_original(file.as_fd(), None, None));
            }
        }
        for root in [self.filesystem_root.as_ref(), self.root.as_ref()] {
            if let Some(root) = root {
                retain_postflight_result(debt, compare_named_original(root.as_fd(), None,
                    Some((root.identity().device, root.identity().inode))));
            }
        }
        if self.failed || !self.admitted {
            self.postflight_unavailable.get_or_insert(StoreFailureV1::Closed);
        }
        self.postflight_unavailable.is_some() || !self.postflight_debt.is_empty()
    }

    pub(super) fn failure(&self) -> Option<&StoreFailureV1> {
        self.first_failure.as_ref()
    }

    /// Arms permanently before parsing/opening and preserves the actual cause.
    pub(super) fn admit(
        &mut self,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ()> {
        if self.failed || self.admitted {
            return Err(());
        }
        self.failed = true;
        let result = self.admit_inner(recipe, session, request);
        self.settle(result)?;
        self.admitted = true;
        Ok(())
    }

    fn admit_inner(
        &mut self,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        session.require_online_request(request)?;
        if self.profile.role() != OnlineFloorRoleV1::Owner
            || hex(&self.profile.domain()) != compiled::DOMAIN_ID_HEX
            || self.profile.domain() != *recipe.domain.as_bytes()
            || self.profile.domain_commitment() != *recipe.domain_commitment.as_bytes()
            || self.profile.disclosure() != *recipe.disclosure.as_bytes()
        {
            return Err(StoreFailureV1::Mismatch);
        }

        if self.outputs {
            let count = self.output_members.as_ref().ok_or(StoreFailureV1::Closed)?.len();
            self.members.try_reserve_exact(count)?;
            // Capacity is ready before moving the parked projection. Reserve
            // failure leaves the actual complete projection in its old slot.
            for expected in self.output_members.as_mut().ok_or(StoreFailureV1::Closed)?.drain(..) {
                self.members.push(RetainedMemberV1 { expected, physical: None });
            }
        } else {
            let members = project_store_members_v2(recipe)?;
            self.members.try_reserve_exact(members.len())?;
            for expected in members {
                self.members.push(RetainedMemberV1 { expected, physical: None });
            }
        }
        self.scratch.try_reserve_exact(SCRATCH_BYTES)?;
        self.scratch.resize(SCRATCH_BYTES, 0);

        self.snapshot_bytes = Some(read_optional_bounded_role_credential_v1(
            Path::new("/run/credentials/aos-sandbox-nixd.service"),
            if self.outputs { "nix-online-output-snapshot-v1" } else { "nix-online-store-snapshot-v1" },
            77, SNAPSHOT_MAXIMUM, false,
            CredentialOwnerPolicyV1::RootOrCurrent,
        )?.ok_or(StoreFailureV1::Mismatch)?);
        session.require_online_request(request)?;
        self.snapshot = Some(if self.outputs {
            decode_snapshot_inner(
                self.snapshot_bytes.as_deref().ok_or(StoreFailureV1::Closed)?,
                self.profile, &self.issuer, None,
            )?
        } else {
            decode_snapshot(
                self.snapshot_bytes.as_deref().ok_or(StoreFailureV1::Closed)?,
                self.profile, &self.issuer,
            )?
        });
        self.require_snapshot_names()?;

        self.filesystem_root_raw = Some(rustix::fs::open(
            c"/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        let duplicate = rustix::io::fcntl_dupfd_cloexec(
            self.filesystem_root_raw.as_ref().ok_or(StoreFailureV1::Closed)?, 3,
        )?;
        self.filesystem_root = Some(BeneathRoot::from_owned(duplicate)?);
        self.selected_root = Some(self.filesystem_root.as_ref()
            .ok_or(StoreFailureV1::Closed)?.resolve(
                Path::new(compiled::DOMAIN_ROOT.strip_prefix('/')
                    .ok_or(StoreFailureV1::Mismatch)?),
                ResolveOptions::directory(),
            )?);
        self.raw_root = Some(rustix::fs::openat(
            self.selected_root.as_ref().ok_or(StoreFailureV1::Closed)?.as_fd(), c".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        self.check_root_metadata(session, request)?;
        let duplicate = rustix::io::fcntl_dupfd_cloexec(
            self.raw_root.as_ref().ok_or(StoreFailureV1::Closed)?, 3,
        )?;
        self.root = Some(BeneathRoot::from_owned(duplicate)?);
        session.require_online_request(request)?;

        self.constructor_directories.try_reserve_exact(CONSTRUCTOR_DIRECTORIES.len())?;
        self.constructor_readers.try_reserve_exact(CONSTRUCTOR_DIRECTORIES.len())?;
        for name in CONSTRUCTOR_DIRECTORIES {
            self.check_root(session, request)?;
            let directory = self.root()?.resolve(Path::new(name), ResolveOptions::directory())?;
            self.constructor_directories.push(directory);
            let directory = self.constructor_directories.last().ok_or(StoreFailureV1::Closed)?;
            self.constructor_readers.push(rustix::fs::openat(
                directory.as_fd(), c".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?);
            let stat = rustix::fs::fstat(directory.as_fd())?;
            if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o022 != 0 {
                return Err(StoreFailureV1::Mismatch);
            }
            require_label(directory.as_fd(), None, session, request)?;
            self.check_root(session, request)?;
        }

        self.controls.try_reserve_exact(CONTROLS.len())?;
        for (name, maximum) in CONTROLS {
            self.check_root(session, request)?;
            let expected = self.snapshot_file(name)?;
            let opened = FsVerityBacking::open_beneath(
                self.root()?, Path::new(name),
                FsVerityDigest::Sha256(decode_hex(&expected.verity_sha256)?),
                expected.bytes, maximum,
            )?;
            self.controls.push(opened);
            self.verify_file(self.controls.len() - 1, true, session, request)?;
        }
        self.verify_controls(session, request)?;

        for index in 0..self.members.len() {
            self.open_member(index, session, request)?;
            self.verify_member(index, session, request)?;
        }
        self.require_hardlink_groups()?;
        self.check_root(session, request)
    }

    fn settle<T>(&mut self, result: Result<T, StoreFailureV1>) -> Result<T, ()> {
        match result {
            Ok(value) => {
                self.failed = false;
                Ok(value)
            }
            Err(cause) => {
                if self.first_failure.is_none() {
                    self.first_failure = Some(cause);
                }
                Err(())
            }
        }
    }

    fn root(&self) -> Result<&BeneathRoot, StoreFailureV1> {
        self.root.as_ref().ok_or(StoreFailureV1::Closed)
    }

    fn require_same_controls(&self, original: &Self) -> Result<(), StoreFailureV1> {
        let root = self.selected_root.as_ref().ok_or(StoreFailureV1::Closed)?;
        let old_root = original.selected_root.as_ref().ok_or(StoreFailureV1::Closed)?;
        if root.identity() != old_root.identity() || self.profile != original.profile
            || self.issuer != original.issuer || self.controls.len() != CONTROLS.len()
            || original.controls.len() != CONTROLS.len()
        {
            return Err(StoreFailureV1::Mismatch);
        }
        for (index, (name, _)) in CONTROLS.iter().enumerate() {
            let current = &self.controls[index];
            let old = &original.controls[index];
            let current_id = current.identity();
            let old_id = old.identity();
            let current_snapshot = self.snapshot_file(name)?;
            let old_snapshot = original.snapshot_file(name)?;
            if current_id.device() != old_id.device() || current_id.inode() != old_id.inode()
                || current_id.bytes() != old_id.bytes()
                || current.verified_verity() != old.verified_verity()
                || current_snapshot.bytes != old_snapshot.bytes
                || current_snapshot.sha256 != old_snapshot.sha256
                || current_snapshot.verity_sha256 != old_snapshot.verity_sha256
            {
                return Err(StoreFailureV1::Mismatch);
            }
        }
        Ok(())
    }

    fn snapshot_file(&self, name: &str) -> Result<&SnapshotFileV1, StoreFailureV1> {
        let snapshot = self.snapshot.as_ref().ok_or(StoreFailureV1::Closed)?;
        snapshot.files.binary_search_by(|entry| entry.name.as_str().cmp(name))
            .map(|index| &snapshot.files[index]).map_err(|_| StoreFailureV1::Mismatch)
    }

    fn require_snapshot_names(&self) -> Result<(), StoreFailureV1> {
        let snapshot = self.snapshot.as_ref().ok_or(StoreFailureV1::Closed)?;
        let files = self.members.iter().filter(|member| {
            matches!(member.expected.kind, NixStoreMemberKindV2::Content { .. })
        }).count();
        if files > MAXIMUM_INPUTS || snapshot.files.len() != files + CONTROLS.len() {
            return Err(StoreFailureV1::Bound);
        }
        for (name, maximum) in CONTROLS {
            let expected = self.snapshot_file(name)?;
            if expected.bytes > maximum || (maximum == 0 && expected.bytes != 0) {
                return Err(StoreFailureV1::Bound);
            }
        }
        let mut total = 0_u64;
        for member in &self.members {
            if let NixStoreMemberKindV2::Content { descriptor, .. } = &member.expected.kind {
                let expected = self.snapshot_file(&member.expected.name)?;
                if expected.bytes != descriptor.encoded_size() {
                    return Err(StoreFailureV1::Mismatch);
                }
                total = total.checked_add(expected.bytes).ok_or(StoreFailureV1::Bound)?;
                if total > MAXIMUM_BYTES {
                    return Err(StoreFailureV1::Bound);
                }
            }
        }
        Ok(())
    }

    fn check_root_metadata(
        &self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        session.require_online_store_readback(request)?;
        let root = self.raw_root.as_ref().ok_or(StoreFailureV1::Closed)?;
        let observed = rustix::fs::fstat(root)?;
        let named = rustix::fs::statat(
            rustix::fs::CWD, compiled::DOMAIN_ROOT, rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
        if observed.st_uid != 0 || observed.st_gid != 0 || observed.st_mode & 0o022 != 0
            || observed.st_dev != named.st_dev || observed.st_ino != named.st_ino
            || rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
        {
            return Err(StoreFailureV1::Mismatch);
        }
        require_label(root.as_fd(), None, session, request)
    }

    fn check_root(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        session.require_online_store_readback(request)?;
        if self.comparison_root.is_some() {
            return Err(StoreFailureV1::Closed);
        }
        self.comparison_root = Some(self.filesystem_root.as_ref()
            .ok_or(StoreFailureV1::Closed)?.resolve(
                Path::new(compiled::DOMAIN_ROOT.strip_prefix('/')
                    .ok_or(StoreFailureV1::Mismatch)?),
                ResolveOptions::directory(),
            )?);
        let reopened = self.comparison_root.as_ref().ok_or(StoreFailureV1::Closed)?;
        let original = rustix::fs::fstat(self.raw_root.as_ref().ok_or(StoreFailureV1::Closed)?)?;
        if reopened.identity().device != original.st_dev
            || reopened.identity().inode != original.st_ino
        {
            return Err(StoreFailureV1::Mismatch);
        }
        self.check_root_metadata(session, request)?;
        // Pending and completed backing comparisons both use the exact stored
        // original; this grants no new dispatch after terminal installation.
        session.require_online_store_readback(request)?;
        self.comparison_root = None;
        Ok(())
    }

    fn open_member(
        &mut self,
        index: usize,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        self.check_root(session, request)?;
        let member = self.members.get(index).ok_or(StoreFailureV1::Closed)?;
        let mut retained_name = String::new();
        retained_name.try_reserve_exact(member.expected.name.len())?;
        retained_name.push_str(&member.expected.name);
        let name = Path::new(&retained_name);
        let physical = match &member.expected.kind {
            NixStoreMemberKindV2::Content { .. } => {
                let expected = self.snapshot_file(&member.expected.name)?;
                PhysicalMemberV1::File(FsVerityBacking::open_beneath(
                    self.root()?, name,
                    FsVerityDigest::Sha256(decode_hex(&expected.verity_sha256)?),
                    expected.bytes, MAXIMUM_BYTES,
                )?)
            }
            NixStoreMemberKindV2::Directory(_) => PhysicalMemberV1::Directory {
                path: self.root()?.resolve(name, ResolveOptions::directory())?, readable: None,
            },
            NixStoreMemberKindV2::Symlink(_) => PhysicalMemberV1::Symlink {
                parent: self.root()?.resolve(
                    name.parent().ok_or(StoreFailureV1::Mismatch)?, ResolveOptions::directory(),
                )?,
                link: None,
            },
        };
        self.members[index].physical = Some(physical);

        // Every returned descriptor is installed before metadata or bookends.
        let member = &mut self.members[index];
        match member.physical.as_mut().ok_or(StoreFailureV1::Closed)? {
            PhysicalMemberV1::Directory { path, readable } => {
                *readable = Some(rustix::fs::openat(
                    path.as_fd(), c".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?);
            }
            PhysicalMemberV1::Symlink { parent, link } => {
                let leaf = name.file_name().ok_or(StoreFailureV1::Mismatch)?;
                *link = Some(rustix::fs::openat(
                    parent.as_fd(), leaf, OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
            }
            PhysicalMemberV1::File(_) => {}
        }
        self.check_root(session, request)
    }

    fn verify_file(
        &mut self,
        index: usize,
        control: bool,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        let (bytes, expected_hash, descriptor) = if control {
            let expected = self.snapshot_file(CONTROLS[index].0)?;
            (expected.bytes, decode_hex(&expected.sha256)?, None)
        } else {
            let member = self.members.get(index).ok_or(StoreFailureV1::Closed)?;
            let expected = self.snapshot_file(&member.expected.name)?;
            let NixStoreMemberKindV2::Content { descriptor, .. } = &member.expected.kind else {
                return Err(StoreFailureV1::Mismatch);
            };
            (expected.bytes, decode_hex(&expected.sha256)?, Some(descriptor.clone()))
        };
        let mut portable = descriptor.map(ObjectDescriptorVerifier::new);
        let mut raw = Sha256::new();
        let mut offset = 0;
        while offset < bytes {
            self.check_root(session, request)?;
            let wanted = usize::try_from((bytes - offset).min(SCRATCH_BYTES as u64))
                .map_err(|_| StoreFailureV1::Bound)?;
            let file = if control {
                self.controls.get(index).ok_or(StoreFailureV1::Closed)?
            } else {
                let Some(PhysicalMemberV1::File(file)) = &self.members[index].physical else {
                    return Err(StoreFailureV1::Closed);
                };
                file
            };
            let received = rustix::io::pread(file.as_fd(), &mut self.scratch[..wanted], offset)?;
            if received == 0 || received > wanted {
                return Err(StoreFailureV1::Mismatch);
            }
            raw.update(&self.scratch[..received]);
            if let Some(portable) = &mut portable {
                portable.update(&self.scratch[..received])?;
            }
            offset = offset.checked_add(received as u64).ok_or(StoreFailureV1::Bound)?;
            self.check_root(session, request)?;
        }

        self.check_root(session, request)?;
        let file = if control {
            self.controls.get(index).ok_or(StoreFailureV1::Closed)?
        } else {
            let Some(PhysicalMemberV1::File(file)) = &self.members[index].physical else {
                return Err(StoreFailureV1::Closed);
            };
            file
        };
        if rustix::io::pread(file.as_fd(), &mut self.scratch[..1], bytes)? != 0
            || <[u8; 32]>::from(raw.finalize()) != expected_hash
        {
            return Err(StoreFailureV1::Mismatch);
        }
        if let Some(portable) = portable {
            portable.finish()?;
        }
        let stat = rustix::fs::fstat(file.as_fd())?;
        if stat.st_size < 0 || u64::try_from(stat.st_size).ok() != Some(bytes) {
            return Err(StoreFailureV1::Mismatch);
        }
        require_label(file.as_fd(), None, session, request)?;
        self.check_root(session, request)
    }

    fn verify_controls(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        self.check_root(session, request)?;
        let schema = self.controls.get(1).ok_or(StoreFailureV1::Closed)?;
        let mut bytes = [0; 3];
        if schema.identity().bytes() != 2
            || rustix::io::pread(schema.as_fd(), &mut bytes, 0)? != 2
            || &bytes[..2] != b"10"
        {
            return Err(StoreFailureV1::Mismatch);
        }
        let database = self.constructor_readers.get(5).ok_or(StoreFailureV1::Closed)?;
        // The same opened directory must contain the closed checkpointed DB
        // set. WAL, SHM, journals and lock/migration artifacts are refused.
        let names = directory_names(database.as_fd(), session, request)?;
        if names != [b"db.sqlite".to_vec(), b"reserved".to_vec(), b"schema".to_vec()] {
            return Err(StoreFailureV1::Mismatch);
        }
        self.check_root(session, request)
    }

    fn verify_member(
        &mut self,
        index: usize,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        self.check_root(session, request)?;
        match &self.members[index].expected.kind {
            NixStoreMemberKindV2::Content { .. } => {
                self.verify_file(index, false, session, request)?;
                let member = &self.members[index];
                let Some(PhysicalMemberV1::File(file)) = &member.physical else {
                    return Err(StoreFailureV1::Closed);
                };
                if let NixStoreMemberKindV2::Content { metadata: Some(metadata), .. }
                    = &member.expected.kind
                {
                    require_metadata(file.as_fd(), None, metadata, session, request)?;
                }
            }
            NixStoreMemberKindV2::Directory(metadata) => {
                let Some(PhysicalMemberV1::Directory { path, readable: Some(readable) })
                    = &self.members[index].physical else
                {
                    return Err(StoreFailureV1::Closed);
                };
                let stat = rustix::fs::fstat(readable)?;
                if path.identity().device != stat.st_dev || path.identity().inode != stat.st_ino {
                    return Err(StoreFailureV1::Mismatch);
                }
                require_metadata(readable.as_fd(), None, metadata, session, request)?;
                let actual = directory_names(readable.as_fd(), session, request)?;
                let prefix = format!("{}/", self.members[index].expected.name);
                let mut expected = Vec::new();
                for member in &self.members {
                    if let Some(leaf) = member.expected.name.strip_prefix(&prefix)
                        && !leaf.contains('/')
                    {
                        expected.try_reserve_exact(1)?;
                        expected.push(leaf.as_bytes().to_vec());
                    }
                }
                expected.sort_unstable();
                if actual != expected {
                    return Err(StoreFailureV1::Mismatch);
                }
            }
            NixStoreMemberKindV2::Symlink(expected) => {
                let Some(PhysicalMemberV1::Symlink { link: Some(link), .. })
                    = &self.members[index].physical else
                {
                    return Err(StoreFailureV1::Closed);
                };
                let stat = rustix::fs::fstat(link)?;
                if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Symlink {
                    return Err(StoreFailureV1::Mismatch);
                }
                let mut target = [0; 4_097];
                let bytes = rustix::fs::readlinkat_raw(link, c"", &mut target)?;
                if bytes > 4_096 || &target[..bytes] != expected.target() {
                    return Err(StoreFailureV1::Mismatch);
                }
                let absolute = Path::new(compiled::DOMAIN_ROOT).join(&self.members[index].expected.name);
                require_metadata(
                    link.as_fd(), Some(&absolute), expected.metadata(), session, request,
                )?;
                let after = rustix::fs::statat(
                    rustix::fs::CWD, &absolute, rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )?;
                if after.st_dev != stat.st_dev || after.st_ino != stat.st_ino {
                    return Err(StoreFailureV1::Mismatch);
                }
            }
        }
        self.check_root(session, request)
    }

    fn require_hardlink_groups(&self) -> Result<(), StoreFailureV1> {
        for (index, left) in self.members.iter().enumerate() {
            let (NixStoreMemberKindV2::Content { hardlink: left_group, .. },
                Some(PhysicalMemberV1::File(left_file))) = (&left.expected.kind, &left.physical)
            else { continue };
            for right in &self.members[..index] {
                let (NixStoreMemberKindV2::Content { hardlink: right_group, .. },
                    Some(PhysicalMemberV1::File(right_file))) = (&right.expected.kind, &right.physical)
                else { continue };
                let same_inode = left_file.identity().device() == right_file.identity().device()
                    && left_file.identity().inode() == right_file.identity().inode();
                let same_group = left_group.is_some() && left_group == right_group;
                if same_inode != same_group {
                    return Err(StoreFailureV1::Mismatch);
                }
            }
        }
        Ok(())
    }

    fn recheck(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        if !self.admitted || self.failed || self.comparison_file.is_some()
            || self.comparison_path.is_some() || self.comparison_raw.is_some()
        {
            return Err(StoreFailureV1::Closed);
        }
        self.check_root(session, request)?;
        for (index, name) in CONSTRUCTOR_DIRECTORIES.iter().enumerate() {
            self.comparison_path = Some(self.root()?.resolve(
                Path::new(name), ResolveOptions::directory(),
            )?);
            let original = self.constructor_directories.get(index)
                .ok_or(StoreFailureV1::Closed)?;
            let compared = self.comparison_path.as_ref().ok_or(StoreFailureV1::Closed)?;
            let readable = self.constructor_readers.get(index).ok_or(StoreFailureV1::Closed)?;
            let stat = rustix::fs::fstat(readable)?;
            if original.identity() != compared.identity()
                || stat.st_dev != original.identity().device
                || stat.st_ino != original.identity().inode
                || stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o022 != 0
            {
                return Err(StoreFailureV1::Mismatch);
            }
            require_label(readable.as_fd(), None, session, request)?;
            self.check_root(session, request)?;
            self.comparison_path = None;
        }
        for (index, (name, maximum)) in CONTROLS.iter().enumerate() {
            let expected = self.snapshot_file(name)?;
            self.comparison_file = Some(FsVerityBacking::open_beneath(
                self.root()?, Path::new(name),
                FsVerityDigest::Sha256(decode_hex(&expected.verity_sha256)?),
                expected.bytes, *maximum,
            )?);
            require_same_backing(
                self.controls.get(index).ok_or(StoreFailureV1::Closed)?,
                self.comparison_file.as_ref().ok_or(StoreFailureV1::Closed)?,
            )?;
            self.verify_file(index, true, session, request)?;
            self.check_root(session, request)?;
            self.comparison_file = None;
        }
        self.verify_controls(session, request)?;

        for index in 0..self.members.len() {
            let expected = &self.members[index].expected;
            let mut name = String::new();
            name.try_reserve_exact(expected.name.len())?;
            name.push_str(&expected.name);
            match &expected.kind {
                NixStoreMemberKindV2::Content { .. } => {
                    let expected = self.snapshot_file(&name)?;
                    self.comparison_file = Some(FsVerityBacking::open_beneath(
                        self.root()?, Path::new(&name),
                        FsVerityDigest::Sha256(decode_hex(&expected.verity_sha256)?),
                        expected.bytes, MAXIMUM_BYTES,
                    )?);
                    let Some(PhysicalMemberV1::File(original)) = &self.members[index].physical else {
                        return Err(StoreFailureV1::Closed);
                    };
                    require_same_backing(
                        original, self.comparison_file.as_ref().ok_or(StoreFailureV1::Closed)?,
                    )?;
                }
                NixStoreMemberKindV2::Directory(_) => {
                    self.comparison_path = Some(self.root()?.resolve(
                        Path::new(&name), ResolveOptions::directory(),
                    )?);
                    let Some(PhysicalMemberV1::Directory { path: original, .. })
                        = &self.members[index].physical else
                    {
                        return Err(StoreFailureV1::Closed);
                    };
                    if self.comparison_path.as_ref().ok_or(StoreFailureV1::Closed)?.identity()
                        != original.identity()
                    {
                        return Err(StoreFailureV1::Mismatch);
                    }
                }
                NixStoreMemberKindV2::Symlink(_) => {
                    let relative = Path::new(&name);
                    self.comparison_path = Some(self.root()?.resolve(
                        relative.parent().ok_or(StoreFailureV1::Mismatch)?,
                        ResolveOptions::directory(),
                    )?);
                    self.comparison_raw = Some(rustix::fs::openat(
                        self.comparison_path.as_ref().ok_or(StoreFailureV1::Closed)?.as_fd(),
                        relative.file_name().ok_or(StoreFailureV1::Mismatch)?,
                        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty(),
                    )?);
                    let Some(PhysicalMemberV1::Symlink { link: Some(original), .. })
                        = &self.members[index].physical else
                    {
                        return Err(StoreFailureV1::Closed);
                    };
                    let actual = rustix::fs::fstat(
                        self.comparison_raw.as_ref().ok_or(StoreFailureV1::Closed)?,
                    )?;
                    let original = rustix::fs::fstat(original)?;
                    if actual.st_dev != original.st_dev || actual.st_ino != original.st_ino {
                        return Err(StoreFailureV1::Mismatch);
                    }
                }
            }
            self.verify_member(index, session, request)?;
            self.check_root(session, request)?;
            self.comparison_file = None;
            self.comparison_path = None;
            self.comparison_raw = None;
        }
        self.require_hardlink_groups()?;
        self.check_root(session, request)
    }
}

fn require_same_backing(
    original: &FsVerityBacking, compared: &FsVerityBacking,
) -> Result<(), StoreFailureV1> {
    let before = original.identity();
    let after = compared.identity();
    if before.device() != after.device() || before.inode() != after.inode()
        || before.bytes() != after.bytes() || original.verified_verity() != compared.verified_verity()
    {
        return Err(StoreFailureV1::Mismatch);
    }
    Ok(())
}

/// Owns physical and process components without any self-referential loan.
///
/// The driving loan borrows only `reader.process`; physical and image checks
/// borrow the disjoint components. No child/FD is extracted across a gate.
pub(super) struct StoreReadbackV1 {
    backing: StoreBackingV1,
    reader: ReaderAttemptV1,
    failed: bool,
    completed: bool,
    output_postflight: OnlinePostflightV1,
}

impl StoreReadbackV1 {
    pub(super) fn new(profile: OnlineFloorProfileV1, issuer: [u8; 48]) -> Self {
        Self {
            backing: StoreBackingV1::new(profile, issuer),
            reader: ReaderAttemptV1::new(),
            failed: false,
            completed: false,
            output_postflight: OnlinePostflightV1::new(),
        }
    }

    pub(super) fn reserve_selected_postflight(&mut self) -> Result<(), StoreFailureV1> {
        self.backing.reserve_selected_postflight(3)
    }

    pub(super) fn observe_selected_postflight(&mut self) -> bool {
        self.backing.observe_selected_postflight()
    }

    /// Compares a held GC directory against the SAME retained Store root name.
    ///
    /// This negative-only loan does not use a failed owner's positive getter,
    /// open another directory, or grant a root registration/currentness right.
    pub(super) fn compare_gc_directory_original(
        &self,
        role: GcDirectoryV1,
        file: BorrowedFd<'_>,
        identity: (u64, u64),
    ) -> Result<(), StoreFailureV1> {
        let root = self.backing.raw_root.as_ref().ok_or(StoreFailureV1::Closed)?;
        compare_named_original(file, Some((root.as_fd(), Path::new(role.relative_name()))),
            Some(identity))
    }

    pub(super) fn resolve(
        &mut self,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ()> {
        if self.failed || self.completed {
            return Err(());
        }
        self.failed = true;
        self.backing.admit(recipe, session, request)?;
        let result = self.reader.run(&mut self.backing, recipe, session, request);
        if let Err(cause) = result {
            self.reader.first_failure.get_or_insert(cause);
            return Err(());
        }
        self.failed = false;
        self.completed = true;
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&StoreFailureV1> {
        self.backing.failure().or(self.reader.first_failure.as_ref())
    }

    /// Creates an empty output destination associated with this original.
    ///
    /// # Errors
    ///
    /// Refuses failed, unfinished or already-output originals. The empty
    /// destination grants no physical/currentness authority before admission.
    pub(super) fn output_destination(&self) -> Result<Self, StoreFailureV1> {
        if self.failed || !self.completed || self.backing.outputs {
            return Err(StoreFailureV1::Closed);
        }
        let mut destination = Self::new(self.backing.profile, self.backing.issuer);
        destination.backing.outputs = true;
        destination.backing.reserve_selected_postflight(crate::handshake::ONLINE_POSTFLIGHT_PASSES_V1)?;
        Ok(destination)
    }

    /// Reads expected existing outputs without mutating the Store or database.
    ///
    /// # Errors
    ///
    /// Refuses repeated use, an altered original/control/snapshot, missing or
    /// noncanonical outputs, or a native/process/currentness failure. Both
    /// originals retain their own full typed cause and partial custody.
    pub(super) fn read_outputs(
        &mut self,
        original: &mut Self,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ()> {
        if self.failed || self.completed || !self.backing.outputs
            || self.backing.output_members.is_some()
        {
            return Err(());
        }
        self.failed = true;
        let result = (|| {
            original.recheck_completed(session, request).map_err(|_| StoreFailureV1::Closed)?;
            self.backing.output_members = Some(project_store_output_members_v2(
                recipe, original.backing.members.iter().map(|member| &member.expected),
            )?);
            for member in self.backing.output_members.as_ref().ok_or(StoreFailureV1::Closed)? {
                if original.backing.members.binary_search_by(|old| {
                    old.expected.name.cmp(&member.name)
                }).is_ok() {
                    return Err(StoreFailureV1::Mismatch);
                }
            }
            self.backing.admit(recipe, session, request).map_err(|_| StoreFailureV1::Closed)?;
            self.backing.require_same_controls(&original.backing)?;
            self.reader.run(&mut self.backing, recipe, session, request)?;
            self.backing.require_same_controls(&original.backing)?;
            original.recheck_completed(session, request).map_err(|_| StoreFailureV1::Closed)?;
            Ok(())
        })();
        if let Err(cause) = result {
            self.reader.first_failure.get_or_insert(cause);
        }
        let original_debt = original.observe_selected_postflight();
        let output_debt = self.observe_selected_postflight();
        session.observe_online_postflight(&mut self.output_postflight);
        if self.reader.first_failure.is_some() || original_debt || output_debt
            || self.output_postflight.failed()
        {
            return Err(());
        }
        self.failed = false;
        self.completed = true;
        Ok(())
    }

    /// Resolves the reader marker to its actual original typed process cause.
    pub(super) fn process_cause(&self)
        -> Option<&aos_sandbox_linux::process::FixedProcessDrivenCauseV1>
    {
        self.reader.process.as_ref().and_then(FixedProcessDrivenSessionV1::cause)
    }

    pub(super) fn cleanup_debt(&self)
        -> Option<&aos_sandbox_linux::process::FixedProcessDrivenDebtV1>
    {
        self.reader.process.as_ref().and_then(FixedProcessDrivenSessionV1::cleanup_debt)
    }

    /// Parks a fixed directory opened beneath this SAME completed Store root.
    ///
    /// # Errors
    ///
    /// Refuses non-output, failed or incomplete owners, occupied destinations,
    /// changed original Session/root, or a failed fixed beneath-root open. The
    /// returned directory is parked before every later fallible observation.
    pub(super) fn open_gc_directory_into(
        &mut self,
        role: GcDirectoryV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        target: &mut Option<ResolvedPath>,
    ) -> Result<(), ()> {
        if self.failed || !self.completed || !self.backing.outputs || target.is_some() {
            return Err(());
        }
        self.failed = true;
        let result = (|| {
            self.backing.check_root(session, request)?;
            // These two fixed writable subtrees are separate bind mounts under
            // the otherwise read-only Store. Keep the same beneath/no-symlink
            // engine without rejecting the deliberate nested mount boundary.
            *target = Some(self.backing.root()?.resolve(
                Path::new(role.relative_name()),
                ResolveOptions { no_mount_crossing: false, require_directory: true },
            )?);
            self.backing.check_root(session, request)
        })();
        if let Err(cause) = result {
            self.reader.first_failure.get_or_insert(cause);
            return Err(());
        }
        self.failed = false;
        Ok(())
    }

    pub(super) fn recheck_completed(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ()> {
        if self.failed || !self.completed {
            return Err(());
        }
        self.failed = true;
        let result = self.backing.recheck(session, request);
        if let Err(cause) = result {
            self.reader.first_failure.get_or_insert(cause);
            return Err(());
        }
        self.failed = false;
        Ok(())
    }
}

#[derive(Serialize)]
struct ReaderRequestV1<'a> {
    version: u32,
    paths: Vec<ReaderPathV1<'a>>,
}

#[derive(Serialize)]
struct RootReaderRequestV2<'a> {
    version: u32,
    operation: &'static str,
    paths: Vec<ReaderPathV1<'a>>,
    names: &'a [String],
}

/// Selects only the fixed private upstream GC-root engine operations.
#[derive(Clone, Copy)]
pub(super) enum RootReaderCommandV1 {
    Plan,
    Register,
    Inspect,
}

impl RootReaderCommandV1 {
    const fn name(self) -> &'static str {
        match self {
            Self::Plan => "plan-roots",
            Self::Register => "register-roots",
            Self::Inspect => "inspect-roots",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootReaderResponseV1 {
    pub(super) version: u32,
    pub(super) roots: Vec<RootReaderEntryV1>,
}

#[derive(Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RootReaderEntryV1 {
    pub(super) path: String,
    pub(super) direct: String,
    pub(super) indirect: String,
    pub(super) target: String,
}

/// Retains a one-shot root operation's actual process and complete response.
pub(super) struct RootReaderV1 {
    reader: ReaderAttemptV1,
    started: bool,
    complete: bool,
}

impl RootReaderV1 {
    pub(super) fn new() -> Self {
        Self { reader: ReaderAttemptV1::new(), started: false, complete: false }
    }

    pub(super) fn run(
        &mut self,
        output: &mut StoreReadbackV1,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        command: RootReaderCommandV1,
        names: &[String],
    ) -> Result<(), ()> {
        if self.started || !output.completed || output.failed || !output.backing.outputs {
            return Err(());
        }
        self.started = true;
        let result = self.reader.run_selected(
            &mut output.backing, recipe, session, request, Some((command, names)),
        );
        if let Err(cause) = result {
            self.reader.first_failure.get_or_insert(cause);
            return Err(());
        }
        self.complete = true;
        Ok(())
    }

    pub(super) fn response(&self) -> Result<&RootReaderResponseV1, StoreFailureV1> {
        if !self.complete || self.reader.first_failure.is_some() {
            return Err(StoreFailureV1::Closed);
        }
        self.reader.root_response.as_ref().ok_or(StoreFailureV1::Closed)
    }

    pub(super) fn failure(&self) -> Option<&StoreFailureV1> {
        self.reader.first_failure.as_ref()
    }

    pub(super) fn process_cause(&self)
        -> Option<&aos_sandbox_linux::process::FixedProcessDrivenCauseV1>
    {
        self.reader.process.as_ref().and_then(FixedProcessDrivenSessionV1::cause)
    }

    pub(super) fn cleanup_debt(&self)
        -> Option<&aos_sandbox_linux::process::FixedProcessDrivenDebtV1>
    {
        self.reader.process.as_ref().and_then(FixedProcessDrivenSessionV1::cleanup_debt)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReaderPathV1<'a> {
    path: &'a str,
    nar_size: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReaderResponseV1 {
    version: u32,
    objects: Vec<ReaderObjectV1>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReaderObjectV1 {
    path: String,
    db_nar_hash: String,
    db_nar_size: u64,
    actual_nar_hash: String,
    actual_nar_size: u64,
    references: Vec<String>,
    deriver: Option<String>,
}

struct ReaderAttemptV1 {
    identity: ReaderIdentityV1,
    executable: Option<OwnedFd>,
    stdin: Option<OwnedFd>,
    writer: Option<OwnedFd>,
    request: Vec<u8>,
    sent: usize,
    process: Option<FixedProcessDrivenSessionV1>,
    response: Option<ReaderResponseV1>,
    first_failure: Option<StoreFailureV1>,
    root_response: Option<RootReaderResponseV1>,
    postflight: OnlinePostflightV1,
}

impl ReaderAttemptV1 {
    fn new() -> Self {
        Self {
            identity: ReaderIdentityV1::new(),
            executable: None,
            stdin: None,
            writer: None,
            request: Vec::new(),
            sent: 0,
            process: None,
            response: None,
            first_failure: None,
            root_response: None,
            postflight: OnlinePostflightV1::new(),
        }
    }

    fn run(
        &mut self,
        backing: &mut StoreBackingV1,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        self.run_selected(backing, recipe, session, original, None)
    }

    fn run_selected(
        &mut self,
        backing: &mut StoreBackingV1,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &AuthenticatedBrokerMethodRequestV1,
        roots: Option<(RootReaderCommandV1, &[String])>,
    ) -> Result<(), StoreFailureV1> {
        if !backing.outputs && roots.is_none() {
            // The ordinary method50 recipe, including local driver disposal,
            // has no selected postflight or additional allocation/effect.
            return self.run_recipe(backing, recipe, session, original, roots);
        }
        let result = self.run_recipe(backing, recipe, session, original, roots);
        if let Err(cause) = result {
            self.first_failure.get_or_insert(cause);
        }
        let physical_debt = backing.observe_selected_postflight();
        session.observe_online_postflight(&mut self.postflight);
        if self.first_failure.is_some() || physical_debt || self.postflight.failed() {
            return Err(StoreFailureV1::ReaderStopped);
        }
        Ok(())
    }

    // One process/write/poll/decoder engine for both dispositions. Returning
    // ends only the driver loan; the actual process/cause/debt stay resident.
    fn run_recipe(
        &mut self,
        backing: &mut StoreBackingV1,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &AuthenticatedBrokerMethodRequestV1,
        roots: Option<(RootReaderCommandV1, &[String])>,
    ) -> Result<(), StoreFailureV1> {
        backing.check_root(session, original)?;
        self.identity.admit()?;
        self.executable = Some(rustix::fs::open(
            compiled::READER_PATH, OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        let actual = rustix::fs::fstat(self.executable.as_ref().ok_or(StoreFailureV1::Closed)?)?;
        let expected = self.identity.executable.as_ref().ok_or(StoreFailureV1::Closed)?
            .physical_identity();
        if (actual.st_dev, actual.st_ino, u64::try_from(actual.st_size).ok())
            != (expected.0, expected.1, Some(expected.2))
        {
            return Err(StoreFailureV1::Mismatch);
        }

        let mut paths = Vec::new();
        let count = if backing.outputs {
            recipe.outputs.len()
        } else {
            recipe.inputs.len().checked_add(1).ok_or(StoreFailureV1::Bound)?
        };
        if count > MAXIMUM_INPUTS {
            return Err(StoreFailureV1::Bound);
        }
        paths.try_reserve_exact(count)?;
        if backing.outputs {
            for output in &recipe.outputs {
                paths.push(ReaderPathV1 { path: &output.object.path, nar_size: output.object.nar_size });
            }
        } else {
            for object in std::iter::once(&recipe.derivation).chain(&recipe.inputs) {
                paths.push(ReaderPathV1 { path: &object.path, nar_size: object.nar_size });
            }
        }
        paths.sort_unstable_by(|left, right| left.path.cmp(right.path));
        if !paths.windows(2).all(|pair| pair[0].path < pair[1].path) {
            return Err(StoreFailureV1::Mismatch);
        }
        self.request = if let Some((command, names)) = roots {
            if !backing.outputs || names.len() != paths.len() || names.len() > 256
                || names.iter().any(|name| name.len() != 64
                    || !name.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
            {
                return Err(StoreFailureV1::Bound);
            }
            serde_json::to_vec(&RootReaderRequestV2 {
                version: 2, operation: command.name(), paths, names,
            })?
        } else {
            serde_json::to_vec(&ReaderRequestV1 { version: 1, paths })?
        };
        if self.request.len() > 262_144 {
            return Err(StoreFailureV1::Bound);
        }

        let prepared = prepare_fixed_process_driven_invocation_v1(FixedProcessRequest {
            executable: Path::new(compiled::READER_PATH), arguments: &[],
            timeout: Duration::from_secs(60), maximum_stdout_bytes: 4_194_304,
            maximum_stderr_bytes: 131_072,
        })?;
        let cut = FixedProcessBoottimeCutV1::new(original.deadline_boottime_nanoseconds())?;
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
        self.stdin = Some(read);
        self.writer = Some(write);
        let writer = self.writer.as_ref().ok_or(StoreFailureV1::Closed)?;
        let flags = rustix::fs::fcntl_getfl(writer)?;
        rustix::fs::fcntl_setfl(writer, flags | OFlags::NONBLOCK)?;
        backing.check_root(session, original)?;

        // All fallible preparation is complete; the exact original input
        // transfer into the resident mechanical owner is now infallible.
        let (Some(executable), Some(stdin)) = (self.executable.take(), self.stdin.take()) else {
            std::process::abort();
        };
        self.process = Some(FixedProcessDrivenSessionV1::park_path(
            prepared,
            FixedProcessDrivenInputsV1 {
                executable, stdin: Some(stdin), inherited: Vec::new(),
                capture: FixedProcessCaptureV1::default(),
            },
            cut,
        ));

        let process = self.process.as_mut().ok_or(StoreFailureV1::Closed)?;
        let mut driving = process.drive();
        loop {
            backing.check_root(session, original)?;
            let progress = driving.advance_once();
            backing.check_root(session, original)?;
            match progress {
                FixedProcessDrivenProgressV1::Ended => break,
                FixedProcessDrivenProgressV1::Debt => return Err(StoreFailureV1::ReaderStopped),
                FixedProcessDrivenProgressV1::Progressed | FixedProcessDrivenProgressV1::Waiting => {}
            }

            if self.writer.is_some() {
                if let Some((child, first_info)) = driving.original_child() {
                    self.identity.require(child, first_info, session, original)?;
                    let end = self.sent.checked_add(SCRATCH_BYTES)
                        .ok_or(StoreFailureV1::Bound)?.min(self.request.len());
                    let writer = self.writer.as_ref().ok_or(StoreFailureV1::Closed)?;
                    if matches!(roots, Some((RootReaderCommandV1::Register, _))) {
                        // Reacquire from the same originals immediately before
                        // each physical request fragment, not from an earlier
                        // root-plan or process-preparation observation.
                        session.require_online_existing_output_suffix(original)?;
                    }
                    let result = rustix::io::write(writer, &self.request[self.sent..end]);
                    match result {
                        Ok(0) => return Err(StoreFailureV1::Mismatch),
                        Ok(count) => self.sent += count,
                        Err(rustix::io::Errno::AGAIN) => {}
                        Err(cause) => return Err(StoreFailureV1::Native(cause)),
                    }
                    self.identity.require(child, first_info, session, original)?;
                    backing.check_root(session, original)?;
                    if self.sent == self.request.len() {
                        if matches!(roots, Some((RootReaderCommandV1::Register, _))) {
                            session.require_online_existing_output_suffix(original)?;
                        }
                        // No byte or EOF crosses before image/peer/cut checks.
                        // The writer is never an inherited child role.
                        self.writer = None;
                    }
                }
            }

            let waited = {
                let Some(view) = driving.wait_view() else { continue };
                let mut polls = Vec::new();
                polls.try_reserve_exact(6)?;
                for descriptor in view.descriptors() {
                    polls.push(rustix::event::PollFd::from_borrowed_fd(
                        descriptor, rustix::event::PollFlags::IN,
                    ));
                }
                if let Some(writer) = &self.writer {
                    polls.push(rustix::event::PollFd::new(writer, rustix::event::PollFlags::OUT));
                }
                session.require_online_request(original)?;
                let waited = rustix::event::poll(&mut polls, None);
                session.require_online_request(original)?;
                waited
            };
            if let Err(cause) = waited {
                driving.wait_failed(cause.into());
                return Err(StoreFailureV1::ReaderStopped);
            }
        }
        drop(driving);
        let process = self.process.as_ref().ok_or(StoreFailureV1::Closed)?;
        if self.writer.is_some() || self.sent != self.request.len()
            || process.cause().is_some() || process.cleanup_debt().is_some()
            || !matches!(process.outcome(), Some(FixedProcessRetainedSessionOutcome::Completed {
                exit_code: Some(0), signal: None, ..
            }))
        {
            return Err(StoreFailureV1::ReaderStopped);
        }
        let capture = process.capture().ok_or(StoreFailureV1::Closed)?;
        if let Some((_, names)) = roots {
            self.root_response = Some(decode_root_reader_response(capture.stdout(), recipe, names)?);
        } else {
            self.response = Some(if backing.outputs {
                decode_reader_response_for(capture.stdout(), recipe, true)?
            } else {
                decode_reader_response(capture.stdout(), recipe)?
            });
        }
        backing.recheck(session, original)?;
        session.require_online_request(original)?;
        Ok(())
    }
}

// Each caller reserves the complete selected diagnostic prefix before any
// physical crossing. Only failures own data here; successful unit comparisons
// have no resources to release and never establish currentness.
fn retain_postflight_result(
    debt: &mut Vec<StoreFailureV1>,
    result: Result<(), StoreFailureV1>,
) {
    if let Err(cause) = result {
        debt.push(cause);
    }
}

fn compare_named_original(
    file: BorrowedFd<'_>,
    named: Option<(BorrowedFd<'_>, &Path)>,
    identity: Option<(u64, u64)>,
) -> Result<(), StoreFailureV1> {
    let observed = rustix::fs::fstat(file)?;
    if let Some((device, inode)) = identity
        && (observed.st_dev, observed.st_ino) != (device, inode)
    {
        return Err(StoreFailureV1::Mismatch);
    }
    if let Some((directory, name)) = named {
        let named = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        if (named.st_dev, named.st_ino) != (observed.st_dev, observed.st_ino) {
            return Err(StoreFailureV1::Mismatch);
        }
    }
    Ok(())
}

fn decode_root_reader_response(
    bytes: &[u8], recipe: &NixPreadmittedRecipeV2, names: &[String],
) -> Result<RootReaderResponseV1, StoreFailureV1> {
    if bytes.is_empty() || bytes.len() > 4_194_304 {
        return Err(StoreFailureV1::Bound);
    }
    let response: RootReaderResponseV1 = serde_json::from_slice(bytes)?;
    if response.version != 2 || response.roots.len() != names.len()
        || response.roots.len() != recipe.outputs.len()
        || serde_json::to_vec(&response)? != bytes
        || !response.roots.windows(2).all(|pair| pair[0].path < pair[1].path)
    {
        return Err(StoreFailureV1::Mismatch);
    }
    let direct_prefix = format!("{}/nix/var/nix/gcroots/aos-online/", compiled::DOMAIN_ROOT);
    let indirect_prefix = format!("{}/nix/var/nix/gcroots/auto/", compiled::DOMAIN_ROOT);
    for (entry, name) in response.roots.iter().zip(names) {
        if !recipe.outputs.iter().any(|output| output.object.path == entry.path)
            || entry.target != entry.path
            || entry.direct.strip_prefix(direct_prefix.as_str()) != Some(name.as_str())
        {
            return Err(StoreFailureV1::Mismatch);
        }
        let indirect = entry.indirect.strip_prefix(indirect_prefix.as_str())
            .ok_or(StoreFailureV1::Mismatch)?;
        // The upstream SHA1/Nix32 engine supplies this name. Rust only checks
        // its closed width/alphabet; actual named links are separately read.
        if indirect.len() != 32 || !indirect.bytes().all(|byte| {
            b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)
        }) {
            return Err(StoreFailureV1::Mismatch);
        }
    }
    Ok(response)
}

fn decode_reader_response(
    bytes: &[u8], recipe: &NixPreadmittedRecipeV2,
) -> Result<ReaderResponseV1, StoreFailureV1> {
    decode_reader_response_for(bytes, recipe, false)
}

fn decode_reader_response_for(
    bytes: &[u8], recipe: &NixPreadmittedRecipeV2, outputs: bool,
) -> Result<ReaderResponseV1, StoreFailureV1> {
    if bytes.is_empty() || bytes.len() > 4_194_304 {
        return Err(StoreFailureV1::Bound);
    }
    let response: ReaderResponseV1 = serde_json::from_slice(bytes)?;
    let count = if outputs { recipe.outputs.len() } else { recipe.inputs.len() + 1 };
    if response.version != 1 || response.objects.len() != count
        || serde_json::to_vec(&response)? != bytes
        || !response.objects.windows(2).all(|pair| pair[0].path < pair[1].path)
    {
        return Err(StoreFailureV1::Mismatch);
    }
    for observed in &response.objects {
        let expected = if outputs {
            recipe.outputs.iter().map(|output| &output.object)
                .find(|object| object.path == observed.path)
        } else {
            std::iter::once(&recipe.derivation).chain(&recipe.inputs)
                .find(|object| object.path == observed.path)
        }.ok_or(StoreFailureV1::Mismatch)?;
        let expected_hash = format!("sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(expected.nar_sha256.as_bytes()));
        if observed.db_nar_hash != expected_hash || observed.actual_nar_hash != expected_hash
            || observed.db_nar_size != expected.nar_size || observed.actual_nar_size != expected.nar_size
            || observed.references != expected.references
            || observed.deriver.as_ref().is_some_and(|path| {
                path.is_empty() || path.len() > 4_096 || path.as_bytes().contains(&0)
            })
        {
            return Err(StoreFailureV1::Mismatch);
        }
        // Deriver syntax is checked by the sole measured upstream Store parser
        // before serialization. It is historical DATA, not build authority.
    }
    Ok(response)
}

struct ReaderIdentityV1 {
    executable: Option<crate::immutable_image::RetainedImmutableFileV1>,
    loader: Option<crate::immutable_image::RetainedImmutableFileV1>,
    parent: Option<PidFd>,
    parent_info: Option<PidFdInfo>,
    child_info: Option<PidFdInfo>,
    maps: ProcFieldV1,
    context: ProcFieldV1,
    status: ProcFieldV1,
}

impl ReaderIdentityV1 {
    fn new() -> Self {
        Self {
            executable: None,
            loader: None,
            parent: None,
            parent_info: None,
            child_info: None,
            maps: ProcFieldV1::new(65_536),
            context: ProcFieldV1::new(256),
            status: ProcFieldV1::new(65_536),
        }
    }

    fn admit(&mut self) -> Result<(), StoreFailureV1> {
        self.executable = Some(crate::immutable_image::RetainedImmutableFileV1::open(
            Path::new(compiled::READER_PATH).to_path_buf(), compiled::READER_CONTENT_SHA256,
        )?);
        self.loader = Some(crate::immutable_image::RetainedImmutableFileV1::open(
            Path::new(compiled::LOADER_PATH).to_path_buf(), compiled::LOADER_CONTENT_SHA256,
        )?);
        self.parent = Some(PidFd::open(std::num::NonZeroU32::new(std::process::id())
            .ok_or(StoreFailureV1::Mismatch)?)?);
        self.parent_info = Some(self.parent.as_ref().ok_or(StoreFailureV1::Closed)?.info()?);
        Ok(())
    }

    fn require(
        &mut self,
        child: &PidFd,
        original: PidFdInfo,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        session.require_online_request(request)?;
        let parent = self.parent.as_ref().ok_or(StoreFailureV1::Closed)?;
        let original_parent = self.parent_info.ok_or(StoreFailureV1::Closed)?;
        if parent.info()? != original_parent || !parent.is_alive()?
            || original.pid() == 0 || original.pid() == std::process::id()
            || original.parent_pid() != std::process::id()
            || original.pid() != original.thread_group_id()
            || original.cgroup_id().is_none() || original.cgroup_id() != original_parent.cgroup_id()
            || !root_credentials(original) || child.info()? != original || !child.is_alive()?
            || self.child_info.is_some_and(|first| first != original)
        {
            return Err(StoreFailureV1::Mismatch);
        }
        self.child_info.get_or_insert(original);
        let executable = self.executable.as_ref().ok_or(StoreFailureV1::Closed)?;
        let loader = self.loader.as_ref().ok_or(StoreFailureV1::Closed)?;
        executable.revalidate()?;
        loader.revalidate()?;
        executable.require_executed(original.pid())?;

        self.maps.read(original.pid(), "maps", session, request)?;
        let maps = std::str::from_utf8(&self.maps.bytes).map_err(|_| StoreFailureV1::Mismatch)?;
        if !loader.mapped_in_helper_data_v5(maps)? {
            return Err(StoreFailureV1::Mismatch);
        }
        self.context.read(original.pid(), "attr/current", session, request)?;
        if self.context.bytes != b"system_u:system_r:aos_nix_online_store_reader_t\n"
            && self.context.bytes != b"system_u:system_r:aos_nix_online_store_reader_t"
            && self.context.bytes != b"system_u:system_r:aos_nix_online_store_reader_t\0"
        {
            return Err(StoreFailureV1::Mismatch);
        }
        self.status.read(original.pid(), "status", session, request)?;
        require_reader_status(&self.status.bytes)?;
        executable.require_executed(original.pid())?;
        executable.revalidate()?;
        loader.revalidate()?;
        if parent.info()? != original_parent || !parent.is_alive()?
            || child.info()? != original || !child.is_alive()?
        {
            return Err(StoreFailureV1::Mismatch);
        }
        session.require_online_request(request)?;
        Ok(())
    }
}

fn root_credentials(info: PidFdInfo) -> bool {
    info.credentials().is_some_and(|credentials| {
        credentials.real_user_id() == 0 && credentials.real_group_id() == 0
            && credentials.effective_user_id() == 0 && credentials.effective_group_id() == 0
            && credentials.saved_user_id() == 0 && credentials.saved_group_id() == 0
            && credentials.filesystem_user_id() == 0 && credentials.filesystem_group_id() == 0
    })
}

struct ProcFieldV1 {
    descriptor: Option<OwnedFd>,
    bytes: Vec<u8>,
    maximum: usize,
}

impl ProcFieldV1 {
    fn new(maximum: usize) -> Self {
        Self { descriptor: None, bytes: Vec::new(), maximum }
    }

    fn read(
        &mut self,
        actual_pid: u32,
        fixed_field: &str,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), StoreFailureV1> {
        if self.descriptor.is_none() {
            self.descriptor = Some(rustix::fs::open(
                format!("/proc/{actual_pid}/{fixed_field}"),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW, Mode::empty(),
            )?);
        }
        let descriptor = self.descriptor.as_ref().ok_or(StoreFailureV1::Closed)?;
        if rustix::fs::fstatfs(descriptor)?.f_type as u64 != 0x9fa0 {
            return Err(StoreFailureV1::Mismatch);
        }
        let length = self.maximum.checked_add(1).ok_or(StoreFailureV1::Bound)?;
        self.bytes.try_reserve_exact(length.saturating_sub(self.bytes.len()))?;
        self.bytes.resize(length, 0);
        let mut offset = 0;
        while offset < length {
            session.require_online_request(request)?;
            let end = offset.checked_add(SCRATCH_BYTES).ok_or(StoreFailureV1::Bound)?.min(length);
            let received = rustix::io::pread(descriptor, &mut self.bytes[offset..end], offset as u64)?;
            session.require_online_request(request)?;
            if received == 0 {
                self.bytes.truncate(offset);
                return Ok(());
            }
            offset += received;
        }
        Err(StoreFailureV1::Bound)
    }
}

fn require_reader_status(bytes: &[u8]) -> Result<(), StoreFailureV1> {
    let status = std::str::from_utf8(bytes).map_err(|_| StoreFailureV1::Mismatch)?;
    // The reader uses existing PATH capability inheritance. It is NOT claimed
    // cap-empty: the actual fixed root control recipe keeps only SETUID/GID.
    for (name, expected, radix) in [
        ("CapInh", 0, 16), ("CapPrm", 0xc0, 16), ("CapEff", 0xc0, 16),
        ("CapBnd", 0xc0, 16), ("CapAmb", 0, 16), ("NoNewPrivs", 1, 10),
    ] {
        let mut fields = status.lines().filter_map(|line| {
            let (field, value) = line.split_once(':')?;
            (field == name).then_some(value.trim())
        });
        let value = fields.next().ok_or(StoreFailureV1::Mismatch)?;
        if fields.next().is_some() || u64::from_str_radix(value, radix).ok() != Some(expected) {
            return Err(StoreFailureV1::Mismatch);
        }
    }
    Ok(())
}

fn directory_names(
    directory: BorrowedFd<'_>,
    session: &mut DormantAuthenticatedBrokerSessionV1,
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<Vec<Vec<u8>>, StoreFailureV1> {
    let mut scratch = [MaybeUninit::uninit(); 4_096];
    session.require_online_store_readback(request)?;
    rustix::fs::seek(directory, rustix::fs::SeekFrom::Start(0))?;
    session.require_online_store_readback(request)?;
    let mut stream = rustix::fs::RawDir::new(directory, &mut scratch);
    let mut names = Vec::new();
    loop {
        session.require_online_store_readback(request)?;
        let next = stream.next();
        session.require_online_store_readback(request)?;
        let Some(entry) = next else { break };
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() >= MAXIMUM_INPUTS || name.len() > 255 {
            return Err(StoreFailureV1::Bound);
        }
        names.try_reserve_exact(1)?;
        let mut retained = Vec::new();
        retained.try_reserve_exact(name.len())?;
        retained.extend_from_slice(name);
        names.push(retained);
    }
    names.sort_unstable();
    if !names.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(StoreFailureV1::Mismatch);
    }
    Ok(names)
}

fn require_label(
    file: BorrowedFd<'_>,
    symlink: Option<&Path>,
    session: &mut DormantAuthenticatedBrokerSessionV1,
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<(), StoreFailureV1> {
    let mut bytes = [0; 256];
    session.require_online_store_readback(request)?;
    let count = match symlink {
        Some(path) => rustix::fs::lgetxattr(path, c"security.selinux", &mut bytes)?,
        None => rustix::fs::fgetxattr(file, c"security.selinux", &mut bytes)?,
    };
    if &bytes[..count] != STORE_LABEL {
        return Err(StoreFailureV1::Mismatch);
    }
    session.require_online_store_readback(request)?;
    Ok(())
}

fn require_metadata(
    file: BorrowedFd<'_>,
    symlink: Option<&Path>,
    expected: &FilesystemMetadata,
    session: &mut DormantAuthenticatedBrokerSessionV1,
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<(), StoreFailureV1> {
    session.require_online_store_readback(request)?;
    let stat = rustix::fs::fstat(file)?;
    if stat.st_mode & 0o7777 != u32::from(expected.mode())
        || stat.st_uid != expected.uid() || stat.st_gid != expected.gid()
        || stat.st_mtime != expected.mtime_seconds()
        || u32::try_from(stat.st_mtime_nsec).ok() != Some(expected.mtime_nanos())
    {
        return Err(StoreFailureV1::Mismatch);
    }
    require_label(file, symlink, session, request)?;

    let mut scratch = Vec::new();
    scratch.try_reserve_exact(SCRATCH_BYTES)?;
    scratch.resize(SCRATCH_BYTES, 0);
    session.require_online_store_readback(request)?;
    let count = match symlink {
        Some(path) => rustix::fs::llistxattr(path, scratch.as_mut_slice())?,
        None => rustix::fs::flistxattr(file, scratch.as_mut_slice())?,
    };
    session.require_online_store_readback(request)?;
    let mut names = Vec::new();
    for name in scratch[..count].split_inclusive(|byte| *byte == 0) {
        let name = name.strip_suffix(&[0]).ok_or(StoreFailureV1::Mismatch)?;
        if name.is_empty() {
            return Err(StoreFailureV1::Mismatch);
        }
        names.try_reserve_exact(1)?;
        let mut retained = Vec::new();
        retained.try_reserve_exact(name.len())?;
        retained.extend_from_slice(name);
        names.push(retained);
    }
    names.sort_unstable();
    if !names.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(StoreFailureV1::Mismatch);
    }

    for name in &names {
        let c_name = CString::new(name.as_slice()).map_err(|_| StoreFailureV1::Mismatch)?;
        session.require_online_store_readback(request)?;
        let count = match symlink {
            Some(path) => rustix::fs::lgetxattr(path, c_name.as_c_str(), scratch.as_mut_slice())?,
            None => rustix::fs::fgetxattr(file, c_name.as_c_str(), scratch.as_mut_slice())?,
        };
        session.require_online_store_readback(request)?;
        let value = &scratch[..count];
        match name.as_slice() {
            b"security.selinux" if value == STORE_LABEL => {}
            b"system.posix_acl_access" => {
                if value != acl_bytes(expected)? {
                    return Err(StoreFailureV1::Mismatch);
                }
            }
            _ => {
                let attribute = expected.xattrs().iter().find(|entry| entry.name() == name)
                    .ok_or(StoreFailureV1::Mismatch)?;
                if attribute.value() != value {
                    return Err(StoreFailureV1::Mismatch);
                }
            }
        }
    }
    if expected.xattrs().iter().any(|entry| !names.iter().any(|name| name == entry.name()))
        || expected.acl().is_some() != names.iter().any(|name| name == b"system.posix_acl_access")
    {
        return Err(StoreFailureV1::Mismatch);
    }
    let after = rustix::fs::fstat(file)?;
    if after.st_dev != stat.st_dev || after.st_ino != stat.st_ino
        || after.st_mode != stat.st_mode || after.st_uid != stat.st_uid
        || after.st_gid != stat.st_gid || after.st_mtime != stat.st_mtime
        || after.st_mtime_nsec != stat.st_mtime_nsec
    {
        return Err(StoreFailureV1::Mismatch);
    }
    session.require_online_store_readback(request)?;
    Ok(())
}

fn acl_bytes(metadata: &FilesystemMetadata) -> Result<Vec<u8>, StoreFailureV1> {
    let acl = metadata.acl().ok_or(StoreFailureV1::Mismatch)?;
    let length = acl.entries().len().checked_mul(8).and_then(|length| length.checked_add(4))
        .ok_or(StoreFailureV1::Bound)?;
    if length > SCRATCH_BYTES {
        return Err(StoreFailureV1::Bound);
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    for entry in acl.entries() {
        let (tag, permissions, id): (u16, u8, u32) = match *entry {
            AclEntry::UserObject(value) => (1, value, u32::MAX),
            AclEntry::NamedUser { uid, permissions } => (2, permissions, uid),
            AclEntry::GroupObject(value) => (4, value, u32::MAX),
            AclEntry::NamedGroup { gid, permissions } => (8, permissions, gid),
            AclEntry::Mask(value) => (16, value, u32::MAX),
            AclEntry::Other(value) => (32, value, u32::MAX),
        };
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&u16::from(permissions).to_le_bytes());
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    Ok(bytes)
}

fn decode_snapshot(
    bytes: &[u8], profile: OnlineFloorProfileV1, issuer: &[u8; 48],
) -> Result<SnapshotV1, StoreFailureV1> {
    decode_snapshot_inner(bytes, profile, issuer, Some(profile.snapshot_digest()))
}

fn decode_snapshot_inner(
    bytes: &[u8], profile: OnlineFloorProfileV1, issuer: &[u8; 48],
    original_artifact: Option<[u8; 32]>,
) -> Result<SnapshotV1, StoreFailureV1> {
    if bytes.len() < 77 || bytes.len() > SNAPSHOT_MAXIMUM || &bytes[..8] != b"AOSNXV01" {
        return Err(StoreFailureV1::Bound);
    }
    let length = u32::from_be_bytes(bytes[8..12].try_into()
        .map_err(|_| StoreFailureV1::Mismatch)?) as usize;
    if length.checked_add(76) != Some(bytes.len()) {
        return Err(StoreFailureV1::Mismatch);
    }
    let mut artifact = Sha256::new();
    artifact.update(SNAPSHOT_ARTIFACT_DOMAIN);
    artifact.update(bytes);
    let artifact: [u8; 32] = artifact.finalize().into();
    if original_artifact.is_some_and(|expected| artifact != expected) {
        return Err(StoreFailureV1::Mismatch);
    }

    let public = VerifyingKey::from_bytes(
        issuer[16..].try_into().map_err(|_| StoreFailureV1::Mismatch)?,
    ).map_err(|_| StoreFailureV1::Mismatch)?;
    let signature = Signature::from_slice(&bytes[12 + length..])
        .map_err(|_| StoreFailureV1::Mismatch)?;
    let mut message = Vec::new();
    message.try_reserve_exact(SNAPSHOT_DOMAIN.len() + 12 + length)?;
    message.extend_from_slice(SNAPSHOT_DOMAIN);
    message.extend_from_slice(&bytes[..12 + length]);
    public.verify_strict(&message, &signature).map_err(|_| StoreFailureV1::Mismatch)?;

    let snapshot: SnapshotV1 = serde_json::from_slice(&bytes[12..12 + length])?;
    if serde_json::to_vec(&snapshot)? != bytes[12..12 + length]
        || snapshot.version != 1 || snapshot.node != hex(&profile.node())
        || snapshot.deployment != hex(&profile.deployment())
        || snapshot.endpoint != hex(&profile.endpoint())
        || snapshot.domain != hex(&profile.domain())
        || snapshot.domain_commitment != hex(&profile.domain_commitment())
        || snapshot.disclosure != hex(&profile.disclosure())
        || snapshot.files.len() > MAXIMUM_INPUTS + CONTROLS.len()
        || !snapshot.files.windows(2).all(|pair| pair[0].name < pair[1].name)
    {
        return Err(StoreFailureV1::Mismatch);
    }
    for file in &snapshot.files {
        require_relative_name(&file.name)?;
        decode_hex(&file.sha256)?;
        decode_hex(&file.verity_sha256)?;
    }
    Ok(snapshot)
}

fn require_relative_name(name: &str) -> Result<(), StoreFailureV1> {
    if name.is_empty() || name.len() > 4_096 || name.as_bytes().contains(&0)
        || name.split('/').any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(StoreFailureV1::Mismatch);
    }
    Ok(())
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

fn decode_hex(value: &str) -> Result<[u8; 32], StoreFailureV1> {
    if value.len() != 64 {
        return Err(StoreFailureV1::Mismatch);
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(StoreFailureV1::Mismatch),
        };
        output[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_snapshot_names_cannot_select_an_alias_or_escape() {
        for name in ["nix/store/input", "etc/nix/nix.conf", "nix/store/a-b"] {
            assert!(require_relative_name(name).is_ok());
        }

        for name in ["", "/nix/store/input", "nix//store", "nix/./store", "nix/../store", "nix/store/", "nix\0store"] {
            assert!(matches!(require_relative_name(name), Err(StoreFailureV1::Mismatch)));
        }
        assert!(require_relative_name(&"a".repeat(4_096)).is_ok());
        assert!(matches!(require_relative_name(&"a".repeat(4_097)), Err(StoreFailureV1::Mismatch)));
    }

    #[test]
    fn snapshot_digest_data_requires_exact_lowercase_width() {
        let bytes = [0xab; 32];
        let encoded = hex(&bytes);

        assert_eq!(encoded, "ab".repeat(32));
        assert_eq!(decode_hex(&encoded).unwrap(), bytes);
        for value in [encoded.to_uppercase(), "a".repeat(63), "a".repeat(65), "g".repeat(64)] {
            assert!(matches!(decode_hex(&value), Err(StoreFailureV1::Mismatch)));
        }
    }

    #[test]
    fn reader_status_data_preserves_root_control_capabilities_without_live_claims() {
        let status = b"CapInh:\t0000000000000000\nCapPrm:\t00000000000000c0\nCapEff:\t00000000000000c0\nCapBnd:\t00000000000000c0\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";

        assert!(require_reader_status(status).is_ok());
        let cap_empty = String::from_utf8(status.to_vec()).unwrap().replace("00c0", "0000");
        assert!(matches!(require_reader_status(cap_empty.as_bytes()), Err(StoreFailureV1::Mismatch)));
        let duplicate = [status.as_slice(), b"CapEff:\t00000000000000c0\n"].concat();
        assert!(matches!(require_reader_status(&duplicate), Err(StoreFailureV1::Mismatch)));
        assert!(matches!(require_reader_status(b"CapEff: c0\n"), Err(StoreFailureV1::Mismatch)));
    }
}
