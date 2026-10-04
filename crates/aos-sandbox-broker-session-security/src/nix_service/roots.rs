//! Retained existing-output GC-root operations under the original Nix Session.
//!
//! Both fixed subtrees must already exist, with independent provisioning and
//! effective labels. The measured upstream reader supplies the sole root
//! naming/registration engine. Its replace-capable temp/rename operations are
//! not durable receipts: original directories, links, Results and process debt
//! remain resident through sync, complete readback and later Query52. Nothing
//! here initializes a Store/floor, heals partial roots or proves Drain.
//!
//! ```text
//! v2 request = {version:2,operation:plan-roots|register-roots|inspect-roots,
//!               paths:[{path,narSize}],names:[lowercase64]}
//! v2 response = {version:2,roots:[{path,direct,indirect,target}]}
//! ```

use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use aos_sandbox_linux::path::ResolvedPath;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::nix_build::NixPreadmittedRecipeV2;
use rustix::fs::{Mode, OFlags};
use sha2::{Digest as _, Sha256};

use super::store::{
    GcDirectoryV1, RootReaderCommandV1, RootReaderV1, StoreReadbackV1, domain_root,
};
use crate::handshake::{DormantAuthenticatedBrokerSessionV1, OnlinePostflightV1};
use crate::BrokerSessionSecurityError;

const ROOT_LABEL: &[u8] = b"system_u:object_r:aos_nix_online_gcroots_t\0";
const MAXIMUM_ROOTS: usize = 256;
// Prepare/register/query plus five response/native/send bookends in each
// successor phase. These archives retain observations, not physical funding.
const DIRECTORY_COMPARISONS: usize = 16;
const LINK_COMPARISONS: usize = 12;
const ROOT_POSTFLIGHT_PASSES: usize = 15;
const MAXIMUM_POSTFLIGHT_ORIGINALS: usize = 2 * (5 + DIRECTORY_COMPARISONS)
    + 2 * MAXIMUM_ROOTS * (1 + LINK_COMPARISONS);

#[derive(Clone, Copy, Debug)]
pub(super) enum ReaderPhaseV1 {
    Plan,
    Register,
    Inspect,
}

/// Keeps the first actual cause separate from later observation/sync debt.
#[derive(Debug, thiserror::Error)]
pub(super) enum RootsFailureV1 {
    #[error("original online Session failed: {0}")]
    Session(#[from] BrokerSessionSecurityError),
    #[error("GC-root physical operation failed: {0}")]
    Native(#[from] rustix::io::Errno),
    #[error("bounded GC-root allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("original Store readback retains its cause")]
    Store,
    #[error("original Store GC-directory comparison failed: {0}")]
    StoreObservation(#[from] super::store::StoreFailureV1),
    #[error("original GC-root reader retains its cause and process debt: {0:?}")]
    Reader(ReaderPhaseV1),
    #[error("GC-root named identity, complete inventory or target changed")]
    Mismatch,
    #[error("GC-root count, name or comparison bound exceeded")]
    Bound,
    #[error("GC-root operation is permanently closed")]
    Closed,
}

struct DirectoryV1 {
    role: GcDirectoryV1,
    path: Option<ResolvedPath>,
    readable: Option<OwnedFd>,
    comparison_pending: Option<ResolvedPath>,
    comparisons: Vec<ResolvedPath>,
    inventories: Vec<Vec<Vec<u8>>>,
}

impl DirectoryV1 {
    fn new(role: GcDirectoryV1) -> Self {
        Self {
            role,
            path: None,
            readable: None,
            comparison_pending: None,
            comparisons: Vec::new(),
            inventories: Vec::new(),
        }
    }
}

struct LinkV1 {
    directory: usize,
    name: String,
    target: String,
    original: Option<OwnedFd>,
    comparisons: Vec<OwnedFd>,
    target_readbacks: Vec<Vec<u8>>,
}

/// Owns only the original selected pending51's actual physical continuation.
pub(super) struct ExistingOutputRootsAttemptV1 {
    directories: [DirectoryV1; 2],
    names: Vec<String>,
    links: Vec<LinkV1>,
    plan: RootReaderV1,
    registration: RootReaderV1,
    inspection: RootReaderV1,
    sync_results: [Option<Result<(), rustix::io::Errno>>; 2],
    first_failure: Option<RootsFailureV1>,
    postcheck_debt: Option<RootsFailureV1>,
    digest: Option<[u8; 32]>,
    started: bool,
    prepared: bool,
    registration_started: bool,
    complete: bool,
    query_started: bool,
    postflight_debt: Vec<RootsFailureV1>,
    postflight_unavailable: Option<RootsFailureV1>,
    postflight_passes: usize,
    postflights: [Option<OnlinePostflightV1>; 13],
}

impl ExistingOutputRootsAttemptV1 {
    pub(super) fn new() -> Self {
        Self {
            directories: [
                DirectoryV1::new(GcDirectoryV1::Direct),
                DirectoryV1::new(GcDirectoryV1::Indirect),
            ],
            names: Vec::new(),
            links: Vec::new(),
            plan: RootReaderV1::new(),
            registration: RootReaderV1::new(),
            inspection: RootReaderV1::new(),
            sync_results: [None, None],
            first_failure: None,
            postcheck_debt: None,
            digest: None,
            started: false,
            prepared: false,
            registration_started: false,
            complete: false,
            query_started: false,
            postflight_debt: Vec::new(),
            postflight_unavailable: None,
            postflight_passes: 0,
            postflights: [const { None }; 13],
        }
    }

    pub(super) fn failure(&self) -> Option<&RootsFailureV1> {
        self.first_failure.as_ref()
    }

    pub(super) fn debt(&self) -> Option<&RootsFailureV1> {
        self.postcheck_debt.as_ref()
    }

    /// Derives names once and parks both real directories before later work.
    ///
    /// # Errors
    ///
    /// Refuses repetition, a changed pending51, nonempty/unseen root inventory,
    /// missing provisioning, native failure, or the original reader's refusal.
    pub(super) fn prepare(
        &mut self,
        output: &mut StoreReadbackV1,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ()> {
        if self.started {
            return Err(());
        }
        self.started = true;
        let result = (|| {
            // A failing root step reaches only its enclosing phase return.
            // Reserve both complete diagnostic passes before opening roots.
            self.postflight_debt.try_reserve_exact(2 * MAXIMUM_POSTFLIGHT_ORIGINALS)?;
            session.require_online_request(request)?;
            if request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2
                || recipe.outputs.is_empty() || recipe.outputs.len() > MAXIMUM_ROOTS
            {
                return Err(RootsFailureV1::Closed);
            }
            self.names.try_reserve_exact(recipe.outputs.len())?;
            let mut objects: Vec<_> = recipe.outputs.iter().collect();
            objects.sort_unstable_by(|left, right| left.object.path.cmp(&right.object.path));
            for output in objects {
                let mut digest = Sha256::new();
                digest.update(b"aos.sandbox.nix.gc-root.name.v1\0");
                digest.update(request.semantic_commitment());
                for field in [output.name.as_bytes(), output.object.path.as_bytes()] {
                    digest.update(u32::try_from(field.len()).map_err(|_| RootsFailureV1::Bound)?.to_be_bytes());
                    digest.update(field);
                }
                self.names.push(super::store::hex(&digest.finalize()));
            }

            self.links.try_reserve_exact(recipe.outputs.len() * 2)?;
            for directory in &mut self.directories {
                directory.comparisons.try_reserve_exact(DIRECTORY_COMPARISONS)?;
                directory.inventories.try_reserve_exact(DIRECTORY_COMPARISONS)?;
                output.open_gc_directory_into(directory.role, session, request, &mut directory.path)
                    .map_err(|_| RootsFailureV1::Store)?;
                directory.readable = Some(rustix::fs::openat(
                    directory.path.as_ref().ok_or(RootsFailureV1::Closed)?.as_fd(), c".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?);
                validate_directory(directory, session, request)?;
                capture_inventory(directory, session, request)?;
                if !directory.inventories.last().ok_or(RootsFailureV1::Closed)?.is_empty() {
                    return Err(RootsFailureV1::Mismatch);
                }
            }
            self.plan.run(output, recipe, session, request, RootReaderCommandV1::Plan, &self.names)
                .map_err(|_| RootsFailureV1::Reader(ReaderPhaseV1::Plan))?;
            let plan = self.plan.response().map_err(|_| RootsFailureV1::Closed)?;
            for root in &plan.roots {
                for (directory, full, target) in [(0, &root.direct, &root.target), (1, &root.indirect, &root.direct)] {
                    let prefix = format!("{}/{}/", domain_root(), self.directories[directory].role.relative_name());
                    let name = full.strip_prefix(prefix.as_str()).ok_or(RootsFailureV1::Mismatch)?;
                    let mut link = LinkV1 {
                        directory, name: name.to_owned(), target: target.to_owned(), original: None,
                        comparisons: Vec::new(), target_readbacks: Vec::new(),
                    };
                    link.comparisons.try_reserve_exact(LINK_COMPARISONS)?;
                    link.target_readbacks.try_reserve_exact(LINK_COMPARISONS + 1)?;
                    self.links.push(link);
                }
            }
            Ok(())
        })();
        self.finish_step(result, output, session, request)?;
        self.prepared = true;
        Ok(())
    }

    /// Executes the real upstream root recipe once after fresh native capacity.
    ///
    /// # Errors
    ///
    /// Refuses changed currentness/headroom, any prior attempt, native/process
    /// ambiguity, sync failure or a complete named readback mismatch. No
    /// partial temp/rename is deleted or retried.
    pub(super) fn register(
        &mut self,
        output: &mut StoreReadbackV1,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ()> {
        if !self.prepared || self.registration_started || self.first_failure.is_some() {
            return Err(());
        }
        self.registration_started = true;
        let result = (|| {
            self.recheck_directories(output, session, request)?;
            for directory in &mut self.directories {
                capture_inventory(directory, session, request)?;
                if !directory.inventories.last().ok_or(RootsFailureV1::Closed)?.is_empty() {
                    return Err(RootsFailureV1::Mismatch);
                }
            }
            session.require_online_existing_output_suffix(request)?;
            output.recheck_completed(session, request).map_err(|_| RootsFailureV1::Store)?;
            self.registration.run(output, recipe, session, request, RootReaderCommandV1::Register, &self.names)
                .map_err(|_| RootsFailureV1::Reader(ReaderPhaseV1::Register))?;
            if self.registration.response().map_err(|_| RootsFailureV1::Closed)?.roots
                != self.plan.response().map_err(|_| RootsFailureV1::Closed)?.roots
            {
                return Err(RootsFailureV1::Mismatch);
            }
            self.capture_links(session, request, false)?;
            self.require_complete_inventories(session, request)?;

            for index in 0..2 {
                session.require_online_existing_output_suffix(request)?;
                self.sync_results[index] = Some(rustix::fs::fsync(
                    self.directories[index].readable.as_ref().ok_or(RootsFailureV1::Closed)?,
                ));
                if let Some(Err(cause)) = self.sync_results[index].as_ref() {
                    return Err(RootsFailureV1::Native(*cause));
                }
                session.require_online_request(request)?;
            }
            let bytes = serde_json::to_vec(self.plan.response().map_err(|_| RootsFailureV1::Closed)?)
                .map_err(|_| RootsFailureV1::Mismatch)?;
            self.digest = Some(Sha256::digest(bytes).into());
            Ok(())
        })();
        self.finish_step(result, output, session, request)?;
        self.complete = true;
        Ok(())
    }

    /// Reobserves exactly these originals under the same next pending52.
    ///
    /// # Errors
    ///
    /// Refuses repeated Query, changed named links/complete inventories, a
    /// failed original reader/current cut, or any prior first cause/debt.
    pub(super) fn query(
        &mut self,
        output: &mut StoreReadbackV1,
        recipe: &NixPreadmittedRecipeV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ()> {
        if !self.complete || self.query_started || self.first_failure.is_some() || self.postcheck_debt.is_some() {
            return Err(());
        }
        self.query_started = true;
        let result = (|| {
            self.recheck_directories(output, session, request)?;
            self.capture_links(session, request, true)?;
            self.require_complete_inventories(session, request)?;
            self.inspection.run(output, recipe, session, request, RootReaderCommandV1::Inspect, &self.names)
                .map_err(|_| RootsFailureV1::Reader(ReaderPhaseV1::Inspect))?;
            if self.inspection.response().map_err(|_| RootsFailureV1::Closed)?.roots
                != self.plan.response().map_err(|_| RootsFailureV1::Closed)?.roots
            {
                return Err(RootsFailureV1::Mismatch);
            }
            Ok(())
        })();
        self.finish_step(result, output, session, request)
    }

    pub(super) fn retained_digest(&self) -> Result<[u8; 32], ()> {
        if !self.complete || self.first_failure.is_some() || self.postcheck_debt.is_some() {
            return Err(());
        }
        self.digest.ok_or(())
    }

    /// Rechecks the same returned links and complete inventories without retry.
    ///
    /// # Errors
    ///
    /// Refuses any prior failure/debt, changed original, or exhausted archive.
    pub(super) fn recheck_completed(
        &mut self,
        output: &mut StoreReadbackV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ()> {
        if !self.complete || self.first_failure.is_some() || self.postcheck_debt.is_some() {
            return Err(());
        }
        let result = (|| {
            self.recheck_directories(output, session, request)?;
            self.capture_links(session, request, true)?;
            self.require_complete_inventories(session, request)
        })();
        self.finish_step(result, output, session, request)
    }

    fn finish_step(
        &mut self,
        result: Result<(), RootsFailureV1>,
        output: &mut StoreReadbackV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ()> {
        if let Err(cause) = result {
            self.first_failure.get_or_insert(cause);
        }
        // Preserve the chronological effect/readback failure before a later
        // current observation. Native sync and all process Results stay parked.
        if let Err(cause) = session.require_online_store_readback(request) {
            self.postcheck_debt.get_or_insert(RootsFailureV1::Session(cause));
        }
        if self.first_failure.is_none() && self.postcheck_debt.is_none() {
            if let Err(cause) = self.recheck_directories(output, session, request) {
                self.postcheck_debt = Some(cause);
            }
        }
        if self.first_failure.is_none() && self.postcheck_debt.is_none() {
            // Infallible moves into the already reserved comparison archives
            // precede the unconditional final observations, not the clock.
            for directory in &mut self.directories {
                if let Some(comparison) = directory.comparison_pending.take() {
                    directory.comparisons.push(comparison);
                }
            }
        }
        let root_debt = self.observe_selected_postflight(Some(output));
        let output_debt = output.observe_selected_postflight();
        let Some(slot) = self.postflights.iter_mut().find(|slot| slot.is_none()) else {
            self.postflight_unavailable = Some(RootsFailureV1::Bound);
            return Err(());
        };
        *slot = Some(OnlinePostflightV1::new());
        let Some(report) = slot.as_mut() else { return Err(()); };
        session.observe_online_postflight(report);
        if self.first_failure.is_some() || self.postcheck_debt.is_some()
            || root_debt || output_debt || report.failed()
        {
            return Err(());
        }
        Ok(())
    }

    /// Observes available original directory/link descriptions without reopen.
    pub(super) fn observe_selected_postflight(&mut self, output: Option<&StoreReadbackV1>) -> bool {
        if self.postflight_passes == ROOT_POSTFLIGHT_PASSES {
            self.postflight_unavailable = Some(RootsFailureV1::Bound);
            return true;
        }
        self.postflight_passes += 1;
        let available = self.postflight_debt.capacity().saturating_sub(self.postflight_debt.len());
        if available < MAXIMUM_POSTFLIGHT_ORIGINALS {
            // Reservation failure happens before any directory/link open.
            // It cannot turn partial custody into a positive observation.
            self.postflight_unavailable = Some(RootsFailureV1::Bound);
            return true;
        }
        for directory in &self.directories {
            let Some(path) = directory.path.as_ref() else {
                if self.started {
                    self.postflight_unavailable = Some(RootsFailureV1::Closed);
                }
                continue;
            };
            let identity = path.identity();
            for file in std::iter::once(path.as_fd())
                .chain(directory.readable.iter().map(|file| file.as_fd()))
                .chain(directory.comparison_pending.iter().map(|path| path.as_fd()))
                .chain(directory.comparisons.iter().map(|path| path.as_fd()))
            {
                let result = compare_root_directory(file, identity.device, identity.inode);
                retain_root_postflight(&mut self.postflight_debt, result);
            }
            let result = match output {
                Some(output) => output.compare_gc_directory_original(directory.role,
                    path.as_fd(), (identity.device, identity.inode)).map_err(Into::into),
                None => Err(RootsFailureV1::Closed),
            };
            retain_root_postflight(&mut self.postflight_debt, result);
            if let Some(readable) = directory.readable.as_ref() {
                let mut bytes = [0; 4_096];
                let result = require_label_bytes(readable.as_fd(), None, &mut bytes);
                retain_root_postflight(&mut self.postflight_debt, result);
            }
        }
        for link in &self.links {
            let Some(directory) = self.directories.get(link.directory) else {
                self.postflight_unavailable = Some(RootsFailureV1::Bound);
                continue;
            };
            let Some(path) = directory.path.as_ref() else {
                self.postflight_unavailable = Some(RootsFailureV1::Closed);
                continue;
            };
            for file in link.original.iter().chain(&link.comparisons) {
                let result = compare_root_link(file.as_fd(), path.as_fd(), &link.name, &link.target);
                retain_root_postflight(&mut self.postflight_debt, result);
            }
        }
        self.postflight_unavailable.is_some() || !self.postflight_debt.is_empty()
    }

    fn recheck_directories(
        &mut self,
        output: &mut StoreReadbackV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), RootsFailureV1> {
        for directory in &mut self.directories {
            if directory.comparison_pending.is_none() {
                if directory.comparisons.len() == DIRECTORY_COMPARISONS {
                    return Err(RootsFailureV1::Bound);
                }
                output.open_gc_directory_into(directory.role, session, request, &mut directory.comparison_pending)
                    .map_err(|_| RootsFailureV1::Store)?;
            }
            if directory.path.as_ref().ok_or(RootsFailureV1::Closed)?.identity()
                != directory.comparison_pending.as_ref().ok_or(RootsFailureV1::Closed)?.identity()
            {
                return Err(RootsFailureV1::Mismatch);
            }
            validate_directory(directory, session, request)?;
        }
        session.require_online_store_readback(request)?;
        Ok(())
    }

    fn capture_links(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        comparison: bool,
    ) -> Result<(), RootsFailureV1> {
        for link in &mut self.links {
            let directory = self.directories[link.directory].readable.as_ref().ok_or(RootsFailureV1::Closed)?;
            session.require_online_store_readback(request)?;
            if comparison {
                if link.comparisons.len() == LINK_COMPARISONS {
                    return Err(RootsFailureV1::Bound);
                }
                link.comparisons.push(rustix::fs::openat(
                    directory, link.name.as_str(), OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty(),
                )?);
            } else {
                if link.original.is_some() {
                    return Err(RootsFailureV1::Closed);
                }
                link.original = Some(rustix::fs::openat(
                    directory, link.name.as_str(), OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty(),
                )?);
            }
            let original = link.original.as_ref().ok_or(RootsFailureV1::Closed)?;
            let actual = if comparison { link.comparisons.last().ok_or(RootsFailureV1::Closed)? } else { original };
            let stat = rustix::fs::fstat(actual)?;
            let old = rustix::fs::fstat(original)?;
            let named = rustix::fs::statat(directory, link.name.as_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Symlink
                || stat.st_uid != 0 || stat.st_gid != 0 || stat.st_nlink != 1
                || stat.st_dev != old.st_dev || stat.st_ino != old.st_ino
                || named.st_dev != stat.st_dev || named.st_ino != stat.st_ino
            {
                return Err(RootsFailureV1::Mismatch);
            }
            if link.target_readbacks.len() == LINK_COMPARISONS + 1 {
                return Err(RootsFailureV1::Bound);
            }
            link.target_readbacks.push(vec![0; 4_097]);
            let bytes = link.target_readbacks.last_mut().ok_or(RootsFailureV1::Closed)?;
            let length = rustix::fs::readlinkat_raw(actual, c"", bytes.as_mut_slice())?;
            if length != link.target.len() || bytes.get(..length) != Some(link.target.as_bytes()) {
                return Err(RootsFailureV1::Mismatch);
            }
            bytes.truncate(length);
            let full = format!("{}/{}/{}", domain_root(), self.directories[link.directory].role.relative_name(), link.name);
            require_label(actual, Some(Path::new(&full)), session, request)?;
            let after = rustix::fs::statat(directory, link.name.as_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
            let held = rustix::fs::fstat(actual)?;
            if after.st_dev != stat.st_dev || after.st_ino != stat.st_ino
                || held.st_dev != stat.st_dev || held.st_ino != stat.st_ino
                || after.st_uid != 0 || after.st_gid != 0 || after.st_nlink != 1
                || rustix::fs::FileType::from_raw_mode(after.st_mode) != rustix::fs::FileType::Symlink
            {
                return Err(RootsFailureV1::Mismatch);
            }
            session.require_online_store_readback(request)?;
        }
        Ok(())
    }

    fn require_complete_inventories(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), RootsFailureV1> {
        for (index, directory) in self.directories.iter_mut().enumerate() {
            capture_inventory(directory, session, request)?;
            let names = directory.inventories.last().ok_or(RootsFailureV1::Closed)?;
            if names.len() != self.links.len() / 2 || names.iter().any(|name| {
                !self.links.iter().any(|link| link.directory == index && link.name.as_bytes() == name)
            }) {
                return Err(RootsFailureV1::Mismatch);
            }
        }
        Ok(())
    }
}

fn retain_root_postflight(debt: &mut Vec<RootsFailureV1>, result: Result<(), RootsFailureV1>) {
    if let Err(cause) = result {
        debt.push(cause);
    }
}

fn compare_root_directory(
    file: std::os::fd::BorrowedFd<'_>, device: u64, inode: u64,
) -> Result<(), RootsFailureV1> {
    let stat = rustix::fs::fstat(file)?;
    compare_root_directory_metadata(&stat, device, inode)
}

fn compare_root_directory_metadata(
    stat: &rustix::fs::Stat, device: u64, inode: u64,
) -> Result<(), RootsFailureV1> {
    if (stat.st_dev, stat.st_ino) != (device, inode)
        || stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o7777 != 0o755
    {
        return Err(RootsFailureV1::Mismatch);
    }
    Ok(())
}

fn compare_root_link(
    file: std::os::fd::BorrowedFd<'_>, directory: std::os::fd::BorrowedFd<'_>,
    name: &str, target: &str,
) -> Result<(), RootsFailureV1> {
    let stat = rustix::fs::fstat(file)?;
    let named = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    if (stat.st_dev, stat.st_ino) != (named.st_dev, named.st_ino)
        || rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Symlink
    {
        return Err(RootsFailureV1::Mismatch);
    }
    let mut bytes = [0; 4_097];
    let length = rustix::fs::readlinkat_raw(file, c"", &mut bytes)?;
    if bytes.get(..length) != Some(target.as_bytes()) {
        return Err(RootsFailureV1::Mismatch);
    }
    Ok(())
}

fn validate_directory(
    directory: &DirectoryV1,
    session: &mut DormantAuthenticatedBrokerSessionV1,
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<(), RootsFailureV1> {
    let file = directory.readable.as_ref().ok_or(RootsFailureV1::Closed)?;
    let stat = rustix::fs::fstat(file)?;
    let identity = directory.path.as_ref().ok_or(RootsFailureV1::Closed)?.identity();
    compare_root_directory_metadata(&stat, identity.device, identity.inode)?;
    require_label(file, None, session, request)
}

fn require_label(
    file: impl AsFd,
    path: Option<&Path>,
    session: &mut DormantAuthenticatedBrokerSessionV1,
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<(), RootsFailureV1> {
    let mut bytes = [0; 4_096];
    session.require_online_store_readback(request)?;
    require_label_bytes(file.as_fd(), path, &mut bytes)?;
    session.require_online_store_readback(request)?;
    Ok(())
}

// Both dispositions borrow this one existing xattr comparison engine. The
// positive wrapper keeps its original Session-before/after ordering.
fn require_label_bytes(
    file: impl AsFd,
    path: Option<&Path>,
    bytes: &mut [u8; 4_096],
) -> Result<(), RootsFailureV1> {
    let count = match path {
        Some(path) => rustix::fs::llistxattr(path, &mut *bytes)?,
        None => rustix::fs::flistxattr(file.as_fd(), &mut *bytes)?,
    };
    let names = bytes.get(..count).ok_or(RootsFailureV1::Mismatch)?;
    if names != b"security.selinux\0" {
        return Err(RootsFailureV1::Mismatch);
    }
    let count = match path {
        Some(path) => rustix::fs::lgetxattr(path, c"security.selinux", &mut *bytes)?,
        None => rustix::fs::fgetxattr(file.as_fd(), c"security.selinux", &mut *bytes)?,
    };
    if bytes.get(..count) != Some(ROOT_LABEL) {
        return Err(RootsFailureV1::Mismatch);
    }
    Ok(())
}

fn capture_inventory(
    directory: &mut DirectoryV1,
    session: &mut DormantAuthenticatedBrokerSessionV1,
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<(), RootsFailureV1> {
    if directory.inventories.len() == DIRECTORY_COMPARISONS {
        return Err(RootsFailureV1::Bound);
    }
    directory.inventories.push(Vec::new());
    let names = directory.inventories.last_mut().ok_or(RootsFailureV1::Closed)?;
    let file = directory.readable.as_ref().ok_or(RootsFailureV1::Closed)?;
    session.require_online_store_readback(request)?;
    rustix::fs::seek(file, rustix::fs::SeekFrom::Start(0))?;
    let mut scratch = [MaybeUninit::uninit(); 4_096];
    let mut stream = rustix::fs::RawDir::new(file, &mut scratch);
    loop {
        session.require_online_store_readback(request)?;
        let next = stream.next();
        let Some(next) = next else { break };
        let entry = next?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            if names.len() == MAXIMUM_ROOTS || name.is_empty() || name.len() > 255 {
                return Err(RootsFailureV1::Bound);
            }
            names.try_reserve_exact(1)?;
            names.push(name.to_vec());
        }
        session.require_online_store_readback(request)?;
    }
    names.sort_unstable();
    if !names.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(RootsFailureV1::Mismatch);
    }
    session.require_online_store_readback(request)?;
    Ok(())
}
