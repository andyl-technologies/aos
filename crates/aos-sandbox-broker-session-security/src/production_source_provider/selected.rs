//! Selected fixed Source opening and protected catalog comparison custody.
//!
//! The parent owns the sole catalog read recipe and canonical pair checker.
//! This child parks selected returned originals, actual native errors and the
//! genuine first Session; it supplies no parser, authority or generic Ready.

use std::io::{Read as _, Seek as _};
use std::os::fd::AsFd as _;

use aos_sandbox_linux::path::ResolvedPath;
use aos_sandbox_source_provider::{
    FixedSelectedProviderFailureRefV1, FixedSelectedProviderOpeningV1,
    FixedSelectedProviderProgressV1,
};

use super::*;

/// Retains returned originals and actual read failures for one fixed catalog file.
/// The one extra root duplicate is not a second authority or reopening path.
#[derive(Default)]
struct SelectedCatalogReadV1 {
    filesystem_root: Option<Result<OwnedFd, rustix::io::Errno>>,
    root_duplicate: Option<Result<OwnedFd, rustix::io::Errno>>,
    checked_root: Option<aos_sandbox_linux::Result<BeneathRoot>>,
    directory: Option<aos_sandbox_linux::Result<ResolvedPath>>,
    directory_stat: Option<Result<Stat, rustix::io::Errno>>,
    descriptor: Option<Result<OwnedFd, rustix::io::Errno>>,
    before: Option<Result<Stat, rustix::io::Errno>>,
    file: Option<File>,
    bytes: Vec<u8>,
    read_result: Option<std::io::Result<()>>,
    trailing: [u8; 1],
    tail_result: Option<std::io::Result<usize>>,
    after: Option<Result<Stat, rustix::io::Errno>>,
    named_directory: Option<aos_sandbox_linux::Result<ResolvedPath>>,
    named_directory_metadata: Option<Result<Stat, rustix::io::Errno>>,
    named_after_directory: Option<aos_sandbox_linux::Result<ResolvedPath>>,
    named_after_directory_metadata: Option<Result<Stat, rustix::io::Errno>>,
    named_descriptor: Option<Result<OwnedFd, rustix::io::Errno>>,
    named_metadata: Option<Result<Stat, rustix::io::Errno>>,
    named_after_descriptor: Option<Result<OwnedFd, rustix::io::Errno>>,
    named_after_metadata: Option<Result<Stat, rustix::io::Errno>>,
    repeat_directory: Option<Result<Stat, rustix::io::Errno>>,
    repeat_before: Option<Result<Stat, rustix::io::Errno>>,
    rewind: Option<std::io::Result<()>>,
    repeat_bytes: Vec<u8>,
    repeat_read: Option<std::io::Result<()>>,
    repeat_trailing: [u8; 1],
    repeat_tail: Option<std::io::Result<usize>>,
    repeat_after: Option<Result<Stat, rustix::io::Errno>>,
    attempted: bool,
    complete: bool,
}

pub(crate) enum CatalogReadFailureRefV1<'owner> {
    Kernel(&'owner rustix::io::Errno),
    Path(&'owner aos_sandbox_linux::Error),
    Read(&'owner std::io::Error),
}

macro_rules! catalog_failure_slot {
    ($owner:ident, $slot:ident, $kind:ident) => {
        if let Some(Err(error)) = $owner.$slot.as_ref() {
            return Some(CatalogReadFailureRefV1::$kind(error));
        }
    };
}

impl SelectedCatalogReadV1 {
    fn failure(&self) -> Option<CatalogReadFailureRefV1<'_>> {
        catalog_failure_slot!(self, filesystem_root, Kernel);
        catalog_failure_slot!(self, root_duplicate, Kernel);
        catalog_failure_slot!(self, checked_root, Path);
        catalog_failure_slot!(self, directory, Path);
        catalog_failure_slot!(self, directory_stat, Kernel);
        catalog_failure_slot!(self, descriptor, Kernel);
        catalog_failure_slot!(self, before, Kernel);
        catalog_failure_slot!(self, read_result, Read);
        catalog_failure_slot!(self, tail_result, Read);
        catalog_failure_slot!(self, after, Kernel);
        catalog_failure_slot!(self, named_directory, Path);
        catalog_failure_slot!(self, named_directory_metadata, Kernel);
        catalog_failure_slot!(self, repeat_directory, Kernel);
        catalog_failure_slot!(self, named_descriptor, Kernel);
        catalog_failure_slot!(self, named_metadata, Kernel);
        catalog_failure_slot!(self, repeat_before, Kernel);
        catalog_failure_slot!(self, rewind, Read);
        catalog_failure_slot!(self, repeat_read, Read);
        catalog_failure_slot!(self, repeat_tail, Read);
        catalog_failure_slot!(self, repeat_after, Kernel);
        catalog_failure_slot!(self, named_after_directory, Path);
        catalog_failure_slot!(self, named_after_directory_metadata, Kernel);
        catalog_failure_slot!(self, named_after_descriptor, Kernel);
        catalog_failure_slot!(self, named_after_metadata, Kernel);
        None
    }

    fn read_once(&mut self, name: &str, maximum_bytes: usize) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        if self.attempted {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("catalog read already attempted"));
        }
        self.attempted = true;
        let result = (|| read_catalog_recipe!(name, maximum_bytes, Retained, self))();
        self.complete = result.is_ok();
        result
    }

    fn recheck(&mut self, name: &str) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        if !self.complete {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("catalog read is not current"));
        }
        self.complete = false;
        let root = match self.checked_root.as_ref() {
            Some(Ok(root)) => root,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("filesystem root custody")),
        };
        let directory = match self.directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("state directory custody")),
        };
        let original_directory = match self.directory_stat.as_ref() {
            Some(Ok(metadata)) => metadata,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("state metadata custody")),
        };
        let original_metadata = match self.before.as_ref() {
            Some(Ok(metadata)) => metadata,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication metadata custody")),
        };
        let file = self.file.as_mut().ok_or(ProductionSourceProviderIngressErrorV1::Catalog(
            "publication file custody",
        ))?;

        // A fresh named pin is only a comparison with the same original file.
        // It cannot replace that original or renew a changed catalog cut.
        let relative = Path::new(STATE_ROOT).strip_prefix("/")
            .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("fixed state path"))?;
        self.named_directory = Some(root.resolve(relative, ResolveOptions {
            no_mount_crossing: false,
            require_directory: true,
        }));
        let named_directory = match self.named_directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("state directory name recheck")),
        };
        self.named_directory_metadata = Some(fstat(named_directory.as_fd()));
        if !matches!(self.named_directory_metadata.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_directory, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("state directory name changed"));
        }
        self.repeat_directory = Some(fstat(directory.as_fd()));
        if !matches!(self.repeat_directory.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_directory, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("state directory changed"));
        }
        self.named_descriptor = Some(openat(
            directory.as_fd(), name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let named = match self.named_descriptor.as_ref() {
            Some(Ok(descriptor)) => descriptor,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication name recheck")),
        };
        self.named_metadata = Some(fstat(named));
        if !matches!(self.named_metadata.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_metadata, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication name changed"));
        }
        self.repeat_before = Some(fstat(file.as_fd()));
        if !matches!(self.repeat_before.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_metadata, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication changed"));
        }

        self.rewind = Some(file.rewind());
        if !matches!(self.rewind.as_ref(), Some(Ok(()))) {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication rewind"));
        }
        self.repeat_bytes.resize(self.bytes.len(), 0);
        self.repeat_read = Some(file.read_exact(&mut self.repeat_bytes));
        if !matches!(self.repeat_read.as_ref(), Some(Ok(()))) {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication reread"));
        }
        self.repeat_tail = Some(file.read(&mut self.repeat_trailing));
        if !matches!(self.repeat_tail.as_ref(), Some(Ok(0))) {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication reread tail"));
        }
        self.repeat_after = Some(fstat(file.as_fd()));
        if self.repeat_bytes != self.bytes
            || !matches!(self.repeat_after.as_ref(), Some(Ok(metadata))
                if same_stable_metadata(original_metadata, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication changed during reread"));
        }
        self.named_after_directory = Some(root.resolve(relative, ResolveOptions {
            no_mount_crossing: false,
            require_directory: true,
        }));
        let named_after_directory = match self.named_after_directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("state final directory name recheck")),
        };
        self.named_after_directory_metadata = Some(fstat(named_after_directory.as_fd()));
        if !matches!(self.named_after_directory_metadata.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_directory, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("state final directory name changed"));
        }
        self.named_after_descriptor = Some(openat(
            named_after_directory.as_fd(), name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let named_after = match self.named_after_descriptor.as_ref() {
            Some(Ok(descriptor)) => descriptor,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication final name recheck")),
        };
        self.named_after_metadata = Some(fstat(named_after));
        if !matches!(self.named_after_metadata.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_metadata, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication final name changed"));
        }
        self.complete = true;
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct SelectedCatalogPairV1 {
    publication: SelectedCatalogReadV1,
    rows: SelectedCatalogReadV1,
    rows_name: Option<String>,
    attempted: bool,
    complete: bool,
}

impl SelectedCatalogPairV1 {
    pub(crate) fn failure(&self) -> Option<CatalogReadFailureRefV1<'_>> {
        self.publication.failure().or_else(|| self.rows.failure())
    }

    pub(crate) fn matches_original_bytes(&self, publication: &[u8], rows: &[u8]) -> bool {
        self.complete && self.publication.bytes == publication && self.rows.bytes == rows
    }

    pub(crate) fn matches_written_originals(&self, directory: &Stat, publication: &Stat, rows: &Stat) -> bool {
        self.complete
            && matches!(self.publication.directory_stat.as_ref(), Some(Ok(actual)) if same_stable_metadata(directory, actual))
            && matches!(self.rows.directory_stat.as_ref(), Some(Ok(actual)) if same_stable_metadata(directory, actual))
            && matches!(self.publication.before.as_ref(), Some(Ok(actual)) if same_stable_metadata(publication, actual))
            && matches!(self.rows.before.as_ref(), Some(Ok(actual)) if same_stable_metadata(rows, actual))
    }

    pub(crate) fn read_once(&mut self) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        if self.attempted {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("catalog pair already attempted"));
        }
        self.attempted = true;
        self.publication.read_once(CATALOG_PUBLICATION, CATALOG_PUBLICATION_BYTES)?;
        if self.publication.bytes.len() != CATALOG_PUBLICATION_BYTES {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication length"));
        }
        let digest = aos_sandbox_core::ObjectDigest::from_bytes(
            self.publication.bytes[112..144].try_into()
                .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("publication digest"))?,
        );
        self.rows_name = Some(crate::production_source_provider_catalog::manifest_filename(digest));
        let name = self.rows_name.as_deref().ok_or(
            ProductionSourceProviderIngressErrorV1::Catalog("catalog rows name"),
        )?;
        self.rows.read_once(name, MAXIMUM_CATALOG_ROWS_BYTES)?;
        validate_catalog_pair_data(&self.publication.bytes, &self.rows.bytes, digest)?;
        self.complete = true;
        Ok(())
    }

    fn recheck(&mut self) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        if !self.complete {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("catalog pair is not current"));
        }
        self.complete = false;
        self.publication.recheck(CATALOG_PUBLICATION)?;
        let name = self.rows_name.as_deref().ok_or(
            ProductionSourceProviderIngressErrorV1::Catalog("catalog rows name"),
        )?;
        self.rows.recheck(name)?;
        let digest = aos_sandbox_core::ObjectDigest::from_bytes(
            self.publication.bytes[112..144].try_into()
                .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("publication digest"))?,
        );
        validate_catalog_pair_data(&self.publication.bytes, &self.rows.bytes, digest)?;
        self.complete = true;
        Ok(())
    }
}

/// Lends a selected original's actual retained cause without copying it.
pub enum ProductionSelectedSourceProviderFailureRefV1<'owner> {
    /// The fixed deadline, listener or catalog boundary retains this first error.
    Ingress(&'owner ProductionSourceProviderIngressErrorV1),
    /// A catalog Result slot retains the actual kernel failure.
    CatalogKernel(&'owner rustix::io::Errno),
    /// The unchanged path validator retains its actual failure.
    CatalogPath(&'owner aos_sandbox_linux::Error),
    /// A read/seek Result slot retains the actual I/O failure and read buffer.
    CatalogRead(&'owner std::io::Error),
    /// The genuine selected Core/security owner retains the actual nested cause.
    Owner(FixedSelectedProviderFailureRefV1<'owner>),
    /// The same original completion owner retains the actual action cause.
    Completion(&'owner (dyn std::error::Error + 'static)),
}

impl core::fmt::Debug for ProductionSelectedSourceProviderFailureRefV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSelectedSourceProviderFailureRefV1([retained cause])")
    }
}

/// Owns one selected accepted original, protected catalog pins and opening.
///
/// The named listener constructs this owner. Selected role validation precedes
/// protected reads; completed custody remains original-only, never generic
/// Ready. Catalog pins are comparison DATA and cannot authorize a Source row.
/// One additional root alias per reader preserves the original through the
/// unchanged consuming validator. Named rechecks retain two directory and two
/// file comparison pins per reader: eight FDs per file, sixteen for the pair.
/// Lower never-returned prefixes and allocation/funding remain excluded.
#[must_use = "retain the original, catalog pins and actual first failure"]
pub struct ProductionSelectedSourceProviderOriginalV1 {
    opening: FixedSelectedProviderOpeningV1,
    owner: Option<FixedProviderOwnerV1>,
    report: Option<FixedProviderOpenReportV1>,
    catalog: SelectedCatalogPairV1,
    first_failure: Option<ProductionSourceProviderIngressErrorV1>,
    completion_failure: Option<ProductionSourceProviderIngressErrorV1>,
    completion_postcheck_debt: Option<ProductionSourceProviderIngressErrorV1>,
    deadline: u64,
    attempted: bool,
    ended: bool,
}

struct SelectedSourceOriginalBoundaryV1<'owner> {
    owner: &'owner mut ProductionSelectedSourceProviderOriginalV1,
    ingress: &'owner mut ProductionSourceProviderIngressV1,
    completed: bool,
}

impl Drop for SelectedSourceOriginalBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.ingress.end_selected_initial();
            self.owner.end_original();
        }
    }
}

impl ProductionSelectedSourceProviderOriginalV1 {
    pub(super) fn new(socket: aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket, deadline: u64) -> Self {
        Self {
            opening: FixedProviderOwnerV1::begin_fixed_selected_mount_source(socket),
            owner: None,
            report: None,
            catalog: SelectedCatalogPairV1::default(),
            first_failure: None,
            completion_failure: None,
            completion_postcheck_debt: None,
            deadline,
            attempted: false,
            ended: false,
        }
    }

    /// Opens one selected self role before the fixed catalog and Journal reads.
    ///
    /// # Errors
    ///
    /// Permanently ends the original queue and lends its retained first cause.
    /// It neither retries failed admission nor reopens catalog/Journal state.
    pub fn open_once(&mut self, ingress: &mut ProductionSourceProviderIngressV1)
        -> Result<(), ProductionSelectedSourceProviderFailureRefV1<'_>>
    {
        {
            let mut boundary = SelectedSourceOriginalBoundaryV1 {
                owner: self,
                ingress,
                completed: false,
            };
            boundary.owner.open_inner(boundary.ingress);
            boundary.completed = boundary.owner.failure().is_none() && !boundary.owner.ended;
        }
        self.finish_step()
    }

    fn open_inner(&mut self, ingress: &mut ProductionSourceProviderIngressV1) {
        if self.failure().is_none() && !self.ended {
            if self.attempted {
                self.first_failure = Some(ProductionSourceProviderIngressErrorV1::Catalog(
                    "selected opening already attempted",
                ));
            } else {
                self.attempted = true;
                if let Err(error) = self.check_opening_boundary(ingress) {
                    self.first_failure = Some(error);
                } else if self.opening.open_once().is_ok() {
                    let result = self.catalog.read_once();
                    if let Err(error) = result {
                        self.first_failure = Some(error);
                    } else if self.opening.retain_catalog_data(&self.catalog.publication.bytes).is_ok() {
                        if let Err(error) = self.check_opening_boundary(ingress) {
                            self.first_failure = Some(error);
                        }
                    }
                }
            }
        }
    }

    /// Advances only the same original HELLO and inline first Session.
    ///
    /// # Errors
    ///
    /// Refuses stale listener, deadline, catalog or genuine opening. Every
    /// completed owner is parked before subsequent bookends can fail.
    pub fn advance_opening(&mut self, ingress: &mut ProductionSourceProviderIngressV1)
        -> Result<FixedSelectedProviderProgressV1, ProductionSelectedSourceProviderFailureRefV1<'_>>
    {
        let progress = {
            let mut boundary = SelectedSourceOriginalBoundaryV1 {
                owner: self,
                ingress,
                completed: false,
            };
            let progress = boundary.owner.advance_opening_inner(boundary.ingress);
            boundary.completed = boundary.owner.failure().is_none() && !boundary.owner.ended;
            progress
        };
        self.finish_step()?;
        Ok(progress)
    }

    fn advance_opening_inner(
        &mut self,
        ingress: &mut ProductionSourceProviderIngressV1,
    ) -> FixedSelectedProviderProgressV1 {
        let mut progress = FixedSelectedProviderProgressV1::Pending;
        if self.failure().is_none() && !self.ended {
            if !self.attempted {
                self.first_failure = Some(ProductionSourceProviderIngressErrorV1::Catalog(
                    "selected opening was not attempted",
                ));
            } else if self.owner.is_some() {
                if let Err(cause) = ingress.check_initial_only(self.deadline) {
                    self.first_failure = Some(cause);
                } else {
                    progress = FixedSelectedProviderProgressV1::OriginalCurrent;
                }
            } else if let Err(error) = self.check_opening_boundary(ingress)
                .and_then(|()| self.catalog.recheck())
            {
                self.first_failure = Some(error);
            } else {
                match self.opening.advance() {
                    Ok(value) => progress = value,
                    Err(_) => {
                        self.end_original();
                        return progress;
                    }
                }
                if progress == FixedSelectedProviderProgressV1::OriginalCurrent {
                    match self.opening.take_original_owner() {
                        Some((owner, report)) => {
                            self.owner = Some(owner);
                            self.report = Some(report);
                        }
                        None => self.first_failure = Some(ProductionSourceProviderIngressErrorV1::Catalog(
                            "completed selected owner custody is absent",
                        )),
                    }
                }
                if self.first_failure.is_none() {
                    if let Err(error) = self.catalog.recheck()
                        .and_then(|()| self.check_opening_boundary(ingress))
                    {
                        self.first_failure = Some(error);
                    }
                }
            }
        }
        progress
    }

    /// Advances the existing original Root1/catalog packet engine in place.
    ///
    /// It does not dispatch a backend or complete native Source effects. A
    /// retained pair subsequently uses the same original completion driver.
    ///
    /// # Errors
    ///
    /// Ends changed listener/catalog or failed original custody permanently,
    /// retaining the whole original owner and every returned rejected packet.
    pub fn advance_original_ingress(&mut self, ingress: &mut ProductionSourceProviderIngressV1)
        -> Result<FixedProviderIngressProgressV1, ProductionSelectedSourceProviderFailureRefV1<'_>>
    {
        let progress = {
            let mut boundary = SelectedSourceOriginalBoundaryV1 {
                owner: self,
                ingress,
                completed: false,
            };
            let progress = boundary.owner.advance_original_ingress_inner(boundary.ingress);
            boundary.completed = progress.is_some()
                && boundary.owner.failure().is_none() && !boundary.owner.ended;
            progress
        };
        match progress {
            Some(progress) if !self.ended && self.failure().is_none() => Ok(progress),
            _ => Err(self.failure_or_refuse()),
        }
    }

    fn advance_original_ingress_inner(
        &mut self,
        ingress: &mut ProductionSourceProviderIngressV1,
    ) -> Option<FixedProviderIngressProgressV1> {
        if self.failure().is_none() && !self.ended {
            if let Err(error) = self.check_opening_boundary(ingress)
                .and_then(|()| self.catalog.recheck())
            {
                self.first_failure = Some(error);
            } else if let Some(owner) = self.owner.as_mut() {
                let result = owner.advance_selected_original_ingress(
                    &self.catalog.publication.bytes, &self.catalog.rows.bytes,
                );
                match result {
                    Ok(progress) => {
                        if let Err(error) = self.catalog.recheck()
                            .and_then(|()| self.check_opening_boundary(ingress))
                        {
                            self.first_failure = Some(error);
                        } else {
                            return Some(progress);
                        }
                    }
                    Err(_) => {}
                }
            } else {
                self.first_failure = Some(ProductionSourceProviderIngressErrorV1::Catalog(
                    "selected original owner is not complete",
                ));
            }
        }
        None
    }

    /// Advances the SAME original pair through stored relay5 and local delivery.
    ///
    /// The private owner, catalog originals and original deadline remain
    /// resident. Actual completion causes precede distinct later bookend debt.
    /// A local send is not a remote ACK, settlement or drain.
    ///
    /// # Errors
    ///
    /// Ends stale listener/catalog/deadline or failed original completion. No
    /// owner extraction, replacement Session, signing epoch or resend is admitted.
    pub fn advance_original_native_completion(
        &mut self,
        ingress: &mut ProductionSourceProviderIngressV1,
    ) -> Result<
        FixedProviderOriginalCompletionProgressV5,
        ProductionSelectedSourceProviderFailureRefV1<'_>,
    > {
        let progress = {
            let mut boundary = SelectedSourceOriginalBoundaryV1 {
                owner: self,
                ingress,
                completed: false,
            };
            let progress = boundary.owner.advance_original_completion_inner(boundary.ingress);
            boundary.completed = progress.is_some()
                && boundary.owner.failure().is_none() && !boundary.owner.ended;
            progress
        };
        match progress {
            Some(progress) if !self.ended && self.failure().is_none() => Ok(progress),
            _ => Err(self.failure_or_refuse()),
        }
    }

    fn advance_original_completion_inner(
        &mut self,
        ingress: &mut ProductionSourceProviderIngressV1,
    ) -> Option<FixedProviderOriginalCompletionProgressV5> {
        if self.failure().is_some() || self.ended {
            return None;
        }

        let before = self.check_opening_boundary(ingress)
            .and_then(|()| self.catalog.recheck())
            .and_then(|()| self.check_opening_boundary(ingress));
        if let Err(cause) = before {
            self.completion_failure = Some(cause);
            return None;
        }
        let progress = match self.owner.as_mut() {
            Some(owner) => owner.advance_original_native_relay_v5(
                &self.catalog.publication.bytes, &self.catalog.rows.bytes,
            ),
            None => {
                self.completion_failure = Some(ProductionSourceProviderIngressErrorV1::Catalog(
                    "selected original owner is not complete",
                ));
                return None;
            }
        };

        // Core parks its whole action results before this later readback. A
        // failed bookend cannot replace the original completion/send cause.
        let after = self.catalog.recheck()
            .and_then(|()| self.check_opening_boundary(ingress));
        if let Err(cause) = after {
            if self.completion_postcheck_debt.is_none() {
                self.completion_postcheck_debt = Some(cause);
            }
        }
        if progress == FixedProviderOriginalCompletionProgressV5::Closed
            || self.failure().is_some()
        {
            None
        } else {
            Some(progress)
        }
    }

    /// Rechecks only the resident waiting cut without receiving another packet.
    ///
    /// This keeps the original deadline, listener and catalog live while the
    /// caller awaits a separately implemented completion continuation. It
    /// neither completes the pair nor renews its lifetime or authorizes effects.
    ///
    /// # Errors
    ///
    /// Retains an actual deadline, listener or catalog refusal and ends the same
    /// original queue. A failed or unwound wait cannot be re-entered.
    pub fn recheck_original_wait(
        &mut self,
        ingress: &mut ProductionSourceProviderIngressV1,
    ) -> Result<(), ProductionSelectedSourceProviderFailureRefV1<'_>> {
        {
            let mut boundary = SelectedSourceOriginalBoundaryV1 {
                owner: self,
                ingress,
                completed: false,
            };
            if boundary.owner.failure().is_none() && !boundary.owner.ended {
                let checked = boundary.owner.check_opening_boundary(boundary.ingress)
                    .and_then(|()| boundary.owner.catalog.recheck())
                    .and_then(|()| boundary.owner.check_opening_boundary(boundary.ingress));
                if let Err(error) = checked {
                    boundary.owner.first_failure = Some(error);
                }
                boundary.completed = boundary.owner.failure().is_none() && !boundary.owner.ended;
            }
        }
        self.finish_step()
    }

    fn check_opening_boundary(&self, ingress: &mut ProductionSourceProviderIngressV1)
        -> Result<(), ProductionSourceProviderIngressErrorV1>
    {
        ingress.check_selected_boundary(self.deadline)
    }

    /// Lends actual retained failure custody without any observation or retry.
    pub fn failure(&self) -> Option<ProductionSelectedSourceProviderFailureRefV1<'_>> {
        if let Some(cause) = self.owner.as_ref()
            .and_then(FixedProviderOwnerV1::original_relay_failure_v5)
        {
            return Some(ProductionSelectedSourceProviderFailureRefV1::Completion(cause));
        }
        if self.completion_failure.is_some() || self.completion_postcheck_debt.is_some() {
            let native = self.catalog.publication.failure().or_else(|| self.catalog.rows.failure());
            if let Some(cause) = native {
                return Some(match cause {
                    CatalogReadFailureRefV1::Kernel(cause) => {
                        ProductionSelectedSourceProviderFailureRefV1::CatalogKernel(cause)
                    }
                    CatalogReadFailureRefV1::Path(cause) => {
                        ProductionSelectedSourceProviderFailureRefV1::CatalogPath(cause)
                    }
                    CatalogReadFailureRefV1::Read(cause) => {
                        ProductionSelectedSourceProviderFailureRefV1::CatalogRead(cause)
                    }
                });
            }
            return self.completion_failure.as_ref().or(self.completion_postcheck_debt.as_ref())
                .map(ProductionSelectedSourceProviderFailureRefV1::Ingress);
        }
        if let Some(error) = self.owner.as_ref().and_then(FixedProviderOwnerV1::selected_original_failure) {
            return Some(ProductionSelectedSourceProviderFailureRefV1::Owner(error));
        }
        if let Some(error) = self.opening.failure() {
            return Some(ProductionSelectedSourceProviderFailureRefV1::Owner(error));
        }
        let native = self.catalog.publication.failure().or_else(|| self.catalog.rows.failure());
        if let Some(error) = native {
            return Some(match error {
                CatalogReadFailureRefV1::Kernel(error) => ProductionSelectedSourceProviderFailureRefV1::CatalogKernel(error),
                CatalogReadFailureRefV1::Path(error) => ProductionSelectedSourceProviderFailureRefV1::CatalogPath(error),
                CatalogReadFailureRefV1::Read(error) => ProductionSelectedSourceProviderFailureRefV1::CatalogRead(error),
            });
        }
        self.first_failure.as_ref().map(ProductionSelectedSourceProviderFailureRefV1::Ingress)
    }

    fn failure_or_refuse(&mut self) -> ProductionSelectedSourceProviderFailureRefV1<'_> {
        if self.failure().is_none() {
            self.first_failure = Some(ProductionSourceProviderIngressErrorV1::Catalog("selected original is ended"));
        }
        // Splitting these resident fields avoids a self-borrowing stored view.
        if let Some(cause) = self.owner.as_ref()
            .and_then(FixedProviderOwnerV1::original_relay_failure_v5)
        {
            return ProductionSelectedSourceProviderFailureRefV1::Completion(cause);
        }
        if self.completion_failure.is_some() || self.completion_postcheck_debt.is_some() {
            match self.catalog.publication.failure().or_else(|| self.catalog.rows.failure()) {
                Some(CatalogReadFailureRefV1::Kernel(cause)) => {
                    return ProductionSelectedSourceProviderFailureRefV1::CatalogKernel(cause);
                }
                Some(CatalogReadFailureRefV1::Path(cause)) => {
                    return ProductionSelectedSourceProviderFailureRefV1::CatalogPath(cause);
                }
                Some(CatalogReadFailureRefV1::Read(cause)) => {
                    return ProductionSelectedSourceProviderFailureRefV1::CatalogRead(cause);
                }
                None => {}
            }
        }
        if let Some(cause) = &self.completion_failure {
            return ProductionSelectedSourceProviderFailureRefV1::Ingress(cause);
        }
        if let Some(cause) = &self.completion_postcheck_debt {
            return ProductionSelectedSourceProviderFailureRefV1::Ingress(cause);
        }
        if let Some(error) = self.owner.as_ref().and_then(FixedProviderOwnerV1::selected_original_failure) {
            return ProductionSelectedSourceProviderFailureRefV1::Owner(error);
        }
        if let Some(error) = self.opening.failure() {
            return ProductionSelectedSourceProviderFailureRefV1::Owner(error);
        }
        match self.catalog.publication.failure().or_else(|| self.catalog.rows.failure()) {
            Some(CatalogReadFailureRefV1::Kernel(error)) => return ProductionSelectedSourceProviderFailureRefV1::CatalogKernel(error),
            Some(CatalogReadFailureRefV1::Path(error)) => return ProductionSelectedSourceProviderFailureRefV1::CatalogPath(error),
            Some(CatalogReadFailureRefV1::Read(error)) => return ProductionSelectedSourceProviderFailureRefV1::CatalogRead(error),
            None => {}
        }
        match &mut self.first_failure {
            Some(error) => ProductionSelectedSourceProviderFailureRefV1::Ingress(error),
            slot => ProductionSelectedSourceProviderFailureRefV1::Ingress(slot.insert(
                ProductionSourceProviderIngressErrorV1::Catalog("selected original is ended"),
            )),
        }
    }

    fn finish_step(&mut self) -> Result<(), ProductionSelectedSourceProviderFailureRefV1<'_>> {
        if self.failure().is_none() && !self.ended {
            return Ok(());
        }
        self.end_original();
        Err(self.failure_or_refuse())
    }

    /// Shuts down the same original queue before catalog or owner destruction.
    pub fn end_original(&mut self) {
        self.ended = true;
        self.opening.end_original();
        if let Some(owner) = self.owner.as_mut() {
            owner.close_selected_original_after_failure();
        }
    }
}

impl Drop for ProductionSelectedSourceProviderOriginalV1 {
    fn drop(&mut self) {
        self.end_original();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_read_refuses_reentry_without_replacing_its_native_cause() {
        let mut reader = SelectedCatalogReadV1 {
            filesystem_root: Some(Err(rustix::io::Errno::ACCES)),
            attempted: true,
            ..SelectedCatalogReadV1::default()
        };

        let result = reader.read_once(CATALOG_PUBLICATION, CATALOG_PUBLICATION_BYTES);

        assert!(result.is_err());
        assert!(matches!(reader.failure(), Some(CatalogReadFailureRefV1::Kernel(error))
            if *error == rustix::io::Errno::ACCES));
        assert!(reader.checked_root.is_none());
        assert!(reader.directory.is_none());
        assert!(reader.file.is_none());
    }

    #[test]
    fn incomplete_pair_refuses_recheck_without_opening_a_replacement() {
        let mut pair = SelectedCatalogPairV1::default();

        let result = pair.recheck();

        assert!(result.is_err());
        assert!(!pair.complete);
        assert!(pair.publication.filesystem_root.is_none());
        assert!(pair.rows.filesystem_root.is_none());
    }
}
