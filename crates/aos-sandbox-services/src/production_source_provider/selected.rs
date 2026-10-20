//! Retained selected SourceProvider service opening and completion custody.
//!
//! Native catalog pins are borrowed DATA from the sole lower read engine;
//! genuine startup and Provider originals remain resident across every crossing.

use aos_sandbox_source_provider::{
    FixedSelectedProviderFailureRefV1, FixedSelectedProviderOpeningV1,
    FixedSelectedProviderProgressV1,
};

use super::*;

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
                    } else if self.opening.retain_catalog_data(self.catalog.publication_bytes_data_v1()).is_ok() {
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
                    self.catalog.publication_bytes_data_v1(), self.catalog.manifest_bytes_data_v1(),
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

    /// Advances the SAME original through completion and independent Release.
    ///
    /// The private owner and catalog originals remain resident. Completion
    /// retains its original deadline; only a genuinely verified fresh Release
    /// supplies the later purpose's separately captured, narrowing clock.
    /// Actual action causes precede distinct later bookend debt. Local send and
    /// Release admission establish neither cleanup, settlement nor Drain.
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

        let before = self.check_completion_boundary(ingress)
            .and_then(|()| self.catalog.recheck())
            .and_then(|()| self.check_completion_boundary(ingress));
        if let Err(cause) = before {
            self.completion_failure = Some(cause);
            return None;
        }
        let progress = match self.owner.as_mut() {
            Some(owner) => owner.advance_original_native_release_status_v1(
                self.catalog.publication_bytes_data_v1(), self.catalog.manifest_bytes_data_v1(),
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
            .and_then(|()| self.check_completion_boundary(ingress));
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

    /// Borrows independent Release posts while the same native owner stays held.
    #[must_use]
    pub fn original_release_postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner.as_ref().and_then(FixedProviderOwnerV1::original_release_postcheck_debt_v1)
            .or_else(|| self.completion_postcheck_debt.as_ref().map(|cause| cause as _))
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

    fn check_completion_boundary(&self, ingress: &mut ProductionSourceProviderIngressV1)
        -> Result<(), ProductionSourceProviderIngressErrorV1>
    {
        // Only the genuine phase10 owner can install this separately bounded
        // intake. Historical opening D is unchanged and never renewed.
        let deadline = self.owner.as_ref()
            .and_then(FixedProviderOwnerV1::original_release_deadline_v1)
            .unwrap_or(self.deadline);
        ingress.check_selected_boundary(deadline)
    }

    /// Lends actual retained failure custody without any observation or retry.
    pub fn failure(&self) -> Option<ProductionSelectedSourceProviderFailureRefV1<'_>> {
        if let Some(cause) = self.owner.as_ref()
            .and_then(FixedProviderOwnerV1::original_release_failure_v1)
        {
            return Some(ProductionSelectedSourceProviderFailureRefV1::Completion(cause));
        }
        if self.completion_failure.is_some() || self.completion_postcheck_debt.is_some() {
            let native = self.catalog.failure();
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
        let native = self.catalog.failure();
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
            .and_then(FixedProviderOwnerV1::original_release_failure_v1)
        {
            return ProductionSelectedSourceProviderFailureRefV1::Completion(cause);
        }
        if self.completion_failure.is_some() || self.completion_postcheck_debt.is_some() {
            match self.catalog.failure() {
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
        match self.catalog.failure() {
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

