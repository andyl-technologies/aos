//! Keeps first-table profile admission paired with its actual C original.
//!
//! The complete router output is consumed once. Enrollment and profile inputs
//! cannot be supplied independently, so the selected admission never accepts
//! a caller-chosen original or a profile capture from another startup.

use std::os::fd::OwnedFd;
use std::sync::Arc;

use aos_sandbox_protocol::domain_ledger::resource_bank::NativeLayoutDemand;

use super::initial_delivery::{ControllerInitialDeliveryPartsV1, ControllerNixDeliveryDataV1};
use super::profile::{
    ControllerProfileAdmissionFailureV1, ControllerSelectedProfileAdmissionV1,
    ControllerSelfProfileOriginalV1,
};
use super::{ControllerReceivingErrorV1, ControllerReceivingOriginalV1};

/// Borrows the first refusal from the same startup opening.
pub enum ControllerStartupFailureRefV1<'opening> {
    /// Original enrollment or fixed pre-admission receiving failed first.
    Receiving(&'opening ControllerReceivingErrorV1),
    /// The actual retained profile admission failed after enrollment.
    Profile(&'opening ControllerProfileAdmissionFailureV1),
}

impl<'opening> ControllerStartupFailureRefV1<'opening> {
    /// Borrows the original retained cause without changing its concrete type.
    #[must_use]
    pub fn as_error(self) -> &'opening (dyn std::error::Error + 'static) {
        match self {
            Self::Receiving(cause) => cause,
            Self::Profile(cause) => cause,
        }
    }
}

/// Retains the actual paired startup when its Bank handoff refuses.
///
/// Neither this error nor its diagnostic projections release original files,
/// reset a stage, construct a profile or establish a successful Bank opening.
pub struct ControllerBankOpeningFailureV1 {
    startup: ControllerStartupOpeningV1,
    cause: ControllerReceivingErrorV1,
}

impl ControllerBankOpeningFailureV1 {
    /// Borrows the first actual startup refusal or the retained handoff cause.
    #[must_use]
    pub fn failure(&self) -> &(dyn std::error::Error + 'static) {
        self.startup.first_failure().map(ControllerStartupFailureRefV1::as_error)
            .unwrap_or(&self.cause)
    }
}

impl std::fmt::Debug for ControllerBankOpeningFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ControllerBankOpeningFailureV1")
            .field("cause", &self.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for ControllerBankOpeningFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.failure(), formatter)
    }
}

impl std::error::Error for ControllerBankOpeningFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.failure())
    }
}

/// Retains linked profile and enrollment inputs throughout selected admission.
///
/// Bank and launch orchestration may borrow its original C. Only this owner
/// passes that original to its profile admission. No caller resource amount,
/// descriptor, pathname or separate admission object constructs the pair.
#[must_use]
pub struct ControllerStartupOpeningV1 {
    original: Option<Arc<ControllerReceivingOriginalV1>>,
    admission: ControllerSelectedProfileAdmissionV1,
    prefix: Option<Result<(), ControllerReceivingErrorV1>>,
    launch: Option<OwnedFd>,
    nix: Option<ControllerNixDeliveryDataV1>,
    git: Option<OwnedFd>,
    publisher: Option<OwnedFd>,
    image: Option<OwnedFd>,
    auxiliary_taken: bool,
    writer_taken: bool,
}

impl ControllerStartupOpeningV1 {
    /// Bounds the compiled enrollment/Arc prefix before selected profile growth.
    ///
    /// This describes the same inline opening, shared-original allocation and
    /// fixed pair/boot reader. First-table routing and the installed process
    /// backstop remain separate; this DATA issues no admission or ledger.
    ///
    /// # Errors
    /// Rejects checked layout overflow or an unavailable existing pair supplier.
    pub fn enrollment_prefix_receiving_demand_v1()
        -> Result<aos_sandbox_core::ResourceVector, ControllerReceivingErrorV1>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let invalid = || ControllerReceivingErrorV1::EnrollmentUnavailable;
        let headers = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerReceivingOriginalV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(std::mem::align_of::<ControllerReceivingOriginalV1>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        // The opening owns policy, sealed delivery and launch channel; the
        // existing pair supplier owns its distinct actual boot probe.
        ResourceVector::ZERO.with(D::MemoryBytes, headers).with(D::OpenFiles, 3)
            .checked_add(crate::receiving::OriginalEnrollmentPairAttemptV1::additional_receiving_demand_v1()
                .ok_or_else(invalid)?).map_err(Into::into)
    }

    /// Bounds the finite sealed range and all possible committed history rows.
    ///
    /// This pure provider invoice composes the actual target's existing prefix,
    /// launch and enrollment suppliers. Actual owners still debit their own
    /// staged requirements before growth; this does not issue a second payer.
    ///
    /// # Errors
    /// Rejects zero recipients, overflow, or an unavailable compiled supplier.
    pub fn enrollment_range_prefix_receiving_demand_v2(recipients: u64)
        -> Result<aos_sandbox_core::ResourceVector, ControllerReceivingErrorV1>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let invalid = || ControllerReceivingErrorV1::EnrollmentUnavailable;
        if recipients == 0 { return Err(invalid()); }
        let row = (17 + aos_sandbox_protocol::domain_ledger::resource_bank::RECIPIENT_RANGE_INCARNATION_BYTES)
            .checked_add(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>())
            .and_then(|bytes| bytes.checked_mul(4))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        let history = row.checked_mul(recipients).ok_or_else(invalid)?;
        Self::enrollment_prefix_receiving_demand_v1()?
            .checked_add(super::bank_launch::ControllerBankLaunchOriginalV1::fixed_demand_v1()
                .map_err(|_| invalid())?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                history)
                .with(D::MetadataEntries, recipients))
            .map_err(Into::into)
    }

    /// Retains this actual startup and its failed Bank handoff cause.
    ///
    /// This consumes custody into a negative diagnostic only. It neither admits
    /// a Bank nor releases originals, resets a stage or creates serving ability.
    #[doc(hidden)]
    #[must_use]
    pub fn into_bank_handoff_failure_v1(
        self,
        cause: ControllerReceivingErrorV1,
    ) -> ControllerBankOpeningFailureV1 {
        ControllerBankOpeningFailureV1 { startup: self, cause }
    }

    /// Moves one complete first-table output into its linked startup owner.
    ///
    /// The layout contains only the actual upper native carrier widths. The
    /// original pair has not been read and no receiving grant is issued here.
    #[must_use]
    pub fn from_initial_delivery(
        parts: ControllerInitialDeliveryPartsV1,
        layout: NativeLayoutDemand,
    ) -> Self {
        let ControllerInitialDeliveryPartsV1 {
            profile, nix, git, enrollment, publisher, image, auxiliary_taken,
        } = parts;
        let mut launch = None;
        let original = enrollment.map(|mut enrollment| {
            launch = enrollment.take_launch_once();
            Arc::new(ControllerReceivingOriginalV1::begin(enrollment, layout))
        });

        Self {
            original,
            admission: ControllerSelectedProfileAdmissionV1::new(profile),
            prefix: None,
            launch,
            nix,
            git,
            publisher,
            image,
            auxiliary_taken,
            writer_taken: false,
        }
    }

    /// Compares the real upper carrier widths before selected bank entry.
    #[must_use]
    pub fn matches_native_layout(&self, layout: NativeLayoutDemand) -> bool {
        self.original.as_ref().is_some_and(|original| original.matches_native_layout(layout))
    }

    /// Borrows the same original for existing upper bank orchestration.
    ///
    /// The borrow does not enter selected receiving or admit a profile. The
    /// opaque original has no public constructor or ledger extraction port.
    #[must_use]
    pub fn original(&self) -> Option<&Arc<ControllerReceivingOriginalV1>> {
        self.original.as_ref()
    }

    /// Attempts selected admission using only this owner's linked original.
    ///
    /// Configured IDs remain comparison DATA. Failure stays resident in the
    /// original prefix or admission owner; reentry performs no new observation.
    #[must_use]
    pub fn admit_selected_profile_once(&mut self, uid: u32, gid: u32) -> bool {
        if self.prefix.is_some() {
            return false;
        }
        self.prefix = Some(match &self.original {
            Some(original) => original.enter_selected_once(),
            None => Err(ControllerReceivingErrorV1::EnrollmentUnavailable),
        });
        if !matches!(self.prefix, Some(Ok(()))) {
            return false;
        }
        match &self.original {
            Some(original) => self.admission.admit_with_controller_baseline_once(
                Arc::clone(original), uid, gid,
            ),
            None => false,
        }
    }

    /// Reports only whether the same original initial receiving completed.
    ///
    /// This stopping projection cannot create admission or replace the owner.
    #[must_use]
    pub fn initial_receiving_succeeded(&self) -> bool {
        matches!(self.prefix, Some(Ok(())))
    }

    /// Borrows this opening's first retained refusal without cloning its cause.
    #[must_use]
    pub fn first_failure(&self) -> Option<ControllerStartupFailureRefV1<'_>> {
        self.prefix.as_ref().and_then(|result| result.as_ref().err())
            .map(ControllerStartupFailureRefV1::Receiving)
            .or_else(|| self.admission.first_failure().map(ControllerStartupFailureRefV1::Profile))
    }

    /// Moves the same completely admitted profile once into its upper owner.
    #[must_use]
    pub fn take_admitted_profile_once(&mut self) -> Option<ControllerSelfProfileOriginalV1> {
        if !matches!(self.prefix, Some(Ok(()))) {
            return None;
        }
        self.admission.take_admitted_profile()
    }

    /// Moves the actual paired launch into its closed native driver once.
    ///
    /// No descriptor or account is accepted from the caller. The driver still
    /// requires the actual fixed writer, typed Bank publication and readback
    /// before PID1 ACK/Confirm. This move itself establishes no live launch.
    #[must_use]
    pub fn take_bank_launch_once(&mut self) -> Option<super::bank_launch::ControllerBankLaunchOriginalV1> {
        let original = Arc::clone(self.original.as_ref()?);
        let channel = self.launch.take()?;
        Some(super::bank_launch::ControllerBankLaunchOriginalV1::from_paired_startup(original, channel))
    }

    /// Creates this same startup's sole fixed Controller writer destination.
    ///
    /// # Errors
    /// Refuses repeated or absent selected startup. The returned owner must
    /// still complete its actual profile/pair/debit/acquisition/replay stages.
    pub fn take_fixed_writer_opening_once(
        &mut self,
    ) -> Result<super::bank_launch::ControllerWriterOpeningOriginalV1, ControllerReceivingErrorV1> {
        if self.writer_taken {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.writer_taken = true;
        let original = Arc::clone(self.original.as_ref()
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?);
        Ok(super::bank_launch::ControllerWriterOpeningOriginalV1::from_paired_startup(original))
    }

    /// Arms the same paid original's once-only pre-Bank Source construction.
    ///
    /// The trusted coordinator must finish actual preopen admission/reservation
    /// before this method and enter the body only at its real Source stage.
    /// The fixed post stays owed even if the prior Controller body fails.
    #[must_use]
    pub fn arm_source_prebank_construction_once_v1<'profile>(
        &self,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Option<super::source_prebank::ControllerSourcePreBankConstructionLoanV1<'profile>> {
        if !matches!(self.prefix, Some(Ok(()))) { return None; }
        Some(super::source_prebank::ControllerSourcePreBankConstructionLoanV1::from_paired_startup(
            Arc::clone(self.original.as_ref()?), profile,
        ))
    }

    /// Advances only this original's already-enrolled no-public startup.
    ///
    /// # Errors
    /// Refuses a configured public listener, incomplete Bank phase, or closed
    /// actual original. It creates no writer, role loan or resource authority.
    pub fn serve_startup_without_public_once_v1(&self) -> Result<(), ControllerReceivingErrorV1> {
        self.original.as_ref().ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?
            .serve_startup_without_public()
    }

    /// Moves optional auxiliary descriptor DATA once without observation.
    ///
    /// These inputs retain their existing upper consumers. None is a profile,
    /// enrollment, receiving or protected operation authority.
    #[must_use]
    pub fn take_auxiliary_parts_once(&mut self) -> Option<(
        Option<ControllerNixDeliveryDataV1>, Option<OwnedFd>,
        Option<OwnedFd>, Option<OwnedFd>,
    )> {
        if self.auxiliary_taken {
            return None;
        }
        self.auxiliary_taken = true;
        Some((self.nix.take(), self.git.take(), self.publisher.take(), self.image.take()))
    }
}

impl ControllerStartupOpeningV1 {
    /// Borrows the paired optional Cache importer before fixed writer opening.
    ///
    /// This constructs no Bank, launch or writer authority. Its lower original
    /// independently requires the actual Source credential disposal stage.
    #[must_use]
    pub fn borrow_cache_prebank_import_once_v1<'profile>(
        &self,
        profile: &'profile super::profile::ControllerSelfProfileOriginalV1,
    ) -> Option<super::cache_prebank::ControllerCachePreBankImportLoanV1<'profile>> {
        if !matches!(self.prefix, Some(Ok(()))) { return None; }
        Some(super::cache_prebank::ControllerCachePreBankImportLoanV1::from_paired_startup(
            Arc::clone(self.original()?), profile,
        ))
    }
}
