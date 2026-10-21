//! Retains funded primary helper observations and independently owed proc posts.
//!
//! The Source caller pays and parks each frame before its physical body. A
//! failed healthy observation cannot suppress these existing negative native
//! readers. Entry latches make unwind drains skip an interrupted native entry
//! and still enter the other owed group once.
//! Each normal primary read separately pays and parks its own raw frame before
//! using the same healthy native engine. Primary refusal never gates owed posts.

use std::error::Error;
use std::fmt;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::pidfd::PidFd;
use aos_sandbox_linux::pidfd::PidFdNegativeContextOriginalV1;
use aos_sandbox_linux::pidfd::PidFdNegativeIdentityOriginalV1;
use aos_sandbox_linux::pidfd::PidFdProcObservationsV1;
use aos_sandbox_linux::pidfd::PidFdProcOriginalsV1;
use aos_sandbox_linux::pidfd::PidFdProcessIdentity;

use super::{PhysicalTpmFailureV1, require_canary_helper_context_v2};

/// Archives each primary read after its own genuine same-Source debit.
///
/// The actual loop chooses how many primary reads occur. No declared retry
/// maximum or fresh account is introduced. Failed and interrupted originals
/// remain resident; the separately prepaid negative post frame owns its drain.
pub(super) struct BootHelperPrimaryArchiveV1 {
    originals: Vec<Option<Box<PidFdProcOriginalsV1>>>,
}

impl BootHelperPrimaryArchiveV1 {
    pub(super) fn new() -> Self {
        Self {
            originals: Vec::new(),
        }
    }

    pub(super) fn identity_receiving_demand_v1() -> Option<ResourceVector> {
        Self::receiving_demand_v1(PidFdProcOriginalsV1::stat_maximum_requested_read_bytes_v1()?)
    }

    pub(super) fn context_receiving_demand_v1() -> Option<ResourceVector> {
        Self::receiving_demand_v1(PidFdProcOriginalsV1::context_maximum_requested_read_bytes_v1()?)
    }

    fn receiving_demand_v1(reads: usize) -> Option<ResourceVector> {
        // The lower supplier owns native controls, read buffers and decoder
        // work. Two pointer cells per admitted element cover the old/new Vec
        // backing overlap during growth; prior elements remain already paid.
        let bytes = PidFdProcOriginalsV1::receiving_bytes_v1()?
            .checked_add(std::mem::size_of::<Option<Box<PidFdProcOriginalsV1>>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<PhysicalTpmFailureV1>().checked_mul(2)?)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OutputBytes, u64::try_from(reads).ok()?),
        )
    }

    fn park_once(&mut self) -> Result<usize, PhysicalTpmFailureV1> {
        // The caller prepays before either allocation. The raw owner enters
        // its stable slot before the common native recipe can fail or unwind.
        self.originals
            .try_reserve_exact(1)
            .map_err(PhysicalTpmFailureV1::BootHelperArchiveAllocation)?;
        let index = self.originals.len();
        self.originals
            .push(Some(Box::new(PidFdProcOriginalsV1::new())));
        Ok(index)
    }

    fn failure(&mut self, index: usize) -> PhysicalTpmFailureV1 {
        match self.originals.get_mut(index).and_then(Option::take) {
            Some(original) => PhysicalTpmFailureV1::BootHelperObservation(
                BootHelperCaptureFailureV1::new(original),
            ),
            None => PhysicalTpmFailureV1::State,
        }
    }

    pub(super) fn observe_identity(
        &mut self,
        source: &mut PidFdProcObservationsV1,
        process: &PidFd,
    ) -> Result<PidFdProcessIdentity, PhysicalTpmFailureV1> {
        let index = self.park_once()?;
        let original = self.originals[index]
            .as_mut()
            .ok_or(PhysicalTpmFailureV1::State)?;
        match source.observe_identity_retaining_v1(process, original) {
            Ok(identity) => Ok(identity),
            Err(_) => Err(self.failure(index)),
        }
    }

    pub(super) fn observe_context(
        &mut self,
        source: &mut PidFdProcObservationsV1,
        process: &PidFd,
    ) -> Result<(), PhysicalTpmFailureV1> {
        let index = self.park_once()?;
        let original = self.originals[index]
            .as_mut()
            .ok_or(PhysicalTpmFailureV1::State)?;
        match source.observe_context_retaining_v1(process, original) {
            Ok(context) => require_canary_helper_context_v2(context),
            Err(_) => Err(self.failure(index)),
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    IdentityPreparation,
    ContextPreparation,
    Identity,
    Context,
    Role,
    Interrupted,
}

/// Keeps the actual two native originals beside their preparation/results.
pub(super) struct BootHelperAfterOriginalV1 {
    identity: PidFdNegativeIdentityOriginalV1,
    context: PidFdNegativeContextOriginalV1,
    identity_preparation: Option<aos_linux_descriptors::Result<()>>,
    context_preparation: Option<aos_linux_descriptors::Result<()>>,
    identity_result: Option<aos_linux_descriptors::Result<()>>,
    context_result: Option<aos_linux_descriptors::Result<()>>,
    role: Option<Result<(), PhysicalTpmFailureV1>>,
    entered: [bool; 4],
    first: Option<First>,
}

impl BootHelperAfterOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            identity: PidFdNegativeIdentityOriginalV1::new(),
            context: PidFdNegativeContextOriginalV1::new(),
            identity_preparation: None,
            context_preparation: None,
            identity_result: None,
            context_result: None,
            role: None,
            entered: [false; 4],
            first: None,
        }
    }

    pub(super) fn receiving_demand_v1() -> Option<ResourceVector> {
        let (identity_bytes, identity_files, _) =
            PidFdNegativeIdentityOriginalV1::receiving_demand_v1()?;
        let (context_bytes, context_files, _) =
            PidFdNegativeContextOriginalV1::receiving_demand_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(identity_bytes.checked_mul(2)?)?
            .checked_add(context_bytes.checked_mul(2)?)?;
        let files = identity_files.checked_add(context_files)?;
        let reads = PidFdNegativeIdentityOriginalV1::maximum_requested_read_bytes_v1()?
            .checked_add(PidFdNegativeContextOriginalV1::maximum_requested_read_bytes_v1()?)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?)
                .with(D::OutputBytes, u64::try_from(reads).ok()?),
        )
    }

    pub(super) fn prepare(&mut self, source: &PidFdProcObservationsV1) {
        if !self.entered[0] {
            self.entered[0] = true;
            self.identity_preparation =
                Some(source.prepare_available_negative_identity_once_into_v1(&mut self.identity));
            if matches!(self.identity_preparation, Some(Err(_))) {
                self.first.get_or_insert(First::IdentityPreparation);
            }
        } else if self.identity_preparation.is_none() {
            self.first.get_or_insert(First::Interrupted);
        }
        if !self.entered[1] {
            self.entered[1] = true;
            self.context_preparation =
                Some(source.prepare_available_negative_context_once_into_v1(&mut self.context));
            if matches!(self.context_preparation, Some(Err(_))) {
                self.first.get_or_insert(First::ContextPreparation);
            }
        } else if self.context_preparation.is_none() {
            self.first.get_or_insert(First::Interrupted);
        }
    }

    pub(super) fn observe(&mut self, pidfd: &PidFd) {
        if !self.entered[2] {
            self.entered[2] = true;
            self.identity_result = Some(self.identity.observe_once(pidfd));
            if matches!(self.identity_result, Some(Err(_))) {
                self.first.get_or_insert(First::Identity);
            }
        } else if self.identity_result.is_none() {
            self.first.get_or_insert(First::Interrupted);
        }
        if !self.entered[3] {
            self.entered[3] = true;
            match self.context.observe_once(pidfd) {
                Ok(bytes) => {
                    self.context_result = Some(Ok(()));
                    self.role = Some(require_canary_helper_context_v2(bytes));
                    if matches!(self.role, Some(Err(_))) {
                        self.first.get_or_insert(First::Role);
                    }
                }
                Err(cause) => {
                    self.context_result = Some(Err(cause));
                    self.first.get_or_insert(First::Context);
                }
            }
        } else if self.context_result.is_none() {
            self.first.get_or_insert(First::Interrupted);
        }
    }

    pub(super) fn failed(&self) -> bool {
        self.first.is_some()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::IdentityPreparation => self
                .identity
                .failure()
                .or_else(|| error(&self.identity_preparation)),
            First::ContextPreparation => self
                .context
                .failure()
                .or_else(|| error(&self.context_preparation)),
            First::Identity => self
                .identity
                .failure()
                .or_else(|| error(&self.identity_result)),
            First::Context => self
                .context
                .failure()
                .or_else(|| error(&self.context_result)),
            First::Role => error(&self.role),
            First::Interrupted => None,
        }
    }
}

/// Keeps the whole failed native post frame as its typed diagnostic original.
pub(in crate::tpm_nv_custody) struct BootHelperAfterFailureV1 {
    original: Box<BootHelperAfterOriginalV1>,
}

impl BootHelperAfterFailureV1 {
    pub(super) fn new(original: Box<BootHelperAfterOriginalV1>) -> Self {
        Self { original }
    }
}

impl fmt::Debug for BootHelperAfterFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootHelperAfterFailureV1")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for BootHelperAfterFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original helper identity/context post failed or was interrupted")
    }
}

impl Error for BootHelperAfterFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

/// Keeps a retained proc recipe and its first raw native cause.
pub(in crate::tpm_nv_custody) struct BootHelperCaptureFailureV1 {
    original: Box<aos_sandbox_linux::pidfd::PidFdProcOriginalsV1>,
}

impl BootHelperCaptureFailureV1 {
    pub(super) fn new(original: Box<aos_sandbox_linux::pidfd::PidFdProcOriginalsV1>) -> Self {
        Self { original }
    }
}

impl fmt::Debug for BootHelperCaptureFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootHelperCaptureFailureV1")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for BootHelperCaptureFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original retained helper proc recipe failed")
    }
}

impl Error for BootHelperCaptureFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}
