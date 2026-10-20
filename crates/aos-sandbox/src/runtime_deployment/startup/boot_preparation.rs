//! Owns the genuine normal publisher's Source and reached startup admission.
//!
//! This recipe captures its sole initial four-entry table before argv or native
//! work. The same Source ledger prepays every later reached model/file shape;
//! no Canary startup, supplied descriptor, decoded profile or amount can create
//! this startup. Failed prefixes remain resident through the owed Source after.

use std::cell::{Cell, RefCell};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::path::PathBuf;

use aos_sandbox_broker::immutable_image::{
    ImmutableFileAcquisitionOriginalV1, ImmutableFileAcquisitionRefusalV1,
    ImmutableFileRevalidationOriginalV1, ImmutableImageErrorV1, RetainedImmutableFileV1,
};
use aos_sandbox_broker::profile_data::runtime_deployment::{
    BootPreparationPublisherProfileDataV1, RuntimeDeploymentProfileDataErrorV1,
};
use aos_sandbox_broker::receiving::{
    RuntimeBootPreparationOriginComparisonDataV1, RuntimeBootPreparationReceivingClosedV1,
    RuntimeBootPreparationSourceCaptureV1,
};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::RecordSubjectListenerAdmissionAttemptV1;

mod admission;
mod arguments;
mod currentness;
mod helper_birth;
mod source_native;

#[derive(Clone, Copy)]
enum First {
    Source,
    Geometry,
    Allocation,
    Admission,
    Arguments,
    AdmissionPost,
    Current(usize),
    Child(usize),
    Population(usize),
    HelperBirth,
    Body,
    Order,
}

/// Refuses a normal startup while its whole native owner retains the cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("normal BootPreparation startup is incomplete or refused")]
pub struct RuntimeBootPreparationStartupClosedV1;

/// Retains only the actual normal Source, original roles and startup results.
///
/// Construction is inert. Capture must precede argv, credentials, runtimes and
/// journal opens. A positive startup remains a prerequisite, never a signing,
/// journal/NV, generation, completion, readiness or effect grant. The entered
/// Source must stay resident until process exit, including on refusal.
#[must_use = "keep the entered Source and all native prefixes alive until exit"]
pub struct RuntimeBootPreparationStartupOriginalV1 {
    source: RefCell<RuntimeBootPreparationSourceCaptureV1>,
    origin: Option<RuntimeBootPreparationOriginComparisonDataV1>,
    body: Option<Box<Body>>,
    geometry: RefCell<Option<Result<ResourceVector, AccountingError>>>,
    receiving: Cell<ResourceVector>,
    current: RefCell<Vec<currentness::CurrentOriginal>>,
    children: RefCell<Vec<source_native::ChildOriginal>>,
    populations: RefCell<Vec<source_native::PopulationOriginal>>,
    helper_birth: RefCell<Option<helper_birth::HelperBirthOriginal>>,
    allocation: RefCell<Option<Result<(), std::collections::TryReserveError>>>,
    first: Cell<Option<First>>,
    capture_attempted: bool,
    admitted: bool,
    after_attempted: Cell<bool>,
    after_result: Cell<Option<Result<(), RuntimeBootPreparationReceivingClosedV1>>>,
    physical_invocation: super::super::invocation::HostPhysicalInvocationStateV1,
    closed: RuntimeBootPreparationStartupClosedV1,
}

struct Body {
    arguments: arguments::ArgumentsOriginal,
    listener: Option<RecordSubjectListenerAdmissionAttemptV1>,
    pid1_original: Option<File>,
    profile_original: Option<File>,
    profile_path: Option<std::io::Result<PathBuf>>,
    profile_flags: Option<Result<rustix::fs::OFlags, rustix::io::Errno>>,
    profile: ImmutableFileAcquisitionOriginalV1,
    profile_measure: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    profile_read: Option<Result<(), ImmutableImageErrorV1>>,
    decoded: Option<Result<BootPreparationPublisherProfileDataV1, serde_json::Error>>,
    shape: Option<Result<(), RuntimeDeploymentProfileDataErrorV1>>,
    pid1: ImmutableFileAcquisitionOriginalV1,
    pid1_measure: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    executable_open: Option<std::io::Result<File>>,
    executable: ImmutableFileAcquisitionOriginalV1,
    executable_measure: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    runtime_acquisitions: Vec<ImmutableFileAcquisitionOriginalV1>,
    runtime: Vec<RetainedImmutableFileV1>,
    evidence_acquisitions: Vec<ImmutableFileAcquisitionOriginalV1>,
    evidence: Vec<RetainedImmutableFileV1>,
    fragment_path: Option<std::io::Result<PathBuf>>,
    fragment: ImmutableFileAcquisitionOriginalV1,
    fragment_normalized: Option<Result<Vec<u8>, RuntimeDeploymentProfileDataErrorV1>>,
    completed: Option<Result<(), RuntimeBootPreparationStartupClosedV1>>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    inline_posts: RefCell<[ImmutableFileRevalidationOriginalV1; 4]>,
    runtime_posts: RefCell<Vec<ImmutableFileRevalidationOriginalV1>>,
    evidence_posts: RefCell<Vec<ImmutableFileRevalidationOriginalV1>>,
    posts_attempted: Cell<bool>,
    post_failure: Cell<Option<(usize, usize)>>,
}

impl Body {
    fn new() -> Self {
        Self {
            arguments: arguments::ArgumentsOriginal::new(),
            listener: None,
            pid1_original: None,
            profile_original: None,
            profile_path: None,
            profile_flags: None,
            profile: ImmutableFileAcquisitionOriginalV1::new(),
            profile_measure: None,
            profile_read: None,
            decoded: None,
            shape: None,
            pid1: ImmutableFileAcquisitionOriginalV1::new(),
            pid1_measure: None,
            executable_open: None,
            executable: ImmutableFileAcquisitionOriginalV1::new(),
            executable_measure: None,
            runtime_acquisitions: Vec::new(),
            runtime: Vec::new(),
            evidence_acquisitions: Vec::new(),
            evidence: Vec::new(),
            fragment_path: None,
            fragment: ImmutableFileAcquisitionOriginalV1::new(),
            fragment_normalized: None,
            completed: None,
            allocation: None,
            inline_posts: RefCell::new(std::array::from_fn(|_| {
                ImmutableFileRevalidationOriginalV1::new()
            })),
            runtime_posts: RefCell::new(Vec::new()),
            evidence_posts: RefCell::new(Vec::new()),
            posts_attempted: Cell::new(false),
            post_failure: Cell::new(None),
        }
    }

    fn model(
        &self,
    ) -> Result<&BootPreparationPublisherProfileDataV1, RuntimeBootPreparationStartupClosedV1> {
        self.decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(RuntimeBootPreparationStartupClosedV1)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let listener =
            self.listener
                .as_ref()
                .and_then(|original| match original.first_failure()? {
                    aos_sandbox_linux::seqpacket::ListenerAdmissionFailureRefV1::Cause(cause) => {
                        Some(cause as &(dyn Error + 'static))
                    }
                    aos_sandbox_linux::seqpacket::ListenerAdmissionFailureRefV1::Closed => None,
                });
        listener
            .or_else(|| result_failure(&self.profile_flags))
            .or_else(|| result_failure(&self.profile_path))
            .or_else(|| self.profile.failure())
            .or_else(|| result_failure(&self.profile_measure))
            .or_else(|| result_failure(&self.profile_read))
            .or_else(|| result_failure(&self.decoded))
            .or_else(|| result_failure(&self.shape))
            .or_else(|| self.pid1.failure())
            .or_else(|| result_failure(&self.pid1_measure))
            .or_else(|| result_failure(&self.executable_open))
            .or_else(|| self.executable.failure())
            .or_else(|| result_failure(&self.executable_measure))
            .or_else(|| {
                self.runtime_acquisitions
                    .iter()
                    .find_map(|owner| owner.failure())
            })
            .or_else(|| {
                self.evidence_acquisitions
                    .iter()
                    .find_map(|owner| owner.failure())
            })
            .or_else(|| result_failure(&self.fragment_path))
            .or_else(|| self.fragment.failure())
            .or_else(|| result_failure(&self.fragment_normalized))
            .or_else(|| result_failure(&self.allocation))
            .or_else(|| result_failure(&self.completed))
    }
}

impl RuntimeBootPreparationStartupOriginalV1 {
    /// Creates inert custody for this build-selected normal initial table.
    #[must_use]
    pub fn new() -> Self {
        // Source already counts its own complete constructor/return layout.
        // Only the co-live upper header is added here; the optional body is
        // separately prepaid before its actual Box and native destinations.
        let upper_header = 2
            * (std::mem::size_of::<Self>()
                - std::mem::size_of::<RefCell<RuntimeBootPreparationSourceCaptureV1>>());
        Self {
            source: RefCell::new(RuntimeBootPreparationSourceCaptureV1::new(upper_header)),
            origin: None,
            body: None,
            geometry: RefCell::new(None),
            receiving: Cell::new(ResourceVector::ZERO),
            current: RefCell::new(Vec::new()),
            children: RefCell::new(Vec::new()),
            populations: RefCell::new(Vec::new()),
            helper_birth: RefCell::new(None),
            allocation: RefCell::new(None),
            first: Cell::new(None),
            capture_attempted: false,
            admitted: false,
            after_attempted: Cell::new(false),
            after_result: Cell::new(None),
            physical_invocation: super::super::invocation::HostPhysicalInvocationStateV1::new(),
            closed: RuntimeBootPreparationStartupClosedV1,
        }
    }

    fn fail(&self, first: First) -> RuntimeBootPreparationStartupClosedV1 {
        if self.first.get().is_none() {
            self.first.set(Some(first));
        }
        self.closed
    }

    pub(in crate::runtime_deployment) fn fund_additional(
        &self,
        demand: Option<ResourceVector>,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        if self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.closed);
        }
        let mut geometry = self
            .geometry
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        *geometry = Some(
            demand
                .ok_or(AccountingError::ArithmeticOverflow {
                    dimension: D::MemoryBytes,
                })
                .and_then(|additional| self.receiving.get().checked_add(additional)),
        );
        let complete = geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or_else(|| self.fail(First::Geometry))?;
        let mut source = self
            .source
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        if source.require_complete_v1(complete).is_err() {
            return Err(self.fail(First::Source));
        }
        self.receiving.set(complete);
        Ok(())
    }

    pub(in crate::runtime_deployment) fn profile_bytes_v1(
        &self,
    ) -> Result<&[u8], RuntimeBootPreparationStartupClosedV1> {
        if !self.admitted || self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.closed);
        }
        Ok(self.body.as_ref().ok_or(self.closed)?.profile.bytes())
    }

    pub(in crate::runtime_deployment) fn profile_data_v1(
        &self,
    ) -> Result<&BootPreparationPublisherProfileDataV1, RuntimeBootPreparationStartupClosedV1> {
        if !self.admitted || self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.closed);
        }
        self.body.as_ref().ok_or(self.closed)?.model()
    }

    pub(in crate::runtime_deployment) fn retained_pid1_v1(
        &self,
    ) -> Result<&RetainedImmutableFileV1, RuntimeBootPreparationStartupClosedV1> {
        self.body
            .as_ref()
            .and_then(|body| body.pid1.completed_measurement())
            .ok_or(self.closed)
    }

    pub(in crate::runtime_deployment) fn origin_data_v1(
        &self,
    ) -> Result<&RuntimeBootPreparationOriginComparisonDataV1, RuntimeBootPreparationStartupClosedV1>
    {
        self.origin.as_ref().ok_or(self.closed)
    }

    pub(in crate::runtime_deployment) fn physical_invocation_state_v1(
        &self,
    ) -> &super::super::invocation::HostPhysicalInvocationStateV1 {
        &self.physical_invocation
    }

    /// Runs the independently owed same-source native after exactly once.
    ///
    /// A body refusal is only a negative selector. It is latched before the
    /// lower after, which runs without a healthy body/debit/currentness guard.
    /// Every Source, startup, SDK, 055 and publication owner must remain alive.
    ///
    /// # Errors
    /// Refuses a prior body/native failure or reentry, retaining the original
    /// cause; no semantic completion, readiness or resource credit is issued.
    pub fn finish_source_after_owed_once_v1(
        &self,
        body: Result<(), RuntimeBootPreparationStartupClosedV1>,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        if body.is_err() {
            self.fail(First::Body);
        }
        if self.after_attempted.replace(true) {
            return Err(self.fail(First::Order));
        }
        let posts = self.finish_admission_posts_once();
        if posts.is_err() {
            self.fail(First::AdmissionPost);
        }
        let result = self
            .source
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?
            .observe_native_after_owed_once_v1();
        self.after_result.set(Some(result));
        if result.is_err() {
            self.fail(First::Source);
        }
        if self.first.get().is_some() {
            Err(self.closed)
        } else {
            Ok(())
        }
    }

    /// Borrows a diagnostic formatter that keeps the actual native owner live.
    #[must_use]
    pub fn failure_view_v1(&self) -> RuntimeBootPreparationStartupFailureViewV1<'_> {
        RuntimeBootPreparationStartupFailureViewV1(self)
    }
}

/// Formats the selected cause from the same retained normal startup owner.
pub struct RuntimeBootPreparationStartupFailureViewV1<'a>(
    &'a RuntimeBootPreparationStartupOriginalV1,
);

impl fmt::Display for RuntimeBootPreparationStartupFailureViewV1<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let owner = self.0;
        match owner.first.get() {
            Some(First::Source) => {
                if let Ok(source) = owner.source.try_borrow() {
                    if let Some(cause) = source.failure_v1() {
                        return write!(output, "{cause}");
                    }
                }
            }
            Some(First::Geometry) => {
                if let Ok(geometry) = owner.geometry.try_borrow() {
                    if let Some(Err(cause)) = geometry.as_ref() {
                        return write!(output, "{cause}");
                    }
                }
            }
            Some(First::Admission) => {
                if let Some(cause) = owner.body.as_ref().and_then(|body| body.failure()) {
                    return write!(output, "{cause}");
                }
            }
            Some(First::Arguments) => {
                if let Some(cause) = owner.body.as_ref().and_then(|body| body.arguments.failure()) {
                    return write!(output, "{cause}");
                }
            }
            Some(First::Allocation) => {
                if let Ok(allocation) = owner.allocation.try_borrow() {
                    if let Some(Err(cause)) = allocation.as_ref() {
                        return write!(output, "{cause}");
                    }
                }
            }
            Some(First::AdmissionPost) => {
                if let Some(body) = owner.body.as_ref() {
                    if let Some((plane, index)) = body.post_failure.get() {
                        match plane {
                            0 => {
                                if let Ok(values) = body.inline_posts.try_borrow() {
                                    if let Some(cause) =
                                        values.get(index).and_then(|value| value.failure())
                                    {
                                        return write!(output, "{cause}");
                                    }
                                }
                            }
                            1 => {
                                if let Ok(values) = body.runtime_posts.try_borrow() {
                                    if let Some(cause) =
                                        values.get(index).and_then(|value| value.failure())
                                    {
                                        return write!(output, "{cause}");
                                    }
                                }
                            }
                            _ => {
                                if let Ok(values) = body.evidence_posts.try_borrow() {
                                    if let Some(cause) =
                                        values.get(index).and_then(|value| value.failure())
                                    {
                                        return write!(output, "{cause}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Some(First::Current(index)) => {
                if let Ok(current) = owner.current.try_borrow() {
                    if let Some(cause) = current.get(index).and_then(|lane| lane.failure()) {
                        return write!(output, "{cause}");
                    }
                }
            }
            Some(First::Child(index)) => {
                if let Ok(children) = owner.children.try_borrow() {
                    if let Some(cause) = children.get(index).and_then(|lane| lane.failure()) {
                        return write!(output, "{cause}");
                    }
                }
            }
            Some(First::Population(index)) => {
                if let Ok(populations) = owner.populations.try_borrow() {
                    if let Some(cause) = populations.get(index).and_then(|lane| lane.failure()) {
                        return write!(output, "{cause}");
                    }
                }
            }
            Some(First::HelperBirth) => {
                if let Ok(birth) = owner.helper_birth.try_borrow() {
                    if let Some(cause) = birth.as_ref().and_then(|lane| lane.failure()) {
                        return write!(output, "{cause}");
                    }
                }
            }
            _ => {}
        }
        fmt::Display::fmt(&owner.closed, output)
    }
}

fn result_failure<T, E: Error + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|value| value.as_ref().err())
        .map(|cause| cause as _)
}
