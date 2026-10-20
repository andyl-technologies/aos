//! Samples a held process, fixed task subject and its original service limits.
//!
//! Only the private same-Source receiver calls this after its actual debit. It
//! borrows the existing pidfd and cgroup/control originals; it cannot construct
//! a receiving original, refresh a limit or supply a currentness token.

use std::error::Error;

use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{
    ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1, RetainedCgroupAnchor,
};
use aos_sandbox_linux::pidfd::{
    CurrentSelfPidFdCustodyV1, PidFdInfo, PidFdProcObservationsV1, PidFdProcessIdentity,
};

use super::receiving_limits::{ReceivingContainmentCurrentnessV1, ReceivingContainmentReadbackV1};


#[derive(Clone, Copy)]
enum Failure {
    Order,
    Original,
    Stat,
    Context,
    Limits,
    NetworkAggregate,
    Membership,
    ProcessPost,
    Binding,
}

/// Retains a same-original native process/control/subject comparison sample.
pub struct FixedServiceCurrentnessSampleV1<E> {
    entered: bool,
    first: Option<Failure>,
    closed: Option<E>,
    original: Option<Result<(), aos_sandbox_linux::Error>>,
    proc: Option<PidFdProcObservationsV1>,
    stat: Option<Result<PidFdProcessIdentity, aos_sandbox_linux::Error>>,
    context: Option<Result<bool, aos_sandbox_linux::Error>>,
    context_bytes: [u8; 256],
    context_length: usize,
    limits: ReceivingContainmentCurrentnessV1,
    network_limits: Option<Box<ReceivingContainmentCurrentnessV1>>,
    network_result: Option<Result<(), E>>,
    membership: Option<Result<PidFdInfo, E>>,
    membership_capture: ExactCgroupMembershipReadbackV1,
    membership_entry: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    process_post: Option<Result<PidFdProcessIdentity, aos_sandbox_linux::Error>>,
    binding: Option<Result<(), E>>,
}

impl<E> Default for FixedServiceCurrentnessSampleV1<E> {
    fn default() -> Self {
        Self {
            entered: false,
            first: None,
            closed: None,
            original: None,
            proc: None,
            stat: None,
            context: None,
            context_bytes: [0; 256],
            context_length: 0,
            limits: Default::default(), network_limits: None, network_result: None,
            membership: None,
            membership_capture: ExactCgroupMembershipReadbackV1::new(),
            membership_entry: None,
            process_post: None,
            binding: None,
        }
    }
}

impl<E: Copy + Default + Error + 'static> FixedServiceCurrentnessSampleV1<E> {
    /// Prices buffers and actual FD geometry beyond its already resident type.
    pub fn dynamic_demand() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let limits = ReceivingContainmentCurrentnessV1::fixed_demand();
        let limits_inline = u64::try_from(std::mem::size_of::<ReceivingContainmentCurrentnessV1>())
            .map_err(|_| overflow)?;
        let membership_residual = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<ExactCgroupMembershipReadbackV1>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(overflow)?;
        let membership_files = u64::try_from(ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)
            .map_err(|_| overflow)?;
        let memory = limits.get(D::MemoryBytes).checked_sub(limits_inline)
            .and_then(|bytes| bytes.checked_add(membership_residual))
            // Existing proc observation bounds: stat4096 and context256, each
            // current+initial, one256-byte scratch and bounded path/error debt.
            .and_then(|bytes| bytes.checked_add(2 * (4097 + 257) + 256 + 1024))
            .ok_or(overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, limits.get(D::OpenFiles).checked_add(2 + membership_files).ok_or(overflow)?)
            .with(D::MetadataEntries, limits.get(D::MetadataEntries).checked_add(4 + membership_files).ok_or(overflow)?))
    }

    pub(super) fn network_aggregate_dynamic_demand_v4() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        // The optional Box exists only for Network. Its body and constructor
        // temporary are additional to the actual sample's already-priced header.
        let body = u64::try_from(std::mem::size_of::<ReceivingContainmentCurrentnessV1>())
            .map_err(|_| overflow)?;
        let extra = body.checked_add(2 * std::mem::size_of::<usize>() as u64).ok_or(overflow)?;
        ReceivingContainmentCurrentnessV1::fixed_demand()
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, extra))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe_network_aggregate_once_v4(
        &mut self, process: &mut CurrentSelfPidFdCustodyV1, anchor: &RetainedCgroupAnchor,
        limits: &ReceivingContainmentReadbackV1, initial_info: PidFdInfo,
        initial_identity: PidFdProcessIdentity, expected_context: Option<&[u8]>,
        allow_terminal_context_marker: bool,
        aggregate: &super::network_receiving_aggregate::NetworkReceivingAggregateOriginalV4,
    ) -> Result<(), E> {
        if self.entered || self.network_result.is_some() { return Err(self.fail(Failure::Order)); }
        let main = self.observe_once(process, anchor, limits, initial_info, initial_identity,
            expected_context, allow_terminal_context_marker);
        // This separate native sample is prepaid and owed even after a failed
        // main process/control observation. It never clears the primary cause.
        self.network_limits = Some(Box::new(ReceivingContainmentCurrentnessV1::default()));
        let sample = self.network_limits.as_mut().ok_or(E::default())?;
        self.network_result = Some(aggregate.observe_current_into_v4(sample).map_err(|_| E::default()));
        if !matches!(self.network_result, Some(Ok(()))) { self.fail(Failure::NetworkAggregate); }
        if main.is_err() || self.first.is_some() { Err(E::default()) } else { Ok(()) }
    }

    /// Observes only the supplied fields of the same genuine fixed-service original.
    ///
    /// # Errors
    /// Retains the earliest native/subject/currentness refusal. Independent
    /// limit, membership and process posts still run after reached stat/context
    /// failure. The sample is one-shot and cannot replace an earlier result.
    pub fn observe_once(
        &mut self,
        process: &mut CurrentSelfPidFdCustodyV1,
        anchor: &RetainedCgroupAnchor,
        limits: &ReceivingContainmentReadbackV1,
        initial_info: PidFdInfo,
        initial_identity: PidFdProcessIdentity,
        expected_context: Option<&[u8]>,
        allow_terminal_context_marker: bool,
    ) -> Result<(), E> {
        if self.entered {
            return Err(self.fail(Failure::Order));
        }
        self.entered = true;
        self.original = Some(process.pidfd().map(|_| ()));
        if !matches!(self.original, Some(Ok(()))) {
            return Err(self.fail(Failure::Original));
        }
        let pidfd = match process.pidfd() {
            Ok(pidfd) => pidfd,
            Err(_) => return Err(self.fail(Failure::Original)),
        };
        self.proc = Some(pidfd.prepare_proc_observations_v1());
        if let Some(observations) = self.proc.as_mut() {
            self.stat = Some(observations.capture_stat(pidfd));
            if matches!(self.stat, Some(Ok(_))) {
                self.context = Some(observations.capture_context(pidfd).map(|bytes| {
                    if bytes.is_empty() || bytes.len() > self.context_bytes.len() {
                        return false;
                    }
                    self.context_bytes[..bytes.len()].copy_from_slice(bytes);
                    self.context_length = bytes.len();
                    expected_context.is_none_or(|expected| {
                        crate::cache_signer_context::exact_task_context_matches_v1(
                            bytes, expected, allow_terminal_context_marker,
                        )
                    })
                }));
            }
        }
        if !matches!(self.stat, Some(Ok(_))) {
            self.fail(Failure::Stat);
        } else if !matches!(self.context, Some(Ok(true))) {
            self.fail(Failure::Context);
        }

        limits.observe_current_into(anchor, &mut self.limits);
        if self.limits.require_current().is_err() {
            self.fail(Failure::Limits);
        }
        self.membership_entry = Some(self.membership_capture.capture_once(anchor, pidfd));
        self.membership = Some(if matches!(self.membership_entry, Some(Ok(()))) {
            self.membership_capture.result().and_then(|result| result.as_ref().ok())
                .copied().ok_or(E::default())
        } else {
            Err(E::default())
        });
        if !matches!(self.membership, Some(Ok(_))) {
            self.fail(Failure::Membership);
        }
        self.process_post = Some(process.observe_identity());
        if !matches!(self.process_post, Some(Ok(_))) {
            self.fail(Failure::ProcessPost);
        }
        self.binding = Some((|| {
            let before = self.stat.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
            let after = self.process_post.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
            let current = self.membership.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
            if *before != initial_identity || after != before || *current != initial_info
                || initial_info.pid() != std::process::id()
                || initial_info.thread_group_id() != std::process::id()
                || initial_info.parent_pid() != 1 || initial_info.credentials().is_none()
            {
                return Err(E::default());
            }
            Ok(())
        })());
        if !matches!(self.binding, Some(Ok(()))) {
            self.fail(Failure::Binding);
        }
        if self.first.is_none() { Ok(()) } else { Err(E::default()) }
    }

    /// Borrows actual context DATA only after the complete same-process sample.
    pub fn captured_context(&self) -> Option<&[u8]> {
        if self.first.is_none() && matches!(self.binding, Some(Ok(())))
            && matches!(self.context, Some(Ok(true))) {
            Some(&self.context_bytes[..self.context_length])
        } else {
            None
        }
    }

    fn fail(&mut self, site: Failure) -> E {
        self.first.get_or_insert(site);
        self.closed.get_or_insert(E::default());
        E::default()
    }

    /// Borrows the earliest reached native/subject/binding cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Failure::Stat => failure(&self.stat),
            Failure::Context => failure(&self.context),
            Failure::Limits => self.limits.failure(),
            Failure::NetworkAggregate => self.network_limits.as_ref().and_then(|sample| sample.failure())
                .or_else(|| failure(&self.network_result)),
            Failure::Membership => self.membership_capture.failure()
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| failure(&self.membership_entry))
                .or_else(|| failure(&self.membership)),
            Failure::ProcessPost => failure(&self.process_post),
            Failure::Binding => failure(&self.binding),
            Failure::Original => failure(&self.original),
            Failure::Order => self.closed.as_ref().map(|error| error as _),
        }.or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
