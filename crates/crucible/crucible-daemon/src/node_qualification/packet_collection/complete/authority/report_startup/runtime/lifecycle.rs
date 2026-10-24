//! Drives the actual original actor without extracting its runtime or authority.
//!
//! Capture follows genuine Arm and durable World activation. Core and native
//! codecs still decide whether the actual unchanged cut is representable.
//! Failed callbacks leave the same actor and protocol partials in the holder.

use super::*;
use crate::node_qualification::packet_collection::complete::{
    PacketCompleteExecutionError, PacketCompleteWorldCapture,
};
use crate::node_qualification::{
    PacketCompletePublicationRequest, StoredPacketCompleteResultPublisher,
};
use crucible_engine::node_contract::{ActivationPublisher, ConformanceResultPublisher};
use crucible_engine::node_state::NativeArchiveRecord;
use crucible_store::content_store::{ImmutableBlobBackend, MutableRefBackend, RefName};
use std::cell::{BorrowError, BorrowMutError, Ref, RefMut};
use std::mem::size_of_val;
use std::sync::Arc;
use std::task::{Context, Poll};

fn execution_error(error: PacketCompleteExecutionError) -> RuntimeError {
    match error {
        PacketCompleteExecutionError::Phase => RuntimeError::OutstandingObligations,
        PacketCompleteExecutionError::Refused(reason) => RuntimeError::SchedulerRefused(reason),
        PacketCompleteExecutionError::Uncertain => RuntimeError::InvalidReceipt,
        PacketCompleteExecutionError::Unwind => RuntimeError::OwnerUnavailable,
    }
}

pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn counter_scratch_data()
-> Result<usize, RuntimeError> {
    use std::mem::size_of;

    let terms = [
        size_of::<&Rc<RefCell<PacketCompleteReportStartupHolder>>>(),
        size_of::<Ref<'static, PacketCompleteReportStartupHolder>>(),
        size_of::<Result<Ref<'static, PacketCompleteReportStartupHolder>, BorrowError>>(),
        size_of::<Result<Ref<'static, PacketCompleteReportStartupHolder>, RuntimeError>>(),
        size_of::<RefMut<'static, OriginalRuntimeOwners>>(),
        size_of::<Result<RefMut<'static, OriginalRuntimeOwners>, BorrowMutError>>(),
        size_of::<Result<RefMut<'static, OriginalRuntimeOwners>, RuntimeError>>(),
        size_of::<&PacketCompleteReportStartupHolder>(),
        size_of::<&mut OriginalRuntimeOwners>(),
        size_of::<&mut Box<PacketCompleteExecutionActor>>(),
        size_of::<Option<&mut Box<PacketCompleteExecutionActor>>>(),
        size_of::<Result<&mut Box<PacketCompleteExecutionActor>, RuntimeError>>(),
        size_of::<&Rc<PacketCompleteCaptureFactory>>(),
        size_of::<Option<&Rc<PacketCompleteCaptureFactory>>>(),
        size_of::<Result<&Rc<PacketCompleteCaptureFactory>, RuntimeError>>(),
        size_of::<&mut dyn ActivationPublisher>(),
        size_of::<&mut dyn ConformanceResultPublisher>(),
        StoredPacketCompleteResultPublisher::counter_scratch_data()?,
        size_of::<Ref<'static, OriginalRuntimeOwners>>(),
        size_of::<Result<Ref<'static, OriginalRuntimeOwners>, BorrowError>>(),
        size_of::<Result<Ref<'static, OriginalRuntimeOwners>, RuntimeError>>(),
        size_of::<&Rc<PacketCompleteExecutionScene>>(),
        size_of::<Option<&Rc<PacketCompleteExecutionScene>>>(),
        size_of::<Result<&Rc<PacketCompleteExecutionScene>, RuntimeError>>(),
        size_of::<Arc<dyn ImmutableBlobBackend>>(),
        size_of::<Arc<dyn MutableRefBackend>>(),
        size_of::<[RefName; 13]>(),
        size_of::<Context<'static>>(),
        size_of::<&mut Context<'static>>(),
        size_of::<Poll<Result<(), PacketCompleteExecutionError>>>(),
        size_of::<Poll<Result<(), RuntimeError>>>(),
        size_of::<Poll<()>>(),
        size_of::<Result<Poll<()>, RuntimeError>>(),
        size_of::<PacketCompleteWorldCapture<'static>>(),
        size_of::<NativeArchiveRecord>(),
        size_of::<Option<NativeArchiveRecord>>(),
        size_of::<&mut Option<NativeArchiveRecord>>(),
        size_of::<Result<NativeArchiveRecord, PacketCompleteExecutionError>>(),
        size_of::<Result<(), PacketCompleteExecutionError>>(),
        size_of::<PacketCompleteExecutionError>(),
        size_of::<RuntimeError>(),
        size_of::<String>(),
        size_of::<Result<(), RuntimeError>>(),
        size_of::<Result<usize, RuntimeError>>(),
        size_of::<Result<usize, std::num::TryFromIntError>>(),
        size_of::<[usize; 2]>(),
        size_of::<std::slice::Iter<'static, usize>>(),
        size_of::<&[usize; 53]>(),
        size_of::<&[std::cell::OnceCell<CompleteOriginalRuntimeConstructionMember>; 3]>(),
        size_of::<&usize>(),
        size_of::<&std::cell::OnceCell<CompleteOriginalRuntimeConstructionMember>>(),
        size_of::<Option<&CompleteOriginalRuntimeConstructionMember>>(),
        size_of::<
            std::slice::Iter<
                'static,
                std::cell::OnceCell<CompleteOriginalRuntimeConstructionMember>,
            >,
        >(),
    ];
    let mut total = size_of_val(&terms);
    for bytes in &terms {
        total = total
            .checked_add(*bytes)
            .ok_or(RuntimeError::ResourceLimit)?;
    }
    Ok(total)
}

impl PacketCompleteReportStartupHolder {
    fn authenticate_original_actor_entry(&self) -> Result<(), RuntimeError> {
        self.authenticate_native_origin_data()?;
        if !matches!(self.purpose, StartupHolderPurpose::OriginalScene)
            || self.original_scene.get().is_none()
            || !self.native_completed.get()
            || !self.host_sdk_completed.get()
            || self.runtime_in_flight.get().is_some()
            || self.runtime_issuing.get().is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        for member in &self.runtime_members {
            if member.get().is_none() {
                return Err(RuntimeError::OutstandingObligations);
            }
        }
        let maximum = usize::try_from(self.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if counter_scratch_data()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }

    /// Reserves a durable Complete publisher for this same original actor scene.
    ///
    /// The caller retains the returned publisher and its durable namespace
    /// through native cleanup. Its independent placement reservation is bounded
    /// by the installed memory/content policy; no startup credit is released.
    /// Only the actual retained authority, plan and scene enter its constructor.
    ///
    /// # Errors
    /// Refuses unavailable original custody, incomplete actor construction,
    /// placement limits exceeding installed policy, another oracle/scene,
    /// duplicate names or failure of the publisher's finite construction quote.
    pub fn prepare_original_scene_result_publisher(
        original: &Rc<RefCell<Self>>,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        references: [RefName; 13],
        maximum_each_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<StoredPacketCompleteResultPublisher, RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_original_actor_entry()?;
        let maximum_memory = usize::try_from(held.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let maximum_content = usize::try_from(held.resources.content_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if maximum_total_bytes == 0
            || maximum_total_bytes > maximum_memory
            || maximum_total_bytes > maximum_content
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let owners = held
            .runtime_owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.complete || owners.actor.is_none() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let scene = owners
            .scene
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        StoredPacketCompleteResultPublisher::new(PacketCompletePublicationRequest {
            authority: Rc::clone(&held.authority),
            plan: Rc::clone(&held.plan),
            scene: Rc::clone(scene),
            blobs,
            refs,
            references,
            maximum_each_bytes,
            maximum_total_bytes,
        })
    }

    /// Arms the four original nodes through their same retained runtime actor.
    ///
    /// The earlier initial lifecycle and inactive runtime construction must have
    /// completed. No actor, controller, readiness or mutable runtime escapes.
    ///
    /// # Errors
    /// Refuses foreign, retired, busy or incomplete scene custody, an actor in
    /// another phase, or failure of an actual owning node's readiness callback.
    pub fn arm_original_scene(original: &Rc<RefCell<Self>>) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_original_actor_entry()?;
        let mut owners = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        owners
            .actor
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .arm()
            .map_err(execution_error)
    }

    /// Durably activates the same armed original four-owner world.
    ///
    /// The caller retains its actual publisher across refusal. The actor keeps
    /// the runtime and every genuine Ready/preparation through publication.
    ///
    /// # Errors
    /// Refuses unavailable original custody, an unarmed or previously attempted
    /// actor, invalid native preparations, exhausted encoding or failed durable
    /// publication. Failed attempts remain held in their original actor.
    pub fn activate_original_scene(
        original: &Rc<RefCell<Self>>,
        publisher: &mut dyn ActivationPublisher,
        maximum_record_bytes: usize,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_original_actor_entry()?;
        let mut owners = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        owners
            .actor
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .activate(publisher, maximum_record_bytes)
            .map_err(execution_error)
    }

    /// Begins the next fixed original grant, including its genuine input handoff.
    ///
    /// Reactive rows stage, acknowledge and commit their actual exact batch
    /// before Begin. The actor retains its own stage IDs and returned operation
    /// token; this entry accepts no caller-supplied operation or input authority.
    ///
    /// # Errors
    /// Refuses unavailable or foreign original custody, the wrong actor phase,
    /// invalid exact-input closure, resource exhaustion or uncertain native work.
    /// The same original token and partial input handoff remain held on failure.
    pub fn begin_original_scene_next(original: &Rc<RefCell<Self>>) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_original_actor_entry()?;
        let mut owners = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        owners
            .actor
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .begin_next()
            .map_err(execution_error)
    }

    /// Polls the same retained original token without issuing another grant.
    ///
    /// Pending leaves the genuine actor running; completion retains its native
    /// result until the separate durable publication and ACK entry succeeds.
    ///
    /// # Errors
    /// Refuses unavailable original custody, a nonrunning actor or a failed
    /// native poll. No token, runtime or protocol partial is extracted.
    pub fn poll_original_scene(
        original: &Rc<RefCell<Self>>,
        context: &mut Context<'_>,
    ) -> Result<Poll<()>, RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_original_actor_entry()?;
        let mut owners = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        let actor = owners
            .actor
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        match actor.poll(context) {
            Poll::Pending => Ok(Poll::Pending),
            Poll::Ready(result) => {
                result.map_err(execution_error)?;
                Ok(Poll::Ready(()))
            }
        }
    }

    /// Durably publishes the original completion before its native scheduling ACK.
    ///
    /// The supplied publisher must authenticate and retain this actual Complete
    /// plan and result. A copied outcome or another fixture's publisher cannot
    /// replace the Core token and Source proof checks performed by the actor.
    ///
    /// # Errors
    /// Refuses unavailable original custody, an incomplete actor, wrong publisher
    /// scope, failed durability or native ACK. The same token remains retained.
    pub fn acknowledge_original_scene(
        original: &Rc<RefCell<Self>>,
        publisher: &mut dyn ConformanceResultPublisher,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_original_actor_entry()?;
        let mut owners = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        owners
            .actor
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .acknowledge(publisher)
            .map_err(execution_error)
    }

    /// Enrolls and durably publishes the actual Complete result before native ACK.
    ///
    /// The same actor lends its retained token and genuine runtime witness to
    /// the concrete publisher. The publisher retains the original native report
    /// and authenticates the Complete oracle before the existing ACK path runs.
    ///
    /// # Errors
    /// Refuses unavailable or foreign original custody, an incomplete actor,
    /// changed publisher/report/oracle scope, failed durability or native ACK.
    /// The original completion and every failed publication partial stay held.
    pub fn acknowledge_original_scene_stored(
        original: &Rc<RefCell<Self>>,
        publisher: &mut StoredPacketCompleteResultPublisher,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_original_actor_entry()?;
        let mut owners = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        owners
            .actor
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .acknowledge_stored(publisher)
            .map_err(execution_error)
    }

    /// Captures the original active world into a caller-retained archive slot.
    ///
    /// The actual factory and actor remain in their owning holder. The caller
    /// keeps the archive, output slot and holder through failure and authentic
    /// source retirement, then reloads the signed result for fresh restoration.
    /// This does not enable modeled grants or the restored recapture codec.
    ///
    /// # Errors
    /// Refuses an occupied destination, foreign or unavailable scene, inactive
    /// actor, unsupported native cut, incomplete proofs or finite capture excess.
    /// Native/SDK originals and partial administrative attempts stay retained.
    pub fn capture_original_scene_into(
        original: &Rc<RefCell<Self>>,
        request: PacketCompleteWorldCapture<'_>,
        output: &mut Option<NativeArchiveRecord>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_original_actor_entry()?;
        let mut owners = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        let OriginalRuntimeOwners { actor, factory, .. } = &mut *owners;
        let factory = factory.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let actor = actor.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        *output = Some(actor.capture(factory, request).map_err(execution_error)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
