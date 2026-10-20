//! Owns the fresh Start native interval before protected authorization.
//!
//! The predecessor is an actual completed Create and closed Root client. Its
//! expired clock remains historical evidence. The new interval uses the same C
//! ledger and sole Bank/name/profile engine, preserving all spent traffic. It
//! grants no Source mutation, accepted operation or Host launch authority.

mod history;
mod authorization;
mod assignment;
mod assignment_inputs;
pub(crate) mod source_origin;
mod terminal;
pub(crate) use terminal::StartTerminalAppendContextV2;
mod network_io;
mod resource_state;
mod resource_ports;
mod network_resident;
pub use network_resident::StartResourceSessionResidentShapeDataV4;
pub use network_io::{StartResourceProvisioningIoLoanV2, StartResourcePreparedRequestBorrowV2,
    StartResourceSessionPostShapeDataV2};
mod host_root;
pub(crate) mod host_publication;
#[doc(hidden)]
pub use host_publication::{StartHostCatalogPublicationLoanV2, StartHostCatalogIoLoanV2, StartHostCatalogNativeCompletionV2, StartHostCatalogCompletionRefusalV2};
#[doc(hidden)]
pub use network_io::StartHostSessionRejoinOriginalV2;
mod host_catalog;
pub use host_catalog::{StartHostCatalogProjectionOriginalV2, StartHostCatalogProjectionClosedV2};
mod network_preparation;
mod network_opening;
pub use network_opening::{StartResourceUpperDisposalV2, StartResourceSessionOpeningOriginalV2, StartResourceSessionOpeningLoanV2, StartResourceSessionOpeningOwnerLinkV2,
    StartResourceColdCompletionOriginalV4,
    StartResourceSessionAssociationV4, StartResourceHelloDisposalV4, StartResourceHelloDisposalErrorV4, StartResourceSessionCurrentnessErrorV4};
pub use network_preparation::{PreparedStartResourceRequestOriginalV2, PreparedStartResourceRequestClosedV2};
pub use host_root::OriginalStartHostRootLoanV1;

use std::error::Error;
use std::mem::size_of;
use std::sync::{Arc, Mutex};

use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_core::{OperationId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1;
use aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1;

use super::{CreateProvisioningOriginalsV1, NativeResidenceV1, runtime_layout};
use crate::controller_resource_reservation::create_intake::ready::ownership::StartOwnershipOriginalV1;
use crate::controller_resource_reservation::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::normal_root::{ProductionControllerNormalRootProfileV1, RootStorageApplyClientOriginalV1};
use crate::public_api_session::PublicApiPeer;
use crate::public_mutation_compiler::PublicMutationAuthorizationNativeV1;
use crate::{CreateStoppedTerminalCustodyV1, Journal};

type PairOriginal = RetainedKernelPairedClockAttemptV1<SourceGenesisErrorV1>;

pub(crate) struct StartNativeEntryPredecessorV1<'previous> {
    previous: &'previous CreateProvisioningOriginalsV1,
}

impl StartNativeEntryPredecessorV1<'_> {
    // The constructor creates this only after the actual Root/client terminal
    // gate. Bank repeats native affinity without retaking its own mutex.
    pub(crate) fn require_bank_v1(&self, bank: &ControllerResourceBankOpeningV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !std::ptr::eq(self.previous.profile.as_ref(), profile) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = self.previous.native.as_ref()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        bank.require_completed_provisioning_original_v1(native.original_v1(), controller, profile)
    }
}

#[derive(Clone, Copy)]
enum FirstV1 {
    Predecessor,
    Resident,
    Geometry,
    Native,
    AppendGeometry(usize),
    AppendFunding(usize),
    After,
    ResourcePost(resource_state::StartResourceKindV2),
    ResourceSessionResident(resource_state::StartResourceKindV2),
    ResourceSessionJoin(bool),
    Reentry,
}

/// Retains fresh Start receiving custody and its authorization originals.
///
/// The physical interval precedes authorization because the canonical protected
/// time-floor write must cross the same native fence. Only a completed Create
/// owner can construct this value; an input envelope supplies no authority.
#[doc(hidden)]
#[must_use = "retain this owner and finish every independently owed native post"]
pub struct AcceptedStartEntryOriginalV1 {
    native_state: Option<StartNativeStateV1>,
    history: Box<history::StartHistoryOriginalV1>,
    history_entry: Option<Result<(), ResourceReservationErrorV1>>,
    body: Box<authorization::StartAuthorizationOriginalV1>,
    source_origin: Box<source_origin::StartSourceOriginOriginalV1>,
    terminal: Box<terminal::StartTerminalOriginalV2>,
    assignment_inputs: Box<assignment_inputs::StartAssignmentInputsOriginalV2>,
    start_assignment: Box<assignment::StartAssignmentOriginalV2>,
    start_ownership: Box<StartOwnershipOriginalV1>,
    ownership_base: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    ownership_next: Option<Result<(), ResourceReservationErrorV1>>,
    ownership_body: Option<Result<crate::CreateStorageOwnershipProgressV1, ResourceReservationErrorV1>>,
    ownership_native_selected: bool,
    ownership_body_selected: bool,
    ownership_resident: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    resource_entries: Box<resource_state::StartResourceEntriesV2>,
    identity: Result<Arc<()>, ResourceReservationErrorV1>,
    native_after_selected: bool,
    entry_failure_selected: bool,
    journal_identity: Option<Result<crate::journal::StartAdmissionJournalIdentityV1, crate::JournalError>>,
    authorization_native: PublicMutationAuthorizationNativeV1,
    first_clock: PairOriginal,
    after_clock: PairOriginal,
}

impl AcceptedStartEntryOriginalV1 {
    /// Quotes fixed destination backing before the installed Runtime grows.
    ///
    /// This passive geometry grants no owner, namespace entry or authority.
    /// The same RuntimeFixed or issue-only precharge must admit the sum before
    /// any of these fixed subslots can allocate.
    #[doc(hidden)]
    pub fn inactive_receiving_bytes_v2() -> Option<usize> {
        let fixed = [
            fixed_box_bytes_v2::<history::StartHistoryOriginalV1>(),
            fixed_box_bytes_v2::<authorization::StartAuthorizationOriginalV1>(),
            fixed_box_bytes_v2::<source_origin::StartSourceOriginOriginalV1>(),
            fixed_box_bytes_v2::<terminal::StartTerminalOriginalV2>(),
            fixed_box_bytes_v2::<assignment_inputs::StartAssignmentInputsOriginalV2>(),
            fixed_box_bytes_v2::<assignment::StartAssignmentOriginalV2>(),
            fixed_box_bytes_v2::<StartOwnershipOriginalV1>(),
            fixed_box_bytes_v2::<resource_state::StartResourceEntriesV2>(),
            fixed_box_bytes_v2::<resource_state::StartResourceStatesV2>(),
            resource_state::StartResourceStatesV2::inactive_receiving_bytes_v2(),
            resource_state::StartResourceEntriesV2::inactive_receiving_bytes_v2(),
        ];
        fixed.into_iter().try_fold(0_usize, |total, next| total.checked_add(next?))
    }
}

fn fixed_box_bytes_v2<T>() -> Option<usize> {
    // Pointee, returned value and callee construction may coexist. Native
    // allocator overhead remains backed by the actual C limit.
    size_of::<T>().checked_mul(3)?
        .checked_add(size_of::<Box<T>>().checked_mul(2)?)?
        .checked_add(size_of::<std::alloc::Layout>())
}

pub(crate) struct StartNativeStateV1 {
    pub(crate) host_publication_action: Option<host_publication::StartHostPublicationActionOriginalV2>,
    create_parent: OperationId,
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    runtime_layout: Result<runtime_layout::RuntimeLayoutV1, runtime_layout::RuntimeLayoutErrorV1>,
    predecessor: Result<(), crate::normal_root::RootStorageApplyClientClosedV1>,
    q04: Result<Q04CutIdentityV1, ResourceReservationErrorV1>,
    predecessor_association: Result<crate::CreateStoppedCompletionAssociationV1,ResourceReservationErrorV1>,
    predecessor_resident: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    history_resident: Option<ResourceVector>,
    resources: Box<resource_state::StartResourceStatesV2>,
    native_turn: u64,
    native: Option<Result<NativeResidenceV1, ResourceReservationErrorV1>>,
    after: Option<Result<(), ResourceReservationErrorV1>>,
    append_geometry: [Option<Result<ResourceVector, ResourceReservationErrorV1>>; 9],
    append_funding: [Option<Result<(), ResourceReservationErrorV1>>; 9],
    spent: ResourceVector,
    append_spent: [Option<ResourceVector>; 9],
    first: Option<FirstV1>,
    reentry: ResourceReservationErrorV1,
}

impl CreateProvisioningOriginalsV1 {
    /// Enters fresh Start custody from the actual fully closed Create owner.
    ///
    /// The returned owner, including refusal, stays in the real Runtime header.
    /// Its fixed subslots are prepaid by the compiled startup backing supplier;
    /// the small Runtime header argument supplies accounting DATA only.
    /// The caller acquires genuine mechanical completed custody before this call.
    /// New profile slots invalidate old native-completed reborrows. A fresh paid
    /// full Source/C historical fold remains mandatory before authorization. No new deadline or account is created.
    #[doc(hidden)]
    pub fn begin_original_start_entry_once_v1<T: Sized>(&mut self,
        terminal: &CreateStoppedTerminalCustodyV1<'_>, root: &RootStorageApplyClientOriginalV1,
        action: &crate::OriginalPublicationActionV1,
        controller: &mut Journal, peer: &PublicApiPeer, encoded: &[u8], runtime_header: &T,
    ) -> AcceptedStartEntryOriginalV1 {
        let repeated = self.start_entry_entered;
        self.start_entry_entered = true;
        let runtime_layout = runtime_layout::RuntimeLayoutV1::from_runtime_header_v1(self.parent, runtime_header);
        let predecessor = if repeated {
            Err(crate::normal_root::RootStorageApplyClientClosedV1)
        } else {
            root.require_completed_create_stopped_custody_v1(terminal, self, controller)
        };
        let mut next = StartNativeStateV1 {
            create_parent: self.parent, bank: Arc::clone(&self.bank), profile: Arc::clone(&self.profile),
            runtime_layout, predecessor, q04: terminal.q04_v1().cloned(),
            predecessor_association: terminal.association_v1(), predecessor_resident: None,
            geometry: None, history_resident: None,
            resources: Box::new(Default::default()), native_turn: 0, native: None, after: None,
            host_publication_action: None,
            append_geometry: std::array::from_fn(|_| None),
            append_funding: std::array::from_fn(|_| None), spent: ResourceVector::ZERO,
            append_spent: [None; 9], first: None, reentry: ResourceReservationErrorV1::Conflict,
        };
        if repeated {
            next.first = Some(FirstV1::Reentry);
        } else if next.predecessor.is_err() || next.q04.is_err() || next.predecessor_association.is_err() {
            next.first = Some(FirstV1::Predecessor);
        } else {
            next.predecessor_resident = Some((|| {
                if action.parent_operation_v1() != self.parent {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                let association = next.predecessor_association.as_ref().map_err(|_|ResourceReservationErrorV1::Conflict)?;
                if association.root_admission_v1() != action.root_admission_commitment_v1() {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                use aos_sandbox_protocol::domain_ledger::effect_history::{
                    decode_lifecycle_effect_receipt_v1, LifecycleEffectReceiptDataV1,
                };
                let receipt = decode_lifecycle_effect_receipt_v1(association.receipt_bytes_v1(), association.lane_v1())
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                let LifecycleEffectReceiptDataV1::CreateStopped(receipt) = receipt else {
                    return Err(ResourceReservationErrorV1::Conflict);
                };
                receipt.require_resources_v1(action.contract_v1().records_v1())
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                Ok(self.completed_resident_receiving_demand_v1(terminal, controller)?
                    .checked_add(terminal.completed_resident_receiving_demand_v1()?)?
                    .checked_add(action.resident_receiving_demand_v1(controller)?)?
                    .checked_add(root.resident_receiving_demand_v1()?)?)
            })());
            if !matches!(next.predecessor_resident, Some(Ok(_))) {
                next.first = Some(FirstV1::Resident);
            } else {
                next.begin_native_from_previous_v1(self, controller, peer, encoded);
            }
        }
        let identity = next.require_current_v1(controller).map(|()| Arc::new(()));
        let journal_identity = identity.as_ref().ok().map(|_| controller.start_admission_identity_v1(&next));
        AcceptedStartEntryOriginalV1 {
            native_state: Some(next),
            history: Box::new(history::StartHistoryOriginalV1::new()), history_entry: None,
            body: Box::new(authorization::StartAuthorizationOriginalV1::new()),
            source_origin: Box::new(source_origin::StartSourceOriginOriginalV1::new()),
            terminal: Box::new(terminal::StartTerminalOriginalV2::new()),
            assignment_inputs: Box::new(assignment_inputs::StartAssignmentInputsOriginalV2::new()),
            start_assignment: Box::new(assignment::StartAssignmentOriginalV2::new()),
            start_ownership: Box::new(StartOwnershipOriginalV1::new()), ownership_base:None,
            ownership_next:None, ownership_body:None, ownership_native_selected:false, ownership_body_selected:false, ownership_resident:None,
            resource_entries: Box::new(Default::default()),
            identity, journal_identity, native_after_selected: false, entry_failure_selected: false,
            authorization_native: PublicMutationAuthorizationNativeV1::new(),
            first_clock: Default::default(),
            after_clock: Default::default(),
        }
    }
}

impl StartNativeStateV1 {
    fn begin_native_from_previous_v1(&mut self, previous: &CreateProvisioningOriginalsV1,
        controller: &mut Journal, peer: &PublicApiPeer, encoded: &[u8],
    ) {
        self.geometry = Some(self.authorization_receiving_demand_v1(controller, peer, encoded));
        let Some(complete) = self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() else {
            self.first = Some(FirstV1::Geometry);
            return;
        };
        let predecessor = StartNativeEntryPredecessorV1 { previous };
        self.native = Some((|| {
            let bank = self.bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let native = bank.begin_accepted_start_native_v1(
                &predecessor, controller, self.profile.as_ref(), complete,
            )?;
            // Retain refusal inline; allocate only after the genuine debit.
            Ok(if native.failure().is_some() {
                NativeResidenceV1::Refused(native)
            } else {
                NativeResidenceV1::Positive(Box::new(native))
            })
        })());
        if self.native.as_ref().and_then(|value| value.as_ref().ok())
            .is_none_or(|native| native.original_v1().failure().is_some()) {
            self.first = Some(FirstV1::Native);
        }
    }

    fn begin_next_start_native_v1(&mut self,controller:&mut Journal,complete:ResourceVector)
        ->Result<(),ResourceReservationErrorV1> {
        if self.first.is_some() || self.resources.failure_v2().is_some()
            || !matches!(self.after,Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let next = self.native_turn.checked_add(1).ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = complete.checked_add(self.resources.retained_demand_v2(next)?)?;
        let native=self.native.as_mut().and_then(|value|value.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let bank=self.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?;
        bank.require_completed_provisioning_original_v1(native.original_v1(),controller,self.profile.as_ref())?;
        // Once lower entry is invoked its actual owning failure also owes its
        // independent post. No prior traffic base is reset or reconstructed.
        self.after=None;
        self.native_turn=next;
        self.spent=ResourceVector::ZERO;
        bank.begin_next_start_provisioning_turn_v1(native.original_mut_v1(),controller,self.profile.as_ref(),complete)
    }

    fn native_failure_v1(&self)->Option<&(dyn Error+'static)> {
        self.native.as_ref().and_then(|value|value.as_ref().ok())
            .and_then(|native|native.original_v1().failure())
    }

    pub(crate) fn require_current_v1(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some() || self.after.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_create_provisioning_current_v1(native.original_v1(), controller, self.profile.as_ref())
    }

    /// Finishes the same fresh native interval even after its body refused.
    ///
    /// # Errors
    /// Retains changed affinity, unfinished native observations or reentry.
    #[doc(hidden)]
    pub fn finish_native_once_v1(&mut self, controller: &mut Journal)
        -> Result<(), ResourceReservationErrorV1> {
        if self.after.is_some() {
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.after = Some(match self.native.as_mut().and_then(|result| result.as_mut().ok()) {
            Some(native) => self.bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
                .and_then(|bank| bank.finish_create_provisioning_native_once_v1(
                    native.original_mut_v1(), controller, self.profile.as_ref())),
            None => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::After);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Borrows the actual first preconstruction or native failure.
    #[doc(hidden)]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Err(cause) = &self.runtime_layout { return Some(cause); }
        match self.first? {
            FirstV1::Reentry => Some(&self.reentry),
            FirstV1::Predecessor => self.predecessor.as_ref().err().map(|cause| cause as _)
                .or_else(|| self.q04.as_ref().err().map(|cause| cause as _))
                .or_else(||self.predecessor_association.as_ref().err().map(|cause|cause as _)),
            FirstV1::Resident => self.predecessor_resident.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::Geometry => self.geometry.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::AppendGeometry(index) => self.append_geometry.get(index)?.as_ref()?.as_ref().err().map(|cause| cause as _),
            FirstV1::AppendFunding(index) => self.native.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|native| native.original_v1().failure())
                .or_else(|| self.append_funding.get(index)?.as_ref()?.as_ref().err().map(|cause| cause as _)),
            FirstV1::Native => match self.native.as_ref()? {
                Err(cause) => Some(cause),
                Ok(native) => native.original_v1().failure(),
            },
            FirstV1::ResourceSessionResident(kind) => self.resources.member_v2(kind).session_resident.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            FirstV1::ResourceSessionJoin(selected) => {
                if selected { self.native_failure_v1().or_else(|| self.resources.storage.retained_create_failure_v2()) }
                else { self.resources.storage.retained_create_failure_v2() }
            }
            FirstV1::ResourcePost(kind) => self.native_failure_v1()
                .or_else(|| self.resources.member_v2(kind).post.failure()),
            FirstV1::After => self.native.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|native| native.original_v1().failure())
                .or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _)),
        }
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn predecessor_association_v1(&self)
        ->Result<&crate::CreateStoppedCompletionAssociationV1,ResourceReservationErrorV1> {
        self.predecessor_association.as_ref().map_err(|_|ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn q04_v1(&self) -> Result<&Q04CutIdentityV1, ResourceReservationErrorV1> {
        self.q04.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_append_once_v1(&mut self, controller: &Journal,
        transaction: &crate::JournalTransaction, index: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_append_index_once_v2(controller, transaction, index, None)
    }

    pub(crate) fn require_host_append_once_v2(&mut self, controller: &Journal,
        transaction: &crate::JournalTransaction, index: usize, root_resident: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !(2..=7).contains(&index) || self.host_publication_action.is_none() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_append_index_once_v2(controller, transaction, index, Some(root_resident))
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn require_terminal_append_once_v2(&mut self,
        controller: &Journal, transaction: &crate::JournalTransaction, complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.host_publication_action.is_none() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_append_index_once_v2(controller, transaction, 8, Some(complete))
    }

    fn require_append_index_once_v2(&mut self, controller: &Journal,
        transaction: &crate::JournalTransaction, index: usize, host_root: Option<ResourceVector>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        let allowed = match host_root {
            None => index < 2,
            Some(_) => (2..=8).contains(&index),
        };
        if !allowed || self.append_geometry[index].is_some()
            || index > 0 && !matches!(self.append_funding[index - 1], Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.append_geometry[index] = Some((|| {
            let append = controller.append_receiving_demand_v1(transaction.records().iter().map(|record|
                aos_sandbox_journal::geometry::RecordShape {
                    key_bytes: record.key().len(), value_bytes: record.value().map(<[u8]>::len),
                })).map_err(|cause| match cause {
                    crate::journal::JournalAppendReceivingDemandErrorV1::Journal(cause) => ResourceReservationErrorV1::Journal(cause),
                    crate::journal::JournalAppendReceivingDemandErrorV1::Accounting(cause) => cause.into(),
                })?;
            self.append_spent[index] = Some(self.spent.checked_add(
                aos_sandbox_core::component_receiving::operation_traffic_demand_v1(append),
            )?);
            let base = self.history_resident.ok_or(ResourceReservationErrorV1::Conflict)?;
            let base = match host_root {
                Some(complete) if index == 8 => complete,
                Some(root) => base.checked_add(root)?
                    .checked_add(self.resources.retained_demand_v2(self.native_turn)?)?,
                None => base,
            };
            Ok(base.checked_add(self.spent)?.checked_add(append)?)
        })());
        let Some(Ok(complete)) = self.append_geometry[index].as_ref() else {
            self.first.get_or_insert(FirstV1::AppendGeometry(index));
            return Err(ResourceReservationErrorV1::Conflict);
        };
        let complete = *complete;
        self.append_funding[index] = Some((|| {
            let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_create_provisioning_complete_v1(native.original_mut_v1(), controller,
                    self.profile.as_ref(), complete)
        })());
        if !matches!(self.append_funding[index], Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::AppendFunding(index));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.spent = self.append_spent[index].ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(())
    }

    fn authorization_receiving_demand_v1(&self, controller: &Journal, peer: &PublicApiPeer, encoded: &[u8])
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        use aos_proto::aos::sandbox::v1 as wire;
        use aos_sandbox_protocol::public_api::mutation::PublicMutationEnvelopeDataV1;
        use aos_sandbox_protocol::public_api::method::PublicApiAuditMethodV1;
        use crate::public_mutation_compiler::delete_admission::geometry::authorization_model_bytes_v1;

        let bad = || ResourceReservationErrorV1::Conflict;
        let envelope = PublicMutationEnvelopeDataV1::decode_v1(encoded).map_err(|_| bad())?;
        if envelope.method_v1() != PublicApiAuditMethodV1::StartSandbox { return Err(bad()); }
        let encoded = encoded.len();
        let peer = peer.retained_recheck_demand_v1().ok_or_else(bad)?;
        let mut bytes = 0_usize;
        let mut rows = 0_usize;
        for (_, key, value) in controller.all_records() {
            bytes = bytes.checked_add(key.len()).and_then(|n| n.checked_add(value.len())).ok_or_else(bad)?;
            rows = rows.checked_add(1).ok_or_else(bad)?;
        }
        let authorization = authorization_model_bytes_v1(bytes, rows).ok_or_else(bad)?;
        let nodes = size_of::<buffa::UnknownField>().checked_add(size_of::<wire::Feature>()).ok_or_else(bad)?;
        let request = encoded.checked_mul(nodes).and_then(|n| n.checked_mul(6))
            .and_then(|n| n.checked_add(encoded.checked_mul(32)?))
            .and_then(|n| n.checked_add(size_of::<wire::SandboxLifecycleRequest>()
                .checked_add(size_of::<wire::MutationContext>())?
                .checked_add(size_of::<wire::Duration>())?
                .checked_add(size_of::<crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1>())?
                .checked_add(size_of::<crate::OperationPlan>())?
                .checked_add(size_of::<aos_sandbox_protocol::domain_ledger::effect_history::EffectPlan>())?
                .checked_add(size_of::<aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1>())?
                .checked_add(size_of::<aos_sandbox_protocol::public_api::projection::PublicProjectionRecordV1>())?
                .checked_mul(4)?))
            .ok_or_else(bad)?;
        let clock = PairOriginal::dominant_requested_bytes_v1().ok_or_else(bad)?;
        let boot = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1().ok_or_else(bad)?;
        let memory = size_of::<AcceptedStartEntryOriginalV1>().checked_mul(2)
            .and_then(|n| n.checked_add(size_of::<crate::reconciler::start_admission::StartAdmissionScopeV1>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<usize>().checked_mul(4)?))
            .and_then(|n| n.checked_add(size_of::<aos_sandbox_broker::controller_receiving::profile::ControllerProfileFailureViewV1<'_>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<crate::lifecycle::LifecycleHistoricalReadOriginalV1>().checked_mul(2)?))
            .and_then(|n| n.checked_add(authorization)).and_then(|n| n.checked_add(request))
            .and_then(|n| n.checked_add(clock.checked_mul(2)?)).and_then(|n| n.checked_add(boot))
            .and_then(|n| u64::try_from(n).ok()).ok_or_else(bad)?;
        let files = PairOriginal::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)
            .and_then(|n| n.checked_add(RootOriginalKernelBootIdAttemptV1::MAXIMUM_RETAINED_FILES_V1))
            .and_then(|n| u64::try_from(n).ok()).ok_or_else(bad)?;
        let names = PairOriginal::receiving_metadata_cells_v1().and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(RootOriginalKernelBootIdAttemptV1::receiving_metadata_cells_v1()))
            .and_then(|n| u64::try_from(n).ok()).ok_or_else(bad)?;
        let native = ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::OpenFiles, files)
            .with(D::MetadataEntries, names);
        Ok(peer.checked_add(peer)?.checked_add(peer)?.checked_add(peer)?.checked_add(native)?
            .checked_add(self.runtime_layout.as_ref().map_err(|_| bad())?.receiving_demand_v1(self.create_parent)?)?
            .checked_add(*self.predecessor_resident.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(bad)?)?
            .checked_add(controller.create_storage_semantic_append_demand_v1()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                crate::controller_service::public_projection::sandbox_source_receiving_bytes_v1(controller)
                    .ok_or_else(bad)?))?)
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Rejoins the same completed Attempt after its new paid entry replaced profile slots.
    ///
    /// # Errors
    /// Refuses a changed opaque predecessor, Source/C instance, new native
    /// currentness, or any failure of the separately funded historical fold.
    #[doc(hidden)]
    pub fn observe_create_history_from_attempt_once_v1(&mut self,
        attempt:&crate::CreateStoppedCompletionAttemptV1,controller:&Journal,
        source:&mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    )->Result<(),ResourceReservationErrorV1> {
        if self.history_entry.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.history_entry = Some((|| {
            let state=self.native_state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            state.require_current_v1(controller)?;
            let custody=attempt.borrow_paid_start_history_custody_v1(state,controller,source)?;
            self.observe_create_history_once_v1(&custody,controller,source)
        })());
        if matches!(self.history_entry,Some(Ok(()))) {Ok(())}
        else {Err(ResourceReservationErrorV1::Conflict)}
    }

    /// Validates the actual predecessor after new native funding and before authorization.
    ///
    /// # Errors
    /// Retains failed native observations, complete schema/current rows or the
    /// shared historical comparison; every reached Source post is still run.
    #[doc(hidden)]
    fn observe_create_history_once_v1(&mut self,
        predecessor: &CreateStoppedTerminalCustodyV1<'_>, controller: &Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.history.observe_once_v1(self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?,
            predecessor,controller,source)
    }

    /// Finishes the independently owed posts after the actual owner handback.
    ///
    /// # Errors
    /// Refuses a missing owner, changed native identity or any failed post.
    #[doc(hidden)]
    pub fn finish_native_once_v1(&mut self, controller: &mut Journal)
        -> Result<(), ResourceReservationErrorV1> {
        self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
            .finish_native_once_v1(controller)
    }

    /// Formats the selected actual refusal, including a guarded native profile cause.
    ///
    /// No native archive guard or temporary error reference escapes this call.
    ///
    /// # Errors
    /// Returns only an error reported by the supplied formatter.
    #[doc(hidden)]
    pub fn fmt_failure_v1(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(formatted) = self.terminal.fmt_selected_decoder_failure_v2(formatter) {
            return formatted;
        }
        if let Some(formatted)=self.source_origin.fmt_selected_decoder_failure_v1(formatter) {
            return formatted;
        }
        if self.assignment_inputs.root_selected {
            return self.assignment_inputs.client.fmt_failure_v2(formatter);
        }
        let inputs_native_selected = self.assignment_inputs.native_selected;
        let assignment_failure = self.start_assignment.failure(None).is_some();
        let ownership_failure=self.start_ownership.failure().is_some() || self.ownership_next.as_ref().is_some_and(Result::is_err)
            || self.ownership_base.as_ref().is_some_and(Result::is_err);
        let resource_native_selected = self.resource_entries.native_failure_is_selected_v2(
            self.native_state.as_ref().and_then(|native| native.host_publication_action.as_ref()));
        let native_selected = if inputs_native_selected { true }
            else if assignment_failure { self.start_assignment.original_failure_is_selected_v2() }
            else if resource_native_selected { true }
            else if self.terminal.failure(self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1)).is_some() {
                self.terminal.native_failure_is_selected_v2()
            }
            else if ownership_failure {self.ownership_native_selected} else {self.native_after_selected || (
            self.body.failure_with_original_v1(self).is_none()
                && if self.source_origin.has_selected_failure_v1() {
                    self.source_origin.native_failure_is_selected_v1()
                } else if self.history.failure(self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1)).is_some() {
                    self.history.native_failure_is_selected_v1()
                } else {
                    self.native_state.as_ref().is_some_and(|state| matches!(state.first,
                        Some(FirstV1::Native | FirstV1::AppendFunding(_) | FirstV1::After)))
                }
        )};
        if native_selected {
            if let Some(view) = self.native_state.as_ref()
                .and_then(|state|state.native.as_ref()).and_then(|value|value.as_ref().ok())
                .and_then(|native|native.original_v1().profile_failure_view_v1()) {
                return formatter.debug_struct("OriginalStartProfileFailure")
                    .field("phase", &view.phase())
                    .field("classification", &view.classification())
                    .field("cause", &view.cause())
                    .field("property", &view.property_failure())
                    .finish();
            }
        }
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original Start entry has no selected failure"),
        }
    }

    /// Borrows the actual retained receiving refusal.
    #[doc(hidden)]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.entry_failure_selected {
            return self.history.failure(self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1))
                .or_else(||self.history_entry.as_ref().and_then(|value|value.as_ref().err()).map(|cause|cause as _))
                .or_else(||self.native_state.as_ref().and_then(StartNativeStateV1::failure));
        }
        if self.native_after_selected {
            return self.native_state.as_ref().and_then(StartNativeStateV1::failure);
        }
        self.body.failure_with_original_v1(self)
            .or_else(||self.source_origin.failure(self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1)))
            .or_else(|| self.assignment_inputs.failure(
                self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1)))
            .or_else(|| self.start_assignment.failure(
                self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1)))
            .or_else(|| {
                let selected=if self.ownership_native_selected {
                    self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1)
                } else {None};
                selected.or_else(||self.ownership_base.as_ref().and_then(|value|value.as_ref().err()).map(|cause|cause as _))
                    .or_else(||self.ownership_next.as_ref().and_then(|value|value.as_ref().err()).map(|cause|cause as _))
                    .or_else(||if self.ownership_body_selected {
                        self.ownership_body.as_ref().and_then(|value|value.as_ref().err()).map(|cause|cause as _)
                    } else {None})
                    .or_else(||self.start_ownership.failure())
                    .or_else(||self.ownership_resident.as_ref().and_then(|value|value.as_ref().err()).map(|cause|cause as _))
                    .or_else(||self.ownership_body.as_ref().and_then(|value|value.as_ref().err()).map(|cause|cause as _))
            })
            .or_else(|| self.resource_entries.failure_v2(
                self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1),
                self.native_state.as_ref().and_then(|native| native.host_publication_action.as_ref())))
            .or_else(|| self.terminal.failure(self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1)))
            .or_else(||self.history.failure(self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1)))
            .or_else(||self.history_entry.as_ref().and_then(|value|value.as_ref().err()).map(|cause|cause as _))
            .or_else(||self.native_state.as_ref().and_then(StartNativeStateV1::failure))
            .or_else(||self.identity.as_ref().err().map(|cause|cause as _))
            .or_else(||self.journal_identity.as_ref().and_then(|value|value.as_ref().err()).map(|cause|cause as _))
    }
}

impl AcceptedStartEntryOriginalV1 {
    pub(crate) fn take_native_state_v1(&mut self, controller: &Journal)
        -> Result<StartNativeStateV1, ResourceReservationErrorV1> {
        self.history.require_before_authorization_v1()?;
        self.native_state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?
            .require_current_v1(controller)?;
        self.native_state.take().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn restore_native_state_v1(&mut self, state: StartNativeStateV1) {
        if self.native_state.is_some() { std::process::abort(); }
        self.native_state = Some(state);
    }
}

pub(crate) struct AcceptedStartPlanOriginalV1<'entry> { entry:&'entry AcceptedStartEntryOriginalV1 }

impl AcceptedStartPlanOriginalV1<'_> {
    pub(crate) fn scope_identity_v1(&self)->Result<&Arc<()>,ResourceReservationErrorV1> {
        self.entry.scope_identity_v1()
    }
    pub(crate) fn plan_v1(&self)->Result<&Arc<crate::OperationPlan>,ResourceReservationErrorV1> {
        self.entry.body.plan_v1()
    }
    pub(crate) fn require_predecessor_v1(&self,q04:&Q04CutIdentityV1)->Result<(),ResourceReservationErrorV1> {
        self.entry.body.require_predecessor_v1(q04)
    }
}

impl AcceptedStartEntryOriginalV1 {
    pub(crate) fn scope_identity_v1(&self)->Result<&Arc<()>,ResourceReservationErrorV1> {
        self.identity.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)
    }
    pub(crate) fn prepare_actual_plan_once_v1(&mut self, controller:&mut Journal,
        compiler:&mut crate::production_operation_compiler::ProductionOperationCompilerV1,peer:&PublicApiPeer,
        capability:aos_sandbox_core::CapabilityId,handle:&[u8],encoded:&[u8],digest:[u8;32],
    )->Result<(),ResourceReservationErrorV1> {
        self.history.require_before_authorization_v1()?;
        controller.require_start_admission_entry_v1(self)?;
        self.body.prepare_once_v1(controller,compiler,peer,capability,handle,encoded,digest,
            &mut self.authorization_native,&mut self.first_clock)
    }
    pub(crate) fn actual_plan_v1(&self)->Result<AcceptedStartPlanOriginalV1<'_>,ResourceReservationErrorV1> {
        self.body.plan_v1()?;
        Ok(AcceptedStartPlanOriginalV1{entry:self})
    }
    pub(crate) fn mark_admission_invoked_v1(&mut self) {
        self.body.mark_admission_invoked_v1();
    }

    pub(crate) fn admission_was_invoked_v1(&self)->bool {
        self.body.admission_was_invoked_v1()
    }

    pub(crate) fn retain_acceptance_v1(&mut self,result:Result<crate::AcceptOutcome,crate::ControllerServiceError>) {
        self.entry_failure_selected=self.failure().is_some() && self.body.failure_with_original_v1(self).is_none();
        self.body.retain_acceptance_v1(result);
    }
    pub(crate) fn accepted_outcome_v1(&self)->Result<crate::AcceptOutcome,crate::ControllerServiceError> {
        self.body.accepted_outcome_v1()
    }
    /// Finishes all reached native and temporal posts before admission is exposed.
    ///
    /// # Errors
    /// Refuses any original body/post failure and fences this same C writer if
    /// durable acceptance was reached before a late ambiguous disposition.
    #[doc(hidden)]
    pub fn finish_after_authorization_once_v1(&mut self,controller:&mut Journal,
        source:&mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    )->Result<(),ResourceReservationErrorV1> {
        let earlier=self.failure().is_some();
        let after=self.finish_native_once_v1(controller);
        self.native_after_selected=!earlier && after.is_err();
        self.body.observe_after_once_v1(&mut self.after_clock);
        if after.is_ok() {
            if let Some(state)=self.native_state.as_ref() {
                let _=self.history.dispose_after_controller_once_v1(state,controller,source);
            }
        }
        if self.failure().is_some() {
            if self.body.admission_was_invoked_v1() {
                self.body.fence=Some(match self.journal_identity.as_ref().and_then(|value|value.as_ref().ok()) {
                    Some(identity)=>controller.fence_start_admission_v1(identity),
                    None=>Err(crate::JournalError::ProtectedBoundary),
                });
            }
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Persists the actual first native Start origin in its sole Source Intent.
    ///
    /// This selects one fresh native turn and the canonical Source admission
    /// planner. Every reached Source, C and paired-clock post runs before the
    /// whole owning stage is restored; a failure admits no Host Root purpose.
    ///
    /// # Errors
    /// Retains changed actual owner, expired original bounds, native/model/
    /// funding/Source CAS or independent post/disposition failures.
    #[doc(hidden)]
    pub fn admit_start_source_origin_once_v1(&mut self,controller:&mut Journal,
        source:&mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    )->Result<(),ResourceReservationErrorV1> {
        if self.failure().is_some() {return Err(ResourceReservationErrorV1::Conflict);}
        let plan=Arc::clone(self.body.plan_v1()?);
        let origin=self.body.origin_v1()?;
        let state=self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut stage=std::mem::replace(&mut *self.source_origin,source_origin::StartSourceOriginOriginalV1::new());
        let returned=stage.admit_once_v1(state,&plan,origin,controller,source);
        *self.source_origin=stage;
        if returned.is_err() {
            self.source_origin.retain_fence_v1(match self.journal_identity.as_ref().and_then(|value|value.as_ref().ok()) {
                Some(identity)=>controller.fence_start_admission_v1(identity),
                None=>Err(crate::JournalError::ProtectedBoundary),
            });
        }
        returned
    }

    /// Reports only completion of the genuine Source first-origin disposition.
    #[doc(hidden)]
    #[must_use]
    pub fn start_source_origin_completed_v1(&self)->bool {self.source_origin.completed_v1()}
}

impl AcceptedStartEntryOriginalV1 {
    /// Selects only this actual accepted Start for its installed continuation.
    #[doc(hidden)]
    pub fn belongs_to_start_operation_v1(&self,operation:OperationId)->bool {
        self.body.plan_v1().is_ok_and(|plan|plan.operation_id()==operation)
    }

    /// Reports the actual all-posts-verified fresh ownership lease stage.
    #[doc(hidden)]
    pub fn start_ownership_completed_v1(&self)->bool {self.start_ownership.completed_v1()}

    /// Advances actual Start ownership using its own next paid native interval.
    ///
    /// The existing sole Ownership transport and verifier perform Query/Begin/
    /// Complete with an exact prior lease fence. Every reached C post runs even
    /// after a credential, claim, transport, signature or accounting refusal.
    ///
    /// # Errors
    /// Retains a changed original, deadline/refused advance or native failure.
    /// An uncertain authority response remains owned and may only query the
    /// same immutable advance claim in a later genuine native turn.
    #[doc(hidden)]
    pub fn progress_start_ownership_once_v1(&mut self,
        intake:&crate::CreateContinuationIntakeAttemptV1,controller:&mut Journal,
        source:&mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        ready: &[u8],
        preparation: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    )->Result<crate::CreateStorageOwnershipProgressV1,ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.source_origin.completed_v1() || self.start_ownership.completed_v1() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if !self.assignment_inputs.completed_v2() {
            self.prepare_start_assignment_inputs_once_v2(intake, controller, source, ready, preparation)?;
        }
        if !self.start_assignment.completed_v2() {
            let plan = self.body.plan_v1()?;
            let origin = self.body.origin_v1()?;
            let state = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
            let completed = intake.borrow_completed_provisioning_v1(state.create_parent)?;
            self.start_assignment.prepare_once_v2(state, plan, origin, &completed,
                &self.assignment_inputs.client, controller, source)?;
        }
        if self.ownership_base.is_none() {
            self.ownership_base=Some(self.native_state.as_ref().and_then(|state|state.history_resident)
                .ok_or(ResourceReservationErrorV1::Conflict));
        }
        let mut entered=false;
        self.ownership_next=Some((|| {
            let base=*self.ownership_base.as_ref().and_then(|value|value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let demand=base.checked_add(self.start_ownership.resident_demand_v1()?)?;
            let state=self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
            let returned=state.begin_next_start_native_v1(controller,demand);
            entered=state.after.is_none();
            returned
        })());
        if entered {self.start_ownership.prepare_entered_native_turn_v1();}
        if !matches!(self.ownership_next,Some(Ok(()))) {
            self.ownership_native_selected=self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1).is_some();
        } else {
            // All other actual Entry fields stay in place. The local owner is
            // restored before post/error projection; no callback/await occurs.
            let mut ownership=std::mem::replace(&mut *self.start_ownership,StartOwnershipOriginalV1::new());
            self.ownership_body=Some(match self.borrow_start_turn_v1(intake,controller,source,false) {
                Ok(mut loan)=>ownership.progress_once_v1(&mut loan,controller),
                Err(cause)=>Err(cause),
            });
            *self.start_ownership=ownership;
            self.ownership_body_selected=self.ownership_body.as_ref().is_some_and(Result::is_err)
                && self.start_ownership.failure().is_none();
            self.ownership_native_selected=self.start_ownership.selected_original_v1()
                && self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1).is_some();
        }
        if entered {
            let returned=self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
                .finish_native_once_v1(controller);
            let after_failed=returned.is_err();
            let body_failed=self.start_ownership.failure().is_some() || self.ownership_body.as_ref().is_some_and(Result::is_err)
                || self.ownership_next.as_ref().is_some_and(Result::is_err);
            self.start_ownership.retain_native_after_v1(returned);
            if after_failed && !body_failed {self.ownership_native_selected=true;}
        }
        if self.failure().is_some() {return Err(ResourceReservationErrorV1::Conflict);}
        self.ownership_resident=Some((|| {
            let resident=self.start_ownership.resident_demand_v1()?;
            let base=*self.ownership_base.as_ref().and_then(|value|value.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            base.checked_add(resident).map_err(ResourceReservationErrorV1::from)
        })());
        let complete=*self.ownership_resident.as_ref().and_then(|value|value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?.history_resident=Some(complete);
        self.ownership_body.as_ref().and_then(|value|value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}



impl AcceptedStartEntryOriginalV1 {
    /// Returns the retained predecessor operation identity as comparison DATA.
    ///
    /// This passive getter performs no native observation or admission. The
    /// actual completed intake and driver repeat their original association
    /// checks before lending Ready and signed preparation bytes.
    #[doc(hidden)]
    pub fn historical_create_operation_data_v2(&self)
        -> Result<OperationId, ResourceReservationErrorV1>
    {
        self.native_state.as_ref().map(|state| state.create_parent)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}

pub use host_root::{OriginalStartAssignmentInputsLoanV2, StartAssignmentInputsCompletedTurnV2};
