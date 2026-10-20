//! Retains the exact protected authorization, compiler and accepted Start result.

use super::*;
use aos_sandbox_model::{CapabilityId,RawPairedClockSample};
use aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1;
use crate::public_mutation_compiler::{AuthorizedPublicMutationRequestV1,PublicMutationAuthorizationErrorV1};
use crate::{AcceptOutcome,ControllerServiceError,OperationCompilationError,OperationPlan};
use crate::production_operation_compiler::ProductionOperationCompilerV1;

#[derive(Clone,Copy)]
enum First { Handle,Authorization,Clock,Origin,Compilation,Acceptance,After,Reentry }

pub(super) struct StartAuthorizationOriginalV1 {
    input:Vec<u8>,
    handle:Option<Result<CapabilityId,ControllerServiceError>>,
    authorization:Option<Result<AuthorizedPublicMutationRequestV1,PublicMutationAuthorizationErrorV1>>,
    clock:Option<Result<RawPairedClockSample,SourceGenesisErrorV1>>,
    origin:Option<Result<StartNativeOriginDataV1,ResourceReservationErrorV1>>,
    plan:Option<Result<Arc<OperationPlan>,OperationCompilationError>>,
    accepted:Option<Result<AcceptOutcome,ControllerServiceError>>,
    after:Option<Result<RawPairedClockSample,SourceGenesisErrorV1>>,
    temporal:Option<Result<(),ResourceReservationErrorV1>>,
    pub(super) fence:Option<Result<(),crate::JournalError>>,
    first:Option<First>,
    entered:bool,
    admission_invoked:bool,
}

impl StartAuthorizationOriginalV1 {
    pub(super) fn new()->Self {Self {input:Vec::new(),handle:None,authorization:None,
        clock:None,origin:None,plan:None,accepted:None,after:None,temporal:None,fence:None,first:None,entered:false,admission_invoked:false}}

    pub(super) fn prepare_once_v1(&mut self,controller:&mut Journal,compiler:&mut ProductionOperationCompilerV1,
        peer:&PublicApiPeer,capability:CapabilityId,handle:&[u8],encoded:&[u8],digest:[u8;32],
        native:&mut PublicMutationAuthorizationNativeV1,clock:&mut PairOriginal,
    )->Result<(),ResourceReservationErrorV1> {
        if self.entered {self.first.get_or_insert(First::Reentry);return Err(CLOSED);}
        self.entered=true;
        // The genuine entry has paid full request/registry/peer/compiler growth.
        self.input.extend_from_slice(encoded);
        self.handle=Some(crate::controller::resolve_delete_capability_handle_retaining_v1(
            controller,peer,capability,handle,&mut native.handle_peers));
        if !matches!(self.handle,Some(Ok(_))) {self.first=Some(First::Handle);return Err(CLOSED);}
        self.authorization=Some(compiler.authorize_original_start_v1(controller,peer,capability,
            &self.input,native));
        if !matches!(self.authorization,Some(Ok(_))) {self.first=Some(First::Authorization);return Err(CLOSED);}
        self.clock=Some(clock.observe_once(None));
        if !matches!(self.clock,Some(Ok(_))) {self.first=Some(First::Clock);return Err(CLOSED);}
        let authorized=self.authorization.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
        self.plan=Some(compiler.compile_original_start_v1(controller,authorized,&self.input,digest).map(Arc::new));
        if !matches!(self.plan,Some(Ok(_))) {self.first=Some(First::Compilation);return Err(CLOSED);}
        self.origin=Some((|| {
            let accepted=self.plan.as_ref().and_then(|value|value.as_ref().ok())
                .and_then(|value|value.accepted_start_origin_data_v1()).ok_or(CLOSED)?;
            let sample=*self.clock.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
            let cutoff=accepted.cutoff_for_sample_data_v1(sample).ok_or(CLOSED)?;
            StartNativeOriginDataV1::from_data_v1(accepted,sample,cutoff).map_err(|_|CLOSED)
        })());
        if !matches!(self.origin,Some(Ok(_))) {self.first=Some(First::Origin);return Err(CLOSED);}
        Ok(())
    }

    pub(super) fn origin_v1(&self)->Result<aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1,ResourceReservationErrorV1> {
        if self.first.is_some() || !self.acceptance_reached_v1() || !matches!(self.temporal,Some(Ok(()))) {return Err(CLOSED);}
        self.origin.as_ref().and_then(|value|value.as_ref().ok()).copied().ok_or(CLOSED)
    }

    pub(super) fn plan_v1(&self)->Result<&Arc<OperationPlan>,ResourceReservationErrorV1> {
        if self.first.is_some() {return Err(CLOSED);}
        self.plan.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)
    }
    // The typed target borrow is comparison DATA from the already paid,
    // original authorized request; it cannot reauthorize or renew Start.
    pub(super) fn retained_authorized_request_v2(&self)
        -> Result<&AuthorizedPublicMutationRequestV1, ResourceReservationErrorV1> {
        if self.first.is_some() || !self.acceptance_reached_v1() {
            return Err(CLOSED);
        }
        self.authorization.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)
    }

    pub(super) fn require_predecessor_v1(&self,q04:&Q04CutIdentityV1)->Result<(),ResourceReservationErrorV1> {
        let authorized=self.authorization.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
        let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Start(request)=authorized.request().request()
        else {return Err(CLOSED);};
        if authorized.project()!=q04.project() || request.sandbox_id.as_slice()!=q04.sandbox().as_bytes() {
            return Err(CLOSED);
        }
        self.plan_v1()?;
        Ok(())
    }
    pub(super) fn mark_admission_invoked_v1(&mut self) {
        self.admission_invoked=true;
    }

    pub(super) fn admission_was_invoked_v1(&self)->bool {
        self.admission_invoked
    }

    pub(super) fn retain_acceptance_v1(&mut self,result:Result<AcceptOutcome,ControllerServiceError>) {
        if self.accepted.is_some() {self.first.get_or_insert(First::Reentry);return;}
        if result.is_err() {self.first.get_or_insert(First::Acceptance);}
        self.accepted=Some(result);
    }
    pub(super) fn acceptance_reached_v1(&self)->bool {matches!(self.accepted,Some(Ok(_)))}
    pub(super) fn accepted_outcome_v1(&self)->Result<AcceptOutcome,ControllerServiceError> {
        if self.first.is_some() || !matches!(self.temporal,Some(Ok(()))) {return Err(OperationCompilationError::Rejected.into());}
        match self.accepted.as_ref() {
            Some(Ok(AcceptOutcome::Accepted(operation)))=>Ok(AcceptOutcome::Accepted(*operation)),
            Some(Ok(AcceptOutcome::Replay(operation)))=>Ok(AcceptOutcome::Replay(*operation)),
            _=>Err(OperationCompilationError::Rejected.into()),
        }
    }
    pub(super) fn observe_after_once_v1(&mut self,clock:&mut PairOriginal) {
        if self.clock.is_none() {return;}
        if self.after.is_some() {self.first.get_or_insert(First::Reentry);return;}
        let original=self.clock.as_ref().and_then(|value|value.as_ref().ok()).copied();
        self.after=Some(clock.observe_once(original));
        self.temporal=Some((|| {
            let origin=*self.origin.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
            let sample=*self.after.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
            if sample.boottime_nanoseconds()>=origin.cutoff_v1()
                || origin.accepted_v1().cutoff_for_sample_data_v1(sample).is_none() {
                return Err(CLOSED);
            }
            Ok(())
        })());
        if !matches!(self.temporal,Some(Ok(()))) {self.first.get_or_insert(First::After);}
    }
    pub(super) fn failure_with_original_v1<'a>(&'a self,entry:&'a AcceptedStartEntryOriginalV1)
        ->Option<&'a(dyn Error+'static)> {
        match self.first? {
            First::Handle=>entry.authorization_native.failure()
                .or_else(||self.handle.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Authorization=>entry.authorization_native.failure()
                .or_else(||self.authorization.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Clock=>entry.first_clock.failure().or_else(||self.clock.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Origin=>self.origin.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Compilation=>self.plan.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Acceptance=>self.accepted.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::After=>entry.after_clock.failure().or_else(||self.after.as_ref()?.as_ref().err().map(|cause|cause as _))
                .or_else(||self.temporal.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Reentry=>Some(&CLOSED),
        }
    }
}
const CLOSED:ResourceReservationErrorV1=ResourceReservationErrorV1::Conflict;
