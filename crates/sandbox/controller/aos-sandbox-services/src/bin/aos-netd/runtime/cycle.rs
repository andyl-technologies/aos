//! Runs one authenticated Network request and retains every entered original.
//!
//! The neutral same-F entrance is consumed by the SDK's actual authenticated
//! request. Domain work, response prepayment and worker effects share that
//! original interval; Session and F posts run after every entered body result.

use super::*;
use aos_sandbox_network::{
    NetworkServiceDestroyProgrammeOriginalV2, NetworkServicePrepareOriginalV4,
    NetworkServiceRequestMethodV5 as Method, NetworkServiceWorkersOriginalV2,
};
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

#[derive(Clone, Copy)]
enum First {
    Session,
    Request,
    Selection,
    Content,
    Sources,
    Programme,
    Prepay,
    Execute,
    Observation,
    Commit,
    Send,
    SessionAfter,
    Body,
    After,
    Panic,
}

pub(super) struct NetworkCycle {
    operation: FixedServiceOperationOriginalV4,
    body: NetworkRequestBody,
}

impl NetworkCycle {
    pub(super) fn new() -> Self {
        Self {
            operation: FixedServiceOperationOriginalV4::new(),
            body: NetworkRequestBody::new(),
        }
    }

    pub(super) fn serve_once(
        &mut self,
        service: &mut NetworkServiceOriginalV4,
        opening: &mut FixedServiceSessionOpenOriginalV4,
    ) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.body
                .serve_body_once(service, opening, &mut self.operation);
        }));
        if let Err(payload) = result {
            // A resumed panic reaches this process terminal boundary while
            // the actual negative graph remains borrowed and resident.
            self.body.terminal_unwind = Some(payload);
            self.body.fail_unwind();
        }
        // Only the whole positive graph reaches replacement. A refusing graph
        // stays resident until the actual process exit in fail().
        drop(std::mem::replace(self, Self::new()));
    }
}

struct NetworkRequestBody {
    request: FixedServiceRequestOriginalV4,
    response: FixedServiceResponseOriginalV4,
    inventory: NetworkServiceInventoryOriginalV4,
    preparation: NetworkServicePrepareOriginalV4,
    workers: NetworkServiceWorkersOriginalV2,
    destroy: NetworkServiceDestroyProgrammeOriginalV2,
    entry: Option<Result<(), NetworkServiceClosedV4>>,
    session: Option<Result<(), FixedServiceSessionClosedV4>>,
    received: Option<Result<(), FixedServiceRequestClosedV4>>,
    selected: Option<Result<Method, NetworkServiceClosedV4>>,
    content: Option<Result<(), FixedServiceRequestClosedV4>>,
    sources: Option<Result<(), NetworkServiceClosedV4>>,
    programme: Option<Result<(), NetworkServiceClosedV4>>,
    prepaid: Option<Result<(), FixedServiceResponseClosedV4>>,
    executed: Option<Result<(), NetworkServiceClosedV4>>,
    observed: Option<Result<(), NetworkServiceClosedV4>>,
    committed: Option<Result<(), FixedServiceResponseClosedV4>>,
    sent: Option<FixedServiceResponseProgressV4>,
    session_after: Option<Result<(), FixedServiceRequestClosedV4>>,
    body: Option<Result<(), Closed>>,
    after: Option<Result<(), Closed>>,
    domain_disposal: Option<Result<(), NetworkServiceClosedV4>>,
    sdk_disposal: Option<Result<(), FixedServiceRequestClosedV4>>,
    first: Option<First>,
    loan_selected: bool,
    unwinds: [Option<Box<dyn Any + Send>>; 3],
    terminal_unwind: Option<Box<dyn Any + Send>>,
    resumed: bool,
}

impl NetworkRequestBody {
    fn new() -> Self {
        Self {
            request: FixedServiceRequestOriginalV4::new(),
            response: FixedServiceResponseOriginalV4::new(),
            inventory: NetworkServiceInventoryOriginalV4::new(),
            preparation: NetworkServicePrepareOriginalV4::new(),
            workers: NetworkServiceWorkersOriginalV2::new(),
            destroy: NetworkServiceDestroyProgrammeOriginalV2::new(),
            entry: None,
            session: None,
            received: None,
            selected: None,
            content: None,
            sources: None,
            programme: None,
            prepaid: None,
            executed: None,
            observed: None,
            committed: None,
            sent: None,
            session_after: None,
            body: None,
            after: None,
            domain_disposal: None,
            sdk_disposal: None,
            first: None,
            loan_selected: false,
            unwinds: std::array::from_fn(|_| None),
            terminal_unwind: None,
            resumed: false,
        }
    }

    fn serve_body_once(
        &mut self,
        service: &mut NetworkServiceOriginalV4,
        opening: &mut FixedServiceSessionOpenOriginalV4,
        operation: &mut FixedServiceOperationOriginalV4,
    ) {
        let entered = service.begin_request_receiving_once_v5(operation, ResourceVector::ZERO);
        let (mut loan, mut callsite) = match entered {
            Ok(value) => {
                self.entry = Some(Ok(()));
                value
            }
            Err(cause) => {
                self.entry = Some(Err(cause));
                fail(
                    service
                        .operation_failure_v4(operation)
                        .or_else(|| {
                            self.entry
                                .as_ref()?
                                .as_ref()
                                .err()
                                .map(|cause| cause as &dyn Error)
                        })
                        .unwrap_or(&CLOSED),
                );
            }
        };
        let mut session_borrow = match opening.session_mut_v4() {
            Ok(session) => {
                self.session = Some(Ok(()));
                Some(session)
            }
            Err(cause) => {
                self.session = Some(Err(cause));
                self.first = Some(First::Session);
                None
            }
        };
        if let Some(session) = session_borrow.as_mut() {
            let body = catch_unwind(AssertUnwindSafe(|| {
                self.received = Some(
                    self.request
                        .receive_network_request_once_v5(session, &mut loan),
                );
                if !matches!(self.received, Some(Ok(()))) {
                    self.first = Some(First::Request);
                    self.loan_selected = self.request.original_failure_selected_v4();
                }
                if self.first.is_none() {
                    let result = self.run_domain_once(session, &mut loan, &mut callsite);
                    if let Err(first) = result {
                        self.first = Some(first);
                    }
                }
                if self.first.is_none() {
                    self.sent = Some(self.response.send_once_v4(session, &mut loan));
                    if self.sent != Some(FixedServiceResponseProgressV4::Sent) {
                        self.first = Some(First::Send);
                        self.loan_selected = self.response.original_failure_selected_v4();
                    }
                }
            }));
            if let Err(payload) = body {
                self.unwinds[0] = Some(payload);
                self.first.get_or_insert(First::Panic);
            }
            // These are distinct prepaid obligations. A body panic must not
            // skip Session posts, and a Session-post panic must not skip F.
            let after = catch_unwind(AssertUnwindSafe(|| {
                self.session_after = Some(self.request.finish_native_once_v4(session));
            }));
            if let Err(payload) = after {
                self.unwinds[1] = Some(payload);
                self.first.get_or_insert(First::Panic);
            }
            if !matches!(self.session_after, Some(Ok(()))) && self.first.is_none() {
                self.first = Some(First::SessionAfter);
            }
        }
        self.body = Some(loan.record_body_result_v4(if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed::default())
        }));
        if !matches!(self.body, Some(Ok(()))) && self.first.is_none() {
            self.first = Some(First::Body);
            self.loan_selected = true;
        }
        let after = catch_unwind(AssertUnwindSafe(|| {
            self.after = Some(loan.finish_native_once_v4());
        }));
        if let Err(payload) = after {
            self.unwinds[2] = Some(payload);
            self.first.get_or_insert(First::Panic);
        }
        if !matches!(self.after, Some(Ok(()))) && self.first.is_none() {
            self.first = Some(First::After);
            self.loan_selected = true;
        }
        if matches!(self.first, Some(First::Panic)) {
            // Resume only after the independent actual posts. The outer once
            // boundary catches this same payload without dropping the graph.
            if let Some(payload) = self.unwinds.iter_mut().find_map(Option::take) {
                self.resumed = true;
                resume_unwind(payload);
            }
            fail(&CLOSED);
        }
        if self.first.is_some() {
            if self.loan_selected {
                fail(loan.failure().unwrap_or(&CLOSED));
            }
            self.fail_selected();
        }
        let Some(session) = session_borrow.as_mut() else {
            fail(&CLOSED);
        };
        let Some(request) = self.request.completed_network_request_v5() else {
            fail(&CLOSED);
        };
        self.domain_disposal = Some(
            match self.selected.as_ref().and_then(|value| value.as_ref().ok()) {
                Some(Method::Inventory) => self
                    .inventory
                    .dispose_completed_inventory_once_v5(&loan, request),
                Some(Method::Prepare) => self.workers.dispose_completed_preparation_once_v5(
                    &loan,
                    request,
                    &mut self.preparation,
                ),
                Some(Method::Destroy) => self
                    .destroy
                    .dispose_completed_destroy_once_v2(&loan, request),
                None => Err(NetworkServiceClosedV4),
            },
        );
        if !matches!(self.domain_disposal, Some(Ok(()))) {
            fail(
                self.domain_disposal
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map_or(&CLOSED as &dyn Error, |cause| cause),
            );
        }
        self.sdk_disposal = Some(self.request.dispose_completed_network_once_v5(
            session,
            &mut loan,
            &mut self.response,
        ));
        if !matches!(self.sdk_disposal, Some(Ok(()))) {
            fail(&FixedServiceRequestClosedV4);
        }
        drop(session_borrow);
        drop(callsite);
        drop(loan);
    }

    fn run_domain_once(
        &mut self,
        session: &mut aos_sandbox_broker_session_security::FixedServiceSessionBorrowV4<'_>,
        loan: &mut aos_sandbox_broker::receiving::NetworkServiceReceivingLoanV4<'_>,
        callsite: &mut aos_sandbox_network::NetworkServiceDomainCallsiteV4<'_>,
    ) -> Result<(), First> {
        let request = self
            .request
            .borrow_authenticated_request_v4()
            .ok_or(First::Request)?;
        self.selected = Some(callsite.select_received_request_once_v5(request, loan));
        let Some(Ok(method)) = self.selected.as_ref() else {
            self.loan_selected = loan.failure().is_some();
            return Err(First::Selection);
        };
        match *method {
            Method::Inventory => {
                let observation =
                    match callsite.inventory_once_v4(request, loan, &mut self.inventory) {
                        Ok(value) => {
                            self.observed = Some(Ok(()));
                            value
                        }
                        Err(cause) => {
                            self.observed = Some(Err(cause));
                            self.loan_selected = self.inventory.original_failure_selected_v4();
                            return Err(First::Observation);
                        }
                    };
                self.committed = Some(self.response.commit_network_once_v4(
                    session,
                    loan,
                    &self.request,
                    &observation,
                ));
            }
            Method::Prepare => {
                self.content = Some(self.request.prepare_network_content_once_v2(loan));
                if !matches!(self.content, Some(Ok(()))) {
                    self.loan_selected = self.request.original_failure_selected_v4();
                    return Err(First::Content);
                }
                let request = self
                    .request
                    .borrow_authenticated_request_v4()
                    .ok_or(First::Request)?;
                let (manifest, specification) =
                    self.request.network_models_v2().ok_or(First::Content)?;
                self.sources = Some(callsite.prepare_sources_once_v4(
                    request,
                    manifest,
                    specification,
                    loan,
                    &mut self.preparation,
                ));
                if !matches!(self.sources, Some(Ok(()))) {
                    self.loan_selected = self.preparation.original_failure_selected_v4();
                    return Err(First::Sources);
                }
                self.programme = Some(callsite.prepare_worker_programme_once_v2(
                    request,
                    &self.preparation,
                    loan,
                    &mut self.workers,
                ));
                if !matches!(self.programme, Some(Ok(()))) {
                    self.loan_selected = self.workers.original_failure_selected_v2();
                    return Err(First::Programme);
                }
                let body = self
                    .workers
                    .prospective_preparation_response_data_v2()
                    .ok_or(First::Programme)?;
                self.prepaid = Some(self.response.prepay_network_response_once_v5(
                    session,
                    loan,
                    &self.request,
                    body,
                ));
                if !matches!(self.prepaid, Some(Ok(()))) {
                    self.loan_selected = self.response.original_failure_selected_v4();
                    return Err(First::Prepay);
                }
                // The factory checks the whole pair against this updated same
                // ledger immediately before P, including the real SDK debit.
                self.executed = Some(callsite.execute_prepared_workers_once_v2(
                    request,
                    &mut self.preparation,
                    loan,
                    &mut self.workers,
                ));
                if !matches!(self.executed, Some(Ok(()))) {
                    self.loan_selected = self.workers
                        .preparation_original_failure_selected_v5(&self.preparation);
                    return Err(First::Execute);
                }
                let observation = match self.workers.preparation_response_v2(request) {
                    Ok(value) => {
                        self.observed = Some(Ok(()));
                        value
                    }
                    Err(cause) => {
                        self.observed = Some(Err(cause));
                        return Err(First::Observation);
                    }
                };
                self.committed = Some(self.response.commit_network_once_v4(
                    session,
                    loan,
                    &self.request,
                    &observation,
                ));
            }
            Method::Destroy => {
                self.programme = Some(callsite.prepare_destroy_programme_once_v2(
                    request,
                    loan,
                    &mut self.destroy,
                ));
                if !matches!(self.programme, Some(Ok(()))) {
                    self.loan_selected = self.destroy.original_failure_selected_v2();
                    return Err(First::Programme);
                }
                let body = self
                    .destroy
                    .prospective_response_body_v2()
                    .map_err(|_| First::Programme)?;
                self.prepaid = Some(self.response.prepay_network_response_once_v5(
                    session,
                    loan,
                    &self.request,
                    body,
                ));
                if !matches!(self.prepaid, Some(Ok(()))) {
                    self.loan_selected = self.response.original_failure_selected_v4();
                    return Err(First::Prepay);
                }
                let observation = match callsite.execute_destroy_programme_once_v2(
                    request,
                    loan,
                    &mut self.destroy,
                ) {
                    Ok(value) => {
                        self.executed = Some(Ok(()));
                        value
                    }
                    Err(cause) => {
                        self.executed = Some(Err(cause));
                        self.loan_selected = self.destroy.original_failure_selected_v2();
                        return Err(First::Execute);
                    }
                };
                self.committed = Some(self.response.commit_network_once_v4(
                    session,
                    loan,
                    &self.request,
                    &observation,
                ));
            }
        }
        if !matches!(self.committed, Some(Ok(()))) {
            self.loan_selected = self.response.original_failure_selected_v4();
            return Err(First::Commit);
        }
        Ok(())
    }

    fn fail_selected(&self) -> ! {
        let method = self.selected.as_ref().and_then(|value| value.as_ref().ok());
        if matches!(
            self.first,
            Some(First::Programme | First::Execute | First::Observation)
        ) {
            if matches!(method, Some(Method::Prepare)) {
                if let Some(view) = self.workers.store_failure_view_v2() {
                    fail_display(&view);
                }
            } else if matches!(method, Some(Method::Inventory)) {
                if let Some(view) = self.inventory.fd_store_failure_view_v2() {
                    fail_display(&view);
                }
            } else if matches!(method, Some(Method::Destroy)) {
                if let Some(view) = self.destroy.store_failure_view_v2() {
                    fail_display(&view);
                }
            }
        }
        let cause: &(dyn Error + 'static) = match self.first {
            Some(First::Session) => self
                .session
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _),
            Some(First::Request | First::Content | First::SessionAfter) => self.request.failure(),
            Some(First::Sources) => self.preparation.failure(),
            Some(First::Execute) if matches!(method, Some(Method::Prepare)) =>
                self.workers.preparation_failure_v5(&self.preparation),
            Some(First::Programme | First::Execute | First::Observation) => match method {
                Some(Method::Inventory) => self.inventory.failure(),
                Some(Method::Prepare) => self.workers.failure(),
                Some(Method::Destroy) => self.destroy.failure(),
                None => None,
            },
            Some(First::Prepay | First::Commit | First::Send) => self
                .response
                .failure()
                .or_else(|| self.response.pending_native_cause_v4()),
            _ => None,
        }
        .unwrap_or(&CLOSED);
        fail(cause)
    }

    fn fail_unwind(&self) -> ! {
        if self.first.is_some() && !matches!(self.first, Some(First::Panic)) {
            self.fail_selected();
        }
        let payload = if self.resumed {
            self.terminal_unwind.as_deref()
        } else {
            self.unwinds
                .iter()
                .find_map(Option::as_deref)
                .or(self.terminal_unwind.as_deref())
        };
        let message = payload.and_then(|payload| {
            payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&'static str>().copied())
        });
        eprintln!(
            "aos-netd: original Network request panicked after owed posts: {}",
            message.unwrap_or("non-string panic payload retained")
        );
        // No failed or uncertain native owner is unwound or disposed here.
        std::process::exit(1)
    }
}
