//! Runs the finite Mount62/16 creation and later Reap62/16 service programme.
//!
//! Every native/model owner remains in this actual inline runtime, including
//! failure. Cold Session opening, requests and response sends use only the
//! shared protected Security engines and their genuine same-role F loans.

use std::error::Error;

use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4 as Closed, FixedServiceOperationOriginalV4,
    MountAttachmentAnchorReceivingLoanV4,
};
use aos_sandbox_broker_session_security::{
    FixedServiceRequestClosedV4,
    FixedServiceRequestOriginalV4, FixedServiceResponseClosedV4,
    FixedServiceResponseOriginalV4, FixedServiceResponseProgressV4,
    FixedServiceSessionClosedV4,
    FixedServiceSessionOpenOriginalV4,
};
use aos_sandbox_core::ResourceVector;
use aos_sandbox_mount::{
    MountAttachmentAnchorServiceOriginalV4,
    MountServiceDomainCallsiteV4, MountServiceEffectOriginalV4,
    MountServiceInventoryOriginalV4, MountServiceObservationV4, MountError,
};

const CLOSED: Closed = Closed;

#[derive(Clone, Copy)]
enum Kind {
    Attachment,
    Reap,
    Inventory,
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    Session,
    Request,
    Domain,
    Commit,
    Send,
    SessionAfter,
    Body,
    After,
}

struct Cycle {
    operation: FixedServiceOperationOriginalV4,
    request: FixedServiceRequestOriginalV4,
    response: FixedServiceResponseOriginalV4,
    entry: Option<Result<(), MountError>>,
    session: Option<Result<(), FixedServiceSessionClosedV4>>,
    received: Option<Result<(), FixedServiceRequestClosedV4>>,
    domain: Option<Result<(), MountError>>,
    committed: Option<Result<(), FixedServiceResponseClosedV4>>,
    sent: Option<FixedServiceResponseProgressV4>,
    session_after: Option<Result<(), FixedServiceRequestClosedV4>>,
    body: Option<Result<(), Closed>>,
    after: Option<Result<(), Closed>>,
    first: Option<First>,
    domain_disposal: Option<Result<(), MountError>>,
    sdk_disposal: Option<Result<(), FixedServiceRequestClosedV4>>,
}

impl Cycle {
    fn new() -> Self {
        Self {
            operation: FixedServiceOperationOriginalV4::new(),
            request: FixedServiceRequestOriginalV4::new(),
            response: FixedServiceResponseOriginalV4::new(),
            entry: None,
            session: None,
            received: None,
            domain: None,
            committed: None,
            sent: None,
            session_after: None,
            body: None,
            after: None,
            first: None, domain_disposal: None, sdk_disposal: None,
        }
    }
}

struct Runtime {
    service: Option<MountAttachmentAnchorServiceOriginalV4>,
    opening_operation: FixedServiceOperationOriginalV4,
    opening: FixedServiceSessionOpenOriginalV4,
    attachment: Cycle,
    attachment_domain: MountServiceEffectOriginalV4,
    inventory: Cycle,
    inventory_domain: MountServiceInventoryOriginalV4,
    reap: Cycle,
    reap_domain: MountServiceEffectOriginalV4,
    reap_inventory: Cycle,
    reap_inventory_domain: MountServiceInventoryOriginalV4,
    startup: Option<Result<(), MountError>>,
    opening_entry: Option<Result<(), MountError>>,
    opened: Option<Result<(), FixedServiceSessionClosedV4>>,
    transport: Option<Result<u64, FixedServiceSessionClosedV4>>,
    inventory_only: Option<Result<bool, FixedServiceSessionClosedV4>>,
}

impl Runtime {
    fn new() -> Self {
        let mut runtime = Self {
            service: None,
            opening_operation: FixedServiceOperationOriginalV4::new(),
            opening: FixedServiceSessionOpenOriginalV4::new(),
            attachment: Cycle::new(),
            attachment_domain: MountServiceEffectOriginalV4::new(),
            inventory: Cycle::new(),
            inventory_domain: MountServiceInventoryOriginalV4::new(),
            reap: Cycle::new(),
            reap_domain: MountServiceEffectOriginalV4::new_reap_v5(),
            reap_inventory: Cycle::new(),
            reap_inventory_domain: MountServiceInventoryOriginalV4::new(),
            startup: None,
            opening_entry: None,
            opened: None,
            transport: None,
            inventory_only: None,
        };
        // This is the actual enclosing header, including its reserved inline
        // service field and both complete finite request/response owners.
        runtime.service = Some(MountAttachmentAnchorServiceOriginalV4::new_with_runtime_header_v4(&runtime));
        runtime
    }

    fn open(&mut self) -> u64 {
        let Some(service) = self.service.as_mut() else {
            fail(&CLOSED);
        };
        self.startup = Some(service.capture_startup_once_v4());
        if !matches!(self.startup, Some(Ok(()))) {
            fail(service.failure().unwrap_or(&CLOSED));
        }
        // Common pays its actual native interval before returning the loan.
        // The SDK intrinsically adds its own fixed backing before first IO.
        let opening = service.borrow_session_opening_once_v4(
            &mut self.opening_operation, ResourceVector::ZERO,
        );
        let (mut loan, mut inputs) = match opening {
            Ok(value) => {
                self.opening_entry = Some(Ok(()));
                value
            }
            Err(error) => {
                self.opening_entry = Some(Err(error));
                fail(service.operation_failure_v4(&self.opening_operation)
                    .or_else(|| self.opening_entry.as_ref().and_then(|v| v.as_ref().err()).map(|v| v as &dyn Error))
                    .unwrap_or(&CLOSED));
            }
        };
        let (journal, listener, credentials) = inputs.fixed_originals_v4();
        // The shared owner installs the fixed credentials, opens/replays the
        // SAME Journal, authenticates HELLO and always finishes this F interval.
        self.opened = Some(self.opening.open_mount_once_v4(
            &mut loan, journal, listener, credentials,
        ));
        // These are short views only. The actual Journal/listener/native
        // owners remain in this service and the cold owner after all posts.
        drop(inputs);
        drop(loan);
        if !matches!(self.opened, Some(Ok(()))) {
            if self.opening.captured_journal_failure_selected_v4() {
                fail(service.captured_session_failure_v4().unwrap_or(&CLOSED));
            }
            if self.opening.original_failure_selected_v4() {
                fail(service.operation_failure_v4(&self.opening_operation).unwrap_or(&CLOSED));
            }
            fail(self.opening.failure().unwrap_or(&CLOSED));
        }
        self.transport = Some(self.opening.original_transport_deadline_data_v4());
        self.inventory_only = Some(self.opening.inventory_only_profile_data_v2());
        match self.transport.as_ref() {
            Some(Ok(deadline)) => *deadline,
            Some(Err(error)) => fail(error),
            None => fail(&CLOSED),
        }
    }
}

enum Domain<'held> {
    Attachment(&'held mut MountServiceEffectOriginalV4),
    Inventory(&'held mut MountServiceInventoryOriginalV4),
}

impl Domain<'_> {
    fn retire_completed_physical_once_v5(&mut self,
        loan: &MountAttachmentAnchorReceivingLoanV4<'_>,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), MountError> {
        match self {
            Self::Attachment(original) => original.retire_completed_physical_once_v5(loan, request),
            Self::Inventory(_) => Err(MountError::Fence("inventory is not a Mount62 physical original")),
        }
    }

    fn execute<'original>(
        &'original mut self,
        callsite: &mut MountServiceDomainCallsiteV4<'_>,
        loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        request: &FixedServiceRequestOriginalV4,
    ) -> Result<MountServiceObservationV4<'original>, MountError> {
        let authenticated = request.borrow_authenticated_request_v4()
            .ok_or(MountError::Fence("the actual fresh Mount request is absent"))?;
        match self {
            Self::Attachment(original) => callsite.apply_attachment_once_v4(authenticated, loan, original),
            Self::Inventory(original) => callsite.inventory_once_v4(authenticated, loan, original),
        }
    }

    fn dispose_completed_inventory_once_v5(&mut self,
        loan: &MountAttachmentAnchorReceivingLoanV4<'_>,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), MountError> {
        match self {
            Self::Inventory(original) => original.dispose_completed_inventory_once_v5(loan, request),
            Self::Attachment(_) => Err(MountError::Fence("attachment is not a maintenance inventory")),
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Attachment(value) => value.failure(),
            Self::Inventory(value) => value.failure(),
        }
    }

    fn original_failure_selected(&self) -> bool {
        match self {
            Self::Attachment(value) => value.original_failure_selected_v4(),
            Self::Inventory(value) => value.original_failure_selected_v4(),
        }
    }
}

fn serve_cycle(
    service: &mut MountAttachmentAnchorServiceOriginalV4,
    opening: &mut FixedServiceSessionOpenOriginalV4,
    cycle: &mut Cycle,
    mut domain_original: Domain<'_>,
    kind: Kind,
    deadline: u64, maintenance: bool,
) {
    let Cycle {
        operation, request, response, entry, session, received, domain,
        committed, sent, session_after, body, after, first, domain_disposal, sdk_disposal,
    } = cycle;
    // Each SDK entry intrinsically joins its actual fixed/dynamic/native
    // backing before growth. Its own amount is not charged a second time by
    // this caller; Common's interval and callsite header remain mandatory.
    let entered = match kind {
        Kind::Attachment | Kind::Reap => service.begin_attachment_anchor_once_v4(operation, ResourceVector::ZERO),
        Kind::Inventory => service.begin_attachment_inventory_once_v4(operation, ResourceVector::ZERO),
    };
    let (mut loan, mut callsite) = match entered {
        Ok(value) => {
            *entry = Some(Ok(()));
            value
        }
        Err(error) => {
            *first = Some(First::Entry);
            *entry = Some(Err(error));
            fail(service.operation_failure_v4(operation)
                .or_else(|| entry.as_ref().and_then(|v| v.as_ref().err()).map(|v| v as &dyn Error))
                .unwrap_or(&CLOSED));
        }
    };
    let mut session_borrow = match opening.session_mut_v4() {
        Ok(value) => {
            *session = Some(Ok(()));
            Some(value)
        }
        Err(error) => {
            *session = Some(Err(error));
            *first = Some(First::Session);
            None
        }
    };
    if let Some(session_borrow) = session_borrow.as_mut() {
        *received = Some(match kind {
            Kind::Attachment => request.receive_mount_attachment_once_v4(session_borrow, &mut loan, deadline),
            Kind::Reap => request.receive_mount_reap_once_v5(session_borrow, &mut loan),
            Kind::Inventory if maintenance => request.receive_mount_maintenance_inventory_once_v5(session_borrow, &mut loan),
            Kind::Inventory => request.receive_mount_inventory_once_v4(session_borrow, &mut loan, deadline),
        });
        if !matches!(received, Some(Ok(()))) {
            *first = Some(First::Request);
        }
        if first.is_none() {
            match domain_original.execute(&mut callsite, &mut loan, request) {
                Ok(observation) => {
                    *domain = Some(Ok(()));
                    *committed = Some(response.commit_mount_once_v4(session_borrow, &mut loan, request, &observation));
                    if !matches!(committed, Some(Ok(()))) {
                        *first = Some(First::Commit);
                    }
                }
                Err(error) => {
                    *domain = Some(Err(error));
                    *first = Some(First::Domain);
                }
            }
        }
        if first.is_none() {
            *sent = Some(response.send_once_v4(session_borrow, &mut loan));
            if *sent != Some(FixedServiceResponseProgressV4::Sent) {
                *first = Some(First::Send);
            }
        }
        // No prior packet, domain, financial, clock or send refusal suppresses
        // the already-entered same-Session endpoint/floor/peer after interval.
        *session_after = Some(request.finish_native_once_v4(session_borrow));
        if !matches!(session_after, Some(Ok(()))) {
            first.get_or_insert(First::SessionAfter);
        }
    }

    *body = Some(loan.record_body_result_v4(if first.is_none() {
        Ok(())
    } else {
        Err(Closed::default())
    }));
    if !matches!(body, Some(Ok(()))) {
        first.get_or_insert(First::Body);
    }
    *after = Some(loan.finish_native_once_v4());
    if !matches!(after, Some(Ok(()))) {
        first.get_or_insert(First::After);
    }
    if let Some(cause) = *first {
        let loan_selected = match cause {
            First::Request => request.original_failure_selected_v4(),
            First::Domain => domain_original.original_failure_selected(),
            First::Commit | First::Send => response.original_failure_selected_v4(),
            First::Body | First::After => true,
            _ => false,
        };
        if loan_selected {
            fail(loan.failure().unwrap_or(&CLOSED));
        }
        let error: &(dyn Error + 'static) = match cause {
            First::Request => request.failure().unwrap_or(&CLOSED),
            First::Domain => domain_original.failure()
                .or_else(|| domain.as_ref().and_then(|v| v.as_ref().err()).map(|v| v as _))
                .unwrap_or(&CLOSED),
            First::Commit => response.failure().unwrap_or(&CLOSED),
            First::Send => response.failure().or_else(|| response.pending_native_cause_v4())
                .unwrap_or(&CLOSED),
            First::SessionAfter => request.failure().unwrap_or(&CLOSED),
            First::Session => session.as_ref().and_then(|v| v.as_ref().err()).map_or(&CLOSED as &dyn Error, |v| v),
            _ => &CLOSED,
        };
        fail(error);
    }
    if matches!(kind, Kind::Attachment | Kind::Reap) {
        // A prior successful creation must not leave its exclusive physical
        // scratch as an owning export that blocks this SAME Store's later
        // Reap. Retain its header/receipt and all charged Source obligations.
        *domain_disposal = Some(match request.completed_mount_attachment_request_v5() {
            Some(request) => domain_original.retire_completed_physical_once_v5(&loan, request),
            None => Err(MountError::Fence("the completed Mount62 request is absent")),
        });
        if !matches!(domain_disposal, Some(Ok(()))) {
            fail(domain_disposal.as_ref().and_then(|result| result.as_ref().err())
                .map_or(&CLOSED as &dyn Error, |cause| cause));
        }
    }
    if maintenance {
        let Some(session) = session_borrow.as_mut() else { fail(&CLOSED); };
        *domain_disposal = Some(match request.completed_inventory_request_v5() {
            Some(request) => domain_original.dispose_completed_inventory_once_v5(&loan, request),
            None => Err(MountError::Fence("the completed Mount inventory request is absent")),
        });
        if !matches!(domain_disposal, Some(Ok(()))) {
            fail(domain_disposal.as_ref().and_then(|result| result.as_ref().err())
                .map_or(&CLOSED as &dyn Error, |cause| cause));
        }
        *sdk_disposal = Some(request.dispose_completed_inventory_once_v5(session, &mut loan, response));
        if !matches!(sdk_disposal, Some(Ok(()))) {
            fail(sdk_disposal.as_ref().and_then(|result| result.as_ref().err())
                .map_or(&CLOSED as &dyn Error, |cause| cause));
        }
    }
}

pub(super) fn run() -> ! {
    let mut runtime = Runtime::new();
    let deadline = runtime.open();
    let inventory_only = match runtime.inventory_only.as_ref() {
        Some(Ok(selected)) => *selected,
        Some(Err(cause)) => fail(cause),
        None => fail(&CLOSED),
    };
    let Some(service) = runtime.service.as_mut() else {
        fail(&CLOSED);
    };
    if !inventory_only {
        serve_cycle(
            service, &mut runtime.opening, &mut runtime.attachment,
            Domain::Attachment(&mut runtime.attachment_domain), Kind::Attachment, deadline, false,
        );
    }
    if inventory_only {
        loop {
            serve_cycle(
                service, &mut runtime.opening, &mut runtime.inventory,
                Domain::Inventory(&mut runtime.inventory_domain), Kind::Inventory, deadline, true,
            );
            // Native SDK/domain originals are already positively disposed.
            // Preserve the same Session, journal history and cumulative F.
            drop(std::mem::replace(&mut runtime.inventory, Cycle::new()));
        }
    }
    serve_cycle(
        service, &mut runtime.opening, &mut runtime.inventory,
        Domain::Inventory(&mut runtime.inventory_domain), Kind::Inventory, deadline, true,
    );
    // This is one finite later cleanup request, not a new generic broker loop.
    // The same authenticated Session and complete cumulative Source remain;
    // only the actual newly signed Reap D opens its positive effect interval.
    serve_cycle(
        service, &mut runtime.opening, &mut runtime.reap,
        Domain::Attachment(&mut runtime.reap_domain), Kind::Reap, deadline, false,
    );
    serve_cycle(
        service, &mut runtime.opening, &mut runtime.reap_inventory,
        Domain::Inventory(&mut runtime.reap_inventory_domain), Kind::Inventory, deadline, true,
    );

    // The finite selected service enters no further request or mutation. Its
    // journals, physical pins and every charged original remain co-live.
    loop {
        std::thread::park();
    }
}

fn fail(error: &dyn Error) -> ! {
    eprintln!("aos-sandbox-mountd: selected attachment service failed: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("caused by: {cause}");
        source = cause.source();
    }
    // No owning Rust fields are dropped between the original failure and the
    // process's terminal boundary; earlier durable ambiguity stays fenced.
    std::process::exit(1);
}
