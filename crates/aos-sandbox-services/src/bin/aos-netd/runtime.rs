//! Owns the image-enrolled Network daemon and its finite authenticated cycle.
//!
//! Startup, cold Session, request and response reuse their actual shared F/SDK
//! engines. Every entered owner remains resident through its independently
//! owed Session and F posts. The genuine SDK request consumes neutral receiving
//! into Inventory19, Prepare63 or Destroy9 without replacing its interval.

use std::error::Error;
use std::fmt::Display;

use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4 as Closed, FixedServiceOperationOriginalV4,
};
use aos_sandbox_broker_session_security::{
    FixedServiceRequestClosedV4, FixedServiceRequestOriginalV4,
    FixedServiceResponseClosedV4, FixedServiceResponseOriginalV4,
    FixedServiceResponseProgressV4, FixedServiceSessionClosedV4,
    FixedServiceSessionOpenOriginalV4,
};
use aos_sandbox_core::ResourceVector;
use aos_sandbox_network::{
    NetworkServiceClosedV4, NetworkServiceInventoryOriginalV4, NetworkServiceOriginalV4,
};

const CLOSED: Closed = Closed;

#[path = "runtime/cycle.rs"]
mod cycle;
use cycle::NetworkCycle;

pub(super) struct NetworkDaemonOriginalV4 {
    service: Option<NetworkServiceOriginalV4>,
    opening_operation: FixedServiceOperationOriginalV4,
    opening: FixedServiceSessionOpenOriginalV4,
    cycle: NetworkCycle,
    startup: Option<Result<(), NetworkServiceClosedV4>>,
    opening_entry: Option<Result<(), NetworkServiceClosedV4>>,
    opened: Option<Result<(), FixedServiceSessionClosedV4>>,
    transport: Option<Result<u64, FixedServiceSessionClosedV4>>,
    profile: Option<Result<(), FixedServiceSessionClosedV4>>,
}

impl NetworkDaemonOriginalV4 {
    fn new() -> Self {
        let mut daemon = Self {
            service: None,
            opening_operation: FixedServiceOperationOriginalV4::new(),
            opening: FixedServiceSessionOpenOriginalV4::new(),
            cycle: NetworkCycle::new(),
            startup: None,
            opening_entry: None,
            opened: None,
            transport: None,
            profile: None,
        };
        // This is the actual complete runtime layout, including every SDK,
        // native census, failed-prefix and response destination kept below.
        daemon.service = Some(NetworkServiceOriginalV4::new_with_runtime_header_v4(&daemon));
        daemon
    }

    fn open_once(&mut self, capacity: usize) -> u64 {
        let Some(service) = self.service.as_mut() else {
            fail(&CLOSED);
        };
        self.startup = Some(service.capture_startup_once_v4(capacity));
        if !matches!(self.startup, Some(Ok(()))) {
            if let Some(view) = service.failure_view_v4() {
                fail_display(&view);
            }
            fail(&CLOSED);
        }
        let entered = service.borrow_session_opening_once_v4(
            &mut self.opening_operation, ResourceVector::ZERO,
        );
        let (mut loan, mut inputs) = match entered {
            Ok(value) => {
                self.opening_entry = Some(Ok(()));
                value
            }
            Err(cause) => {
                self.opening_entry = Some(Err(cause));
                fail(service.operation_failure_v4(&self.opening_operation)
                    .or_else(|| self.opening_entry.as_ref()?.as_ref().err().map(|cause| cause as &dyn Error))
                    .unwrap_or(&CLOSED));
            }
        };
        let (journal, listener, credentials) = inputs.fixed_originals_v4();
        // The actual shared cold owner records its body and finishes its own F
        // interval on every entered exit. These short views owe no second post.
        self.opened = Some(self.opening.open_network_once_v4(
            &mut loan, journal, listener, credentials,
        ));
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
        self.profile = Some(self.opening.require_network_service_profile_v5());
        match self.transport.as_ref() {
            Some(Ok(cutoff)) => *cutoff,
            Some(Err(cause)) => fail(cause),
            None => fail(&CLOSED),
        }
    }
}

pub(super) fn run(capacity: usize) -> ! {
    let mut daemon = NetworkDaemonOriginalV4::new();
    let _opening_cutoff = daemon.open_once(capacity);
    match daemon.profile.as_ref() {
        Some(Ok(())) => {}
        Some(Err(cause)) => fail(cause),
        None => fail(&CLOSED),
    }
    let Some(service) = daemon.service.as_mut() else {
        fail(&CLOSED);
    };
    loop {
        // Each request gets a fresh once-owned ordinal and actual signed D.
        // Common's cumulative F accounting bounds the finite continuation;
        // no prior capacity, history, method or clock is reset.
        daemon.cycle.serve_once(service, &mut daemon.opening);
    }
}

fn fail_display(cause: &dyn Display) -> ! {
    eprintln!("aos-netd: selected Network service failed: {cause}");
    std::process::exit(1);
}

fn fail(cause: &dyn Error) -> ! {
    eprintln!("aos-netd: selected Network service failed: {cause}");
    let mut source = cause.source();
    while let Some(cause) = source {
        eprintln!("caused by: {cause}");
        source = cause.source();
    }
    // No failed native, journal, SDK or financial owner is dropped before the
    // actual process terminal boundary. An uncertain prefix stays fenced.
    std::process::exit(1);
}
