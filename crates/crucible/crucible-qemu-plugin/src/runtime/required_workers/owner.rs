//! Retains born role outputs and independent physical return histories in Runtime.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::runtime::native_worker::owner::OwnerField;
use module::{ConstructorInput, HandoffInput};
use std::mem::size_of;

struct Owner {
    kind: Kind,
    field: OwnerField<abi::Worker>,
    id: u64,
    api: Option<abi::Api>,
    attempted: bool,
    control_address: usize,
    returned: bool,
    history: History,
}

impl Owner {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            field: OwnerField::new(),
            id: 0,
            api: None,
            attempted: false,
            control_address: 0,
            returned: false,
            history: History::default(),
        }
    }

    fn handle(&self) -> Result<Handle, Error> {
        Ok(Handle {
            id: self.id,
            worker: self.field.projection() as usize,
            api: self.api.ok_or(Error::Native {
                operation: "missing SDK",
                status: -libc::ENOSYS,
            })?,
            kind: self.kind,
        })
    }

    fn observe(&mut self) -> Result<abi::Status, Error> {
        let handle = self.handle()?;
        let mut journal = abi::Status {
            schema_version: 1,
            struct_size: size_of::<abi::Status>() as u32,
            ..abi::Status::default()
        };
        let status = (handle.api.observe)(handle.id, handle.pointer(), &mut journal);
        self.history.observation = Some(status);
        self.history.snapshot = Some(journal);
        native_status("observe", status)?;
        validate(&journal)?;
        Ok(journal)
    }

    fn create(
        &mut self,
        material: abi::Material,
        child: *mut c_void,
        body: *mut Option<Body>,
        workers: Arc<LiveWorkerQuiescence>,
        router: Arc<LiveRuntimeTeardownRouter>,
        interrupt: RuntimeInterrupt,
    ) -> Result<(), Error> {
        if self.attempted {
            return native_status("duplicate creation", -libc::EALREADY);
        }
        let api = abi::Api::resolve().map_err(|status| Error::Native {
            operation: "SDK resolution",
            status,
        })?;
        self.id = material.id;
        self.api = Some(api);
        self.attempted = true;
        let mut input = ConstructorInput {
            native: Handle {
                id: material.id,
                worker: 0,
                api,
                kind: self.kind,
            },
            projection: self.field.creation_projection_address(),
            body,
            workers: Some(workers),
            router: Some(router),
            interrupt,
            control_address: &mut self.control_address,
            panic_payload: &mut self.history.constructor_panic,
        };
        let raw = std::ptr::from_mut(&mut input).cast();
        let status = match self.kind {
            Kind::Run => (api.create_run)(
                material.id,
                material.runtime,
                material.run,
                child,
                raw,
                self.field.creation_address(),
            ),
            Kind::Teardown => (api.create_teardown)(
                material.id,
                material.runtime,
                material.teardown,
                child,
                raw,
                self.field.creation_address(),
            ),
        };
        self.history.creation = Some(status);
        self.field.record_birth();
        native_status("creation", status)?;
        if self.field.projection().is_null() || self.control_address == 0 {
            return native_status("creation outputs", -libc::EPROTO);
        }
        let status = self
            .field
            .transfer(|creation, canonical| (api.transfer)(material.id, creation, canonical));
        self.history.transfer = Some(status);
        native_status("transfer", status)?;
        if !self.field.creation_consumed() {
            return native_status("transfer disposition", -libc::EPROTO);
        }
        Ok(())
    }

    /// Keeps health reports separate while attempting actual close and join.
    fn identity_return(&mut self, unused_returned: bool) -> Result<(), Error> {
        if self.returned {
            return self.history.health();
        }
        if self.field.projection().is_null() {
            if unused_returned {
                return Ok(());
            }
            return native_status("unreturned planned role", -libc::EBUSY);
        }
        let handle = self.handle()?;
        let close = (handle.api.close)(handle.id, handle.pointer());
        self.history.close = Some(close);
        let mut first = (close != 0).then_some(Error::Native {
            operation: "close",
            status: close,
        });
        let before = self.observe();
        if let Ok(journal) = before {
            if journal.initialized == 1 && journal.destroyed == 0 {
                let report = handle.with_control(true, |control| {
                    let mut state = control.lock();
                    if let Some(status) = state.native[NativeCut::Ready as usize] {
                        self.history.ready_status = Some(status);
                    }
                    match state.terminal_report(&mut self.history.module_health) {
                        TerminalReport::FirstFailure => {
                            drop(state);
                            Err(failed(control))
                        }
                        TerminalReport::ReportedFailure => Ok(true),
                        TerminalReport::Healthy => Ok(false),
                    }
                });
                if let Err(error) = report {
                    // This owning report must survive an independent native
                    // error; its actual Arc deliberately prevents early Drop.
                    first = Some(error);
                }
            }
        } else if first.is_none() {
            first = before.err();
        }
        // Even negative health/control observation cannot skip actual tryjoin.
        let joined = (handle.api.tryjoin)(handle.id, handle.pointer());
        self.history.join = Some(joined);
        let observed = self.observe();
        let journal = match observed {
            Ok(value) => value,
            Err(error) => return Err(first.unwrap_or(error)),
        };
        if journal.physical_returned == 1 && journal.control_lifetime_uncertain == 0 {
            let field = self.field.return_address();
            let status = (handle.api.identity_return)(handle.id, field);
            self.history.identity_return = Some(status);
            if status == 0 {
                // SAFETY: the same exact field was lent synchronously to pure
                // by-reference return after genuine physical-return observation.
                if unsafe { (*field).is_null() } {
                    self.returned = true;
                    self.field.returned();
                } else if first.is_none() {
                    first = Some(Error::Native {
                        operation: "identity consumption",
                        status: -libc::EPROTO,
                    });
                }
            } else if first.is_none() {
                first = Some(Error::Native {
                    operation: "identity return",
                    status,
                });
            }
        }
        if let Some(error) = first {
            return Err(error);
        }
        native_status("tryjoin", joined)?;
        if !self.returned {
            return native_status("physical return", -libc::EBUSY);
        }
        self.history.health()
    }
}

/// Owns both distinct native identities and any unconsumed installer input.
pub(in crate::runtime) struct RequiredWorkers {
    run: Owner,
    teardown: Owner,
    pending_teardown: Option<Body>,
    stream: Option<ControlLifecycleStream<SetupControlSocket>>,
    owner_process: u32,
    material: Option<abi::Material>,
    readiness: Option<i32>,
    readiness_post: Option<crate::StartupSourceError>,
    unborn_return: Option<i32>,
}

impl RequiredWorkers {
    /// Prepares empty inline custody before the actual Runtime birth.
    pub(in crate::runtime) fn new() -> Self {
        Self {
            run: Owner::new(Kind::Run),
            teardown: Owner::new(Kind::Teardown),
            pending_teardown: None,
            stream: None,
            owner_process: std::process::id(),
            material: None,
            readiness: None,
            readiness_post: None,
            unborn_return: None,
        }
    }

    /// Retains the same consumer and validated mapping before either creator.
    pub(in crate::runtime) fn prepare(
        &mut self,
        consumer: teardown_latch::TeardownConsumer,
        handle: LiveControlTeardownHandle,
        request_shutdown: QemuRequestShutdownFn,
    ) {
        self.pending_teardown = Some(Body::Teardown(TeardownControl {
            consumer,
            handle,
            request_shutdown,
            selected: Mutex::new(None),
            completed: AtomicBool::new(false),
        }));
    }

    /// Enters both separately paid genuine constructors and retains all born outputs.
    ///
    /// # Errors
    /// Preserves the first creator/refusal with its independent installing post.
    pub(in crate::runtime) fn create(
        &mut self,
        setup: &PluginSetupCompletion,
        child: *mut c_void,
        workers: &Arc<LiveWorkerQuiescence>,
        router: &Arc<LiveRuntimeTeardownRouter>,
    ) -> Result<(), Error> {
        self.check_process()?;
        let material = setup
            .required_worker_material()
            .map_err(|source| Error::Original { source })?;
        self.material = Some(material);
        let interrupt = setup
            .runtime_interrupt_handle()
            .map_err(|source| Error::Original { source })?;
        for kind in [Kind::Run, Kind::Teardown] {
            setup
                .check_runtime_installation()
                .map_err(|source| Error::Original { source })?;
            let (owner, input) = match kind {
                Kind::Run => (&mut self.run, std::ptr::null_mut()),
                Kind::Teardown => (&mut self.teardown, &mut self.pending_teardown as *mut _),
            };
            let birth = owner.create(
                material,
                child,
                input,
                Arc::clone(workers),
                Arc::clone(router),
                interrupt,
            );
            let post = setup.check_runtime_installation();
            if let Err(source) = &post {
                owner.history.installation_post.get_or_insert(*source);
            }
            birth?;
            post.map_err(|source| Error::Original { source })?;
        }
        Ok(())
    }

    /// Observes Native's actual parked RUN and entered teardown before Ready.
    ///
    /// # Errors
    /// Refuses expired startup, failed births or missing Native readiness. Only
    /// EAGAIN continues under the same saved Original and its remaining slice.
    pub(in crate::runtime) fn wait_ready(
        &mut self,
        setup: &PluginSetupCompletion,
    ) -> Result<(), Error> {
        self.check_process()?;
        let material = self.material.ok_or(Error::Native {
            operation: "required pair",
            status: -libc::ENOKEY,
        })?;
        let api = self.run.handle()?.api;
        loop {
            let slice = setup
                .original_startup_slice()
                .map_err(|source| Error::Original { source })?;
            let status = (api.current)(material.id, material.runtime);
            self.readiness = Some(status);
            let post = setup.check_original_startup();
            if let Err(source) = &post {
                self.readiness_post.get_or_insert(*source);
            }
            if status != 0 && status != -libc::EAGAIN {
                native_status("required pair readiness", status)?;
            }
            post.map_err(|source| Error::Original { source })?;
            if status == 0 {
                return Ok(());
            }
            std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));
        }
    }

    /// Retains the actual sole RUN stream before entering the once-only handoff.
    ///
    /// # Errors
    /// Refuses duplicate movement, Native failure, a negative post or incomplete
    /// factual disposition. Any moved stream remains in the same real control.
    pub(in crate::runtime) fn handoff(
        &mut self,
        stream: &mut Option<ControlLifecycleStream<SetupControlSocket>>,
    ) -> Result<(), Error> {
        self.check_process()?;
        let handle = self.run.handle()?;
        if self.run.history.handoff.is_some() || self.stream.is_some() {
            return native_status("duplicate stream handoff", -libc::EALREADY);
        }
        self.stream = stream.take();
        let mut input = HandoffInput {
            stream: &mut self.stream,
            moved: false,
            committed_status: None,
        };
        let status = (handle.api.handoff)(
            handle.id,
            handle.pointer(),
            std::ptr::from_mut(&mut input).cast(),
        );
        self.run.history.handoff = Some(status);
        self.run.history.handoff_moved = input.moved;
        self.run.history.handoff_commit = input.committed_status;
        let observation = self.run.observe();
        native_status("stream handoff", status)?;
        let journal = observation?;
        if !input.moved
            || self.stream.is_some()
            || input.committed_status != Some(0)
            || journal.handoff_committed != 1
            || journal.handoff_released != 1
        {
            return native_status("stream handoff disposition", -libc::EPROTO);
        }
        Ok(())
    }

    /// Retains the independent post after the actual once-only handoff result.
    pub(in crate::runtime) fn record_handoff_post(
        &mut self,
        post: &Result<(), crate::StartupSourceError>,
    ) {
        if let Err(source) = post {
            self.run.history.handoff_post.get_or_insert(*source);
        }
    }

    /// Attempts both physical returns without allowing health to skip a sibling.
    ///
    /// # Errors
    /// Keeps failed health separate from physical identity consumption; busy or
    /// uncertain thread/control/stack custody remains retained for later cleanup.
    pub(in crate::runtime) fn identity_return(
        &mut self,
        setup: &mut PluginSetupCompletion,
    ) -> Result<(), CleanupError> {
        self.check_process()?;
        let unused = if self.run.field.projection().is_null()
            || self.teardown.field.projection().is_null()
        {
            let status = setup.return_unborn_required_workers();
            self.unborn_return = Some(status);
            status == 0
        } else {
            false
        };
        let run = self.run.identity_return(unused);
        let teardown = self.teardown.identity_return(unused);
        match (run, teardown) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(first), Ok(())) | (Ok(()), Err(first)) => Err(CleanupError {
                first,
                independent: None,
                unborn_status: self.unborn_return,
                receipts: [self.run.history.receipt(), self.teardown.history.receipt()],
                readiness: (self.readiness, self.readiness_post),
            }),
            (Err(first), Err(independent)) => Err(CleanupError {
                first,
                independent: Some(independent),
                unborn_status: self.unborn_return,
                receipts: [self.run.history.receipt(), self.teardown.history.receipt()],
                readiness: (self.readiness, self.readiness_post),
            }),
        }
    }

    /// Reports only genuine byref consumption or actual unused-claim return.
    pub(in crate::runtime) fn identities_returned(&self) -> bool {
        [&self.run, &self.teardown].into_iter().all(|owner| {
            owner.returned || (owner.field.projection().is_null() && self.unborn_return == Some(0))
        })
    }

    fn check_process(&self) -> Result<(), Error> {
        native_status(
            "creator process",
            if self.owner_process == std::process::id() {
                0
            } else {
                -libc::EPERM
            },
        )
    }
}

fn validate(journal: &abi::Status) -> Result<(), Error> {
    if journal.schema_version != 1 || journal.struct_size as usize != size_of::<abi::Status>() {
        return native_status("journal shape", -libc::EPROTO);
    }
    let flags = [
        journal.initialized,
        journal.ready,
        journal.closing,
        journal.entry_entered,
        journal.entry_returned,
        journal.joined,
        journal.destroyed,
        journal.physical_returned,
        journal.destruction_active,
        journal.destruction_returned,
        journal.destruction_uncertain,
        journal.control_lifetime_uncertain,
        journal.handoff_attempted,
        journal.handoff_committed,
        journal.handoff_returned,
        journal.handoff_released,
        journal.cancelled_before_handoff,
        journal.task_reserved,
        journal.born,
        journal.birth_attempted,
        journal.allocation_attempted,
        journal.allocation_returned,
        journal.construction_returned,
        journal.close_attempted,
        journal.close_returned,
        journal.destruction_begun,
        journal.pins_held,
        journal.stack_mapped,
        journal.stack_charge_held,
        journal.residual_charge_held,
    ];
    if flags.into_iter().any(|flag| flag > 1) {
        return native_status("journal flag", -libc::EPROTO);
    }
    if journal.physical_returned == 1
        && (journal.task_reserved != 0
            || journal.stack_mapped != 0
            || journal.stack_charge_held != 0
            || journal.control_lifetime_uncertain != 0
            || journal.destruction_uncertain != 0
            || (journal.born == 1 && (journal.entry_returned != 1 || journal.joined != 1)))
    {
        return native_status("physical journal disposition", -libc::EPROTO);
    }
    Ok(())
}
