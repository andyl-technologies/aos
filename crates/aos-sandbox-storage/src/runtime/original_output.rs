//! Shares the exact original logical46/47 operation across closed receiving paths.
//!
//! Ordinary callers retain their existing native order. The lifecycle entrance
//! owns the same fixed F, request and Output writer, prepays complete models and
//! retained native clocks, and finishes every reached independent post.

use super::*;
use crate::execution_output_credential::logical_receiving::{OriginalOutputIntervalV1, LogicalOutputNativeOriginalV1};

impl StorageBrokerRuntime {
    /// Enters the same logical writer using the actual entered Storage F.
    ///
    /// The immutable request/Host owners stay with the caller. Every reached
    /// lower Result returns to that same attempt, including constructor debt
    /// and independently owed posts after a primary failure.
    pub(crate) fn register_original_execution_output_receiving_v1(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut crate::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        host: Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1>,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        if attempt.started { return; }
        attempt.started = true;
        let mut boundary = OriginalOutputRegistrationBoundaryV1 { attempt };
        let attempt = &mut *boundary.attempt;
        let demand = (|| {
            let state = self.coordinator.receiving_inventory_geometry_v1()?.retained_model_demand_v1()?;
            LogicalOutputNativeOriginalV1::receiving_demand_v1(state, output, &attempt.request, host)
        })();
        if attempt.lifecycle_entry.prepare(lifecycle, session, socket, demand) {
            attempt.lifecycle_native = Some(Box::new(LogicalOutputNativeOriginalV1::new()));
        }
        attempt.lifecycle_entry.finish(lifecycle, session, socket);
        if attempt.lifecycle_entry.failure().is_some() { return; }
        let Some(mut native) = attempt.lifecycle_native.take() else {
            attempt.first_cause = Some(crate::execution_output_credential::OriginalOutputRegistrationErrorV1::NotCurrent);
            return;
        };
        self.register_original_execution_output_inner(output, attempt, host,
            OriginalOutputIntervalV1::Lifecycle { lifecycle, session, socket, original: &mut native });
        native.finish_owed_v1(output, lifecycle, session, socket);
        attempt.lifecycle_native = Some(native);
        attempt.completed = attempt.completed && attempt.failure().is_none() && attempt.postcheck_debt().is_none();
    }

    /// Holds configured Storage admission around the original atomic output write.
    /// The pending Session owns `attempt`; no borrowed owner is stored in it.
    pub(crate) fn register_original_execution_output(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut crate::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        host_terminal: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) {
        if attempt.started {
            return;
        }
        attempt.started = true;

        let mut boundary = OriginalOutputRegistrationBoundaryV1 { attempt };
        self.register_original_execution_output_inner(output, &mut *boundary.attempt, Some(host_terminal), OriginalOutputIntervalV1::Ordinary);
    }

    /// Reads an original occupied marker under the same configured admission.
    pub(crate) fn query_original_execution_output(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut crate::execution_output_credential::OriginalExecutionOutputRegistrationV1,
    ) {
        if attempt.started { return; }
        attempt.started = true;
        let mut boundary = OriginalOutputRegistrationBoundaryV1 { attempt };
        self.register_original_execution_output_inner(output, &mut *boundary.attempt, None, OriginalOutputIntervalV1::Ordinary);
    }

    fn register_original_execution_output_inner(
        &mut self,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        attempt: &mut crate::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        host_terminal: Option<&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1>,
        mut interval: OriginalOutputIntervalV1<'_, '_, '_>,
    ) {
        use crate::execution_output_credential::OriginalOutputRegistrationErrorV1 as Error;
        let state_root = Path::new("/var/lib/aos/sandbox-storage");

        // Prearming is irreversible even if a lower observer panics. The
        // caller's resident Session/attempt survives its unwind fence.
        if self.readiness != StorageRuntimeReadiness::Ready
            || self.held_reader_state_directory.as_deref() != Some(state_root)
            || attempt.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || !matches!((attempt.request.method(), host_terminal.is_some()),
                (BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT, true)
                | (BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT, false))
        {
            attempt.first_cause = Some(Error::NotCurrent);
            return;
        }

        attempt.initial_custody = Some(interval.custody(output, state_root, 0));
        if attempt.failure().is_some() {
            return;
        }
        attempt.initial_clock = Some(interval.clock(0));
        let Some(Ok(clock)) = &attempt.initial_clock else {
            return;
        };
        let clock = *clock;
        attempt.initial_cut = Some(self.coordinator.authenticate_output_registration(
            &attempt.request, &clock,
        ));
        let Some(Ok(initial)) = &attempt.initial_cut else {
            return;
        };
        if clock.host_boot_id() != initial.records.host_locator().host_boot_id() {
            attempt.first_cause = Some(Error::NotCurrent);
            return;
        }
        let dispatch = match self.worker_dispatch.enter() {
            Ok(dispatch) => dispatch,
            Err(_) => {
                attempt.first_cause = Some(Error::NotCurrent);
                return;
            }
        };

        // Canonical Host comparison and repeated signature/cut validation may
        // be lengthy. Their complete results precede the final clock read.
        if let Some(host_terminal) = host_terminal {
            output.prepare_original(attempt, host_terminal, clock.boottime_nanoseconds());
        }
        if attempt.failure().is_none() {
            attempt.crossing_clock = Some(interval.clock(1));
            if let Some(Ok(crossing_clock)) = &attempt.crossing_clock {
                attempt.crossing_cut = Some(self.coordinator.authenticate_output_registration(
                    &attempt.request, &crossing_clock,
                ));
                if let (Some(Ok(initial)), Some(Ok(crossing))) =
                    (&attempt.initial_cut, &attempt.crossing_cut)
                {
                    if !initial.matches(crossing) {
                        attempt.first_cause = Some(Error::NotCurrent);
                    }
                }
            }
        }
        if attempt.failure().is_none() {
            attempt.entry_clock = Some(interval.clock(2));
            if let (Some(Ok(cut)), Some(Ok(entry_clock))) =
                (&attempt.initial_cut, &attempt.entry_clock)
            {
                attempt.entry_clock_check = Some(
                    self.coordinator.check_output_registration_clock(cut, entry_clock),
                );
            }
            if attempt.failure().is_none() && host_terminal.is_some() {
                // Security retains its genuine exclusive Host currentness
                // loan through this call and the subsequent bookends.
                output.register_original(attempt);
            }
        }

        // Later failures never replace a prior parser, admission or commit
        // result. Every observer's whole Result remains request-resident.
        attempt.final_custody = Some(interval.custody(output, state_root, 1));
        attempt.final_clock = Some(interval.clock(3));
        if let Some(Ok(final_clock)) = &attempt.final_clock {
            attempt.final_cut = Some(self.coordinator.authenticate_output_registration(
                &attempt.request, &final_clock,
            ));
            if let (Some(Ok(initial)), Some(Ok(successor))) =
                (&attempt.initial_cut, &attempt.final_cut)
            {
                if (!initial.matches(successor) || final_clock.host_boot_id() != clock.host_boot_id())
                    && attempt.postcheck_debt().is_none()
                {
                    attempt.postcheck_debt = Some(Error::NotCurrent);
                }
            }
        }
        drop(dispatch);
        if attempt.failure().is_some() || attempt.postcheck_debt().is_some() {
            return;
        }
        if let Err(error) = output.read_original_registration(attempt) {
            if attempt.failure().is_none() {
                attempt.first_cause = Some(error);
            }
        }
        attempt.response_custody = Some(interval.custody(output, state_root, 2));
        attempt.response_clock = Some(interval.clock(4));
        if let Some(Ok(response_clock)) = &attempt.response_clock {
            attempt.response_cut = Some(self.coordinator.authenticate_output_registration(
                &attempt.request, &response_clock,
            ));
            if let (Some(Ok(initial)), Some(Ok(successor))) =
                (&attempt.initial_cut, &attempt.response_cut)
            {
                if (!initial.matches(successor) || response_clock.host_boot_id() != clock.host_boot_id())
                    && attempt.postcheck_debt().is_none()
                {
                    attempt.postcheck_debt = Some(Error::NotCurrent);
                }
            }
        }
        attempt.completed = attempt.failure().is_none() && attempt.postcheck_debt().is_none();
    }

}
