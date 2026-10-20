//! Uses actual authenticated/current Host custody for the early closure writer.
//!
//! The Host broker must durably admit its exact terminal grant in HostState
//! before entering this same held runtime claim. No historical method42/43
//! response or caller-produced marker can be adopted as that live authority.

use super::*;
use aos_sandbox_core::{BrokerAdmissionIntersection, BrokerGrantTarget, BrokerVerb};
use aos_sandbox_protocol::host_execution_no_apply::ClosedBeforeArgumentNoApplyRecordV2;
use aos_sandbox_protocol::semantics::host_execution_argument::{
    host_before_argument_no_apply_grant_v2, host_before_argument_no_apply_query_grant_v2,
};

impl DormantRuntimeExecutionClaimV1<'_> {
    /// Rechecks an active early closure under the same actual native claim.
    ///
    /// This reads the exact protected marker and current assignment while the
    /// caller retains all four journal writers. It issues no transferable
    /// lease and supplies no cold recovery or replacement-owner constructor.
    ///
    /// # Errors
    /// Rejects a missing or changed marker, runtime, assignment, boot or claim.
    pub fn require_held_active_closed_no_apply_v2(
        &self,
        marker: ClosedBeforeArgumentNoApplyRecordV2,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.require_held_closed_no_apply_history_v2(marker)?;
        if marker.fields().source.fields().host_boot != self.host_verifier.boot_id() {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        Ok(())
    }

    /// Rechecks exact terminal history under the actual current native claim.
    ///
    /// The marker's original boot remains historical. A fresh cleanup borrower
    /// must separately establish its paid current boot, deadline and restricted
    /// purpose; this read issues no execution or settlement capability.
    ///
    /// # Errors
    /// Rejects a missing or changed marker, runtime, assignment or native claim.
    pub fn require_held_closed_no_apply_history_v2(
        &self,
        marker: ClosedBeforeArgumentNoApplyRecordV2,
    ) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let fields = marker.fields();
        let source = fields.source.fields();
        let current = self.currentness.runtime().currentness();
        if self.execution.load_before_argument_no_apply_v2(
            ExecutionId::from_bytes(source.execution),
        )? != Some(marker)
            || fields.runtime_handle != *self.currentness.runtime().handle().as_bytes()
            || fields.execution_store != *self.execution_store_binding.as_bytes()
            || source.sandbox != *current.sandbox().as_bytes()
            || source.incarnation != *current.incarnation().as_bytes()
            || source.node != *current.node().as_bytes()
            || source.assignment_epoch != current.assignment_epoch().get()
            || source.desired_generation != current.desired_generation().get()
            || source.assignment_digest != *current.assignment_digest().as_bytes()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        self.validate_current()
    }

    /// Reads exact early closure history under the actual current Host claim.
    ///
    /// The returned record retains its original terminal boot/Session/epoch.
    /// A freshly authenticated query never revives that old native interval,
    /// a live settlement lease, or a new terminal mutation permission.
    ///
    /// # Errors
    /// Rejects changed query/source/grant/current assignment or unavailable
    /// protected history. An absent result never authorizes a replacement send.
    pub fn query_host_before_argument_no_apply_v2(
        &self,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
        intersection: &BrokerAdmissionIntersection,
    ) -> Result<Option<ClosedBeforeArgumentNoApplyRecordV2>, DormantRuntimeExecutionOwnerErrorV1>
    {
        self.validate_current()?;
        let decoded = authenticated
            .host_before_argument_no_apply_data_v2()
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        let source = decoded.source();
        let current = self.currentness.runtime().currentness();
        let assignment = BrokerAssignment::new(
            current.sandbox(),
            current.incarnation(),
            current.assignment_epoch(),
            current.desired_generation(),
            current.assignment_digest(),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let semantics = host_before_argument_no_apply_query_grant_v2(
            assignment,
            authenticated.request_id(),
            source,
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        if !decoded.is_query()
            || authenticated.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || authenticated.method() != BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY
            || authenticated.authorization().is_none()
            || authenticated.request_id() != *decoded.header().request_id()
            || intersection.request_id() != &authenticated.request_id()
            || intersection.verb() != BrokerVerb::HostQueryNoApply
            || intersection.target() != BrokerGrantTarget::Assignment
            || intersection.request_digest() != semantics.commitment().digest()
            || intersection.host_boot_id() != &self.host_verifier.boot_id()
            || source.fields().node != *current.node().as_bytes()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        let record = self
            .execution
            .load_before_argument_no_apply_v2(ExecutionId::from_bytes(source.fields().execution))?;
        if record.is_some_and(|record| record.fields().source != source) {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        self.validate_current()?;
        Ok(record)
    }

    /// Closes future Apply before an original argument source exists.
    ///
    /// The caller holds its authenticated HostState terminal handoff and paid
    /// native receiving owner across this same runtime/Host journal claim.
    /// The intersection remains distinct from durable HostState admission;
    /// neither its scalars nor this return value supplies a settlement lease.
    ///
    /// # Errors
    /// Rejects changed authenticated source/grant/currentness, any admission or
    /// dispatch, another closure branch, or uncertain native durability.
    pub fn commit_host_before_argument_no_apply_v2(
        &mut self,
        authenticated: &AuthenticatedBrokerMethodRequestV1,
        intersection: &BrokerAdmissionIntersection,
    ) -> Result<ClosedBeforeArgumentNoApplyRecordV2, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        let decoded = authenticated
            .host_before_argument_no_apply_data_v2()
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        let source = decoded.source();
        let fields = source.fields();
        let current = self.currentness.runtime().currentness();
        let assignment = BrokerAssignment::new(
            current.sandbox(),
            current.incarnation(),
            current.assignment_epoch(),
            current.desired_generation(),
            current.assignment_digest(),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let semantics =
            host_before_argument_no_apply_grant_v2(assignment, authenticated.request_id(), source)
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)?;
        if decoded.is_query()
            || authenticated.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || authenticated.method() != BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
            || authenticated.authorization().is_none()
            || authenticated.exact_body() != decoded.exact_body()
            || authenticated.request_id() != *decoded.header().request_id()
            || intersection.request_id() != &authenticated.request_id()
            || intersection.verb() != BrokerVerb::HostTerminalNoApply
            || intersection.target() != BrokerGrantTarget::Assignment
            || intersection.request_digest() != semantics.commitment().digest()
            || intersection.host_boot_id() != &fields.host_boot
            || fields.host_boot != self.host_verifier.boot_id()
            || fields.node != *current.node().as_bytes()
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }

        let identity = super::super::store::HostBeforeArgumentNoApplyIdentityV2 {
            source,
            terminal_request: authenticated.request_id(),
            terminal_session: authenticated.session_binding(),
            signed_terminal_request: authenticated.signed_request_digest(),
            runtime_handle: self.currentness.runtime().handle(),
        };
        let record = self
            .execution
            .commit_before_argument_no_apply_v2(&identity)?;
        self.validate_current()
            .map_err(|_| JournalRuntimeExecutionError::NoApplyOutcomeUnknown)?;
        Ok(record)
    }
}
