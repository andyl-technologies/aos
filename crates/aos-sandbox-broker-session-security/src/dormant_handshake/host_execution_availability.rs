//! Joins the actual paid Host64 native receiver to the same signed Session.
//!
//! The Host retains its four native writers after the exact response is sent.
//! This module uses the existing protected outcome CAS/readback/Sent engine;
//! it creates no dormant opener, receiver adapter or scalar capability.

use super::*;

impl DormantAuthenticatedBrokerSessionV1 {
    /// Executes the genuine preaccept or accepted-bind native interval.
    ///
    /// # Errors
    /// Retains the actual authenticated request and all independently owed Host
    /// posts on domain/currentness/commit/send refusal or ambiguity.
    pub async fn execute_host_execution_availability_and_commit_v2(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        deadline: u64,
    ) -> Result<
        (
            ProtectedBrokerOutcomeCommitResultV1,
            DormantReceivedBrokerRequestV1,
        ),
        DormantBrokerExecutionFailureV1<crate::HostExecutionHandoffErrorV1>,
    > {
        let matches = match request.0.method() {
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 => {
                request.0.authorization().is_none()
                    && request.0.execution_availability_data_v2().is_some()
            }
            BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT => {
                request.0.authorization().is_some() && host.has_execution_availability()
            }
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY => {
                request.0.authorization().is_some()
                    && request.0.host_before_argument_no_apply_data_v2().is_some()
                    && host.has_execution_availability()
            }
            BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => {
                request.0.authorization().is_none()
                    && request.0.host_held_no_apply_settlement_data_v2().is_some()
                    && (host.has_execution_availability()
                        || matches!(request.0.host_held_no_apply_settlement_data_v2()
                            .map(|value| value.command_v2()),
                            Some(aos_sandbox_protocol::host_execution_no_apply::held_settlement_transport::HostNoApplyHeldCommandV2::RecoveryPreliminary { .. })))
            }
            BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
                request.0.authorization().is_none()
                    && request.0.host_no_apply_current_lease_query_data_v2().is_some()
                    && host.has_execution_availability()
            }
            _ => false,
        };
        let (request, context) = self.begin_execution(request, matches)?;
        let body = match host
            .execute_execution_availability(&request.0, context.boot_id(), deadline)
            .await
        {
            Ok(body) => body,
            Err(cause) => return Err(Self::unknown_domain(request, cause.into())),
        };
        self.finish_observed_success_retaining_request_v2(request, body)
    }
}
