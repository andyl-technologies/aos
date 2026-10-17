//! Bounded RPC client for live executor operational controls.

use super::*;
use crate::host_operational::{
    HOST_OPERATIONAL_MAX_BYTES, HostOperationalRequest, HostOperationalResponse, codec,
};

impl RpcControlClient {
    /// Sends an authenticated host control request outside the modeled command stream.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid canonical fields, transport failures,
    /// unauthorized ownership, unavailable controllers, oversized replies, or
    /// a response that does not match the requested operation and target.
    pub(super) async fn send_host_operational(
        &self,
        request: HostOperationalRequest,
    ) -> Result<crate::AdmittedOutput<HostOperationalResponse>, ControlClientError> {
        if !self.endpoint.uri().starts_with("https://") {
            return Err(message_error(
                "host operational controls require a mutual-TLS endpoint",
            ));
        }
        let principal = self.host_operational_principal.as_deref().ok_or_else(|| {
            message_error("host operational controls require a client certificate")
        })?;
        self.host_operational_negotiation
            .get_or_try_init(|| async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    self.hello(HelloRequest::new(
                        "crucible-host-control",
                        RPC_PROTOCOL_VERSION,
                    )),
                )
                .await
                .map_err(|_| message_error("host operational protocol negotiation timed out"))??;
                Ok::<(), ControlClientError>(())
            })
            .await?;
        let body = {
            let budget = self.output_budget()?;
            let _scope = budget.enter();
            let encoded = codec::encode_request(&request).map_err(|error| match error {
                crate::host_operational::HostOperationalError::Admission { source } => {
                    client_output_admission(crate::admitted_output::admission(source))
                }
                other => message_error(other),
            })?;
            request_storage::from_admitted(encoded)?
        };
        let response = self
            .http
            .post(self.endpoint.rpc_url("/crucible.rpc/host-operational"))
            .timeout(std::time::Duration::from_secs(30))
            .header(
                "x-crucible-rpc-build",
                self.wire_model.protocol_version.build,
            )
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/vnd.crucible.host-operational.v1",
            )
            .body(body)
            .send()
            .await
            .map_err(|error| ControlClientError::HttpRequest {
                message: error.to_string(),
            })?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > HOST_OPERATIONAL_MAX_BYTES as u64)
        {
            return Err(message_error(
                "host operational response exceeds size limit",
            ));
        }
        let bytes = wire_storage::read_response(
            response,
            self.output_budget()?.child().map_err(|source| {
                client_output_admission(crate::admitted_output::admission(source))
            })?,
            Some(HOST_OPERATIONAL_MAX_BYTES),
        )
        .await?;
        if !status.is_success() {
            let budget = self.output_budget()?;
            let _scope = budget.enter();
            return Err(decode_http_failure(&bytes, status.as_u16(), &budget));
        }
        let budget = self.output_budget()?;
        let _scope = budget.enter();
        let response = codec::decode_response(&bytes).map_err(|error| match error {
            crate::host_operational::HostOperationalError::Admission { source } => {
                client_output_admission(crate::admitted_output::admission(source))
            }
            other => message_error(other),
        })?;
        let response_target = match response.value() {
            HostOperationalResponse::Targets { target, .. } => {
                crate::host_operational::HostOperationalTarget::Owner(*target)
            }
            HostOperationalResponse::Capabilities { target, .. }
            | HostOperationalResponse::PolicyUpdate { target, .. } => {
                crate::host_operational::HostOperationalTarget::Ram(*target)
            }
            HostOperationalResponse::OuterCapAmendment { target, .. } => {
                crate::host_operational::HostOperationalTarget::OuterCap(*target)
            }
            HostOperationalResponse::Status(status) => {
                crate::host_operational::HostOperationalTarget::Ram(status.target)
            }
        };
        let expected_kind = matches!(
            (&request, response.value()),
            (
                HostOperationalRequest::ListTargets { .. },
                HostOperationalResponse::Targets { .. }
            ) | (
                HostOperationalRequest::Capabilities { .. },
                HostOperationalResponse::Capabilities { .. }
            ) | (
                HostOperationalRequest::Status { .. },
                HostOperationalResponse::Status(_)
            ) | (
                HostOperationalRequest::UpdatePolicy { .. },
                HostOperationalResponse::PolicyUpdate { .. }
            ) | (
                HostOperationalRequest::AmendOuterCap { .. },
                HostOperationalResponse::OuterCapAmendment { .. }
            )
        );
        if request.target() != response_target || !expected_kind {
            return Err(message_error(
                "host operational response does not bind request target and operation",
            ));
        }
        if let (
            HostOperationalRequest::ListTargets { after, limit, .. },
            HostOperationalResponse::Targets { targets, .. },
        ) = (&request, response.value())
            && (targets.len() > usize::from(*limit)
                || after
                    .is_some_and(|cursor| targets.first().is_some_and(|first| *first <= cursor)))
        {
            return Err(message_error(
                "host target discovery violates requested page bounds",
            ));
        }
        if let HostOperationalResponse::PolicyUpdate { request_digest, .. }
        | HostOperationalResponse::OuterCapAmendment { request_digest, .. } = response.value()
        {
            let expected =
                crate::host_operational::host_operational_request_digest(principal, &request)
                    .map_err(message_error)?;
            if *request_digest != expected {
                return Err(message_error(
                    "host operational receipt does not bind authenticated request bytes",
                ));
            }
        }
        Ok(response)
    }
}

fn message_error(error: impl std::fmt::Display) -> ControlClientError {
    ControlClientError::HttpRequest {
        message: format!("invalid host operational message: {error}"),
    }
}
