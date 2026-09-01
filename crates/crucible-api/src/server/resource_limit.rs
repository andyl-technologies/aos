//! Machine-readable lifecycle resource-limit RPC responses.

use super::*;

pub(super) fn response(limit: &crate::LifecycleResourceLimit) -> Response {
    http2_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        encode_lifecycle_resource_limit(limit),
    )
}

fn encode_lifecycle_resource_limit(limit: &crate::LifecycleResourceLimit) -> String {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(
        &mut output,
        "status",
        rpc_status_code_wire_name(RpcStatusCode::Internal),
    );
    push_wire_line(&mut output, "reason", "resource-limit");
    push_wire_line(&mut output, "field", limit.field);
    push_wire_line(&mut output, "current", &limit.current.to_string());
    push_wire_line(&mut output, "requested", &limit.requested.to_string());
    push_wire_line(&mut output, "configured", &limit.configured.to_string());
    push_wire_line(&mut output, "hard", &limit.hard.to_string());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_resource_limit_response_preserves_exact_coordinates() {
        let encoded = encode_lifecycle_resource_limit(&crate::LifecycleResourceLimit {
            field: "event_log_bytes",
            current: 1024,
            requested: 512,
            configured: 1280,
            hard: 274_877_906_944,
        });
        assert_eq!(
            encoded,
            "crucible.rpc/error\nstatus=internal\nreason=resource-limit\nfield=event_log_bytes\ncurrent=1024\nrequested=512\nconfigured=1280\nhard=274877906944\n"
        );
    }
}
