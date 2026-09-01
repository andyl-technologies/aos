//! Machine-readable lifecycle resource-limit RPC decoding.

use super::*;

pub(super) fn decode_lifecycle_resource_limit<'a, I>(
    status: RpcStatusCode,
    mut lines: I,
) -> Result<ControlClientError, ControlClientError>
where
    I: Iterator<Item = &'a str>,
{
    require_rpc_error_status(status, RpcStatusCode::Internal, "resource-limit")?;
    let field = match parse_prefixed_line(lines.next(), "field=")? {
        "nodes" => "nodes",
        "event_records" => "event_records",
        "event_log_bytes" => "event_log_bytes",
        "lifecycle_run_state_bytes" => "lifecycle_run_state_bytes",
        field => {
            return Err(rpc_decode(format!(
                "unknown lifecycle resource field `{field}`"
            )));
        }
    };
    let current = parse_u64_line(lines.next(), "current=")?;
    let requested = parse_u64_line(lines.next(), "requested=")?;
    let configured = parse_u64_line(lines.next(), "configured=")?;
    let hard = parse_u64_line(lines.next(), "hard=")?;
    reject_trailing(lines.next())?;
    Ok(ControlClientError::Lifecycle {
        source: LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_resource_limit_decodes_to_typed_lifecycle_error() {
        let decoded = decode_error_response(
            b"crucible.rpc/error\nstatus=internal\nreason=resource-limit\nfield=event_log_bytes\ncurrent=1024\nrequested=512\nconfigured=1280\nhard=274877906944\n",
        )
        .unwrap_or_else(|error| panic!("typed resource error should decode: {error}"));
        assert!(matches!(
            decoded,
            ControlClientError::Lifecycle {
                source: LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
                    field: "event_log_bytes",
                    current: 1024,
                    requested: 512,
                    configured: 1280,
                    hard: 274_877_906_944,
                }),
            }
        ));
    }
}
