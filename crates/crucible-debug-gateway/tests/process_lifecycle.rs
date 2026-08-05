//! SPDX-License-Identifier: GPL-2.0-only
//! Process-boundary lifecycle tests for the standalone debugger gateway.

use std::path::Path;

use crucible_api::DebugGatewayProcess;

#[test]
fn apache_client_launches_negotiates_queries_and_reaps_gateway() {
    let executable = Path::new(env!("CARGO_BIN_EXE_crucible-debug-gateway"));
    let mut process = DebugGatewayProcess::launch(executable)
        .unwrap_or_else(|error| panic!("gateway should launch: {error}"));
    assert!(process.control_socket().is_absolute());
    let status = process
        .client_mut()
        .backend_status()
        .unwrap_or_else(|error| panic!("gateway should report status: {error}"));
    assert!(status.active.is_none());
    assert!(status.prepared.is_none());

    let status = process
        .shutdown()
        .unwrap_or_else(|error| panic!("gateway should shut down: {error}"));
    assert!(
        !status.success(),
        "forced gateway shutdown should be signaled"
    );
}
