//! Production control-boundary fingerprint regressions.

use super::*;

#[test]
fn stale_execution_fingerprint_requests_production_control_boundary() -> Result<(), Box<dyn Error>>
{
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            fingerprint_retry_countdown: 1,
            ..ScriptedNodeOptions::default()
        },
        std::iter::empty(),
    )?;

    assert_eq!(
        node.execution_fingerprint()?,
        ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        }
    );
    node.shutdown_child()?;
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemFingerprint,
            ChannelCall::HostFingerprintBoundary,
            ChannelCall::ShmemFingerprint,
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );
    Ok(())
}
