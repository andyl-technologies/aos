//! Released campaign marker parks resume QEMU only under a published ceiling.

use super::*;

#[test]
fn released_campaign_marker_resumes_qemu_after_the_next_ceiling() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        [
            QemuAsyncWaitOutcome::Completed,
            QemuAsyncWaitOutcome::Completed,
        ],
    )?;

    node.release_campaign_marker_stop()?;
    node.advance_to_ceiling(Icount { retired: 42 })?;
    node.advance_to_ceiling(Icount { retired: 84 })?;

    // The release only confirms the native stop; the first quantum publishes
    // its ceiling before resuming QEMU, and the next one does not resume again.
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::QmpStop,
            ChannelCall::HostYield,
            ChannelCall::ShmemStart(42),
            ChannelCall::QmpContinue,
            ChannelCall::HostAwait {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::Completed,
            },
            ChannelCall::ShmemFinish(42),
            ChannelCall::HostYield,
            ChannelCall::HostYield,
            ChannelCall::ShmemStart(84),
            ChannelCall::HostAwait {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::Completed,
            },
            ChannelCall::ShmemFinish(84),
            ChannelCall::HostYield,
        ]
    );
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn campaign_marker_release_requires_a_confirmed_pause_and_one_resume() -> Result<(), Box<dyn Error>>
{
    let log = shared_log();
    let mut unconfirmed = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            fail_qmp_stop: true,
            ..ScriptedNodeOptions::default()
        },
        std::iter::empty(),
    )?;

    let error = unconfirmed
        .release_campaign_marker_stop()
        .expect_err("an unconfirmed QEMU pause must refuse the release");

    assert!(error.to_string().contains("injected QMP stop failure"));
    unconfirmed.shutdown_child()?;

    let mut node = scripted_node(shared_log(), false, false, false)?;
    node.release_campaign_marker_stop()?;

    let error = node
        .release_campaign_marker_stop()
        .expect_err("a second release before the resume must be refused");

    assert!(error.to_string().contains("already pending"));
    node.shutdown_child()?;
    Ok(())
}
