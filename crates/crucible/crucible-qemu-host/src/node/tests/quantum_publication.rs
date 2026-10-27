//! Quantum publications around idle advances and selectable replies.
//!
//! A node publishes its next ceiling, and any selectable reply, only in the
//! order QEMU can observe them: an idle advance pauses below an unrelated
//! ceiling, and a reply reaches shared memory only after QEMU confirms its
//! pause.

use super::*;

#[test]
fn next_idle_advance_pauses_below_an_unrelated_large_ceiling() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

    let outcome = node.advance_to_next_idle(Icount { retired: 1_000_000 })?;

    assert_eq!(
        outcome,
        AdvanceOutcome::Paused {
            at: Icount { retired: 73 },
        }
    );
    assert_eq!(
        node.last_step_final_state(),
        Some(QemuNodeIdleState {
            current_icount: Icount { retired: 73 },
            next_deadline: Some(Icount { retired: 91 }),
        })
    );
    assert!(recorded(&log).contains(&ChannelCall::ShmemStartNextIdle(1_000_000)));
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn selectable_reply_and_ceiling_are_published_before_qemu_resumes() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let request = crucible_qemu_protocol::SelectionRequest::new(
        7,
        "product.test.selectable",
        "instance-a",
        None,
        128,
    )?;
    let pending =
        crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanPendingRequest::new(
            request,
            41,
            (41) * 50,
            0,
            0x1000,
        );
    let reply = crucible_qemu_protocol::SelectionReply::rejected(
        7,
        crucible_qemu_protocol::SelectionReplyStatus::Unavailable,
        [0; 32],
        [0; 32],
    )?;

    node.enqueue_selectable_reply(&pending, &reply)?;
    node.advance_to_ceiling(Icount { retired: 42 })?;

    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::QmpStop,
            ChannelCall::ShmemSelectableReply(7),
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
        ]
    );
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn selectable_reply_is_not_published_before_qemu_confirms_pause() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            fail_qmp_stop: true,
            ..ScriptedNodeOptions::default()
        },
        std::iter::empty(),
    )?;
    let request = crucible_qemu_protocol::SelectionRequest::new(
        7,
        "product.test.selectable",
        "instance-a",
        None,
        128,
    )?;
    let pending =
        crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanPendingRequest::new(
            request,
            41,
            (41) * 50,
            0,
            0x1000,
        );
    let reply = crucible_qemu_protocol::SelectionReply::rejected(
        7,
        crucible_qemu_protocol::SelectionReplyStatus::Unavailable,
        [0; 32],
        [0; 32],
    )?;

    let error = node
        .enqueue_selectable_reply(&pending, &reply)
        .expect_err("an unconfirmed QEMU pause must reject the reply");

    assert!(error.to_string().contains("injected QMP stop failure"));
    assert_eq!(recorded(&log), vec![ChannelCall::QmpStop]);
    node.shutdown_child()?;
    Ok(())
}
