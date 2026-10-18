//! Public diagnostic vectors exercise the owned-child parser, not VM outcomes.

use super::control_diagnostics_summary;

const STOP: &str = "CRUCIBLE-CHECKPOINT-STOP-V1 phase=after-request pid=153 device=1 inode=15 length=49302720 slot=0 generation=2 caller=selectable-sim-publication raw_icount=5859570659 logical_ps=561196676600 token=4502 status=0";
const STAGE: &str = "CRUCIBLE-CONTROL-STAGE-V1 phase=settle-return pid=153 callback=7327 token=4502 raw=5859570659 dev=1 ino=15 slot=0 gen=2 result=false";

fn accepted(row: &str) {
    let summary = control_diagnostics_summary(format!("{row}\n").as_bytes(), 153);
    assert!(
        summary.contains("accepted_rows=1 rejected_rows=0"),
        "{summary}"
    );
    assert!(summary.ends_with(row));
}

fn rejected(row: &str) {
    let summary = control_diagnostics_summary(format!("{row}\n").as_bytes(), 153);
    assert!(
        summary.contains("accepted_rows=0 rejected_rows=1"),
        "{summary}"
    );
    assert_eq!(summary.lines().count(), 1);
}

#[test]
fn stop_callers_accept_only_matching_identity_phase_and_status_grammar() {
    for caller in [
        "selectable-sim-publication",
        "campaign-marker-sim-publication",
        "network-output",
        "vcpu-idle-wait",
        "vcpu-idle",
        "vcpu-resume",
        "sim-publication",
        "progress-publication",
        "block-wait",
        "control-boundary",
        "max-advance",
        "block-poll",
        "ninep-poll",
        "ninep-burst-done",
        "accelerator-poll",
    ] {
        accepted(&STOP.replace(
            "caller=selectable-sim-publication",
            &format!("caller={caller}"),
        ));
    }
    for phase in ["claimed-before-pause", "before-request"] {
        accepted(
            &STOP
                .replace("phase=after-request", &format!("phase={phase}"))
                .replace("status=0", "status=unavailable"),
        );
    }
    accepted(&STOP.replace("device=1 inode=15 length=49302720 slot=0 generation=2",
        "device=unavailable inode=unavailable length=unavailable slot=unavailable generation=unavailable"));
    accepted(&STOP.replace("status=0", "status=-2147483648"));
    accepted(&STOP.replace("status=0", "status=2147483647"));

    for row in [
        STOP.replace("pid=153", "pid=132"),
        STOP.replace("phase=after-request", "phase=unknown"),
        STOP.replace("device=1", "device=unavailable"),
        STOP.replace("slot=0", "slot=4294967296"),
        STOP.replace("caller=selectable-sim-publication", "caller=unknown"),
        STOP.replace("phase=after-request", "phase=claimed-before-pause")
            .replace("status=0", "status=unavailable")
            .replace("caller=selectable-sim-publication", "caller=vcpu-idle"),
        STOP.replace("phase=after-request", "phase=before-request"),
        STOP.replace("status=0", "status=unavailable"),
        STOP.replace("status=0", "status=2147483648"),
        STOP.replace("status=0", "status=+1"),
        STOP.replace("token=4502", "token=-1"),
        STOP.replace("raw_icount=5859570659", "raw_icount=18446744073709551616"),
        format!("{STOP} extra=1"),
        format!("{STOP}\x1b"),
        format!("{STOP}é"),
        format!("{STOP}{}", " ".repeat(512 - STOP.len())),
    ] {
        rejected(&row);
    }
}

#[test]
fn admitted_control_stages_preserve_exact_results_and_optional_identity() {
    for phase in ["settle-return", "pause-return"] {
        for result in ["true", "false", "error"] {
            accepted(
                &STAGE
                    .replace("phase=settle-return", &format!("phase={phase}"))
                    .replace("result=false", &format!("result={result}")),
            );
        }
    }
    for phase in ["settle-enter", "pause-enter"] {
        accepted(
            &STAGE
                .replace("phase=settle-return", &format!("phase={phase}"))
                .replace("result=false", "result=unavailable"),
        );
    }
    accepted(&STAGE.replace(
        "dev=1 ino=15 slot=0 gen=2",
        "dev=unavailable ino=unavailable slot=unavailable gen=unavailable",
    ));
    for row in [
        STAGE.replace("pid=153", "pid=154"),
        STAGE.replace("phase=settle-return", "phase=unknown"),
        STAGE.replace("phase=settle-return", "phase=settle-enter"),
        STAGE.replace("result=false", "result=unavailable"),
        STAGE.replace("result=false", "result=other"),
        STAGE.replace("dev=1", "dev=unavailable"),
        STAGE.replace("callback=7327", "callback=-1"),
        STAGE.replace("token=4502", "token=4294967296"),
        STAGE.replace("slot=0", "slot=4294967296"),
        format!("{STAGE} extra=1"),
        format!("{STAGE}\t"),
        format!("{STAGE}{}", " ".repeat(256 - STAGE.len())),
    ] {
        rejected(&row);
    }
}

#[test]
fn mixed_late_notices_share_existing_32_row_child_tail() {
    let mut bytes = b"CRUCIBLE-UNKNOWN-V1 pid=153\n".to_vec();
    for token in 4400..4440 {
        for row in [STOP, STAGE] {
            bytes.extend_from_slice(
                row.replace("token=4502", &format!("token={token}"))
                    .as_bytes(),
            );
            bytes.push(b'\n');
        }
    }
    bytes.extend_from_slice(STAGE.replace("pid=153", "pid=154").as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(b"CRUCIBLE-CONTROL-STAGE-V1 incomplete");
    let summary = control_diagnostics_summary(&bytes, 153);
    assert!(summary.contains(
        "accepted_rows=80 rejected_rows=1 tail_rows=32 omitted_rows=48 incomplete_last_row=true"
    ));
    assert_eq!(summary.lines().count(), 33);
    assert!(
        summary
            .lines()
            .nth(1)
            .is_some_and(|row| row.contains("token=4424 "))
    );
    assert!(summary.ends_with(&STAGE.replace("token=4502", "token=4439")));
    assert!(!summary.contains("UNKNOWN"));
    assert!(!summary.contains("pid=154"));
    assert!(summary.len() <= 32 * 512 + 256);
}

#[test]
fn late_stop_notices_survive_the_original_owned_socket_capture()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    use std::net::Shutdown;

    let mut pair = super::super::create_diagnostic_pair(2)?;
    let mut consumer = pair.take_consumer()?;
    pair.child
        .write_all(STAGE.replace("pid=153", "pid=154").as_bytes())?;
    pair.child.write_all(b"\n")?;
    for token in 4400..4440 {
        for row in [STOP, STAGE] {
            pair.child.write_all(
                row.replace("token=4502", &format!("token={token}"))
                    .as_bytes(),
            )?;
            pair.child.write_all(b"\n")?;
        }
        consumer.drain_available_bounded()?;
    }
    pair.child.shutdown(Shutdown::Write)?;
    consumer.mark_writer_detached(&pair.descriptor_name, pair.socket_cookie, 2)?;
    let capture = consumer.finish_detached_capture()?;

    assert_eq!(capture.socket_cookie(), pair.socket_cookie);
    assert_eq!(capture.template_generation(), 2);
    let summary = capture.control_diagnostics_summary(153);
    assert!(summary.contains("accepted_rows=80 rejected_rows=1 tail_rows=32 omitted_rows=48"));
    assert!(summary.ends_with(&STAGE.replace("token=4502", "token=4439")));
    assert!(
        capture
            .control_diagnostics_summary(154)
            .contains("accepted_rows=1 rejected_rows=80")
    );
    assert!(consumer.finish_detached_capture().is_err());
    Ok(())
}
