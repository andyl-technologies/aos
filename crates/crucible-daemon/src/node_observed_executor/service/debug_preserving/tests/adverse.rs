//! Exercises original public route, current-root and owner refusals beside native twins.

#![cfg(test)]

use super::*;
use crucible_cas::content_store::{BlobHandle, ObjectKind};

fn cli(server: &Server, command: &str, operand: (&str, &Path)) -> NodePreservingDebugRecord {
    let executable = std::env::var("CRUCIBLE_PRESERVING_DEBUG_CLI")
        .expect("actual source-built preserving CLI binding is mandatory");
    let output = std::process::Command::new(executable)
        .args(["node", command, "--socket"])
        .arg(&server.socket)
        .arg(operand.0)
        .arg(operand.1)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

pub(super) fn prepare_cli(
    server: &Server,
    directory: &Path,
    request: NodePreservingDebugRequest,
) -> NodePreservingDebugRecord {
    let file = directory.join("original-prepare.json");
    std::fs::write(&file, encode(&request).unwrap()).unwrap();
    let queued = cli(server, "debug-preserving-prepare", ("--request", &file));
    assert_eq!(queued.execution, request.execution);
    server.status(&request.execution, false)
}

pub(super) fn resume_cli(
    server: &Server,
    directory: &Path,
    execution: &str,
) -> NodePreservingDebugRecord {
    let file = directory.join("original-resume.json");
    std::fs::write(&file, encode(&resume_request(execution)).unwrap()).unwrap();
    let queued = cli(server, "debug-preserving-resume", ("--request", &file));
    assert_eq!(queued.execution, execution);
    let completed = server.status(execution, true);
    let status = cli(
        server,
        "debug-preserving-status",
        ("--execution", Path::new(execution)),
    );
    assert_eq!(encode(&status).unwrap(), encode(&completed).unwrap());
    completed
}

fn resume_request(execution: &str) -> NodePreservingDebugResumeRequest {
    NodePreservingDebugResumeRequest {
        format: "crucible.preserving-debug-resume".into(),
        version: 1,
        execution: execution.into(),
        horizon_ps: 2_100_000.into(),
    }
}

fn reject(server: &Server, request: NodeControlRequest) {
    let reply = request_node_control(&server.socket, &request).unwrap();
    assert!(
        matches!(reply.result, NodeControlResult::Refused { .. }),
        "{reply:?}"
    );
}

fn record_ref(directory: &Path, namespace: &str, execution: &str) -> Option<ContentId> {
    DirectoryRefBackend::new(directory.join("refs"))
        .read_ref(&RefName::new(format!("{namespace}/{execution}")).unwrap())
        .unwrap()
}

pub(super) fn refuse_original_nonce_change(
    server: &Server,
    directory: &Path,
    original: &NodePreservingDebugRequest,
) {
    let retained = server.status(&original.execution, false);
    let mut changed = original.clone();
    changed.maximum_physical_cut = (original.maximum_physical_cut.get() + 1).into();
    reject(
        server,
        NodeControlRequest::preserving_debug_prepare("adverse/nonce", changed).unwrap(),
    );
    assert_eq!(
        encode(&retained).unwrap(),
        encode(&server.status(&original.execution, false)).unwrap()
    );
    assert!(
        record_ref(
            directory,
            "node-original-preparation-claims",
            &original.execution
        )
        .is_some()
    );
}

pub(super) fn refuse_foreign_relations(
    server: &Server,
    directory: &Path,
    source: &NodePreservingDebugRequest,
    capture: &NodePreservingDebugCapture,
) {
    for axis in 0..6 {
        let mut changed = source.clone();
        changed.execution = format!("{:032x}", 0x70 + axis);
        changed.action = NodePreservingDebugAction::Restore {
            source_execution: source.execution.clone(),
            capture: capture.artifact.clone(),
        };
        match axis {
            0 => {
                let NodePreservingDebugAction::Restore {
                    source_execution, ..
                } = &mut changed.action
                else {
                    unreachable!()
                };
                *source_execution = "ffffffffffffffffffffffffffffffff".into();
            }
            1 => {
                let NodePreservingDebugAction::Restore { capture, .. } = &mut changed.action else {
                    unreachable!()
                };
                *capture =
                    canonical::content_ref(b"foreign signed capture", "application/json").unwrap();
            }
            2 => changed.maximum_physical_cut = (changed.maximum_physical_cut.get() + 1).into(),
            3 => changed.maximum_record_bytes = (16 << 20).into(),
            4 => changed.scenario = Bytes::new(b"foreign authored scenario".to_vec()),
            5 => changed.selections[0].owner = id("foreign-owner"),
            _ => unreachable!(),
        }
        reject(
            server,
            NodeControlRequest::preserving_debug_prepare("adverse/relation", changed.clone())
                .unwrap(),
        );
        for namespace in [
            "node-original-preparation-claims",
            "node-preserving-debug-preparations",
        ] {
            assert!(record_ref(directory, namespace, &changed.execution).is_none());
        }
    }
}

fn unknown(server: &Server, execution: &str) -> NodePreservingDebugRecord {
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(40)).unwrap();
    loop {
        let record = server.request(
            NodeControlRequest::preserving_debug_status("adverse/status", execution.into())
                .unwrap(),
        );
        if matches!(record.outcome, NodePreservingDebugState::Unknown { .. }) {
            assert!(record.capture.is_some());
            assert!(record.resume_request.is_some());
            return record;
        }
        assert!(!deadline.expired());
        std::thread::yield_now();
    }
}

pub(super) fn refuse_changed_current_report(
    server: &Server,
    directory: &Path,
    source: &NodePreservingDebugRequest,
    capture: &NodePreservingDebugCapture,
) {
    let mut target = source.clone();
    target.execution = "50505050505050505050505050505050".into();
    target.action = NodePreservingDebugAction::Restore {
        source_execution: source.execution.clone(),
        capture: capture.artifact.clone(),
    };
    server.prepare(target.clone());
    let refs = DirectoryRefBackend::new(directory.join("refs"));
    let reference = RefName::new(format!(
        "node-world-coordinators/condition/debug-preserving-{}-stop-report",
        source.execution
    ))
    .unwrap();
    let original = refs.read_ref(&reference).unwrap().unwrap();
    let body = b"changed current source report";
    let changed = ContentId::for_bytes(ObjectKind::Trace, 1, body);
    DirectoryBlobBackend::new("operator-adverse", directory.join("blobs"))
        .put_if_absent(changed, &BlobHandle::from_bytes(body.to_vec()))
        .unwrap();
    refs.compare_exchange(&reference, Some(original), changed)
        .unwrap();

    server.request(
        NodeControlRequest::preserving_debug_resume(
            "adverse/report",
            resume_request(&target.execution),
        )
        .unwrap(),
    );
    let retained = unknown(server, &target.execution);
    let NodePreservingDebugState::Unknown { reason } = &retained.outcome else {
        unreachable!()
    };
    assert!(reason.contains("durable Stop roots"), "{reason}");
    assert!(
        record_ref(
            directory,
            "node-preserving-debug-publications",
            &target.execution
        )
        .is_none()
    );
    let unchanged = server.request(
        NodeControlRequest::preserving_debug_resume(
            "adverse/repeat",
            resume_request(&target.execution),
        )
        .unwrap(),
    );
    assert_eq!(encode(&retained).unwrap(), encode(&unchanged).unwrap());
    refs.compare_exchange(&reference, Some(changed), original)
        .unwrap();
}

pub(super) fn refuse_stored_stop_without_owner(server: &Server, directory: &Path, execution: &str) {
    server.request(
        NodeControlRequest::preserving_debug_resume("adverse/restart", resume_request(execution))
            .unwrap(),
    );
    let retained = unknown(server, execution);
    let NodePreservingDebugState::Unknown { reason } = &retained.outcome else {
        unreachable!()
    };
    assert!(
        reason.contains("no current native stopped owner"),
        "{reason}"
    );
    assert!(record_ref(directory, "node-preserving-debug-publications", execution).is_none());
}

/// Refuses missing or malformed original signed bytes under unchanged source identity.
pub(super) fn refuse_unavailable_signed_archive(
    server: &Server,
    directory: &Path,
    source: &NodePreservingDebugRequest,
    capture: &NodePreservingDebugCapture,
) {
    let archive = directory.join("condition-preserving-archive").join(format!(
        "{}.host-world-v1.json",
        capture.artifact.hash.digest
    ));
    let saved = directory.join("adverse-original-host-archive.json");
    std::fs::rename(&archive, &saved).unwrap();
    let original_source = encode(&server.status(&source.execution, true)).unwrap();
    let mut attempted = Vec::new();
    for (index, execution) in [
        "70707070707070707070707070707070",
        "80808080808080808080808080808080",
    ]
    .into_iter()
    .enumerate()
    {
        if index == 1 {
            std::fs::write(&archive, b"{}").unwrap();
        }
        let mut target = source.clone();
        target.execution = execution.into();
        target.action = NodePreservingDebugAction::Restore {
            source_execution: source.execution.clone(),
            capture: capture.artifact.clone(),
        };
        let command =
            NodeControlRequest::preserving_debug_prepare("adverse/archive", target.clone())
                .unwrap();
        server.request(command);
        let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(40)).unwrap();
        let retained = loop {
            let record = server.request(
                NodeControlRequest::preserving_debug_status(
                    "adverse/archive-status",
                    execution.into(),
                )
                .unwrap(),
            );
            if matches!(record.outcome, NodePreservingDebugState::Unknown { .. }) {
                break record;
            }
            assert!(!deadline.expired());
            std::thread::yield_now();
        };
        assert_eq!(retained.capture.as_ref(), Some(capture));
        assert!(retained.resume_request.is_none());
        assert!(record_ref(directory, "node-preserving-debug-publications", execution).is_none());
        std::fs::write(
            directory.join(format!("archive-refusal-{execution}.json")),
            encode(&retained).unwrap(),
        )
        .unwrap();
        attempted.push((target, retained));
    }
    std::fs::remove_file(&archive).unwrap();
    std::fs::rename(&saved, &archive).unwrap();

    // Recovered source bytes do not grant a second attempt to a retained claim.
    for (target, retained) in attempted {
        let unchanged = server.request(
            NodeControlRequest::preserving_debug_prepare("adverse/archive-repeat", target).unwrap(),
        );
        assert_eq!(encode(&unchanged).unwrap(), encode(&retained).unwrap());
    }
    assert_eq!(
        encode(&server.status(&source.execution, true)).unwrap(),
        original_source
    );
}
