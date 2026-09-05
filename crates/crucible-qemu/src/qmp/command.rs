//! Closed typed QMP command vocabulary and exact JSON request encoding.
//!
//! Only the operations represented here can reach the machine-control stream.
//! Each request retains its command kind for bounded response authentication.
//!
//! ```json
//! {"execute":"query-status"}
//! ```

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkPluginBarrierAction {
    Hold,
    Query,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkRcuBarrierAction {
    Hold,
    Query,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkBhTimerBarrierAction {
    Hold,
    Query,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkBlockBarrierAction {
    Hold,
    Query,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkTemplateAction {
    Prepare,
    Query,
    Abort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkPrivateRingAction {
    Stage,
    Query,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkPluginEndpointAction {
    Stage,
    Query,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkChildDiagnosticAction {
    Stage,
    Query,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkChildQmpAction {
    Stage,
    Query,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HotForkChildConsoleAction {
    Stage,
    Query,
    Release,
}

impl HotForkTemplateAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Query => "query",
            Self::Abort => "abort",
        }
    }
}

impl HotForkPrivateRingAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

impl HotForkPluginEndpointAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

impl HotForkChildDiagnosticAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

impl HotForkChildQmpAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

impl HotForkChildConsoleAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

impl HotForkPluginBarrierAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

impl HotForkRcuBarrierAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

impl HotForkBhTimerBarrierAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

impl HotForkBlockBarrierAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Query => "query",
            Self::Release => "release",
        }
    }
}

pub(super) enum QmpCommand<'a> {
    Capabilities,
    SaveVm {
        tag: &'a QmpSnapshotTag,
        job_id: &'a str,
    },
    LoadVm {
        tag: &'a QmpSnapshotTag,
        job_id: &'a str,
    },
    DeleteSnapshot {
        tag: &'a QmpSnapshotTag,
        job_id: &'a str,
    },
    QueryJobs,
    JobDismiss {
        job_id: &'a str,
    },
    QueryStatus,
    Stop,
    Cont,
    CompleteTerminalLifecycle {
        action: crucible::ContentHash,
        evidence: crucible::ContentHash,
        process_generation: u64,
    },
    QueryCpusFast,
    QueryHotForkReadiness,
    QueryHotForkThreadInventory,
    QueryHotForkRcuInventory,
    QueryHotForkAioInventory,
    QueryHotForkAioHandlerInventory,
    QueryHotForkBlockBackendInventory,
    QueryHotForkPluginResourceInventory,
    QueryHotForkChildRuntime,
    HotForkPluginBarrier {
        action: HotForkPluginBarrierAction,
    },
    HotForkRcuBarrier {
        action: HotForkRcuBarrierAction,
    },
    HotForkBhTimerBarrier {
        action: HotForkBhTimerBarrierAction,
    },
    HotForkBlockBarrier {
        action: HotForkBlockBarrierAction,
    },
    HotForkTemplate {
        action: HotForkTemplateAction,
        block_snapshot_bindings: Option<&'a [QmpHotForkBlockSnapshotBinding]>,
    },
    HotFork {
        request: QmpHotForkRequest,
    },
    HotForkChildProcess {
        action: HotForkChildProcessAction,
        generation: u64,
    },
    HotForkChildProcessContract {
        action: HotForkChildProcessContractAction,
        cgroup_name: Option<&'a QmpDescriptorName>,
        cancellation_name: Option<&'a QmpDescriptorName>,
        identity: Option<QmpHotForkChildProcessContractIdentity>,
    },
    HotForkPrivateRings {
        action: HotForkPrivateRingAction,
        name: Option<&'a QmpDescriptorName>,
        identity: Option<SetupRegionBackingIdentity>,
    },
    HotForkPluginEndpoints {
        action: HotForkPluginEndpointAction,
        control_name: Option<&'a QmpDescriptorName>,
        wake_name: Option<&'a QmpDescriptorName>,
        identity: Option<QmpHotForkPluginEndpointIdentity>,
    },
    HotForkChildDiagnostics {
        action: HotForkChildDiagnosticAction,
        name: Option<&'a QmpDescriptorName>,
        socket_cookie: Option<u64>,
    },
    HotForkChildQmp {
        action: HotForkChildQmpAction,
        name: Option<&'a QmpDescriptorName>,
        socket_cookie: Option<u64>,
    },
    HotForkChildConsole {
        action: HotForkChildConsoleAction,
        name: Option<&'a QmpDescriptorName>,
        socket_cookie: Option<u64>,
    },
    QueryHotForkBottomHalfInventory,
    QueryHotForkMutexInventory,
    QueryHotForkTimerInventory,
    QueryHotForkMonitorInventory,
    Quit,
    GetFd {
        name: &'a QmpDescriptorName,
    },
    CloseFd {
        name: &'a QmpDescriptorName,
    },
}

impl QmpCommand<'_> {
    pub(super) const fn kind(&self) -> QmpCommandKind {
        match self {
            Self::Capabilities => QmpCommandKind::Capabilities,
            Self::SaveVm { .. } => QmpCommandKind::SaveVm,
            Self::LoadVm { .. } => QmpCommandKind::LoadVm,
            Self::DeleteSnapshot { .. } => QmpCommandKind::DeleteSnapshot,
            Self::QueryJobs => QmpCommandKind::QueryJobs,
            Self::JobDismiss { .. } => QmpCommandKind::JobDismiss,
            Self::QueryStatus => QmpCommandKind::QueryStatus,
            Self::Stop => QmpCommandKind::Stop,
            Self::Cont => QmpCommandKind::Cont,
            Self::CompleteTerminalLifecycle { .. } => QmpCommandKind::CompleteTerminalLifecycle,
            Self::QueryCpusFast => QmpCommandKind::QueryCpusFast,
            Self::QueryHotForkReadiness => QmpCommandKind::QueryHotForkReadiness,
            Self::QueryHotForkThreadInventory => QmpCommandKind::QueryHotForkThreadInventory,
            Self::QueryHotForkRcuInventory => QmpCommandKind::QueryHotForkRcuInventory,
            Self::QueryHotForkAioInventory => QmpCommandKind::QueryHotForkAioInventory,
            Self::QueryHotForkAioHandlerInventory => {
                QmpCommandKind::QueryHotForkAioHandlerInventory
            }
            Self::QueryHotForkBlockBackendInventory => {
                QmpCommandKind::QueryHotForkBlockBackendInventory
            }
            Self::QueryHotForkPluginResourceInventory => {
                QmpCommandKind::QueryHotForkPluginResourceInventory
            }
            Self::QueryHotForkChildRuntime => QmpCommandKind::QueryHotForkChildRuntime,
            Self::HotForkPluginBarrier { .. } => QmpCommandKind::HotForkPluginBarrier,
            Self::HotForkRcuBarrier { .. } => QmpCommandKind::HotForkRcuBarrier,
            Self::HotForkBhTimerBarrier { .. } => QmpCommandKind::HotForkBhTimerBarrier,
            Self::HotForkBlockBarrier { .. } => QmpCommandKind::HotForkBlockBarrier,
            Self::HotForkTemplate { .. } => QmpCommandKind::HotForkTemplate,
            Self::HotFork { .. } => QmpCommandKind::HotFork,
            Self::HotForkChildProcess { .. } => QmpCommandKind::HotForkChildProcess,
            Self::HotForkChildProcessContract { .. } => QmpCommandKind::HotForkChildProcessContract,
            Self::HotForkPrivateRings { .. } => QmpCommandKind::HotForkPrivateRings,
            Self::HotForkPluginEndpoints { .. } => QmpCommandKind::HotForkPluginEndpoints,
            Self::HotForkChildDiagnostics { .. } => QmpCommandKind::HotForkChildDiagnostics,
            Self::HotForkChildQmp { .. } => QmpCommandKind::HotForkChildQmp,
            Self::HotForkChildConsole { .. } => QmpCommandKind::HotForkChildConsole,
            Self::QueryHotForkBottomHalfInventory => {
                QmpCommandKind::QueryHotForkBottomHalfInventory
            }
            Self::QueryHotForkMutexInventory => QmpCommandKind::QueryHotForkMutexInventory,
            Self::QueryHotForkTimerInventory => QmpCommandKind::QueryHotForkTimerInventory,
            Self::QueryHotForkMonitorInventory => QmpCommandKind::QueryHotForkMonitorInventory,
            Self::Quit => QmpCommandKind::Quit,
            Self::GetFd { .. } => QmpCommandKind::GetFd,
            Self::CloseFd { .. } => QmpCommandKind::CloseFd,
        }
    }

    pub(super) fn request(&self) -> Value {
        match self {
            Self::Capabilities => json!({
                "execute": QMP_CAPABILITIES_COMMAND,
                "arguments": {
                    "enable": ["oob"],
                },
            }),
            Self::SaveVm { tag, job_id } => {
                snapshot_request(QMP_SNAPSHOT_SAVE_COMMAND, job_id, tag)
            }
            Self::LoadVm { tag, job_id } => {
                snapshot_request(QMP_SNAPSHOT_LOAD_COMMAND, job_id, tag)
            }
            Self::DeleteSnapshot { tag, job_id } => json!({
                "execute": QMP_SNAPSHOT_DELETE_COMMAND,
                "arguments": {
                    "job-id": job_id,
                    "tag": tag.as_str(),
                    "devices": [QMP_SNAPSHOT_VMSTATE_DEVICE],
                },
            }),
            Self::QueryJobs => json!({
                "execute": QMP_QUERY_JOBS_COMMAND,
            }),
            Self::JobDismiss { job_id } => json!({
                "execute": QMP_JOB_DISMISS_COMMAND,
                "arguments": { "id": job_id },
            }),
            Self::QueryStatus => json!({
                "execute": QMP_QUERY_STATUS_COMMAND,
            }),
            Self::Stop => json!({
                "execute": QMP_STOP_COMMAND,
            }),
            Self::Cont => json!({
                "execute": QMP_CONT_COMMAND,
            }),
            Self::CompleteTerminalLifecycle {
                action,
                evidence,
                process_generation,
            } => json!({
                "execute": QMP_COMPLETE_TERMINAL_LIFECYCLE_COMMAND,
                "arguments": {
                    "action-sha256": action.to_hex(),
                    "evidence-sha256": evidence.to_hex(),
                    "process-generation": process_generation,
                },
            }),
            Self::QueryCpusFast => json!({
                "execute": QMP_QUERY_CPUS_FAST_COMMAND,
            }),
            Self::QueryHotForkReadiness => json!({
                "execute": QMP_QUERY_HOT_FORK_READINESS_COMMAND,
            }),
            Self::QueryHotForkThreadInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkRcuInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkAioInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkAioHandlerInventory => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_AIO_HANDLER_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkBlockBackendInventory => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_BLOCK_BACKEND_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkPluginResourceInventory => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkChildRuntime => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_CHILD_RUNTIME_COMMAND,
            }),
            Self::HotForkPluginBarrier { action } => json!({
                "exec-oob": QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND,
                "arguments": {
                    "action": action.wire_name(),
                },
            }),
            Self::HotForkRcuBarrier { action } => json!({
                "exec-oob": QMP_HOT_FORK_RCU_BARRIER_COMMAND,
                "arguments": {
                    "action": action.wire_name(),
                },
            }),
            Self::HotForkBhTimerBarrier { action } => json!({
                "exec-oob": QMP_HOT_FORK_BH_TIMER_BARRIER_COMMAND,
                "arguments": {
                    "action": action.wire_name(),
                },
            }),
            Self::HotForkBlockBarrier { action } => json!({
                "execute": QMP_HOT_FORK_BLOCK_BARRIER_COMMAND,
                "arguments": {
                    "action": action.wire_name(),
                },
            }),
            Self::HotForkTemplate {
                action,
                block_snapshot_bindings,
            } => {
                let mut arguments = serde_json::Map::new();
                arguments.insert(
                    String::from("action"),
                    Value::String(action.wire_name().to_owned()),
                );
                if let Some(bindings) = block_snapshot_bindings {
                    arguments.insert(
                        String::from("block-snapshot-bindings"),
                        Value::Array(
                            bindings
                                .iter()
                                .map(QmpHotForkBlockSnapshotBinding::wire_value)
                                .collect(),
                        ),
                    );
                }
                json!({
                    "exec-oob": QMP_HOT_FORK_TEMPLATE_COMMAND,
                    "arguments": Value::Object(arguments),
                })
            }
            Self::HotFork { request } => json!({
                "exec-oob": QMP_HOT_FORK_COMMAND,
                "arguments": request.wire_value(),
            }),
            Self::HotForkChildProcess { action, generation } => json!({
                "exec-oob": QMP_HOT_FORK_CHILD_PROCESS_COMMAND,
                "arguments": {
                    "action": action.wire_name(),
                    "generation": generation,
                },
            }),
            Self::HotForkChildProcessContract {
                action,
                cgroup_name,
                cancellation_name,
                identity,
            } => {
                let mut arguments = serde_json::Map::new();
                arguments.insert(
                    String::from("action"),
                    Value::String(action.wire_name().to_owned()),
                );
                if let Some(name) = cgroup_name {
                    arguments.insert(
                        String::from("cgroup-fdname"),
                        Value::String(name.as_str().to_owned()),
                    );
                }
                if let Some(name) = cancellation_name {
                    arguments.insert(
                        String::from("cancellation-fdname"),
                        Value::String(name.as_str().to_owned()),
                    );
                }
                if let Some(identity) = identity {
                    arguments.insert(
                        String::from("expected-cgroup-device"),
                        Value::from(identity.cgroup_device()),
                    );
                    arguments.insert(
                        String::from("expected-cgroup-inode"),
                        Value::from(identity.cgroup_inode()),
                    );
                    arguments.insert(
                        String::from("expected-cancellation-eventfd-id"),
                        Value::from(identity.cancellation_eventfd_id()),
                    );
                    arguments.insert(
                        String::from("maximum-file-bytes"),
                        Value::from(identity.maximum_file_bytes()),
                    );
                }
                json!({
                    "exec-oob": QMP_HOT_FORK_CHILD_PROCESS_CONTRACT_COMMAND,
                    "arguments": Value::Object(arguments),
                })
            }
            Self::HotForkPrivateRings {
                action,
                name,
                identity,
            } => {
                let mut arguments = serde_json::Map::new();
                arguments.insert(
                    String::from("action"),
                    Value::String(action.wire_name().to_owned()),
                );
                if let Some(name) = name {
                    arguments.insert(
                        String::from("fdname"),
                        Value::String(name.as_str().to_owned()),
                    );
                }
                if let Some(identity) = identity {
                    arguments.insert(
                        String::from("expected-device"),
                        Value::from(identity.device()),
                    );
                    arguments.insert(
                        String::from("expected-inode"),
                        Value::from(identity.inode()),
                    );
                    arguments.insert(
                        String::from("expected-length"),
                        Value::from(identity.length()),
                    );
                }
                json!({
                    "exec-oob": QMP_HOT_FORK_PRIVATE_RINGS_COMMAND,
                    "arguments": Value::Object(arguments),
                })
            }
            Self::HotForkPluginEndpoints {
                action,
                control_name,
                wake_name,
                identity,
            } => {
                let mut arguments = serde_json::Map::new();
                arguments.insert(
                    String::from("action"),
                    Value::String(action.wire_name().to_owned()),
                );
                if let Some(control_name) = control_name {
                    arguments.insert(
                        String::from("control-fdname"),
                        Value::String(control_name.as_str().to_owned()),
                    );
                }
                if let Some(wake_name) = wake_name {
                    arguments.insert(
                        String::from("wake-fdname"),
                        Value::String(wake_name.as_str().to_owned()),
                    );
                }
                if let Some(identity) = identity {
                    arguments.insert(
                        String::from("expected-control-socket-cookie"),
                        Value::from(identity.control_socket_cookie()),
                    );
                    arguments.insert(
                        String::from("expected-wake-eventfd-id"),
                        Value::from(identity.wake_eventfd_id()),
                    );
                }
                json!({
                    "exec-oob": QMP_HOT_FORK_PLUGIN_ENDPOINTS_COMMAND,
                    "arguments": Value::Object(arguments),
                })
            }
            Self::HotForkChildDiagnostics {
                action,
                name,
                socket_cookie,
            } => {
                let mut arguments = serde_json::Map::new();
                arguments.insert(
                    String::from("action"),
                    Value::String(action.wire_name().to_owned()),
                );
                if let Some(name) = name {
                    arguments.insert(
                        String::from("fdname"),
                        Value::String(name.as_str().to_owned()),
                    );
                }
                if let Some(socket_cookie) = socket_cookie {
                    arguments.insert(
                        String::from("expected-socket-cookie"),
                        Value::from(*socket_cookie),
                    );
                }
                json!({
                    "exec-oob": QMP_HOT_FORK_CHILD_DIAGNOSTICS_COMMAND,
                    "arguments": Value::Object(arguments),
                })
            }
            Self::HotForkChildQmp {
                action,
                name,
                socket_cookie,
            } => {
                let mut arguments = serde_json::Map::new();
                arguments.insert(
                    String::from("action"),
                    Value::String(action.wire_name().to_owned()),
                );
                if let Some(name) = name {
                    arguments.insert(
                        String::from("fdname"),
                        Value::String(name.as_str().to_owned()),
                    );
                }
                if let Some(socket_cookie) = socket_cookie {
                    arguments.insert(
                        String::from("expected-socket-cookie"),
                        Value::from(*socket_cookie),
                    );
                }
                json!({
                    "exec-oob": QMP_HOT_FORK_CHILD_QMP_COMMAND,
                    "arguments": Value::Object(arguments),
                })
            }
            Self::HotForkChildConsole {
                action,
                name,
                socket_cookie,
            } => {
                let mut arguments = serde_json::Map::new();
                arguments.insert(
                    String::from("action"),
                    Value::String(action.wire_name().to_owned()),
                );
                if let Some(name) = name {
                    arguments.insert(
                        String::from("fdname"),
                        Value::String(name.as_str().to_owned()),
                    );
                }
                if let Some(socket_cookie) = socket_cookie {
                    arguments.insert(
                        String::from("expected-socket-cookie"),
                        Value::from(*socket_cookie),
                    );
                }
                json!({
                    "exec-oob": QMP_HOT_FORK_CHILD_CONSOLE_COMMAND,
                    "arguments": Value::Object(arguments),
                })
            }
            Self::QueryHotForkBottomHalfInventory => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_BOTTOM_HALF_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkMutexInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkTimerInventory => json!({
                "execute": QMP_QUERY_HOT_FORK_TIMER_INVENTORY_COMMAND,
            }),
            Self::QueryHotForkMonitorInventory => json!({
                "exec-oob": QMP_QUERY_HOT_FORK_MONITOR_INVENTORY_COMMAND,
            }),
            Self::Quit => json!({
                "execute": QMP_QUIT_COMMAND_NAME,
            }),
            Self::GetFd { name } => json!({
                "execute": QMP_GETFD_COMMAND,
                "arguments": { "fdname": name.as_str() },
            }),
            Self::CloseFd { name } => json!({
                "execute": QMP_CLOSEFD_COMMAND,
                "arguments": { "fdname": name.as_str() },
            }),
        }
    }
}

fn snapshot_request(command: &'static str, job_id: &str, tag: &QmpSnapshotTag) -> Value {
    json!({
        "execute": command,
        "arguments": {
            "job-id": job_id,
            "tag": tag.as_str(),
            "vmstate": QMP_SNAPSHOT_VMSTATE_DEVICE,
            "devices": [QMP_SNAPSHOT_VMSTATE_DEVICE],
        },
    })
}
