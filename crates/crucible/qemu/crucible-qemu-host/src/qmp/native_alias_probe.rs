//! Qualification-only attempts to substitute real source objects for private stages.
//!
//! Explicit native rejection is followed by an unchanged typed stage query and
//! exact monitor close acknowledgement. Transport uncertainty keeps caller
//! custody; no rejection or release proof is synthesized from an error string.

use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::node::QemuTestNativeAliasKind;

static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Stage {
    Ring(QmpHotForkPrivateRingState),
    Endpoints(QmpHotForkPluginEndpointState),
    Console(QmpHotForkChildConsoleState),
    Files(QmpHotForkChildFilesState),
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(super) fn probe_native_source_alias(
        &mut self,
        kind: QemuTestNativeAliasKind,
        descriptor: BorrowedFd<'_>,
    ) -> Result<QemuNodeChannelError, QmpError> {
        let sequence = PROBE_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| QmpError::InvalidBound {
                operation: "native alias probe sequence",
            })?;
        let name = QmpDescriptorName::new(format!("crucible-hfork-alias-probe-{sequence:016x}"))?;
        let before = self.native_alias_probe_stage(kind)?;
        self.install_descriptor(&name, descriptor)?;
        let command = match &before {
            Stage::Ring(state) => QmpCommand::HotForkPrivateRings {
                action: HotForkPrivateRingAction::Stage,
                name: Some(&name),
                identity: SetupRegionBackingIdentity::from_parts(
                    state.device(),
                    state.inode(),
                    state.length(),
                ),
            },
            Stage::Endpoints(state) => QmpCommand::HotForkPluginEndpoints {
                action: HotForkPluginEndpointAction::Stage,
                control_name: if kind == QemuTestNativeAliasKind::Control {
                    Some(&name)
                } else {
                    state.control_name()
                },
                wake_name: if kind == QemuTestNativeAliasKind::Wake {
                    Some(&name)
                } else {
                    state.wake_name()
                },
                identity: state.identity(),
            },
            Stage::Console(_) => QmpCommand::HotForkChildConsole {
                action: HotForkChildConsoleAction::Stage,
                name: Some(&name),
                socket_cookie: Some(rustix::net::sockopt::socket_cookie(descriptor).map_err(
                    |source| QmpError::Io {
                        operation: "inspect actual diagnostic alias cookie",
                        kind: std::io::Error::from(source).kind(),
                    },
                )?),
            },
            Stage::Files(_) => {
                let metadata = rustix::fs::fstat(descriptor).map_err(|source| QmpError::Io {
                    operation: "inspect actual source file alias",
                    kind: std::io::Error::from(source).kind(),
                })?;
                let file = QmpHotForkChildFile::new(
                    QmpHotForkChildFileRoot::node_name(crate::DEFAULT_VMSTATE_NODE_NAME)?,
                    name.clone(),
                    metadata.st_dev,
                    metadata.st_ino,
                )?;
                return self.probe_native_file_alias(kind, &name, before, file);
            }
        };
        let result = self.send_command_return(command);
        self.finish_native_alias_probe(kind, &name, before, result)
    }

    fn probe_native_file_alias(
        &mut self,
        kind: QemuTestNativeAliasKind,
        name: &QmpDescriptorName,
        before: Stage,
        file: QmpHotForkChildFile,
    ) -> Result<QemuNodeChannelError, QmpError> {
        let files = [file];
        let result = self.send_command_return(QmpCommand::HotForkChildFiles {
            action: HotForkChildFilesAction::Stage,
            files: Some(&files),
            maximum_bytes: Some(1),
            expected_generation: None,
        });
        self.finish_native_alias_probe(kind, name, before, result)
    }

    fn finish_native_alias_probe(
        &mut self,
        kind: QemuTestNativeAliasKind,
        name: &QmpDescriptorName,
        before: Stage,
        result: Result<QmpCommandReturn, QmpError>,
    ) -> Result<QemuNodeChannelError, QmpError> {
        let (command, class, description) = match result {
            Err(QmpError::Command {
                command,
                class,
                description,
            }) => (command, class, description),
            Err(error) => return Err(error),
            Ok(response) => {
                return Err(QmpError::MalformedTypedResponse {
                    command: response.command,
                    response: String::from("actual native source alias was accepted"),
                });
            }
        };
        let expected_rejection = match kind {
            QemuTestNativeAliasKind::Ring => "private-ring descriptor identity mismatch",
            QemuTestNativeAliasKind::Control | QemuTestNativeAliasKind::Wake => {
                "plugin endpoint identity mismatch"
            }
            QemuTestNativeAliasKind::ConsoleDiagnostics => "child console aliases another",
            QemuTestNativeAliasKind::WritableDisk => "empty writable regular file",
            QemuTestNativeAliasKind::NetworkScope | QemuTestNativeAliasKind::NinepScope => {
                "unavailable host scope"
            }
        };
        if self.native_alias_probe_stage(kind)? != before {
            return Err(QmpError::MalformedTypedResponse {
                command,
                response: String::from("native alias refusal changed the retained stage"),
            });
        }
        self.close_descriptor(name)?;
        // Initial source wake objects may be blocking. Their duplicated file
        // description must be rejected without changing the source flags.
        let source_wake_flags_rejected =
            kind == QemuTestNativeAliasKind::Wake && description.contains("not nonblocking");
        if !description.contains(expected_rejection) && !source_wake_flags_rejected {
            return Err(QmpError::MalformedTypedResponse {
                command,
                response: format!("native alias request refused at another stage: {description}"),
            });
        }
        Ok(QemuNodeChannelError::from(QmpError::Command {
            command,
            class,
            description,
        }))
    }

    fn native_alias_probe_stage(
        &mut self,
        kind: QemuTestNativeAliasKind,
    ) -> Result<Stage, QmpError> {
        match kind {
            QemuTestNativeAliasKind::Ring => self.query_hot_fork_private_rings().map(Stage::Ring),
            QemuTestNativeAliasKind::Control | QemuTestNativeAliasKind::Wake => {
                self.query_hot_fork_plugin_endpoints().map(Stage::Endpoints)
            }
            QemuTestNativeAliasKind::ConsoleDiagnostics => {
                self.query_hot_fork_child_console().map(Stage::Console)
            }
            QemuTestNativeAliasKind::WritableDisk => {
                self.query_hot_fork_child_files().map(Stage::Files)
            }
            QemuTestNativeAliasKind::NetworkScope | QemuTestNativeAliasKind::NinepScope => {
                Err(QmpError::InvalidBound {
                    operation: "native alias host reader scope",
                })
            }
        }
    }
}
