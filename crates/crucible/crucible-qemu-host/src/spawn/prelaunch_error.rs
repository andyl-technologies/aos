//! Closed causes from credential inspection and descriptor-pinned preparation.
//!
//! These operations precede process birth and cannot return a plugin startup
//! failure or retain a launched child. Conversion to the public spawn error
//! moves each original payload without allocating another diagnostic carrier.

use super::QemuSpawnError;
use thiserror::Error;

/// Reports an actual credential or pinned-directory preparation refusal.
#[derive(Debug, Error)]
pub(crate) enum QemuPrelaunchError {
    /// The active configuration account refused group-inventory storage.
    #[error("QEMU configuration admission refused: {0}")]
    ConfigurationAdmission(#[source] crucible_engine::owned_decode::DecodeAdmissionError),
    /// The supervisor group inventory exceeded its fixed supported bound.
    #[error("supervisor supplementary groups exceed the supported bound")]
    SupervisorGroupLimit,
    /// The supervisor group inventory changed during inspection.
    #[error("supervisor supplementary groups changed while inspected")]
    SupervisorGroupsChanged,
    /// The child would retain root or a supervisor credential.
    #[error(
        "QEMU child credentials must be non-root and distinct from the supervisor: {user_id}:{group_id}"
    )]
    InvalidChildCredentials {
        /// Requested child user ID.
        user_id: libc::uid_t,
        /// Requested child group ID.
        group_id: libc::gid_t,
    },
    /// The launch requirements exceeded the original process contract.
    #[error("QEMU launch exceeds admitted attempt resources: {source}")]
    LaunchResources {
        /// The unchanged resource-ceiling mismatch.
        source: crate::QemuLaunchResourceError,
    },
    /// An inspection or descriptor operation failed.
    #[error("{operation} failed: {source}")]
    Io {
        /// Original static operation label.
        operation: &'static str,
        /// Original system or file-policy error.
        source: std::io::Error,
    },
}

impl QemuPrelaunchError {
    pub(super) fn last_io_error(operation: &'static str) -> Self {
        Self::Io {
            operation,
            source: std::io::Error::last_os_error(),
        }
    }

    pub(super) fn invalid_input(operation: &'static str, message: &'static str) -> Self {
        Self::Io {
            operation,
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, message),
        }
    }
}

impl From<QemuPrelaunchError> for QemuSpawnError {
    fn from(source: QemuPrelaunchError) -> Self {
        match source {
            QemuPrelaunchError::ConfigurationAdmission(source) => {
                Self::ConfigurationAdmission(source)
            }
            QemuPrelaunchError::SupervisorGroupLimit => Self::SupervisorGroupLimit,
            QemuPrelaunchError::SupervisorGroupsChanged => Self::SupervisorGroupsChanged,
            QemuPrelaunchError::InvalidChildCredentials { user_id, group_id } => {
                Self::InvalidChildCredentials { user_id, group_id }
            }
            QemuPrelaunchError::LaunchResources { source } => Self::LaunchResources { source },
            QemuPrelaunchError::Io { operation, source } => Self::Io { operation, source },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::test_support::TestAllocationObserver;
    use std::error::Error as _;

    #[test]
    fn closed_prelaunch_conversion_retains_all_causes_without_allocating() {
        let io = std::io::Error::other(std::io::Error::from_raw_os_error(libc::EIO));
        let io_payload = io.get_ref().unwrap() as *const _;
        let admission = crucible_engine::owned_decode::DecodeAdmissionError::new(
            std::io::Error::from_raw_os_error(libc::ENOSPC),
        );
        let admission_payload = admission.source().unwrap() as *const _;
        let cases = [
            QemuPrelaunchError::Io {
                operation: "inspect prepared QEMU run directory",
                source: io,
            },
            QemuPrelaunchError::ConfigurationAdmission(admission),
            QemuPrelaunchError::SupervisorGroupLimit,
            QemuPrelaunchError::SupervisorGroupsChanged,
            QemuPrelaunchError::InvalidChildCredentials {
                user_id: 123,
                group_id: 456,
            },
            QemuPrelaunchError::LaunchResources {
                source: crate::QemuLaunchResourceError::VirtualCpus {
                    required: 8,
                    admitted: 4,
                },
            },
            QemuPrelaunchError::LaunchResources {
                source: crate::QemuLaunchResourceError::ResidentBytes {
                    required: 8192,
                    admitted: 4096,
                },
            },
            QemuPrelaunchError::LaunchResources {
                source: crate::QemuLaunchResourceError::WritableBytes {
                    required: 16384,
                    admitted: 8192,
                },
            },
        ];

        for first in cases {
            let display = first.to_string();
            let (converted, counts) = TestAllocationObserver::count(|| QemuSpawnError::from(first));

            assert_eq!(counts.allocations, 0);
            assert_eq!(counts.reallocations, 0);
            assert!(!counts.overflow);
            assert_eq!(converted.to_string(), display);
            match &converted {
                QemuSpawnError::Io { operation, source } => {
                    assert_eq!(*operation, "inspect prepared QEMU run directory");
                    assert!(std::ptr::eq(source.get_ref().unwrap(), io_payload));
                    assert_eq!(
                        source
                            .get_ref()
                            .unwrap()
                            .downcast_ref::<std::io::Error>()
                            .unwrap()
                            .raw_os_error(),
                        Some(libc::EIO),
                    );
                }
                QemuSpawnError::ConfigurationAdmission(source) => {
                    assert!(std::ptr::eq(source.source().unwrap(), admission_payload));
                    assert_eq!(
                        source
                            .source()
                            .unwrap()
                            .downcast_ref::<std::io::Error>()
                            .unwrap()
                            .raw_os_error(),
                        Some(libc::ENOSPC),
                    );
                }
                QemuSpawnError::InvalidChildCredentials { user_id, group_id } => {
                    assert_eq!((*user_id, *group_id), (123, 456));
                }
                QemuSpawnError::LaunchResources { source } => {
                    assert!(
                        converted
                            .source()
                            .unwrap()
                            .downcast_ref::<crate::QemuLaunchResourceError>()
                            .is_some()
                    );
                    match source {
                        crate::QemuLaunchResourceError::VirtualCpus { required, admitted } => {
                            assert_eq!((*required, *admitted), (8, 4));
                        }
                        crate::QemuLaunchResourceError::ResidentBytes { required, admitted } => {
                            assert_eq!((*required, *admitted), (8192, 4096));
                        }
                        crate::QemuLaunchResourceError::WritableBytes { required, admitted } => {
                            assert_eq!((*required, *admitted), (16384, 8192));
                        }
                    }
                }
                QemuSpawnError::SupervisorGroupLimit | QemuSpawnError::SupervisorGroupsChanged => {
                    assert!(converted.source().is_none());
                }
                _ => panic!("prelaunch conversion must retain the original concrete variant"),
            }
        }
    }
}
