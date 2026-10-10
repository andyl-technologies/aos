//! Owns the actor's actual later Quiescence and its prepaid failure storage.
//!
//! The fixed Node/host adapter authenticates the slot and supplies its retained
//! process contract. This owner derives from the decoder's same Preparation;
//! it accepts no allocator, timeout, alternative event or class policy.

use std::fmt;
use std::sync::Arc;

use crucible_linux_resource::host_services::{
    HostServiceError, HostServiceLease, HostServiceLeasePair,
};
use crucible_linux_resource::host_supervision::{
    HostOperationGuard, HostSupervisionError, OriginalQuiescenceStartError,
};

use super::OriginalActorParkCaller;
use crate::{QemuChildProcessContract, QemuSpawnError};

#[derive(Debug, thiserror::Error)]
enum EnteredCause {
    #[error("derive actual actor Quiescence: {0}")]
    Original(#[source] OriginalQuiescenceStartError),
    #[error("retain actor Quiescence event: {0}")]
    Supervision(#[source] HostSupervisionError),
    #[error("duplicate actual process cancellation: {0}")]
    Process(#[source] QemuSpawnError),
    #[error("admit actor Quiescence descriptor: {0}")]
    Account(#[source] HostServiceError),
}

struct EnteredState {
    operation: Option<HostOperationGuard>,
    first: Option<EnteredCause>,
    original_after: Option<HostSupervisionError>,
    original: Arc<HostOperationGuard>,
}

/// Retains the actual actor Pause, same Preparation and external original credit.
///
/// Only the fixed authenticated host adapter enters this operation. The daemon
/// provider retains it with the complete lifecycle until native relinquishment
/// or terminal containment. Dropping a facade is not physical retirement.
#[must_use = "retain with the complete phase owner through physical disposition"]
pub struct OriginalActorParkQuiescence {
    state: Box<EnteredState>,
    // The operation, subscriber, typed cause and Box close before this pair.
    _controls: HostServiceLeasePair,
}

/// Preserves refusal before or after the prepaid phase body is born.
#[derive(Debug, thiserror::Error)]
pub enum OriginalActorParkQuiescenceError {
    /// The fixed Node, host or decoder refused its actual retained identity.
    #[error("actor park binding refused: {first}; original: {original_after:?}")]
    Binding {
        /// Actual slot, decoder or host first cause.
        #[source]
        first: crate::OriginalActorAccountError,
        /// Independent same-original observation.
        original_after: Option<HostSupervisionError>,
    },
    /// The actual retained host could not lend its process contract.
    #[error("actor park contract refused: {first}; original: {original_after:?}")]
    Contract {
        /// Actual process/storage owner refusal.
        #[source]
        first: crate::QemuVmRealizationError,
        /// Independent same-original observation.
        original_after: Option<HostSupervisionError>,
    },
    /// No phase or descriptor effect entered before this actual refusal.
    #[error("actor Quiescence preflight refused: {first}; original: {original_after:?}")]
    Preflight {
        /// Actual original identity, interval or admission refusal.
        first: HostSupervisionError,
        /// Independent retained actor-original cut.
        original_after: Option<HostSupervisionError>,
    },
    /// Original paired accounts refused before any phase body was allocated.
    #[error("actor Quiescence controls refused: {first}; original: {original_after:?}")]
    Admission {
        /// Actual same-account refusal.
        first: HostServiceError,
        /// Independent retained actor-original cut.
        original_after: Option<HostSupervisionError>,
    },
    /// The same prepaid body retains the entered operation and first cause.
    #[error("entered actor Quiescence refused: {0}")]
    Entered(#[source] OriginalActorParkQuiescence),
}

impl fmt::Debug for OriginalActorParkQuiescence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OriginalActorParkQuiescence")
            .field("first", &self.state.first)
            .field("original_after", &self.state.original_after)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for OriginalActorParkQuiescence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "first: {:?}; original: {:?}",
            self.state.first, self.state.original_after,
        )
    }
}

impl std::error::Error for OriginalActorParkQuiescence {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.state.first.as_ref().map(|first| first as _)
    }
}

impl OriginalActorParkQuiescence {
    /// Invokes a fixed phase action while lending the actual retained guard.
    ///
    /// The result cannot borrow the guard. The separate postcut is observed
    /// even when the invoked action returns its own first refusal.
    ///
    /// # Errors
    /// Refuses consumed operation custody, actor expiry or event revocation
    /// before invoking the action. An entered refusal remains owned.
    pub fn with_quiescence<T>(
        &self,
        invoke: impl for<'guard> FnOnce(&'guard HostOperationGuard) -> T,
    ) -> Result<(T, Option<HostSupervisionError>), HostSupervisionError> {
        let operation = self
            .state
            .operation
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        operation.check_original_quiescence_cancellation()?;
        let outcome = invoke(operation);
        let post = operation.check_original_quiescence_cancellation().err();
        Ok((outcome, post))
    }

    /// Encodes the retained actor operation without replacing its interval.
    ///
    /// # Errors
    /// Refuses absent custody, actual actor expiry or subscriber revocation.
    pub fn serialize_quiescence_basis(&self) -> Result<[u8; 80], HostSupervisionError> {
        self.state
            .operation
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?
            .serialize_original_quiescence_basis()
    }
}

impl OriginalActorParkCaller {
    pub(crate) fn enter_park_quiescence(
        &self,
        original: &Arc<HostOperationGuard>,
        contract: &QemuChildProcessContract,
    ) -> Result<OriginalActorParkQuiescence, OriginalActorParkQuiescenceError> {
        let Some(authority) = &self.authority else {
            return Err(OriginalActorParkQuiescenceError::Preflight {
                first: HostSupervisionError::Unavailable,
                original_after: None,
            });
        };
        if !Arc::ptr_eq(original, &authority.original) {
            return Err(OriginalActorParkQuiescenceError::Preflight {
                first: HostSupervisionError::Unavailable,
                original_after: authority.original.wait_slice().err(),
            });
        }
        if let Err(first) = authority.original.wait_slice() {
            return Err(OriginalActorParkQuiescenceError::Preflight {
                first,
                original_after: authority.original.wait_slice().err(),
            });
        }

        // Pay the persistent Box plus construction overlap, its external
        // paired controls and the entered subscriber before any body/FD birth.
        let extent = std::mem::size_of::<EnteredState>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalActorParkQuiescence>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| {
                HostServiceLease::metadata_bytes()
                    .checked_mul(3)
                    .and_then(|controls| controls.checked_add(bytes))
                    .and_then(|bytes| {
                        bytes.checked_add(
                            HostOperationGuard::original_quiescence_cancellation_bytes(),
                        )
                    })
            })
            .ok_or_else(|| OriginalActorParkQuiescenceError::Admission {
                first: HostServiceError::CapacityExhausted,
                original_after: authority.original.wait_slice().err(),
            })?;
        let (resident, metadata) = authority
            .resident
            .reserve_paired_bytes(&authority.metadata, extent)
            .map_err(|first| OriginalActorParkQuiescenceError::Admission {
                first,
                original_after: authority.original.wait_slice().err(),
            })?;
        let controls = HostServiceLeasePair::new(resident, metadata);
        let mut entered = OriginalActorParkQuiescence {
            state: Box::new(EnteredState {
                operation: None,
                first: None,
                original_after: None,
                original: Arc::clone(original),
            }),
            _controls: controls,
        };

        let acquire = (|| {
            entered.state.operation = Some(
                original
                    .begin_original_quiescence()
                    .map_err(EnteredCause::Original)?,
            );
            let subscriber = authority
                .resident
                .reserve_resources(0, 1, 0)
                .map_err(EnteredCause::Account)?;
            let event = contract
                .try_clone_cancellation_event()
                .map_err(EnteredCause::Process)?;
            let operation = entered
                .state
                .operation
                .as_ref()
                .ok_or(EnteredCause::Supervision(HostSupervisionError::Unavailable))?;
            operation
                .retain_original_quiescence_cancellation(event, subscriber)
                .map_err(EnteredCause::Supervision)?;
            operation
                .check_original_quiescence_cancellation()
                .map_err(EnteredCause::Supervision)
        })();
        entered.state.original_after = entered.state.original.wait_slice().err();
        match acquire {
            Ok(()) if entered.state.original_after.is_none() => Ok(entered),
            Ok(()) => {
                entered.state.first = entered.state.original_after.map(EnteredCause::Supervision);
                Err(OriginalActorParkQuiescenceError::Entered(entered))
            }
            Err(first) => {
                entered.state.first = Some(first);
                Err(OriginalActorParkQuiescenceError::Entered(entered))
            }
        }
    }
}

/// Retains the sealed paired basis and same-process event through monitor custody.
///
/// The fixed host adapter constructs this only after both actual phase guards
/// and the live slot are checked. Imported descriptors remain owned here until
/// the enclosing complete world proves disposition or retires physically.
#[must_use = "retain with the phase until actual native disposition"]
pub struct OriginalActorParkImports {
    pub(crate) basis: std::os::fd::OwnedFd,
    pub(crate) cancellation: std::os::fd::OwnedFd,
    pub(crate) basis_name: crate::QmpDescriptorName,
    pub(crate) cancellation_name: crate::QmpDescriptorName,
    _descriptors: HostServiceLease,
    _controls: HostServiceLeasePair,
}

/// Retains the exact import admission or physical descriptor first cause.
#[derive(Debug, thiserror::Error)]
pub enum OriginalActorParkImportError {
    /// The actual host could not lend its retained process contract.
    #[error(transparent)]
    Owner(#[from] crate::QemuVmRealizationError),
    /// The real decoder or original identity refused.
    #[error(transparent)]
    Binding(#[from] crate::OriginalActorAccountError),
    /// The actual same-account byte or descriptor reservation refused.
    #[error(transparent)]
    Account(#[from] HostServiceError),
    /// Either actual entered operation or subscriber refused.
    #[error(transparent)]
    Supervision(#[from] HostSupervisionError),
    /// The actual process event duplication refused.
    #[error(transparent)]
    Process(#[from] QemuSpawnError),
    /// The actual basis descriptor operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A fixed public descriptor name could not be encoded.
    #[error(transparent)]
    Command(#[from] crate::QmpError),
}

impl OriginalActorParkCaller {
    pub(crate) fn prepare_park_imports(
        &self,
        original: &Arc<HostOperationGuard>,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
        contract: &QemuChildProcessContract,
    ) -> Result<OriginalActorParkImports, OriginalActorParkImportError> {
        use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
        use std::io::Write;

        self.verify_original(original)?;
        let basis_bytes =
            crate::qmp::parent_park_drain::encode_parent_park_drain_basis(actor, family)?;
        let authority = self
            .authority
            .as_ref()
            .ok_or(crate::OriginalActorAccountError::Unavailable)?;
        // One real memfd page, fixed paired body and names, construction
        // overlap and all three external lease controls precede either FD.
        let bytes = (2 * std::mem::size_of::<OriginalActorParkImports>() + 176 + 64) as u64
            + u64::try_from(rustix::param::page_size())
                .map_err(|_| crate::OriginalActorAccountError::Unavailable)?
            + 3 * HostServiceLease::metadata_bytes();
        let (resident, metadata) = authority
            .resident
            .reserve_paired_bytes(&authority.metadata, bytes)?;
        let controls = HostServiceLeasePair::new(resident, metadata);
        let descriptors = authority.resident.reserve_resources(0, 2, 0)?;
        let basis_name = crate::QmpDescriptorName::new("original-park-pair-v1")?;
        let cancellation_name = crate::QmpDescriptorName::new("original-park-event-v1")?;
        let descriptor = memfd_create(
            "crucible-parent-park-pair",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .map_err(std::io::Error::from)?;
        let mut file = std::fs::File::from(descriptor);
        file.write_all(&basis_bytes)?;
        fcntl_add_seals(
            &file,
            SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
        )
        .map_err(std::io::Error::from)?;
        let cancellation = contract.try_clone_cancellation_event()?;
        let actor_after = actor.check_original_quiescence_cancellation();
        let family_after = family.check_original_quiescence_cancellation();
        actor_after.and(family_after)?;
        Ok(OriginalActorParkImports {
            basis: file.into(),
            cancellation,
            basis_name,
            cancellation_name,
            _descriptors: descriptors,
            _controls: controls,
        })
    }
}
