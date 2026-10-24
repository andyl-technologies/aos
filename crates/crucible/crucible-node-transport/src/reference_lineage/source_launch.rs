//! Allocates the complete original source holder before provider spawn.
//!
//! The private unstarted holder is never published as an original guard. A
//! successful spawn installs the actual Child immediately, before any identity
//! validation can fail. Post-spawn refusal returns the same owning capsule.

use std::{os::unix::process::CommandExt, process::Command};

use super::*;

/// Preserves the original reservation or spawned owner on launcher refusal.
pub enum LineageSourceLaunchFailure {
    /// Retains an unused reservation after validation or actual spawn refusal.
    BeforeSpawn {
        /// Reports refusal before a successfully returned original Child.
        error: ProviderError,
        /// Returns the same preallocated source supervisory obligation.
        slot: Box<dyn LineageSourceCustodySlot>,
    },
    /// Retains the actual original Child and its complete source capsule.
    AfterSpawn(LineageSourceFailure),
}

impl LineageSourceGuard {
    /// Allocates original source storage and then spawns one actual provider.
    ///
    /// This low-level owning primitive grants no source or behavioral authority.
    /// A trusted launcher supplies the independently measured executable and
    /// reserves its whole runtime and complete reader slots before calling it.
    /// It configures a new process group itself, preserving distinct native
    /// companion custody. The legacy consuming [`Self::new`] remains unchanged.
    ///
    /// # Errors
    /// Returns the same unused slot on pre-spawn validation or spawn refusal,
    /// and the same actual Child/slot on any original identity or byte mismatch.
    pub fn spawn_reserved(
        command: &mut Command,
        directory: PathBuf,
        expected_provider: ContentRef,
        expected_native: ContentRef,
        slot: Box<dyn LineageSourceCustodySlot>,
    ) -> Result<Self, Box<LineageSourceLaunchFailure>> {
        let validated = expected_provider
            .validate()
            .and_then(|()| expected_native.validate());
        if let Err(error) = validated {
            return Err(Box::new(LineageSourceLaunchFailure::BeforeSpawn {
                error: error.into(),
                slot,
            }));
        }

        let mut custody = Box::new(LineageSourceCustody {
            child: None,
            child_pid: 0,
            directory,
            provider: None,
            expected_provider,
            expected_native,
            controller: None,
            handshake: None,
            extension_handshake: None,
            refused_extensions: None,
            native: NativeCustody::NotStarted,
            provider_signalled: false,
            reaped: None,
            bootstrap: None,
            realization: None,
        });
        let read_owner = std::rc::Rc::new(SourceReadOwner::new(slot.identity()));
        let child = match command.process_group(0).spawn() {
            Ok(child) => child,
            Err(error) => {
                return Err(Box::new(LineageSourceLaunchFailure::BeforeSpawn {
                    error: error.into(),
                    slot,
                }));
            }
        };
        custody.child_pid = child.id();
        custody.child = Some(child);
        let mut guard = Self {
            read_owner,
            custody: Some(custody),
            slot: Some(slot),
        };
        let result = (|| {
            let custody = guard.custody_mut()?;
            let original = kernel::identity(custody.child_pid)?;
            custody.provider = Some(original);
            kernel::verify_executable(original.pid, &custody.expected_provider)
        })();
        match result {
            Ok(()) => Ok(guard),
            Err(error) => Err(Box::new(LineageSourceLaunchFailure::AfterSpawn(
                LineageSourceFailure { error, guard },
            ))),
        }
    }
}
