//! Owns the feature-private original-bound setup and physical cleanup route.
//!
//! Actual setup remnants stay in the same external roster before refusal.
//! This child borrows the original factory and returned guard; it creates no
//! worker, bank, clock or namespace and never falls back to ordinary quarantine.

use super::*;

impl LinuxQemuAttemptHostFactory {
    /// Binds this genuine factory once to its admitted external account roster.
    ///
    /// The same concrete factory keeps its existing pinned process and storage
    /// roots. This move supplies account custody only; it does not install a
    /// domain, certify Source, or authorize a research launch.
    ///
    /// # Errors
    /// Refuses poisoned or already bound factories without replacing custody.
    #[cfg(feature = "private-measurement-domain")]
    pub fn bind_original_accounts(
        &mut self,
        binding: OriginalNativeAccountFactoryBinding,
    ) -> Result<(), OriginalActorAccountError> {
        if self.poisoned || self.process.is_poisoned() || self.original_accounts.is_some() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.original_accounts = Some(binding);
        Ok(())
    }

    pub(super) fn begin_original_with_checkpoint_root(
        &mut self,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
        exact_checkpoint_root: Option<crucible::ContentHash>,
    ) -> Result<LinuxQemuAttemptHostOwner, QemuVmRealizationError> {
        let original = self
            .original_accounts
            .as_ref()
            .ok_or_else(|| missing_authority("retain original native factory binding"))?
            .claim(
                maximum_vcpus,
                maximum_resident_bytes,
                maximum_writable_bytes,
            )
            .map_err(original_roster::original_error)?;
        let storage = match self.storage.begin(maximum_writable_bytes) {
            Ok(storage) => storage,
            Err(error) => {
                self.poisoned = true;
                let mapped = map_storage_error("create QEMU attempt storage", error.source_error());
                let cleanup = if let Some(storage) = error.into_owner() {
                    original
                        .retain_unsettled(original_roster::RetainedNativeHost {
                            process: None,
                            storage: Some(storage),
                            native_resources: None,
                            unconfigured: None,
                        })
                        .map_err(original_roster::original_error)
                } else {
                    Ok(())
                };
                return Err(original_roster::setup_refusal(&original, mapped, cleanup));
            }
        };
        if let Err(source) = original.require_original() {
            self.poisoned = true;
            let cleanup = original
                .retain_unsettled(original_roster::RetainedNativeHost {
                    process: None,
                    storage: Some(storage),
                    native_resources: None,
                    unconfigured: None,
                })
                .map_err(original_roster::original_error);
            return Err(original_roster::setup_refusal(
                &original,
                original_roster::original_error(source),
                cleanup,
            ));
        }
        let mut process_setup =
            crate::linux_attempt_process::OriginalProcessSetupCustody::default();
        let process = match self.process.begin_under_original(
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            exact_checkpoint_root,
            &original,
            &mut process_setup,
        ) {
            Ok(process) => process,
            Err(error) => {
                self.poisoned = true;
                let cleanup = original
                    .retain_unsettled(original_roster::RetainedNativeHost {
                        process: process_setup.owner,
                        storage: Some(storage),
                        native_resources: None,
                        unconfigured: process_setup.unconfigured,
                    })
                    .map_err(original_roster::original_error);
                return Err(original_roster::setup_refusal(&original, error, cleanup));
            }
        };
        let owner = LinuxQemuAttemptHostOwner {
            process: Some(process),
            storage: Some(storage),
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_writable_bytes,
            quarantine: None,
            native_resources: None,
            original_retirement_pinned: false,
            original_account: Some(original),
            terminal: false,
        };
        if let Some(original) = owner.original_account.as_ref() {
            original
                .require_original()
                .map_err(original_roster::original_error)?;
        }
        Ok(owner)
    }
}

impl LinuxQemuAttemptHostOwner {
    /// Pins an already-created native control for private original retirement.
    ///
    /// This method clones only the same existing allocation. It does not
    /// initialize a controller, perform I/O, issue a purpose or attest physical
    /// cleanup. The actor must retain the charged original pair externally
    /// through the pin's successful close and genuine factory deallocation.
    ///
    /// # Errors
    /// Refuses an owner that has not created its actual native resource state,
    /// has already transferred or retired that state, or has already issued
    /// its one nonduplicable terminal pin.
    #[cfg(feature = "private-measurement-domain")]
    pub fn retain_original_native_control(
        &mut self,
    ) -> Result<OriginalNativeControlRetirement, LinuxQemuNativeResourceError> {
        let state = self
            .native_resources
            .as_ref()
            .ok_or(LinuxQemuNativeResourceError::Retired)?;
        if self.terminal
            || self.original_retirement_pinned
            || !NativeResourceState::available(state)
        {
            return Err(LinuxQemuNativeResourceError::Retired);
        }
        self.original_retirement_pinned = true;
        Ok(OriginalNativeControlRetirement::retain(state))
    }

    #[cfg(feature = "private-measurement-domain")]
    pub(super) fn finish_original_accounts(&mut self) -> Result<(), QemuVmRealizationError> {
        let cleanup = self
            .original_account
            .as_ref()
            .ok_or_else(|| missing_authority("retain original native cleanup"))?
            .cleanup()
            .map_err(original_roster::original_error)?;
        self.retire_native_resources();
        if let Some(process) = self.process.as_mut() {
            process.finish_under_original(&cleanup)?;
        }
        self.process = None;
        if let Some(state) = self.native_resources.as_ref() {
            NativeResourceState::drain(state);
        }
        self.native_resources = None;

        cleanup
            .wait_slice()
            .map_err(|source| original_roster::original_error(source.into()))?;
        let result = if let Some(storage) = self.storage.as_mut() {
            storage.cleanup_under_original(&cleanup)
        } else {
            Ok(())
        };
        if result.is_ok() {
            // Physical release is recorded before the separate original
            // postcut. Refusal leaves the actual owner in this same slot.
            self.storage = None;
        }
        // Physical success or the actual recoverable owner is recorded before
        // observing original expiry on either outcome. Retry keeps Cleanup.
        original_roster::after_cleanup(result, &cleanup)?;
        self.original_account
            .as_ref()
            .ok_or_else(|| missing_authority("close original native vector"))?
            .close_vector()
            .map_err(original_roster::original_error)?;
        self.terminal = true;
        self.original_account = None;
        Ok(())
    }
}
