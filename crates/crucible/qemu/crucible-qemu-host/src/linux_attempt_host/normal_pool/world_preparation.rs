//! Carries one paid World Preparation from its actual pool to constructor entry.
//!
//! The origin borrows the existing pool purpose; it creates no bank or budget.
//! Preparation is entered once outside the shared factory mutex and remains
//! caller-owned through refused admission. Pool identity, selected generation
//! and the once-attempted latch are checked before any lower constructor effect.
//! The nominal proof is consumed later, at the checked assignment publication cut.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Borrows the existing normal pool before entering a World Preparation.
///
/// Cloning retains the same authenticated pool facade, not an issued guard.
/// Each actual constructor still retains its own once-entered Preparation.
#[derive(Clone)]
#[must_use = "retain the same origin until its one Preparation is entered"]
pub struct LinuxQemuNativeWorldPreparationOrigin {
    purpose: AuthenticatedNativePoolPurpose,
}

/// Retains one actual World Preparation and its immutable pool/selection binding.
#[must_use = "retain this same Preparation until its constructor has returned"]
pub struct LinuxQemuNativeWorldPreparation {
    purpose: AuthenticatedNativePoolPurpose,
    original: Arc<HostOperationGuard>,
    binding: PreparationBinding,
}

struct PreparationBinding {
    identity: NativeWorldIdentity,
    entry: PreparationEntry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparationEntry {
    Ready,
    Attempted,
    Committed,
}

impl PreparationBinding {
    fn begin_attempt(&mut self, same_pool: bool, identity: NativeWorldIdentity) -> bool {
        if !same_pool || self.identity != identity || self.entry != PreparationEntry::Ready {
            return false;
        }
        self.entry = PreparationEntry::Attempted;
        true
    }

    fn commit_world(&mut self, entered: impl FnOnce()) {
        // Only the checked assignment's move-only callback reaches this cut.
        // Refusal never resets Attempted to Ready or reconstructs a proof.
        self.entry = PreparationEntry::Committed;
        entered();
    }
}

impl LinuxQemuNativeWorldPreparationOrigin {
    pub(super) fn from_purpose(purpose: &AuthenticatedNativePoolPurpose) -> Self {
        Self {
            purpose: purpose.clone(),
        }
    }

    /// Enters the existing pool's actual Preparation once beneath its same Main.
    ///
    /// Its guard allocation must already be funded by the caller's Main body.
    /// The returned move-only value is retained before any shared-lock wait.
    ///
    /// # Errors
    /// Refuses the original Main, changed family or genuine Preparation admission.
    pub fn prepare(
        self,
        identity: NativeWorldIdentity,
    ) -> Result<LinuxQemuNativeWorldPreparation, QemuVmRealizationError> {
        let original = self
            .purpose
            .begin_native_preparation()
            .map_err(|source| original_roster::original_error(source.into()))?;
        Ok(LinuxQemuNativeWorldPreparation {
            purpose: self.purpose,
            original: Arc::new(original),
            binding: PreparationBinding {
                identity,
                entry: PreparationEntry::Ready,
            },
        })
    }
}

impl LinuxQemuNativeWorldPreparation {
    /// Prices the one guard allocation before caller-owned admission begins.
    ///
    /// Inline token/identity storage belongs to the containing body's own layout.
    /// This additional preassignment reservation preserves the pool's existing
    /// standing peak; it releases no capacity and changes no deadline.
    #[must_use]
    pub fn shared_control_extent() -> Option<u64> {
        let (allocation, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<HostOperationGuard>())
        .ok()?;
        u64::try_from(allocation.pad_to_align().size()).ok()
    }

    /// Borrows the same existing operation for bounded shared-factory admission.
    #[must_use]
    pub fn operation(&self) -> &HostOperationGuard {
        &self.original
    }

    pub(super) fn begin_attempt(
        &mut self,
        purpose: &AuthenticatedNativePoolPurpose,
        identity: NativeWorldIdentity,
    ) -> Result<Arc<HostOperationGuard>, QemuVmRealizationError> {
        if !self
            .binding
            .begin_attempt(purpose.same_pool(&self.purpose), identity)
        {
            return Err(QemuVmRealizationError::CleanupRetained {
                operation: "enter the same World Preparation exactly once",
            });
        }
        Ok(Arc::clone(&self.original))
    }

    pub(super) fn commit_world(&mut self, entered: impl FnOnce()) {
        self.binding.commit_world(entered);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_binding_requires_original_pool_selection_and_unconsumed_latch() {
        // Inert metadata controls issue no Main, token, native claim or provider.
        let identity = NativeWorldIdentity {
            owner: [3; 32],
            selection: [5; 32],
        };
        let mut binding = PreparationBinding {
            identity,
            entry: PreparationEntry::Ready,
        };
        assert!(!binding.begin_attempt(false, identity));
        assert!(!binding.begin_attempt(
            true,
            NativeWorldIdentity {
                owner: [4; 32],
                ..identity
            }
        ));
        assert!(!binding.begin_attempt(
            true,
            NativeWorldIdentity {
                selection: [6; 32],
                ..identity
            }
        ));
        assert_eq!(binding.entry, PreparationEntry::Ready);

        assert!(binding.begin_attempt(true, identity));
        assert_eq!(binding.entry, PreparationEntry::Attempted);
        assert!(!binding.begin_attempt(true, identity));
        assert_eq!(binding.entry, PreparationEntry::Attempted);
    }

    #[test]
    fn committed_callback_consumes_the_same_nominal_slot_without_rearming_attempt() {
        let identity = NativeWorldIdentity {
            owner: [3; 32],
            selection: [5; 32],
        };
        let mut binding = PreparationBinding {
            identity,
            entry: PreparationEntry::Ready,
        };
        let original_nominal = Box::new(17_u64);
        let pointer = std::ptr::from_ref(&*original_nominal);
        let mut nominal = Some(original_nominal);
        assert!(binding.begin_attempt(true, identity));
        assert_eq!(std::ptr::from_ref(&**nominal.as_ref().unwrap()), pointer);
        assert!(!binding.begin_attempt(true, identity));
        assert!(nominal.is_some());

        let mut callbacks = 0;
        binding.commit_world(|| {
            callbacks += 1;
            drop(nominal.take());
        });
        assert_eq!(callbacks, 1);
        assert!(nominal.is_none());
        assert_eq!(binding.entry, PreparationEntry::Committed);
        assert!(!binding.begin_attempt(true, identity));
        assert_eq!(binding.entry, PreparationEntry::Committed);
    }
}
