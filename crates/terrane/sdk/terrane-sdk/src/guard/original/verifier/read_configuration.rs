//! Carries one native reader invocation's actual ordinary configuration inputs.
//!
//! The adapter clears protected Original state and has no store or clock. It
//! preserves interpretation and selection data without carrying a completed
//! history, permission, physical receipt or native backend binding.

use crate::guard::{Guard, PendingCurrentReadCheck};
use crate::store::StoreFailure;

/// Retains the caller's ordinary inputs independently of the captured backend.
pub(super) struct ReadConfiguration {
    inputs: Guard<(), ()>,
}

impl ReadConfiguration {
    /// Copies only ordinary configuration through the existing read adapter.
    pub(super) fn capture<S, C>(guard: &Guard<S, C>) -> Self {
        Self {
            inputs: guard.read_configuration_adapter((), ()),
        }
    }

    /// Binds the actual caller inputs to the separately retained native reader.
    ///
    /// The owning factory must restore genuine Original state afterward and
    /// independently compare its selected Guard and resolver inputs. This method
    /// neither installs authority nor replaces those physical checks.
    ///
    /// # Errors
    /// Refuses a substituted issuer inventory or failed fresh authentication.
    pub(super) fn bind<T, D>(
        self,
        store: T,
        clock: D,
        current: &PendingCurrentReadCheck,
    ) -> Result<Guard<T, D>, StoreFailure> {
        current.check_configured_keys(&self.inputs.keys)?;
        Ok(self.inputs.read_configuration_adapter(store, clock))
    }

    /// Binds direct immutable inputs to the independently configured native keys.
    ///
    /// # Errors
    /// Refuses an issuer inventory different from the actual captured factory.
    pub(super) fn bind_direct<T, D>(
        self,
        store: T,
        clock: D,
        keys: &[terrane_format::auth::IssuerKey],
    ) -> Result<Guard<T, D>, StoreFailure> {
        let same = self.inputs.keys.len() == keys.len()
            && self.inputs.keys.iter().zip(keys).all(|(left, right)| {
                left.issuer == right.issuer
                    && left.key_id == right.key_id
                    && left.public_key == right.public_key
                    && left.retirement == right.retirement
            });
        if !same {
            return Err(crate::guard::invalid());
        }
        Ok(self.inputs.read_configuration_adapter(store, clock))
    }
}
