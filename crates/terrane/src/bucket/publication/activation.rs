//! Activates genuinely new roots and recovers the exact protected registration.
//!
//! Pending registration is restart evidence for its existing binding; it never
//! authorizes another registration or imports a copied physical incarnation.

#[cfg(all(test, feature = "tokio", unix))]
mod tests;

use super::control::Control;
use super::projection;
use super::{corrupt, unsupported};
use crate::bucket::held::SingleHeld;
use crate::bucket::{BucketBinding, FileBucket, files};
use crate::store::{
    Clock, ContentValidator, LocalFs, NativePublicationInitializationOutcome, StoreErrorKind,
    StoreFailure,
};
use terrane_core::gc::publication::{Activation, BackendRegistration, LogicalChange};

#[cfg(all(test, feature = "tokio", unix))]
use terrane_core::bucket::{BucketCapabilities, BucketKey};

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Checks configured protected namespace admission before filesystem effects.
    ///
    /// # Errors
    /// Refuses unconfigured, unsafe, aliased, stale or unregistered namespaces.
    /// This check creates no registration and grants no freshness capability.
    pub(in crate::bucket) async fn preflight_publication_namespace(
        &self,
    ) -> Result<(), StoreFailure> {
        Control::preflight(self).await
    }

    /// Admits a configured fresh creator or verifies the exact existing registration.
    ///
    /// This private open hook consumes the native creator's actual retained receipt
    /// or checks an existing registration without inferring freshness.
    ///
    /// # Errors
    /// Refuses unconfigured ownership, missing existing control, incomplete or
    /// inconsistent activation, unsafe physical binding, and failed durability.
    pub(in crate::bucket) async fn open_publication(
        &self,
        initialization: NativePublicationInitializationOutcome,
    ) -> Result<(), StoreFailure> {
        if self.inner.config.publication_control.is_none() {
            return Err(unsupported());
        }
        if let NativePublicationInitializationOutcome::Fresh(receipt) = initialization {
            return crate::store::native_publication_effects::initialization::activate(
                &self.inner.fs,
                *receipt,
            )
            .await;
        }
        self.preflight_publication_namespace().await?;
        let guard = self.existing_exclusive().await?;
        let control = Control::open(self, false).await?;
        let bytes = control
            .read(&self.inner.fs, "backend-registration.cbor")
            .await?
            .ok_or_else(corrupt)?;
        let registration = BackendRegistration::decode(&bytes).map_err(|_| corrupt())?;
        if registration.binding != control.binding {
            return Err(corrupt());
        }
        match registration.activation {
            Activation::Active => self.open_active_with_guard(guard).await,
            Activation::Pending => {
                let retained = self
                    .inner
                    .fs
                    .retain_native_exclusion(&guard)
                    .map_err(files::io_failure)?;
                let config = self
                    .inner
                    .config
                    .publication_control
                    .as_ref()
                    .ok_or_else(unsupported)?;
                let (owner, path) = super::configured_location(self.root(), config)?;
                let timestamp = self
                    .inner
                    .clock
                    .now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map_err(|_| files::malformed())?
                    .as_secs();
                let request = crate::store::native_initialization_request(
                    self.root(),
                    &path,
                    owner,
                    self.profile(),
                    timestamp,
                )?;
                crate::store::native_publication_effects::pending_initialization::activate_existing(
                    &self.inner.fs, request, retained,
                ).await?;
                self.open_active_with_guard(guard).await
            }
        }
    }

    async fn open_active_with_guard(&self, guard: F::Lock) -> Result<(), StoreFailure> {
        let holder = SingleHeld::from_active_guard(self, guard).await?;
        let destination = holder.destination();
        let observed = destination.observe_for_read().await?;
        crate::store::native_publication_effects::repair(&self.inner.fs, &observed).await?;
        crate::store::native_publication_effects::probe_active(&self.inner.fs, &observed).await?;

        // The proposed successor is canonical and independently eligible.
        // Refusal must come from the stale whole preimage, before any staging.
        let bytes = projection::value(observed.logical(), "CAPABILITIES")?;
        let mut stale = bytes.to_vec();
        stale.push(0);
        let mut proposal = projection::capabilities(observed.logical())?;
        proposal.probed_at = proposal.probed_at.checked_add(1).ok_or_else(corrupt)?;
        let proposal = proposal.encode().map_err(|_| corrupt())?;
        match destination
            .prepare_raw(
                &observed,
                vec![LogicalChange {
                    key: "CAPABILITIES".into(),
                    expected: Some(stale),
                    new: Some(proposal),
                }],
            )
            .await
        {
            Err(error) if matches!(error.kind(), StoreErrorKind::Unavailable { .. }) => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(unsupported()),
        }
        observed.revalidate().await?;

        let mut capabilities = projection::capabilities(observed.logical())?;
        capabilities.probed_at = self
            .inner
            .clock
            .now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| files::malformed())?
            .as_secs();
        let replacement = capabilities.encode().map_err(|_| corrupt())?;
        if bytes != replacement {
            destination
                .publish_backend_raw(
                    &observed,
                    vec![LogicalChange {
                        key: "CAPABILITIES".into(),
                        expected: Some(bytes.to_vec()),
                        new: Some(replacement),
                    }],
                )
                .await?;
        }
        Ok(())
    }
}
