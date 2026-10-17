//! Scoped stage dispatch under the accepted runtime and original profile pins.
//!
//! Material profiles describe the actual provider and credential pins. Accepted
//! runtime evidence remains the broker's gate. The material projection follows
//! complete accepted-profile equality checks; this interface cannot produce
//! Native promotion permissions or publication acknowledgements.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use async_trait::async_trait;
use worker::Env;

use super::config::{ManagedCredentials, QualifiedConfig};

/// Actual material facts needed to create and sign a private stage.
pub(super) enum MaterialProfile {
    Managed {
        profile: DirectManagedR2Profile,
    },
    External {
        profile: DirectExternalStorageCapabilities,
    },
}

/// Supplies scoped stage eligibility without conferring final publication authority.
#[async_trait(?Send)]
pub(super) trait StageAuthority {
    fn latest_now(&self) -> Result<u64>;

    fn maximum_object_bytes(&self) -> u64;

    fn managed(&self, env: &Env) -> Result<(DirectManagedR2Profile, ManagedCredentials)>;

    async fn protected_material(
        &self,
        env: &Env,
        placement: &DirectPlacement,
    ) -> Result<MaterialProfile>;
}

#[async_trait(?Send)]
impl StageAuthority for QualifiedConfig {
    fn latest_now(&self) -> Result<u64> {
        QualifiedConfig::latest_now(self)
    }

    fn maximum_object_bytes(&self) -> u64 {
        self.runtime.maximum_object_bytes.get()
    }

    fn managed(&self, env: &Env) -> Result<(DirectManagedR2Profile, ManagedCredentials)> {
        let (protected, credentials) = QualifiedConfig::managed(self, env)?;
        let DirectProtectedProfile::Managed { profile, .. } = protected else {
            anyhow::bail!("accepted managed material profile differs");
        };
        Ok((profile, credentials))
    }

    async fn protected_material(
        &self,
        env: &Env,
        placement: &DirectPlacement,
    ) -> Result<MaterialProfile> {
        // Full accepted runtime/profile equality is checked before projecting
        // the material needed by the common SDK path.
        Ok(
            match QualifiedConfig::protected(self, env, placement).await? {
                DirectProtectedProfile::Managed { profile, .. } => {
                    MaterialProfile::Managed { profile }
                }
                DirectProtectedProfile::External { profile, .. } => {
                    MaterialProfile::External { profile }
                }
            },
        )
    }
}

pub(super) fn current(
    authority: &dyn StageAuthority,
    context: &DirectRequestContext,
    admission: &DirectUploadAdmission,
) -> Result<()> {
    let latest = authority.latest_now()?;
    context.foreground.validate_at(latest)?;
    ensure!(
        latest < admission.expires_at.get()
            && admission.intent.byte_size.get() <= authority.maximum_object_bytes(),
        "direct original stage admission no longer eligible"
    );
    Ok(())
}
