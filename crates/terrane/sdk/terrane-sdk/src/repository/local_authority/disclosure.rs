//! Keeps dedicated disclosure signing material outside capability and bucket formats.
//!
//! The native initializer installs a protected public role under the actual
//! physical registration before the first guard snapshot. Each issuance rereads
//! the matching private seed under that source's configuration exclusion.

use crate::bucket::held::SingleHeld;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{Guard, OriginalAuthority};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};

use super::public_trust::DisclosureRoleRecord;
use super::retention::{self, Record};
use super::{Error, random_seed, read_seed, write_private};

/// Holds a private seed whose dedicated role was checked against the actual source.
///
/// No constructor accepts a caller-supplied authority tuple or signing key.
/// Secrets are deliberately excluded from Debug and public configuration.
pub(crate) struct DisclosureSigner {
    role: DisclosureRoleRecord,
    secret: [u8; 32],
}

impl DisclosureSigner {
    /// Returns the actual independently checked historical source role.
    pub(crate) fn role(&self) -> &DisclosureRoleRecord {
        &self.role
    }

    /// Captures the exact protected role and seed consumed by this signer.
    ///
    /// These bytes stay inside the native physical effect receipt. Only the
    /// public role is included in retained destination trust or signed metadata.
    ///
    /// # Errors
    /// Rejects a malformed role selector or canonical role encoding.
    pub(crate) fn retained_records(&self) -> Result<Vec<(String, Vec<u8>)>, Error> {
        Ok(vec![
            (self.role.selector()?, self.role.encode()?),
            (seed_selector(&self.role.public_key), self.secret.to_vec()),
        ])
    }

    /// Signs only after the core checks complete source and target witnesses.
    ///
    /// # Errors
    /// Rejects differing content, domain or introduction, malformed target
    /// metadata, unsupported projections and issue times outside the role.
    pub(crate) fn sign(
        &self,
        witness: terrane_format::provenance::DisclosureSigning<'_>,
    ) -> Result<[u8; 64], StoreFailure> {
        terrane_format::provenance::sign_disclosure(witness, self.role.view(), &self.secret)
            .map_err(|_| crate::guard::invalid())
    }
}

/// Installs a new dedicated role beneath the initializer's checked registration.
///
/// This runs before native dispatch or its first snapshot is installed. Reopen
/// never calls it, and existing selected state cannot use it as a repair path.
///
/// # Errors
/// Rejects changed registration or protection, unavailable clock or entropy,
/// conflicting role/seed files and failed durable writes.
pub(super) async fn initialize<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    owner: u32,
) -> Result<(), Error>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let holder = SingleHeld::acquire(guard.store()).await?;
    let destination = holder.destination();
    let identity = destination.identity_proof();
    let mut controls = guard
        .hold_original_registration_write(authority, &identity)
        .await?;
    let now = guard
        .clock()
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Denied)?
        .as_secs();
    let secret = random_seed(guard.store().fs()).await?;
    let role = DisclosureRoleRecord {
        repository: identity_name(authority.id()),
        domain: authority.domain().to_owned(),
        public_key: terrane_format::auth::public_key_from_secret(&secret),
        not_before: now,
        not_after: None,
    };
    let selector = role.selector()?;
    let seed = authority.control().join(seed_selector(&role.public_key));
    write_private(guard.store().fs(), &seed, &secret).await?;
    retention::retain(
        guard.store().fs(),
        authority.control(),
        owner,
        &selector,
        &role,
        true,
    )
    .await?;
    controls.revalidate().await?;
    Ok(())
}

/// Rereads a dedicated source key while genuine source control exclusion is held.
///
/// The native producer independently verifies its current source request before
/// using this signer and retains these exact role/seed bytes through publication.
///
/// # Errors
/// Rejects absent or equally current live roles, different physical source identity,
/// changed canonical role bytes, missing/unsafe seeds and mismatched keys.
pub(crate) async fn load<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    controls: &mut crate::guard::ControlExclusion<'_, F>,
    now: u64,
) -> Result<DisclosureSigner, Error>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let repository = identity_name(authority.id());
    let mut roles = guard
        .configured_disclosure_roles()?
        .into_iter()
        .filter(|role| role.repository == repository && role.domain == authority.domain())
        .collect::<Vec<_>>();
    // A checked rotation adds a strictly later issue start without changing old
    // historical rows. Select the current row before checking its window so a
    // rollback or expiry never falls back to an obsolete seed. The owning
    // producer checks the complete selected/protected role set; equal starts
    // never choose an arbitrary signing key.
    roles.sort_by_key(|role| role.not_before);
    let role = roles.pop().ok_or(Error::Denied)?;
    if now < role.not_before
        || role.not_after.is_some_and(|end| now >= end)
        || roles
            .last()
            .is_some_and(|previous| previous.not_before == role.not_before)
        || controls.read_record(&role.selector()?).await? != role.encode()?
    {
        return Err(Error::Denied);
    }
    let owner = guard
        .store()
        .publication_operator_uid()
        .ok_or(Error::Denied)?;
    let seed_name = seed_selector(&role.public_key);
    let secret = read_seed(
        guard.store().fs(),
        &authority.control().join(&seed_name),
        owner,
    )
    .await?;
    if controls.read_record(&seed_name).await? != secret {
        return Err(Error::Denied);
    }
    if terrane_format::auth::public_key_from_secret(&secret) != role.public_key {
        return Err(Error::Denied);
    }
    controls.revalidate().await?;
    Ok(DisclosureSigner { role, secret })
}

/// Installs a fresh key only inside the current-Admin-authorized rotation producer.
///
/// The caller retains actual backend and write-configuration exclusion. Old
/// role bytes and issue windows remain immutable; the new row becomes usable
/// only after the producer selects the complete additive Guard snapshot.
///
/// # Errors
/// Rejects nonmonotonic issue time, a foreign or absent role set, changed
/// protection, entropy failures and unsuccessful durable seed or role writes.
pub(crate) async fn prepare_rotation<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    controls: &mut crate::guard::ControlExclusion<'_, F>,
    final_check: &crate::selected_bridge::OwnedFinalCheck,
) -> Result<DisclosureSigner, Error>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    if guard.configured_original_authority()? != *authority {
        return Err(Error::Denied);
    }
    let now = guard
        .clock()
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Denied)?
        .as_secs();
    let previous = guard.configured_disclosure_roles()?;
    let repository = identity_name(authority.id());
    if previous.is_empty()
        || previous.iter().any(|role| {
            role.repository != repository
                || role.domain != authority.domain()
                || role.not_before >= now
        })
    {
        return Err(Error::Denied);
    }
    let owner = guard
        .store()
        .publication_operator_uid()
        .ok_or(Error::Denied)?;
    let secret = random_seed(guard.store().fs()).await?;
    let role = DisclosureRoleRecord {
        repository,
        domain: authority.domain().to_owned(),
        public_key: terrane_format::auth::public_key_from_secret(&secret),
        not_before: now,
        not_after: None,
    };
    if previous
        .iter()
        .any(|previous| previous.public_key == role.public_key)
    {
        return Err(Error::Denied);
    }
    final_check.recheck()?;
    controls.revalidate().await?;
    write_private(
        guard.store().fs(),
        &authority.control().join(seed_selector(&role.public_key)),
        &secret,
    )
    .await?;
    final_check.recheck()?;
    retention::retain(
        guard.store().fs(),
        authority.control(),
        owner,
        &role.selector()?,
        &role,
        true,
    )
    .await?;
    final_check.recheck()?;
    controls.revalidate().await?;
    Ok(DisclosureSigner { role, secret })
}

fn seed_selector(key: &[u8; 32]) -> String {
    format!("disclosure-{}.seed", identity_name(key))
}

fn identity_name(identity: &[u8; 32]) -> String {
    identity.iter().map(|byte| format!("{byte:02x}")).collect()
}
