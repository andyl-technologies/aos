//! Retains an original sealed file across cold recovery and publisher retirement.

use super::{Result, config, file_closure, hex, now, snapshot};
use crate::repository_fixture::{MAIN, RepositoryFixture};
use std::{
    fs::{File, Metadata},
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    time::Duration,
};
use terrane_format::{
    identity::{Descriptor, IdentityKind, TERRANE_V1},
    surface::View,
};
use terrane_linux::{
    host_cache::{NativeExposureLease, NativeMetadataOwner, NativeRootIndex},
    host_quota::HostQuotaClient,
};

/// Supplies the same plaintext to guarded source commit and native publication.
pub(super) const BODY: &[u8] = b"actual sealed file retained through new funded recovery";

/// Holds only the actual disclosed descriptor and its independently observed inode.
pub(super) struct RetainedFile {
    file: File,
    original: Metadata,
    hash: String,
}

impl RetainedFile {
    /// Publishes and discloses the actual file before releasing ordinary receipts.
    ///
    /// # Errors
    /// Preserves guarded read, native publication, disclosure and handoff failures.
    pub(super) async fn prepare(
        owner: &NativeMetadataOwner,
        fixture: &RepositoryFixture,
        admitted: &NativeRootIndex,
        exposure: &NativeExposureLease,
        expires: u64,
    ) -> Result<Self> {
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, BODY)?;
        let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, BODY)?;
        let publication = owner
            .publish_inline(descriptor, [vec![0], BODY.to_vec()].concat())
            .await?;
        let selection = fixture
            .repository
            .prepare_file_read(
                &View::parse(MAIN)?,
                b"file",
                fixture.authority.token(),
                "sdk",
            )
            .await?;
        let backing = owner
            .prepare_exposure_file_backing(exposure, admitted, selection, expires)
            .await?;
        let file = File::from(backing.as_fd().try_clone_to_owned()?);
        let original = file.metadata()?;
        owner.release_sealed_object_lease(backing.lease()).await?;
        drop(backing);
        publication.complete_cache_handoff(owner).await?;

        let retained = Self {
            file,
            original,
            hash: hex(identity.digest()),
        };
        retained.check_readable()?;
        Ok(retained)
    }

    /// Requires readable original bytes and the independently observed inode.
    ///
    /// # Errors
    /// Refuses changed inode identity, unreadable backing or different plaintext.
    pub(super) fn check_readable(&self) -> Result<()> {
        let current = self.file.metadata()?;
        let mut bytes = [0; BODY.len()];
        self.file.read_exact_at(&mut bytes, 0)?;
        if (current.dev(), current.ino()) != (self.original.dev(), self.original.ino())
            || bytes != BODY
        {
            return Err("cold recovery changed the original disclosed file backing".into());
        }
        Ok(())
    }

    /// Retires the actual body while retaining its disclosed descriptor.
    ///
    /// # Errors
    /// Refuses premature release, missed grace, lost backing, failed native
    /// retirement or changed exposure obligations.
    pub(super) async fn retire_backing(
        &self,
        owner: &NativeMetadataOwner,
        inputs: &config::Inputs,
        id: &str,
        generation: u64,
    ) -> Result<()> {
        let pin_owner = format!("exposure:{id}");
        // The genuine pre-crash producer and consumer grace still protects this
        // file. Recovery cannot manufacture expiry or credit their reservations.
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                owner.sweep_consumer_leases().await?;
                if !snapshot(inputs)
                    .await?
                    .pins
                    .iter()
                    .any(|row| row.hash == self.hash && row.owner != pin_owner)
                {
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| "ordinary retained-file pins did not expire within actual release grace")??;
        eprintln!("RETAINED_FILE_STAGE phase=ordinary-grace-complete");
        let protected = snapshot(inputs).await?.exposures;
        if file_closure::pressure(owner, inputs).await? != 1 {
            return Err("Running owner failed actual original body retirement".into());
        }
        eprintln!("RETAINED_FILE_STAGE phase=publisher-retirement-accepted");
        tokio::time::timeout(Duration::from_secs(40), async {
            while self.file.metadata()?.nlink() != 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await
        .map_err(
            |_| "publisher did not unlink the retained original file within retirement bound",
        )??;
        eprintln!("RETAINED_FILE_STAGE phase=publisher-final-removal-observed");
        self.check_readable()?;
        if owner.reconcile_surface_exposure(id, generation).await?
            || snapshot(inputs).await?.exposures != protected
        {
            return Err("recovered publisher retirement released a surviving descriptor".into());
        }
        Ok(())
    }

    /// Requires the new owner to refuse adoption from a retained physical pin.
    ///
    /// # Errors
    /// Refuses a named or changed original file, a successful new consumer grant
    /// or any policy mutation while that grant is refused.
    pub(super) async fn check_unadopted(
        &self,
        owner: &NativeMetadataOwner,
        inputs: &config::Inputs,
    ) -> Result<()> {
        self.check_readable()?;
        if self.file.metadata()?.nlink() != 0 {
            return Err("original orphan file unexpectedly retains a name".into());
        }
        let policy = inputs.root.join("state/cache/records.toml");
        let before = std::fs::read(&policy)?;
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, BODY)?;
        if owner.pin_sealed_object(identity, now()? + 30).await.is_ok()
            || std::fs::read(&policy)? != before
        {
            return Err("cold physical obligation became a new native content source".into());
        }
        Ok(())
    }

    /// Closes the original retired file and observes its exact physical release.
    ///
    /// # Errors
    /// Refuses a named file, premature reconciliation, lost original bytes,
    /// changed policy or inexact native block and inode release.
    pub(super) async fn close(
        self,
        owner: &NativeMetadataOwner,
        inputs: &config::Inputs,
        id: &str,
        generation: u64,
    ) -> Result<()> {
        self.check_readable()?;
        let policy = inputs.root.join("state/cache/records.toml");
        let durable = std::fs::read(&policy)?;
        if self.file.metadata()?.nlink() != 0
            || owner.reconcile_surface_exposure(id, generation).await?
            || std::fs::read(&policy)? != durable
        {
            return Err("retired original descriptor lost its durable exposure protection".into());
        }

        // Sample before final close and before the separate closure snapshot so
        // metadata allocation cannot mask the original physical release.
        let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
        let before = crate::quota_sample(&mut quota, inputs)?;
        let allocated = self.original.blocks() * 512;
        drop(self);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let after = crate::quota_sample(&mut quota, inputs)?;
                if before.0.checked_sub(after.0) == Some(allocated)
                    && before.1.checked_sub(after.1) == Some(1)
                {
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        if std::fs::read(&policy)? != durable {
            return Err(
                "final recovered file close discharged policy without reconciliation".into(),
            );
        }
        Ok(())
    }
}
