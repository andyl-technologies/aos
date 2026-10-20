//! Checks shared views over genuine acknowledged native consumer grants.
//!
//! The repository binding below is fixture routing configuration only. Native
//! authority comes exclusively from the actual owner's acknowledged lease.

use super::{Inputs, PLAINTEXT, invalid};
use std::{io, path::PathBuf};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
};
use terrane_linux::host_cache::{NativeConsumerLease, NativeSharedResidences};
use terrane_sdk::{
    domain::DomainBinding,
    host::cache::{DomainHostLayout, HostResidenceReader},
    repository::MetadataValidator,
    store::{
        ContentStore, StoreErrorKind, TokioLocalFs,
        shared_dir::{ResidentSharedDir, SharedDir},
    },
};

type Directory = ResidentSharedDir<TokioLocalFs, MetadataValidator, NativeSharedResidences>;

/// Retains a directory view without acquiring any additional physical resource.
pub(super) struct SharedChecks {
    directory: Directory,
}

impl SharedChecks {
    /// Opens real sealed fallback and checks its finite inventory and isolation.
    ///
    /// # Errors
    /// Refuses a failed control, absent original grant or changed durable state.
    pub(super) fn open(
        runtime: &tokio::runtime::Runtime,
        inputs: &Inputs,
        lease: &NativeConsumerLease,
    ) -> io::Result<Self> {
        let layout = layout(inputs, inputs.root.clone(), &inputs.domain)?;
        // Ordinary chunk lookup must miss; otherwise it could hide a broken
        // native residence binding by returning another existing encoded body.
        if std::fs::read_dir(inputs.root.join("chunks"))?
            .next()
            .is_some()
        {
            return Err(invalid(
                "sealed shared witness has standalone chunk entries",
            ));
        }
        let wrong_profile = DomainHostLayout::new(
            inputs.root.clone(),
            layout.domain_binding().clone(),
            ChunkProfile::cdc_1m([1; 32]),
        )
        .map_err(io::Error::other)?;
        for foreign in [
            layout_with_domain(inputs, "tenant:another-shared-domain")?,
            layout_with_domain(inputs, "private:another-consumer")?,
            self::layout(inputs, inputs.root.join("must-not-open"), &inputs.domain)?,
            wrong_profile,
        ] {
            if !matches!(
                NativeSharedResidences::new(&foreign, vec![lease.clone()], 1)
                    .err()
                    .ok_or_else(|| invalid("foreign shared layout accepted"))?
                    .kind(),
                StoreErrorKind::Denied { .. }
            ) {
                return Err(invalid("foreign shared layout changed refusal category"));
            }
        }
        if inputs.root.join("must-not-open").exists() {
            return Err(invalid("shared layout refusal created a foreign directory"));
        }
        for (leases, limit) in [
            (vec![lease.clone()], 0),
            (vec![lease.clone(), lease.clone()], 1),
        ] {
            if NativeSharedResidences::new(&layout, leases, limit)
                .err()
                .ok_or_else(|| invalid("shared inventory exceeded its bound"))?
                .kind()
                != &StoreErrorKind::Capacity
            {
                return Err(invalid("shared inventory lost its capacity category"));
            }
        }
        let duplicates =
            NativeSharedResidences::new(&layout, vec![lease.clone(), lease.clone()], 2)
                .err()
                .ok_or_else(|| invalid("duplicate shared identity accepted"))?;
        if !matches!(duplicates.kind(), StoreErrorKind::Invalid(_)) {
            return Err(invalid(
                "duplicate shared identity changed refusal category",
            ));
        }
        let residences = NativeSharedResidences::new(&layout, vec![lease.clone()], 1)
            .map_err(io::Error::other)?;
        let bounded = runtime
            .block_on(residences.read_chunk(&layout, lease.identity(), PLAINTEXT.len() - 1))
            .err()
            .ok_or_else(|| invalid("shared plaintext exceeded allocation cap"))?;
        if bounded.kind() != &StoreErrorKind::Capacity {
            return Err(invalid(
                "shared read allocation failure lost capacity category",
            ));
        }
        let inventory = runtime
            .block_on(residences.chunk_identities(&layout, 1))
            .map_err(io::Error::other)?;
        if inventory != [lease.identity().clone()] {
            return Err(invalid("shared inventory lost its actual grant identity"));
        }
        let directory = runtime
            .block_on(SharedDir::open_existing(
                layout,
                TokioLocalFs,
                MetadataValidator::new(inputs.owner_config()?.location.chunk_profile().clone()),
            ))
            .map_err(io::Error::other)?
            .with_residences(residences, 1)
            .map_err(io::Error::other)?;
        let checks = Self { directory };
        checks.read(runtime, lease)?;
        Ok(checks)
    }

    /// Reads a reconstructed raw envelope from the original live sealed inode.
    ///
    /// # Errors
    /// Refuses missing backing, changed bytes or a revoked original consumer.
    pub(super) fn read(
        &self,
        runtime: &tokio::runtime::Runtime,
        lease: &NativeConsumerLease,
    ) -> io::Result<()> {
        let bytes = runtime
            .block_on(self.directory.get(lease.identity(), None))
            .map_err(io::Error::other)?;
        if bytes.first() != Some(&0) || bytes.get(1..) != Some(PLAINTEXT) {
            return Err(invalid("shared residence changed the original plaintext"));
        }
        Ok(())
    }

    /// Checks that this retained view cannot outlive release of its original grant.
    ///
    /// # Errors
    /// Refuses a successful read or membership answer after actual revocation.
    pub(super) fn revoked(
        &self,
        runtime: &tokio::runtime::Runtime,
        lease: &NativeConsumerLease,
    ) -> io::Result<()> {
        if runtime
            .block_on(self.directory.get(lease.identity(), None))
            .is_ok()
            || runtime
                .block_on(self.directory.has(&[lease.identity().clone()]))
                .is_ok()
        {
            return Err(invalid(
                "released consumer still served through shared directory",
            ));
        }
        Ok(())
    }
}

fn layout_with_domain(inputs: &Inputs, domain: &str) -> io::Result<DomainHostLayout> {
    layout(inputs, inputs.root.clone(), domain)
}

fn layout(inputs: &Inputs, root: PathBuf, domain: &str) -> io::Result<DomainHostLayout> {
    DomainHostLayout::new(
        root,
        DomainBinding {
            domain: domain.to_owned(),
            reference: "refs/heads/shared-fixture".into(),
            root: TERRANE_V1
                .calculate(IdentityKind::Node, b"shared fixture routing configuration")
                .map_err(io::Error::other)?,
            path: b"/".to_vec(),
        },
        inputs.owner_config()?.location.chunk_profile().clone(),
    )
    .map_err(io::Error::other)
}
