//! Consumes actual metadata witnesses while leaving durable-pin authority in cache.

use super::*;
use terrane::host::cache::HostReadLimits;

impl CommandOwner {
    pub(super) async fn consume_manifest(
        &mut self,
        witness: NativeManifestWitness,
        source: Option<File>,
        key: Option<NativeBodyKey>,
    ) -> io::Result<NativeCommandResult> {
        self.confinement.check_current()?;
        if self._configured_custody.is_none() {
            return Err(unsupported(
                "manifest consumption requires actual configured native custody",
            ));
        }
        witness.recheck(&self.domain, &self.profile)?;
        self.body_io.check_manifest_pack(witness.file())?;
        self.validate_claim(witness.claim())?;
        if let Some(key) = key {
            key.validate()?;
            if key
                != (NativeBodyKey::Sealed {
                    descriptor: witness.claim().descriptor().clone(),
                })
            {
                return Err(invalid(
                    "manifest inspection key disagrees with exact reconstruction witness",
                ));
            }
        }

        // This is native memory policy, not a new accepted-format maximum.
        // Retained canonical metadata is bounded across the entire owner, not
        // merely once per packet. Exhaustion refuses this resource policy
        // without changing the set of accepted immutable formats.
        let used = self.bodies.iter().try_fold(0usize, |used, body| {
            used.checked_add(
                body.manifest
                    .as_ref()
                    .map_or(0, |manifest| manifest.canonical_size()),
            )
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "retained manifest budget overflow",
                )
            })
        })?;
        if used
            .checked_add(witness.canonical_size())
            .is_none_or(|size| size > HostReadLimits::default().max_allocation_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "retained manifest memory budget exhausted",
            ));
        }
        if self.bodies.len() >= 4096 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "publisher incarnation budget exhausted",
            ));
        }

        let witness = Arc::new(witness);
        let claim = witness.claim().clone();
        // The accepted worker owns this local witness and source throughout the
        // actual async engine, including rollback after late durable-state error.
        // A dropped client waiter cannot drop this future or metadata descriptor.
        let object = match source {
            Some(source) => self.publisher()?.publish(&claim, source).await?,
            None => self.publisher()?.adopt(&claim).await?,
        };
        self.retain_with_manifest(claim, NativePublishedObject { object }, Some(witness))
            .await
    }
}
