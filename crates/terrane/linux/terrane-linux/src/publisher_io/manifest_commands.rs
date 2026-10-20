//! Consumes actual metadata witnesses while leaving durable-pin authority in cache.

use super::*;
use terrane_sdk::host::cache::HostReadLimits;

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

        // Separate resource policies bound canonical payload and decoded
        // payload capacities. These are not a claim about total allocator/RSS
        // overhead: at most 4096 rows separately bound fixed structs, Arc headers
        // and the small registered-hash BTreeMap node overhead.
        let limit = HostReadLimits::default().max_allocation_bytes;
        let (canonical, decoded) =
            self.bodies
                .iter()
                .try_fold((0usize, 0usize), |(canonical, decoded), body| {
                    let Some(manifest) = &body.manifest else {
                        return Ok((canonical, decoded));
                    };
                    Ok::<_, io::Error>((
                        canonical
                            .checked_add(manifest.canonical_size())
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::OutOfMemory,
                                    "canonical manifest capacity overflow",
                                )
                            })?,
                        decoded
                            .checked_add(manifest.decoded_payload_size()?)
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::OutOfMemory,
                                    "decoded manifest capacity overflow",
                                )
                            })?,
                    ))
                })?;
        if canonical
            .checked_add(witness.canonical_size())
            .is_none_or(|size| size > limit)
            || decoded
                .checked_add(witness.decoded_payload_size()?)
                .is_none_or(|size| size > limit)
        {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "canonical or decoded manifest payload budget exhausted",
            ));
        }
        // Recheck uses one separate fixed 64 KiB stack buffer. Initial receiver
        // verification has its own bounded full-pack/decoder scratch policy;
        // neither temporary cost is charged as retained canonical payload.
        if self.bodies.len() >= 4096 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "publisher incarnation budget exhausted",
            ));
        }

        let witness = Arc::new(witness);
        let claim = witness.shared_claim();
        let prepared = self.prepare_retention(Arc::clone(&claim)).await?;
        // The accepted worker owns this local witness and source throughout the
        // actual async engine, including rollback after late durable-state error.
        // A dropped client waiter cannot drop this future or metadata descriptor.
        let object = match source {
            Some(source) => self.publisher()?.publish_retained(&claim, source).await?,
            None => self.publisher()?.adopt_retained(&claim).await?,
        };
        Ok(self.commit_retention(prepared, object, Some(witness)))
    }
}
