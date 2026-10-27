//! Closes bounded complete-body reads beneath one fresh selected observation.
//!
//! Each consumed artifact keeps its own original recipe. Grouping shares the
//! complete selected catalog, including every shard, and dispatches the same
//! closing checks together. It grants no publication or repair authority.

use super::*;

impl<F, C, V> FileBucket<F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Reads one bounded group while retaining every original until closing.
    ///
    /// # Errors
    /// Preserves scalar retrieval failures and refuses changed selection or
    /// any changed consumed artifact before returning any result in the group.
    pub(in crate::bucket::content) async fn get_selected_group(
        &self,
        identities: &[Identity],
        mode: super::super::ranged_pack::MemberReadMode,
    ) -> Result<Vec<Vec<u8>>, StoreFailure> {
        let holder = SingleHeld::acquire_read_namespace(self).await?;
        let held = holder.source();
        let retained = match held.identity_proof().retained_namespace() {
            Ok(_) => true,
            Err(error) if matches!(error.kind(), StoreErrorKind::Unsupported) => false,
            Err(error) => return Err(error),
        };

        let mut values = Vec::with_capacity(identities.len());
        if matches!(mode, super::super::ranged_pack::MemberReadMode::Ordinary) || !retained {
            // Preserve unsupported bindings' scalar I/O and refusal boundaries.
            // This actual read-only holder cannot mint a retained native proof.
            self.ensure_layout().await?;
            for identity in identities {
                values.push(self.get_locked_mode(identity, None, mode).await?);
                self.ensure_layout().await?;
            }
            return Ok(values);
        }

        let observed = held.observe_publication_ordinary_retained().await?;
        let reads = RequestReads {
            bucket: self,
            records: Mutex::new(Vec::new()),
            prefetched: Mutex::new(BTreeMap::new()),
            members: Mutex::new(Vec::new()),
            bounded: false,
            mode,
        };
        let catalog = self.catalog_observed_with_reads(&observed, &reads).await?;
        for identity in identities {
            #[cfg(test)]
            self.inner.content_observation.get(identity.kind());
            values.push(
                self.get_catalog_body_with_reads(&catalog, identity, None, &reads)
                    .await?,
            );
        }

        #[cfg(test)]
        self.inner.content_observation.before_get_close().await;
        reads.close(&observed, &catalog).await?;
        Ok(values)
    }
}
