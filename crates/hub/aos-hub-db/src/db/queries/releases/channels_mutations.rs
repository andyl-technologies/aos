//! Channels mutations in the releases capability.

use super::*;

impl Database {
    /// Replace a registry's channels (and partitions) without touching the
    /// rest of the index.
    ///
    /// This is the write half of the incremental channel refresh: when the
    /// ref advertisement is unchanged, only the mutable channel partitions
    /// need re-verifying, so only `channels`/`channel_partitions` are
    /// rewritten (in one transaction) and `registry_index.indexed_at` is
    /// bumped. Everything else — packages, releases, roster, caches — is
    /// left untouched.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure; the transaction rolls back.
    pub async fn update_channels(
        &self,
        registry_id: i64,
        channels: &[ChannelSummary],
    ) -> Result<()> {
        self.update_channels_from_placement(registry_id, channels, None)
            .await
    }

    /// The recorded anti-rollback floor for one channel, when set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn channel_floor(&self, registry_id: i64, channel: &str) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT floor FROM channel_floors WHERE registry_id = ?1 AND channel = ?2",
                &vals![registry_id, channel],
            )
            .await
            .context("loading channel floor")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Set (or overwrite) the anti-rollback floor for one channel.
    ///
    /// Callers are responsible for only ever *raising* the floor; this
    /// method records whatever it is given.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_channel_floor(
        &self,
        registry_id: i64,
        channel: &str,
        floor: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO channel_floors (registry_id, channel, floor)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(registry_id, channel) DO UPDATE SET floor = excluded.floor",
                &vals![registry_id, channel, floor],
            )
            .await?;
        Ok(())
    }

    /// Replaces channels from one exact authoritative placement.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-authoritative source, missing parent index,
    /// stale generation, or database failure.
    pub async fn update_channels_from_placement(
        &self,
        registry_id: i64,
        channels: &[ChannelSummary],
        indexed_placement_id: Option<i64>,
    ) -> Result<()> {
        self.assert_registry_index_mutation_source(registry_id, indexed_placement_id)
            .await?;
        let current = self
            .backend
            .query_opt(
                "SELECT content_digest FROM registry_index
                 WHERE registry_id = ?1 AND generation > 0 AND content_digest IS NOT NULL",
                &vals![registry_id],
            )
            .await?
            .context("incremental index has no immutable parent generation")?;
        let previous_digest: String = current.get(0)?;
        let content_digest = incremental_index_digest(&previous_digest, channels)?;
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("indexed registry does not exist")?;
        let indexed_at = unix_now();
        // Client-side channel ids (assigned in order) so this is one batch with
        // no mid-flight `last_insert_rowid`; the per-registry sequential indexer
        // rules out a concurrent writer colliding on the id base.
        let mut next_channel = self.max_id("channels").await?;
        let mut stmts = vec![Self::registry_index_mutation_guard(
            registry_id,
            indexed_placement_id,
        )];
        stmts.push(
            Statement::new(
                "UPDATE channels SET active = 0 WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            )
            .unchecked(),
        );
        for channel in channels {
            let channel_id = if let Some(row) = self
                .backend
                .query_opt(
                    "SELECT id FROM channels WHERE registry_id = ?1 AND name = ?2",
                    &vals![registry_id, channel.name],
                )
                .await?
            {
                row.get(0)?
            } else {
                next_channel += 1;
                next_channel
            };
            stmts.push(
                Statement::new(
                    "INSERT INTO channels (id, registry_id, name, frontier, active)
                 VALUES (?1, ?2, ?3, ?4, 1)
                 ON CONFLICT(registry_id, name) DO UPDATE SET
                   frontier = excluded.frontier, active = 1",
                    vals![channel_id, registry_id, channel.name, channel.frontier].to_vec(),
                )
                .unchecked(),
            );
            for (bucket, release) in channel.partitions.iter().enumerate() {
                if let Some(release) = release {
                    stmts.push(
                        Statement::new(
                            "INSERT INTO channel_partitions (channel_id, bucket, release)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(channel_id, bucket) DO UPDATE SET
                           release = excluded.release",
                            vals![channel_id, bucket as i64, release].to_vec(),
                        )
                        .unchecked(),
                    );
                } else {
                    stmts.push(
                        Statement::new(
                            "DELETE FROM channel_partitions
                         WHERE channel_id = ?1 AND bucket = ?2",
                            vals![channel_id, bucket as i64].to_vec(),
                        )
                        .unchecked(),
                    );
                }
            }
        }
        stmts.push(
            Statement::new(
                "UPDATE registry_index
             SET indexed_at = ?2, generation = generation + 1, content_digest = ?3
             WHERE registry_id = ?1 AND generation > 0 AND content_digest = ?4",
                vals![registry_id, indexed_at, content_digest, previous_digest].to_vec(),
            )
            .expecting(1),
        );
        if registry.org_id.is_some() {
            let status = self
                .index_status(registry_id)
                .await?
                .context("incremental index status does not exist")?;
            let event = aos_hub_model::webhook::WebhookEvent::IndexCompleted {
                registry: registry.slug.clone(),
                commit: status
                    .last_indexed_commit
                    .context("incremental index has no indexed commit")?,
                packages: self.list_packages(registry_id).await?.len(),
                releases: self.list_releases(registry_id).await?.len(),
                channels: channels.len(),
                incremental: true,
                at: indexed_at,
            };
            let dedupe_key = serde_json::to_string(&serde_json::json!([
                registry.slug.as_str(),
                event.event_type(),
                content_digest.as_str()
            ]))?;
            stmts.push(
                Self::operational_webhook_event_insert_statement(
                    &registry,
                    &event,
                    Some(&dedupe_key),
                    indexed_at,
                )?
                .unchecked(),
            );
        }
        stmts.extend(
            self.channel_floor_guard_statements(registry_id, channels)
                .await?,
        );
        self.backend.checked_batch(&stmts).await
    }
}
