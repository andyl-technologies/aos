//! Channels reads in the releases capability.

use super::*;

impl Database {
    /// Lists live channel partitions whose target owns a complete release snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_retention_channel_partitions(
        &self,
        registry_id: i64,
    ) -> Result<Vec<RetentionChannelPartitionRecord>> {
        let releases = self.list_retention_release_snapshots(registry_id).await?;
        let by_id = releases
            .into_iter()
            .map(|release| (release.release_id, release))
            .collect::<std::collections::BTreeMap<_, _>>();
        let rows = self
            .backend
            .query(
                "SELECT ch.id, ch.name, cp.bucket, rel.id, rel.semver
                 FROM channels ch
                 JOIN channel_partitions cp ON cp.channel_id = ch.id
                 JOIN releases rel ON rel.registry_id = ch.registry_id
                   AND rel.semver = cp.release
                 WHERE ch.registry_id = ?1 AND ch.active = 1
                 ORDER BY ch.name, cp.bucket",
                &vals![registry_id],
            )
            .await?;
        let mut partitions = Vec::new();
        for row in &rows {
            let release_id: i64 = row.get(3)?;
            let Some(release) = by_id.get(&release_id) else {
                continue;
            };
            partitions.push(RetentionChannelPartitionRecord {
                channel_id: row.get(0)?,
                channel_name: row.get(1)?,
                bucket: row.get(2)?,
                release_id,
                release_tag: row.get(4)?,
                snapshot_id: release.snapshot_id.clone(),
                artifacts: release.artifacts.clone(),
            });
        }
        Ok(partitions)
    }

    /// List channels with their full partition maps.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_channels(&self, registry_id: i64) -> Result<Vec<ChannelSummary>> {
        let rows = self
            .backend
            .query(
                "SELECT c.id, c.name, c.frontier, p.bucket, p.release
                 FROM channels c
                 LEFT JOIN channel_partitions p ON p.channel_id = c.id
                 WHERE c.registry_id = ?1 AND c.active = 1
                 ORDER BY c.name, p.bucket",
                &vals![registry_id],
            )
            .await?;

        let mut out: Vec<ChannelSummary> = Vec::new();
        let mut current_id = None;
        for row in rows {
            let channel_id: i64 = row.get(0)?;
            if current_id != Some(channel_id) {
                out.push(ChannelSummary {
                    name: row.get(1)?,
                    frontier: row.get(2)?,
                    partitions: vec![None; 256],
                });
                current_id = Some(channel_id);
            }

            let bucket: Option<i64> = row.get(3)?;
            let release: Option<String> = row.get(4)?;
            if let (Some(bucket), Some(release), Some(channel)) = (bucket, release, out.last_mut())
            {
                if let Ok(bucket) = usize::try_from(bucket) {
                    if let Some(slot) = channel.partitions.get_mut(bucket) {
                        *slot = Some(release);
                    }
                }
            }
        }
        Ok(out)
    }
}
