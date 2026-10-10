//! Channels helpers in the releases capability.

use super::*;

impl Database {
    // -- anti-rollback floors ------------------------------------------------

    pub(in crate::db) async fn channel_floor_guard_statements(
        &self,
        registry_id: i64,
        channels: &[ChannelSummary],
    ) -> Result<Vec<CheckedStatement>> {
        let mut statements = Vec::new();
        let mut names = std::collections::BTreeSet::new();
        for channel in channels {
            anyhow::ensure!(
                names.insert(channel.name.as_str()),
                "snapshot repeats channel '{}'",
                channel.name
            );
            let Some(frontier) = channel.frontier.as_deref() else {
                continue;
            };
            let frontier_version = semver::Version::parse(frontier)
                .with_context(|| format!("channel '{}' has invalid frontier", channel.name))?;
            let floor = self.channel_floor(registry_id, &channel.name).await?;
            if let Some(floor) = floor {
                let floor_version = semver::Version::parse(&floor).with_context(|| {
                    format!("channel '{}' has an invalid recorded floor", channel.name)
                })?;
                anyhow::ensure!(
                    frontier_version >= floor_version,
                    "channel '{}' frontier {frontier} is below the recorded floor {floor}: refusing rollback",
                    channel.name
                );
                statements.push(CheckedStatement::exact(
                    "DELETE FROM channel_floors
                     WHERE registry_id = ?1 AND channel = ?2 AND floor = ?3",
                    vals![registry_id, channel.name, floor].to_vec(),
                    1,
                ));
            }
            statements.push(CheckedStatement::exact(
                "INSERT INTO channel_floors (registry_id, channel, floor)
                 VALUES (?1, ?2, ?3)",
                vals![registry_id, channel.name, frontier].to_vec(),
                1,
            ));
        }
        Ok(statements)
    }
}
