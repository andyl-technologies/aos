//! Integration helpers in the caches capability.

use super::*;

impl RpcService {
    pub(in crate::service) fn mutated_consumer_cache_entries(
        stack: &pb::ConsumerCacheStack,
        change: &pb::ConsumerCacheChange,
    ) -> Result<Vec<pb::ConsumerCacheStackEntry>, RpcError> {
        let mut entries = stack.entries.clone();
        let current_index = entries
            .iter()
            .position(|entry| entry.entry_id == change.entry_id);
        match change.operation.as_str() {
            "add" => entries.push(
                change
                    .desired
                    .clone()
                    .ok_or_else(|| RpcError::invalid("add requires desired"))?,
            ),
            "replace" => {
                let index =
                    current_index.ok_or_else(|| RpcError::not_found("consumer cache entry"))?;
                entries[index] = change
                    .desired
                    .clone()
                    .ok_or_else(|| RpcError::invalid("replace requires desired"))?;
            }
            "move" => {
                let index =
                    current_index.ok_or_else(|| RpcError::not_found("consumer cache entry"))?;
                let entry = entries.remove(index);
                entries.push(entry);
            }
            "remove" => {
                let index =
                    current_index.ok_or_else(|| RpcError::not_found("consumer cache entry"))?;
                entries.remove(index);
            }
            _ => return Err(RpcError::invalid("unsupported consumer cache operation")),
        }
        let moving_id = change
            .desired
            .as_ref()
            .map(|entry| entry.entry_id.as_str())
            .unwrap_or(change.entry_id.as_str());
        if !change.before_entry_id.is_empty() {
            let from = entries
                .iter()
                .position(|entry| entry.entry_id == moving_id)
                .ok_or_else(|| RpcError::invalid("moving entry disappeared"))?;
            let entry = entries.remove(from);
            let before = entries
                .iter()
                .position(|entry| entry.entry_id == change.before_entry_id)
                .ok_or_else(|| RpcError::invalid("before entry disappeared"))?;
            entries.insert(before, entry);
        }
        if !change.mirror_with_entry_id.is_empty() {
            let peer_group = entries
                .iter()
                .find(|entry| entry.entry_id == change.mirror_with_entry_id)
                .map(|entry| entry.mirror_group_id.clone())
                .filter(|group| !group.is_empty())
                .unwrap_or_else(|| format!("mirror:{}", change.mirror_with_entry_id));
            for entry in &mut entries {
                if entry.entry_id == moving_id || entry.entry_id == change.mirror_with_entry_id {
                    entry.mirror_group_id = peer_group.clone();
                }
            }
        }
        Ok(entries)
    }

    pub(in crate::service) async fn validate_consumer_cache_change(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
        stack: &pb::ConsumerCacheStack,
        change: &pb::ConsumerCacheChange,
    ) -> Result<(), RpcError> {
        let ids = stack
            .entries
            .iter()
            .map(|entry| entry.entry_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        match change.operation.as_str() {
            "add" => {
                let desired = change
                    .desired
                    .as_ref()
                    .ok_or_else(|| RpcError::invalid("add requires desired"))?;
                if desired.entry_id.is_empty() || ids.contains(desired.entry_id.as_str()) {
                    return Err(RpcError::invalid(
                        "add requires a new non-empty desired.entry_id",
                    ));
                }
                self.consumer_entry_url(auth, registry, desired).await?;
            }
            "replace" => {
                if !ids.contains(change.entry_id.as_str()) {
                    return Err(RpcError::not_found("consumer cache entry"));
                }
                let desired = change
                    .desired
                    .as_ref()
                    .ok_or_else(|| RpcError::invalid("replace requires desired"))?;
                self.consumer_entry_url(auth, registry, desired).await?;
            }
            "move" | "remove" => {
                if !ids.contains(change.entry_id.as_str()) {
                    return Err(RpcError::not_found("consumer cache entry"));
                }
            }
            _ => {
                return Err(RpcError::invalid(
                    "operation must be add, replace, move, or remove",
                ));
            }
        }
        for (field, id) in [
            ("before_entry_id", change.before_entry_id.as_str()),
            ("mirror_with_entry_id", change.mirror_with_entry_id.as_str()),
        ] {
            if !id.is_empty() && !ids.contains(id) {
                return Err(RpcError::invalid(format!(
                    "{field} references an unknown stack entry"
                )));
            }
        }
        Ok(())
    }

    pub(in crate::service) async fn apply_consumer_cache_change_to_toml(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
        stack: &pb::ConsumerCacheStack,
        change: &pb::ConsumerCacheChange,
        ready_routes: &std::collections::BTreeMap<
            String,
            aos_hub_db::db::ReadyRouteAdvertisementIdentity,
        >,
    ) -> Result<String, RpcError> {
        let entries = Self::mutated_consumer_cache_entries(stack, change)?;
        let head = self.head_commit(registry).await?;
        let fetch = self.topology_surface_fetcher(SurfaceTarget::Registry(registry.id));
        let existing = crate::git::load_committed_file(fetch.as_ref(), head, "registry.toml")
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::FailedPrecondition("registry.toml is missing".to_string()))?;
        let mut root: toml::Value = toml::from_str(&existing)
            .map_err(|error| RpcError::invalid(format!("invalid registry.toml: {error}")))?;
        let table = root
            .as_table_mut()
            .ok_or_else(|| RpcError::invalid("registry.toml root must be a table"))?;
        if entries.is_empty() {
            table.remove("caches");
        } else {
            let mut nodes = Vec::new();
            let mut consumed_groups = std::collections::BTreeSet::new();
            for entry in &entries {
                if entry.mirror_group_id.is_empty() {
                    nodes.push(
                        self.consumer_endpoint_toml(auth, registry, entry, ready_routes)
                            .await?,
                    );
                } else if consumed_groups.insert(entry.mirror_group_id.clone()) {
                    let mut members = Vec::new();
                    for member in entries
                        .iter()
                        .filter(|candidate| candidate.mirror_group_id == entry.mirror_group_id)
                    {
                        members.push(
                            self.consumer_endpoint_toml(auth, registry, member, ready_routes)
                                .await?,
                        );
                    }
                    let mut mirror = toml::map::Map::new();
                    mirror.insert(
                        "kind".to_string(),
                        toml::Value::String("mirror".to_string()),
                    );
                    mirror.insert("members".to_string(), toml::Value::Array(members));
                    nodes.push(toml::Value::Table(mirror));
                }
            }
            let cache_value = if nodes.len() == 1 {
                nodes.remove(0)
            } else {
                let mut try_node = toml::map::Map::new();
                try_node.insert("kind".to_string(), toml::Value::String("try".to_string()));
                try_node.insert("members".to_string(), toml::Value::Array(nodes));
                toml::Value::Table(try_node)
            };
            table.insert("caches".to_string(), cache_value);
        }
        toml::to_string_pretty(&root).map_err(RpcError::internal)
    }

    pub(in crate::service) async fn consumer_cache_stack_message(
        &self,
        registry: &RegistryRecord,
    ) -> Result<pb::ConsumerCacheStack, RpcError> {
        let rows = self
            .db
            .registry_cache_stack_entries(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let indexed_commit = if let Some(entry) = rows.first() {
            entry.indexed_commit.clone()
        } else {
            self.db
                .index_status(registry.id)
                .await
                .map_err(RpcError::internal)?
                .and_then(|status| status.last_indexed_commit)
                .unwrap_or_default()
        };
        let mut entries = Vec::with_capacity(rows.len());
        for row in &rows {
            entries.push(self.consumer_cache_entry_message(row).await?);
        }
        Ok(pb::ConsumerCacheStack {
            registry_id: registry.slug.clone(),
            indexed_commit: indexed_commit.clone(),
            entries,
            resource_version: indexed_commit,
        })
    }

    pub(in crate::service) async fn consumer_cache_entry_message(
        &self,
        row: &aos_hub_db::db::RegistryCacheStackEntryRecord,
    ) -> Result<pb::ConsumerCacheStackEntry, RpcError> {
        let source = match row.cache_id {
            Some(cache_id) => {
                let cache = self
                    .db
                    .binary_cache_by_id(cache_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("binary cache"))?;
                pb::consumer_cache_stack_entry::Source::BinaryCacheId(cache.slug)
            }
            None => pb::consumer_cache_stack_entry::Source::External(pb::ExternalConsumerCache {
                url: row.committed_url.clone(),
            }),
        };
        Ok(pb::ConsumerCacheStackEntry {
            entry_id: row.stack_path.clone(),
            source: Some(source),
            priority: u32::try_from(row.resolved_priority)
                .map_err(|_| RpcError::internal(anyhow::anyhow!("negative stack priority")))?,
            mirror_group_id: row.mirror_group_id.clone().unwrap_or_default(),
        })
    }

    pub(in crate::service) async fn cache_integration_message(
        &self,
        cache: &aos_hub_db::db::BinaryCache,
        registry: &RegistryRecord,
        publication_rows: &[aos_hub_db::db::RegistryCacheStackEntryRecord],
    ) -> Result<pb::CacheIntegration, RpcError> {
        let mut publications = Vec::new();
        for row in publication_rows
            .iter()
            .filter(|row| row.cache_id == Some(cache.id) && row.registry_id == registry.id)
        {
            publications.push(self.consumer_cache_entry_message(row).await?);
        }
        let retention = self
            .db
            .cache_retention_subscription_topology(cache.id, registry.id)
            .await
            .map_err(RpcError::internal)?
            .map(|record| {
                Self::retention_subscription_message(&record, &cache.slug, &registry.slug)
            })
            .transpose()?;
        let population = self
            .population_target_for_pair(cache.id, registry.id)
            .await?
            .map(|record| Self::population_target_message(&record, &cache.slug, &registry.slug));
        Ok(pb::CacheIntegration {
            cache_id: cache.slug.clone(),
            registry_id: registry.slug.clone(),
            publications,
            retention,
            population,
        })
    }
}
