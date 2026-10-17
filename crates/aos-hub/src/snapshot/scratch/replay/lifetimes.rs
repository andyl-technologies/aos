//! Read-only generation-7 lifetime checks after exact relational replay.
//!
//! These checks neither manufacture missing reservations nor activate provider
//! work. Historical generations keep their original verification contract.

use aos_hub_core::db::{
    BindingIdentityReservation, validate_binding_identity_plan_confirmation,
    validate_binding_identity_snapshot_history,
};
use rusqlite::OptionalExtension as _;

use super::{Failure, MemoryReplay, ScratchResult};

impl MemoryReplay {
    pub(super) fn lifetime_checks(&self) -> ScratchResult<()> {
        if self.catalogue.schema().version < 7 {
            return Ok(());
        }
        for query in [
            "SELECT EXISTS(SELECT 1 FROM bindings binding WHERE NOT EXISTS
               (SELECT 1 FROM binding_identity_reservations reservation
                 WHERE reservation.stable_id = binding.stable_id))",
            "SELECT EXISTS(SELECT 1 FROM surface_object_usage charge JOIN surface_objects object
               ON object.id = charge.surface_object_id WHERE object.registry_id IS NULL)",
            "SELECT EXISTS(SELECT 1 FROM surface_object_usage charge JOIN surface_objects object
               ON object.id = charge.surface_object_id JOIN registries registry ON registry.id = object.registry_id
               WHERE NOT (charge.org_id = registry.org_id OR (charge.org_id IS NULL AND registry.org_id IS NULL))
                 OR (charge.org_id IS NULL AND registry.org_id IS NOT NULL)
                 OR (charge.org_id IS NOT NULL AND registry.org_id IS NULL))",
            "SELECT EXISTS(SELECT 1 FROM mirror_import_objects original
               WHERE original.publication_commit_version = 7 AND NOT EXISTS
                 (SELECT 1 FROM surface_objects object JOIN surface_object_usage charge ON charge.surface_object_id = object.id
                   WHERE object.registry_id = original.registry_id AND object.object_key = original.source_path))",
            "SELECT EXISTS(SELECT 1 FROM (SELECT org_id, SUM(accounted_bytes) bytes, COUNT(*) objects
               FROM surface_object_usage WHERE org_id IS NOT NULL GROUP BY org_id) charge
               WHERE NOT EXISTS (SELECT 1 FROM org_usage usage
                 WHERE usage.org_id = charge.org_id AND usage.used_bytes >= charge.bytes
                   AND usage.object_count >= charge.objects))",
            "SELECT EXISTS(SELECT 1 FROM topology_plans WHERE plan_kind = 'delete_binding'
               AND (length(input_versions_json) > 4096 OR length(apply_result_json) > 4096))",
        ] {
            if self.scalar(query, Failure::Constraints)? != 0 {
                return Err(Failure::Constraints);
            }
        }
        self.direct_presence_checks()?;

        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT input_versions_json, applied_at, apply_idempotency_key, apply_result_json, confirmation_hash
               FROM topology_plans WHERE plan_kind = 'delete_binding' ORDER BY plan_id",
        ).map_err(|error| self.sql_failure(&error, Failure::Constraints))?;
        let mut histories = statement
            .query([])
            .map_err(|error| self.sql_failure(&error, Failure::Constraints))?;
        while let Some(row) = histories
            .next()
            .map_err(|error| self.sql_failure(&error, Failure::Constraints))?
        {
            self.budget.check()?;
            let input: String = row.get(0).map_err(|_| Failure::Constraints)?;
            let document: serde_json::Value =
                serde_json::from_str(&input).map_err(|_| Failure::Constraints)?;
            let stable_id = document["stable_id"].as_str().ok_or(Failure::Constraints)?;
            let (reservation, live) = connection.query_row(
                "SELECT reservation_id, reserved_at, EXISTS(SELECT 1 FROM bindings WHERE stable_id = ?1)
                   FROM binding_identity_reservations WHERE stable_id = ?1",
                [stable_id],
                |row| Ok((BindingIdentityReservation {
                    stable_id: stable_id.into(), reservation_id: row.get(0)?, reserved_at: row.get(1)?,
                }, row.get::<_, bool>(2)?)),
            ).optional().map_err(|error| self.sql_failure(&error, Failure::Constraints))?
                .ok_or(Failure::Constraints)?;
            let applied_at: Option<i64> = row.get(1).map_err(|_| Failure::Constraints)?;
            let key: Option<String> = row.get(2).map_err(|_| Failure::Constraints)?;
            let result: Option<String> = row.get(3).map_err(|_| Failure::Constraints)?;
            let confirmation: Option<String> = row.get(4).map_err(|_| Failure::Constraints)?;
            validate_binding_identity_plan_confirmation(&input, confirmation.as_deref())
                .map_err(|_| Failure::Constraints)?;
            validate_binding_identity_snapshot_history(
                &input,
                applied_at,
                key.as_deref(),
                result.as_deref(),
                live.then_some(&reservation),
            )
            .map_err(|_| Failure::Constraints)?;
        }
        self.budget.check()
    }
}
