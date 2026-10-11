//! Exact selected profile-head expiry horizons without provider effects.
//!
//! The maximum elapsed deadline coalesces every already-expired selected head.
//! A monotonic private admission clock prevents renewed or removed heads from creating
//! scan feedback. These indexed facts request work; they grant no fresh coverage.

use anyhow::{Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::schedules::ScheduleConfigurationV1;

use super::super::scans::profile_name;
use crate::db::assessment::AssessmentResource;
use crate::db::Database;

impl Database {
    /// Reads the elapsed deadline horizon for the exact reviewed package/profile set.
    ///
    /// Each chunk uses at most 67 bound parameters and returns one scalar. The
    /// closed configuration allows at most 1,000 coordinates and three profiles;
    /// no evidence blobs, external sources or arbitrary package predicates are read.
    ///
    /// # Errors
    /// Returns an error for invalid configuration, corrupt timestamps or database failure.
    pub(super) async fn expired_assessment_schedule_deadline(
        &self,
        resource: &AssessmentResource,
        configuration: &ScheduleConfigurationV1,
        as_of: &Timestamp,
    ) -> Result<Option<Timestamp>> {
        configuration.validate()?;
        if !configuration.continuous {
            return Ok(None);
        }
        let first = configuration
            .profiles
            .first()
            .context("schedule profiles are absent")?;
        let profiles = [
            first,
            configuration.profiles.get(1).unwrap_or(first),
            configuration.profiles.get(2).unwrap_or(first),
        ];
        let mut horizon = None;
        for packages in configuration.packages.chunks(60) {
            let mut values = vals![
                resource.registry_id,
                resource.inventory_digest.to_string(),
                resource.policy_digest.to_string(),
                profile_name(*profiles[0]),
                profile_name(*profiles[1]),
                profile_name(*profiles[2]),
                as_of.unix_seconds()
            ];
            let selectors = packages
                .iter()
                .enumerate()
                .map(|(index, _)| format!("?{}", index + 8))
                .collect::<Vec<_>>()
                .join(", ");
            for coordinate in packages {
                values.push(crate::value::Value::Text(coordinate.clone()));
            }
            let row = self.backend.query_opt(
                &format!("SELECT MAX(head.validated_until)
                    FROM assessment_heads AS head
                    JOIN assessment_subjects AS subject ON subject.registry_id = head.registry_id
                        AND subject.inventory_digest = head.inventory_digest AND subject.subject_ref = head.subject_ref
                    WHERE head.registry_id = ?1 AND head.inventory_digest = ?2 AND head.policy_digest = ?3
                        AND head.profile IN (?4, ?5, ?6) AND head.validated_until <= ?7
                        AND head.assessment_digest IS NOT NULL AND head.committed_generation > 0
                        AND subject.package_coordinate IN ({selectors})"),
                &values,
            ).await?.context("schedule deadline aggregate is absent")?;
            horizon = horizon.max(row.get::<Option<u64>>(0)?);
        }
        horizon.map(Timestamp::from_unix_seconds).transpose()
    }
}
