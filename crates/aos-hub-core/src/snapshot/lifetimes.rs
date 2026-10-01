//! Retained logical charges and permanent provider-authority identities.
//!
//! Row validation preserves exact accounting and reservation originals. It
//! performs no backfill, deletion settlement or restored runtime activation.

use anyhow::{ensure, Context as _, Result};

use crate::db::{BindingIdentityReservation, SurfaceObjectUsageRecord};
use crate::value::{FromValue, Row};

use super::TableContract;

pub(super) fn validate_row(name: &str, table: &TableContract, row: &Row) -> Result<()> {
    let cells = Cells { table, row };
    match name {
        "surface_objects"
            if table
                .columns
                .iter()
                .any(|column| column.name == "accounting_origin_version") =>
        {
            if let Some(version) = cells.get::<Option<i64>>("accounting_origin_version")? {
                ensure!(
                    version == 7
                        && cells.get::<Option<i64>>("registry_id")?.is_some()
                        && cells.get::<Option<i64>>("cache_id")?.is_none(),
                    "snapshot accounting origin is not an exclusive registry publication"
                );
            }
            Ok(())
        }
        "surface_object_usage" => SurfaceObjectUsageRecord {
            surface_object_id: cells.get("surface_object_id")?,
            org_id: cells.get("org_id")?,
            accounted_bytes: cells.get("accounted_bytes")?,
            resource_version: cells.get("resource_version")?,
            updated_at: cells.get("updated_at")?,
        }
        .validate(),
        "binding_identity_reservations" => BindingIdentityReservation {
            stable_id: cells.get("stable_id")?,
            reservation_id: cells.get("reservation_id")?,
            reserved_at: cells.get("reserved_at")?,
        }
        .validate(),
        "object_placements"
            if table
                .columns
                .iter()
                .any(|column| column.name == "observed_write_spec_version") =>
        {
            let pins = [
                cells.get::<Option<i64>>("observed_placement_resource_version")?,
                cells.get("observed_write_spec_version")?,
                cells.get("observed_binding_resource_version")?,
            ];
            ensure!(
                pins.iter().all(Option::is_none)
                    || pins.iter().all(|pin| pin.is_some_and(|value| value > 0)),
                "snapshot placement provenance is partial"
            );
            if let Some(session_id) = cells.get::<Option<String>>("direct_upload_session_id")? {
                ensure!(
                    crate::direct_upload::valid_direct_identity(&session_id)
                        && pins[0].is_some()
                        && cells.get::<String>("state")? == "present",
                    "snapshot Direct placement source is incomplete"
                );
            }
            if pins[0].is_some() && cells.get::<String>("state")? == "present" {
                ensure!(
                    cells.get::<Option<String>>("etag")?.is_some()
                        && (cells.get::<Option<String>>("provider_version")?.is_some()
                            || cells
                                .get::<Option<String>>("direct_upload_session_id")?
                                .is_some()),
                    "snapshot placement provenance lacks a positive provider receipt"
                );
            }
            Ok(())
        }
        _ => Ok(()),
    }
    .map_err(|_| anyhow::anyhow!("snapshot retained lifetime identity differs"))
}

struct Cells<'a> {
    table: &'a TableContract,
    row: &'a Row,
}

impl Cells<'_> {
    fn get<T: FromValue>(&self, name: &str) -> Result<T> {
        let index = self
            .table
            .columns
            .iter()
            .position(|column| column.name == name)
            .context("snapshot lifetime column is absent")?;
        self.row
            .get(index)
            .map_err(|_| anyhow::anyhow!("snapshot lifetime scalar differs"))
    }
}
