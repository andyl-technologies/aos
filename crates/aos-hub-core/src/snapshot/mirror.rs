//! Exact retained mirror original, progress and terminal row consistency.
//!
//! These checks preserve the original private bytes. They do not authenticate
//! provider proof, renew authority or permit a restored job to resume effects.

use anyhow::{ensure, Context as _, Result};

use crate::db::MirrorImportRecord;
use crate::value::{FromValue, Row};

use super::TableContract;

pub(super) fn validate_row(name: &str, table: &TableContract, row: &Row) -> Result<()> {
    if name != "mirror_import_objects" {
        return Ok(());
    }

    let cells = Cells { table, row };
    let record = MirrorImportRecord::decode(
        &cells.get::<String>("job_id")?,
        cells.get("registry_id")?,
        &cells.get::<String>("original_digest")?,
        &cells.get::<String>("original_json")?,
        cells.get::<Option<String>>("progress_json")?.as_deref(),
        &cells.get::<String>("state")?,
        cells.get::<Option<String>>("commit_digest")?.as_deref(),
        cells.get("created_at")?,
        cells.get("updated_at")?,
    )
    .map_err(|_| anyhow::anyhow!("snapshot mirror original or lifecycle differs"))?;
    if table
        .columns
        .iter()
        .any(|column| column.name == "publication_commit_version")
    {
        record
            .validate_publication_commit_version(cells.get("publication_commit_version")?)
            .map_err(|_| anyhow::anyhow!("snapshot mirror publication qualifier differs"))?;
    }
    if table
        .columns
        .iter()
        .any(|column| column.name == "source_path")
    {
        record
            .validate_index(
                cells.get::<Option<String>>("source_path")?.as_deref(),
                cells
                    .get::<Option<String>>("source_path_digest")?
                    .as_deref(),
                cells.get::<Option<String>>("copy_operation_id")?.as_deref(),
            )
            .map_err(|_| anyhow::anyhow!("snapshot mirror source index differs"))?;
    } else {
        ensure!(
            record.original.copy_operation_id.is_none(),
            "historical snapshot mirror operation differs"
        );
    }
    Ok(())
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
            .context("snapshot mirror column is absent")?;
        self.row
            .get(index)
            .map_err(|_| anyhow::anyhow!("snapshot mirror scalar differs"))
    }
}
