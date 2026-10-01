//! Admitted native source adapters for the shared encrypted logical record writer.

use anyhow::Result;

#[cfg(feature = "postgres")]
use crate::backend::postgres_snapshot::{PostgresSnapshotReader, PostgresSnapshotTable};
use crate::backend::sqlite_snapshot::{
    SqliteSnapshotLimits, SqliteSnapshotPage, SqliteSnapshotReader, SqliteSnapshotSchema,
    SqliteSnapshotSourceAudit, SqliteSnapshotTable, SqliteSnapshotTableCount,
};

use super::wire::{Audit, PostgresSource, POSTGRES_PROFILE, PROFILE};

pub(super) enum Source {
    Sqlite {
        reader: SqliteSnapshotReader,
        audit: SqliteSnapshotSourceAudit,
    },
    #[cfg(feature = "postgres")]
    Postgres(PostgresSnapshotReader),
}

impl Source {
    pub(super) fn schema(&self) -> &SqliteSnapshotSchema {
        match self {
            Self::Sqlite { reader, .. } => reader.schema(),
            #[cfg(feature = "postgres")]
            Self::Postgres(reader) => reader.schema(),
        }
    }

    pub(super) fn table_counts(&self) -> &[SqliteSnapshotTableCount] {
        match self {
            Self::Sqlite { audit, .. } => audit.table_counts(),
            #[cfg(feature = "postgres")]
            Self::Postgres(reader) => reader.audit().table_counts(),
        }
    }

    pub(super) fn profile(&self) -> &'static str {
        match self {
            Self::Sqlite { .. } => PROFILE,
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => POSTGRES_PROFILE,
        }
    }

    pub(super) fn declaration(&self) -> Option<PostgresSource> {
        match self {
            Self::Sqlite { .. } => None,
            #[cfg(feature = "postgres")]
            Self::Postgres(reader) => Some(PostgresSource::new(
                reader.audit().catalogue_sha256().to_owned(),
            )),
        }
    }

    pub(super) fn audit(&self) -> Audit {
        let (integrity, checked) = match self {
            Self::Sqlite { audit, .. } => ("passed", audit.checked_expressions()),
            #[cfg(feature = "postgres")]
            Self::Postgres(reader) => ("not_observed", reader.audit().checked_expressions()),
        };
        Audit {
            integrity: integrity.into(),
            compiled_checks: "passed".into(),
            declared_foreign_keys: "passed".into(),
            checked_expressions: checked.to_string(),
        }
    }

    pub(super) fn table(&mut self, name: &str) -> Result<Table<'_>> {
        match self {
            Self::Sqlite { reader, .. } => reader.table(name).map(Table::Sqlite),
            #[cfg(feature = "postgres")]
            Self::Postgres(reader) => reader.table(name).map(Table::Postgres),
        }
    }

    pub(super) async fn close(self) -> Result<()> {
        match self {
            Self::Sqlite { reader, .. } => reader.close().await,
            #[cfg(feature = "postgres")]
            Self::Postgres(reader) => reader.close().await,
        }
    }
}

pub(super) enum Table<'a> {
    Sqlite(SqliteSnapshotTable<'a>),
    #[cfg(feature = "postgres")]
    Postgres(PostgresSnapshotTable<'a>),
}

impl Table<'_> {
    pub(super) async fn next_page(
        &mut self,
        limits: SqliteSnapshotLimits,
    ) -> Result<SqliteSnapshotPage> {
        match self {
            Self::Sqlite(cursor) => cursor.next_page(limits).await,
            #[cfg(feature = "postgres")]
            Self::Postgres(cursor) => cursor.next_page(limits).await,
        }
    }
}
