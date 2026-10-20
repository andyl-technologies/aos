//! Test-only real SQLite initialization probes; never compiled into ordinary serving.

use super::*;

impl SqlDoBackend {
    pub(crate) async fn e2e_seed_master_two(&self) -> Result<()> {
        anyhow::ensure!(
            self.query("SELECT name FROM sqlite_schema LIMIT 1", &[])
                .await?
                .is_empty(),
            "fixture schema is not empty"
        );
        self.execute_batch("CREATE TABLE _do_migrations(id INTEGER PRIMARY KEY CHECK(id=0),applied INTEGER NOT NULL)").await?;
        self.execute_batch(MIGRATIONS[0]).await?;
        self.execute_batch(MIGRATIONS[7]).await?;
        self.execute("INSERT INTO _do_migrations(id,applied) VALUES(0,2)", &[])
            .await?;
        self.execute(
            "INSERT INTO users(email,created_at) VALUES('retained@example.test',1)",
            &[],
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn e2e_schema_fingerprint(&self) -> Result<serde_json::Value> {
        let objects = self
            .query(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name",
                &[],
            )
            .await?;
        let has = |name: &str| {
            objects
                .iter()
                .any(|row| row.get::<String>(1).is_ok_and(|value| value == name))
        };
        let versions = if has("_do_migrations") {
            self.query("SELECT id,applied FROM _do_migrations ORDER BY id", &[])
                .await?
        } else {
            Vec::new()
        };
        let identity = if has("hub_schema_identity") {
            self.query(
                "SELECT identity FROM hub_schema_identity ORDER BY identity",
                &[],
            )
            .await?
        } else {
            Vec::new()
        };
        let users = if has("users") {
            self.query("SELECT id,email FROM users ORDER BY id", &[])
                .await?
        } else {
            Vec::new()
        };
        let changes = self.query("SELECT total_changes()", &[]).await?;
        Ok(
            serde_json::json!({"schema":objects,"versions":versions,"identity":identity,"users":users,"changes":changes}),
        )
    }
}
