use std::fs;

use anyhow::{Context, Result};

use crate::views::ViewManager;

/// Update access metadata for a path when it is served via narinfo.
/// Increments `access_count` and sets `last_accessed` to now.
pub fn update_access(views: &ViewManager, view: &str, hash: &str) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock error")?
        .as_secs() as i64;

    // Try bin/ first, then src/
    for ns in &["bin", "src"] {
        let meta_path = views
            .root()
            .join("meta")
            .join(view)
            .join(ns)
            .join(format!("{hash}.json"));

        if !meta_path.exists() {
            continue;
        }

        let meta_str = fs::read_to_string(&meta_path)
            .with_context(|| format!("reading {}", meta_path.display()))?;
        let mut meta: serde_json::Value = serde_json::from_str(&meta_str)
            .with_context(|| format!("parsing {}", meta_path.display()))?;

        // Update access fields
        meta["last_accessed"] = serde_json::json!(now);
        let count = meta
            .get("access_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        meta["access_count"] = serde_json::json!(count + 1);

        // Write back atomically
        views.write_metadata(view, ns, hash, &meta)?;
        return Ok(());
    }

    // No metadata found — that's OK, the path may have been served without push metadata
    Ok(())
}
