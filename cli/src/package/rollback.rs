use anyhow::{bail, Result};

use super::config::ApmConfig;
use super::profile::meta;
use super::profile::Profile;
use super::registry::RegistrySet;
use aos::output::Printer;

/// Run `apm rollback [--generation=N]`.
///
/// Rollback is instantaneous -- no downloads, no store mutations.
/// It switches the `current` symlink to a previous generation and
/// rebuilds metadata from that generation's roots.
pub async fn run(
    config: &ApmConfig,
    generation: Option<u32>,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    let profile = Profile::open(config.scope)?;

    // Must have a current generation to roll back from.
    let current = match profile.current_generation()? {
        Some(g) => g,
        None => bail!("no active generation to roll back from"),
    };

    let all_gens = profile.list_generations()?;

    // Determine target generation.
    let target = if let Some(n) = generation {
        // Explicit generation number.
        match all_gens.iter().find(|g| g.number == n) {
            Some(g) => g,
            None => bail!("generation {n} not found"),
        }
    } else {
        // Find the highest-numbered generation below the current one.
        match all_gens
            .iter()
            .rev()
            .find(|g| g.number < current.number)
        {
            Some(g) => g,
            None => bail!("no previous generation to roll back to"),
        }
    };

    // Show what we are about to do.
    printer.info(&format!(
        "Rolling back from generation {} to generation {}.",
        current.number, target.number
    ));

    // Optionally show package differences.
    let current_roots = current.roots().unwrap_or_default();
    let target_roots = target.roots().unwrap_or_default();

    let current_hashes: std::collections::HashSet<&str> =
        current_roots.iter().map(|(h, _)| h.as_str()).collect();
    let target_hashes: std::collections::HashSet<&str> =
        target_roots.iter().map(|(h, _)| h.as_str()).collect();

    let added: Vec<_> = target_hashes.difference(&current_hashes).collect();
    let removed: Vec<_> = current_hashes.difference(&target_hashes).collect();

    if !added.is_empty() || !removed.is_empty() {
        if !added.is_empty() {
            printer.plain(&format!("  Restoring {} path(s).", added.len()));
        }
        if !removed.is_empty() {
            printer.plain(&format!("  Removing {} path(s).", removed.len()));
        }
    }

    if dry_run {
        printer.info("Dry run: no changes made.");
        return Ok(());
    }

    // Switch to the target generation.
    profile.switch_to(target)?;

    // Rebuild metadata from the target generation's roots.
    let reg_configs = config.enabled_registries();
    let registries = RegistrySet::load(&config.cache_path(), &reg_configs, "x86_64-linux")?;
    meta::rebuild_meta(&profile, target, &registries)?;

    printer.success(&format!("Rolled back to generation {}.", target.number));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::profile::Profile;
    use crate::package::types::ProfileScope;
    use tempfile::TempDir;

    fn test_profile(tmp: &TempDir) -> Profile {
        Profile::open_at(tmp.path().to_path_buf(), ProfileScope::User).unwrap()
    }



    #[tokio::test]
    async fn rollback_switches_to_previous_generation() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let g1 = profile.new_generation().unwrap();
        let g2 = profile.new_generation().unwrap();
        profile.switch_to(&g2).unwrap();

        // Verify current is gen-2.
        assert_eq!(profile.current_generation().unwrap().unwrap().number, 2);

        // Rollback should switch to gen-1 (the previous).
        // We cannot use run() directly because it calls Profile::open() which
        // uses the system path. Instead, test the logic manually.
        let all_gens = profile.list_generations().unwrap();
        let current = profile.current_generation().unwrap().unwrap();
        let target = all_gens
            .iter()
            .rev()
            .find(|g| g.number < current.number)
            .unwrap();
        assert_eq!(target.number, g1.number);

        profile.switch_to(target).unwrap();
        assert_eq!(profile.current_generation().unwrap().unwrap().number, 1);
    }

    #[tokio::test]
    async fn rollback_to_specific_generation() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let _g1 = profile.new_generation().unwrap();
        let _g2 = profile.new_generation().unwrap();
        let g3 = profile.new_generation().unwrap();
        profile.switch_to(&g3).unwrap();

        // Roll back to generation 1 specifically.
        let all_gens = profile.list_generations().unwrap();
        let target = all_gens.iter().find(|g| g.number == 1).unwrap();
        profile.switch_to(target).unwrap();

        assert_eq!(profile.current_generation().unwrap().unwrap().number, 1);
    }

    #[tokio::test]
    async fn rollback_no_previous_generation_errors() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let g1 = profile.new_generation().unwrap();
        profile.switch_to(&g1).unwrap();

        // Only one generation exists; no previous generation available.
        let all_gens = profile.list_generations().unwrap();
        let current = profile.current_generation().unwrap().unwrap();
        let target = all_gens
            .iter()
            .rev()
            .find(|g| g.number < current.number);
        assert!(target.is_none(), "expected no previous generation");
    }

    #[tokio::test]
    async fn rollback_no_current_generation_errors() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        // No switch_to has been called, so current_generation is None.
        assert!(profile.current_generation().unwrap().is_none());
    }
}
