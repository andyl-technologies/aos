//! Selects explicit package owners whose interface dependencies may be refreshed.
//!
//! Eligibility is independent of payload changes. The native resolver keeps
//! original signed package roots and protects dependency choices of owners that
//! are held, excluded, or outside the requested package filter.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};

use crate::install::native::Prepared;
use crate::profile::{Generation, Profile};
use crate::types::InstalledMeta;

/// Selects installed explicit owners under the ordinary upgrade filters.
pub(super) fn refresh_names(
    installed: &[InstalledMeta],
    requested: &[String],
    excluded: &[String],
) -> BTreeSet<String> {
    let held: BTreeSet<_> = installed
        .iter()
        .filter_map(|entry| entry.apm.as_ref())
        .filter(|entry| entry.held)
        .map(|entry| entry.name.as_str())
        .collect();

    installed
        .iter()
        .filter_map(|entry| entry.apm.as_ref())
        .filter(|entry| {
            entry.explicit
                && !held.contains(entry.name.as_str())
                && (requested.is_empty() || requested.contains(&entry.name))
                && !excluded.contains(&entry.name)
        })
        .map(|entry| entry.name.clone())
        .collect()
}

/// Publishes new interface choices while preserving the selected payload roots.
///
/// # Errors
/// Returns an error if preparation changes payload selection, the previous
/// generation is absent, profile construction fails, or native activation fails.
pub(super) fn commit(
    profile: &Profile,
    installed: &[InstalledMeta],
    prepared: Prepared,
    printer: &aos_core::output::Printer,
) -> Result<Generation> {
    let payloads: BTreeSet<_> = installed
        .iter()
        .map(|entry| entry.store_path.as_str())
        .collect();
    ensure!(
        prepared.selected_paths() == payloads && prepared.additional.is_empty(),
        "interface-only upgrade changed installed payload selection"
    );

    let previous = profile
        .current_generation()?
        .context("interface upgrade has no previous generation")?;
    let generation = profile.new_generation()?;
    crate::install::copy_roots_except_hashes(&previous, &generation, &Default::default())?;
    let metadata_profile = Profile {
        path: generation.path.clone(),
        scope: profile.scope,
    };
    for entry in installed {
        crate::profile::meta::write_meta(
            &metadata_profile,
            crate::registry::store_path_hash(&entry.store_path),
            entry,
        )?;
    }

    crate::profile::merge::build_generation_fhs_tree(&generation, printer)?;
    prepared.commit(profile, &generation)?;
    Ok(generation)
}

#[cfg(test)]
mod tests {
    use super::refresh_names;
    use crate::upgrade::tests::sample_installed_with_flags;

    #[test]
    fn unchanged_payload_is_eligible_for_interface_refresh() {
        let installed = [sample_installed_with_flags(
            "app", "1.0", "app", "main", true, false,
        )];

        let selected = refresh_names(&installed, &[], &[]);

        assert_eq!(selected.into_iter().collect::<Vec<_>>(), ["app"]);
    }

    #[test]
    fn interface_refresh_obeys_requested_excluded_and_held_owners() {
        let installed = [
            sample_installed_with_flags("selected", "1.0", "a", "main", true, false),
            sample_installed_with_flags("excluded", "1.0", "b", "main", true, false),
            sample_installed_with_flags("held", "1.0", "c", "main", true, true),
            sample_installed_with_flags("implicit", "1.0", "d", "main", false, false),
            sample_installed_with_flags("outside", "1.0", "e", "main", true, false),
        ];
        let requested = [
            "selected".into(),
            "excluded".into(),
            "held".into(),
            "implicit".into(),
        ];

        let selected = refresh_names(&installed, &requested, &["excluded".into()]);

        assert_eq!(selected.into_iter().collect::<Vec<_>>(), ["selected"]);
    }

    #[test]
    fn held_named_output_protects_the_package_owner() {
        let installed = [
            sample_installed_with_flags("app", "1.0", "out", "main", true, false),
            sample_installed_with_flags("app", "1.0", "dev", "main", false, true),
        ];

        assert!(refresh_names(&installed, &[], &[]).is_empty());
    }
}
