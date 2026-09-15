//! Qualified image rollout identity and state transitions.
//!
//! This module authenticates the running and candidate image identities before
//! A/B selection, gates native executor replacement on a drained reboot, and
//! constructs the durable `aos.image-rollout/v1` record.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::types::{ImageGeneration, ImageGenerationState, ImageRollout, ImageRolloutStatus};

use super::{
    SystemTransitionMode, load_image_generation_state_pub, read_toplevel_meta,
    running_image_generation,
};

mod ability;
mod boot_commit;
mod model;
mod observer;
mod plan;
mod process;
mod provider;

pub(crate) use ability::NativeAbRolloutBackend;
pub use boot_commit::run_from_process as run_boot_commit_from_process;
pub(crate) use boot_commit::verify_rollout_boot_commit;
pub(super) use ability::retained_uki_entry_ids;
pub(crate) use model::{AbRolloutRequest, MAX_RETENTION_MILLIS, RolloutImageIdentity};
pub use observer::run_from_process as run_observer_from_process;
pub(crate) use plan::authenticate_single_image_rollout_fragment;
pub use provider::run_from_process as run_provider_from_process;

const IMAGE_ROLLOUT_SCHEMA: &str = "aos.image-rollout/v1";

pub(super) const fn is_qualified_image_rollout(mode: SystemTransitionMode, drain: bool) -> bool {
    matches!(mode, SystemTransitionMode::Reboot) && drain
}

/// Verifies the data and executor boundary before any A/B image selection.
pub(super) fn preflight_image_selection(
    image_profile: &Path,
    system_profile: &Path,
    candidate_toplevel: &Path,
    qualified_rollout: bool,
) -> Result<()> {
    let authenticated_running = running_image_generation()
        .context("authenticating the actual running image before selection")?;
    preflight_image_selection_beneath(
        image_profile,
        system_profile,
        candidate_toplevel,
        qualified_rollout,
        Path::new("/"),
        &authenticated_running,
    )
}

/// Verifies an image selection against live authenticated state without mutation.
///
/// # Errors
///
/// Returns an error for an unauthenticated running image, incompatible state
/// format or executor transition, unsettled retained configuration, or invalid
/// candidate metadata.
pub(super) fn probe_image_selection(
    image_profile: &Path,
    system_profile: &Path,
    candidate_toplevel: &Path,
    qualified_rollout: bool,
) -> Result<()> {
    let authenticated_running = running_image_generation()
        .context("authenticating the actual running image before selection")?;
    preflight_image_selection_beneath(
        image_profile,
        system_profile,
        candidate_toplevel,
        qualified_rollout,
        Path::new("/"),
        &authenticated_running,
    )
}

fn preflight_image_selection_beneath(
    image_profile: &Path,
    system_profile: &Path,
    candidate_toplevel: &Path,
    qualified_rollout: bool,
    immutable_root: &Path,
    authenticated_running: &ImageGeneration,
) -> Result<()> {
    let images = load_image_generation_state_pub(image_profile)?;
    let running = images
        .running_generation()
        .cloned()
        .context("image state has no running generation")?;
    ensure!(
        serde_json::to_value(&running)? == serde_json::to_value(authenticated_running)?,
        "image state running generation differs from the authenticated booted image"
    );
    crate::config_eval::materialize::validate_canonical_store_path(&running.toplevel)
        .context("validating running image toplevel identity")?;
    let running_toplevel =
        immutable_store_path_beneath(immutable_root, Path::new(&running.toplevel))?;
    let immutable_running_state_version = read_toplevel_meta(&running_toplevel, "state-version")?;
    let immutable_running_executor = read_toplevel_meta(&running_toplevel, "native-executor-ref")?;
    crate::config_eval::materialize::validate_canonical_store_path(&immutable_running_executor)
        .context("validating immutable running native executor identity")?;

    let candidate_toplevel = candidate_toplevel
        .to_str()
        .context("candidate image toplevel path is not UTF-8")?;
    crate::config_eval::materialize::validate_canonical_store_path(candidate_toplevel)
        .context("validating candidate image toplevel identity")?;
    let candidate_toplevel =
        immutable_store_path_beneath(immutable_root, Path::new(candidate_toplevel))?;
    let candidate_state_version = read_toplevel_meta(&candidate_toplevel, "state-version")?;
    let candidate_executor = read_toplevel_meta(&candidate_toplevel, "native-executor-ref")?;
    crate::config_eval::materialize::validate_canonical_store_path(&candidate_executor)
        .context("validating candidate native executor identity")?;

    validate_image_selection_compatibility(
        &running,
        &immutable_running_state_version,
        &immutable_running_executor,
        &candidate_state_version,
        &candidate_executor,
        qualified_rollout,
    )?;

    let executor_changes = immutable_running_executor != candidate_executor;
    if !executor_changes {
        return Ok(());
    }

    ensure_executor_replacement_is_settled(retained_config_generation_paths(system_profile)?)?;
    Ok(())
}

fn immutable_store_path_beneath(root: &Path, store_path: &Path) -> Result<PathBuf> {
    ensure!(
        root.is_absolute(),
        "immutable filesystem root must be absolute"
    );
    let relative = store_path
        .strip_prefix("/")
        .context("immutable store path must be absolute")?;
    Ok(root.join(relative))
}

fn validate_image_selection_compatibility(
    running: &ImageGeneration,
    immutable_running_state_version: &str,
    immutable_running_executor: &str,
    candidate_state_version: &str,
    candidate_executor: &str,
    qualified_rollout: bool,
) -> Result<bool> {
    ensure!(
        !immutable_running_state_version.is_empty(),
        "running image has no authenticated state version"
    );
    ensure!(
        running.state_version == immutable_running_state_version,
        "running image state version differs from immutable toplevel metadata"
    );
    ensure!(
        running.native_executor_ref == immutable_running_executor,
        "running native executor differs from immutable toplevel metadata"
    );
    ensure!(
        !candidate_state_version.is_empty()
            && candidate_state_version == immutable_running_state_version,
        "image selection requires identical nonempty state versions (running {immutable_running_state_version:?}, candidate {candidate_state_version:?})"
    );
    let executor_changes = immutable_running_executor != candidate_executor;
    ensure!(
        !executor_changes || qualified_rollout,
        "native executor replacement requires an explicit drained reboot rollout"
    );
    Ok(executor_changes)
}

fn ensure_executor_replacement_is_settled(
    generations: impl IntoIterator<Item = (u32, PathBuf)>,
) -> Result<()> {
    for (number, generation_path) in generations {
        if crate::config_eval::transaction_store::generation_has_unfinished_transactions(
            &generation_path,
        )? {
            bail!(
                "native executor replacement requires config generation {number} to settle all ability transactions under the running executor"
            );
        }
    }
    Ok(())
}

fn retained_config_generation_paths(profile: &Path) -> Result<Vec<(u32, PathBuf)>> {
    let entries = match std::fs::read_dir(profile) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "listing retained config generations in {}",
                    profile.display()
                )
            });
        }
    };
    let mut generations = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "reading retained config generations in {}",
                profile.display()
            )
        })?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Some(number) = name
            .strip_prefix("gen-")
            .and_then(|suffix| suffix.parse::<u32>().ok())
            .filter(|number| name == format!("gen-{number}"))
        else {
            continue;
        };
        let file_type = entry.file_type().with_context(|| {
            format!(
                "inspecting retained config generation {}",
                entry.path().display()
            )
        })?;
        ensure!(
            file_type.is_dir() && !file_type.is_symlink(),
            "retained config generation {} is not a directory",
            entry.path().display()
        );
        generations.push((number, entry.path()));
    }
    generations.sort_by_key(|(number, _)| *number);
    Ok(generations)
}

pub(super) fn qualified_rollout_record(
    state: &ImageGenerationState,
    candidate: u32,
    candidate_state_version: &str,
) -> Result<ImageRollout> {
    ensure!(
        candidate != state.running,
        "qualified rollout candidate is already the running image"
    );
    let running = state
        .running_generation()
        .context("image state has no running generation")?;
    let running_state_version = &running.state_version;
    ensure!(
        !candidate_state_version.is_empty() && candidate_state_version == running_state_version,
        "qualified image rollout requires identical nonempty state versions"
    );
    let rollout = ImageRollout {
        schema: IMAGE_ROLLOUT_SCHEMA.to_string(),
        candidate,
        prior: state.running,
        state_version: candidate_state_version.to_string(),
        status: ImageRolloutStatus::Staged,
    };
    if let Some(active) = &state.active_rollout {
        ensure!(
            active == &rollout,
            "another qualified image rollout is already active"
        );
    }
    Ok(rollout)
}

pub(super) fn validate_active_rollout_selection(
    state: &ImageGenerationState,
    rollout: &ImageRollout,
    target: u32,
) -> Result<()> {
    ensure!(
        rollout.schema == IMAGE_ROLLOUT_SCHEMA
            && rollout.status == ImageRolloutStatus::Staged
            && !rollout.state_version.is_empty()
            && rollout.candidate != rollout.prior
            && rollout.candidate == target,
        "active qualified rollout cannot be superseded by image generation {target}"
    );
    ensure!(
        rollout.prior == state.running && state.pending == Some(rollout.candidate),
        "active qualified rollout no longer names the running prior and pending candidate"
    );
    for (role, number) in [("candidate", rollout.candidate), ("prior", rollout.prior)] {
        let matching = state
            .generations
            .iter()
            .filter(|generation| {
                generation.number == number && generation.state_version == rollout.state_version
            })
            .count();
        ensure!(
            matching == 1,
            "active rollout {role} generation {number} is absent, ambiguous, or changed"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::types::ImageSlot;

    use super::*;
    use crate::sysroot::{
        IMAGE_STATE_FILE, IMAGE_TRANSITION_INTENT, abort_unpublished_image_selection,
        prepare_image_selection,
    };

    fn rollout_test_image(number: u32, state_version: &str, executor: &str) -> ImageGeneration {
        ImageGeneration {
            number,
            slot: if number % 2 == 0 {
                ImageSlot::B
            } else {
                ImageSlot::A
            },
            uki_path: format!("EFI/Linux/aos-{number}+3.efi"),
            uki_source_path: None,
            toplevel: format!("/nix/store/{}-top-{number}", "0".repeat(32)),
            package_name: "aos".into(),
            version: number.to_string(),
            state_version: state_version.to_string(),
            native_executor_ref: executor.to_string(),
            registry: "test".into(),
            kernel_path: None,
            evaluator_ref: format!("/nix/store/{}-base-{number}", "1".repeat(32)),
            module_abi: 1,
            base_lib_abi_hash: format!("sha256:{}", "0".repeat(64)),
            root_verity_roothash: None,
            expected_pcr11: None,
            initrd_pcr11: None,
            recovery: None,
            created_at: "2026-09-10T00:00:00Z".into(),
        }
    }

    #[test]
    fn preflight_rejects_state_that_differs_from_authenticated_boot_identity() {
        let tmp = TempDir::new().unwrap();
        let immutable_root = tmp.path().join("root");
        let image_profile = tmp.path().join("image-profile");
        let system_profile = tmp.path().join("system-profile");
        let running_toplevel =
            PathBuf::from(format!("/nix/store/{}-running-toplevel", "0".repeat(32)));
        let candidate_toplevel =
            PathBuf::from(format!("/nix/store/{}-candidate-toplevel", "1".repeat(32)));
        let running_executor = format!("/nix/store/{}-running-executor", "2".repeat(32));
        let candidate_executor = format!("/nix/store/{}-candidate-executor", "3".repeat(32));

        for (toplevel, executor) in [
            (&running_toplevel, &running_executor),
            (&candidate_toplevel, &candidate_executor),
        ] {
            let physical = immutable_store_path_beneath(&immutable_root, toplevel).unwrap();
            std::fs::create_dir_all(physical.join("meta")).unwrap();
            std::fs::write(physical.join("meta/state-version"), "1").unwrap();
            std::fs::write(physical.join("meta/native-executor-ref"), executor).unwrap();
        }

        let mut running = rollout_test_image(1, "1", &running_executor);
        running.toplevel = running_toplevel.to_string_lossy().into_owned();
        let state = ImageGenerationState {
            running: running.number,
            default: running.number,
            pending: None,
            recovery_known_good: None,
            recovery_pending: None,
            active_rollout: None,
            last_rollout: None,
            generations: vec![running.clone()],
        };
        std::fs::create_dir_all(&image_profile).unwrap();
        std::fs::write(
            image_profile.join(IMAGE_STATE_FILE),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        let mut different_boot_identity = running;
        different_boot_identity.slot = ImageSlot::B;
        let error = preflight_image_selection_beneath(
            &image_profile,
            &system_profile,
            &candidate_toplevel,
            true,
            &immutable_root,
            &different_boot_identity,
        )
        .expect_err("persisted running selection must match authenticated boot identity");

        assert!(error.to_string().contains("authenticated booted image"));
    }

    #[test]
    fn image_selection_rejects_state_or_executor_gate_bypasses() {
        let executor_a = format!("/nix/store/{}-executor-a", "2".repeat(32));
        let executor_b = format!("/nix/store/{}-executor-b", "3".repeat(32));
        let running = rollout_test_image(1, "7", &executor_a);

        assert!(
            !validate_image_selection_compatibility(
                &running,
                "7",
                &executor_a,
                "7",
                &executor_a,
                false,
            )
            .expect("same executor needs no drain gate")
        );
        for (mode, drain) in [
            (SystemTransitionMode::Advisory, true),
            (SystemTransitionMode::Reboot, false),
        ] {
            assert!(!is_qualified_image_rollout(mode, drain));
            let error = validate_image_selection_compatibility(
                &running,
                "7",
                &executor_a,
                "7",
                &executor_b,
                is_qualified_image_rollout(mode, drain),
            )
            .expect_err("an executor change must not bypass the drained reboot gate");
            assert!(error.to_string().contains("explicit drained reboot"));
        }
        assert!(
            validate_image_selection_compatibility(
                &running,
                "7",
                &executor_a,
                "7",
                &executor_b,
                true,
            )
            .expect("qualified executor replacement")
        );
        assert!(
            validate_image_selection_compatibility(
                &running,
                "7",
                &executor_a,
                "8",
                &executor_a,
                true,
            )
            .expect_err("state migration is not implemented")
            .to_string()
            .contains("identical nonempty state versions")
        );
    }

    #[test]
    fn image_selection_rebinds_running_state_to_immutable_metadata() {
        let executor_a = format!("/nix/store/{}-executor-a", "2".repeat(32));
        let executor_b = format!("/nix/store/{}-executor-b", "3".repeat(32));
        let running = rollout_test_image(1, "7", &executor_a);

        assert!(
            validate_image_selection_compatibility(
                &running,
                "8",
                &executor_a,
                "8",
                &executor_a,
                true,
            )
            .expect_err("persisted state version must match immutable metadata")
            .to_string()
            .contains("state version differs")
        );
        assert!(
            validate_image_selection_compatibility(
                &running,
                "7",
                &executor_b,
                "7",
                &executor_b,
                true,
            )
            .expect_err("persisted executor must match immutable metadata")
            .to_string()
            .contains("executor differs")
        );
    }

    #[test]
    fn native_executor_identity_is_a_canonical_store_root() {
        let valid = format!("/nix/store/{}-aos-package-runtime", "4".repeat(32));
        crate::config_eval::materialize::validate_canonical_store_path(&valid)
            .expect("canonical executor store root");

        for invalid in [
            format!("{valid}/bin/aos-package-runtime"),
            "/nix/store/short-runtime".to_string(),
            format!("/nix/store/{}-runtime", "e".repeat(32)),
            format!("/nix/store/{}-bad/name", "4".repeat(32)),
        ] {
            assert!(
                crate::config_eval::materialize::validate_canonical_store_path(&invalid).is_err(),
                "unexpectedly accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn executor_replacement_rejects_an_unfinished_old_generation() {
        let tmp = TempDir::new().unwrap();
        let old_generation = tmp.path().join("gen-9");
        std::fs::create_dir_all(old_generation.join("ability-transactions/old-executor")).unwrap();

        let error = ensure_executor_replacement_is_settled([(9, old_generation)])
            .expect_err("missing terminal evidence must block executor replacement");

        assert!(error.to_string().contains("config generation 9"));
        ensure_executor_replacement_is_settled([(10, tmp.path().join("gen-10"))])
            .expect("a generation with no transactions is settled");
    }

    #[test]
    fn active_rollout_cannot_be_superseded_or_made_vacuous() {
        let executor = format!("/nix/store/{}-executor", "5".repeat(32));
        let generations = vec![
            rollout_test_image(1, "7", &executor),
            rollout_test_image(2, "7", &executor),
            rollout_test_image(3, "7", &executor),
        ];
        let rollout = ImageRollout {
            schema: IMAGE_ROLLOUT_SCHEMA.into(),
            candidate: 2,
            prior: 1,
            state_version: "7".into(),
            status: ImageRolloutStatus::Staged,
        };
        let mut state = ImageGenerationState {
            running: 1,
            default: 1,
            pending: Some(2),
            recovery_known_good: None,
            recovery_pending: None,
            active_rollout: Some(rollout.clone()),
            last_rollout: None,
            generations,
        };
        let tmp = TempDir::new().unwrap();

        let mut prior_mismatch = state.clone();
        prior_mismatch.active_rollout.as_mut().unwrap().prior = 3;
        assert!(
            validate_active_rollout_selection(
                &prior_mismatch,
                prior_mismatch.active_rollout.as_ref().unwrap(),
                2,
            )
            .expect_err("staged rollout prior must remain the running image")
            .to_string()
            .contains("running prior")
        );
        let mut duplicate = state.clone();
        duplicate.generations.push(duplicate.generations[1].clone());
        assert!(
            validate_active_rollout_selection(
                &duplicate,
                duplicate.active_rollout.as_ref().unwrap(),
                2,
            )
            .expect_err("duplicate candidate records must fail closed")
            .to_string()
            .contains("ambiguous")
        );
        let error = abort_unpublished_image_selection(tmp.path(), &mut state, 2)
            .expect_err("a qualified unpublished candidate must remain recoverable");
        assert!(error.to_string().contains("qualified rollout is active"));
        assert_eq!(state.pending, Some(2));
        let error = prepare_image_selection(tmp.path(), &mut state, 3, "aos-3+3.efi", None)
            .expect_err("an active rollout must reject an unqualified superseding selection");
        assert!(error.to_string().contains("cannot be superseded"));
        let error = prepare_image_selection(tmp.path(), &mut state, 2, "aos-2+3.efi", None)
            .expect_err("an advisory retry must not bypass the qualified drain gate");
        assert!(error.to_string().contains("exact drained rollout identity"));
        prepare_image_selection(
            tmp.path(),
            &mut state,
            2,
            "aos-2+3.efi",
            Some(rollout.clone()),
        )
        .expect("the exact qualified candidate is idempotently resumable");
        assert_eq!(state.active_rollout, Some(rollout));
        assert!(
            qualified_rollout_record(&state, 1, "7")
                .expect_err("candidate and prior must differ")
                .to_string()
                .contains("already the running image")
        );
        assert!(tmp.path().join(IMAGE_TRANSITION_INTENT).is_file());
    }
}
