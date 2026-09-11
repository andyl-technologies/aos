//! Qualified image rollout identity and state transitions.
//!
//! This module authenticates the running and candidate image identities before
//! A/B selection, gates native executor replacement on a drained reboot, and
//! constructs the durable `aos.image-rollout/v1` record. It also owns the
//! one-time migration from immutable images that predate the explicit
//! `state-version` and `native-executor-ref` toplevel metadata.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::types::{ImageGeneration, ImageGenerationState, ImageRollout, ImageRolloutStatus};

use super::{
    IMAGE_STATE_FILE, SystemTransitionMode, load_image_generation_state_pub,
    read_immutable_os_release, read_toplevel_meta, running_image_generation, write_atomic_durable,
};

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

fn preflight_image_selection_beneath(
    image_profile: &Path,
    system_profile: &Path,
    candidate_toplevel: &Path,
    qualified_rollout: bool,
    immutable_root: &Path,
    authenticated_running: &ImageGeneration,
) -> Result<()> {
    let mut images = load_image_generation_state_pub(image_profile)?;
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
    let immutable_running_state_version =
        read_optional_toplevel_meta(&running_toplevel, "state-version")?;
    let immutable_running_executor =
        read_optional_toplevel_meta(&running_toplevel, "native-executor-ref")?;

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

    let legacy_state_version = match (
        immutable_running_state_version.as_deref(),
        immutable_running_executor.as_deref(),
    ) {
        (Some(state_version), Some(executor)) => {
            crate::config_eval::materialize::validate_canonical_store_path(executor)
                .context("validating immutable running native executor identity")?;
            validate_image_selection_compatibility(
                &running,
                state_version,
                executor,
                &candidate_state_version,
                &candidate_executor,
                qualified_rollout,
            )?;
            None
        }
        (None, None) => {
            let state_version = authenticate_legacy_running_state_version(
                &running,
                &running_toplevel,
                immutable_root,
            )?;
            validate_legacy_image_selection_compatibility(
                &running,
                &state_version,
                &candidate_state_version,
                qualified_rollout,
            )?;
            Some(state_version)
        }
        _ => {
            bail!("running immutable toplevel has a partial state-version/native-executor identity")
        }
    };

    let executor_changes = legacy_state_version.is_some()
        || immutable_running_executor.as_deref() != Some(candidate_executor.as_str());
    if !executor_changes {
        return Ok(());
    }

    ensure_executor_replacement_is_settled(retained_config_generation_paths(system_profile)?)?;

    if let Some(state_version) = legacy_state_version {
        migrate_legacy_running_state_version(
            image_profile,
            &mut images,
            running.number,
            &state_version,
        )?;
    }
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

fn read_optional_toplevel_meta(toplevel: &Path, name: &str) -> Result<Option<String>> {
    match std::fs::read_to_string(toplevel.join("meta").join(name)) {
        Ok(value) => Ok(Some(value.trim().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading target image metadata {name}")),
    }
}

fn authenticate_legacy_running_state_version(
    running: &ImageGeneration,
    toplevel: &Path,
    immutable_root: &Path,
) -> Result<String> {
    let immutable_base_lib = std::fs::read_link(toplevel.join("base-lib"))
        .context("reading legacy immutable base-library pointer")?;
    ensure!(
        immutable_base_lib == Path::new(&running.evaluator_ref),
        "legacy running base library differs from immutable toplevel metadata"
    );
    let immutable_abi = read_toplevel_meta(toplevel, "module-abi")?
        .parse::<u32>()
        .context("legacy immutable toplevel has invalid module ABI")?;
    let immutable_digest = read_toplevel_meta(toplevel, "baselib-digest")?;
    let immutable_uki = read_toplevel_meta(toplevel, "uki-path")?;
    let immutable_package = read_toplevel_meta(toplevel, "package-name")?;
    let immutable_version = read_toplevel_meta(toplevel, "version")?;
    let recorded_uki = running
        .uki_source_path
        .as_deref()
        .unwrap_or(&running.uki_path);
    ensure!(
        immutable_abi == running.module_abi
            && immutable_digest == running.baselib_digest
            && immutable_uki == recorded_uki
            && immutable_package == running.package_name
            && immutable_version == running.version,
        "legacy running image differs from immutable toplevel metadata"
    );

    let os_release = std::fs::read_link(toplevel.join("os-release"))
        .context("reading legacy immutable os-release pointer")?;
    let fields = read_immutable_os_release(immutable_root, &os_release)
        .context("reading legacy immutable os-release identity")?;
    let os_abi = fields
        .get("AOS_MODULE_ABI")
        .context("legacy immutable os-release has no AOS_MODULE_ABI")?
        .parse::<u32>()
        .context("legacy immutable os-release has invalid AOS_MODULE_ABI")?;
    let os_digest = fields
        .get("AOS_BASELIB_DIGEST")
        .context("legacy immutable os-release has no AOS_BASELIB_DIGEST")?;
    let os_version = fields
        .get("VERSION_ID")
        .context("legacy immutable os-release has no VERSION_ID")?;
    ensure!(
        os_abi == immutable_abi
            && os_digest == &immutable_digest
            && os_version == &immutable_version,
        "legacy immutable os-release disagrees with toplevel metadata"
    );
    let state_version = fields
        .get("AOS_STATE_VERSION")
        .filter(|version| !version.is_empty())
        .context("legacy immutable os-release has no nonempty AOS_STATE_VERSION")?;
    Ok(state_version.clone())
}

fn validate_legacy_image_selection_compatibility(
    running: &ImageGeneration,
    authenticated_state_version: &str,
    candidate_state_version: &str,
    qualified_rollout: bool,
) -> Result<()> {
    ensure!(
        running.native_executor_ref.is_none(),
        "legacy running image record unexpectedly names a native executor"
    );
    ensure!(
        running
            .state_version
            .as_deref()
            .is_none_or(|version| version == authenticated_state_version),
        "legacy running image state version differs from immutable os-release"
    );
    ensure!(
        !candidate_state_version.is_empty()
            && candidate_state_version == authenticated_state_version,
        "legacy image migration requires the candidate to preserve the authenticated state version"
    );
    ensure!(
        qualified_rollout,
        "introducing the native executor requires an explicit drained reboot rollout"
    );
    Ok(())
}

fn migrate_legacy_running_state_version(
    image_profile: &Path,
    state: &mut ImageGenerationState,
    running_number: u32,
    state_version: &str,
) -> Result<()> {
    let matching = state
        .generations
        .iter()
        .enumerate()
        .filter(|(_, generation)| generation.number == running_number)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "legacy running image generation is absent or ambiguous"
    );
    let index = matching[0];
    ensure!(
        state.generations[index].native_executor_ref.is_none(),
        "legacy running image record unexpectedly names a native executor"
    );
    if state.generations[index].state_version.as_deref() == Some(state_version) {
        return Ok(());
    }
    ensure!(
        state.generations[index].state_version.is_none(),
        "legacy running image state version changed before migration"
    );

    let mut migrated = state.clone();
    migrated.generations[index].state_version = Some(state_version.to_string());
    write_atomic_durable(
        &image_profile.join(IMAGE_STATE_FILE),
        &serde_json::to_vec_pretty(&migrated)?,
    )?;
    *state = migrated;
    Ok(())
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
        running.state_version.as_deref() == Some(immutable_running_state_version),
        "running image state version differs from immutable toplevel metadata"
    );
    ensure!(
        running.native_executor_ref.as_deref() == Some(immutable_running_executor),
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
        if crate::config_eval::ability_store::generation_has_unfinished_transactions(
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
    let running_state_version = running
        .state_version
        .as_deref()
        .filter(|version| !version.is_empty())
        .context("running image has no authenticated state version")?;
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
                generation.number == number
                    && generation.state_version.as_deref() == Some(rollout.state_version.as_str())
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
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use crate::types::{ImageSlot, RecoveryPublication};

    use super::*;
    use crate::sysroot::{
        IMAGE_TRANSITION_INTENT, abort_unpublished_image_selection, prepare_image_selection,
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
            state_version: Some(state_version.to_string()),
            native_executor_ref: Some(executor.to_string()),
            registry: "test".into(),
            kernel_path: None,
            evaluator_ref: format!("/nix/store/{}-base-{number}", "1".repeat(32)),
            module_abi: 1,
            baselib_digest: format!("sha256:{}", "0".repeat(64)),
            root_verity_roothash: None,
            expected_pcr11: None,
            initrd_pcr11: None,
            recovery: None,
            created_at: "2026-09-10T00:00:00Z".into(),
        }
    }

    struct LegacyPreflightFixture {
        _tmp: TempDir,
        immutable_root: PathBuf,
        image_profile: PathBuf,
        system_profile: PathBuf,
        legacy_toplevel: PathBuf,
        candidate_toplevel: PathBuf,
    }

    impl LegacyPreflightFixture {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let immutable_root = tmp.path().join("root");
            let image_profile = tmp.path().join("image-profile");
            let system_profile = tmp.path().join("system-profile");
            let legacy_toplevel =
                PathBuf::from(format!("/nix/store/{}-legacy-toplevel", "0".repeat(32)));
            let legacy_base =
                PathBuf::from(format!("/nix/store/{}-legacy-base-lib", "1".repeat(32)));
            let legacy_os_release = PathBuf::from(format!(
                "/nix/store/{}-legacy-os-release/os-release",
                "2".repeat(32)
            ));
            let candidate_toplevel =
                PathBuf::from(format!("/nix/store/{}-candidate-toplevel", "3".repeat(32)));
            let candidate_executor = format!("/nix/store/{}-aos-package-runtime", "4".repeat(32));

            let physical_legacy =
                immutable_store_path_beneath(&immutable_root, &legacy_toplevel).unwrap();
            std::fs::create_dir_all(physical_legacy.join("meta")).unwrap();
            for (name, value) in [
                ("module-abi", "7"),
                ("baselib-digest", "sha256:legacy-base"),
                ("uki-path", "EFI/Linux/aos-legacy+3.efi"),
                ("package-name", "aos"),
                ("version", "1"),
            ] {
                std::fs::write(physical_legacy.join("meta").join(name), value).unwrap();
            }
            symlink(&legacy_base, physical_legacy.join("base-lib")).unwrap();
            symlink(&legacy_os_release, physical_legacy.join("os-release")).unwrap();
            let physical_os_release =
                immutable_store_path_beneath(&immutable_root, &legacy_os_release).unwrap();
            std::fs::create_dir_all(physical_os_release.parent().unwrap()).unwrap();
            std::fs::write(
                physical_os_release,
                "VERSION_ID=1\nAOS_MODULE_ABI=7\nAOS_BASELIB_DIGEST=sha256:legacy-base\nAOS_STATE_VERSION=1\n",
            )
            .unwrap();

            let physical_candidate =
                immutable_store_path_beneath(&immutable_root, &candidate_toplevel).unwrap();
            std::fs::create_dir_all(physical_candidate.join("meta")).unwrap();
            std::fs::write(physical_candidate.join("meta/state-version"), "1").unwrap();
            std::fs::write(
                physical_candidate.join("meta/native-executor-ref"),
                candidate_executor,
            )
            .unwrap();

            std::fs::create_dir_all(&image_profile).unwrap();
            let state = ImageGenerationState {
                running: 1,
                default: 1,
                pending: None,
                recovery_known_good: None,
                recovery_pending: None::<RecoveryPublication>,
                active_rollout: None,
                last_rollout: None,
                generations: vec![ImageGeneration {
                    number: 1,
                    slot: ImageSlot::A,
                    uki_path: "EFI/Linux/aos-legacy+3.efi".into(),
                    uki_source_path: None,
                    toplevel: legacy_toplevel.to_string_lossy().into_owned(),
                    package_name: "aos".into(),
                    version: "1".into(),
                    state_version: None,
                    native_executor_ref: None,
                    registry: "system".into(),
                    kernel_path: None,
                    evaluator_ref: legacy_base.to_string_lossy().into_owned(),
                    module_abi: 7,
                    baselib_digest: "sha256:legacy-base".into(),
                    root_verity_roothash: None,
                    expected_pcr11: None,
                    initrd_pcr11: None,
                    recovery: None,
                    created_at: "2026-09-10T00:00:00Z".into(),
                }],
            };
            std::fs::write(
                image_profile.join(IMAGE_STATE_FILE),
                serde_json::to_vec_pretty(&state).unwrap(),
            )
            .unwrap();

            Self {
                _tmp: tmp,
                immutable_root,
                image_profile,
                system_profile,
                legacy_toplevel,
                candidate_toplevel,
            }
        }

        fn preflight(&self, qualified_rollout: bool) -> Result<()> {
            let state = self.image_state();
            let authenticated_running = state.running_generation().unwrap();
            self.preflight_with_authenticated(qualified_rollout, authenticated_running)
        }

        fn preflight_with_authenticated(
            &self,
            qualified_rollout: bool,
            authenticated_running: &ImageGeneration,
        ) -> Result<()> {
            preflight_image_selection_beneath(
                &self.image_profile,
                &self.system_profile,
                &self.candidate_toplevel,
                qualified_rollout,
                &self.immutable_root,
                authenticated_running,
            )
        }

        fn image_state(&self) -> ImageGenerationState {
            load_image_generation_state_pub(&self.image_profile).unwrap()
        }

        fn write_image_state(&self, state: &ImageGenerationState) {
            std::fs::write(
                self.image_profile.join(IMAGE_STATE_FILE),
                serde_json::to_vec_pretty(state).unwrap(),
            )
            .unwrap();
        }

        fn legacy_meta(&self, name: &str) -> PathBuf {
            immutable_store_path_beneath(&self.immutable_root, &self.legacy_toplevel)
                .unwrap()
                .join("meta")
                .join(name)
        }

        fn legacy_os_release(&self) -> PathBuf {
            let toplevel =
                immutable_store_path_beneath(&self.immutable_root, &self.legacy_toplevel).unwrap();
            let logical = std::fs::read_link(toplevel.join("os-release")).unwrap();
            immutable_store_path_beneath(&self.immutable_root, &logical).unwrap()
        }
    }

    #[test]
    fn legacy_preflight_authenticates_and_durably_migrates_state_version() {
        let fixture = LegacyPreflightFixture::new();
        let rejected = fixture
            .preflight(false)
            .expect_err("legacy executor introduction requires a drained reboot");
        assert!(rejected.to_string().contains("explicit drained reboot"));
        assert_eq!(
            fixture.image_state().generations[0].state_version,
            None,
            "a rejected preflight must not mutate legacy state"
        );

        fixture
            .preflight(true)
            .expect("authenticated legacy identity should migrate");
        let migrated = fixture.image_state();
        assert_eq!(migrated.generations[0].state_version.as_deref(), Some("1"));
        assert_eq!(migrated.generations[0].native_executor_ref, None);

        let durable = std::fs::read(fixture.image_profile.join(IMAGE_STATE_FILE)).unwrap();
        fixture
            .preflight(true)
            .expect("the durable migration should be idempotent");
        assert_eq!(
            std::fs::read(fixture.image_profile.join(IMAGE_STATE_FILE)).unwrap(),
            durable
        );
    }

    #[test]
    fn legacy_preflight_rejects_os_release_symlink_escape() {
        let fixture = LegacyPreflightFixture::new();
        let outside = fixture
            .immutable_root
            .parent()
            .unwrap()
            .join("live-root-os-release");
        std::fs::write(
            &outside,
            "VERSION_ID=1\nAOS_MODULE_ABI=7\nAOS_BASELIB_DIGEST=sha256:legacy-base\nAOS_STATE_VERSION=1\n",
        )
        .unwrap();
        let os_release = fixture.legacy_os_release();
        std::fs::remove_file(&os_release).unwrap();
        symlink(&outside, &os_release).unwrap();

        let error = fixture
            .preflight(true)
            .expect_err("legacy identity reads must not follow a live-root symlink");

        assert!(
            format!("{error:#}").contains("opening"),
            "unexpected error: {error:#}"
        );
        assert_eq!(fixture.image_state().generations[0].state_version, None);
    }

    #[test]
    fn legacy_preflight_scans_retained_generations_without_parsing_config_state() {
        let fixture = LegacyPreflightFixture::new();
        let generation = fixture.system_profile.join("gen-1");
        std::fs::create_dir_all(&generation).unwrap();
        std::fs::write(
            fixture.system_profile.join(super::super::SYSTEM_STATE_FILE),
            r#"{"current":1,"next":2,"generations":[{"number":1,"toplevel":"/nix/store/legacy","created_at":"2026-01-01T00:00:00Z"}]}"#,
        )
        .unwrap();

        fixture
            .preflight(true)
            .expect("legacy config state must not strand the first native rollout");
        assert_eq!(
            fixture.image_state().generations[0]
                .state_version
                .as_deref(),
            Some("1")
        );

        let blocked = LegacyPreflightFixture::new();
        let unfinished = blocked
            .system_profile
            .join("gen-7/ability-transactions/unfinished");
        std::fs::create_dir_all(&unfinished).unwrap();
        std::fs::write(
            blocked.system_profile.join(super::super::SYSTEM_STATE_FILE),
            r#"{"current":7,"next":8,"generations":[{"number":7,"toplevel":"/nix/store/legacy","created_at":"2026-01-01T00:00:00Z"}]}"#,
        )
        .unwrap();
        let error = blocked
            .preflight(true)
            .expect_err("unfinished retained work must block executor replacement");
        assert!(error.to_string().contains("config generation 7"));
        assert_eq!(blocked.image_state().generations[0].state_version, None);
    }

    #[test]
    fn legacy_preflight_rejects_partial_new_metadata() {
        let fixture = LegacyPreflightFixture::new();
        for (present, absent, value) in [
            ("state-version", "native-executor-ref", "1"),
            (
                "native-executor-ref",
                "state-version",
                &format!("/nix/store/{}-runtime", "5".repeat(32)),
            ),
        ] {
            std::fs::write(fixture.legacy_meta(present), value).unwrap();
            let error = fixture
                .preflight(true)
                .expect_err("one new immutable identity field must fail closed");
            assert!(error.to_string().contains("partial state-version"));
            std::fs::remove_file(fixture.legacy_meta(present)).unwrap();
            assert!(!fixture.legacy_meta(absent).exists());
        }
    }

    #[test]
    fn legacy_preflight_rejects_record_mismatches() {
        let fixture = LegacyPreflightFixture::new();
        let mut state = fixture.image_state();
        state.generations[0].state_version = Some("9".into());
        fixture.write_image_state(&state);
        let error = fixture
            .preflight(true)
            .expect_err("persisted state version must match immutable os-release");
        assert!(error.to_string().contains("state version differs"));

        state.generations[0].state_version = None;
        state.generations[0].version = "attacker".into();
        fixture.write_image_state(&state);
        let error = fixture
            .preflight(true)
            .expect_err("legacy record must match immutable toplevel fields");
        assert!(
            error
                .to_string()
                .contains("differs from immutable toplevel")
        );
    }

    #[test]
    fn preflight_rejects_state_that_differs_from_authenticated_boot_identity() {
        let fixture = LegacyPreflightFixture::new();
        let mut authenticated_running = fixture.image_state().generations[0].clone();
        authenticated_running.slot = ImageSlot::B;

        let error = fixture
            .preflight_with_authenticated(true, &authenticated_running)
            .expect_err("persisted running selection must match authenticated boot identity");

        assert!(error.to_string().contains("authenticated booted image"));
        assert_eq!(fixture.image_state().generations[0].state_version, None);
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
