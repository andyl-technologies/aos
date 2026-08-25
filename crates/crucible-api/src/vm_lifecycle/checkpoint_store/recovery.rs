//! Authentication and ownership recovery for published checkpoint closures.

use super::*;

/// Authenticates every published closure and recovers configuration ownership.
///
/// This runs before a new lifecycle launches guest processes. Transaction
/// staging names are ignored, while every content-addressed directory must
/// decode through the same complete production restore path used by an
/// explicit checkpoint load.
///
/// # Errors
///
/// Returns an error for directory I/O, malformed names, resource-limit
/// violations, corrupt closures, duplicate configuration owners, or any
/// referenced object that does not authenticate.
pub(in crate::vm_lifecycle) fn recover_published_checkpoint_catalog(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
) -> Result<BTreeMap<ContentHash, ContentHash>, LifecycleApiError> {
    let parent = closure_parent(run_state_root, scenario.id());
    let entries = match fs::read_dir(&parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        }
        Err(error) => {
            return Err(loop_factory_error(format!(
                "enumerate published exact checkpoints in {}: {error}",
                parent.display()
            )));
        }
    };
    enforce_published_checkpoint_count(&parent, source.plan().fault_signals().resource_limits())
        .map_err(scheduler_api_error)?;

    let mut catalog = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            loop_factory_error(format!(
                "read published exact checkpoint entry in {}: {error}",
                parent.display()
            ))
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(loop_factory_error(format!(
                "exact checkpoint closure name in {} is not UTF-8",
                parent.display()
            )));
        };
        if name.starts_with(".closure-") {
            continue;
        }
        if !entry
            .file_type()
            .map_err(|error| {
                loop_factory_error(format!(
                    "inspect exact checkpoint closure {}: {error}",
                    entry.path().display()
                ))
            })?
            .is_dir()
        {
            return Err(loop_factory_error(format!(
                "exact checkpoint closure {} is not a directory",
                entry.path().display()
            )));
        }
        let identity = parse_content_hash(name).ok_or_else(|| {
            loop_factory_error(format!(
                "exact checkpoint closure {} has a noncanonical identity name",
                entry.path().display()
            ))
        })?;
        let checkpoint = load_exact_checkpoint_set(run_state_root, scenario, source, identity)?;
        let configuration = checkpoint.configuration.id();
        if catalog.insert(configuration, identity).is_some() {
            return Err(loop_factory_error(format!(
                "multiple exact checkpoint closures own configuration {}",
                configuration.to_hex()
            )));
        }
    }
    Ok(catalog)
}

/// Reconciles one closure whose final directory rename had an uncertain sync.
///
/// # Errors
///
/// Returns an error when absence cannot be synchronized, the visible closure
/// fails complete authentication, or checkpoint-count admission fails.
pub(in crate::vm_lifecycle) fn reconcile_indeterminate_publication(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    identity: ContentHash,
) -> Result<Option<ContentHash>, SchedulerError> {
    let parent = closure_parent(run_state_root, scenario.id());
    let destination = parent.join(identity.to_hex());
    if !destination.exists() {
        if parent.exists() {
            sync_directory(&parent)?;
        }
        return Ok(None);
    }
    let checkpoint = load_exact_checkpoint_set(run_state_root, scenario, source, identity)
        .map_err(lifecycle_scheduler_error)?;
    enforce_published_checkpoint_count(&parent, source.plan().fault_signals().resource_limits())?;
    Ok(Some(checkpoint.configuration.id()))
}

fn parse_content_hash(value: &str) -> Option<ContentHash> {
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(ContentHash { bytes })
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn scheduler_api_error(error: SchedulerError) -> LifecycleApiError {
    match error {
        SchedulerError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        }),
        error => loop_factory_error(error.to_string()),
    }
}

fn lifecycle_scheduler_error(error: LifecycleApiError) -> SchedulerError {
    match error {
        LifecycleApiError::ResourceLimit(error) => SchedulerError::ResourceLimit {
            field: error.field,
            current: error.current,
            requested: error.requested,
            configured: error.configured,
            hard: error.hard,
        },
        error => store_error(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixtures require exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn production_checkpoint_load_rejects_manifest_bytes_before_decode() {
        let fixture = crucible::happy_path_scenario()
            .expect("build checkpoint-load scenario")
            .scenario;
        let limits = FaultResourceLimits {
            fat_checkpoint_bytes: 7,
            ..FaultResourceLimits::default()
        };
        let faults = crucible::model::FaultSignalPlan::new(Vec::new(), Vec::new(), limits)
            .expect("build exact checkpoint resource contract");
        let plan = fixture.plan().clone().with_fault_signals(faults);
        let source = ScenarioDefForm::from_components_with_app_random_draw_cap(
            fixture.world(),
            &plan,
            fixture.properties(),
            fixture.seed(),
            fixture.app_random_draw_cap(),
        )
        .expect("rebuild checkpoint-load scenario");
        let scenario = source.scenario_def();
        let identity = ContentHash::from_bytes(b"oversized manifest");
        let root = tempfile::tempdir().expect("create checkpoint-load store");
        let closure = closure_parent(root.path(), scenario.id()).join(identity.to_hex());
        fs::create_dir_all(&closure).expect("create checkpoint closure directory");
        fs::write(closure.join(MANIFEST_FILE), b"12345678").expect("write over-authored manifest");

        let error = load_exact_checkpoint_set(root.path(), &scenario, &source, identity)
            .expect_err("manifest bytes must be admitted before decode");

        assert!(matches!(
            error,
            LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
                field: "fat_checkpoint_bytes",
                current: 0,
                requested: 8,
                configured: 7,
                hard,
            }) if hard == FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes
        ));
    }
}
