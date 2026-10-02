//! Realizes mount, swap, and timer units with exact definitions and pinned manager jobs.
//!
//! Private JSON receipts retain both sides of interrupted transitions:
//!
//! ```json
//! {"owner":"effect-id","desired":{"unit":"dev-swap.swap","text":"...",
//! "target":"swap.target","enabled":true,"revision":"sha256:...",
//! "swap_source":"/dev/swap","trigger":null},"retiring":null,"complete":true}
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_runtime::activation::Invocation;
use aos_systemd::PinnedSystemdManager;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{atomic_write, key, normalized_path, private_directory, read_regular, state_path};

#[cfg(all(test, feature = "systemd-parser-tests"))]
mod parser_tests;

const UNIT_ROOT: &str = "/etc/systemd/system";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    unit: String,
    text: String,
    target: String,
    enabled: bool,
    revision: String,
    swap_source: Option<String>,
    trigger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    optional_mount_source: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    owner: String,
    desired: Definition,
    retiring: Option<Definition>,
    complete: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Swap {
    name: String,
    source: String,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    priority: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mount {
    name: String,
    #[serde(default)]
    optional: bool,
    source: String,
    destination: String,
    #[serde(default)]
    filesystem: Option<String>,
    #[serde(default)]
    options: Vec<String>,
    #[serde(default)]
    timeout_millis: Option<u64>,
    #[serde(default = "yes")]
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Timer {
    name: String,
    target: String,
    schedule: Schedule,
    #[serde(default)]
    persistent: bool,
    #[serde(default = "accuracy")]
    accuracy_millis: u64,
    #[serde(default)]
    randomized_delay_millis: u64,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Schedule {
    Calendar {
        expression: String,
    },
    Interval {
        initial_delay_millis: u64,
        interval_millis: u64,
    },
}

fn yes() -> bool {
    true
}
fn accuracy() -> u64 {
    60_000
}

fn scalar(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control),
        "unit value contains a control character"
    );
    ensure!(
        value == value.trim() && !value.ends_with('\\'),
        "unit scalar cannot require whitespace or continuation escaping"
    );

    // These directives consume the whole value, without Exec*= unquoting.
    // Preserve literal path characters and escape only manager specifiers.
    Ok(value.replace('%', "%%"))
}

fn path_unit(path: &str, suffix: &str) -> Result<String> {
    normalized_path(path)?;
    let mut name = String::new();
    for (index, byte) in path.trim_start_matches('/').bytes().enumerate() {
        match byte {
            b'/' => name.push('-'),
            b'.' if index == 0 => name.push_str("\\x2e"),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' | b':' => {
                name.push(char::from(byte))
            }
            _ => name.push_str(&format!("\\x{byte:02x}")),
        }
    }
    ensure!(!name.is_empty(), "root is not an ancillary unit resource");
    let unit = format!("{name}.{suffix}");
    ensure!(unit.len() <= 255, "unit name exceeds systemd limit");
    Ok(unit)
}

fn receipt_uri(unit: &str, revision: &str) -> String {
    let encoded: String = unit
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    format!(
        "file:/etc/aos/ability-revisions/{encoded}/sha256/{}",
        revision.trim_start_matches("sha256:")
    )
}

fn definition(invocation: &Invocation, ability: &str) -> Result<Definition> {
    definition_for(
        &invocation.id,
        &invocation.revision,
        ability,
        &invocation.input,
    )
}

fn definition_for(id: &str, revision: &str, ability: &str, input: &Value) -> Result<Definition> {
    let mut optional_mount_source = None;
    let (unit, title, body, target, enabled, swap_source, trigger) = match ability {
        "swap" => {
            let input: Swap = serde_json::from_value(input.clone())?;
            let unit = path_unit(&input.source, "swap")?;
            let mut body = format!("[Swap]\nWhat={}\n", scalar(&input.source)?);
            if let Some(priority) = input.priority {
                body.push_str(&format!("Priority={priority}\n"));
            }
            (
                unit,
                input.name,
                body,
                "swap.target",
                input.enabled,
                Some(input.source),
                None,
            )
        }
        "mount" => {
            let input: Mount = serde_json::from_value(input.clone())?;
            normalized_path(&input.source)?;
            let unit = path_unit(&input.destination, "mount")?;
            if input.optional {
                optional_mount_source = Some(input.source.clone());
            }
            let mut body = if input.optional {
                format!("ConditionPathExists={}\n\n", scalar(&input.source)?)
            } else {
                String::new()
            };
            body.push_str(&format!(
                "[Mount]\nWhat={}\nWhere={}\n",
                scalar(&input.source)?,
                scalar(&input.destination)?
            ));
            if let Some(filesystem) = input.filesystem {
                ensure!(!filesystem.is_empty(), "empty filesystem type");
                body.push_str(&format!("Type={}\n", scalar(&filesystem)?));
            }
            let mut options = input.options;
            if input.optional && !options.iter().any(|option| option == "nofail") {
                options.push("nofail".into());
            }
            if !options.is_empty() {
                ensure!(
                    options
                        .iter()
                        .all(|option| !option.is_empty() && !option.contains(',')),
                    "ambiguous mount options"
                );
                body.push_str(&format!("Options={}\n", scalar(&options.join(","))?));
            }
            if let Some(timeout) = input.timeout_millis {
                body.push_str(&format!("TimeoutSec={timeout}ms\n"));
            }
            (
                unit,
                input.name,
                body,
                "local-fs.target",
                input.enabled,
                None,
                None,
            )
        }
        "scheduledActivation" => {
            let input: Timer = serde_json::from_value(input.clone())?;
            ensure!(
                input.target.ends_with(".service")
                    && !input.target.contains(['/', '\0', '\n'])
                    && input.target.len() <= 255,
                "timer target must be a canonical service unit"
            );
            let unit = format!("aos-{}.timer", &key(id)[..40]);
            let mut body = format!("[Timer]\nUnit={}\n", scalar(&input.target)?);
            match input.schedule {
                Schedule::Calendar { expression } => {
                    ensure!(!expression.is_empty(), "calendar expression is empty");
                    body.push_str(&format!("OnCalendar={}\n", scalar(&expression)?));
                }
                Schedule::Interval {
                    initial_delay_millis,
                    interval_millis,
                } => {
                    ensure!(interval_millis > 0, "timer interval must be positive");
                    body.push_str(&format!(
                        "OnBootSec={initial_delay_millis}ms\nOnUnitActiveSec={interval_millis}ms\n"
                    ));
                }
            }
            body.push_str(&format!(
                "Persistent={}\nAccuracySec={}ms\nRandomizedDelaySec={}ms\n",
                if input.persistent { "yes" } else { "no" },
                input.accuracy_millis,
                input.randomized_delay_millis
            ));
            (
                unit,
                input.name,
                body,
                "timers.target",
                true,
                None,
                Some(input.target),
            )
        }
        _ => bail!("unsupported unit resource"),
    };
    let text = format!(
        "[Unit]\nDescription={}\nDocumentation={}\n\n{body}",
        scalar(&title)?,
        scalar(&receipt_uri(&unit, &format!("sha256:{revision}")))?
    );
    Ok(Definition {
        unit,
        text,
        target: target.into(),
        enabled,
        revision: format!("sha256:{revision}"),
        swap_source,
        trigger,
        optional_mount_source,
    })
}

fn unit_path(definition: &Definition) -> PathBuf {
    Path::new(UNIT_ROOT).join(&definition.unit)
}
fn link_path(definition: &Definition) -> PathBuf {
    Path::new(UNIT_ROOT)
        .join(format!("{}.wants", definition.target))
        .join(&definition.unit)
}

fn owned_file(definition: &Definition) -> Result<bool> {
    owned_file_at(&unit_path(definition), definition)
}

fn owned_file_at(path: &Path, definition: &Definition) -> Result<bool> {
    match read_regular(path, 262_144)? {
        Some(bytes) => {
            ensure!(
                bytes == definition.text.as_bytes(),
                "installed unit differs from ownership receipt"
            );
            Ok(true)
        }
        None => Ok(false),
    }
}

fn check_link(definition: &Definition) -> Result<bool> {
    match fs::symlink_metadata(link_path(definition)) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_symlink()
                    && fs::read_link(link_path(definition))? == unit_path(definition),
                "enablement link is foreign"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn owned_identity(manager: &PinnedSystemdManager, definition: &Definition) -> Result<String> {
    let identity = manager
        .unit_identity_at_revision(&definition.unit, &definition.revision)
        .await?;
    let (fragment, dropins) = manager
        .unit_definition_paths_exact(&definition.unit, &identity)
        .await?;
    ensure!(
        Path::new(&fragment) == unit_path(definition) && dropins.is_empty(),
        "manager unit definition is foreign or extended"
    );
    Ok(identity)
}

async fn manager_absent(manager: &PinnedSystemdManager, definition: &Definition) -> Result<bool> {
    match manager.unit_identity(&definition.unit).await {
        Err(error) if error.is_no_such_unit() => Ok(true),
        Ok(identity) => {
            let (fragment, dropins) = manager
                .unit_definition_paths_exact(&definition.unit, &identity)
                .await?;
            let active = manager
                .active_state_exact(&definition.unit, &identity)
                .await?;
            Ok(fragment.is_empty()
                && dropins.is_empty()
                && active == aos_systemd::UnitActiveState::Inactive)
        }
        Err(error) => Err(error.into()),
    }
}

async fn retire(manager: &PinnedSystemdManager, definition: &Definition) -> Result<()> {
    if !owned_file(definition)? {
        ensure!(
            !check_link(definition)?,
            "owned unit disappeared while enablement remains"
        );
        if manager_absent(manager, definition).await? {
            return Ok(());
        }
        match manager.unit_identity(&definition.unit).await {
            Err(error) if error.is_no_such_unit() => return Ok(()),
            Ok(identity) => {
                let exact = owned_identity(manager, definition).await?;
                ensure!(
                    identity == exact
                        && manager
                            .active_state_exact_revision(
                                &definition.unit,
                                &identity,
                                &definition.revision
                            )
                            .await?
                            == aos_systemd::UnitActiveState::Inactive,
                    "missing unit remains active or differs from receipt"
                );
                manager.daemon_reload().await?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }
    if !manager_absent(manager, definition).await? {
        let identity = owned_identity(manager, definition).await?;
        let job = manager
            .stop_unit_exact_revision(&definition.unit, &identity, &definition.revision)
            .await?;
        ensure!(
            job.result.is_done(),
            "owned unit stop failed: {}",
            job.result.label()
        );
    }
    if check_link(definition)? {
        fs::remove_file(link_path(definition))?;
    }
    fs::remove_file(unit_path(definition))?;
    manager.daemon_reload().await?;
    Ok(())
}

/// Converges or observes one exact owned unit through a pinned manager.
///
/// # Errors
/// Returns an error for malformed inputs, foreign resource state, lost manager
/// identity, or unsuccessful unit jobs.
pub(super) async fn execute(invocation: &Invocation, action: &str, ability: &str) -> Result<Value> {
    let desired = definition(invocation, ability)?;
    let path = state_path(invocation, "unit");
    let previous: Option<Receipt> = read_regular(&path, 1_048_576)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?;
    if let Some(receipt) = &previous {
        ensure!(receipt.owner == invocation.id, "unit receipt owner differs");
    }
    let manager = PinnedSystemdManager::connect().await?;

    if action == "observe" {
        return Ok(
            match observe(&manager, invocation, &desired, previous.as_ref()).await {
                Ok(value) => value,
                Err(_) => json!({"status":"indeterminate"}),
            },
        );
    }
    if action == "remove" {
        if let Some(receipt) = previous {
            if let Some(retiring) = &receipt.retiring {
                retire(&manager, retiring).await?;
            }
            retire(&manager, &receipt.desired).await?;
            fs::remove_file(path)?;
        } else {
            ensure!(
                read_regular(&unit_path(&desired), 262_144)?.is_none() && !check_link(&desired)?,
                "resource exists without ownership receipt"
            );
            ensure!(
                manager_absent(&manager, &desired).await?,
                "manager resource exists without ownership receipt"
            );
        }
        return Ok(json!({}));
    }

    if let Some(trigger) = &desired.trigger {
        // A deferred service result is canonical; aliases must not redirect a timer.
        manager.unit_identity(trigger).await?;
    }
    let parent = path.parent().context("receipt has no parent")?;
    private_directory(parent)?;
    let mut receipt = match previous {
        Some(receipt) if receipt.desired == desired => receipt,
        Some(receipt) => {
            ensure!(
                receipt.retiring.is_none(),
                "finish interrupted prior transition before changing desired state"
            );
            Receipt {
                owner: invocation.id.clone(),
                desired: desired.clone(),
                retiring: Some(receipt.desired),
                complete: false,
            }
        }
        None => {
            ensure!(
                read_regular(&unit_path(&desired), 262_144)?.is_none() && !check_link(&desired)?,
                "resource name is already owned"
            );
            ensure!(
                manager_absent(&manager, &desired).await?,
                "manager resource is already owned"
            );
            Receipt {
                owner: invocation.id.clone(),
                desired: desired.clone(),
                retiring: None,
                complete: false,
            }
        }
    };
    atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
    if let Some(retiring) = &receipt.retiring {
        retire(&manager, retiring).await?;
        receipt.retiring = None;
        atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
    }
    if !owned_file(&desired)? {
        let mut temporary = tempfile::NamedTempFile::new_in(UNIT_ROOT)?;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
        temporary.write_all(desired.text.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary
            .persist_noclobber(unit_path(&desired))
            .map_err(|error| error.error)?;
    }
    let enabled = check_link(&desired)?;
    if desired.enabled && !enabled {
        fs::create_dir_all(
            link_path(&desired)
                .parent()
                .context("link parent missing")?,
        )?;
        std::os::unix::fs::symlink(unit_path(&desired), link_path(&desired))?;
    } else if !desired.enabled && enabled {
        fs::remove_file(link_path(&desired))?;
    }
    manager.daemon_reload().await?;
    manager.load_unit(&desired.unit).await?;
    let identity = owned_identity(&manager, &desired).await?;
    let source_missing = optional_mount_source_missing(&desired)?;
    let job = if desired.enabled && !source_missing {
        Some(
            manager
                .start_unit_exact_revision(&desired.unit, &identity, &desired.revision)
                .await?,
        )
    } else if !desired.enabled {
        Some(
            manager
                .stop_unit_exact_revision(&desired.unit, &identity, &desired.revision)
                .await?,
        )
    } else {
        None
    };
    if let Some(job) = job {
        ensure!(
            job.result.is_done(),
            "owned unit convergence failed: {}",
            job.result.label()
        );
    }
    let active = manager
        .active_state_exact_revision(&desired.unit, &identity, &desired.revision)
        .await?;
    ensure!(
        resource_converged(&desired, &active, source_missing),
        "owned resource did not reach its requested availability"
    );
    receipt.complete = true;
    atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
    Ok(resource_outputs(&desired, &active))
}

/// Distinguishes an absent optional source from inaccessible or invalid paths.
fn optional_mount_source_missing(desired: &Definition) -> Result<bool> {
    let Some(source) = &desired.optional_mount_source else {
        return Ok(false);
    };
    match fs::metadata(source) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn resource_converged(
    desired: &Definition,
    active: &aos_systemd::UnitActiveState,
    source_missing: bool,
) -> bool {
    if !desired.enabled {
        *active == aos_systemd::UnitActiveState::Inactive
    } else {
        active.is_active()
            || (desired.optional_mount_source.is_some()
                && source_missing
                && *active == aos_systemd::UnitActiveState::Inactive)
    }
}

fn resource_outputs(desired: &Definition, active: &aos_systemd::UnitActiveState) -> Value {
    let mut outputs = json!({"resource":desired.unit});
    if desired.unit.ends_with(".mount") {
        outputs["state"] = json!(if !desired.enabled {
            "disabled"
        } else if active.is_active() {
            "mounted"
        } else {
            "unavailable"
        });
    }
    outputs
}

async fn observe(
    manager: &PinnedSystemdManager,
    invocation: &Invocation,
    desired: &Definition,
    receipt: Option<&Receipt>,
) -> Result<Value> {
    let Some(receipt) = receipt else {
        ensure!(
            read_regular(&unit_path(desired), 262_144)?.is_none() && !check_link(desired)?,
            "unowned unit exists"
        );
        ensure!(
            manager_absent(manager, desired).await?,
            "unowned manager unit exists"
        );
        return Ok(
            json!({"status": if invocation.action == aos_ability_runtime::activation::Action::Remove { "absent" } else { "retry-safe" }}),
        );
    };
    let mut needs_reload = false;
    let same_unit_transition = receipt
        .retiring
        .as_ref()
        .is_some_and(|old| old.unit == receipt.desired.unit);
    for definition in receipt
        .retiring
        .iter()
        .chain((!same_unit_transition).then_some(&receipt.desired))
    {
        if owned_file(definition)? {
            if manager_absent(manager, definition).await? {
                needs_reload = true;
            } else {
                owned_identity(manager, definition).await?;
            }
        } else {
            ensure!(!check_link(definition)?, "orphan enablement link");
            if manager_absent(manager, definition).await? {
                continue;
            }
            match manager.unit_identity(&definition.unit).await {
                Err(error) if error.is_no_such_unit() => {}
                Ok(identity) => {
                    let exact = owned_identity(manager, definition).await?;
                    ensure!(
                        identity == exact
                            && manager
                                .active_state_exact_revision(
                                    &definition.unit,
                                    &identity,
                                    &definition.revision
                                )
                                .await?
                                == aos_systemd::UnitActiveState::Inactive,
                        "orphan manager resource is active or foreign"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    if invocation.action == aos_ability_runtime::activation::Action::Remove
        || receipt.retiring.is_some()
        || receipt.desired != *desired
        || !receipt.complete
        || needs_reload
    {
        return Ok(json!({"status":"retry-safe"}));
    }
    ensure!(
        owned_file(desired)? && check_link(desired)? == desired.enabled,
        "owned resource is incomplete"
    );
    if let Some(trigger) = &desired.trigger {
        manager.unit_identity(trigger).await?;
    }
    let identity = owned_identity(manager, desired).await?;
    let active = manager
        .active_state_exact_revision(&desired.unit, &identity, &desired.revision)
        .await?;
    let converged = resource_converged(desired, &active, optional_mount_source_missing(desired)?);
    if !converged {
        return Ok(json!({"status":"retry-safe"}));
    }
    if let Some(source) = &desired.swap_source {
        let swaps = fs::read_to_string("/proc/swaps")?;
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let expected = fs::metadata(source)?;
        let matches = swaps
            .lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().next())
            .any(|path| {
                if path == source {
                    return true;
                }
                fs::metadata(path).is_ok_and(|actual| {
                    if expected.file_type().is_block_device() {
                        actual.file_type().is_block_device() && actual.rdev() == expected.rdev()
                    } else {
                        actual.is_file()
                            && actual.dev() == expected.dev()
                            && actual.ino() == expected.ino()
                    }
                })
            });
        ensure!(
            matches == desired.enabled,
            "owned swap kernel state differs from desired activation"
        );
    }
    Ok(json!({"status":"current","outputs":resource_outputs(desired, &active)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_mount_reports_absence_and_retries_when_source_appears() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("sealed-volume");
        let desired = definition_for(
            "optional-data",
            &"a".repeat(64),
            "mount",
            &json!({
                "name": "data", "source": source, "destination": "/srv/data",
                "filesystem": "ext4", "optional": true
            }),
        )
        .unwrap();
        let inactive = aos_systemd::UnitActiveState::Inactive;

        assert!(desired.text.contains("ConditionPathExists="));
        assert!(desired.text.contains("Options=nofail"));
        assert!(optional_mount_source_missing(&desired).unwrap());
        assert!(resource_converged(&desired, &inactive, true));
        assert_eq!(
            resource_outputs(&desired, &inactive)["state"],
            "unavailable"
        );

        fs::write(&source, b"available source").unwrap();

        assert!(!optional_mount_source_missing(&desired).unwrap());
        assert!(!resource_converged(&desired, &inactive, false));
        let active = aos_systemd::UnitActiveState::Active;
        assert!(resource_converged(&desired, &active, false));
        assert_eq!(resource_outputs(&desired, &active)["state"], "mounted");
    }

    #[test]
    fn required_mount_never_converges_with_an_absent_source() {
        let desired = definition_for(
            "required-data",
            &"a".repeat(64),
            "mount",
            &json!({"name": "state", "source": "/dev/disk/by-label/var", "destination": "/var"}),
        )
        .unwrap();

        assert!(!desired.text.contains("ConditionPathExists="));
        assert!(!desired.text.contains("nofail"));
        assert!(!resource_converged(
            &desired,
            &aos_systemd::UnitActiveState::Inactive,
            true
        ));
        assert!(!resource_converged(
            &desired,
            &aos_systemd::UnitActiveState::Failed,
            true
        ));
        assert!(resource_converged(
            &desired,
            &aos_systemd::UnitActiveState::Active,
            false
        ));
    }

    #[test]
    fn unit_receipt_rejects_foreign_replacements_and_recognizes_missing_owned_files() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("owned.swap");
        let desired = definition_for(
            "swap",
            &"a".repeat(64),
            "swap",
            &json!({
                "name":"swap", "source":"/dev/mapper/cryptswap"
            }),
        )
        .unwrap();
        assert!(!owned_file_at(&path, &desired).unwrap());

        fs::write(&path, desired.text.as_bytes()).unwrap();
        assert!(owned_file_at(&path, &desired).unwrap());

        fs::write(&path, b"[Swap]\nWhat=/dev/foreign\n").unwrap();
        assert!(owned_file_at(&path, &desired).is_err());
        fs::remove_file(&path).unwrap();
        assert!(!owned_file_at(&path, &desired).unwrap());
    }

    #[test]
    fn timer_policy_preserves_target_and_calendar_or_interval_settings() {
        let calendar = definition_for(
            "effect-one",
            &"a".repeat(64),
            "scheduledActivation",
            &json!({
                "name":"scrub", "target":"aos-zfs-scrub.service",
                "schedule":{"kind":"calendar","expression":"Sun *-*-* 02:00:00"},
                "persistent":true, "accuracy_millis":1000, "randomized_delay_millis":45000
            }),
        )
        .unwrap();
        assert!(calendar.text.contains("Unit=aos-zfs-scrub.service"));
        assert!(
            calendar
                .text
                .contains("Persistent=yes\nAccuracySec=1000ms\nRandomizedDelaySec=45000ms")
        );
        assert!(!calendar.text.contains("[Service]"));

        let interval = definition_for(
            "effect-one",
            &"a".repeat(64),
            "scheduledActivation",
            &json!({
                "name":"scrub", "target":"aos-zfs-scrub.service",
                "schedule":{"kind":"interval","initial_delay_millis":100,"interval_millis":5000}
            }),
        )
        .unwrap();
        assert_eq!(calendar.unit, interval.unit);
        assert!(
            interval
                .text
                .contains("OnBootSec=100ms\nOnUnitActiveSec=5000ms")
        );
        assert_ne!(calendar.text, interval.text);
    }

    #[test]
    fn swap_mapping_and_bind_mount_keep_native_concrete_paths() {
        let swap = definition_for(
            "swap",
            &"b".repeat(64),
            "swap",
            &json!({
                "name":"cryptswap", "source":"/dev/mapper/cryptswap", "priority":20, "enabled":false
            }),
        )
        .unwrap();
        assert_eq!(swap.swap_source.as_deref(), Some("/dev/mapper/cryptswap"));
        assert!(
            swap.text
                .contains("What=/dev/mapper/cryptswap\nPriority=20")
        );
        assert!(!swap.enabled);

        let mount = definition_for("bridge", &"b".repeat(64), "mount", &json!({
            "name":"profile GC bridge", "source":"/var/lib/profiles",
            "destination":"/nix/var/nix/gcroots/aos-profiles", "options":["bind"], "timeout_millis":5000
        })).unwrap();
        assert_eq!(mount.unit, "nix-var-nix-gcroots-aos\\x2dprofiles.mount");
        assert!(mount.text.contains("Options=bind\nTimeoutSec=5000ms"));
    }

    #[test]
    fn unsupported_schedule_fields_and_directive_injection_fail_closed() {
        assert!(
            definition_for(
                "timer",
                &"a".repeat(64),
                "scheduledActivation",
                &json!({
                    "name":"timer", "target":"foreign.service\nUnit=other.service",
                    "schedule":{"kind":"calendar","expression":"daily"}
                })
            )
            .is_err()
        );
        assert!(
            definition_for(
                "timer",
                &"a".repeat(64),
                "scheduledActivation",
                &json!({
                    "name":"timer", "target":"target.service",
                    "schedule":{"kind":"interval","initial_delay_millis":0,"interval_millis":0}
                })
            )
            .is_err()
        );
    }

    #[test]
    fn path_names_distinguish_separators_from_literal_hyphens() {
        assert_eq!(
            path_unit("/dev/mapper/cryptswap", "swap").unwrap(),
            "dev-mapper-cryptswap.swap"
        );
        assert_eq!(path_unit("/dev/a-b", "swap").unwrap(), "dev-a\\x2db.swap");
        assert!(path_unit("/dev/../foreign", "swap").is_err());
        assert_eq!(
            path_unit("/.private/mount", "mount").unwrap(),
            "\\x2eprivate-mount.mount"
        );
    }

    #[test]
    fn unit_values_cannot_inject_directives_or_specifiers() {
        assert!(scalar("x\nExecStart=foreign").is_err());
        assert!(scalar(" /leading-whitespace").is_err());
        assert!(scalar("/trailing-whitespace ").is_err());
        assert!(scalar("/continuation\\").is_err());
        assert_eq!(scalar("%n\"").unwrap(), "%%n\"");
        assert_eq!(
            receipt_uri("dev-a\\x2db.swap", &format!("sha256:{}", "a".repeat(64))),
            format!(
                "file:/etc/aos/ability-revisions/dev-a%5Cx2db.swap/sha256/{}",
                "a".repeat(64)
            )
        );
    }
}
