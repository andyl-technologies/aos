//! Fleet BPF-LSM policy loading.
//!
//! RFC-0001 treats BPF-LSM as host/fleet policy, not as per-package manifest
//! privilege. `/etc/aos/policy.toml` selects exact policy packages from the
//! system package profile, and this module resolves those selections to
//! package-contained JSON/BPF artifacts before invoking the AOS-built loader.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::policy::{DEFAULT_POLICY_PATH, EbpfLsmPolicyRef, HostPolicy, policy_root};
use crate::profile::Profile;
use crate::profile::meta::list_meta;
use crate::registry::store_path_hash;
use crate::types::{BpfLsmPolicyArtifactMeta, InstalledMeta, ProfileScope};

const EBPF_LSM_POLICY_ENV: &str = "AOS_EBPF_LSM_POLICY";
const EBPF_LSM_PIN_DIR_ENV: &str = "AOS_EBPF_LSM_PIN_DIR";
const DEFAULT_EBPF_LSM_PIN_DIR: &str = "/sys/fs/bpf/aos/lsm";

/// Load the BPF-LSM policies selected by `/etc/aos/policy.toml`.
///
/// # Errors
///
/// Returns an error when host policy cannot be loaded, a selected policy
/// package is not installed with the expected registry/version, policy
/// artifacts do not match the selector, or the helper fails to load and pin a
/// BPF-LSM link.
pub fn load_system_policies() -> Result<()> {
    let Some(policy) = load_host_policy()? else {
        return Ok(());
    };
    if policy.ebpf_lsm.policies.is_empty() {
        return Ok(());
    }

    let profile = Profile::open_readonly(ProfileScope::System);
    let installed = list_meta(&profile)?;
    let current_roots = current_generation_roots(&profile)?;
    let helper = trusted_ebpf_lsm_policy_path()?;
    let pin_dir = ebpf_lsm_pin_dir();

    for plan in load_plans(
        &policy,
        &installed,
        &current_roots,
        helper.as_path(),
        pin_dir.as_path(),
    )? {
        run_load_plan(&plan)?;
    }

    Ok(())
}

fn load_host_policy() -> Result<Option<HostPolicy>> {
    let policy_path = policy_root().join(DEFAULT_POLICY_PATH.trim_start_matches('/'));
    if !policy_path.exists() {
        return Ok(None);
    }
    HostPolicy::load_from_path(&policy_path).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadPlan {
    name: String,
    helper: PathBuf,
    policy: PathBuf,
    object: PathBuf,
    pin_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyArtifact {
    version: u32,
    name: String,
    programs: Vec<String>,
}

fn load_plans(
    policy: &HostPolicy,
    installed: &[InstalledMeta],
    current_roots: &HashMap<String, PathBuf>,
    helper: &Path,
    pin_dir: &Path,
) -> Result<Vec<LoadPlan>> {
    policy
        .ebpf_lsm
        .policies
        .iter()
        .map(|policy_ref| load_plan(policy_ref, installed, current_roots, helper, pin_dir))
        .collect()
}

fn load_plan(
    policy_ref: &EbpfLsmPolicyRef,
    installed: &[InstalledMeta],
    current_roots: &HashMap<String, PathBuf>,
    helper: &Path,
    pin_dir: &Path,
) -> Result<LoadPlan> {
    let installed = find_policy_package(policy_ref, installed, current_roots)?;
    let signed_policy = find_signed_policy_metadata(policy_ref, installed)?;
    let package_root = Path::new(&installed.store_path);
    let policy_path = package_root.join(&policy_ref.policy);
    let object_path = package_root.join(&policy_ref.object);

    if signed_policy.policy != policy_ref.policy
        || signed_policy.object != policy_ref.object
        || signed_policy.programs != policy_ref.programs
    {
        bail!(
            "BPF-LSM policy '{}' differs from installed signed package metadata",
            policy_ref.name
        );
    }
    validate_artifact(&policy_path, policy_ref)?;
    require_regular_file("BPF-LSM object", &object_path)?;

    Ok(LoadPlan {
        name: policy_ref.name.clone(),
        helper: helper.to_path_buf(),
        policy: policy_path,
        object: object_path,
        pin_dir: pin_dir.to_path_buf(),
    })
}

fn find_policy_package<'a>(
    policy_ref: &EbpfLsmPolicyRef,
    installed: &'a [InstalledMeta],
    current_roots: &HashMap<String, PathBuf>,
) -> Result<&'a InstalledMeta> {
    installed
        .iter()
        .find(|meta| {
            meta.apm.as_ref().is_some_and(|apm| {
                apm.name == policy_ref.package
                    && apm.registry == policy_ref.registry
                    && apm.version == policy_ref.version
                    && is_current_generation_root(meta, current_roots)
            })
        })
        .with_context(|| {
            format!(
                "BPF-LSM policy '{}' requires installed package {}/{} {} rooted in the current system generation",
                policy_ref.name, policy_ref.registry, policy_ref.package, policy_ref.version
            )
        })
}

fn current_generation_roots(profile: &Profile) -> Result<HashMap<String, PathBuf>> {
    let generation = profile
        .current_generation()?
        .context("BPF-LSM policies require an active system package generation")?;
    Ok(generation.roots()?.into_iter().collect())
}

fn is_current_generation_root(
    meta: &InstalledMeta,
    current_roots: &HashMap<String, PathBuf>,
) -> bool {
    let hash = store_path_hash(&meta.store_path);
    current_roots
        .get(hash)
        .is_some_and(|target| target == Path::new(&meta.store_path))
}

fn find_signed_policy_metadata<'a>(
    policy_ref: &EbpfLsmPolicyRef,
    installed: &'a InstalledMeta,
) -> Result<&'a BpfLsmPolicyArtifactMeta> {
    let apm = installed
        .apm
        .as_ref()
        .context("BPF-LSM policy package is missing APM metadata")?;
    let bpf_lsm = apm.bpf_lsm.as_ref().with_context(|| {
        format!(
            "BPF-LSM policy package '{}' is missing signed BPF-LSM metadata",
            policy_ref.package
        )
    })?;
    bpf_lsm
        .policies
        .iter()
        .find(|candidate| candidate.name == policy_ref.name)
        .with_context(|| {
            format!(
                "BPF-LSM policy package '{}' does not declare policy '{}'",
                policy_ref.package, policy_ref.name
            )
        })
}

fn validate_artifact(path: &Path, policy_ref: &EbpfLsmPolicyRef) -> Result<()> {
    require_regular_file("BPF-LSM policy", path)?;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading BPF-LSM policy {}", path.display()))?;
    let artifact: PolicyArtifact = serde_json::from_str(&text)
        .with_context(|| format!("parsing BPF-LSM policy {}", path.display()))?;

    if artifact.version != 1 {
        bail!(
            "BPF-LSM policy '{}' has unsupported version {}",
            policy_ref.name,
            artifact.version
        );
    }
    if artifact.name != policy_ref.name {
        bail!(
            "BPF-LSM policy name mismatch: host policy selects '{}', artifact declares '{}'",
            policy_ref.name,
            artifact.name
        );
    }
    if artifact.programs != policy_ref.programs {
        bail!(
            "BPF-LSM policy '{}' program list differs from host policy",
            policy_ref.name
        );
    }

    Ok(())
}

fn require_regular_file(kind: &str, path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{kind} is not a regular file: {}", path.display());
    }
    Ok(())
}

fn run_load_plan(plan: &LoadPlan) -> Result<()> {
    let output = Command::new(&plan.helper)
        .arg("load")
        .arg("--policy")
        .arg(&plan.policy)
        .arg("--object")
        .arg(&plan.object)
        .arg("--pin-dir")
        .arg(&plan.pin_dir)
        .output()
        .with_context(|| format!("running {}", plan.helper.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "loading BPF-LSM policy '{}' failed with status {}: {}{}",
            plan.name,
            output.status,
            stdout,
            stderr
        );
    }

    io::stdout()
        .write_all(&output.stdout)
        .context("writing BPF-LSM loader stdout")?;
    io::stderr()
        .write_all(&output.stderr)
        .context("writing BPF-LSM loader stderr")?;

    Ok(())
}

fn trusted_ebpf_lsm_policy_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(EBPF_LSM_POLICY_ENV) {
        if path.is_empty() {
            bail!("{EBPF_LSM_POLICY_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/aos-ebpf-lsm-policy") {
            bail!("{EBPF_LSM_POLICY_ENV} must point to an absolute aos-ebpf-lsm-policy binary");
        }
        return Ok(PathBuf::from(path));
    }

    #[cfg(test)]
    {
        return Ok(PathBuf::from(
            "/nix/store/hash-aos-ebpf-lsm-policy-0/bin/aos-ebpf-lsm-policy",
        ));
    }

    #[cfg(not(test))]
    {
        bail!("{EBPF_LSM_POLICY_ENV} is not configured for BPF-LSM policy loading");
    }
}

fn ebpf_lsm_pin_dir() -> PathBuf {
    std::env::var(EBPF_LSM_PIN_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_EBPF_LSM_PIN_DIR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EbpfLsmPolicyRef, EbpfLsmPolicySet, PolicyAllow};
    use crate::types::{ApmMeta, BpfLsmPolicyArtifactMeta, BpfLsmPolicyMeta};
    use tempfile::TempDir;

    fn installed_policy(root: &Path) -> InstalledMeta {
        InstalledMeta {
            store_path: root.display().to_string(),
            pushed_at: 1,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1,
            access_count: 0,
            apm: Some(ApmMeta {
                name: "aos-ebpf-lsm-policy".into(),
                version: "0".into(),
                explicit: true,
                registry: "aos".into(),
                installed_at: "1970-01-01T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: Some(BpfLsmPolicyMeta {
                    policies: vec![BpfLsmPolicyArtifactMeta {
                        name: "aos-lsm-task-audit".into(),
                        policy: "share/aos/ebpf-lsm/aos-task-audit.json".into(),
                        object: "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o".into(),
                        programs: vec!["aos_lsm_file_mprotect".into()],
                    }],
                }),
                attestation: Default::default(),
            }),
        }
    }

    fn host_policy() -> HostPolicy {
        HostPolicy {
            tier: Default::default(),
            allow: PolicyAllow::default(),
            kernel_modules: Vec::new(),
            systemd_security_threshold: None,
            ebpf_lsm: EbpfLsmPolicySet {
                policies: vec![EbpfLsmPolicyRef {
                    name: "aos-lsm-task-audit".into(),
                    registry: "aos".into(),
                    package: "aos-ebpf-lsm-policy".into(),
                    version: "0".into(),
                    policy: "share/aos/ebpf-lsm/aos-task-audit.json".into(),
                    object: "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o".into(),
                    programs: vec!["aos_lsm_file_mprotect".into()],
                }],
            },
        }
    }

    fn write_policy_package(root: &Path, programs: &[&str]) {
        let policy_dir = root.join("share/aos/ebpf-lsm");
        let object_dir = root.join("lib/bpf");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::create_dir_all(&object_dir).unwrap();
        let programs_json = programs
            .iter()
            .map(|program| format!("\"{program}\""))
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(
            policy_dir.join("aos-task-audit.json"),
            format!(
                "{{\"version\":1,\"name\":\"aos-lsm-task-audit\",\"programs\":[{programs_json}]}}"
            ),
        )
        .unwrap();
        std::fs::write(object_dir.join("aos-ebpf-lsm-task-audit.bpf.o"), b"object").unwrap();
    }

    #[test]
    fn plans_loader_from_installed_signed_policy_package() {
        let tmp = TempDir::new().unwrap();
        write_policy_package(tmp.path(), &["aos_lsm_file_mprotect"]);
        let installed = vec![installed_policy(tmp.path())];
        let plans = load_plans(
            &host_policy(),
            &installed,
            &current_roots(tmp.path()),
            Path::new("/nix/store/hash-aos-ebpf-lsm-policy-0/bin/aos-ebpf-lsm-policy"),
            Path::new("/sys/fs/bpf/aos/lsm"),
        )
        .unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].name, "aos-lsm-task-audit");
        assert!(
            plans[0]
                .policy
                .ends_with("share/aos/ebpf-lsm/aos-task-audit.json")
        );
        assert!(
            plans[0]
                .object
                .ends_with("lib/bpf/aos-ebpf-lsm-task-audit.bpf.o")
        );
    }

    #[test]
    fn rejects_policy_package_with_wrong_registry_or_programs() {
        let tmp = TempDir::new().unwrap();
        write_policy_package(tmp.path(), &["other_program"]);
        let installed = vec![installed_policy(tmp.path())];

        let err = load_plans(
            &host_policy(),
            &installed,
            &current_roots(tmp.path()),
            Path::new("/nix/store/hash-aos-ebpf-lsm-policy-0/bin/aos-ebpf-lsm-policy"),
            Path::new("/sys/fs/bpf/aos/lsm"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("program list differs"));

        let mut wrong = installed_policy(tmp.path());
        wrong.apm.as_mut().unwrap().registry = "other".into();
        let err = load_plans(
            &host_policy(),
            &[wrong],
            &current_roots(tmp.path()),
            Path::new("/nix/store/hash-aos-ebpf-lsm-policy-0/bin/aos-ebpf-lsm-policy"),
            Path::new("/sys/fs/bpf/aos/lsm"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("requires installed package"));
    }

    #[test]
    fn rejects_policy_package_without_signed_bpf_lsm_metadata() {
        let tmp = TempDir::new().unwrap();
        write_policy_package(tmp.path(), &["aos_lsm_file_mprotect"]);
        let mut installed = installed_policy(tmp.path());
        installed.apm.as_mut().unwrap().bpf_lsm = None;

        let err = load_plans(
            &host_policy(),
            &[installed],
            &current_roots(tmp.path()),
            Path::new("/nix/store/hash-aos-ebpf-lsm-policy-0/bin/aos-ebpf-lsm-policy"),
            Path::new("/sys/fs/bpf/aos/lsm"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing signed BPF-LSM metadata"));
    }

    fn current_roots(root: &Path) -> HashMap<String, PathBuf> {
        HashMap::from([(
            store_path_hash(&root.display().to_string()).to_string(),
            root.to_path_buf(),
        )])
    }

    #[test]
    fn rejects_policy_package_metadata_without_current_generation_root() {
        let tmp = TempDir::new().unwrap();
        write_policy_package(tmp.path(), &["aos_lsm_file_mprotect"]);
        let installed = vec![installed_policy(tmp.path())];

        let err = load_plans(
            &host_policy(),
            &installed,
            &HashMap::new(),
            Path::new("/nix/store/hash-aos-ebpf-lsm-policy-0/bin/aos-ebpf-lsm-policy"),
            Path::new("/sys/fs/bpf/aos/lsm"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("current system generation"));
    }
}
