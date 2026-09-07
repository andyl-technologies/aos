//! Strict pre-bind campaign artifact-import manifests.
//!
//! ```toml
//! schema = "crucible.campaign-import"
//! version = 1
//!
//! [[configuration]]
//! scenario = "/srv/crucible/import/scenario.bin"
//! schedule = "/srv/crucible/import/schedule.bin"
//!
//! [[generator]]
//! specification = "/srv/crucible/import/generator.bin"
//! ```
//!
//! Manifests and every referenced body are exact-owner regular files with no
//! group/other write bits. Bodies are read and verified one at a time while the
//! durable campaign repository is exclusively owned and before its service
//! socket is bound.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use crucible::{ScenarioDefForm, Schedule};
use crucible_campaign::{
    CandidateGeneratorAlgorithm, CandidateGeneratorSpec, CandidateGeneratorSpecId,
    ConfigurationArtifactId,
};
use crucible_daemon::{
    MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES, PreparedCampaignLocalService,
    decode_crucible_configuration_artifact, decode_crucible_scenario_artifact,
    encode_crucible_configuration_artifact, encode_crucible_scenario_artifact,
};
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;

use super::*;

const CAMPAIGN_IMPORT_SCHEMA: &str = "crucible.campaign-import";
const CAMPAIGN_IMPORT_VERSION: u32 = 1;
const CAMPAIGN_IMPORT_VALIDATION_REPORT_SCHEMA: &str = "crucible.cli.campaign-import-validation.v1";
const MAX_CAMPAIGN_IMPORT_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_CAMPAIGN_IMPORT_ENTRIES: usize = 4_096;
const MAX_CAMPAIGN_IMPORT_PATH_BYTES: usize = 4_095;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignImportManifest {
    schema: String,
    version: u32,
    #[serde(default)]
    configuration: Vec<ConfigurationImport>,
    #[serde(default)]
    generator: Vec<GeneratorImport>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationImport {
    scenario: PathBuf,
    schedule: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratorImport {
    specification: PathBuf,
}

/// Summary produced by strict offline campaign-import validation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct CampaignImportValidationReport {
    schema: &'static str,
    manifests: usize,
    configurations: Vec<String>,
    generators: Vec<String>,
}

impl CampaignImportValidationReport {
    /// Returns the number of strict manifests validated together.
    #[must_use]
    pub(super) const fn manifest_count(&self) -> usize {
        self.manifests
    }

    /// Returns the exact verified configuration-artifact identities.
    #[must_use]
    pub(super) fn configurations(&self) -> &[String] {
        &self.configurations
    }

    /// Returns the exact verified generator identities.
    #[must_use]
    pub(super) fn generators(&self) -> &[String] {
        &self.generators
    }
}

trait CampaignImportTarget {
    fn configuration(
        &mut self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<ConfigurationArtifactId, String>;

    fn generator(
        &mut self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<CandidateGeneratorSpecId, String>;
}

struct RepositoryImportTarget<'a> {
    prepared: &'a PreparedCampaignLocalService,
}

impl CampaignImportTarget for RepositoryImportTarget<'_> {
    fn configuration(
        &mut self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<ConfigurationArtifactId, String> {
        self.prepared
            .import_configuration(scenario, schedule)
            .map_err(|error| error.to_string())
    }

    fn generator(
        &mut self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<CandidateGeneratorSpecId, String> {
        self.prepared
            .import_generator(generator)
            .map_err(|error| error.to_string())
    }
}

#[derive(Default)]
struct OfflineValidationTarget {
    generators: BTreeSet<CandidateGeneratorSpecId>,
}

impl CampaignImportTarget for OfflineValidationTarget {
    fn configuration(
        &mut self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<ConfigurationArtifactId, String> {
        let scenario_artifact =
            encode_crucible_scenario_artifact(scenario).map_err(|error| error.to_string())?;
        decode_crucible_scenario_artifact(&scenario_artifact).map_err(|error| error.to_string())?;
        let configuration = encode_crucible_configuration_artifact(&scenario_artifact, schedule)
            .map_err(|error| error.to_string())?;
        decode_crucible_configuration_artifact(scenario, &scenario_artifact, &configuration)
            .map_err(|error| error.to_string())?;
        configuration.id().map_err(|error| error.to_string())
    }

    fn generator(
        &mut self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<CandidateGeneratorSpecId, String> {
        if let CandidateGeneratorAlgorithm::OrderedMixture { components } = generator.algorithm() {
            for component in components {
                if !self.generators.contains(&component.generator()) {
                    return Err(format!(
                        "generator dependency {} was not validated earlier in this manifest set",
                        component.generator()
                    ));
                }
            }
        }
        let id = generator.id().map_err(|error| error.to_string())?;
        self.generators.insert(id);
        Ok(id)
    }
}

pub(super) fn apply_campaign_import_manifests(
    prepared: &PreparedCampaignLocalService,
    manifests: &[PathBuf],
) -> Result<(), CliError> {
    let mut target = RepositoryImportTarget { prepared };
    process_campaign_import_manifests(&mut target, manifests).map(|_| ())
}

/// Validates one closed dependency-ordered manifest set without repository access.
///
/// Configuration identities are re-derived through the same Crucible adapter
/// used by durable import. Generator dependencies must occur earlier in the
/// supplied manifest sequence, making the offline result independent of any
/// preexisting repository state.
pub(super) fn validate_campaign_import_manifests(
    manifests: &[PathBuf],
) -> Result<CampaignImportValidationReport, CliError> {
    let mut target = OfflineValidationTarget::default();
    process_campaign_import_manifests(&mut target, manifests)
}

fn process_campaign_import_manifests<T: CampaignImportTarget>(
    target: &mut T,
    manifests: &[PathBuf],
) -> Result<CampaignImportValidationReport, CliError> {
    let mut total_entries = 0_usize;
    let mut report = CampaignImportValidationReport {
        schema: CAMPAIGN_IMPORT_VALIDATION_REPORT_SCHEMA,
        manifests: manifests.len(),
        configurations: Vec::new(),
        generators: Vec::new(),
    };
    for path in manifests {
        apply_campaign_import_manifest(target, path, &mut total_entries, &mut report)?;
    }
    Ok(report)
}

fn apply_campaign_import_manifest<T: CampaignImportTarget>(
    target: &mut T,
    path: &Path,
    total_entries: &mut usize,
    report: &mut CampaignImportValidationReport,
) -> Result<(), CliError> {
    let bytes = read_secure_import_file(path, MAX_CAMPAIGN_IMPORT_MANIFEST_BYTES, "manifest")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| campaign_import_error(path, format!("manifest is not UTF-8: {error}")))?;
    let manifest: CampaignImportManifest = toml::from_str(text)
        .map_err(|error| campaign_import_error(path, format!("invalid manifest: {error}")))?;
    let manifest_entries = validate_manifest(path, &manifest)?;
    charge_manifest_entries(path, total_entries, manifest_entries)?;

    for configuration in manifest.configuration {
        let scenario_bytes = read_secure_import_file(
            &configuration.scenario,
            MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES,
            "scenario",
        )?;
        let scenario = ScenarioDefForm::from_compact_binary(&scenario_bytes).map_err(|error| {
            campaign_import_error(
                &configuration.scenario,
                format!("invalid scenario body: {error}"),
            )
        })?;
        drop(scenario_bytes);

        let schedule_bytes = read_secure_import_file(
            &configuration.schedule,
            MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES,
            "schedule",
        )?;
        let schedule = Schedule::from_compact_binary(&schedule_bytes).map_err(|error| {
            campaign_import_error(
                &configuration.schedule,
                format!("invalid schedule body: {error}"),
            )
        })?;
        drop(schedule_bytes);

        let id = target
            .configuration(&scenario, &schedule)
            .map_err(|error| {
                campaign_import_error(path, format!("configuration import failed: {error}"))
            })?;
        report.configurations.push(id.to_string());
    }

    for generator in manifest.generator {
        let bytes = read_secure_import_file(
            &generator.specification,
            MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES,
            "generator",
        )?;
        let specification =
            CandidateGeneratorSpec::from_canonical_bytes(&bytes).map_err(|error| {
                campaign_import_error(
                    &generator.specification,
                    format!("invalid generator body: {error}"),
                )
            })?;
        drop(bytes);

        let id = target.generator(&specification).map_err(|error| {
            campaign_import_error(path, format!("generator import failed: {error}"))
        })?;
        report.generators.push(id.to_string());
    }
    Ok(())
}

fn validate_manifest(path: &Path, manifest: &CampaignImportManifest) -> Result<usize, CliError> {
    if manifest.schema != CAMPAIGN_IMPORT_SCHEMA || manifest.version != CAMPAIGN_IMPORT_VERSION {
        return Err(campaign_import_error(
            path,
            format!(
                "unsupported schema/version; expected {CAMPAIGN_IMPORT_SCHEMA} version {CAMPAIGN_IMPORT_VERSION}"
            ),
        ));
    }
    let entry_count = manifest
        .configuration
        .len()
        .checked_add(manifest.generator.len())
        .ok_or_else(|| campaign_import_error(path, "manifest entry count overflow"))?;
    if entry_count == 0 || entry_count > MAX_CAMPAIGN_IMPORT_ENTRIES {
        return Err(campaign_import_error(
            path,
            format!("manifest must contain 1..={MAX_CAMPAIGN_IMPORT_ENTRIES} import entries"),
        ));
    }

    let mut configurations = BTreeSet::new();
    for entry in &manifest.configuration {
        validate_import_path(path, &entry.scenario)?;
        validate_import_path(path, &entry.schedule)?;
        if !configurations.insert((entry.scenario.clone(), entry.schedule.clone())) {
            return Err(campaign_import_error(
                path,
                "manifest contains a duplicate configuration import",
            ));
        }
    }
    let mut generators = BTreeSet::new();
    for entry in &manifest.generator {
        validate_import_path(path, &entry.specification)?;
        if !generators.insert(entry.specification.clone()) {
            return Err(campaign_import_error(
                path,
                "manifest contains a duplicate generator import",
            ));
        }
    }
    Ok(entry_count)
}

fn charge_manifest_entries(
    path: &Path,
    total_entries: &mut usize,
    manifest_entries: usize,
) -> Result<(), CliError> {
    let next = total_entries
        .checked_add(manifest_entries)
        .ok_or_else(|| campaign_import_error(path, "aggregate manifest entry count overflow"))?;
    if next > MAX_CAMPAIGN_IMPORT_ENTRIES {
        return Err(campaign_import_error(
            path,
            format!(
                "startup imports exceed the aggregate {MAX_CAMPAIGN_IMPORT_ENTRIES}-entry bound"
            ),
        ));
    }
    *total_entries = next;
    Ok(())
}

fn validate_import_path(manifest: &Path, path: &Path) -> Result<(), CliError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute()
        || path.file_name().is_none()
        || bytes.contains(&0)
        || bytes.len() > MAX_CAMPAIGN_IMPORT_PATH_BYTES
        || !path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(campaign_import_error(
            manifest,
            format!("import path is invalid: {}", path.display()),
        ));
    }
    Ok(())
}

fn read_secure_import_file(
    path: &Path,
    maximum_bytes: usize,
    kind: &'static str,
) -> Result<Vec<u8>, CliError> {
    validate_import_path(path, path)?;
    let expected = fs::symlink_metadata(path)
        .map_err(|error| campaign_import_io_error(path, kind, "stat", error))?;
    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    if !expected.is_file()
        || expected.uid() != user_id
        || expected.gid() != group_id
        || expected.mode() & 0o022 != 0
        || expected.len() > maximum_bytes as u64
    {
        return Err(campaign_import_error(
            path,
            format!(
                "{kind} must be an exact-owner regular file with no group/other write bits and at most {maximum_bytes} bytes"
            ),
        ));
    }

    let mut file: fs::File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        campaign_import_io_error(
            path,
            kind,
            "open",
            io::Error::from_raw_os_error(error.raw_os_error()),
        )
    })?
    .into();
    let opened = file
        .metadata()
        .map_err(|error| campaign_import_io_error(path, kind, "inspect", error))?;
    if opened.dev() != expected.dev()
        || opened.ino() != expected.ino()
        || !opened.is_file()
        || opened.uid() != user_id
        || opened.gid() != group_id
        || opened.mode() & 0o022 != 0
        || opened.len() > maximum_bytes as u64
    {
        return Err(campaign_import_error(
            path,
            format!("{kind} identity or ownership changed while opening"),
        ));
    }

    let mut bytes = Vec::with_capacity(opened.len() as usize);
    Read::by_ref(&mut file)
        .take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| campaign_import_io_error(path, kind, "read", error))?;
    if bytes.len() > maximum_bytes {
        return Err(campaign_import_error(
            path,
            format!("{kind} exceeds the {maximum_bytes}-byte bound"),
        ));
    }
    Ok(bytes)
}

fn campaign_import_io_error(
    path: &Path,
    kind: &'static str,
    operation: &'static str,
    error: io::Error,
) -> CliError {
    campaign_import_error(path, format!("{operation} {kind} file failed: {error}"))
}

fn campaign_import_error(path: &Path, detail: impl std::fmt::Display) -> CliError {
    serve_error(format!(
        "campaign import error for {}: {detail}",
        path.display()
    ))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use crucible_campaign::WeightedGenerator;

    use super::*;

    #[test]
    fn manifest_schema_rejects_unknown_and_duplicate_entries() {
        let manifest_path = Path::new("/tmp/import.toml");
        let duplicate: CampaignImportManifest = toml::from_str(
            r#"schema = "crucible.campaign-import"
version = 1

[[configuration]]
scenario = "/tmp/scenario.bin"
schedule = "/tmp/schedule.bin"

[[configuration]]
scenario = "/tmp/scenario.bin"
schedule = "/tmp/schedule.bin"
"#,
        )
        .expect("duplicate manifest remains structurally valid");
        assert!(validate_manifest(manifest_path, &duplicate).is_err());

        assert!(
            toml::from_str::<CampaignImportManifest>(
                r#"schema = "crucible.campaign-import"
version = 1
unknown = true

[[generator]]
specification = "/tmp/generator.bin"
"#,
            )
            .is_err()
        );
    }

    #[test]
    fn secure_import_reader_rejects_symlinks_and_oversized_files() {
        let directory = tempfile::tempdir().expect("import directory");
        let body = directory.path().join("body.bin");
        fs::write(&body, b"body").expect("write import body");
        fs::set_permissions(&body, fs::Permissions::from_mode(0o600)).expect("secure import body");
        let link = directory.path().join("body-link.bin");
        symlink(&body, &link).expect("import symlink");
        assert!(read_secure_import_file(&link, 16, "test").is_err());

        let oversized = directory.path().join("oversized.bin");
        fs::write(&oversized, vec![0_u8; 17]).expect("write oversized body");
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))
            .expect("secure oversized body");
        assert!(read_secure_import_file(&oversized, 16, "test").is_err());
    }

    #[test]
    fn repeated_manifests_share_one_aggregate_entry_bound() {
        let path = Path::new("/tmp/import.toml");
        let mut total = MAX_CAMPAIGN_IMPORT_ENTRIES - 1;
        charge_manifest_entries(path, &mut total, 1).expect("exact aggregate bound");
        assert_eq!(total, MAX_CAMPAIGN_IMPORT_ENTRIES);
        assert!(charge_manifest_entries(path, &mut total, 1).is_err());
        assert_eq!(total, MAX_CAMPAIGN_IMPORT_ENTRIES);
    }

    #[test]
    fn offline_validation_authenticates_dependency_order_without_repository_state() {
        let directory = tempfile::tempdir().expect("campaign import validation directory");
        let base = CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All)
            .expect("base generator");
        let base_id = base.id().expect("base generator ID");
        let mixture = CandidateGeneratorSpec::new(
            1,
            CandidateGeneratorAlgorithm::OrderedMixture {
                components: vec![WeightedGenerator::new(base_id, 1).expect("mixture component")],
            },
        )
        .expect("mixture generator");
        let mixture_id = mixture.id().expect("mixture generator ID");
        let base_path = directory.path().join("base.bin");
        let mixture_path = directory.path().join("mixture.bin");
        for (path, bytes) in [
            (&base_path, base.canonical_bytes()),
            (&mixture_path, mixture.canonical_bytes()),
        ] {
            fs::write(path, bytes).expect("generator body");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("secure generator body");
        }
        let manifest = directory.path().join("manifest.toml");
        fs::write(
            &manifest,
            format!(
                concat!(
                    "schema = \"crucible.campaign-import\"\n",
                    "version = 1\n\n",
                    "[[generator]]\n",
                    "specification = \"{}\"\n\n",
                    "[[generator]]\n",
                    "specification = \"{}\"\n",
                ),
                base_path.display(),
                mixture_path.display(),
            ),
        )
        .expect("campaign import manifest");
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))
            .expect("secure campaign import manifest");

        let report = validate_campaign_import_manifests(std::slice::from_ref(&manifest))
            .expect("offline manifest validation");
        assert_eq!(report.manifest_count(), 1);
        assert!(report.configurations().is_empty());
        assert_eq!(
            report.generators(),
            &[base_id.to_string(), mixture_id.to_string()]
        );

        fs::write(
            &manifest,
            format!(
                concat!(
                    "schema = \"crucible.campaign-import\"\n",
                    "version = 1\n\n",
                    "[[generator]]\n",
                    "specification = \"{}\"\n",
                ),
                mixture_path.display(),
            ),
        )
        .expect("missing-dependency manifest");
        assert!(
            validate_campaign_import_manifests(std::slice::from_ref(&manifest))
                .expect_err("missing dependency must fail")
                .to_string()
                .contains("was not validated earlier")
        );
    }

    #[test]
    fn offline_validation_rederives_configuration_identity() {
        let directory = tempfile::tempdir().expect("campaign configuration validation directory");
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let schedule = Schedule::empty();
        let scenario_path = directory.path().join("scenario.bin");
        let schedule_path = directory.path().join("schedule.bin");
        for (path, bytes) in [
            (&scenario_path, scenario.to_compact_binary()),
            (&schedule_path, schedule.to_compact_binary()),
        ] {
            fs::write(path, bytes).expect("configuration body");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("secure configuration body");
        }
        let manifest = directory.path().join("manifest.toml");
        fs::write(
            &manifest,
            format!(
                concat!(
                    "schema = \"crucible.campaign-import\"\n",
                    "version = 1\n\n",
                    "[[configuration]]\n",
                    "scenario = \"{}\"\n",
                    "schedule = \"{}\"\n",
                ),
                scenario_path.display(),
                schedule_path.display(),
            ),
        )
        .expect("configuration manifest");
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))
            .expect("secure configuration manifest");

        let scenario_artifact =
            encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let expected = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
            .expect("configuration artifact")
            .id()
            .expect("configuration artifact ID")
            .to_string();
        let report = validate_campaign_import_manifests(std::slice::from_ref(&manifest))
            .expect("offline configuration validation");
        assert_eq!(report.configurations(), &[expected]);
        assert!(report.generators().is_empty());
    }
}
