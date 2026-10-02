//! Command dispatch and local Nix store database realization.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::AbilityValue;
use aos_ability_runtime::activation::{Action, Invocation};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::artifact::ContentArtifactProvider;
use crate::process::ProcessStoreCommands;
#[cfg(test)]
use crate::process::argument_batches;

const DATABASE_PATH: &str = "/nix/var/nix/db/db.sqlite";
const MAX_REGISTRATION_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REGISTRATION_RECORDS: usize = 1_000_000;

/// Handles package-owned local Nix store abilities.
pub struct NixStoreProvider {
    artifacts: ContentArtifactProvider,
    database_path: PathBuf,
    commands: Box<dyn StoreCommands>,
    validate_executable_file: bool,
}

impl NixStoreProvider {
    /// Constructs the production provider for the local Nix database.
    #[must_use]
    pub fn production() -> Self {
        Self {
            artifacts: ContentArtifactProvider::production(),
            database_path: DATABASE_PATH.into(),
            commands: Box::new(ProcessStoreCommands),
            validate_executable_file: true,
        }
    }

    /// Handles one bounded command invocation and returns canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the native invocation, immutable executable,
    /// registration stream, or requested store operation is invalid or cannot
    /// complete within its supplied deadline.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            matches!(purpose, "apply" | "remove" | "observe"),
            "unknown native Nix store purpose"
        );
        let invocation: Invocation =
            aos_contract::canonical::from_slice(input, "Nix store invocation")?;
        ensure!(
            purpose == "observe" || (purpose == "apply") == (invocation.action == Action::Apply),
            "action differs from argv"
        );
        let ability = invocation
            .effect
            .identity
            .iter()
            .rev()
            .nth(2)
            .context("Nix store operation identity is missing")?;
        let result = match ability.as_str() {
            "contentAddressedObject" => self.artifacts.invoke(purpose, invocation)?,
            "nixStoreDatabase" => self.invoke_database(purpose, invocation)?,
            _ => bail!("unknown native Nix store ability"),
        };
        aos_contract::canonical::canonical_json(&result)
    }

    fn invoke_database(&self, purpose: &str, invocation: Invocation) -> Result<serde_json::Value> {
        if purpose == "observe" && invocation.action == Action::Remove {
            return Ok(json!({"status":"absent"}));
        }
        let desired: DatabaseRequest = serde_json::from_value(invocation.input.clone())?;
        validate_request(&desired)?;
        if purpose == "remove" {
            // Removing readiness never deletes a shared Nix database.
            return Ok(json!({}));
        }
        let executable = self.bundled_executable()?;
        let registration = read_registration(desired.registration.as_ref())?;
        if let (Some(input), Some(registration)) = (&desired.registration, &registration) {
            if let Some(expected) = &input.sha256 {
                ensure!(
                    *expected == registration.digest.to_string(),
                    "registration stream differs from the exact retained digest"
                );
            } else if self.validate_executable_file {
                let path = fs::canonicalize(&input.path)?;
                ensure!(
                    path.starts_with("/nix/store"),
                    "mutable registration input requires an exact retained digest"
                );
            }
        }

        let expected = ability_value(invocation.input)?;
        if purpose == "apply" {
            ensure!(
                !desired
                    .registration
                    .as_ref()
                    .is_some_and(|value| value.required)
                    || registration.is_some(),
                "required registration stream is missing"
            );
            self.apply(
                &executable,
                registration.as_ref(),
                invocation.effect.timeout_ms,
            )?;
        }
        let observation = self.observe(
            "aos.nix.store-database-observation/v1",
            &expected,
            &desired,
            &executable,
            registration.as_ref(),
            invocation.effect.timeout_ms,
        )?;
        let outputs = json!({"resource": self.database_path,"registration_digest":observation.as_json()["registration_digest"]});
        let state = observation_state(&observation);
        if purpose == "apply" {
            ensure!(
                state == Some(DatabaseState::Ready),
                "Nix database did not converge to the exact requested registration"
            );
            return Ok(outputs);
        }
        Ok(match state {
            Some(DatabaseState::Ready) => json!({"status":"current","outputs":outputs}),
            Some(DatabaseState::Absent) => json!({"status":"absent"}),
            Some(DatabaseState::Degraded) => json!({"status":"retry-safe"}),
            Some(DatabaseState::Unknown) | None => json!({"status":"indeterminate"}),
        })
    }

    fn bundled_executable(&self) -> Result<Executable> {
        let current = std::env::current_exe()?;
        let path = current
            .parent()
            .context("Nix handler has no parent")?
            .join("../libexec/nix-store");
        // Validate the resolved immutable target without losing nix-store's
        // argv[0] dispatch through the package-owned multicall symlink.
        let executable = Executable { path };
        executable.validate(self.validate_executable_file)?;
        Ok(executable)
    }

    fn observe(
        &self,
        observation_schema: &str,
        expected: &AbilityValue,
        desired: &DatabaseRequest,
        executable: &Executable,
        registration: Option<&Registration>,
        remaining_millis: u64,
    ) -> Result<AbilityValue> {
        let initialized = database_is_regular(&self.database_path)?;
        let registration_digest = registration.map(|value| value.digest.to_string());
        let (registration_state, state) = if !initialized {
            (
                registration_missing_state(desired, registration),
                DatabaseState::Absent,
            )
        } else if let Some(registration) = registration {
            match self
                .commands
                .records_match(executable, &registration.records, remaining_millis)
            {
                Ok(true) => (RegistrationState::Loaded, DatabaseState::Ready),
                Ok(false) => (RegistrationState::Partial, DatabaseState::Degraded),
                Err(_) => (RegistrationState::Unknown, DatabaseState::Unknown),
            }
        } else if desired
            .registration
            .as_ref()
            .is_some_and(|value| value.required)
        {
            (RegistrationState::Absent, DatabaseState::Degraded)
        } else {
            match self.commands.probe(executable, remaining_millis) {
                Ok(()) => (
                    registration_missing_state(desired, None),
                    DatabaseState::Ready,
                ),
                Err(_) => (RegistrationState::Unknown, DatabaseState::Unknown),
            }
        };

        ability_value(json!({
            "schema": observation_schema,
            "expected": expected.as_json(),
            "initialized": initialized,
            "registration_digest": registration_digest,
            "registration_state": registration_state,
            "state": state,
        }))
    }

    fn apply(
        &self,
        executable: &Executable,
        registration: Option<&Registration>,
        remaining_millis: u64,
    ) -> Result<()> {
        let deadline = deadline(remaining_millis)?;
        self.commands
            .initialize(executable, remaining(deadline)?)
            .context("initializing the local Nix store database")?;
        if let Some(registration) = registration {
            self.commands
                .load(executable, &registration.bytes, remaining(deadline)?)
                .context("loading the verified Nix registration stream")?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn test(database_path: PathBuf, commands: Box<dyn StoreCommands>) -> Self {
        Self {
            artifacts: ContentArtifactProvider::production(),
            database_path,
            commands,
            validate_executable_file: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum DatabaseScope {
    Local,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct DatabaseRequest {
    scope: DatabaseScope,
    #[serde(default)]
    registration: Option<RegistrationInput>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RegistrationInput {
    path: String,
    #[serde(default)]
    sha256: Option<String>,
    required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Executable {
    path: PathBuf,
}

impl Executable {
    pub(super) fn path(&self) -> PathBuf {
        self.path.clone()
    }

    fn validate(&self, inspect_file: bool) -> Result<()> {
        ensure!(
            self.path.is_absolute() && self.path.starts_with("/nix/store"),
            "Nix executable is outside immutable store"
        );
        if inspect_file {
            let resolved = fs::canonicalize(&self.path)?;
            ensure!(
                resolved.starts_with("/nix/store"),
                "Nix executable escapes immutable store"
            );
            let metadata = fs::metadata(resolved)?;
            ensure!(
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
                "nix-store is not executable"
            );
        }
        Ok(())
    }
}

struct Registration {
    bytes: Vec<u8>,
    digest: Sha256Digest,
    records: BTreeMap<String, RegistrationRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RegistrationRecord {
    path: String,
    nar_hash: String,
    nar_size: u64,
    deriver: String,
    references: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RegistrationState {
    Absent,
    Loaded,
    NotRequested,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DatabaseState {
    Absent,
    Degraded,
    Ready,
    Unknown,
}

pub(super) trait StoreCommands: Send + Sync {
    fn probe(&self, executable: &Executable, remaining_millis: u64) -> Result<()>;

    fn records_match(
        &self,
        executable: &Executable,
        expected: &BTreeMap<String, RegistrationRecord>,
        remaining_millis: u64,
    ) -> Result<bool>;

    fn initialize(&self, executable: &Executable, remaining_millis: u64) -> Result<()>;

    fn load(
        &self,
        executable: &Executable,
        registration: &[u8],
        remaining_millis: u64,
    ) -> Result<()>;
}

fn read_registration(input: Option<&RegistrationInput>) -> Result<Option<Registration>> {
    let Some(input) = input else {
        return Ok(None);
    };
    let path = Path::new(&input.path);
    ensure!(path.is_absolute(), "registration path is not absolute");
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !input.required => {
            return Ok(None);
        }
        Err(error) => return Err(error).context("inspecting Nix registration stream"),
    };
    ensure!(
        metadata.is_file(),
        "Nix registration stream is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_REGISTRATION_BYTES,
        "Nix registration stream exceeds its bound"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .context("opening Nix registration stream")?
        .take(MAX_REGISTRATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("reading Nix registration stream")?;
    ensure!(
        bytes.len() as u64 <= MAX_REGISTRATION_BYTES,
        "Nix registration stream grew beyond its bound"
    );
    let records = parse_registration(&bytes)?;
    Ok(Some(Registration {
        digest: Sha256Digest::of_bytes(&bytes),
        bytes,
        records,
    }))
}

pub(super) fn parse_registration(bytes: &[u8]) -> Result<BTreeMap<String, RegistrationRecord>> {
    let text = std::str::from_utf8(bytes).context("registration stream is not UTF-8")?;
    ensure!(
        text.is_empty() || text.ends_with('\n'),
        "registration stream has a truncated final line"
    );
    let mut lines = text.lines();
    let mut records = BTreeMap::new();
    while let Some(path) = lines.next() {
        ensure!(
            records.len() < MAX_REGISTRATION_RECORDS,
            "registration stream contains too many records"
        );
        validate_store_path(path)?;
        let nar_hash = next_line(&mut lines, "NAR hash")?;
        ensure!(
            !nar_hash.is_empty() && nar_hash.bytes().all(|byte| byte.is_ascii_graphic()),
            "registration NAR hash is invalid"
        );
        let nar_size = next_line(&mut lines, "NAR size")?
            .parse::<u64>()
            .context("registration NAR size is invalid")?;
        let deriver = next_line(&mut lines, "deriver")?;
        if !deriver.is_empty() {
            validate_store_path(deriver)?;
        }
        let reference_count = next_line(&mut lines, "reference count")?
            .parse::<usize>()
            .context("registration reference count is invalid")?;
        ensure!(
            reference_count <= MAX_REGISTRATION_RECORDS,
            "registration record contains too many references"
        );
        let mut references = Vec::with_capacity(reference_count);
        for _ in 0..reference_count {
            let reference = next_line(&mut lines, "reference")?;
            validate_store_path(reference)?;
            references.push(reference.to_string());
        }
        let record = RegistrationRecord {
            path: path.to_string(),
            nar_hash: nar_hash.to_string(),
            nar_size,
            deriver: deriver.to_string(),
            references,
        };
        ensure!(
            records.insert(path.to_string(), record).is_none(),
            "registration stream repeats a store path"
        );
    }
    Ok(records)
}

fn next_line<'a>(lines: &mut impl Iterator<Item = &'a str>, field: &str) -> Result<&'a str> {
    lines
        .next()
        .with_context(|| format!("registration stream ends before {field}"))
}

fn validate_store_path(path: &str) -> Result<()> {
    let parsed = Path::new(path);
    ensure!(
        parsed.is_absolute()
            && parsed.parent() == Some(Path::new("/nix/store"))
            && parsed.file_name().is_some_and(|name| !name.is_empty()),
        "registration contains an invalid store path"
    );
    Ok(())
}

fn validate_request(request: &DatabaseRequest) -> Result<()> {
    ensure!(
        request.scope == DatabaseScope::Local,
        "the Nix store database provider only supports the local store"
    );
    Ok(())
}

fn observation_state(observation: &AbilityValue) -> Option<DatabaseState> {
    serde_json::from_value(observation.as_json().get("state")?.clone()).ok()
}

fn registration_missing_state(
    desired: &DatabaseRequest,
    registration: Option<&Registration>,
) -> RegistrationState {
    if desired.registration.is_none() {
        RegistrationState::NotRequested
    } else if registration.is_none() {
        RegistrationState::Absent
    } else {
        RegistrationState::Unknown
    }
}

fn database_is_regular(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspecting local Nix store database"),
    }
}

pub(super) fn deadline(remaining_millis: u64) -> Result<Instant> {
    ensure!(remaining_millis > 0, "operation deadline expired");
    monotonic_now()
        .checked_add(Duration::from_millis(remaining_millis))
        .context("operation deadline overflow")
}

pub(super) fn remaining(deadline: Instant) -> Result<u64> {
    let millis = deadline
        .checked_duration_since(monotonic_now())
        .context("operation deadline expired")?
        .as_millis();
    u64::try_from(millis.max(1)).context("operation deadline is too large")
}

// Monotonic time bounds a live subprocess only; it never enters provider state.
#[allow(clippy::disallowed_methods)]
pub(super) fn monotonic_now() -> Instant {
    Instant::now()
}

pub(super) fn ability_value(value: serde_json::Value) -> Result<AbilityValue> {
    AbilityValue::new(value).context("constructing canonical ability value")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tempfile::tempdir;

    use super::*;

    const SAMPLE: &str = concat!(
        "/nix/store/00000000000000000000000000000000-root\n",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        "42\n",
        "\n",
        "1\n",
        "/nix/store/11111111111111111111111111111111-child\n",
        "/nix/store/11111111111111111111111111111111-child\n",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n",
        "21\n",
        "\n",
        "0\n",
    );

    #[derive(Default)]
    struct FakeCommands {
        records: Mutex<BTreeMap<String, RegistrationRecord>>,
        initialized: Mutex<bool>,
    }

    impl StoreCommands for FakeCommands {
        fn probe(&self, _: &Executable, _: u64) -> Result<()> {
            ensure!(
                *self.initialized.lock().map_err(lock_error)?,
                "not initialized"
            );
            Ok(())
        }

        fn records_match(
            &self,
            _: &Executable,
            expected: &BTreeMap<String, RegistrationRecord>,
            _: u64,
        ) -> Result<bool> {
            Ok(*self.records.lock().map_err(lock_error)? == *expected)
        }

        fn initialize(&self, _: &Executable, _: u64) -> Result<()> {
            *self.initialized.lock().map_err(lock_error)? = true;
            Ok(())
        }

        fn load(&self, _: &Executable, registration: &[u8], _: u64) -> Result<()> {
            *self.records.lock().map_err(lock_error)? = parse_registration(registration)?;
            Ok(())
        }
    }

    fn lock_error<T>(_: std::sync::PoisonError<T>) -> anyhow::Error {
        anyhow::anyhow!("test lock is poisoned")
    }

    #[test]
    fn registration_parser_retains_exact_database_records() {
        let records = parse_registration(SAMPLE.as_bytes()).expect("registration parses");

        assert_eq!(records.len(), 2);
        assert_eq!(records.values().next().expect("root exists").nar_size, 42);
        assert_eq!(
            records.values().next().expect("root exists").references,
            ["/nix/store/11111111111111111111111111111111-child"]
        );
    }

    #[test]
    fn registration_parser_rejects_truncation_and_duplicate_paths() {
        let truncated = SAMPLE.trim_end_matches('\n').as_bytes();
        assert!(parse_registration(truncated).is_err());

        let duplicate = format!("{SAMPLE}{SAMPLE}");
        assert!(parse_registration(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn apply_loads_the_exact_registration_before_reporting_ready() {
        let temporary = tempdir().expect("temporary directory exists");
        let registration_path = temporary.path().join("registration");
        fs::write(&registration_path, SAMPLE).expect("registration is written");
        let database_path = temporary.path().join("db.sqlite");
        fs::write(&database_path, []).expect("database marker is written");
        let desired = DatabaseRequest {
            scope: DatabaseScope::Local,
            registration: Some(RegistrationInput {
                path: registration_path.display().to_string(),
                sha256: None,
                required: true,
            }),
        };
        let registration = read_registration(desired.registration.as_ref())
            .expect("registration can be read")
            .expect("registration exists");
        let expected = ability_value(
            serde_json::to_value(json!({
                "scope": "local",
                "registration": {
                    "path": registration_path,
                    "required": true,
                },
            }))
            .expect("request serializes"),
        )
        .expect("request is bounded");
        let executable = Executable {
            path: "/nix/store/00000000000000000000000000000000-nix/bin/nix-store".into(),
        };
        let provider = NixStoreProvider::test(
            database_path,
            Box::new(FakeCommands {
                initialized: Mutex::new(true),
                ..FakeCommands::default()
            }),
        );

        let before = provider
            .observe(
                "aos.test.nix-store-observation/v1",
                &expected,
                &desired,
                &executable,
                Some(&registration),
                1_000,
            )
            .expect("initial state observes");
        assert_eq!(observation_state(&before), Some(DatabaseState::Degraded));

        provider
            .apply(&executable, Some(&registration), 1_000)
            .expect("registration loads");
        let after = provider
            .observe(
                "aos.test.nix-store-observation/v1",
                &expected,
                &desired,
                &executable,
                Some(&registration),
                1_000,
            )
            .expect("loaded state observes");
        assert_eq!(observation_state(&after), Some(DatabaseState::Ready));
    }

    #[test]
    fn argument_batches_bound_process_argv() {
        let paths = (0..1_100)
            .map(|index| format!("/nix/store/{index:032}-package"))
            .collect::<Vec<_>>();
        let batches = argument_batches(paths.iter().map(String::as_str));

        assert_eq!(batches.len(), 3);
        assert!(batches.iter().all(|batch| batch.len() <= 512));
        assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), paths.len());
    }
}
