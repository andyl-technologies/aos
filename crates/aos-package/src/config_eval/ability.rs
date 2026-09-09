//! Restricted evaluation of authenticated Nix ability entry points.
//!
//! The adapter selects a declared composition or transition function from one
//! fixed-NAR artifact, supplies one bounded JSON argument, and accepts only a
//! bounded JSON result. It invokes stock Nix behind explicit CPU, address-space,
//! wall-clock, stdout, and stderr limits. The expression rejects functions,
//! derivations, paths, and context-bearing strings before serialization.

use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, ArtifactReference, ImplementationKind, LocalKey,
    ProviderImplementation, ProviderImplementationReference,
};
use aos_ability_plan::{CompositionEvaluator, EvaluationError};
use base64::Engine as _;
use serde::de::DeserializeOwned;

use super::stock::{locked_store_input, nix_string, store_root_and_suffix};

static EVALUATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod reference_composition;

/// Selects one of the two pure functions declared by a provider implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbilityEntryPoint {
    /// Expands a provider request into finite child requests and resources.
    Compose,
    /// Constructs a finite transition graph from exact current and desired state.
    Transition,
}

/// Bounds one stock-Nix ability evaluation independently of its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbilityEvaluationLimits {
    /// Limits elapsed wall-clock time, including process startup and pipe I/O.
    pub wall_time: Duration,
    /// Limits CPU time through the process resource limit, in whole seconds.
    pub cpu_seconds: u64,
    /// Limits the evaluator's virtual address space in bytes.
    pub address_space_bytes: u64,
    /// Limits the generated expression written to the evaluator.
    pub expression_bytes: usize,
    /// Limits JSON bytes read from standard output.
    pub stdout_bytes: usize,
    /// Limits diagnostic bytes read from standard error.
    pub stderr_bytes: usize,
}

impl Default for AbilityEvaluationLimits {
    fn default() -> Self {
        Self {
            wall_time: Duration::from_secs(30),
            cpu_seconds: 15,
            address_space_bytes: 1024 * 1024 * 1024,
            expression_bytes: 34 * 1024 * 1024,
            stdout_bytes: ABILITY_LIMITS_V1.max_document_bytes as usize,
            stderr_bytes: 1024 * 1024,
        }
    }
}

impl AbilityEvaluationLimits {
    fn validate(self) -> Result<Self> {
        ensure!(
            !self.wall_time.is_zero(),
            "ability evaluation wall-time limit must be nonzero"
        );
        ensure!(
            self.cpu_seconds > 0,
            "ability evaluation CPU limit must be nonzero"
        );
        ensure!(
            self.address_space_bytes > 0,
            "ability evaluation address-space limit must be nonzero"
        );
        ensure!(
            self.expression_bytes > 0,
            "ability expression byte limit must be nonzero"
        );
        ensure!(
            self.stdout_bytes > 0,
            "ability stdout byte limit must be nonzero"
        );
        ensure!(
            self.stderr_bytes > 0,
            "ability stderr byte limit must be nonzero"
        );
        ensure!(
            self.stdout_bytes <= ABILITY_LIMITS_V1.max_document_bytes as usize,
            "ability stdout limit exceeds the version-1 document limit"
        );
        Ok(self)
    }
}

/// Evaluates exact ability modules with stock Nix and local resource limits.
pub struct RestrictedAbilityEvaluator {
    nix_instantiate: PathBuf,
    prlimit: PathBuf,
    nix_cache_home: PathBuf,
    limits: AbilityEvaluationLimits,
}

impl RestrictedAbilityEvaluator {
    /// Creates an evaluator from exact executable and caller-owned cache paths.
    ///
    /// The `prlimit` executable must implement the util-linux command-line
    /// contract. AOS packages provide it as `${pkgs.util-linux}/bin/prlimit`.
    /// The caller must keep the cache path outside every provider-writable
    /// domain because it also holds the evaluator's trusted Nix configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when a resource or byte limit is zero, or when the
    /// stdout limit exceeds the ability document ceiling.
    pub fn new(
        nix_instantiate: impl Into<PathBuf>,
        prlimit: impl Into<PathBuf>,
        nix_cache_home: impl Into<PathBuf>,
        limits: AbilityEvaluationLimits,
    ) -> Result<Self> {
        Ok(Self {
            nix_instantiate: nix_instantiate.into(),
            prlimit: prlimit.into(),
            nix_cache_home: nix_cache_home.into(),
            limits: limits.validate()?,
        })
    }

    /// Evaluates one declared provider entry point and decodes its typed result.
    ///
    /// The implementation artifact is admitted by its fixed NAR hash. Only its
    /// exact store root is present in `allowed-uris`; other store objects,
    /// network locations, ambient environment values, host paths, builds, and
    /// import-from-derivation are unavailable to the evaluator.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider is terminal, the artifact or limits
    /// are invalid, Nix fails or exceeds a resource limit, output is not closed
    /// context-free JSON, or the result does not decode as `T` within the
    /// version-1 ability limits.
    pub fn evaluate<T>(
        &self,
        implementation: &ProviderImplementation,
        selected: AbilityEntryPoint,
        arguments: &AbilityValue,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        ensure!(
            implementation.artifact.store_path.len() <= ABILITY_LIMITS_V1.max_string_bytes as usize,
            "ability artifact store path exceeds the version-1 string limit"
        );
        let entry = selected_entry(implementation, selected)?;
        let implementation = ProviderImplementationReference {
            descriptor: implementation.descriptor_digest()?,
            artifact: implementation.artifact.clone(),
            handler: None,
        };

        self.evaluate_reference(&implementation, entry, arguments)
    }

    /// Evaluates one exact pure implementation reference and declared entry.
    ///
    /// This is the planner-facing boundary after package validation has
    /// resolved the implementation descriptor and entry name independently.
    /// The reference must identify a pure Nix implementation rather than a
    /// terminal handler.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference names a terminal handler, the
    /// artifact or limits are invalid, Nix fails or exceeds a resource limit,
    /// output is not closed context-free JSON, or the result does not decode as
    /// `T` within the version-1 ability limits.
    pub fn evaluate_reference<T>(
        &self,
        implementation: &ProviderImplementationReference,
        entry: &LocalKey,
        arguments: &AbilityValue,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        ensure!(
            implementation.handler.is_none(),
            "terminal provider implementation references have no Nix ability entry point"
        );
        ensure!(
            implementation.artifact.store_path.len() <= ABILITY_LIMITS_V1.max_string_bytes as usize,
            "ability artifact store path exceeds the version-1 string limit"
        );
        let root = store_root_and_suffix(Path::new(&implementation.artifact.store_path))?.0;
        let allowed_uri = artifact_allowed_uri(&root, &implementation.artifact.nar_hash)?;
        let expression = render_expression(&implementation.artifact, entry, arguments)?;
        ensure!(
            expression.len() <= self.limits.expression_bytes,
            "ability expression exceeds the {} byte limit",
            self.limits.expression_bytes
        );

        let environment = self.create_evaluation_environment()?;
        let mut command = self.command(&allowed_uri, &environment);
        let output = run_bounded(&mut command, expression.into_bytes(), self.limits)
            .context("running restricted Nix ability evaluation")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "restricted Nix ability evaluation failed with {}: {}",
                output.status,
                stderr.trim()
            );
        }

        let json_limits = aos_contract::limits::JsonLimits {
            max_bytes: self.limits.stdout_bytes,
            max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize,
            max_items: ABILITY_LIMITS_V1.max_collection_items as usize,
            max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
        };
        let value = json_limits.decode(&output.stdout, "Nix ability result")?;
        let canonical =
            AbilityValue::new(value).context("validating the canonical Nix ability result")?;

        serde_json::from_value(canonical.into_json())
            .context("decoding the typed Nix ability result")
    }

    fn create_evaluation_environment(&self) -> Result<EvaluationEnvironment> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.nix_cache_home)
            .with_context(|| {
                format!(
                    "creating ability evaluator state root {}",
                    self.nix_cache_home.display()
                )
            })?;

        let root = loop {
            let sequence = EVALUATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let candidate = self
                .nix_cache_home
                .join(format!("evaluation-{}-{sequence}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("creating private evaluator state {}", candidate.display())
                    });
                }
            }
        };

        let environment = EvaluationEnvironment::new(root)?;
        for directory in [
            &environment.home,
            &environment.cache,
            &environment.config,
            &environment.data,
            &environment.state,
        ] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(directory)
                .with_context(|| {
                    format!(
                        "creating private evaluator directory {}",
                        directory.display()
                    )
                })?;
        }
        std::fs::write(
            &environment.config_file,
            b"plugin-files =\nallow-unsafe-native-code-during-evaluation = false\nsubstituters =\n",
        )
        .with_context(|| {
            format!(
                "writing restricted Nix configuration {}",
                environment.config_file.display()
            )
        })?;
        Ok(environment)
    }

    fn command(&self, allowed_uri: &str, environment: &EvaluationEnvironment) -> Command {
        let mut command = Command::new(&self.prlimit);
        // Register derivation metadata in the disposable private store so the
        // explicit IFD prohibition, rather than an incidental invalid-path
        // error, remains the effect boundary.
        command
            .arg(format!("--as={}", self.limits.address_space_bytes))
            .arg(format!("--cpu={}", self.limits.cpu_seconds))
            .arg("--core=0")
            .arg("--")
            .arg(&self.nix_instantiate)
            .args(["--store", environment.store_uri.as_str()])
            .arg("--read-write-mode")
            .args(["--extra-experimental-features", "nix-command flakes"])
            .args(["--eval", "--strict", "--json", "--pure-eval"])
            .args(["--option", "restrict-eval", "true"])
            .args(["--option", "allow-import-from-derivation", "false"])
            .args([
                "--option",
                "allow-unsafe-native-code-during-evaluation",
                "false",
            ])
            .args(["--option", "plugin-files", ""])
            .args(["--option", "substituters", ""])
            .args(["--option", "allowed-uris"])
            .arg(allowed_uri)
            .env_clear()
            .env("HOME", &environment.home)
            .env("XDG_CACHE_HOME", &environment.cache)
            .env("XDG_CONFIG_HOME", &environment.config)
            .env("XDG_DATA_HOME", &environment.data)
            .env("XDG_STATE_HOME", &environment.state)
            .env("NIX_CONF_DIR", &environment.config)
            .env("NIX_USER_CONF_FILES", &environment.config_file);
        command.arg("-");
        command
    }
}

/// Owns the private home and XDG roots for one evaluator subprocess.
///
/// Nix initializes mutable fallback-store state below these paths. Keeping
/// them invocation-local prevents parallel pure evaluations from racing while
/// creating profiles and roots. Dropping the environment releases all of that
/// ephemeral state after the subprocess has been reaped.
struct EvaluationEnvironment {
    root: PathBuf,
    home: PathBuf,
    cache: PathBuf,
    config: PathBuf,
    config_file: PathBuf,
    data: PathBuf,
    state: PathBuf,
    store_uri: String,
}

impl EvaluationEnvironment {
    fn new(root: PathBuf) -> Result<Self> {
        let home = root.join("home");
        let cache = root.join("cache");
        let config = root.join("config");
        let config_file = config.join("nix.conf");
        let data = root.join("data");
        let state = root.join("state");
        let store_root = root.join("store");
        let store_root = store_root
            .to_str()
            .context("private ability evaluator store path is not UTF-8")?;
        let store_uri = format!(
            "local?root={}",
            encode_nix_uri_component(store_root, b":@/")
        );

        Ok(Self {
            root,
            home,
            cache,
            config,
            config_file,
            data,
            state,
            store_uri,
        })
    }
}

impl Drop for EvaluationEnvironment {
    fn drop(&mut self) {
        let _ = remove_private_tree(&self.root);
    }
}

/// Removes one evaluator-owned tree without following symlinks.
///
/// Nix can create read-only state directories in its fallback chroot. The
/// adapter restores owner access only on directories created below its unique
/// private root. It never changes file modes, so a hard-linked store file
/// cannot cause a permission change outside the evaluator tree.
fn remove_private_tree(path: &Path) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_dir() {
        return std::fs::remove_file(path);
    }

    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)?;
    for entry in std::fs::read_dir(path)? {
        remove_private_tree(&entry?.path())?;
    }
    std::fs::remove_dir(path)
}

impl CompositionEvaluator for RestrictedAbilityEvaluator {
    fn evaluate(
        &mut self,
        implementation: &ProviderImplementationReference,
        entry: &LocalKey,
        input: &AbilityValue,
    ) -> std::result::Result<AbilityValue, EvaluationError> {
        self.evaluate_reference(implementation, entry, input)
            .map_err(|error| EvaluationError::new(bounded_error_message(&error)))
    }
}

fn bounded_error_message(error: &anyhow::Error) -> String {
    let mut message = format!("{error:#}");
    let limit = ABILITY_LIMITS_V1.max_string_bytes as usize;
    if message.len() <= limit {
        return message;
    }

    let mut boundary = limit;
    while !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message.truncate(boundary);
    message
}

fn artifact_allowed_uri(root: &Path, nar_hash: &aos_contract::Sha256Digest) -> Result<String> {
    let root = root
        .to_str()
        .context("ability artifact store root is not UTF-8")?;
    let sri = format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(nar_hash.as_bytes())
    );

    Ok(format!(
        "path:{}?narHash={}",
        encode_nix_uri_component(root, b":@/"),
        encode_nix_uri_component(&sri, b":@/?")
    ))
}

fn encode_nix_uri_component(value: &str, additionally_allowed: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || b"-._~".contains(&byte)
            || additionally_allowed.contains(&byte)
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;

            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn selected_entry(
    implementation: &ProviderImplementation,
    selected: AbilityEntryPoint,
) -> Result<&LocalKey> {
    let ImplementationKind::PureComposition {
        compose_entry,
        transition_entry,
    } = &implementation.implementation
    else {
        bail!("terminal provider implementations have no Nix ability entry point");
    };

    Ok(match selected {
        AbilityEntryPoint::Compose => compose_entry,
        AbilityEntryPoint::Transition => transition_entry,
    })
}

fn render_expression(
    artifact: &ArtifactReference,
    entry: &LocalKey,
    arguments: &AbilityValue,
) -> Result<String> {
    let artifact_input = locked_store_input(
        Path::new(&artifact.store_path),
        Some(&artifact.nar_hash.to_string()),
    )?;
    let argument_json = aos_contract::canonical::to_vec(arguments.as_json())
        .context("encoding Nix ability arguments")?;
    let argument_json =
        std::str::from_utf8(&argument_json).context("canonical ability arguments are not UTF-8")?;

    Ok(format!(
        "let\n\
         \x20 module = import {artifact_input};\n\
         \x20 entryName = {};\n\
         \x20 entry =\n\
         \x20   if !builtins.isAttrs module then\n\
         \x20     throw \"ability module must evaluate to an attribute set\"\n\
         \x20   else if !builtins.hasAttr entryName module then\n\
         \x20     throw \"ability module does not contain its declared entry point\"\n\
         \x20   else builtins.getAttr entryName module;\n\
         \x20 arguments = builtins.fromJSON {};\n\
         \x20 rejectImpure = depth: value:\n\
         \x20   if depth > {} then\n\
         \x20     throw \"ability result exceeds the structural depth limit\"\n\
         \x20   else if builtins.isFunction value then\n\
         \x20     throw \"ability result contains a function\"\n\
         \x20   else if builtins.typeOf value == \"path\" then\n\
         \x20     throw \"ability result contains a Nix path\"\n\
         \x20   else if builtins.isString value && builtins.hasContext value then\n\
         \x20     throw \"ability result contains a context-bearing string\"\n\
         \x20   else if builtins.isAttrs value then\n\
         \x20     if value ? type && value.type == \"derivation\" then\n\
         \x20       throw \"ability result contains a derivation\"\n\
         \x20     else builtins.mapAttrs (_: rejectImpure (depth + 1)) value\n\
         \x20   else if builtins.isList value then\n\
         \x20     builtins.map (rejectImpure (depth + 1)) value\n\
         \x20   else if value == null || builtins.isBool value || builtins.isInt value || builtins.isString value then\n\
         \x20     value\n\
         \x20   else throw \"ability result contains an unsupported Nix value\";\n\
         \x20 result =\n\
         \x20   if !builtins.isFunction entry then\n\
         \x20     throw \"declared ability entry point must be a function\"\n\
         \x20   else rejectImpure 1 (entry arguments);\n\
         in builtins.deepSeq result result\n",
        nix_string(entry.as_str()),
        nix_string(argument_json),
        ABILITY_LIMITS_V1.max_structural_depth,
    ))
}

struct BoundedProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
enum PumpEvent {
    Limit(&'static str),
    ReadError(&'static str, io::Error),
}

fn run_bounded(
    command: &mut Command,
    expression: Vec<u8>,
    limits: AbilityEvaluationLimits,
) -> Result<BoundedProcessOutput> {
    let deadline = Instant::now()
        .checked_add(limits.wall_time)
        .context("ability evaluation wall-time deadline is not representable")?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = KillAndReapChild(command.spawn().context("spawning bounded evaluator")?);
    let stdin = child
        .0
        .stdin
        .take()
        .context("bounded evaluator has no stdin")?;
    let stdout = child
        .0
        .stdout
        .take()
        .context("bounded evaluator has no stdout")?;
    let stderr = child
        .0
        .stderr
        .take()
        .context("bounded evaluator has no stderr")?;

    let (events, received_events) = mpsc::channel();
    let stdout_events = events.clone();
    let stdout_thread = thread::Builder::new()
        .name("ability-eval-stdout".to_string())
        .spawn(move || read_bounded(stdout, limits.stdout_bytes, "stdout", stdout_events))
        .context("starting ability evaluator stdout worker")?;
    let stderr_events = events.clone();
    let stderr_thread = thread::Builder::new()
        .name("ability-eval-stderr".to_string())
        .spawn(move || read_bounded(stderr, limits.stderr_bytes, "stderr", stderr_events))
        .context("starting ability evaluator stderr worker")?;
    drop(events);
    let stdin_thread = thread::Builder::new()
        .name("ability-eval-stdin".to_string())
        .spawn(move || write_expression(stdin, expression))
        .context("starting ability evaluator stdin worker")?;
    let mut primary_error = None;
    let status = loop {
        if let Ok(event) = received_events.try_recv() {
            primary_error = Some(match event {
                PumpEvent::Limit(stream) => {
                    anyhow!("ability evaluation {stream} exceeds its configured byte limit")
                }
                PumpEvent::ReadError(stream, error) => {
                    anyhow!(error).context(format!("reading ability evaluation {stream}"))
                }
            });
            let _ = child.0.kill();
            break child.0.wait().context("reaping bounded evaluator")?;
        }

        if let Some(status) = child.0.try_wait().context("polling bounded evaluator")? {
            break status;
        }
        if Instant::now() >= deadline {
            primary_error = Some(anyhow!(
                "ability evaluation exceeded its {:?} wall-time limit",
                limits.wall_time
            ));
            let _ = child.0.kill();
            break child.0.wait().context("reaping timed-out evaluator")?;
        }
        thread::sleep(Duration::from_millis(5));
    };

    let stdin_result = stdin_thread
        .join()
        .map_err(|_| anyhow!("ability evaluator stdin worker panicked"))?;
    let stdout = stdout_thread
        .join()
        .map_err(|_| anyhow!("ability evaluator stdout worker panicked"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| anyhow!("ability evaluator stderr worker panicked"))??;

    if primary_error.is_none()
        && let Ok(event) = received_events.try_recv()
    {
        primary_error = Some(match event {
            PumpEvent::Limit(stream) => {
                anyhow!("ability evaluation {stream} exceeds its configured byte limit")
            }
            PumpEvent::ReadError(stream, error) => {
                anyhow!(error).context(format!("reading ability evaluation {stream}"))
            }
        });
    }
    if let Some(error) = primary_error {
        return Err(error);
    }
    if status.success() {
        stdin_result.context("writing bounded ability expression")?;
    }
    Ok(BoundedProcessOutput {
        status,
        stdout,
        stderr,
    })
}

/// Kills and reaps an evaluator when an I/O or polling error returns early.
///
/// Pure evaluation, disabled IFD and native evaluation, an empty plugin set,
/// and the exact path-fetch URI expose no process-spawning evaluator primitive.
/// The evaluator process therefore owns every pipe for this invocation.
struct KillAndReapChild(Child);

impl Drop for KillAndReapChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn write_expression(mut stdin: impl Write, expression: Vec<u8>) -> io::Result<()> {
    stdin.write_all(&expression)
}

fn read_bounded(
    mut reader: impl Read,
    limit: usize,
    stream: &'static str,
    events: Sender<PumpEvent>,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0_u8; 8192];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) => {
                let _ = events.send(PumpEvent::ReadError(
                    stream,
                    io::Error::new(error.kind(), error.to_string()),
                ));
                return Err(error);
            }
        };
        if count == 0 {
            return Ok(output);
        }

        let remaining = limit.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            let _ = events.send(PumpEvent::Limit(stream));
            return Ok(output);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io::Cursor;

    use aos_ability_model::{InterfaceKey, InterfaceName, RequirementDeclaration};
    use aos_contract::Sha256Digest;
    use serde::Deserialize;

    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn implementation() -> ProviderImplementation {
        implementation_at(
            "/nix/store/00000000000000000000000000000000-provider",
            digest(3),
        )
    }

    fn implementation_at(store_path: &str, nar_hash: Sha256Digest) -> ProviderImplementation {
        ProviderImplementation {
            interface: InterfaceKey {
                name: InterfaceName::new("aos.test.provider").unwrap(),
                abi: 1.try_into().unwrap(),
                descriptor: digest(1),
            },
            artifact: ArtifactReference {
                content: digest(2),
                store_path: store_path.to_string(),
                nar_hash,
                closure: digest(4),
            },
            requirements: Vec::<RequirementDeclaration>::new(),
            implementation: ImplementationKind::PureComposition {
                compose_entry: LocalKey::new("compose").unwrap(),
                transition_entry: LocalKey::new("transition").unwrap(),
            },
            owns_resource_kinds: Vec::new(),
        }
    }

    fn arguments() -> AbilityValue {
        AbilityValue::new(serde_json::json!({"enabled": true})).unwrap()
    }

    #[test]
    fn expression_pins_artifact_and_selects_exact_entry() {
        let entry = LocalKey::new("compose").unwrap();
        let expression =
            render_expression(&implementation().artifact, &entry, &arguments()).unwrap();

        assert!(expression.contains("builtins.fetchTree"), "{expression}");
        assert!(expression.contains("narHash = \"sha256-"), "{expression}");
        assert!(
            expression.contains("entryName = \"compose\""),
            "{expression}"
        );
        assert!(expression.contains("builtins.fromJSON \"{\\\"enabled\\\":true}\""));
        assert!(expression.contains("builtins.hasContext"), "{expression}");
        assert!(expression.contains("contains a derivation"), "{expression}");
    }

    #[test]
    fn artifact_uri_matches_nix_path_and_query_encoding() {
        let uri = artifact_allowed_uri(
            Path::new("/nix/store/00000000000000000000000000000000-provider?+="),
            &digest(3),
        )
        .unwrap();

        assert!(uri.starts_with(
            "path:/nix/store/00000000000000000000000000000000-provider%3F%2B%3D?narHash="
        ));
        assert!(uri.ends_with("%3D"));
    }

    #[test]
    fn command_uses_exact_fixed_nar_uri_and_resource_limits() {
        let evaluator = RestrictedAbilityEvaluator::new(
            "/aos/nix-instantiate",
            "/aos/prlimit",
            "/var/cache/aos/ability-eval",
            AbilityEvaluationLimits::default(),
        )
        .unwrap();
        let allowed_uri = artifact_allowed_uri(
            Path::new("/nix/store/00000000000000000000000000000000-provider"),
            &digest(3),
        )
        .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let environment_root = temporary.path().join("owned-evaluation");
        std::fs::create_dir(&environment_root).unwrap();
        let expected_store = format!("local?root={}/store", environment_root.to_string_lossy());
        let environment = EvaluationEnvironment::new(environment_root.clone()).unwrap();
        let command = evaluator.command(&allowed_uri, &environment);
        let arguments = command
            .get_args()
            .map(OsStr::to_string_lossy)
            .collect::<Vec<_>>();

        assert_eq!(command.get_program(), OsStr::new("/aos/prlimit"));
        assert!(arguments.iter().any(|value| value == "--as=1073741824"));
        assert!(arguments.iter().any(|value| value == "--cpu=15"));
        assert!(arguments.iter().any(|value| value == "--pure-eval"));
        assert!(arguments.iter().any(|value| value == "--read-write-mode"));
        assert!(arguments.iter().any(|value| value == &allowed_uri));
        assert!(allowed_uri.contains("?narHash=sha256-"));
        assert!(!arguments.iter().any(|value| value == "path:/nix/store/"));
        assert!(arguments.windows(3).any(|values| {
            values
                == [
                    "--option",
                    "allow-unsafe-native-code-during-evaluation",
                    "false",
                ]
        }));
        assert!(
            arguments
                .windows(3)
                .any(|values| values == ["--option", "plugin-files", ""])
        );
        assert!(
            arguments
                .windows(3)
                .any(|values| values == ["--option", "substituters", ""])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--store", &expected_store])
        );
        assert!(!arguments.iter().any(|value| value == "daemon"));
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == "XDG_CACHE_HOME"),
            Some((
                OsStr::new("XDG_CACHE_HOME"),
                Some(environment.cache.as_os_str())
            ))
        );
        assert_eq!(
            command.get_envs().find(|(name, _)| *name == "NIX_CONF_DIR"),
            Some((
                OsStr::new("NIX_CONF_DIR"),
                Some(environment.config.as_os_str())
            ))
        );
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == "XDG_DATA_HOME"),
            Some((
                OsStr::new("XDG_DATA_HOME"),
                Some(environment.data.as_os_str())
            ))
        );

        drop(command);
        drop(environment);
        assert!(!environment_root.exists());
    }

    #[test]
    fn bounded_reader_never_retains_bytes_past_limit() {
        let (events, received_events) = mpsc::channel();
        let output = read_bounded(Cursor::new(vec![b'x'; 32]), 8, "stdout", events).unwrap();

        assert_eq!(output, vec![b'x'; 8]);
        assert!(matches!(
            received_events.recv().unwrap(),
            PumpEvent::Limit("stdout")
        ));
    }

    #[test]
    fn invalid_limits_fail_before_process_creation() {
        let limits = AbilityEvaluationLimits {
            wall_time: Duration::ZERO,
            ..AbilityEvaluationLimits::default()
        };
        let error = RestrictedAbilityEvaluator::new("nix", "prlimit", "cache", limits)
            .err()
            .unwrap();

        assert!(
            error
                .to_string()
                .contains("wall-time limit must be nonzero")
        );
    }

    #[test]
    fn private_tree_cleanup_handles_read_only_directories_without_following_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let owned = temporary.path().join("owned");
        let read_only = owned.join("read-only");
        let external = temporary.path().join("external");
        std::fs::create_dir_all(&read_only).unwrap();
        std::fs::create_dir(&external).unwrap();
        std::fs::write(external.join("retained"), b"outside").unwrap();
        std::os::unix::fs::symlink(&external, read_only.join("external-link")).unwrap();
        std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o555)).unwrap();

        remove_private_tree(&owned).unwrap();

        assert!(!owned.exists());
        assert_eq!(
            std::fs::read(external.join("retained")).unwrap(),
            b"outside"
        );
    }

    #[test]
    fn planner_error_messages_respect_the_versioned_string_bound() {
        let oversized = format!(
            "{}é",
            "x".repeat(ABILITY_LIMITS_V1.max_string_bytes as usize)
        );
        let error = anyhow!(oversized);

        let message = bounded_error_message(&error);

        assert!(message.len() <= ABILITY_LIMITS_V1.max_string_bytes as usize);
        assert!(message.is_char_boundary(message.len()));
    }

    #[test]
    fn terminal_implementations_cannot_select_nix_entries() {
        let mut implementation = implementation();
        implementation.implementation = ImplementationKind::TerminalHandler {
            handler: LocalKey::new("native").unwrap(),
        };

        assert!(selected_entry(&implementation, AbilityEntryPoint::Compose).is_err());
    }

    #[test]
    fn oversized_artifact_path_fails_before_process_creation() {
        let evaluator = RestrictedAbilityEvaluator::new(
            "missing-nix-instantiate",
            "missing-prlimit",
            "missing-cache",
            AbilityEvaluationLimits::default(),
        )
        .unwrap();
        let mut implementation = implementation();
        implementation.artifact.store_path =
            "x".repeat(ABILITY_LIMITS_V1.max_string_bytes as usize + 1);

        let error = evaluator
            .evaluate::<serde_json::Value>(
                &implementation,
                AbilityEntryPoint::Compose,
                &arguments(),
            )
            .unwrap_err();

        assert!(error.to_string().contains("artifact store path"));
    }

    #[test]
    fn malformed_or_traversing_artifact_path_fails_before_process_creation() {
        let evaluator = RestrictedAbilityEvaluator::new(
            "missing-nix-instantiate",
            "missing-prlimit",
            "missing-cache",
            AbilityEvaluationLimits::default(),
        )
        .unwrap();
        let rejected_paths = [
            "/nix/store/../etc/hostname",
            "/nix/store/00000000000000000000000000000000-provider/../other",
            "/nix/store/not-a-store-path/default.nix",
        ];

        for path in rejected_paths {
            let mut implementation = implementation();
            implementation.artifact.store_path = path.to_string();
            let error = evaluator
                .evaluate::<serde_json::Value>(
                    &implementation,
                    AbilityEntryPoint::Compose,
                    &arguments(),
                )
                .unwrap_err();

            assert!(
                error.to_string().contains("evaluator input"),
                "path {path:?} failed for the wrong reason: {error:#}"
            );
        }
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct EnabledResult {
        enabled: bool,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct EnvironmentResult {
        observed: String,
    }

    fn real_fixture() -> Result<Option<(RestrictedAbilityEvaluator, ProviderImplementation, String)>>
    {
        if std::env::var("AOS_TEST_ABILITY_EVALUATOR_DISABLED").as_deref() == Ok("1") {
            return Ok(None);
        }

        const REQUIRED_ENVIRONMENT: [&str; 7] = [
            "AOS_NIX_INSTANTIATE",
            "AOS_PRLIMIT",
            "AOS_TEST_ABILITY_CACHE",
            "AOS_TEST_ABILITY_FIXTURE",
            "AOS_TEST_ABILITY_FIXTURE_NAR_HASH",
            "AOS_TEST_ABILITY_IFD_DERIVATION",
            "AOS_TEST_ABILITY_IFD_SYSTEM",
        ];
        if REQUIRED_ENVIRONMENT
            .iter()
            .all(|name| std::env::var_os(name).is_none())
        {
            return Ok(None);
        }

        let required = |name: &str| {
            std::env::var(name).with_context(|| format!("reading required test variable {name}"))
        };
        let nix_instantiate = required("AOS_NIX_INSTANTIATE")?;
        let prlimit = required("AOS_PRLIMIT")?;
        let cache = required("AOS_TEST_ABILITY_CACHE")?;
        let fixture = required("AOS_TEST_ABILITY_FIXTURE")?;
        let nar_hash = Sha256Digest::parse(&required("AOS_TEST_ABILITY_FIXTURE_NAR_HASH")?)
            .context("parsing AOS_TEST_ABILITY_FIXTURE_NAR_HASH")?;
        let evaluator = RestrictedAbilityEvaluator::new(
            &nix_instantiate,
            prlimit,
            cache,
            AbilityEvaluationLimits::default(),
        )?;

        Ok(Some((
            evaluator,
            implementation_at(&fixture, nar_hash),
            nix_instantiate,
        )))
    }

    fn fixture_arguments(mode: &str, executable: &str) -> AbilityValue {
        let ifd_derivation = std::env::var("AOS_TEST_ABILITY_IFD_DERIVATION").unwrap();
        let ifd_system = std::env::var("AOS_TEST_ABILITY_IFD_SYSTEM").unwrap();
        AbilityValue::new(serde_json::json!({
            "builder": executable,
            "enabled": true,
            "ifd_derivation": ifd_derivation,
            "ifd_system": ifd_system,
            "mode": mode,
            "outside_path": executable,
        }))
        .unwrap()
    }

    #[test]
    fn real_nix_fixture_accepts_closed_json_and_hides_environment() {
        let Some((evaluator, implementation, executable)) = real_fixture().unwrap() else {
            return;
        };

        let result: EnabledResult = evaluator
            .evaluate(
                &implementation,
                AbilityEntryPoint::Compose,
                &fixture_arguments("ok", &executable),
            )
            .unwrap();
        assert_eq!(result, EnabledResult { enabled: true });

        assert!(std::env::var_os("AOS_ABILITY_EVALUATOR_SECRET").is_some());
        let result: EnvironmentResult = evaluator
            .evaluate(
                &implementation,
                AbilityEntryPoint::Compose,
                &fixture_arguments("environment", &executable),
            )
            .unwrap();
        assert_eq!(
            result,
            EnvironmentResult {
                observed: String::new(),
            }
        );
    }

    #[test]
    fn real_nix_fixture_isolates_parallel_fallback_store_initialization() {
        let Some((evaluator, implementation, executable)) = real_fixture().unwrap() else {
            return;
        };

        thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..4 {
                workers.push(scope.spawn(|| {
                    evaluator.evaluate::<EnabledResult>(
                        &implementation,
                        AbilityEntryPoint::Compose,
                        &fixture_arguments("ok", &executable),
                    )
                }));
            }

            for worker in workers {
                assert_eq!(
                    worker.join().unwrap().unwrap(),
                    EnabledResult { enabled: true }
                );
            }
        });
    }

    #[test]
    fn real_nix_fixture_removes_private_state_after_success_and_failure() {
        let Some((base, implementation, executable)) = real_fixture().unwrap() else {
            return;
        };
        let temporary = tempfile::tempdir().unwrap();
        let cache = temporary.path().join("ability-evaluator");
        let evaluator = RestrictedAbilityEvaluator::new(
            base.nix_instantiate,
            base.prlimit,
            &cache,
            AbilityEvaluationLimits::default(),
        )
        .unwrap();

        evaluator
            .evaluate::<EnabledResult>(
                &implementation,
                AbilityEntryPoint::Compose,
                &fixture_arguments("ok", &executable),
            )
            .unwrap();
        assert!(std::fs::read_dir(&cache).unwrap().next().is_none());

        evaluator
            .evaluate::<serde_json::Value>(
                &implementation,
                AbilityEntryPoint::Transition,
                &fixture_arguments("host-file", &executable),
            )
            .unwrap_err();
        assert!(std::fs::read_dir(&cache).unwrap().next().is_none());
    }

    #[test]
    fn real_nix_fixture_rejects_impure_and_runtime_values() {
        let Some((evaluator, implementation, executable)) = real_fixture().unwrap() else {
            return;
        };
        let rejected_modes = [
            ("host-file", "forbidden in pure evaluation mode"),
            ("outside-store", "forbidden in pure evaluation mode"),
            (
                "network",
                "URI 'https://example.invalid/aos-ability-evaluator' is forbidden",
            ),
            ("time", "currentTime"),
            ("path-result", "contains a Nix path"),
            ("context-result", "context-bearing string"),
            ("function-result", "contains a function"),
            ("derivation-result", "contains a derivation"),
            ("ifd", "option 'allow-import-from-derivation' is disabled"),
            ("native-exec", "attribute 'exec' missing"),
            ("native-import", "attribute 'importNative' missing"),
            ("non-ascii-key", "canonical JSON dialect"),
            ("unsafe-integer", "canonical JSON dialect"),
        ];

        for (mode, expected) in rejected_modes {
            let error = evaluator
                .evaluate::<serde_json::Value>(
                    &implementation,
                    AbilityEntryPoint::Transition,
                    &fixture_arguments(mode, &executable),
                )
                .unwrap_err();
            let chain = format!("{error:#}");
            assert!(
                chain.contains(expected),
                "fixture mode '{mode}' failed for the wrong reason: {chain}"
            );
        }
    }

    #[test]
    fn real_nix_fixture_enforces_output_and_wall_time_limits() {
        let Some((_, implementation, executable)) = real_fixture().unwrap() else {
            return;
        };
        let nix_instantiate = std::env::var("AOS_NIX_INSTANTIATE").unwrap();
        let prlimit = std::env::var("AOS_PRLIMIT").unwrap();
        let cache = std::env::var("AOS_TEST_ABILITY_CACHE").unwrap();
        let output_limits = AbilityEvaluationLimits {
            stdout_bytes: 128,
            ..AbilityEvaluationLimits::default()
        };
        let output_evaluator =
            RestrictedAbilityEvaluator::new(&nix_instantiate, &prlimit, &cache, output_limits)
                .unwrap();
        let output_error = output_evaluator
            .evaluate::<serde_json::Value>(
                &implementation,
                AbilityEntryPoint::Compose,
                &fixture_arguments("large-output", &executable),
            )
            .unwrap_err();
        assert!(
            format!("{output_error:#}").contains("stdout"),
            "{output_error:#}"
        );

        let wall_limits = AbilityEvaluationLimits {
            wall_time: Duration::from_millis(100),
            cpu_seconds: 5,
            ..AbilityEvaluationLimits::default()
        };
        let wall_evaluator =
            RestrictedAbilityEvaluator::new(nix_instantiate, prlimit, cache, wall_limits).unwrap();
        let wall_error = wall_evaluator
            .evaluate::<serde_json::Value>(
                &implementation,
                AbilityEntryPoint::Compose,
                &fixture_arguments("slow", &executable),
            )
            .unwrap_err();
        assert!(
            format!("{wall_error:#}").contains("wall-time"),
            "{wall_error:#}"
        );
    }
}
