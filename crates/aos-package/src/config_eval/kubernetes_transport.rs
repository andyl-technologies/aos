//! Authenticated Kubernetes API capability and bounded kubectl transport.
//!
//! The capability seals a canonical kubeconfig snapshot in memory, verifies
//! cluster identity before each use, and confines kubectl I/O to one shared
//! runtime deadline. Child process groups are always reaped on failure.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aos_ability_model::{ArtifactReference, IncarnationId};
use aos_ability_runtime::adapter::RuntimeControl;
use aos_contract::Sha256Digest;

use crate::ability_package::VerifiedAbilityPackage;
use crate::config_eval::native_ability_fs::{RootedDirectory, RootedFile};

const MAX_API_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_KUBECONFIG_BYTES: u64 = 1024 * 1024;
pub(super) const KUBECONFIG_CAPTURE_ARGUMENTS: [&str; 6] =
    ["config", "view", "--raw", "--minify", "-o", "json"];

/// Retains one exact authenticated Kubernetes API transport.
#[derive(Clone, Debug)]
pub(crate) struct KubernetesApiCapability {
    kubectl: PathBuf,
    pub(super) kubeconfig_source: PathBuf,
    kubeconfig_snapshot: Arc<Mutex<Option<Arc<KubeconfigSnapshot>>>>,
}

#[derive(Debug)]
pub(super) struct KubeconfigSnapshot {
    pub(super) file: File,
    digest: Sha256Digest,
}

pub(super) struct KubernetesInvocation<'a> {
    capability: &'a KubernetesApiCapability,
    control: &'a dyn RuntimeControl,
    deadline: ExecutionDeadline,
    kubeconfig: Arc<KubeconfigSnapshot>,
}

#[derive(Clone, Copy)]
pub(super) struct ExecutionDeadline(Instant);

/// Retains verified capability inputs without opening an executable or kubeconfig.
#[derive(Clone, Debug)]
pub(crate) struct DeferredKubernetesApiCapability {
    package: VerifiedAbilityPackage,
    kubectl: ArtifactReference,
    kubeconfig: PathBuf,
}

impl DeferredKubernetesApiCapability {
    /// Captures package-verified capability inputs without acquiring live authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the kubectl artifact is outside its owner package.
    pub(crate) fn new(
        package: &VerifiedAbilityPackage,
        kubectl: &ArtifactReference,
        kubeconfig: &Path,
    ) -> Result<Self, io::Error> {
        if !package.artifacts().contains(kubectl) {
            return Err(invalid_data(
                "Kubernetes API capability artifact is outside its owner package",
            ));
        }
        Ok(Self {
            package: package.clone(),
            kubectl: kubectl.clone(),
            kubeconfig: kubeconfig.to_path_buf(),
        })
    }

    /// Acquires the executable side of the capability after producer readiness.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained package or executable no longer
    /// authenticates as the captured capability.
    pub(crate) fn acquire(&self) -> Result<KubernetesApiCapability, io::Error> {
        KubernetesApiCapability::new(&self.package, &self.kubectl, &self.kubeconfig)
    }
}

impl KubernetesApiCapability {
    /// Authenticates the exact kubectl artifact and retains the kubeconfig path.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is outside the package or its
    /// executable fails root-owned path authentication.
    pub(crate) fn new(
        package: &VerifiedAbilityPackage,
        kubectl: &ArtifactReference,
        kubeconfig: &Path,
    ) -> Result<Self, io::Error> {
        if !package.artifacts().contains(kubectl) {
            return Err(invalid_data(
                "Kubernetes API capability artifact is outside its owner package",
            ));
        }
        Ok(Self {
            kubectl: authenticate_kubectl(kubectl)?,
            kubeconfig_source: kubeconfig.to_path_buf(),
            kubeconfig_snapshot: Arc::new(Mutex::new(None)),
        })
    }

    /// Observes a stable cluster incarnation from the kube-system namespace UID.
    ///
    /// # Errors
    ///
    /// Returns an error when kubectl fails, the response is malformed, or the
    /// cluster does not return a nonempty kube-system UID.
    pub(crate) fn observe_incarnation(
        &self,
        control: &dyn RuntimeControl,
    ) -> Result<IncarnationId, io::Error> {
        let deadline = ExecutionDeadline::new(control)?;
        let kubeconfig = self.kubeconfig_snapshot(control, deadline)?;
        observe_cluster_incarnation(&self.kubectl, &kubeconfig, control, deadline)
    }

    /// Observes the cluster under a fixed pre-dispatch discovery budget.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::observe_incarnation`].
    pub(crate) fn observe_incarnation_bounded(
        &self,
        remaining_millis: u64,
    ) -> Result<IncarnationId, io::Error> {
        self.observe_incarnation(&FixedBudgetControl::new(remaining_millis))
    }

    pub(super) fn invocation<'a>(
        &'a self,
        expected: &IncarnationId,
        control: &'a dyn RuntimeControl,
    ) -> Result<KubernetesInvocation<'a>, io::Error> {
        let deadline = ExecutionDeadline::new(control)?;
        let kubeconfig = self.kubeconfig_snapshot(control, deadline)?;
        let invocation = KubernetesInvocation {
            capability: self,
            control,
            deadline,
            kubeconfig,
        };
        invocation.require_incarnation(expected)?;
        Ok(invocation)
    }

    fn kubeconfig_snapshot(
        &self,
        control: &dyn RuntimeControl,
        deadline: ExecutionDeadline,
    ) -> Result<Arc<KubeconfigSnapshot>, io::Error> {
        let mut retained = self
            .kubeconfig_snapshot
            .lock()
            .map_err(|_| io::Error::other("Kubernetes kubeconfig snapshot lock is poisoned"))?;
        if let Some(snapshot) = retained.as_ref() {
            return Ok(Arc::clone(snapshot));
        }

        let snapshot = Arc::new(capture_kubeconfig(
            &self.kubectl,
            &self.kubeconfig_source,
            control,
            deadline,
        )?);
        *retained = Some(Arc::clone(&snapshot));
        Ok(snapshot)
    }

    pub(super) fn snapshot_digest(&self) -> Result<Sha256Digest, io::Error> {
        self.kubeconfig_snapshot
            .lock()
            .map_err(|_| io::Error::other("Kubernetes kubeconfig snapshot lock is poisoned"))?
            .as_ref()
            .map(|snapshot| snapshot.digest)
            .ok_or_else(|| invalid_data("Kubernetes kubeconfig was not acquired during admission"))
    }
}

impl KubernetesInvocation<'_> {
    pub(super) fn require_incarnation(&self, expected: &IncarnationId) -> Result<(), io::Error> {
        let observed = observe_cluster_incarnation(
            &self.capability.kubectl,
            &self.kubeconfig,
            self.control,
            self.deadline,
        )?;
        if &observed != expected {
            return Err(invalid_data(
                "captured kubeconfig resolved to another Kubernetes cluster",
            ));
        }
        Ok(())
    }

    pub(super) fn run(
        &self,
        arguments: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<Vec<u8>, io::Error> {
        run_kubectl_process(
            &self.capability.kubectl,
            &self.kubeconfig.path(),
            arguments,
            stdin,
            self.control,
            self.deadline,
        )
    }
}

impl ExecutionDeadline {
    pub(super) fn new(control: &dyn RuntimeControl) -> Result<Self, io::Error> {
        let budget = execution_budget(control)?;
        Instant::now()
            .checked_add(Duration::from_millis(budget))
            .map(Self)
            .ok_or_else(|| invalid_data("Kubernetes runtime budget exceeds monotonic time range"))
    }

    fn expired(self, control: &dyn RuntimeControl) -> bool {
        control.is_cancelled()
            || control.attempt_remaining_millis() == 0
            || control.recovery_remaining_millis() == 0
            || Instant::now() >= self.0
    }
}

impl KubeconfigSnapshot {
    pub(super) fn new(bytes: &[u8]) -> Result<Self, io::Error> {
        let descriptor = rustix::fs::memfd_create(
            "aos-kubeconfig",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .map_err(io::Error::from)?;
        let mut file = File::from(descriptor);
        file.write_all(bytes)?;
        file.flush()?;
        file.seek(SeekFrom::Start(0))?;
        rustix::fs::fcntl_add_seals(
            &file,
            rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::SEAL,
        )
        .map_err(io::Error::from)?;
        Ok(Self {
            file,
            digest: Sha256Digest::of_bytes(bytes),
        })
    }

    pub(super) fn path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.file.as_raw_fd()
        ))
    }
}

fn run_kubectl_process(
    kubectl: &Path,
    kubeconfig: &Path,
    arguments: &[String],
    stdin: Option<&[u8]>,
    control: &dyn RuntimeControl,
    deadline: ExecutionDeadline,
) -> Result<Vec<u8>, io::Error> {
    if deadline.expired(control) {
        return Err(runtime_budget_exhausted());
    }
    let mut child = Command::new(kubectl)
        .process_group(0)
        .env_clear()
        .arg("--kubeconfig")
        .arg(kubeconfig)
        .args(arguments)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let group = match child_process_group(&child) {
        Ok(group) => group,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let result = exchange_kubectl_io(&mut child, group, stdin, control, deadline);
    if result.is_err() {
        terminate_and_reap(&mut child, group);
    }
    result
}

pub(super) fn exchange_kubectl_io(
    child: &mut Child,
    group: rustix::process::Pid,
    input: Option<&[u8]>,
    control: &dyn RuntimeControl,
    deadline: ExecutionDeadline,
) -> Result<Vec<u8>, io::Error> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("kubectl stdout pipe is unavailable"))?;
    set_nonblocking(&stdout)?;
    let mut stdin = match input {
        Some(_) => {
            let pipe = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("kubectl stdin pipe is unavailable"))?;
            set_nonblocking(&pipe)?;
            Some(pipe)
        }
        None => None,
    };
    let mut input_offset = 0_usize;
    let mut output = Vec::new();
    let mut stdout_eof = false;
    let mut exit_status = None;

    loop {
        if deadline.expired(control) {
            return Err(runtime_budget_exhausted());
        }

        if let (Some(bytes), Some(pipe)) = (input, stdin.as_mut()) {
            while input_offset < bytes.len() {
                if deadline.expired(control) {
                    return Err(runtime_budget_exhausted());
                }

                match pipe.write(&bytes[input_offset..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "kubectl stdin stopped accepting input",
                        ));
                    }
                    Ok(written) => input_offset += written,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            if input_offset == bytes.len() {
                stdin = None;
            }
        }

        if !stdout_eof {
            let mut chunk = [0_u8; 16 * 1024];
            loop {
                if deadline.expired(control) {
                    return Err(runtime_budget_exhausted());
                }

                match stdout.read(&mut chunk) {
                    Ok(0) => {
                        stdout_eof = true;
                        break;
                    }
                    Ok(read) => {
                        let next_len = output.len().saturating_add(read);
                        if next_len as u64 > MAX_API_RESPONSE_BYTES {
                            return Err(invalid_data("kubectl response exceeds its size bound"));
                        }
                        output.extend_from_slice(&chunk[..read]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
        }

        if exit_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_status = Some(status);
                    // A helper must not outlive kubectl or retain its output pipe.
                    let _ =
                        rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
                }
                Ok(None) => {}
                Err(error) => return Err(error),
            }
        }
        if stdout_eof && exit_status.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let status = exit_status.ok_or_else(|| io::Error::other("kubectl was not reaped"))?;
    if !status.success() {
        return Err(io::Error::other("kubectl operation failed"));
    }
    while output.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        output.pop();
    }
    Ok(output)
}

fn set_nonblocking<Fd: AsFd>(descriptor: Fd) -> Result<(), io::Error> {
    let flags = rustix::fs::fcntl_getfl(&descriptor).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(&descriptor, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(io::Error::from)
}

pub(super) fn child_process_group(child: &Child) -> Result<rustix::process::Pid, io::Error> {
    let raw = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| io::Error::other("kubectl has no valid process group"))?;
    Ok(raw)
}

fn capture_kubeconfig(
    kubectl: &Path,
    source: &Path,
    control: &dyn RuntimeControl,
    deadline: ExecutionDeadline,
) -> Result<KubeconfigSnapshot, io::Error> {
    let source = authenticate_kubeconfig(source, 0)?;
    let raw = source.read(MAX_KUBECONFIG_BYTES)?;
    let raw_snapshot = KubeconfigSnapshot::new(&raw)?;
    let captured = run_kubectl_process(
        kubectl,
        &raw_snapshot.path(),
        &KUBECONFIG_CAPTURE_ARGUMENTS.map(str::to_string),
        None,
        control,
        deadline,
    )?;
    let canonical = validate_captured_kubeconfig(&captured)?;
    KubeconfigSnapshot::new(&canonical)
}

pub(super) fn validate_captured_kubeconfig(bytes: &[u8]) -> Result<Vec<u8>, io::Error> {
    if bytes.len() as u64 > MAX_KUBECONFIG_BYTES {
        return Err(invalid_data(
            "captured Kubernetes kubeconfig exceeds its size bound",
        ));
    }
    let config = aos_contract::canonical::parse_json(bytes, "captured Kubernetes kubeconfig")
        .map_err(|error| invalid_data(error.to_string()))?;
    let current_context = required_string(&config, "current-context", "Kubernetes kubeconfig")?;
    let context = one_named_entry(&config, "contexts", current_context)?;
    let context = context
        .get("context")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_data("Kubernetes kubeconfig context is malformed"))?;
    let cluster_name = context
        .get("cluster")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_data("Kubernetes kubeconfig context has no cluster"))?;
    let user_name = context
        .get("user")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_data("Kubernetes kubeconfig context has no user"))?;

    let cluster = one_named_entry(&config, "clusters", cluster_name)?;
    let cluster = cluster
        .get("cluster")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_data("Kubernetes kubeconfig cluster is malformed"))?;
    let server = cluster
        .get("server")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_data("Kubernetes kubeconfig cluster has no server"))?;
    let server = url::Url::parse(server)
        .map_err(|error| invalid_data(format!("invalid Kubernetes API server URL: {error}")))?;
    if server.scheme() != "https"
        || server.host_str().is_none()
        || !server.username().is_empty()
        || server.password().is_some()
        || server.fragment().is_some()
    {
        return Err(invalid_data(
            "Kubernetes API server must be an authenticated HTTPS origin",
        ));
    }
    if cluster.contains_key("certificate-authority")
        || cluster
            .get("certificate-authority-data")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        || cluster
            .get("insecure-skip-tls-verify")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    {
        return Err(invalid_data(
            "Kubernetes kubeconfig must embed a trusted certificate authority",
        ));
    }

    let user = one_named_entry(&config, "users", user_name)?;
    let user = user
        .get("user")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_data("Kubernetes kubeconfig user is malformed"))?;
    for forbidden in [
        "auth-provider",
        "client-certificate",
        "client-key",
        "exec",
        "tokenFile",
    ] {
        if user.contains_key(forbidden) {
            return Err(invalid_data(
                "Kubernetes kubeconfig retains an external credential provider",
            ));
        }
    }
    let has_token = user
        .get("token")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let has_certificates = ["client-certificate-data", "client-key-data"]
        .iter()
        .all(|field| {
            user.get(*field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.is_empty())
        });
    let has_password = ["username", "password"].iter().all(|field| {
        user.get(*field)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.is_empty())
    });
    if !(has_token || has_certificates || has_password) {
        return Err(invalid_data(
            "Kubernetes kubeconfig has no embedded client credential",
        ));
    }

    aos_contract::canonical::canonical_json(&config)
        .map_err(|error| invalid_data(error.to_string()))
}

fn one_named_entry<'a>(
    config: &'a serde_json::Value,
    field: &str,
    expected_name: &str,
) -> Result<&'a serde_json::Value, io::Error> {
    let entries = config
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid_data(format!("Kubernetes kubeconfig has no {field} array")))?;
    let [entry] = entries.as_slice() else {
        return Err(invalid_data(format!(
            "Kubernetes kubeconfig must contain exactly one selected {field} entry"
        )));
    };
    if entry.get("name").and_then(serde_json::Value::as_str) != Some(expected_name) {
        return Err(invalid_data(format!(
            "Kubernetes kubeconfig selected {field} entry has another name"
        )));
    }
    Ok(entry)
}

fn required_string<'a>(
    value: &'a serde_json::Value,
    field: &str,
    label: &str,
) -> Result<&'a str, io::Error> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_data(format!("{label} has no {field}")))
}

fn observe_cluster_incarnation(
    kubectl: &Path,
    kubeconfig: &KubeconfigSnapshot,
    control: &dyn RuntimeControl,
    deadline: ExecutionDeadline,
) -> Result<IncarnationId, io::Error> {
    let output = run_kubectl_process(
        kubectl,
        &kubeconfig.path(),
        &[
            "get".to_string(),
            "namespace".to_string(),
            "kube-system".to_string(),
            "-o".to_string(),
            "json".to_string(),
        ],
        None,
        control,
        deadline,
    )?;
    let object = aos_contract::canonical::parse_json(&output, "Kubernetes cluster identity")
        .map_err(|error| invalid_data(error.to_string()))?;
    let uid = object
        .get("metadata")
        .and_then(|metadata| metadata.get("uid"))
        .and_then(serde_json::Value::as_str)
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| invalid_data("Kubernetes cluster identity has no UID"))?;
    IncarnationId::new(format!("kubernetes:{uid}")).map_err(|error| invalid_data(error.to_string()))
}

fn execution_budget(control: &dyn RuntimeControl) -> Result<u64, io::Error> {
    if control.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Kubernetes operation was cancelled before spawn",
        ));
    }
    let budget = control
        .attempt_remaining_millis()
        .min(control.recovery_remaining_millis());
    if budget == 0 {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Kubernetes operation has no remaining runtime budget",
        ))
    } else {
        Ok(budget)
    }
}

fn runtime_budget_exhausted() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "Kubernetes operation exhausted its runtime budget",
    )
}

pub(super) fn terminate_and_reap(child: &mut Child, group: rustix::process::Pid) {
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

pub(super) struct FixedBudgetControl {
    remaining_millis: u64,
}

impl FixedBudgetControl {
    pub(super) const fn new(remaining_millis: u64) -> Self {
        Self { remaining_millis }
    }
}

impl RuntimeControl for FixedBudgetControl {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn attempt_remaining_millis(&self) -> u64 {
        self.remaining_millis
    }

    fn recovery_remaining_millis(&self) -> u64 {
        self.remaining_millis
    }

    fn elapsed_millis(&self) -> u64 {
        0
    }
}

fn authenticate_kubectl(artifact: &ArtifactReference) -> Result<PathBuf, io::Error> {
    let root = PathBuf::from(&artifact.store_path);
    if root.to_str() != Some(artifact.store_path.as_str()) {
        return Err(invalid_data("kubectl artifact store path is not canonical"));
    }
    let root = RootedDirectory::open(&root, 0, "kubectl artifact root")?;
    let executable = root.resolve(Path::new("bin/kubectl"))?;
    if executable.mode()? & 0o111 == 0 {
        return Err(invalid_data(
            "authenticated kubectl entry point is not executable",
        ));
    }
    Ok(executable.display().to_path_buf())
}

fn authenticate_kubeconfig(path: &Path, trusted_owner: u32) -> Result<RootedFile, io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("Kubernetes kubeconfig has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid_data("Kubernetes kubeconfig has no file name"))?;
    let parent = RootedDirectory::open(parent, trusted_owner, "Kubernetes kubeconfig parent")?;
    let file = parent.resolve(Path::new(name))?;
    file.open_read_only()?;
    Ok(file)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
