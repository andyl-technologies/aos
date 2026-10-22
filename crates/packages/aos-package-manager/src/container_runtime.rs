//! Prepares the retained root profile and launches the package-selected init.
//!
//! The private startup command writes only a NUL-delimited executable and its
//! arguments to standard output. Missing init configuration produces no bytes.
//! The configuration contract is:
//!
//! ```json
//! {"schema":"aos.init-command/v1","executable":"/nix/store/00000000000000000000000000000000-init/bin/init","arguments":[]}
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_activation::adapter::CancellationToken;
use aos_core::Sha256Digest;
use serde::Deserialize;

#[derive(clap::Args)]
pub struct ContainerStartupArgs {
    /// Read the retained immutable container deployment.
    #[arg(long)]
    image_input: PathBuf,
    /// Use this private container startup state directory.
    #[arg(long)]
    state_directory: PathBuf,
    /// Activate service phases after the selected init is ready.
    #[arg(long)]
    activate: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitCommand {
    schema: String,
    executable: PathBuf,
    arguments: Vec<String>,
}

pub(crate) fn run(
    arguments: &ContainerStartupArgs,
    cancellation: &CancellationToken,
) -> Result<()> {
    ensure!(
        crate::runtime_boundary::is_container(),
        "container startup requires the container runtime"
    );
    ensure!(
        rustix::process::geteuid().is_root(),
        "container startup requires root"
    );
    if arguments.activate {
        invalidate_ready(Path::new("/run/aos/container-service-ready"))?;
    }
    crate::native_deployment::container::prepare_profile(
        &arguments.image_input,
        &arguments.state_directory,
        arguments.activate,
        cancellation,
    )?;
    if arguments.activate {
        publish_ready(
            Path::new("/run/aos/container-service-ready"),
            Path::new("/proc/1/stat"),
            Path::new("/proc/1/exe"),
            Path::new("/etc/aos/init.json"),
        )?;
        return Ok(());
    }
    let bytes = read_init(Path::new("/etc/aos/init.json"))?;
    std::io::stdout()
        .lock()
        .write_all(&bytes)
        .context("writing selected container init")
}

fn read_init(path: &Path) -> Result<Vec<u8>> {
    read_init_command(path)?.map_or_else(|| Ok(Vec::new()), |command| encode_init(&command))
}

fn read_init_command(path: &Path) -> Result<Option<InitCommand>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("reading selected init configuration"),
    };
    ensure!(
        metadata.is_file() && metadata.len() <= 64 * 1024,
        "init configuration must be a bounded regular file"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() <= 64 * 1024,
        "init configuration exceeds its byte bound"
    );
    let command: InitCommand =
        serde_json::from_slice(&bytes).context("decoding selected init configuration")?;
    encode_init(&command)?;
    Ok(Some(command))
}

/// Compares the candidate graph's prepared init command to current selection.
///
/// # Errors
/// Returns an error for invalid current configuration or multiple init commands.
pub(crate) fn candidate_init_matches(
    deployment: &aos_deployment_format::model::Deployment,
) -> Result<bool> {
    let mut inputs = deployment
        .graph()
        .graph()
        .nodes
        .values()
        .filter(|effect| {
            let identity = &effect.identity;
            identity.len() >= 4
                && identity[identity.len() - 3] == "initSystem"
                && identity[identity.len() - 2] == "install"
        })
        .map(|effect| &effect.input);
    let Some(input) = inputs.next() else {
        return Ok(false);
    };
    ensure!(
        inputs.next().is_none(),
        "candidate graph selects multiple init commands"
    );
    let selected = read_init(Path::new("/etc/aos/init.json"))?;
    candidate_command_matches(input, &selected)
}

fn candidate_command_matches(input: &serde_json::Value, selected: &[u8]) -> Result<bool> {
    let Some(executable) = input.get("executable").and_then(serde_json::Value::as_str) else {
        return Ok(false);
    };
    let Some(arguments) = input.get("arguments").and_then(serde_json::Value::as_array) else {
        return Ok(false);
    };
    let Some(arguments) = arguments
        .iter()
        .map(|argument| argument.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(false);
    };
    let candidate = InitCommand {
        schema: "aos.init-command/v1".into(),
        executable: executable.into(),
        arguments,
    };
    Ok(encode_init(&candidate)? == selected)
}

fn encode_init(command: &InitCommand) -> Result<Vec<u8>> {
    ensure!(
        command.schema == "aos.init-command/v1",
        "unsupported init configuration schema"
    );
    ensure!(
        command.executable.is_absolute(),
        "selected init executable must be absolute"
    );
    aos_deployment::nix::store_root_and_suffix(&command.executable)?;
    let executable = command
        .executable
        .to_str()
        .context("selected init executable is not UTF-8")?;
    let mut bytes = Vec::new();
    for argument in std::iter::once(executable).chain(command.arguments.iter().map(String::as_str))
    {
        ensure!(
            !argument.contains('\0'),
            "selected init argument contains NUL"
        );
        bytes.extend_from_slice(argument.as_bytes());
        bytes.push(0);
    }
    Ok(bytes)
}

// A failed activation must not leave readiness from an earlier attempt in
// this PID-1 lifetime visible to package consumers.
fn invalidate_ready(marker: &Path) -> Result<()> {
    match fs::remove_file(marker) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("invalidating container service readiness"),
    }
}

/// Checks service readiness against both desired init and the running PID-1.
///
/// # Errors
/// Returns an error for malformed configuration or unreadable process identity.
pub(crate) fn service_ready(
    marker: &Path,
    stat: &Path,
    executable: &Path,
    configuration: &Path,
) -> Result<bool> {
    let bytes = match fs::read(marker) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("reading container service readiness"),
    };
    let Some(command) = read_init_command(configuration)? else {
        return Ok(false);
    };
    let selected =
        fs::canonicalize(&command.executable).context("resolving selected init executable")?;
    if !running_selected_init(executable, &selected)? {
        return Ok(false);
    }
    Ok(bytes == readiness_identity(stat, &selected, &encode_init(&command)?)?)
}

fn publish_ready(
    marker: &Path,
    stat: &Path,
    executable: &Path,
    configuration: &Path,
) -> Result<()> {
    let command =
        read_init_command(configuration)?.context("service activation has no selected init")?;
    let selected =
        fs::canonicalize(&command.executable).context("resolving selected init executable")?;
    ensure!(
        running_selected_init(executable, &selected)?,
        "selected init differs from the running PID-1; restart the container to activate it"
    );
    let bytes = readiness_identity(stat, &selected, &encode_init(&command)?)?;
    let directory = marker
        .parent()
        .context("container readiness marker has no parent")?;
    fs::create_dir_all(directory)?;
    let temporary = directory.join(format!(".container-service-ready-{}", std::process::id()));
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, marker)?;
    Ok(())
}

fn running_selected_init(executable: &Path, selected: &Path) -> Result<bool> {
    Ok(fs::read_link(executable).context("reading running PID-1 executable")? == selected)
}

fn readiness_identity(stat: &Path, selected: &Path, command: &[u8]) -> Result<Vec<u8>> {
    let identity = fs::read_to_string(stat).context("reading container PID-1 identity")?;
    let (_, fields) = identity
        .rsplit_once(") ")
        .context("container PID-1 identity has no command terminator")?;
    let start_time = fields
        .split_whitespace()
        .nth(19)
        .context("container PID-1 identity omits its start time")?;
    ensure!(
        !start_time.is_empty() && start_time.bytes().all(|byte| byte.is_ascii_digit()),
        "container PID-1 start time is invalid"
    );
    let executable = selected
        .to_str()
        .context("selected init executable is not UTF-8")?;
    ensure!(
        !executable.contains(['\n', '\r']),
        "selected init executable contains a line terminator"
    );
    // Desired arguments are part of selection identity even though procfs only
    // supplies the executable identity. Changing selection requires a restart.
    Ok(format!("schema=aos.container.service-ready/v1\npid1_start_time={start_time}\ninit_executable={executable}\ninit_command_sha256={}\n", Sha256Digest::of_bytes(command)).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_command_is_private_and_serializes_its_options() {
        use clap::Parser;

        #[derive(clap::Parser)]
        struct Cli {
            #[command(subcommand)]
            command: crate::PackageCommand,
        }

        let cli = Cli::try_parse_from([
            "aos-package-runtime",
            "container-startup",
            "--image-input",
            "/usr/lib/aos-container/native-deployment",
            "--state-directory",
            "/var/lib/apm/container-runtime",
            "--activate",
        ])
        .unwrap();
        assert!(cli.command.is_runtime_internal());
        let crate::PackageCommand::ContainerStartup(arguments) = cli.command else {
            panic!("wrong private runtime command");
        };
        assert!(arguments.activate);
        assert_eq!(
            arguments.image_input,
            Path::new("/usr/lib/aos-container/native-deployment")
        );
        assert_eq!(
            arguments.state_directory,
            Path::new("/var/lib/apm/container-runtime")
        );
    }

    #[test]
    fn activation_invalidates_previous_readiness_before_retry() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("ready");
        fs::write(&marker, "previous readiness").unwrap();

        invalidate_ready(&marker).unwrap();

        assert!(!marker.exists());
        invalidate_ready(&marker).unwrap();
    }

    #[test]
    fn service_readiness_binds_pid1_and_selected_init_command() {
        let directory = tempfile::tempdir().unwrap();
        let stat = directory.path().join("stat");
        fs::write(
            &stat,
            "1 (command with ) parentheses) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4242 0\n",
        )
        .unwrap();
        let executable = Path::new("/nix/store/00000000000000000000000000000000-init/bin/init");

        let identity = readiness_identity(&stat, executable, b"init\0--system\0").unwrap();
        let changed_arguments = readiness_identity(&stat, executable, b"init\0--other\0").unwrap();
        let changed_executable = readiness_identity(
            &stat,
            Path::new("/nix/store/11111111111111111111111111111111-init/bin/init"),
            b"init\0--system\0",
        )
        .unwrap();

        assert!(
            std::str::from_utf8(&identity)
                .unwrap()
                .contains("pid1_start_time=4242\n")
        );
        assert_ne!(identity, changed_arguments);
        assert_ne!(identity, changed_executable);
    }

    #[test]
    fn selecting_a_new_init_does_not_change_the_running_init() {
        let directory = tempfile::tempdir().unwrap();
        let process_executable = directory.path().join("exe");
        let running = Path::new("/nix/store/00000000000000000000000000000000-init/bin/init");
        let selected = Path::new("/nix/store/11111111111111111111111111111111-init/bin/init");
        std::os::unix::fs::symlink(running, &process_executable).unwrap();

        assert!(running_selected_init(&process_executable, running).unwrap());
        assert!(!running_selected_init(&process_executable, selected).unwrap());
    }

    #[test]
    fn candidate_init_changes_defer_services_but_unchanged_selection_does_not() {
        let input = serde_json::json!({
            "executable": "/nix/store/00000000000000000000000000000000-init/bin/init",
            "arguments": ["--system"],
        });
        let selected = b"/nix/store/00000000000000000000000000000000-init/bin/init\0--system\0";
        assert!(candidate_command_matches(&input, selected).unwrap());

        let mut changed = input.clone();
        changed["executable"] =
            serde_json::json!("/nix/store/11111111111111111111111111111111-init/bin/init");
        assert!(!candidate_command_matches(&changed, selected).unwrap());
        changed = input.clone();
        changed["arguments"] = serde_json::json!(["--different"]);
        assert!(!candidate_command_matches(&changed, selected).unwrap());
        assert!(
            !candidate_command_matches(
                &serde_json::json!({"executable": {"$ref": "deferred"}}),
                selected
            )
            .unwrap()
        );
    }

    #[test]
    fn missing_service_marker_does_not_read_selection() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent");
        assert!(!service_ready(&absent, &absent, &absent, &absent).unwrap());
    }

    #[test]
    fn init_handoff_preserves_empty_and_spaced_arguments() {
        let command = InitCommand {
            schema: "aos.init-command/v1".into(),
            executable: "/nix/store/00000000000000000000000000000000-init/bin/init".into(),
            arguments: vec!["".into(), "argument with spaces".into()],
        };
        assert_eq!(
            encode_init(&command).unwrap(),
            b"/nix/store/00000000000000000000000000000000-init/bin/init\0\0argument with spaces\0"
        );
    }

    #[test]
    fn missing_configuration_has_no_handoff() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            read_init(&directory.path().join("absent"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn invalid_configuration_cannot_split_arguments() {
        let mut command = InitCommand {
            schema: "aos.init-command/v1".into(),
            executable: "/nix/store/00000000000000000000000000000000-init/bin/init".into(),
            arguments: vec!["bad\0argument".into()],
        };
        assert!(encode_init(&command).is_err());
        command.arguments.clear();
        command.schema = "unknown".into();
        assert!(encode_init(&command).is_err());
    }
}
