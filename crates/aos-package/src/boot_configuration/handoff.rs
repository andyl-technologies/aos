//! Transfers the two journal-authorized receipt objects into the host store.
//!
//! The source journal remains locked throughout export, import, verification,
//! and retention. The target is the mounted host overlay, not a second source
//! of authority. A failed transfer prevents the initrd completion target.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_ability_runtime::adapter::CancellationToken;
use aos_contract::Sha256Digest;
use clap::Parser as _;

use super::{proof, reader};
use crate::deployment::process::run_bounded_with_input_limit;
use crate::native_deployment::{
    EvaluationInput, ImportControl, NativeDeploymentArgs, NativeDeploymentCommand,
};
use crate::store::temp_roots::TemporaryRoots;

const TRANSFER_LIMIT: usize = 8 * 1024 * 1024;
const RECEIPT_LIMIT: u64 = reader::AUTHORIZATION_LIMIT;
const TARGET_ROOT: &str = "/sysroot";
const BINDING: &str = "/sysroot/usr/lib/aos/boot-metadata-binding.json";

#[derive(clap::Parser)]
struct Arguments {
    #[command(flatten)]
    deployment: NativeDeploymentArgs,
}

/// Transfers committed receipts into the fixed mounted host overlay.
///
/// # Errors
/// Returns an error for a mismatched image binding, unfinished journal,
/// changed provenance or receipt identity, or failed store transport.
pub(super) fn run_from_process() -> Result<()> {
    let arguments = Arguments::parse_from(
        std::env::args_os()
            .take(1)
            .chain(std::env::args_os().skip(2)),
    );
    let command = arguments.deployment.command()?;
    ensure!(
        command.input == Path::new("/lib/aos/initrd/deployment")
            && command.profile.is_none()
            && command.admission == command.input.join("admission.json"),
        "receipt handoff requires the fixed authenticated initrd bundle"
    );
    ensure!(
        std::env::var_os("AOS_NIX_STORE").as_deref() == Some(command.nix_store.as_os_str()),
        "receipt handoff store differs from its retained launcher"
    );
    let policy: proof::MetadataBinding = GRAPH_LIMITS.decode(
        &reader::read_bounded(Path::new(BINDING), 4096)?,
        "image metadata policy",
    )?;
    if !policy.required()? {
        return Ok(());
    }

    handoff_in(
        &command,
        Path::new(BINDING),
        Path::new(TARGET_ROOT),
        &CancellationToken::default(),
    )
}

/// Transfers receipts selected by an authenticated, completely committed initrd.
///
/// The production caller supplies its fixed image binding and mounted host
/// root. Keeping this boundary separate permits the same authority and store
/// transport to be exercised against two isolated stores.
///
/// # Errors
/// Returns an error for invalid image admission or journal authority, changed
/// receipt provenance, or failed import, verification, or durable retention.
pub(super) fn handoff_in(
    command: &NativeDeploymentCommand,
    binding: &Path,
    target_root: &Path,
    cancellation: &CancellationToken,
) -> Result<()> {
    let committed = reader::read_committed_preparation(command, binding)?;
    let descriptor = EvaluationInput::read_in(
        &command.input.join("evaluation.json"),
        &command.nix_store,
        cancellation,
    )?;
    let bytes = reader::read_immutable_bounded(
        &committed.result.authorized_input,
        &command.nix_store,
        RECEIPT_LIMIT,
    )?;
    let authorized = proof::validate_authorized_bytes(
        &bytes,
        committed.result.authorized_input_sha256,
        &descriptor,
    )?;
    ensure!(
        serde_json::to_value(authorized.source)?.as_str() == Some(committed.result.source.as_str()),
        "committed disk source differs from its authorization receipt"
    );
    transfer_receipts(
        &command.nix_store,
        target_root,
        &committed.result,
        cancellation,
    )?;
    // Keep the committed decision's shared journal locks through retention.
    drop(committed);
    Ok(())
}

/// Imports only the exact flat objects selected by the verified preparation.
///
/// The caller holds the journal locks and verifies authorization provenance.
/// Both NAR identities and the authorization content digest are checked before
/// and after import; no store closure or ambient root is discovered here.
fn transfer_receipts(
    nix_store: &Path,
    target_root: &Path,
    result: &proof::PreparationResult,
    cancellation: &CancellationToken,
) -> Result<()> {
    let roots = [&result.authorized_input, &result.committed_plan];
    let mut temporary = TemporaryRoots::open(nix_store, cancellation)?;
    temporary.retain(
        roots.iter().map(|root| root.to_string_lossy().into_owned()),
        cancellation,
    )?;
    let mut source_nars = Vec::new();
    for root in roots {
        let (canonical, suffix) = crate::deployment::nix::store_root_and_suffix(root)?;
        ensure!(
            canonical == *root && suffix.as_os_str().is_empty(),
            "receipt is not an exact store root"
        );
        let mut references = source_command(nix_store)?;
        references.args(["--query", "--references"]).arg(root);
        ensure!(
            run(&mut references, None, cancellation)?
                .iter()
                .all(u8::is_ascii_whitespace),
            "receipt has unexpected store references"
        );
        let bytes = reader::read_immutable_bounded(root, nix_store, RECEIPT_LIMIT)?;
        if root == &result.authorized_input {
            ensure!(
                Sha256Digest::of_bytes(&bytes) == result.authorized_input_sha256,
                "authorization receipt digest differs before handoff"
            );
        }
        let mut dump = aos_core::nix::identity::store_nar_command(
            nix_store,
            root.to_str().context("receipt path is not UTF-8")?,
        )?;
        source_nars.push(run(&mut dump, None, cancellation)?);
    }

    let mut export = source_command(nix_store)?;
    export.arg("--export").args(roots);
    let archive =
        run(&mut export, None, cancellation).context("exporting committed initrd receipts")?;
    let mut initialize = target_command(nix_store, target_root, false)?;
    initialize.arg("--init");
    run(&mut initialize, None, cancellation)?;
    let mut import = target_command(nix_store, target_root, false)?;
    import.arg("--import");
    run(&mut import, Some(&archive), cancellation)
        .context("importing committed receipts into the mounted host store")?;

    for (root, source_nar) in roots.into_iter().zip(source_nars) {
        let mut dump = target_command(nix_store, target_root, true)?;
        dump.args(["store", "dump-path"]).arg(root);
        ensure!(
            run(&mut dump, None, cancellation)? == source_nar,
            "host receipt NAR differs from its authenticated source"
        );
        let mut references = target_command(nix_store, target_root, false)?;
        references.args(["--query", "--references"]).arg(root);
        ensure!(
            run(&mut references, None, cancellation)?
                .iter()
                .all(u8::is_ascii_whitespace),
            "imported receipt has unexpected store references"
        );
        let mut read = target_command(nix_store, target_root, true)?;
        read.args(["store", "cat"]).arg(root);
        let bytes = run(&mut read, None, cancellation)?;
        ensure!(
            bytes.len() <= RECEIPT_LIMIT as usize,
            "imported receipt exceeds its content bound"
        );
        if root == &result.authorized_input {
            ensure!(
                Sha256Digest::of_bytes(&bytes) == result.authorized_input_sha256,
                "authorization receipt digest differs after handoff"
            );
        }
        retain_receipt(target_root, root)?;
    }
    Ok(())
}

fn source_command(executable: &Path) -> Result<Command> {
    let mut command = Command::new(executable);
    aos_core::nix::configure_aos_nix_store(&mut command)?;
    Ok(command)
}

// Resolve the authenticated suite while preserving nix-store's multicall name.
// Target routing deliberately ignores the source process's selected-store env.
fn target_command(executable: &Path, target_root: &Path, modern: bool) -> Result<Command> {
    let trusted = aos_core::nix::identity::store_command(executable)?;
    let program = if modern {
        PathBuf::from(trusted.get_program())
    } else {
        executable.to_path_buf()
    };
    let mut command = Command::new(program);
    command.args([
        "--store",
        &format!("local?root={}", target_root.display()),
        "--option",
        "build-users-group",
        "",
    ]);
    if modern {
        command.args(["--extra-experimental-features", "nix-command"]);
    }
    Ok(command)
}

fn run(
    command: &mut Command,
    input: Option<&[u8]>,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>> {
    let environment: Vec<(OsString, OsString)> = command
        .get_envs()
        .filter_map(|(name, value)| value.map(|value| (name.into(), value.into())))
        .collect();
    let output = run_bounded_with_input_limit(
        command,
        input,
        TRANSFER_LIMIT,
        TRANSFER_LIMIT,
        &ImportControl(cancellation),
        &environment,
    )?;
    ensure!(
        output.status.success(),
        "boot receipt store transport failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

// Roots are retained at the host store's persistent physical GC-root directory,
// with logical link targets that remain valid after switch-root.
fn retain_receipt(target_root: &Path, root: &Path) -> Result<()> {
    let directory = target_root.join("nix/var/nix/gcroots/aos/boot-metadata-handoff");
    let relative = directory.strip_prefix(target_root)?;
    let mut current = target_root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => {
                fs::File::open(
                    current
                        .parent()
                        .context("retention directory has no parent")?,
                )?
                .sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                ensure!(
                    fs::symlink_metadata(&current)?.is_dir(),
                    "receipt retention directory is not a real directory"
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
    let link = directory.join(
        root.file_name()
            .context("receipt root has no object name")?,
    );
    match symlink(root, &link) {
        Ok(()) => {
            fs::File::open(&directory)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                fs::read_link(&link)? == root,
                "receipt retention root has a different identity"
            );
            fs::File::open(&directory)?.sync_all()?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_retention_rejects_redirected_directories_and_links() -> Result<()> {
        let root = tempfile::tempdir()?;
        let receipt = Path::new("/nix/store/00000000000000000000000000000000-receipt");
        retain_receipt(root.path(), receipt)?;
        retain_receipt(root.path(), receipt)?;
        let directory = root
            .path()
            .join("nix/var/nix/gcroots/aos/boot-metadata-handoff");
        fs::remove_file(directory.join(receipt.file_name().unwrap()))?;
        symlink("/unrelated", directory.join(receipt.file_name().unwrap()))?;
        assert!(retain_receipt(root.path(), receipt).is_err());

        fs::remove_dir_all(root.path().join("nix"))?;
        symlink("/unrelated", root.path().join("nix"))?;
        assert!(retain_receipt(root.path(), receipt).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires source-built Nix and a private selected source store"]
    fn actual_two_store_receipts_keep_identity_and_reject_changed_digest() -> Result<()> {
        let executable = PathBuf::from(
            std::env::var_os("AOS_NIX_STORE").context("source-built Nix is required")?,
        );
        let source_uri =
            std::env::var("AOS_NIX_EVAL_STORE").context("private source store is required")?;
        ensure!(
            source_uri.starts_with("local?root=/tmp/"),
            "test requires a private source store"
        );
        let cancellation = CancellationToken::default();
        let scratch = tempfile::tempdir()?;
        let target = scratch.path().join("target");
        fs::create_dir(&target)?;
        let mut initialize = source_command(&executable)?;
        initialize.arg("--init");
        run(&mut initialize, None, &cancellation)?;

        let authorization_bytes = b"{\"source\":\"operator\",\"receipt\":\"committed-test\"}\n";
        let plan_bytes = b"{\"plan\":\"committed-test\"}\n";
        let mut roots = Vec::new();
        for (name, bytes) in [
            ("authorization", authorization_bytes.as_slice()),
            ("plan", plan_bytes.as_slice()),
        ] {
            let source = scratch.path().join(name);
            fs::write(&source, bytes)?;
            let mut add = source_command(&executable)?;
            add.args(["--add-fixed", "sha256"]).arg(&source);
            let output = run(&mut add, None, &cancellation)?;
            roots.push(PathBuf::from(std::str::from_utf8(&output)?.trim()));
        }
        let result = proof::PreparationResult {
            resource: "disk".into(),
            source: "operator".into(),
            authorized_input: roots[0].clone(),
            committed_plan: roots[1].clone(),
            authorized_input_sha256: Sha256Digest::of_bytes(authorization_bytes),
        };
        let mut initialize = target_command(&executable, &target, false)?;
        initialize.arg("--init");
        run(&mut initialize, None, &cancellation)?;
        for root in &roots {
            let mut valid = target_command(&executable, &target, false)?;
            valid.arg("--check-validity").arg(root);
            assert!(run(&mut valid, None, &cancellation).is_err());
        }
        let wrong = proof::PreparationResult {
            authorized_input_sha256: Sha256Digest::of_bytes(b"foreign"),
            resource: result.resource.clone(),
            source: result.source.clone(),
            authorized_input: result.authorized_input.clone(),
            committed_plan: result.committed_plan.clone(),
        };
        assert!(transfer_receipts(&executable, &target, &wrong, &cancellation).is_err());
        for root in &roots {
            assert!(!target.join(root.strip_prefix("/")?).exists());
        }

        transfer_receipts(&executable, &target, &result, &cancellation)?;
        transfer_receipts(&executable, &target, &result, &cancellation)?;
        // Production releases the transfer process before host adoption. The
        // exact persistent roots must survive GC without its temporary roots.
        let mut collect = target_command(&executable, &target, false)?;
        collect.arg("--gc");
        run(&mut collect, None, &cancellation)?;
        for (root, bytes) in roots
            .iter()
            .zip([authorization_bytes.as_slice(), plan_bytes.as_slice()])
        {
            let mut valid = target_command(&executable, &target, false)?;
            valid.arg("--check-validity").arg(root);
            run(&mut valid, None, &cancellation)?;
            assert_eq!(fs::read(target.join(root.strip_prefix("/")?))?, bytes);
            assert_eq!(
                fs::read_link(
                    target
                        .join("nix/var/nix/gcroots/aos/boot-metadata-handoff")
                        .join(root.file_name().unwrap())
                )?,
                *root
            );
        }
        Ok(())
    }
}
