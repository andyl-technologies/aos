//! Labels staged native units before their no-replacement publication.
//!
//! Runtime directory inheritance does not supply a unit's service label. The
//! deployed policy resolves its canonical vendor path before any manager use.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

const OUTPUT_LIMIT: u64 = 4096;

trait LabelRunner {
    async fn run(&mut self, executable: &Path, arguments: &[&OsStr]) -> Result<Vec<u8>>;
}

struct NativeLabelRunner;

impl LabelRunner for NativeLabelRunner {
    async fn run(&mut self, executable: &Path, arguments: &[&OsStr]) -> Result<Vec<u8>> {
        let mut child = Command::new(executable)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("start pinned unit-label tool")?;
        let result = tokio::time::timeout(Duration::from_secs(45), async {
            let stdout = child.stdout.take().context("missing unit-label output")?;
            let mut output = Vec::new();
            stdout
                .take(OUTPUT_LIMIT + 1)
                .read_to_end(&mut output)
                .await?;
            ensure!(
                output.len() <= OUTPUT_LIMIT as usize,
                "unit-label output exceeds limit"
            );
            ensure!(child.wait().await?.success(), "unit-label tool failed");
            Ok(output)
        })
        .await
        .context("unit-label tool timed out")
        .and_then(|result| result);

        if result.is_err() {
            // A failed bounded read must not leave a labeler running against
            // the staged path after the temporary file is removed.
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        result
    }
}

/// Publishes a canonically labeled unit without replacing another file.
///
/// # Errors
/// Returns an error for invalid names or tools, policy lookup or labeling
/// failures, and staging, synchronization or no-replacement publication errors.
pub(super) async fn publish(
    directory: &Path,
    name: &str,
    text: &str,
    tools: Option<(&str, &str)>,
) -> Result<()> {
    publish_with_runner(
        directory,
        name,
        text,
        Path::new("/sys/fs/selinux/enforce").exists(),
        tools,
        &mut NativeLabelRunner,
    )
    .await
}

async fn publish_with_runner(
    directory: &Path,
    name: &str,
    text: &str,
    selinux_enabled: bool,
    tools: Option<(&str, &str)>,
    runner: &mut impl LabelRunner,
) -> Result<()> {
    ensure!(
        !name.is_empty()
            && !name.contains(['/', '\0', '\n', '\r'])
            && Path::new(name).components().count() == 1
            && matches!(
                Path::new(name).components().next(),
                Some(Component::Normal(_))
            ),
        "unit name must be a single filename"
    );
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;
    temporary.write_all(text.as_bytes())?;
    temporary.flush()?;

    if selinux_enabled {
        let (lookup, label) = tools.context("SELinux requires pinned unit-label tools")?;
        for tool in [lookup, label] {
            let path = super::normalized_path(tool)?;
            ensure!(
                path.starts_with("/nix/store") && path.components().count() >= 5,
                "unit-label tool is not an immutable store executable"
            );
        }
        let canonical = Path::new("/usr/lib/systemd/system").join(name);
        let output = runner
            .run(
                Path::new(lookup),
                &[
                    OsStr::new("-n"),
                    OsStr::new("-m"),
                    OsStr::new("file"),
                    canonical.as_os_str(),
                ],
            )
            .await?;
        let context = std::str::from_utf8(&output)?.trim();
        ensure!(
            !context.is_empty()
                && context != "<<none>>"
                && !context
                    .chars()
                    .any(|character| character.is_whitespace() || character == '\0'),
            "policy returned no single unit context"
        );
        runner
            .run(
                Path::new(label),
                &[OsStr::new(context), temporary.path().as_os_str()],
            )
            .await?;
    }

    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(directory.join(name))
        .map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOOLS: Option<(&str, &str)> = Some((
        "/nix/store/00000000000000000000000000000000-labels/sbin/matchpathcon",
        "/nix/store/00000000000000000000000000000000-labels/sbin/setfilecon",
    ));

    struct ObservedLabeler {
        directory: std::path::PathBuf,
        context: Vec<u8>,
        fail_at: Option<usize>,
        calls: usize,
    }

    impl LabelRunner for ObservedLabeler {
        async fn run(&mut self, executable: &Path, arguments: &[&OsStr]) -> Result<Vec<u8>> {
            self.calls += 1;
            ensure!(
                self.fail_at != Some(self.calls),
                "injected label-tool failure"
            );
            if self.calls == 1 {
                assert_eq!(executable, Path::new(TOOLS.unwrap().0));
                assert_eq!(
                    arguments,
                    ["-n", "-m", "file", "/usr/lib/systemd/system/example.mount"].map(OsStr::new)
                );
                Ok(self.context.clone())
            } else {
                assert_eq!(executable, Path::new(TOOLS.unwrap().1));
                assert_eq!(
                    arguments[0],
                    OsStr::new("system_u:object_r:systemd_unit_t:s0")
                );
                let staged = Path::new(arguments[1]);
                assert_eq!(staged.parent(), Some(self.directory.as_path()));
                assert_eq!(fs::read_to_string(staged)?, "new unit\n");
                assert!(!self.directory.join("example.mount").exists());
                Ok(Vec::new())
            }
        }
    }

    fn labeler(directory: &Path) -> ObservedLabeler {
        ObservedLabeler {
            directory: directory.to_owned(),
            context: b"system_u:object_r:systemd_unit_t:s0\n".to_vec(),
            fail_at: None,
            calls: 0,
        }
    }

    #[tokio::test]
    async fn labeling_observes_complete_staged_bytes_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let mut observer = labeler(directory.path());
        publish_with_runner(
            directory.path(),
            "example.mount",
            "new unit\n",
            true,
            TOOLS,
            &mut observer,
        )
        .await
        .unwrap();
        assert_eq!(observer.calls, 2);
        assert_eq!(
            fs::read_to_string(directory.path().join("example.mount")).unwrap(),
            "new unit\n"
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn failed_labeling_preserves_destination_and_removes_scratch() {
        for fail_at in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let destination = directory.path().join("example.mount");
            fs::write(&destination, "previous unit").unwrap();
            let mut observer = labeler(directory.path());
            observer.fail_at = Some(fail_at);
            assert!(
                publish_with_runner(
                    directory.path(),
                    "example.mount",
                    "new unit\n",
                    true,
                    TOOLS,
                    &mut observer
                )
                .await
                .is_err()
            );
            assert_eq!(fs::read_to_string(destination).unwrap(), "previous unit");
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        }
    }

    #[tokio::test]
    async fn missing_or_ambiguous_context_never_runs_the_labeler() {
        for context in [b"".as_slice(), b"<<none>>\n", b"first second", b"context\0"] {
            let directory = tempfile::tempdir().unwrap();
            let mut observer = labeler(directory.path());
            observer.context = context.to_vec();
            assert!(
                publish_with_runner(
                    directory.path(),
                    "example.mount",
                    "new unit\n",
                    true,
                    TOOLS,
                    &mut observer
                )
                .await
                .is_err()
            );
            assert_eq!(observer.calls, 1);
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn selinux_without_pinned_tools_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let mut observer = labeler(directory.path());
        assert!(
            publish_with_runner(
                directory.path(),
                "example.mount",
                "new unit\n",
                true,
                None,
                &mut observer
            )
            .await
            .is_err()
        );
        assert_eq!(observer.calls, 0);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn invalid_unit_names_never_create_scratch_or_run_tools() {
        let directory = tempfile::tempdir().unwrap();
        let mut observer = labeler(directory.path());
        for name in [
            "",
            ".",
            "..",
            "../example.mount",
            "example.mount/",
            "bad\0.mount",
            "bad\n.mount",
        ] {
            assert!(
                publish_with_runner(
                    directory.path(),
                    name,
                    "new unit\n",
                    true,
                    TOOLS,
                    &mut observer
                )
                .await
                .is_err()
            );
        }
        assert_eq!(observer.calls, 0);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn mutable_or_noncanonical_tools_are_rejected_before_execution() {
        let directory = tempfile::tempdir().unwrap();
        let mut observer = labeler(directory.path());
        for lookup in [
            "matchpathcon",
            "/tmp/matchpathcon",
            "/nix/store/tool/../bin/matchpathcon",
        ] {
            let tools = Some((lookup, TOOLS.unwrap().1));
            assert!(
                publish_with_runner(
                    directory.path(),
                    "example.mount",
                    "new unit\n",
                    true,
                    tools,
                    &mut observer
                )
                .await
                .is_err()
            );
        }
        assert_eq!(observer.calls, 0);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn disabled_selinux_needs_no_tools_and_never_replaces_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let mut observer = labeler(directory.path());
        publish_with_runner(
            directory.path(),
            "example.mount",
            "new unit\n",
            false,
            None,
            &mut observer,
        )
        .await
        .unwrap();
        assert!(
            publish_with_runner(
                directory.path(),
                "example.mount",
                "replacement",
                false,
                None,
                &mut observer
            )
            .await
            .is_err()
        );
        assert_eq!(observer.calls, 0);
        assert_eq!(
            fs::read_to_string(directory.path().join("example.mount")).unwrap(),
            "new unit\n"
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
