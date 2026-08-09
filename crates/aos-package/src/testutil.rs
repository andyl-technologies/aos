//! Test-only git helpers insulated from the host's git configuration.
//!
//! Test fixtures must behave identically on every machine, but plain `git`
//! invocations read `~/.gitconfig` and the system config — a host that sets
//! `commit.gpgsign`, `init.templateDir`, or similar breaks fixture setup in
//! ways unrelated to the code under test. These helpers pin the relevant
//! environment so fixture repositories are built hermetically.
//!
//! Only fixture *setup* goes through here. Code under test keeps spawning
//! git the way production does: tolerating host configuration is part of
//! its contract.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

fn apply_builder_identity(command: &mut Command, preload: Option<OsString>) {
    if let Some(preload) = preload {
        command.env("LD_PRELOAD", preload);
    }
}

/// Build a git command that ignores global and system configuration and
/// carries a fixed author/committer identity.
pub(crate) fn git_command(dir: &Path) -> Command {
    let mut cmd = crate::gitcmd::hermetic();
    crate::gitcmd::add_ssh_program_config(&mut cmd);
    apply_builder_identity(&mut cmd, std::env::var_os("AOS_TEST_IDENTITY_PRELOAD"));
    cmd.current_dir(dir)
        .env("GIT_AUTHOR_NAME", "AOS Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "AOS Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com");
    cmd
}

/// Run a hermetic git command in `dir`, panicking on failure.
pub(crate) fn git(dir: &Path, args: &[&str]) -> String {
    let output = git_command(dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running git {} in {}: {e}", args.join(" "), dir.display()));
    assert!(
        output.status.success(),
        "git {} failed in {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        dir.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn builder_identity_is_scoped_to_the_child_command() {
        let mut command = Command::new("git");
        apply_builder_identity(&mut command, Some(OsString::from("/build/identity.so")));

        let preload = command
            .get_envs()
            .find_map(|(key, value)| (key == OsStr::new("LD_PRELOAD")).then_some(value))
            .flatten();
        assert_eq!(preload, Some(OsStr::new("/build/identity.so")));
    }
}
