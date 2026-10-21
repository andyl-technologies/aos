//! Exercises local porcelain in separate processes on private filesystem fixtures.
//!
//! These tests verify the shipped parser, persisted local authority, actual
//! repository publication, authorized reflog history and registered SDK checkout.
//! They do not qualify any particular filesystem implementation or the mandatory ext4 workflow.

#![forbid(unsafe_code)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    process::{Command, Output},
    time::UNIX_EPOCH,
};

use terrane_sdk::store::{Clock, LocalFs, TokioClock, TokioLocalFs};

type Error = Box<dyn std::error::Error>;

#[tokio::test]
async fn local_log_reports_committed_provenance_and_honors_sequence_filter() -> Result<(), Error> {
    let fixture = Fixture::new().await?;
    fixture.initialize()?;
    let issuer = fs::read(fixture.authority.join("issuer.seed"))?;
    let terminal = fs::read(fixture.authority.join("terminal.seed"))?;
    fs::create_dir(fixture.root.join("source"))?;
    fs::write(fixture.root.join("source/file"), b"history fixture\n")?;
    let commit = fixture.succeed(
        "commit",
        &[
            &fixture.path_text("source")?,
            "--message",
            "Record CLI history",
        ],
    )?;

    let history = fixture.succeed("log", &[])?;
    let lines: Vec<_> = history.lines().collect();
    assert!(lines.len() >= 2);
    for (index, line) in lines.iter().enumerate() {
        assert!(line.starts_with(&format!("sequence={} commit=", index + 1)));
        assert!(line.contains(" writer_epoch="));
        assert!(line.contains(" at="));
        assert!(line.contains(" principal=\"owner\" reason=Commit"));
    }
    assert!(
        lines
            .last()
            .ok_or("missing CLI event")?
            .contains(&format!("commit={commit} "))
    );

    let last = fixture.succeed("log", &["--from-sequence", &lines.len().to_string()])?;
    assert_eq!(last, *lines.last().ok_or("missing CLI event")?);
    assert!(
        fixture
            .succeed("log", &["--from-sequence", &u64::MAX.to_string()])?
            .is_empty()
    );
    assert!(
        !fixture
            .invoke("log", &["--reference", "refs/tags/release"])?
            .status
            .success()
    );
    assert_eq!(fs::read(fixture.authority.join("issuer.seed"))?, issuer);
    assert_eq!(fs::read(fixture.authority.join("terminal.seed"))?, terminal);
    Ok(())
}

struct Fixture {
    root: PathBuf,
    bucket: String,
    authority: PathBuf,
    uid: String,
}

impl Fixture {
    async fn new() -> Result<Self, Error> {
        let entropy = TokioLocalFs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = std::env::temp_dir().join(format!("terrane-cli-{suffix}"));
        TokioLocalFs.create_dir_new(&root).await?;
        let uid = fs::symlink_metadata(&root)?.uid().to_string();
        let bucket = format!("file://{}/bucket", root.display());
        let authority = root.join("authority");

        Ok(Self {
            root,
            bucket,
            authority,
            uid,
        })
    }

    fn invoke(&self, command: &str, arguments: &[&str]) -> Result<Output, Error> {
        let clock = TokioClock;
        let started = clock.monotonic();
        eprintln!("starting {command} {arguments:?}");
        let output = Command::new(env!("CARGO_BIN_EXE_terrane"))
            .arg(command)
            .args(["--bucket", &self.bucket, "--owner-uid", &self.uid])
            .arg("--authority")
            .arg(&self.authority)
            .args(arguments)
            .output()?;
        let elapsed = clock
            .monotonic()
            .checked_sub(started)
            .ok_or("monotonic clock moved backwards")?;
        eprintln!("finished {command} after {elapsed:?}");
        Ok(output)
    }

    fn succeed(&self, command: &str, arguments: &[&str]) -> Result<String, Error> {
        let output = self.invoke(command, arguments)?;
        assert!(
            output.status.success(),
            "{command} {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }

    fn initialize(&self) -> Result<(), Error> {
        let not_after = (TokioClock.now().duration_since(UNIX_EPOCH)?.as_secs() + 3600).to_string();
        let output = self.succeed("init", &["--not-after", &not_after])?;
        assert_eq!(output, "initialized refs/heads/_/main");
        Ok(())
    }

    fn path_text(&self, name: &str) -> Result<String, Error> {
        self.root
            .join(name)
            .into_os_string()
            .into_string()
            .map_err(|_| "temporary path is not UTF-8".into())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn separate_invocations_initialize_commit_fork_merge_and_checkout() -> Result<(), Error> {
    let fixture = Fixture::new().await?;
    fixture.initialize()?;
    assert_eq!(fs::metadata(&fixture.authority)?.mode() & 0o7777, 0o700);
    for name in ["issuer.seed", "terminal.seed", "token.cbor"] {
        assert_eq!(
            fs::metadata(fixture.authority.join(name))?.mode() & 0o7777,
            0o600
        );
    }
    let issuer = fs::read(fixture.authority.join("issuer.seed"))?;
    let terminal = fs::read(fixture.authority.join("terminal.seed"))?;

    let source = fixture.root.join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("original"), b"original content\n")?;
    fs::create_dir(source.join("nested"))?;
    fs::write(source.join("nested/executable"), b"executable content\n")?;
    fs::set_permissions(
        source.join("nested/executable"),
        fs::Permissions::from_mode(0o750),
    )?;
    symlink("original", source.join("link"))?;

    let original = fixture.succeed(
        "commit",
        &[
            &fixture.path_text("source")?,
            "--message",
            "Import directory",
        ],
    )?;
    assert_eq!(original.len(), 64);
    assert!(original.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let fork = fixture.succeed(
        "fork",
        &["refs/heads/_/feature", "--message", "Fork feature"],
    )?;
    assert_eq!(fork.len(), 64);

    fs::write(source.join("feature"), b"feature content\n")?;
    let feature = fixture.succeed(
        "commit",
        &[
            "--reference",
            "refs/heads/_/feature",
            &fixture.path_text("source")?,
            "--message",
            "Add feature",
        ],
    )?;
    assert_ne!(feature, fork);

    fs::remove_file(source.join("feature"))?;
    fs::write(source.join("main"), b"main content\n")?;
    let main = fixture.succeed(
        "commit",
        &[&fixture.path_text("source")?, "--message", "Add main file"],
    )?;
    let merged = fixture.succeed(
        "merge",
        &["refs/heads/_/feature", "--message", "Merge feature"],
    )?;
    assert_ne!(merged, main);
    assert_ne!(merged, feature);

    let checkout = fixture.succeed(
        "checkout",
        &["refs/heads/_/main", &fixture.path_text("checkout")?],
    )?;
    assert_eq!(checkout, merged);
    let result = fixture.root.join("checkout");
    assert_eq!(fs::read(result.join("original"))?, b"original content\n");
    assert_eq!(fs::read(result.join("feature"))?, b"feature content\n");
    assert_eq!(fs::read(result.join("main"))?, b"main content\n");
    assert_eq!(
        fs::read_link(result.join("link"))?,
        PathBuf::from("original")
    );
    assert_eq!(
        fs::metadata(result.join("nested/executable"))?.mode() & 0o7777,
        0o750
    );

    let historical = fixture.succeed(
        "checkout",
        &[
            &format!("commit:{original}"),
            &fixture.path_text("historical")?,
        ],
    )?;
    assert_eq!(historical, original);
    assert_eq!(
        fs::read(fixture.root.join("historical/original"))?,
        b"original content\n"
    );
    assert!(!fixture.root.join("historical/feature").exists());
    assert!(!fixture.root.join("historical/main").exists());
    assert_eq!(fs::read(fixture.authority.join("issuer.seed"))?, issuer);
    assert_eq!(fs::read(fixture.authority.join("terminal.seed"))?, terminal);
    Ok(())
}

#[tokio::test]
async fn local_commands_refuse_reinitialization_and_unsafe_existing_authority() -> Result<(), Error>
{
    let fixture = Fixture::new().await?;
    fixture.initialize()?;
    let credential_names = ["issuer.seed", "terminal.seed", "token.cbor"];
    let credentials = credential_names
        .iter()
        .map(|name| fs::read(fixture.authority.join(name)))
        .collect::<Result<Vec<_>, _>>()?;

    let result = fixture.invoke("init", &["--not-after", "18446744073709551615"])?;
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert_eq!(
        String::from_utf8(result.stderr)?.trim(),
        "terrane: local bucket already exists"
    );
    for (name, bytes) in credential_names.iter().zip(&credentials) {
        assert_eq!(&fs::read(fixture.authority.join(name))?, bytes);
    }

    fs::set_permissions(&fixture.authority, fs::Permissions::from_mode(0o755))?;
    let result = fixture.invoke(
        "checkout",
        &["refs/heads/_/main", &fixture.path_text("denied")?],
    )?;
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert_eq!(
        String::from_utf8(result.stderr)?.trim(),
        "terrane: repository access denied"
    );
    assert!(!fixture.root.join("denied").exists());
    for (name, bytes) in credential_names.iter().zip(&credentials) {
        assert_eq!(&fs::read(fixture.authority.join(name))?, bytes);
    }

    fs::set_permissions(&fixture.authority, fs::Permissions::from_mode(0o700))?;
    let restored = fixture.succeed(
        "checkout",
        &["refs/heads/_/main", &fixture.path_text("restored")?],
    )?;
    assert_eq!(restored.len(), 64);
    assert!(restored.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(fs::read_dir(fixture.root.join("restored"))?.count(), 0);
    Ok(())
}

#[tokio::test]
async fn configured_role_parser_and_unavailable_dispatch_remain_compatible() -> Result<(), Error> {
    let fixture = Fixture::new().await?;
    let config = fixture.root.join("role.toml");
    for role in ["serve", "realize", "fuse-worker", "publish", "gc", "job"] {
        fs::write(
            &config,
            format!("role = \"{role}\"\nstore = \"bucket(file:///tmp/store)\"\n"),
        )?;
        let invoke = |arguments: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_terrane"))
                .arg("--config")
                .arg(&config)
                .args(arguments)
                .output()
        };
        let result = invoke(&["--role", role, "--check-config"])?;
        assert!(result.status.success());
        assert!(
            String::from_utf8(result.stdout)?.contains(&format!("syntax valid for role {role}"))
        );

        let other_role = if role == "serve" { "gc" } else { "serve" };
        let result = invoke(&["--role", other_role, "--check-config"])?;
        assert!(!result.status.success());
        assert!(String::from_utf8(result.stderr)?.contains("differs"));

        let result = invoke(&[])?;
        assert!(!result.status.success());
        let stderr = String::from_utf8(result.stderr)?;
        assert!(stderr.contains(role));
        assert!(stderr.contains("unavailable"));

        let result = invoke(&["init", "--not-after", "1"])?;
        assert!(!result.status.success());
    }
    Ok(())
}
