//! Exercises retained initrd transport with genuine private Nix stores.

use super::*;
use std::os::unix::fs::symlink;

fn selected_nix_store() -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os("AOS_NIX_STORE").expect("tests require AOS_NIX_STORE"));
    aos_nix::executable::validate_store_executable(&path, "test Nix store").unwrap();
    path
}

fn private_store(executable: &Path, directory: &Path) -> Command {
    let mut command = Command::new(executable);
    command.args(["--store", &format!("local?root={}", directory.display())]);
    command
}

fn add_file(command: &Command, directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let file = directory.join(name);
    fs::write(&file, bytes).unwrap();
    let output = base_command(command)
        .arg("--add")
        .arg(file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

fn add_reference_file(
    executable: &Path,
    source: &Command,
    name: &str,
    reference: &Path,
) -> PathBuf {
    let evaluator = executable.parent().unwrap().join("nix-instantiate");
    aos_nix::executable::validate_store_executable(&evaluator, "test Nix evaluator").unwrap();
    let expression =
        format!("builtins.toFile {name:?} (\"reference \" + builtins.storePath {reference:?})");
    let output = Command::new(evaluator)
        .args(source.get_args())
        .args(["--eval", "--read-write-mode", "--json", "--expr"])
        .arg(expression)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(serde_json::from_slice::<String>(&output.stdout).unwrap())
}

fn import_roots(source: &Command, receiver: &Command, roots: &BTreeSet<PathBuf>) {
    let export = base_command(source)
        .arg("--export")
        .args(roots)
        .output()
        .unwrap();
    assert!(export.status.success());
    let mut child = base_command(receiver)
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&export.stdout)
        .unwrap();
    assert!(child.wait().unwrap().success());
}

fn assert_valid(command: &Command, roots: &BTreeSet<PathBuf>) {
    assert!(
        base_command(command)
            .arg("--check-validity")
            .args(roots)
            .status()
            .unwrap()
            .success()
    );
}

struct TransportFixture {
    directory: tempfile::TempDir,
    executable: PathBuf,
    source: Command,
    common: PathBuf,
    old: PathBuf,
    new: PathBuf,
}

impl TransportFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let executable = selected_nix_store();
        let source = private_store(&executable, &directory.path().join("source-store"));
        let common = add_file(
            &source,
            directory.path(),
            "shared-input",
            b"shared immutable input\n",
        );
        let old = add_reference_file(&executable, &source, "old-input", &common);
        let new = add_reference_file(&executable, &source, "new-input", &common);
        Self {
            directory,
            executable,
            source,
            common,
            old,
            new,
        }
    }

    fn journal(&self) -> PathBuf {
        let journal = self.directory.path().join("journal");
        fs::create_dir(&journal).unwrap();
        journal
    }

    fn preserve(&mut self, journal: &Path) {
        let old = BTreeSet::from([self.common.clone(), self.old.clone()]);
        let new = BTreeSet::from([self.common.clone(), self.new.clone()]);
        preserve_with(
            &mut self.source,
            journal,
            &[self.old.to_string_lossy().into_owned()],
            &old,
            &new,
        )
        .unwrap();
    }
}

#[test]
fn symmetric_image_delta_restores_both_directions_with_exact_references_and_retry() {
    let mut fixture = TransportFixture::new();
    let journal = fixture.journal();
    fixture.preserve(&journal);
    let manifest = read_manifest(&journal.join(DIRECTORY)).unwrap().unwrap();
    assert_eq!(
        manifest.roots,
        BTreeSet::from([fixture.old.clone(), fixture.new.clone()])
    );

    for (label, installed) in [
        ("old-receiver", &fixture.old),
        ("new-receiver", &fixture.new),
    ] {
        let receiver_directory = fixture.directory.path().join(label);
        let mut receiver = private_store(&fixture.executable, &receiver_directory);
        import_roots(
            &fixture.source,
            &receiver,
            &BTreeSet::from([fixture.common.clone(), installed.clone()]),
        );
        restore_with(&mut receiver, &journal).unwrap();
        restore_with(&mut receiver, &journal).unwrap();
        let expected = BTreeSet::from([
            fixture.common.clone(),
            fixture.old.clone(),
            fixture.new.clone(),
        ]);
        assert_valid(&receiver, &expected);
        for root in [&fixture.old, &fixture.new] {
            assert_eq!(
                closure_paths(
                    &mut base_command(&receiver),
                    &BTreeSet::from([root.clone()])
                )
                .unwrap(),
                BTreeSet::from([root.clone(), fixture.common.clone()])
            );
            let relative = root.strip_prefix("/").unwrap();
            let original = base_command(&fixture.source)
                .arg("--dump")
                .arg(fixture.directory.path().join("source-store").join(relative))
                .output()
                .unwrap();
            let restored = base_command(&receiver)
                .arg("--dump")
                .arg(receiver_directory.join(relative))
                .output()
                .unwrap();
            assert!(
                original.status.success(),
                "original NAR dump: {}",
                String::from_utf8_lossy(&original.stderr)
            );
            assert!(
                restored.status.success(),
                "restored NAR dump: {}",
                String::from_utf8_lossy(&restored.stderr)
            );
            assert_eq!(restored.stdout, original.stdout);
        }
    }
}

#[test]
fn changed_truncated_or_aliased_capsules_are_refused_without_rewriting_manifest() {
    let mut fixture = TransportFixture::new();
    let journal = fixture.journal();
    fixture.preserve(&journal);
    let directory = journal.join(DIRECTORY);
    let manifest_bytes = fs::read(directory.join(MANIFEST)).unwrap();
    let manifest = read_manifest(&directory).unwrap().unwrap();
    let payload = payload_path(&directory, manifest.payload.as_ref().unwrap()).unwrap();
    let original = fs::read(&payload).unwrap();
    let mut receiver = private_store(
        &fixture.executable,
        &fixture.directory.path().join("receiver"),
    );

    let mut changed = original.clone();
    changed[0] ^= 1;
    for bytes in [&changed[..], &original[..original.len() - 1]] {
        fs::write(&payload, bytes).unwrap();
        assert!(restore_with(&mut receiver, &journal).is_err());
        assert_eq!(fs::read(directory.join(MANIFEST)).unwrap(), manifest_bytes);
    }
    fs::remove_file(&payload).unwrap();
    let outside = fixture.directory.path().join("outside-payload");
    fs::write(&outside, &original).unwrap();
    symlink(&outside, &payload).unwrap();
    assert!(restore_with(&mut receiver, &journal).is_err());
    assert_eq!(fs::read(&outside).unwrap(), original);
    fs::remove_file(&payload).unwrap();
    fs::create_dir(&payload).unwrap();
    assert!(restore_with(&mut receiver, &journal).is_err());
}

#[test]
fn failed_export_preserves_previous_manifest_and_payload() {
    let mut fixture = TransportFixture::new();
    let journal = fixture.journal();
    fixture.preserve(&journal);
    let directory = journal.join(DIRECTORY);
    let before = fs::read(directory.join(MANIFEST)).unwrap();
    let manifest = read_manifest(&directory).unwrap().unwrap();
    let path = payload_path(&directory, manifest.payload.as_ref().unwrap()).unwrap();
    let payload = fs::read(&path).unwrap();
    // A different actual empty Nix database cannot export these registered roots.
    let mut empty = private_store(
        &fixture.executable,
        &fixture.directory.path().join("empty-store"),
    );
    assert!(
        preserve_with(
            &mut empty,
            &journal,
            &[fixture.old.to_string_lossy().into_owned()],
            &BTreeSet::new(),
            &BTreeSet::new()
        )
        .is_err()
    );
    assert_eq!(fs::read(directory.join(MANIFEST)).unwrap(), before);
    assert_eq!(fs::read(path).unwrap(), payload);
}

#[test]
fn empty_delta_does_not_dispatch_nix_and_aliases_cannot_own_transport() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("journal");
    fs::create_dir(&journal).unwrap();
    let mut unavailable = Command::new(directory.path().join("no-executable"));
    preserve_with(
        &mut unavailable,
        &journal,
        &[],
        &BTreeSet::new(),
        &BTreeSet::new(),
    )
    .unwrap();
    restore_with(&mut unavailable, &journal).unwrap();
    assert!(
        read_manifest(&journal.join(DIRECTORY))
            .unwrap()
            .unwrap()
            .payload
            .is_none()
    );

    let alias = directory.path().join("alias");
    symlink(&journal, &alias).unwrap();
    assert!(
        preserve_with(
            &mut unavailable,
            &alias,
            &[],
            &BTreeSet::new(),
            &BTreeSet::new()
        )
        .is_err()
    );
    assert!(restore_with(&mut unavailable, &alias).is_err());
    let manifest = journal.join(DIRECTORY).join(MANIFEST);
    let bytes = fs::read(&manifest).unwrap();
    fs::remove_file(&manifest).unwrap();
    let outside = directory.path().join("outside-manifest");
    fs::write(&outside, &bytes).unwrap();
    symlink(&outside, &manifest).unwrap();
    assert!(restore_with(&mut unavailable, &journal).is_err());
    assert_eq!(fs::read(outside).unwrap(), bytes);
    fs::remove_file(&manifest).unwrap();
    symlink(directory.path().join("missing-manifest"), &manifest).unwrap();
    assert!(restore_with(&mut unavailable, &journal).is_err());
    assert!(
        fs::symlink_metadata(&manifest)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn limited_writer_refuses_excess_without_partial_extra_bytes() {
    let mut writer = LimitedWriter {
        output: Vec::new(),
        remaining: 3,
    };
    writer.write_all(b"ab").unwrap();
    assert!(writer.write_all(b"cd").is_err());
    assert_eq!(writer.output, b"ab");
    assert_eq!(writer.remaining, 1);
    writer.write_all(b"c").unwrap();
    assert_eq!(writer.output, b"abc");
}

#[test]
fn writable_journal_requires_same_inode_and_rejects_foreign_and_alias_paths() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("aos/journal");
    fs::create_dir_all(&state).unwrap();
    assert_eq!(
        writable_journal(&state, root.path(), root.path()).unwrap(),
        state
    );

    let foreign = tempfile::tempdir().unwrap();
    fs::create_dir_all(foreign.path().join("aos/journal")).unwrap();
    assert!(writable_journal(&state, root.path(), foreign.path()).is_err());
    let alias = root.path().join("alias");
    symlink(&state, &alias).unwrap();
    assert!(writable_journal(&alias, root.path(), root.path()).is_err());
    assert!(writable_journal(root.path(), root.path(), root.path()).is_err());
}
