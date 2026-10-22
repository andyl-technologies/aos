//! Runs configured SDK completion in an explicitly invoked fresh process.
//!
//! Build with `--features tokio,terrane-sdk/surface-sdk`. Run `setup ROOT UID` in
//! a separate fixture process before `run ROOT UID` or `deny-late ROOT UID`.
//! Setup exclusively creates the named directory and genuine signed repository;
//! it never runs in the confined actor. The actor must already have the supplied
//! Unix identity and no capabilities. This example is not an ordinary unit test
//! and does not install a filter unless explicitly invoked in an actor mode.
//!
//! For the late-denial witness, the external fixture driver removes only
//! `second.cap` after setup. Private authority remains present, so successful
//! refusal also witnesses the absence of an instance-token fallback.
//!
//! `verify-cli ROOT UID` independently checks the actual CLI completion receipts
//! in sibling `ROOT.stdout` and `ROOT.stderr` files against the setup commit and
//! durable payloads. `verify-cli-denial ROOT UID` checks its late-token refusal.
//! These verification modes never invoke configured startup or confinement.
//! `verify-reopen-publication ROOT UID` checks the exact original snapshot
//! predecessor and permits only the existing capability probe timestamp refresh.

#[path = "configured_sdk_fixture/offline.rs"]
mod offline;

#[path = "configured_sdk_fixture/payload.rs"]
mod payload;

#[path = "configured_sdk_fixture/publication.rs"]
mod publication;

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::ExitCode,
    time::Duration,
};

use terrane_format::{
    auth::{Attenuation, Authority, Grant, Token, Verbs, public_key_from_secret},
    refs::{CommitSource, Locality, PrincipalKind},
};
use terrane_linux::configured_sdk::{self, FailureKind};
use terrane_sdk::{
    config::Config,
    ref_advance::CommitTiming,
    repository::{
        CommitMetadata, LocalAuthorityParameters, LocalRepositoryLocation, LocalRepositoryPolicy,
        Repository,
    },
    role::Role,
    store::{LocalFs, TokioClock, TokioLocalFs},
    surface::{ExposureState, ReaderMode, SchemaState},
};

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

const MAIN: &str = "refs/heads/_/main";
const PAYLOAD: &[u8] = b"independent configured SDK snapshot payload\n";

fn main() -> ExitCode {
    match dispatch() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(_) => {
            // Neither configuration parser source text nor capability-bearing
            // lower-level diagnostics are emitted by the fixture process.
            eprintln!("configured SDK fixture failed");
            ExitCode::FAILURE
        }
    }
}

fn dispatch() -> FixtureResult<&'static str> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let [command, root, owner] = arguments.as_slice() else {
        return Err("expected a fixture command followed by ROOT OWNER_UID".into());
    };
    let owner: u32 = owner.parse()?;
    if owner == u32::MAX
        || !root.starts_with('/')
        || root == "/"
        || !root
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
        || root
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err("invalid explicit fixture ownership or root".into());
    }
    if terrane_sdk::surface::registration("sdk").is_none() {
        return Err("the fixture requires the actual compiled SDK surface".into());
    }
    let root = Path::new(root);
    match command.as_str() {
        "setup" | "setup-manifest" | "setup-default-wipe" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            if command == "setup-manifest" {
                runtime.block_on(setup_payload(root, owner, &payload::manifest(), true))?;
            } else if command == "setup-default-wipe" {
                runtime.block_on(setup_payload(root, owner, PAYLOAD, false))?;
            } else {
                runtime.block_on(setup(root, owner))?;
            }
            Ok("PASS: separate-process configured SDK fixture setup")
        }
        "run" => {
            run(root, owner)?;
            Ok("PASS: actual confined SDK snapshots completed and stopped")
        }
        "deny-late" => {
            deny_late(root, owner)?;
            Ok("PASS: late exposure denial started no endpoint and used no authority fallback")
        }
        "verify-cli" => {
            verify_cli(root, owner)?;
            Ok("PASS: actual CLI receipts match the setup commit and durable SDK payloads")
        }
        "read-cache-offline" => {
            offline::run(root, owner)?;
            Ok(
                "PASS: actual confined SDK reads recovered native residents while original lower chunks are unavailable",
            )
        }
        "verify-reopen-publication" => {
            publication::verify(root, owner)?;
            Ok("PASS: original publication changed only by the exact reopen probe timestamp")
        }
        "verify-cli-denial" => {
            verify_cli_denial(root, owner)?;
            Ok("PASS: actual CLI late-token refusal left no snapshots or authority fallback")
        }
        _ => Err("unsupported fixture command".into()),
    }
}

async fn setup(root: &Path, owner: u32) -> FixtureResult<()> {
    setup_payload(root, owner, PAYLOAD, true).await
}

async fn setup_payload(
    root: &Path,
    owner: u32,
    payload: &[u8],
    explicit_wipe_none: bool,
) -> FixtureResult<()> {
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    check_owner(root, owner)?;
    let location = LocalRepositoryLocation {
        bucket: root.join("bucket"),
        authority: root.join("authority"),
    };
    let token_id = TokioLocalFs
        .random_bytes(16)
        .await?
        .try_into()
        .map_err(|_| "unexpected fixture entropy length")?;
    let (repository, authority) = Repository::initialize_local_with_seed(
        &location,
        LocalAuthorityParameters {
            owner_uid: owner,
            authority: Authority {
                issuer: "configured-sdk-fixture".into(),
                key_id: "initial".into(),
                subject: "fixture-owner".into(),
                kind: PrincipalKind::Human,
                groups: Vec::new(),
                not_after: u64::MAX,
                not_before: None,
                token_id,
                grants: vec![Grant::new("refs/**".into(), Verbs::new(31)?)?],
                workload: None,
            },
        },
        LocalRepositoryPolicy {
            store_name: "fixture".into(),
            domain: "private:fixture".into(),
            default_private_domain: "private:fixture".into(),
            acl: vec![("fixture-owner".into(), 31)],
            locality: Locality::default(),
            timing: CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            policy_authority: Some(MAIN.into()),
            // Successful sealed-cache cases explicitly sign their erasure policy.
            // The negative case leaves the private-domain zero default intact.
            bootstrap_properties: if explicit_wipe_none {
                let mut value = Vec::new();
                terrane_format::cbor::write_text(&mut value, "none");
                vec![("wipe".into(), value)]
            } else {
                Vec::new()
            },
        },
        MAIN,
        [7; 32],
        TokioLocalFs,
        TokioClock,
    )
    .await?;
    let source = root.join("source");
    fs::create_dir(&source)?;
    write_private(&source.join("file"), payload)?;
    if payload != PAYLOAD {
        write_private(&root.join("expected.payload"), payload)?;
    }
    let mut session = repository.begin(MAIN, authority.token(), "sdk").await?;
    let commit = repository
        .commit_directory(
            &mut session,
            &source,
            &authority,
            CommitMetadata {
                message: "Prepare independent configured SDK fixture".into(),
                process: "configured-sdk-fixture-setup".into(),
                source: CommitSource::Built,
            },
        )
        .await?
        .commit;

    // Setup creates explicit read-only exposure capabilities. Runtime reopening
    // temporarily reads private authority state, then drops its signing handle;
    // exposure preparation uses these files without an instance-token fallback.
    let secret: [u8; 32] = fs::read(location.authority.join("terminal.seed"))?
        .try_into()
        .map_err(|_| "unexpected fixture terminal seed length")?;
    let token = Token::decode(authority.token())?
        .attenuate(
            Attenuation {
                grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
                ..Attenuation::default()
            },
            &secret,
            public_key_from_secret(&secret),
        )?
        .encode();
    write_private(&root.join("first.cap"), &token)?;
    write_private(&root.join("second.cap"), &token)?;
    write_private(&root.join("expected.commit"), &commit)?;
    write_private(
        &root.join("config.toml"),
        configuration(root, owner).as_bytes(),
    )?;
    publication::save(root)?;
    drop(repository);
    drop(authority);
    Ok(())
}

fn configuration(root: &Path, owner: u32) -> String {
    let root = root.display();
    format!(
        r#"store = "bucket(file://{root}/bucket)"
[[expose]]
id = "first"
view = "{MAIN}"
surface = "sdk"
at = "{root}/snapshot-first"
token = "file:{root}/first.cap"
mode = {{ reader = "pinned" }}
[[expose]]
id = "second"
view = "{MAIN}"
surface = "sdk"
at = "{root}/snapshot-second"
token = "file:{root}/second.cap"
mode = {{ reader = "pinned" }}
[local_repository]
authority_directory = "{root}/authority"
issuer = "configured-sdk-fixture"
key_id = "initial"
owner_uid = {owner}
store_name = "fixture"
domain = "private:fixture"
default_private_domain = "private:fixture"
current_reference = "{MAIN}"
policy_authority = "{MAIN}"
acl = [{{ principal = "fixture-owner", verbs = ["read", "fork", "commit", "tag", "admin"] }}]
[local_repository.timing]
maximum_ms = 30000
grace_ms = 60000
margin_ms = 10000
"#
    )
}

fn run(root: &Path, owner: u32) -> FixtureResult<()> {
    check_owner(root, owner)?;
    let config = Config::parse(&fs::read_to_string(root.join("config.toml"))?)?;
    let expected = expected_commit(root)?;
    let completed = configured_sdk::run(&config, Role::Serve)?;
    let snapshots = completed.snapshots()?;
    if snapshots.len() != 2 {
        return Err("missing completed SDK snapshots".into());
    }
    for (snapshot, id) in snapshots.iter().zip(["first", "second"]) {
        let status = snapshot.status();
        if snapshot.id() != id
            || snapshot.endpoint() != root.join(format!("snapshot-{id}")).as_path()
            || status.commit != expected
            || status.surface != "sdk"
            || status.state != ExposureState::Stopped
            || status.reader != ReaderMode::Pinned
            || status.writer.is_some()
            || status.schema != SchemaState::Valid
            || status.realizer.is_some()
            || !status.features.is_empty()
            || status.last_commit.is_some()
            || fs::read(snapshot.endpoint().join("file"))? != payload::expected(root)?
        {
            return Err("SDK completion did not match the independent fixture".into());
        }
    }
    drop(completed);
    verify_payloads(root)
}

fn expected_commit(root: &Path) -> FixtureResult<[u8; 32]> {
    fs::read(root.join("expected.commit"))?
        .try_into()
        .map_err(|_| "unexpected fixture commit length".into())
}

fn verify_payloads(root: &Path) -> FixtureResult<()> {
    for id in ["first", "second"] {
        if fs::read(root.join(format!("snapshot-{id}/file")))? != payload::expected(root)? {
            return Err("stopping SDK presentation removed its durable snapshot".into());
        }
    }
    Ok(())
}

fn verify_cli(root: &Path, owner: u32) -> FixtureResult<()> {
    check_owner(root, owner)?;
    let commit: String = expected_commit(root)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let expected: String = ["first", "second"]
        .iter()
        .map(|id| {
            let endpoint = root.join(format!("snapshot-{id}"));
            format!(
                "completed SDK snapshot {id:?}: commit {commit}, state Stopped, endpoint {endpoint:?}\n"
            )
        })
        .collect();

    if fs::read(root.with_extension("stdout"))? != expected.as_bytes()
        || !fs::read(root.with_extension("stderr"))?.is_empty()
    {
        return Err("actual CLI completion did not match the independent fixture".into());
    }
    verify_payloads(root)
}

fn verify_cli_denial(root: &Path, owner: u32) -> FixtureResult<()> {
    check_owner(root, owner)?;
    if !fs::read(root.with_extension("stdout"))?.is_empty()
        || fs::read(root.with_extension("stderr"))?
            != b"terrane: configured SDK exposure preparation failed\n"
        || !absent(&root.join("second.cap"))?
        || fs::read(root.join("first.cap"))?.is_empty()
    {
        return Err("actual CLI did not preserve the expected late-token refusal".into());
    }
    for name in ["issuer.seed", "terminal.seed", "token.cbor"] {
        if fs::metadata(root.join("authority").join(name))?.len() == 0 {
            return Err("late-token refusal lost its existing authority witness".into());
        }
    }
    for id in ["first", "second"] {
        if !absent(&root.join(format!("snapshot-{id}")))? {
            return Err("actual CLI late-token refusal started an endpoint".into());
        }
    }
    Ok(())
}

fn deny_late(root: &Path, owner: u32) -> FixtureResult<()> {
    check_owner(root, owner)?;
    if !absent(&root.join("second.cap"))? || absent(&root.join("first.cap"))? {
        return Err("late-denial fixture requires only the second token to be absent".into());
    }
    let config = Config::parse(&fs::read_to_string(root.join("config.toml"))?)?;
    let error = match configured_sdk::run(&config, Role::Serve) {
        Ok(_) => return Err("missing exposure credential used an unintended fallback".into()),
        Err(error) => error,
    };
    if error.kind() != FailureKind::Preparation || !error.requires_process_exit() {
        return Err("late denial did not reach genuine exposure preparation".into());
    }
    for id in ["first", "second"] {
        if !absent(&root.join(format!("snapshot-{id}")))? {
            return Err("late preparation failure started an endpoint".into());
        }
    }
    Ok(())
}

fn check_owner(root: &Path, owner: u32) -> FixtureResult<()> {
    if fs::symlink_metadata(root)?.uid() != owner || rustix::process::geteuid().as_raw() != owner {
        return Err("fixture requires the explicitly supplied Unix identity".into());
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn absent(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}
