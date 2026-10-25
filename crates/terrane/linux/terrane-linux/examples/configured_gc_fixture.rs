//! Exercises configured local collection only in explicitly invoked guest actors.
//!
//! `setup ROOT UID` creates genuine Original history and an unreferenced native
//! pack, then removes private authority. `run ROOT UID` installs the production
//! collector boundary before its executor and public-key-only reopen. An external
//! driver observes real time, pack absence and SIGTERM shutdown. `verify ROOT UID`
//! checks durable deletion, fresh checkpoints and an ordinary authenticated read.
//! Decoded journals are observations; only the production collector makes effects.

#[path = "configured_gc_fixture/observe.rs"]
mod observe;

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
    codec::{Codec, EncodedChunk, encode_envelope},
    identity::{IdentityKind, TERRANE_V1},
    refs::{CommitSource, Locality, PrincipalKind},
    surface::View,
};
use terrane_linux::configured_gc;
use terrane_sdk::{
    bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig},
    config::Config,
    pack::PackId,
    ref_advance::CommitTiming,
    repository::{
        CommitMetadata, LocalAuthorityParameters, LocalRepositoryLocation, LocalRepositoryPolicy,
        MetadataValidator, Repository,
    },
    role::Role,
    store::{ChunkPosition, ChunkUpload, ContentStore, ContentUpload, TokioClock, TokioLocalFs},
};

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

const MAIN: &str = "refs/heads/_/main";
const PAYLOAD: &[u8] = b"live signed configured collector witness\n";
const ORPHAN: &[u8] = b"unreferenced native configured collector witness\n";

fn main() -> ExitCode {
    match dispatch() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("configured GC fixture failed");
            ExitCode::FAILURE
        }
    }
}

fn dispatch() -> FixtureResult<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let [mode, root, owner] = arguments.as_slice() else {
        return Err("expected MODE ROOT OWNER_UID".into());
    };
    let owner: u32 = owner.parse()?;
    let root = Path::new(root);
    if owner == u32::MAX || !root.is_absolute() || root.parent().is_none() {
        return Err("invalid explicit fixture location or owner".into());
    }
    if mode == "run" {
        check_owner(root, owner)?;
        let config = Config::parse(&fs::read_to_string(root.join("config.toml"))?)?;
        return configured_gc::run_service(&config, Role::Gc, || {
            println!("CONFIGURED_GC_READY");
            io::stdout().flush()
        })
        .map_err(Into::into);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match mode.as_str() {
        "setup" => runtime.block_on(setup(root, owner)),
        "verify" => runtime.block_on(verify(root, owner)),
        _ => Err("unknown fixture mode".into()),
    }
}

async fn setup(root: &Path, owner: u32) -> FixtureResult<()> {
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    check_owner(root, owner)?;
    let location = LocalRepositoryLocation {
        bucket: root.join("bucket"),
        authority: root.join("authority"),
    };
    let (repository, authority) = Repository::initialize_local_with_seed(
        &location,
        LocalAuthorityParameters {
            owner_uid: owner,
            authority: Authority {
                issuer: "configured-gc-fixture".into(),
                key_id: "initial".into(),
                subject: "fixture-owner".into(),
                kind: PrincipalKind::Human,
                groups: Vec::new(),
                not_after: u64::MAX,
                not_before: None,
                token_id: *PackId::generate(&TokioLocalFs).await?.as_bytes(),
                grants: vec![Grant::new("refs/**".into(), Verbs::new(31)?)?],
                workload: None,
            },
        },
        LocalRepositoryPolicy {
            store_name: "fixture".into(),
            domain: "public".into(),
            default_private_domain: "private:fixture".into(),
            acl: vec![("fixture-owner".into(), 31)],
            locality: Locality::default(),
            timing: CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            policy_authority: Some(MAIN.into()),
            bootstrap_properties: Vec::new(),
        },
        MAIN,
        [7; 32],
        TokioLocalFs,
        TokioClock,
    )
    .await?;
    let source = root.join("source");
    fs::create_dir(&source)?;
    write_private(&source.join("file"), PAYLOAD)?;
    let mut session = repository.begin(MAIN, authority.token(), "sdk").await?;
    repository
        .commit_directory(
            &mut session,
            &source,
            &authority,
            CommitMetadata {
                message: "Prepare configured collector witness".into(),
                process: "configured-gc-fixture-setup".into(),
                source: CommitSource::Built,
            },
        )
        .await?;
    let head = repository
        .ref_head(MAIN, authority.token(), "sdk")
        .await?
        .ok_or("missing genuine committed head")?;
    write_private(&root.join("expected.ref"), &head.encode()?)?;

    // Only the independent verifier receives this read-only capability. The
    // production GC configuration has public verification keys and no token.
    let terminal: [u8; 32] = fs::read(location.authority.join("terminal.seed"))?
        .try_into()
        .map_err(|_| "invalid terminal seed length")?;
    let token = Token::decode(authority.token())?
        .attenuate(
            Attenuation {
                grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
                ..Attenuation::default()
            },
            &terminal,
            public_key_from_secret(&terminal),
        )?
        .encode();
    write_private(&root.join("verify-read.cap"), &token)?;
    let key = authority.issuer_key();
    let public: String = key
        .public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    write_private(
        &root.join("issuer.pub"),
        format!(
            "version = 1\nissuer = {:?}\nkey_id = {:?}\npublic_key = {public:?}\n",
            key.issuer, key.key_id,
        )
        .as_bytes(),
    )?;

    let profile = repository.chunk_profile().clone();
    let bucket = FileBucket::open(
        FileBucketConfig {
            root: location.bucket.clone(),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: profile.clone(),
            locality: Locality::default(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: None,
            }),
        },
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(profile.clone()),
    )
    .await?;
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, ORPHAN)?;
    let encoded = encode_envelope(EncodedChunk {
        codec: Codec::Raw,
        body: ORPHAN,
    });
    let uploaded = bucket
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: &encoded,
            identity: &identity,
            declared_plaintext_len: ORPHAN.len(),
            position: ChunkPosition::Final,
            profile: &profile,
        }))
        .await?;
    if uploaded != identity {
        return Err("native admission returned another identity".into());
    }
    let pack = observe::find_pack(&location.bucket, identity.terrane_v1_digest()?)?;
    write_private(&root.join("expected.pack"), pack.as_bytes())?;
    write_private(
        &root.join("config.toml"),
        configuration(root, owner).as_bytes(),
    )?;
    for name in ["issuer.seed", "terminal.seed", "token.cbor"] {
        fs::remove_file(location.authority.join(name))?;
    }
    println!("CONFIGURED_GC_SETUP original-head public-keys-only native-orphan");
    Ok(())
}

async fn verify(root: &Path, owner: u32) -> FixtureResult<()> {
    check_owner(root, owner)?;
    for name in ["issuer.seed", "terminal.seed", "token.cbor"] {
        if root.join("authority").join(name).try_exists()? {
            return Err("private authority unexpectedly present".into());
        }
    }
    observe::verify_deletion(root)?;
    let config = Config::parse(&fs::read_to_string(root.join("config.toml"))?)?;
    let repository = config
        .open_local_maintenance(Role::Gc, TokioLocalFs, TokioClock)
        .await?;
    let token = fs::read(root.join("verify-read.cap"))?;
    let head = repository
        .ref_head(MAIN, &token, "sdk")
        .await?
        .ok_or("lost live head")?;
    if head.encode()? != fs::read(root.join("expected.ref"))? {
        return Err("live head changed during collection".into());
    }
    let (_, bytes) = repository
        .read_file(&View::parse(MAIN)?, b"file", &token, "sdk")
        .await?;
    if bytes != PAYLOAD {
        return Err("live signed payload changed during collection".into());
    }
    println!("CONFIGURED_GC_VERIFIED full-D exact-Done fresh-cycles live-signed-read");
    Ok(())
}

fn configuration(root: &Path, owner: u32) -> String {
    let root = root.display();
    format!(
        r#"role = "gc"
store = "bucket(file://{root}/bucket)"
[tokens]
issuer_public_keys = ["file:{root}/issuer.pub"]
[local_repository]
authority_directory = "{root}/authority"
issuer = "configured-gc-fixture"
key_id = "initial"
owner_uid = {owner}
store_name = "fixture"
domain = "public"
default_private_domain = "private:fixture"
current_reference = "refs/heads/_/main"
policy_authority = "refs/heads/_/main"
acl = [{{ principal = "fixture-owner", verbs = ["read", "fork", "commit", "tag", "admin"] }}]
[local_repository.timing]
maximum_ms = 30000
grace_ms = 60000
margin_ms = 10000
[gc]
lease_seconds = 300
poll_ms = 100
cycle_interval_ms = 1000
mark_batch = 32
maintenance_batch = 8
deletion_seconds = 60
"#
    )
}

fn check_owner(root: &Path, owner: u32) -> FixtureResult<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        return Err("unexpected fixture ownership or permissions".into());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_fixture_configuration_passes_whole_service_preflight() -> FixtureResult<()> {
        let config = Config::parse(&configuration(Path::new("/unopened/fixture"), 840))?;

        configured_gc::preflight(&config, Role::Gc)?;
        Ok(())
    }
}
