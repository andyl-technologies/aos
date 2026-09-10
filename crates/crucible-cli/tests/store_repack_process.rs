//! Process-boundary flight for packed-store repack porcelain.
//!
//! The test creates a sparse live pack through the library boundary, then uses
//! only the shipped CLI to plan and apply its replacement. It retains an
//! already-open reader across the CLI's generation switch to exercise the
//! inode-lifetime contract at the public process boundary.

#![cfg(target_os = "linux")]
// crucible-lint: allow clippy-disallowed-method -- this test intentionally exercises a host process boundary.
// crucible-lint: allow panic-shortcut -- assertions localize failures in one bounded process flight.
#![allow(clippy::disallowed_methods, clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crucible_cas::content_store::{
    BlobHandle, BlobStoreAdmin, ContentId, ImmutableBlobBackend, ObjectKind, PackedBlobBackend,
    PlannedDeleteDisposition,
};
use serde_json::Value;
use tempfile::TempDir;

const TARGET_PACK_BYTES: u64 = 64 * 1024;
const MAXIMUM_TEST_READ_BYTES: u64 = 1024 * 1024;

#[test]
fn public_repack_rewrites_sparse_pack_and_keeps_open_reader_valid() -> Result<(), Box<dyn Error>> {
    let fixture = RepackFixture::new()?;
    let first_bytes = vec![0x31; 12 * 1024];
    let retained_bytes = vec![0x72; 18 * 1024];
    let first = ContentId::for_bytes(ObjectKind::RamExtent, 1, &first_bytes);
    let retained = ContentId::for_bytes(ObjectKind::DiskExtent, 1, &retained_bytes);

    fixture
        .backend
        .put_if_absent(first, &BlobHandle::from_bytes(first_bytes))?;
    fixture
        .backend
        .put_if_absent(retained, &BlobHandle::from_bytes(retained_bytes.clone()))?;
    let coalesce = fixture.backend.plan_repack()?;
    fixture.backend.apply_repack(&coalesce)?;

    let mut inventory = fixture.backend.acquire_inventory_fence()?;
    assert_eq!(
        inventory.delete_candidate(first)?,
        PlannedDeleteDisposition::Deleted
    );
    drop(inventory);

    let sparse = fixture.backend.accounting()?;
    assert_eq!(sparse.logical_objects(), 1);
    assert_eq!(sparse.packs(), 1);
    let sparse_pack = only_complete_pack(&fixture.packed)?;
    let sparse_pack_name = sparse_pack
        .file_name()
        .ok_or("sparse pack has no file name")?
        .to_owned();
    let sparse_pack_bytes = fs::read(&sparse_pack)?;
    let old_reader = fixture.backend.read(retained, None)?;

    let planned = fixture.run_repack("plan", &fixture.plan)?;
    assert_eq!(planned["schema"], "crucible.cli.store-repack.v1");
    assert_eq!(planned["operation"], "plan");
    assert_eq!(planned["node"], "packed");
    assert_eq!(planned["plan_disposition"], "created");
    assert_eq!(planned["before"]["generation"], sparse.generation());
    assert_eq!(planned["before"]["physical_bytes"], sparse.physical_bytes());

    let applied = fixture.run_repack("apply", &fixture.plan)?;
    assert_eq!(applied["plan"], planned["plan"]);
    assert_eq!(applied["replayed"], false);
    assert_eq!(applied["after"]["logical_objects"], 1);
    assert_eq!(applied["after"]["packs"], 1);
    assert!(
        applied["after"]["physical_bytes"]
            .as_u64()
            .ok_or("missing physical bytes")?
            < sparse.physical_bytes()
    );

    assert_eq!(
        old_reader.read_all(MAXIMUM_TEST_READ_BYTES)?,
        retained_bytes
    );
    assert_eq!(
        fixture
            .backend
            .read(retained, None)?
            .read_all(MAXIMUM_TEST_READ_BYTES)?,
        retained_bytes
    );

    let replayed = fixture.run_repack("apply", &fixture.plan)?;
    assert_eq!(replayed["plan"], planned["plan"]);
    assert_eq!(replayed["replayed"], true);

    let stale_plan = fixture.root.join("stale-plan");
    fixture.run_repack("plan", &stale_plan)?;
    let intervening_bytes = b"intervening packed object";
    let intervening = ContentId::for_bytes(ObjectKind::Trace, 1, intervening_bytes);
    fixture.backend.put_if_absent(
        intervening,
        &BlobHandle::from_bytes(intervening_bytes.to_vec()),
    )?;
    let orphan = fixture.packed.join("packs").join(&sparse_pack_name);
    fs::write(&orphan, sparse_pack_bytes)?;
    let staging = fixture
        .packed
        .join("packs")
        .join(format!(".pack.tmp-{}-9999", std::process::id()));
    fs::write(&staging, b"abandoned packed staging bytes")?;
    let packs_before_rejection = pack_names(&fixture.packed)?;

    let stale = fixture.repack_command("apply", &stale_plan).output()?;
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("repack apply failed"));
    assert_eq!(pack_names(&fixture.packed)?, packs_before_rejection);
    assert!(orphan.is_file());
    assert!(staging.is_file());
    assert!(fixture.backend.contains(retained)?);
    assert!(fixture.backend.contains(intervening)?);

    Ok(())
}

struct RepackFixture {
    _temporary: TempDir,
    root: PathBuf,
    packed: PathBuf,
    store: PathBuf,
    plan: PathBuf,
    backend: PackedBlobBackend,
}

impl RepackFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().to_path_buf();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let packed = secure_directory(&root, "packed")?;
        let refs = secure_directory(&root, "refs")?;
        let store = root.join("store.toml");
        let plan = root.join("repack-plan");
        fs::write(
            &store,
            format!(
                r#"schema = "crucible.campaign-repository-store"
version = 1
root = "packed"
admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
ref_directory = {refs:?}

[[nodes]]
id = "packed"
[nodes.spec]
kind = "packed"
root = {packed:?}
target_pack_bytes = {TARGET_PACK_BYTES}
"#
            ),
        )?;
        fs::set_permissions(&store, fs::Permissions::from_mode(0o600))?;
        let backend = PackedBlobBackend::open("packed", &packed, TARGET_PACK_BYTES)?;

        Ok(Self {
            _temporary: temporary,
            root,
            packed,
            store,
            plan,
            backend,
        })
    }

    fn repack_command(&self, operation: &str, plan: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_crucible"));
        command
            .args(["--format", "jsonl", "store", "repack", "--store"])
            .arg(&self.store)
            .args(["--node", "packed", "--plan"])
            .arg(plan)
            .arg(operation);
        command
    }

    fn run_repack(&self, operation: &str, plan: &Path) -> Result<Value, Box<dyn Error>> {
        let output = self.repack_command(operation, plan).output()?;
        parse_json_output(output, operation)
    }
}

fn secure_directory(root: &Path, name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = root.join(name);
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

fn pack_names(root: &Path) -> Result<BTreeSet<String>, Box<dyn Error>> {
    fs::read_dir(root.join("packs"))?
        .map(|entry| {
            let entry = entry?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF-8 pack name".into())
        })
        .collect()
}

fn only_complete_pack(root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let packs = fs::read_dir(root.join("packs"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "pack")
        })
        .collect::<Vec<_>>();
    if packs.len() != 1 {
        return Err(format!("expected one complete pack, found {}", packs.len()).into());
    }
    Ok(packs[0].clone())
}

fn parse_json_output(output: Output, operation: &str) -> Result<Value, Box<dyn Error>> {
    if !output.status.success() {
        return Err(format!(
            "store repack {operation} failed with {}; stdout=`{}` stderr=`{}`",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    let mut lines = stdout.lines();
    let line = lines
        .next()
        .ok_or_else(|| format!("store repack {operation} returned empty stdout"))?;
    if lines.next().is_some() {
        return Err(format!("store repack {operation} returned multiple JSONL records").into());
    }
    Ok(serde_json::from_str(line)?)
}
