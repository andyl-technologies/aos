//! Exports exact current semantic/live boundary pairs as immutable fixture files.
//!
//! Install as a private auxiliary example in a separate c334 source copy. This
//! executable is a fixture artifact and does not change the deployed Worker.

#[path = "pack_memory_fixture/builders.rs"]
mod builders;

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use aos_registry_surface::pack_index::{self, projection::{ContentRange, PairReader, Selection}};
use serde_json::json;
use sha2::{Digest as _, Sha256};

fn write_new(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(root.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn emit(root: &Path, name: &str, delta: Option<bool>, extra: bool,
        expected_inflated: u64, expected_peak: Option<u64>) -> Result<serde_json::Value> {
    let fixture = builders::pair(delta, extra)?;
    let directory = root.join(name);
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let mut reader = PairReader::new(&fixture.path)?;
    for chunk in fixture.pack.chunks(64 * 1024) { reader.feed_pack(chunk)?; }
    for chunk in fixture.index.chunks(64 * 1024) { reader.feed_index(chunk)?; }
    let selection = Selection {
        oid: fixture.selected_oid,
        range: Some(ContentRange { start: 0, end: 32 }),
    };
    let parsed = reader.finish(&[selection]);
    let observation = if let Some(peak) = expected_peak {
        pack_index::validate_against_pack(&fixture.path, &fixture.index, &fixture.pack)?;
        let parsed = parsed?;
        ensure!(parsed.inflated_entry_bytes == expected_inflated, "inflated fixture boundary changed");
        ensure!(parsed.peak_decoded_graph_bytes == peak, "live fixture boundary changed");
        ensure!(parsed.objects.len() == 1 && parsed.objects[0].content.len() == 32,
            "fixture selected result changed");
        json!({"parserOutcome":"verified", "inflatedEntryBytes":parsed.inflated_entry_bytes,
            "peakDecodedGraphBytes":parsed.peak_decoded_graph_bytes,
            "selectedSha256":hex::encode(Sha256::digest(&parsed.objects[0].content)),
            "selectedBytes":32})
    } else {
        let error = parsed.err().context("overflow fixture unexpectedly passed")?;
        ensure!(error.to_string().contains("remaining decoded-graph budget"),
            "overflow fixture failed outside the intended preallocation fence: {error}");
        json!({"parserOutcome":"refused", "intendedFence":"remaining decoded-graph budget",
            "inflatedEntryBytes":null, "peakDecodedGraphBytes":null,
            "selectedSha256":null,"selectedBytes":null})
    };
    write_new(&directory, "pair.pack", &fixture.pack)?;
    write_new(&directory, "pair.idx", &fixture.index)?;
    let row = json!({"version":1,"case":name,"indexPath":fixture.path,
        "packSha256":hex::encode(Sha256::digest(&fixture.pack)),
        "packBytes":fixture.pack.len(),"indexSha256":hex::encode(Sha256::digest(&fixture.index)),
        "indexBytes":fixture.index.len(),"selectedOid":hex::encode(fixture.selected_oid.as_bytes()),
        "range":{"start":0,"end":32},"pureParser":observation});
    write_new(&directory, "manifest.json", &serde_json::to_vec_pretty(&row)?)?;
    Ok(row)
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(args.next().context("one fresh private output root required")?);
    if args.next().is_some() || !root.is_absolute() || root.exists() {
        bail!("output must be a new absolute private directory");
    }
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let rows = vec![
        emit(&root, "semantic32", None, false, 32 * 1024 * 1024, Some(32 * 1024 * 1024))?,
        emit(&root, "live36", Some(true), false, 32 * 1024 * 1024, Some(36 * 1024 * 1024))?,
        emit(&root, "replacement-overflow", Some(false), true, 0, None)?,
    ];
    write_new(&root, "manifest.json", &serde_json::to_vec_pretty(&json!({
        "version":1,"execution":"fixture_export_only","pairs":rows,
        "wholeWorkerMemoryBytes":null,"providerEffects":"not_invoked"}))?)?;
    Ok(())
}
