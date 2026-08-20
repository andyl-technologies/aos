mod common;

use std::fs;
use std::io::Cursor;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use aos_cache::backend::{self, AuthOptions};
use aos_core::nar::info::{self as narinfo, store_hash};
use aos_core::output::Printer;
use aos_net::{TransferEngine, TransferEngineConfig};
use aos_package::download::{
    DownloadRequest, default_engine, download_nars, fetch_narinfos, narinfo_url,
};
use aos_package::registry::nixcache;
use base64::Engine as _;

use common::StaticHttpServer;

const REAL_NIX_CACHE_TEST_ENV: &str = "AOS_PACKAGE_TEST_REAL_NIX_CACHE";
const GENERATED_CACHE_UPLOAD_URLS_ENV: &str = "AOS_PACKAGE_TEST_GENERATED_CACHE_UPLOAD_URLS";

#[tokio::test]
async fn static_nix_cache_e2e_generates_serves_and_downloads_real_store_path() -> Result<()> {
    if std::env::var_os(REAL_NIX_CACHE_TEST_ENV).is_none() {
        eprintln!(
            "skipping static Nix cache e2e: set {REAL_NIX_CACHE_TEST_ENV}=1 to run real nix-store fixture"
        );
        return Ok(());
    }

    let Some(store_path) = tiny_store_path_fixture(b"aos static cache fixture\n")? else {
        eprintln!(
            "skipping static Nix cache e2e: nix-store is unavailable or refused fixture setup"
        );
        return Ok(());
    };
    let image_store_path = tiny_store_path_fixture(b"tiny fake qcow2 image payload\n")?
        .context("image store fixture setup was refused after package setup succeeded")?;
    assert!(
        fs::symlink_metadata(&image_store_path)?
            .file_type()
            .is_file()
    );

    let tmp = tempfile::TempDir::new()?;
    let registry_dir = tmp.path().join("registry");
    let output_dir = tmp.path().join("cache");
    let download_dir = tmp.path().join("downloads");
    fs::create_dir_all(registry_dir.join("packages/f"))?;
    fs::write(
        registry_dir.join("packages/f/fixture.toml"),
        package_toml(&store_path, &image_store_path),
    )?;

    let (key_file, trusted_public_key) = nix_cache_key(tmp.path())?;
    let printer = Printer::new(0, true, false);
    let report = nixcache::generate_static_cache(
        &registry_dir,
        &output_dir,
        Some(&key_file),
        37,
        None,
        None,
        false,
        &printer,
    )
    .await?;
    assert_eq!(report.paths, 2);
    assert_eq!(report.narinfos, 2);
    assert_eq!(report.nars, 2);
    assert!(output_dir.join("nix-cache-info").exists());

    let server = StaticHttpServer::spawn(output_dir.clone()).await?;
    let mirror_url = server.base_url();
    let narinfo_text = fetch_text(&narinfo_url(&mirror_url, &store_path)).await?;
    assert!(narinfo_text.contains("Sig: aos-cache:"));

    let engine = Arc::new(default_engine());
    let resolved = fetch_narinfos(
        Arc::clone(&engine),
        &[DownloadRequest {
            store_path: store_path.clone(),
            mirror_url: mirror_url.clone(),
            fallback_mirrors: Vec::new(),
        }],
        1,
        &printer,
    )
    .await?;
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].narinfo.store_path, store_path);

    let results = download_nars(&resolved, &download_dir, 1, &printer).await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].store_path, store_path);
    assert!(results[0].local_path.exists());

    let downloaded = fs::read(&results[0].local_path)?;
    let decoded = zstd::stream::decode_all(Cursor::new(downloaded))?;
    let expected = nix_store_dump(&store_path)?;
    assert_eq!(decoded, expected);

    let image_narinfo_text = fetch_text(&narinfo_url(&mirror_url, &image_store_path)).await?;
    let image_resolved = fetch_narinfos(
        Arc::clone(&engine),
        &[DownloadRequest {
            store_path: image_store_path.clone(),
            mirror_url: mirror_url.clone(),
            fallback_mirrors: Vec::new(),
        }],
        1,
        &printer,
    )
    .await?;
    let image_results = download_nars(&image_resolved, &download_dir, 1, &printer).await?;
    let image_decoded =
        zstd::stream::decode_all(Cursor::new(fs::read(&image_results[0].local_path)?))?;
    assert_eq!(image_decoded, nix_store_dump(&image_store_path)?);
    assert!(image_narinfo_text.contains(&format!("StorePath: {image_store_path}")));

    assert_filesystem_upload_array_round_trips(&output_dir, &store_path, &narinfo_text, &printer)
        .await?;
    assert_generated_cache_external_upload_matrix_round_trips(
        &output_dir,
        &store_path,
        &narinfo_text,
        &printer,
    )
    .await?;
    assert_stock_nix_can_query_signed_cache(&mirror_url, &store_path, &trusted_public_key)?;
    Ok(())
}

fn tiny_store_path_fixture(contents: &[u8]) -> Result<Option<String>> {
    if command_missing("nix-store") {
        return Ok(None);
    }

    let tmp = tempfile::Builder::new()
        .prefix("aos-cache-fixture-")
        .tempfile()?;
    fs::write(tmp.path(), contents)?;
    let output = Command::new("nix-store")
        .args(["--add-fixed", "sha256"])
        .arg(tmp.path())
        .output()
        .context("running nix-store --add-fixed")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "skipping static Nix cache e2e: nix-store --add-fixed failed: {}",
            stderr.trim(),
        );
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

fn nix_cache_key(root: &std::path::Path) -> Result<(std::path::PathBuf, String)> {
    let seed = [11u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(seed);
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
    let key_file = root.join("nix-cache.sec");
    fs::write(&key_file, format!("aos-cache:{secret_b64}\n"))?;
    Ok((key_file, format!("aos-cache:{public_b64}")))
}

fn package_toml(store_path: &str, image_store_path: &str) -> String {
    format!(
        r#"[package]
name = "fixture"
description = "Static cache fixture"
license = "MIT"
maintainer = "registry@example.com"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "{store_path}"
nar_hash = "sha256:placeholder"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []

[[versions.platforms.x86_64-linux.images]]
format = "qcow2"
store_path = "{image_store_path}"
nar_hash = "sha256:placeholder"
nar_size = 1
"#,
    )
}

async fn fetch_text(url: &str) -> Result<String> {
    let engine = TransferEngine::new(TransferEngineConfig::default());
    let result = engine.execute(aos_net::TransferRequest::get(url)).await?;
    let body = result
        .body
        .ok_or_else(|| anyhow::anyhow!("no response body for {url}"))?;
    String::from_utf8(body).with_context(|| format!("{url} body is not UTF-8"))
}

async fn assert_filesystem_upload_array_round_trips(
    output_dir: &std::path::Path,
    store_path: &str,
    source_narinfo_text: &str,
    printer: &Printer,
) -> Result<()> {
    let first = tempfile::TempDir::new()?;
    let second = tempfile::TempDir::new()?;
    let upload_urls = vec![
        format!("file://{}", first.path().display()),
        format!("file://{}", second.path().display()),
    ];
    nixcache::upload_static_cache_to_all(
        output_dir,
        &upload_urls,
        &AuthOptions::default(),
        &[],
        false,
        printer,
    )
    .await?;

    assert_uploaded_static_cache_round_trips(
        &upload_urls,
        output_dir,
        store_path,
        source_narinfo_text,
    )
    .await
}

async fn assert_generated_cache_external_upload_matrix_round_trips(
    output_dir: &std::path::Path,
    store_path: &str,
    source_narinfo_text: &str,
    printer: &Printer,
) -> Result<()> {
    let Some(raw_urls) = std::env::var_os(GENERATED_CACHE_UPLOAD_URLS_ENV) else {
        eprintln!(
            "skipping generated static-cache external upload matrix: set {GENERATED_CACHE_UPLOAD_URLS_ENV} to whitespace- or comma-separated upload URLs"
        );
        return Ok(());
    };
    let external_urls = raw_urls
        .to_string_lossy()
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .filter(|url| !url.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if external_urls.is_empty() {
        eprintln!(
            "skipping generated static-cache external upload matrix: {GENERATED_CACHE_UPLOAD_URLS_ENV} is empty"
        );
        return Ok(());
    }

    let local = tempfile::TempDir::new()?;
    let mut upload_urls = vec![format!("file://{}", local.path().display())];
    upload_urls.extend(external_urls);
    nixcache::upload_static_cache_to_all(
        output_dir,
        &upload_urls,
        &AuthOptions::default(),
        &[],
        false,
        printer,
    )
    .await?;

    assert_uploaded_static_cache_round_trips(
        &upload_urls,
        output_dir,
        store_path,
        source_narinfo_text,
    )
    .await
}

async fn assert_uploaded_static_cache_round_trips(
    upload_urls: &[String],
    output_dir: &std::path::Path,
    store_path: &str,
    source_narinfo_text: &str,
) -> Result<()> {
    let hash = store_hash(store_path);
    let source_narinfo = narinfo::parse(source_narinfo_text)?;
    let source_cache_info = fs::read_to_string(output_dir.join("nix-cache-info"))?;
    let source_nar = fs::read(output_dir.join(&source_narinfo.url))?;

    for upload_url in upload_urls {
        let uploaded = backend::from_url(upload_url, &AuthOptions::default()).await?;
        assert!(uploaded.has_narinfo(hash).await?);
        assert_eq!(
            uploaded
                .query_missing(&[hash, "missingmissingmissingmissingmiss"])
                .await?,
            vec!["missingmissingmissingmissingmiss".to_string()]
        );
        assert_eq!(uploaded.get_narinfo(hash).await?, source_narinfo_text);
        assert_eq!(uploaded.get_nar(&source_narinfo.url).await?, source_nar);

        if let Some(root) = upload_url.strip_prefix("file://") {
            assert_eq!(
                fs::read_to_string(std::path::Path::new(root).join("nix-cache-info"))?,
                source_cache_info,
            );
        }
    }

    Ok(())
}

fn nix_store_dump(store_path: &str) -> Result<Vec<u8>> {
    let output = Command::new("nix-store")
        .args(["--dump", store_path])
        .output()
        .with_context(|| format!("running nix-store --dump {store_path}"))?;
    if !output.status.success() {
        bail!(
            "nix-store --dump failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(output.stdout)
}

fn assert_stock_nix_can_query_signed_cache(
    mirror_url: &str,
    store_path: &str,
    trusted_public_key: &str,
) -> Result<()> {
    if std::env::var_os("AOS_PACKAGE_TEST_STOCK_NIX_CACHE").is_none() {
        eprintln!(
            "skipping stock nix signed-cache check: set AOS_PACKAGE_TEST_REAL_NIX_CACHE=1 and AOS_PACKAGE_TEST_STOCK_NIX_CACHE=1 to run"
        );
        return Ok(());
    }

    if command_missing("nix") {
        eprintln!("skipping stock nix signed-cache check: nix is unavailable");
        return Ok(());
    }

    let mut command = Command::new("nix");
    command.args([
        "--extra-experimental-features",
        "nix-command",
        "--option",
        "require-sigs",
        "true",
        "--option",
        "trusted-public-keys",
        trusted_public_key,
        "path-info",
        "--store",
        mirror_url,
        store_path,
    ]);

    let Some(output) = command_output_with_timeout(command, Duration::from_secs(15))? else {
        bail!("stock nix path-info against static cache timed out after 15s");
    };
    if !output.status.success() {
        bail!(
            "stock nix path-info against static cache failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(store_path));
    Ok(())
}

fn command_output_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> Result<Option<std::process::Output>> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().context("spawning timed command")?;
    let started = Instant::now();
    loop {
        if child.try_wait().context("polling timed command")?.is_some() {
            let output = child
                .wait_with_output()
                .context("collecting timed command output")?;
            return Ok(Some(output));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn command_missing(command: &str) -> bool {
    matches!(
        Command::new(command).arg("--version").output(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound
    )
}
