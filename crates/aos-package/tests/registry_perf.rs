mod common;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aos_core::output::Printer;
use aos_package::registry::{fetch, objectstore, pack};
use semver::Version;

use common::{RegistryFixture, StaticHttpServer};

const PERF_ENV: &str = "AOS_PACKAGE_TEST_REGISTRY_PERF";
const PERF_PACKAGE_COUNT_ENV: &str = "AOS_PACKAGE_TEST_REGISTRY_PERF_PACKAGES";
const DEFAULT_PACKAGE_COUNT: usize = 80;

#[tokio::test]
#[ignore = "set AOS_PACKAGE_TEST_REGISTRY_PERF=1 to run the registry pack/delta perf harness"]
async fn registry_pack_delta_perf_harness_reports_metrics() -> Result<()> {
    if std::env::var_os(PERF_ENV).is_none() {
        eprintln!("skipping registry perf harness: set {PERF_ENV}=1 to run");
        return Ok(());
    }

    let package_count = std::env::var(PERF_PACKAGE_COUNT_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PACKAGE_COUNT);

    let fixture = RegistryFixture::new("perf")?;
    fixture.write_registry_toml_with_caches(&[])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;

    write_perf_release(&fixture, "1.0.0", 0, package_count)?;
    let base_commit = fixture.commit_all("release 1.0.0")?;
    fixture.signed_tag("1.0.0", "HEAD")?;

    write_perf_release(&fixture, "1.0.1", 1, package_count)?;
    let target_commit = fixture.commit_all("release 1.0.1")?;
    fixture.signed_tag("1.0.1", "HEAD")?;
    fixture.publish_bare_origin()?;

    let scratch = tempfile::TempDir::new()?;
    let (full_pack, full_pack_time) = timed_async(pack::full_pack(
        fixture.source_path(),
        "1.0.0",
        scratch.path(),
    ))
    .await?;
    let full_pack_name = copy_full_pack_to_origin(&fixture, &v("1.0.0"), &full_pack)?;
    let full_pack_bytes = fs::metadata(&full_pack)?.len();

    let (delta_pack, delta_pack_time) = timed_async(pack::thin_delta(
        fixture.source_path(),
        &base_commit,
        &target_commit,
        &v("1.0.0"),
        scratch.path(),
    ))
    .await?;
    let delta_pack_bytes = fs::metadata(&delta_pack)?.len();
    let (compressed_delta, zstd_time) = timed_async(pack::zstd_compress(&delta_pack, None)).await?;
    let compressed_delta_name =
        copy_delta_pack_to_origin(&fixture, &v("1.0.1"), &compressed_delta)?;
    let compressed_delta_bytes = fs::metadata(&compressed_delta)?.len();

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let consumer = tempfile::TempDir::new()?;
    let repo = init_consumer_repo(consumer.path())?;
    let printer = Printer::new(0, true, false);

    let (full_plan, full_reconstruct_time) = timed_async(fetch::resolve_objects(
        &repo,
        &server.base_url(),
        &v("1.0.0"),
        &[],
        &printer,
    ))
    .await?;
    assert_eq!(
        full_plan.steps,
        vec![fetch::FetchStep::Full {
            version: v("1.0.0"),
            pack: full_pack_name.clone(),
        }],
    );
    assert_git_object_exists(&repo, &base_commit);

    let (delta_plan, delta_reconstruct_time) = timed_async(fetch::resolve_objects(
        &repo,
        &server.base_url(),
        &v("1.0.1"),
        &[v("1.0.0")],
        &printer,
    ))
    .await?;
    assert_eq!(
        delta_plan.steps,
        vec![fetch::FetchStep::Delta {
            target: v("1.0.1"),
            base: v("1.0.0"),
            compressed: true,
        }],
    );
    assert_git_object_exists(&repo, &target_commit);

    assert!(full_pack_bytes > 0);
    assert!(delta_pack_bytes > 0);
    assert!(compressed_delta_bytes > 0);
    eprintln!(
        "registry perf: packages={package_count} full_pack={full_pack_bytes}B/{full_pack_time:?} \
         delta_pack={delta_pack_bytes}B/{delta_pack_time:?} \
         zstd_delta={compressed_delta_bytes}B/{zstd_time:?} \
         full_reconstruct={full_reconstruct_time:?} delta_reconstruct={delta_reconstruct_time:?} \
         full_pack_name={full_pack_name} delta_name={compressed_delta_name}",
    );

    Ok(())
}

async fn timed_async<T>(
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<(T, Duration)> {
    let start = Instant::now();
    let value = future.await?;
    Ok((value, start.elapsed()))
}

fn write_perf_release(
    fixture: &RegistryFixture,
    version: &str,
    salt: usize,
    package_count: usize,
) -> Result<()> {
    for index in 0..package_count {
        let name = format!("pkg{index:03}");
        let store_path = fixture.write_package(&name, version)?;
        fixture.write_closure(&store_path)?;
        let package_path = fixture
            .source_path()
            .join("packages")
            .join(&name[..1])
            .join(format!("{name}.toml"));
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&package_path)
            .with_context(|| format!("opening {}", package_path.display()))?;
        writeln!(
            file,
            "\n[perf]\nsalt = {salt}\nindex = {index}\npayload = \"{}\"",
            "x".repeat(512 + salt + index % 17),
        )?;
    }
    Ok(())
}

fn init_consumer_repo(root: &Path) -> Result<PathBuf> {
    let repo = root.join("consumer.git");
    objectstore::init_bare_sha256(&repo, "stable")?;
    Ok(repo)
}

fn copy_full_pack_to_origin(
    fixture: &RegistryFixture,
    version: &Version,
    pack_path: &Path,
) -> Result<String> {
    let pack_name = file_name(pack_path)?;
    let release_objects = fixture
        .origin_path()
        .join("releases")
        .join(objectstore::release_object_dir(version));
    let pack_dir = release_objects.join("pack");
    let info_dir = release_objects.join("info");
    fs::create_dir_all(&pack_dir)?;
    fs::create_dir_all(&info_dir)?;
    fs::copy(pack_path, pack_dir.join(&pack_name))?;
    let idx_path = pack_path.with_extension("idx");
    if idx_path.exists() {
        fs::copy(
            &idx_path,
            pack_dir.join(pack_name.trim_end_matches(".pack").to_string() + ".idx"),
        )?;
    }
    fs::write(info_dir.join("packs"), format!("P {pack_name}\n"))?;
    Ok(pack_name)
}

fn copy_delta_pack_to_origin(
    fixture: &RegistryFixture,
    target: &Version,
    pack_path: &Path,
) -> Result<String> {
    let pack_name = file_name(pack_path)?;
    let pack_dir = fixture
        .origin_path()
        .join("releases")
        .join(objectstore::release_object_dir(target))
        .join("pack");
    fs::create_dir_all(&pack_dir)?;
    fs::copy(pack_path, pack_dir.join(&pack_name))?;
    Ok(pack_name)
}

fn file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("path has no UTF-8 file name: {}", path.display()))
}

fn assert_git_object_exists(repo: &Path, rev: &str) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "-e", &format!("{rev}^{{commit}}")])
        .output()
        .expect("running git cat-file");
    assert!(
        output.status.success(),
        "expected git object {rev} to exist\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn v(input: &str) -> Version {
    Version::parse(input).unwrap()
}
