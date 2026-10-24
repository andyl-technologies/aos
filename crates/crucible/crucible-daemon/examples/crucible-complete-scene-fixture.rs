//! Writes actual collecting-scene DATA or independently measures its finished file.
//!
//! ```text
//! crucible-complete-scene-fixture build INPUTS.json NEW_OUTPUT_DIRECTORY
//! crucible-complete-scene-fixture measure CONFIGURATION.json NEW_EXPECTED.json
//! crucible-complete-scene-fixture measure-elf EXECUTABLE NEW_EXPECTED.json
//! ```
//!
//! Build and measurement are separate ordinary invocations. Neither constitutes
//! an installation witness, native runtime result or accepted qualification.

use crucible_daemon::node_qualification::{
    CompleteSceneFixtureInputs, write_complete_scene_fixture,
};
use crucible_node_format::canonical;
use std::{
    error::Error,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

type Failure = Box<dyn Error>;

fn main() -> Result<(), Failure> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 3 {
        return Err("expected build|measure|measure-elf INPUT OUTPUT".into());
    }
    let input = Path::new(&arguments[1]);
    let output = Path::new(&arguments[2]);
    if !input.is_absolute() || !output.is_absolute() {
        return Err("fixture paths must be absolute".into());
    }
    match arguments[0].to_str() {
        Some("build") => {
            let bytes = bounded_read(input, 65_536)?;
            let value = canonical::parse_json(&bytes, 65_536)?;
            let inputs: CompleteSceneFixtureInputs = serde_json::from_value(value)?;
            write_complete_scene_fixture(inputs, output)
        }
        Some("measure") => {
            let bytes = bounded_read(input, 8 * 1024 * 1024)?;
            let value = canonical::parse_json(&bytes, 8 * 1024 * 1024)?;
            if canonical::canonical_json(&value)? != bytes {
                return Err("configuration is not canonical JSON".into());
            }
            let reference = canonical::content_ref(&bytes, "application/json")?;
            let encoded = canonical::canonical_json(&serde_json::to_value(reference)?)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            file.write_all(&encoded)?;
            Ok(())
        }
        Some("measure-elf") => {
            let (bytes, original) = read_original(input, 512 * 1024 * 1024)?;
            if original.mode() & 0o111 == 0 || !bytes.starts_with(b"\x7fELF") {
                return Err("measurement input is not an executable ELF".into());
            }
            let reference = canonical::content_ref(&bytes, "application/octet-stream")?;
            let encoded = canonical::canonical_json(&serde_json::to_value(reference)?)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            file.write_all(&encoded)?;
            Ok(())
        }
        _ => Err("expected build, measure or measure-elf".into()),
    }
}

fn bounded_read(path: &Path, maximum: usize) -> Result<Vec<u8>, Failure> {
    read_original(path, maximum).map(|(bytes, _)| bytes)
}

fn read_original(path: &Path, maximum: usize) -> Result<(Vec<u8>, std::fs::Metadata), Failure> {
    if std::fs::canonicalize(path)? != path {
        return Err("fixture input must name its original file".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > u64::try_from(maximum)? {
        return Err("fixture input exceeds its fixed bound".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let facts = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.ctime(),
            m.ctime_nsec(),
            m.mtime(),
            m.mtime_nsec(),
        )
    };
    if facts(&before) != facts(&after) || u64::try_from(bytes.len())? != before.len() {
        return Err("fixture input changed during its complete measurement".into());
    }
    Ok((bytes, after))
}
