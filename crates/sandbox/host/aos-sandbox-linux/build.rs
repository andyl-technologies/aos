//! Checks the same configured kernel's build-only FD-table DATA artifact.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

const PREFIX: &str = "AOS_KERNEL_CLONE_V1_";
const FACTS: [&str; 9] = [
    "FORMAT",
    "FILES_STRUCT_BYTES",
    "FDTABLE_BYTES",
    "FILE_POINTER_BYTES",
    "ULONG_BYTES",
    "BITS_PER_LONG",
    "NR_OPEN_DEFAULT",
    "L1_CACHE_BYTES",
    "PAGE_BYTES",
];
const ASSOCIATIONS: [&str; 6] = [
    "NOTES_BYTES",
    "NOTES_SHA256",
    "CONFIG_SHA256",
    "IMAGE_SHA256",
    "LAYOUT_SHA256",
    "KERNEL_RELEASE",
];

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=AOS_KERNEL_CLONE_LAYOUT_DIR");
    if std::env::var_os("CARGO_FEATURE_SELECTED_KERNEL_CLONE_LAYOUT").is_none() {
        return Ok(());
    }
    let directory = PathBuf::from(
        std::env::var_os("AOS_KERNEL_CLONE_LAYOUT_DIR")
            .ok_or("selected kernel layout artifact is required")?,
    );
    let layout_path = directory.join("aos-kernel-clone-layout-v1.h");
    let association_path = directory.join("aos-kernel-clone-association-v1.h");
    let layout = fs::read_to_string(&layout_path)?;
    let association = fs::read_to_string(&association_path)?;
    println!("cargo:rerun-if-changed={}", layout_path.display());
    println!("cargo:rerun-if-changed={}", association_path.display());
    let facts = defines(&layout, &FACTS)?;
    let association = defines(&association, &ASSOCIATIONS)?;
    let mut output = String::new();
    for name in FACTS {
        let value = integer(facts.get(name).ok_or("missing kernel fact")?)?;
        if value == 0 || name == "FORMAT" && value != 1 {
            return Err("invalid configured kernel fact".into());
        }
        output.push_str(&format!("pub(super) const {name}: u64 = {value};\n"));
    }
    if std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH")? != "64"
        || integer(facts["FILE_POINTER_BYTES"])? != 8
        || integer(facts["ULONG_BYTES"])? != 8
        || integer(facts["BITS_PER_LONG"])? != 64
    {
        return Err("configured kernel facts differ from the supported 64-bit target".into());
    }
    let notes_bytes = integer(association["NOTES_BYTES"])?;
    if notes_bytes == 0 || fs::metadata(directory.join("kernel-notes"))?.len() != notes_bytes {
        return Err("configured kernel notes extent differs".into());
    }
    for (name, path) in [
        ("LAYOUT_SHA256", layout_path),
        ("NOTES_SHA256", directory.join("kernel-notes")),
        ("CONFIG_SHA256", directory.join("kernel.config")),
    ] {
        let expected = digest_literal(association[name])?;
        if digest(&path)? != expected {
            return Err("configured kernel artifact association differs".into());
        }
        println!("cargo:rerun-if-changed={}", path.display());
    }
    // Image/config/layout digests remain build identity DATA. Runtime admission
    // uses its own actual notes hash, not a path into this development output.
    for name in [
        "NOTES_SHA256",
        "CONFIG_SHA256",
        "IMAGE_SHA256",
        "LAYOUT_SHA256",
    ] {
        output.push_str(&format!(
            "pub(super) const {name}: [u8; 32] = {:?};\n",
            digest_literal(association[name])?
        ));
    }
    let release = association["KERNEL_RELEASE"];
    if !release.starts_with('"') || !release.ends_with('"') || release.len() <= 2 {
        return Err("configured kernel release is missing".into());
    }
    output.push_str(&format!(
        "pub(super) const NOTES_BYTES: u64 = {notes_bytes};\n"
    ));
    let destination = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("missing Cargo output")?);
    fs::write(destination.join("aos-kernel-clone-layout-v1.rs"), output)?;
    Ok(())
}

fn defines<'a>(
    header: &'a str,
    expected: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, Box<dyn Error>> {
    let mut result = BTreeMap::new();
    for line in header.lines() {
        let Some(line) = line
            .strip_prefix("#define ")
            .and_then(|line| line.strip_prefix(PREFIX))
        else {
            continue;
        };
        let (name, value) = line
            .split_once(char::is_whitespace)
            .ok_or("invalid kernel define")?;
        if !expected.contains(&name) || result.insert(name, value.trim()).is_some() {
            return Err("unexpected or duplicate kernel define".into());
        }
    }
    if result.len() != expected.len() {
        return Err("incomplete configured kernel vocabulary".into());
    }
    Ok(result)
}

fn integer(value: &str) -> Result<u64, Box<dyn Error>> {
    let value = value
        .split("/*")
        .next()
        .ok_or("missing kernel integer")?
        .trim();
    let value = value.trim_end_matches("ULL");
    Ok(if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)?
    } else {
        value.parse()?
    })
}

fn digest_literal(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let hex = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or("kernel digest is not a string")?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("kernel digest has invalid width or syntax".into());
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16)?;
    }
    Ok(result)
}

fn digest(path: &Path) -> Result<[u8; 32], Box<dyn Error>> {
    use std::io::Read as _;
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = [0; 64 * 1024];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            return Ok(digest.finalize().into());
        }
        digest.update(&bytes[..count]);
    }
}
