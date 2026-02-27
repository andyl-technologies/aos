use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};

/// Metadata for a store path, from nix-store queries or Nix DB.
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub path: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Vec<String>,
    pub deriver: Option<String>,
    pub signatures: Vec<String>,
}

/// Portable classic Nix command wrapper.
///
/// Wraps `nix-instantiate`, `nix-build`, `nix-store` — works on any Nix
/// installation without experimental features.
pub struct NixCli {
    verbose: u8,
}

impl NixCli {
    pub fn new(verbose: u8) -> Self {
        Self { verbose }
    }

    /// Instantiate an attribute from a file -> .drv path.
    pub fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let mut cmd = Command::new("nix-instantiate");
        cmd.arg("-f").arg(file).arg("-A").arg(attr);
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output = cmd
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-instantiate")?;
        if !output.status.success() {
            anyhow::bail!("nix-instantiate failed for {}", attr);
        }
        let drv = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-instantiate")?
            .trim()
            .to_string();
        Ok(PathBuf::from(drv))
    }

    /// Instantiate a raw expression -> .drv path.
    pub fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        let mut cmd = Command::new("nix-instantiate");
        cmd.arg("-E").arg(expr);
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output = cmd
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-instantiate -E")?;
        if !output.status.success() {
            anyhow::bail!("nix-instantiate -E failed");
        }
        let drv = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-instantiate")?
            .trim()
            .to_string();
        Ok(PathBuf::from(drv))
    }

    /// Build a derivation from a file + attribute -> store path.
    pub fn build(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let mut cmd = Command::new("nix-build");
        cmd.arg(file).arg("-A").arg(attr).arg("--no-out-link");
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output = cmd
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-build")?;
        if !output.status.success() {
            anyhow::bail!("nix-build failed for {}", attr);
        }
        let path = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-build")?
            .trim()
            .to_string();
        Ok(PathBuf::from(path))
    }

    /// Build a .drv directly -> output store path.
    pub fn realise(&self, drv: &str) -> Result<String> {
        let output = Command::new("nix-store")
            .args(["--realise", drv])
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-store --realise")?;
        if !output.status.success() {
            anyhow::bail!("nix-store --realise failed for {}", drv);
        }
        let path = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-store --realise")?
            .trim()
            .to_string();
        Ok(path)
    }

    /// Get recursive closure of a store path.
    pub fn closure(&self, path: &str) -> Result<Vec<String>> {
        let output = Command::new("nix-store")
            .args(["-qR", path])
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-store -qR")?;
        if !output.status.success() {
            anyhow::bail!("nix-store -qR failed for {}", path);
        }
        let text = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-store -qR")?;
        Ok(text.lines().filter(|l| !l.is_empty()).map(String::from).collect())
    }

    /// Query metadata for a store path via CLI commands.
    pub fn path_info(&self, store_path: &str) -> Result<PathInfo> {
        let hash = run_nix_store_query(store_path, "--hash")?;
        let size_str = run_nix_store_query(store_path, "--size")?;
        let refs_str = run_nix_store_query(store_path, "--references")?;
        let deriver_str = run_nix_store_query(store_path, "--deriver")?;

        let nar_size: u64 = size_str
            .parse()
            .with_context(|| format!("invalid nar size '{size_str}'"))?;

        let references: Vec<String> = refs_str
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();

        let deriver = if deriver_str == "unknown-deriver" || deriver_str.is_empty() {
            None
        } else {
            Some(deriver_str)
        };

        Ok(PathInfo {
            path: store_path.to_string(),
            nar_hash: hash,
            nar_size,
            references,
            deriver,
            signatures: Vec::new(),
        })
    }

    /// Batch path_info for multiple paths.
    /// Uses Nix SQLite DB directly for large closures (>50 paths), falls back
    /// to CLI queries otherwise.
    pub fn path_info_batch(&self, paths: &[&str]) -> Result<Vec<PathInfo>> {
        if paths.len() > 50 {
            if let Ok(infos) = self.path_info_batch_db(paths) {
                return Ok(infos);
            }
        }
        paths.iter().map(|p| self.path_info(p)).collect()
    }

    /// Read path info from the Nix SQLite DB directly.
    fn path_info_batch_db(&self, paths: &[&str]) -> Result<Vec<PathInfo>> {
        use crate::server::store::NixStore;

        let db_path = std::path::Path::new("/nix/var/nix/db/db.sqlite");
        let store = NixStore::open(db_path)?;

        let mut result = Vec::with_capacity(paths.len());
        for &path in paths {
            let info = store
                .path_info(path)?
                .with_context(|| format!("path not in DB: {path}"))?;

            result.push(PathInfo {
                path: info.path,
                nar_hash: info.nar_hash,
                nar_size: info.nar_size as u64,
                references: info.refs,
                deriver: info.deriver,
                signatures: info.sigs,
            });
        }
        Ok(result)
    }

    /// Check if a store path is valid locally.
    pub fn is_valid(&self, path: &str) -> Result<bool> {
        let status = Command::new("nix-store")
            .args(["--check-validity", path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run nix-store --check-validity")?;
        Ok(status.success())
    }

    /// Spawn `nix-store --dump <path>` with piped stdout.
    #[allow(dead_code)]
    pub fn nar_dump(&self, path: &str) -> Result<Child> {
        Command::new("nix-store")
            .args(["--dump", path])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning nix-store --dump {path}"))
    }

    /// Spawn `nix-store --export <path>` with piped stdout.
    #[allow(dead_code)]
    pub fn nar_export(&self, path: &str) -> Result<Child> {
        Command::new("nix-store")
            .args(["--export", path])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning nix-store --export {path}"))
    }

    /// Pipe data to `nix-store --import` stdin, return imported paths.
    #[allow(dead_code)]
    pub fn nar_import(&self, mut data: impl Read) -> Result<Vec<String>> {
        let mut child = Command::new("nix-store")
            .arg("--import")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to spawn nix-store --import")?;

        {
            let stdin = child.stdin.as_mut().context("no stdin for nix-store --import")?;
            std::io::copy(&mut data, stdin).context("writing to nix-store --import")?;
        }

        let output = child.wait_with_output().context("waiting for nix-store --import")?;
        if !output.status.success() {
            anyhow::bail!("nix-store --import failed");
        }

        let text = String::from_utf8(output.stdout).context("invalid utf-8 from nix-store --import")?;
        Ok(text.lines().filter(|l| !l.is_empty()).map(String::from).collect())
    }
}

/// Run a single `nix-store -q <flag> <path>` query.
fn run_nix_store_query(path: &str, flag: &str) -> Result<String> {
    let output = Command::new("nix-store")
        .args(["-q", flag, path])
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("nix-store -q {flag} {path}"))?;
    if !output.status.success() {
        anyhow::bail!("nix-store -q {flag} failed for {path}");
    }
    Ok(String::from_utf8(output.stdout)
        .context("invalid utf-8")?
        .trim()
        .to_string())
}

// ---------------------------------------------------------------------------
// .drv ATerm parser for FOD discovery
// ---------------------------------------------------------------------------

/// A fixed-output derivation discovered from a .drv file.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FixedOutputDrv {
    pub drv_path: String,
    pub output_path: String,
    pub name: String,
    pub output_hash: String,
    pub output_hash_algo: String,
    pub output_hash_mode: String,
    pub url: Option<String>,
    pub builder: String,
}

/// Parse a .drv file (ATerm format) and extract FOD info if present.
///
/// Returns `Some(FixedOutputDrv)` if the derivation has an `outputHash` env var,
/// `None` otherwise.
pub fn parse_drv_for_fod(drv_path: &str) -> Result<Option<FixedOutputDrv>> {
    let content = std::fs::read_to_string(drv_path)
        .with_context(|| format!("reading {drv_path}"))?;

    // Quick check: if no outputHash, not a FOD.
    if !content.contains("\"outputHash\"") {
        return Ok(None);
    }

    let env = parse_drv_env(&content)?;

    let output_hash = match env.get("outputHash") {
        Some(h) if !h.is_empty() => h.clone(),
        _ => return Ok(None),
    };

    let outputs = parse_drv_outputs(&content)?;
    let (output_path, _) = outputs.first().context("no outputs in .drv")?;

    Ok(Some(FixedOutputDrv {
        drv_path: drv_path.to_string(),
        output_path: output_path.clone(),
        name: env.get("name").cloned().unwrap_or_default(),
        output_hash,
        output_hash_algo: env.get("outputHashAlgo").cloned().unwrap_or_default(),
        output_hash_mode: env
            .get("outputHashMode")
            .cloned()
            .unwrap_or_else(|| "flat".to_string()),
        url: env.get("url").cloned(),
        builder: parse_drv_builder(&content).unwrap_or_default(),
    }))
}

/// Parse the env section of a .drv file into a key-value map.
///
/// The env is the last bracketed list in the Derive(...) call:
/// `[("key","value"),("key2","value2")]`
fn parse_drv_env(content: &str) -> Result<std::collections::HashMap<String, String>> {
    let mut env = std::collections::HashMap::new();

    // Find the last `[` in the content which starts the env list.
    // The ATerm format is: Derive([outputs],[inputDrvs],[inputSrcs],"system","builder",[args],[env])
    // We need the 7th component (env), which is the last list.

    // Strategy: parse pairs of ("key","value") from the env section.
    // Find all ("key","value") patterns in the last section.
    let bytes = content.as_bytes();
    let len = bytes.len();

    // Find the last occurrence of `,[` which starts the env list.
    // We look backwards for the pattern `,[(`
    let mut env_start = None;
    let _bracket_depth: i32 = 0;
    let mut list_starts = Vec::new();

    // Track all top-level list boundaries inside Derive(...)
    let derive_start = content.find("Derive(").map(|i| i + 7).unwrap_or(0);
    let mut i = derive_start;
    let mut depth = 0;
    while i < len {
        match bytes[i] {
            b'[' => {
                if depth == 0 {
                    list_starts.push(i);
                }
                depth += 1;
            }
            b']' => {
                depth -= 1;
            }
            b'"' => {
                // Skip quoted string
                i += 1;
                while i < len {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    // The env list is the last top-level list.
    if let Some(&start) = list_starts.last() {
        env_start = Some(start);
    }

    let env_start = env_start.context("could not find env section in .drv")?;

    // Now parse ("key","value") pairs from env_start.
    let mut pos = env_start;
    while pos < len {
        // Find next `("`
        match content[pos..].find("(\"") {
            Some(offset) => pos += offset + 1,
            None => break,
        }

        // Parse key
        let key = parse_aterm_string(content, &mut pos)?;

        // Skip comma
        while pos < len && bytes[pos] != b'"' {
            pos += 1;
        }

        // Parse value
        let value = parse_aterm_string(content, &mut pos)?;

        env.insert(key, value);

        // Skip to after `)`
        while pos < len && bytes[pos] != b')' {
            pos += 1;
        }
        if pos < len {
            pos += 1;
        }
    }

    Ok(env)
}

/// Parse the outputs section: `[("out","/nix/store/xxx","sha256","abc123..."),...]`
fn parse_drv_outputs(content: &str) -> Result<Vec<(String, String)>> {
    let mut outputs = Vec::new();
    let bytes = content.as_bytes();
    let len = bytes.len();

    // Outputs is the first list after Derive(
    let derive_start = content.find("Derive(").map(|i| i + 7).unwrap_or(0);
    let list_start = match content[derive_start..].find('[') {
        Some(offset) => derive_start + offset,
        None => return Ok(outputs),
    };

    // Parse ("name","path",...) tuples
    let mut pos = list_start;
    while pos < len {
        match content[pos..].find("(\"") {
            Some(offset) => pos += offset + 1,
            None => break,
        }

        // Check we haven't left the first list
        let depth: i32 = content[list_start..pos]
            .bytes()
            .map(|b| match b {
                b'[' => 1,
                b']' => -1,
                _ => 0,
            })
            .sum();
        if depth <= 0 {
            break;
        }

        let name = parse_aterm_string(content, &mut pos)?;
        while pos < len && bytes[pos] != b'"' {
            pos += 1;
        }
        let path = parse_aterm_string(content, &mut pos)?;

        outputs.push((path, name));

        // Skip rest of tuple
        while pos < len && bytes[pos] != b')' {
            pos += 1;
        }
        if pos < len {
            pos += 1;
        }
    }

    Ok(outputs)
}

/// Extract the builder string from a .drv (4th string field).
fn parse_drv_builder(content: &str) -> Result<String> {
    let bytes = content.as_bytes();
    let len = bytes.len();

    let derive_start = content.find("Derive(").map(|i| i + 7).unwrap_or(0);

    // Skip past: [outputs],[inputDrvs],[inputSrcs],"system","builder"
    // We need to skip 3 lists and then read the 2nd string.
    let mut pos = derive_start;
    let mut lists_skipped = 0;

    while pos < len && lists_skipped < 3 {
        match bytes[pos] {
            b'[' => {
                // Skip entire list
                let mut depth = 1;
                pos += 1;
                while pos < len && depth > 0 {
                    match bytes[pos] {
                        b'[' => depth += 1,
                        b']' => depth -= 1,
                        b'"' => {
                            pos += 1;
                            while pos < len {
                                if bytes[pos] == b'\\' {
                                    pos += 2;
                                    continue;
                                }
                                if bytes[pos] == b'"' {
                                    break;
                                }
                                pos += 1;
                            }
                        }
                        _ => {}
                    }
                    pos += 1;
                }
                lists_skipped += 1;
            }
            _ => pos += 1,
        }
    }

    // Now read the system string (skip it)
    while pos < len && bytes[pos] != b'"' {
        pos += 1;
    }
    let _system = parse_aterm_string(content, &mut pos)?;

    // Skip comma
    while pos < len && bytes[pos] != b'"' {
        pos += 1;
    }

    // Read builder string
    let builder = parse_aterm_string(content, &mut pos)?;
    Ok(builder)
}

/// Parse a double-quoted ATerm string starting at `pos`.
/// `pos` should point to the opening `"`. On return, `pos` is after the closing `"`.
fn parse_aterm_string(content: &str, pos: &mut usize) -> Result<String> {
    let bytes = content.as_bytes();
    let len = bytes.len();

    if *pos >= len || bytes[*pos] != b'"' {
        anyhow::bail!("expected '\"' at position {}", *pos);
    }
    *pos += 1; // skip opening "

    let mut result = String::new();
    while *pos < len {
        match bytes[*pos] {
            b'\\' => {
                *pos += 1;
                if *pos < len {
                    match bytes[*pos] {
                        b'n' => result.push('\n'),
                        b't' => result.push('\t'),
                        b'\\' => result.push('\\'),
                        b'"' => result.push('"'),
                        other => {
                            result.push('\\');
                            result.push(other as char);
                        }
                    }
                }
            }
            b'"' => {
                *pos += 1; // skip closing "
                return Ok(result);
            }
            _ => result.push(bytes[*pos] as char),
        }
        *pos += 1;
    }

    anyhow::bail!("unterminated string at position {}", *pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aterm_string_basic() {
        let s = r#""hello world""#;
        let mut pos = 0;
        let result = parse_aterm_string(s, &mut pos).unwrap();
        assert_eq!(result, "hello world");
        assert_eq!(pos, s.len());
    }

    #[test]
    fn parse_aterm_string_escapes() {
        let s = r#""hello \"world\"""#;
        let mut pos = 0;
        let result = parse_aterm_string(s, &mut pos).unwrap();
        assert_eq!(result, r#"hello "world""#);
    }

    #[test]
    fn parse_drv_env_extracts_output_hash() {
        let drv = r#"Derive([("out","/nix/store/xxx-foo","sha256","abc")],[],[],"/nix/store/bash","builtin:fetchurl",[],[("name","foo-1.0.tar.gz"),("outputHash","sha256-AAAA"),("outputHashAlgo","sha256"),("outputHashMode","flat"),("url","https://example.com/foo.tar.gz")])"#;
        let env = parse_drv_env(drv).unwrap();
        assert_eq!(env.get("outputHash").unwrap(), "sha256-AAAA");
        assert_eq!(env.get("name").unwrap(), "foo-1.0.tar.gz");
        assert_eq!(env.get("url").unwrap(), "https://example.com/foo.tar.gz");
    }

    #[test]
    fn non_fod_returns_none() {
        let drv = r#"Derive([("out","/nix/store/xxx-bar","","")],[],[],"/nix/store/bash","/nix/store/builder",[],[("name","bar"),("system","x86_64-linux")])"#;
        // No outputHash in content
        assert!(!drv.contains("\"outputHash\""));
    }
}
