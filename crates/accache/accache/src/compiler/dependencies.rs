//! Make-style dependency parsing shared by compiler discovery.

use anyhow::{Result, ensure};
use std::collections::BTreeSet;

/// Reads Make dependency syntax, including escaped spaces and continuations.
pub(super) fn dependencies(text: &str) -> Result<BTreeSet<String>> {
    let joined = text.replace("\\\n", "");
    let mut files = BTreeSet::new();
    for line in joined
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
    {
        let (_, rest) = line
            .split_once(": ")
            .or_else(|| line.strip_suffix(':').map(|value| (value, "")))
            .ok_or_else(|| anyhow::anyhow!("unsupported dependency syntax"))?;
        let mut word = String::new();
        let mut escaped = false;
        for ch in rest.chars().chain(std::iter::once(' ')) {
            if escaped {
                word.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch.is_whitespace() {
                if !word.is_empty() {
                    files.insert(std::mem::take(&mut word).replace("$$", "$"));
                }
            } else {
                word.push(ch);
            }
        }
        ensure!(!escaped, "incomplete dependency escape");
    }
    Ok(files)
}
