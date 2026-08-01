//! Generic process-test artifact discovery helpers.

use super::*;

pub(super) fn single_savepoint_handle(dir: &Path, label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let prefix = format!("savepoint-{label}-");
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid_data(format!("non-UTF-8 entry in `{}`", dir.display())))?;
        if file_name.starts_with(&prefix) && file_name.ends_with(".crucible-savepoint") {
            paths.push(path);
        }
    }
    paths.sort();
    match paths.as_slice() {
        [path] => Ok(path.clone()),
        _ => Err(invalid_data(format!(
            "expected one savepoint handle with prefix `{prefix}` in `{}`, found {}",
            dir.display(),
            paths.len()
        ))
        .into()),
    }
}
