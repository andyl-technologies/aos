//! Forwards actual native DATA recipes with independent observation and physical faults.

use super::{Fault, ReadFs};
use crate::store::{LocalFs, NativePayloadRangeRead, NativePayloadRangeRecord, TokioLocalFs};
use std::path::Path;

impl ReadFs {
    /// Forwards unchanged native capture, DATA, probe and closing requests.
    ///
    /// # Errors
    /// Preserves actual native failures, injected DATA errors and physical fault I/O.
    ///
    /// # Panics
    /// Panics if an isolated observer, fault or pause mutex is poisoned.
    pub(super) async fn forward_native_ranges(
        &self,
        request: NativePayloadRangeRead,
    ) -> std::io::Result<Option<NativePayloadRangeRecord>> {
        if let Some(path) = request.capture_path_for_test() {
            let corrupt = {
                let mut armed = self.fault.lock().unwrap();
                if armed.as_ref().is_some_and(|(target, fault)| {
                    target == path && matches!(fault, Fault::Corrupt)
                }) {
                    armed.take();
                    true
                } else {
                    false
                }
            };
            if corrupt {
                // Change the real file before capture. The sealed native result
                // remains genuine and must fail ordinary whole-pack verification.
                let mut bytes = TokioLocalFs.read_nofollow(path).await?;
                *bytes
                    .last_mut()
                    .ok_or_else(|| std::io::Error::other("empty fixture body"))? ^= 1;
                tokio::fs::write(path, bytes).await?;
            }
        }

        let data_path = request.read_data_range().map(|(path, _)| path.to_owned());
        let fault = if let Some(path) = &data_path {
            self.native_paths.lock().unwrap().push(path.clone());
            let pause = {
                let mut armed = self.pause.lock().unwrap();
                if armed.as_ref().is_some_and(|pause| pause.target == *path) {
                    armed.take()
                } else {
                    None
                }
            };
            if let Some(pause) = pause {
                pause
                    .entered
                    .send(())
                    .map_err(|_| std::io::Error::other("DATA observer dropped"))?;
                pause
                    .released
                    .await
                    .map_err(|_| std::io::Error::other("DATA release dropped"))?;
            }
            if self.native_failure.lock().unwrap().as_ref() == Some(path) {
                return Err(std::io::Error::other(
                    "configured native held reader failure",
                ));
            }
            let fault = {
                let mut armed = self.fault.lock().unwrap();
                if armed.as_ref().is_some_and(|(target, _)| target == path) {
                    armed.take().map(|(_, fault)| fault)
                } else {
                    None
                }
            };
            if matches!(fault, Some(Fault::Unavailable)) {
                return Err(std::io::Error::other(
                    "actual native held history DATA unavailable",
                ));
            }
            fault
        } else {
            None
        };

        let record = TokioLocalFs.read_payload_ranges(request).await?;
        if record.is_some()
            && let Some(path) = data_path
        {
            replace_incarnation(&path, fault).await?;
        }
        Ok(record)
    }
}

// Replacements follow a successful native DATA read. Its unchanged actual
// result can be consumed, but the genuine closing recipe must reject the new name.
async fn replace_incarnation(path: &Path, fault: Option<Fault>) -> std::io::Result<()> {
    match fault {
        Some(Fault::ReplaceLeaf) => {
            let bytes = TokioLocalFs.read_nofollow(path).await?;
            let temporary = path.with_extension("held-history-replacement");
            TokioLocalFs.write_new(&temporary, &bytes).await?;
            TokioLocalFs.rename(&temporary, path).await?;
        }
        Some(Fault::ReplaceParent) => {
            let parent = path
                .parent()
                .ok_or_else(|| std::io::Error::other("fixture parent absent"))?;
            let archived = parent.with_extension("held-history-ancestor");
            TokioLocalFs.rename(parent, &archived).await?;
            // Preserve actual file inodes and bytes while the newly named
            // parent supplies a distinct ancestor incarnation.
            TokioLocalFs.create_dir_new(parent).await?;
            for original in TokioLocalFs.read_dir(&archived).await? {
                let name = original
                    .file_name()
                    .ok_or_else(|| std::io::Error::other("fixture leaf absent"))?;
                TokioLocalFs.rename(&original, &parent.join(name)).await?;
            }
            TokioLocalFs.remove_dir(&archived).await?;
        }
        _ => {}
    }
    Ok(())
}
