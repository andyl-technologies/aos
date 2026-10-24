//! Forwards actual native DATA recipes with independent observation and physical faults.

use super::{Fault, ReadFs};
use crate::store::{LocalFs, NativePayloadRangeRead, NativePayloadRangeRecord, TokioLocalFs};
use std::path::Path;

impl ReadFs {
    /// Forwards unchanged native capture, DATA, probe and closing requests.
    ///
    /// # Errors
    /// Preserves actual native failures and physical replacement I/O.
    ///
    /// # Panics
    /// Panics if an isolated observer or replacement mutex is poisoned.
    pub(super) async fn forward_native_ranges(
        &self,
        request: NativePayloadRangeRead,
    ) -> std::io::Result<Option<NativePayloadRangeRecord>> {
        let data_path = request.read_data_range().map(|(path, _)| path.to_owned());
        let fault = if let Some(path) = &data_path {
            self.native_paths.lock().unwrap().push(path.clone());
            let mut armed = self.fault.lock().unwrap();
            if armed.as_ref().is_some_and(|(target, _)| target == path) {
                armed.take().map(|(_, fault)| fault)
            } else {
                None
            }
        } else {
            None
        };

        let record = TokioLocalFs.read_payload_ranges(request).await?;
        if record.is_some()
            && let Some(path) = data_path
        {
            replace_incarnation(&path, fault).await?;
            let replacement = {
                let mut armed = self.after_data_replacement.lock().unwrap();
                if armed.as_ref().is_some_and(|(trigger, _)| *trigger == path) {
                    armed.take().map(|(_, target)| target)
                } else {
                    None
                }
            };
            if let Some(target) = replacement {
                replace_incarnation(&target, Some(Fault::ReplaceLeaf)).await?;
            }
        }
        Ok(record)
    }
}

// Replacements follow a successful native DATA read. Its unchanged actual
// result can be consumed, but the genuine closing recipe must reject the new name.
async fn replace_incarnation(path: &Path, fault: Option<Fault>) -> std::io::Result<()> {
    if let Some(Fault::ReplaceLeaf) = fault {
        let bytes = TokioLocalFs.read_nofollow(path).await?;
        let temporary = path.with_extension("overlay-history-replacement");
        let permissions = TokioLocalFs.symlink_metadata(path).await?.permissions();
        TokioLocalFs.write_new(&temporary, &bytes).await?;
        TokioLocalFs
            .set_permissions_and_sync(&temporary, permissions)
            .await?;
        TokioLocalFs.rename(&temporary, path).await?;
    }
    Ok(())
}
