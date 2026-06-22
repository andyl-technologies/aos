//! Recording of impure evaluator input observations for future cache leaves.

use super::*;

impl TreeWalk {
    pub(super) fn record_impure_input_result(
        &mut self,
        fingerprint: Result<ImpureInputFingerprint, InputFingerprintError>,
    ) {
        let Ok(fingerprint) = fingerprint else {
            self.mark_impure_input_trace_incomplete();
            return;
        };
        self.record_impure_input(fingerprint);
    }

    pub(super) fn record_impure_input(&mut self, fingerprint: ImpureInputFingerprint) {
        if !self.impure_input_trace_complete {
            return;
        }
        if self.impure_input_trace.try_reserve_exact(1).is_err() {
            self.mark_impure_input_trace_incomplete();
            return;
        }
        self.impure_input_trace.push(fingerprint);
    }

    pub(super) fn mark_impure_input_trace_incomplete(&mut self) {
        self.impure_input_trace.clear();
        self.impure_input_trace_complete = false;
    }

    pub(super) fn file_type_for_impure_input(file_type: fs::FileType) -> FileTypeForInput {
        if file_type.is_file() {
            FileTypeForInput::Regular
        } else if file_type.is_dir() {
            FileTypeForInput::Directory
        } else if file_type.is_symlink() {
            FileTypeForInput::Symlink
        } else {
            FileTypeForInput::Unknown
        }
    }
}
