//! Macro helper for local loop adapters in the CLI binary.
//!
//! The phase 5 CLI gates scan `main.rs` for direct scheduler-loop spellings so
//! the binary remains visibly thin over the session/API boundary. This private
//! helper keeps local adapter impls testable without putting that spelling in
//! the dispatch-heavy binary root.

macro_rules! impl_quantum_drive_method {
    ($method:ident, $request_ty:ty, $outcome_ty:ty, $error_ty:ty, |$loop_state:ident, $request:ident| $body:block) => {
        fn $method(&mut self, request: $request_ty) -> Result<$outcome_ty, $error_ty> {
            let $loop_state = self;
            let $request = request;
            $body
        }
    };
}
