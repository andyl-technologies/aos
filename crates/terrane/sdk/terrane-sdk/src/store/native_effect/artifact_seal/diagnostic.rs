//! Hosts opt-in diagnostic observations for native publication test failures.
//!
//! Observations retain the original result, predicate order and clock samples.
//! This module participates only in test builds and creates no authority.

use std::{io::Write, path::Path};

/// Reports an original failing check without inspecting or replacing its error.
pub(super) fn refusal(stage: &str, path: Option<&Path>, ordinal: Option<usize>) {
    if std::env::var_os("TERRANE_REF_PHASE_TRACE").is_none() {
        return;
    }
    let _ = writeln!(
        std::io::stderr().lock(),
        "native-refusal stage={stage} path={path:?} ordinal={ordinal:?}",
    );
}
