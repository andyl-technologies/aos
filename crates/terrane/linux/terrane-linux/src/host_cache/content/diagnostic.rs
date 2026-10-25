//! Reports original native preparation results only in explicit fixture builds.

use std::{fmt::Debug, future::Future};

/// Awaits the original operation without changing its result or cancellation owner.
///
/// # Errors
/// Returns the original operation's error unchanged.
pub(super) async fn stage<T, E: Debug>(
    name: &'static str,
    operation: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    #[cfg(feature = "native-test-fixtures")]
    let started = tokio::time::Instant::now();
    #[cfg(not(feature = "native-test-fixtures"))]
    let _ = name;

    let result = operation.await;

    #[cfg(feature = "native-test-fixtures")]
    {
        use std::io::Write as _;

        let elapsed = started.elapsed().as_millis();
        match &result {
            Ok(_) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "NATIVE_FILE_STAGE phase={name} elapsed_ms={elapsed} result=Ok"
                );
            }
            Err(error) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "NATIVE_FILE_STAGE phase={name} elapsed_ms={elapsed} result=Err({error:?})"
                );
            }
        }
    }
    result
}
