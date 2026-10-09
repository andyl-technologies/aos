//! Owns Controller socket custody and root-only diagnostic acceptance.

use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::Duration;

use super::{ControllerRuntimeError, ControllerServerTerminal};

pub(super) fn bind_controller_socket(
    path: &Path,
    uid: u32,
    mode: u32,
) -> Result<std::os::unix::net::UnixListener, ControllerRuntimeError> {
    let parent = path
        .parent()
        .ok_or(ControllerRuntimeError::UnsafeDiagnosticSocket)?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != uid
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ControllerRuntimeError::UnsafeDiagnosticSocket);
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == uid => {
            std::fs::remove_file(path)
                .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
        }
        Ok(_) => return Err(ControllerRuntimeError::UnsafeDiagnosticSocket),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ControllerRuntimeError::DiagnosticSocketFilesystem(error)),
    }
    let listener = std::os::unix::net::UnixListener::bind(path)
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    listener
        .set_nonblocking(true)
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    Ok(listener)
}

// Called inside the existing runtime with only loans of the parent's fields.
// Neither a returned error nor a registered listener crosses that runtime
// return boundary before entering the same parent's resident destination.
pub(super) fn register_retained_diagnostic(
    attempt: &mut tokio::net::UnixListenerRegistrationAttempt,
    destination: &mut Option<AuthenticatedDiagnosticListener>,
    terminal: &dyn ControllerServerTerminal,
) {
    if destination.is_some() {
        terminal.closed("Controller diagnostic destination occupied");
    }

    let listener = match attempt.register() {
        Ok(listener) => listener,
        Err(cause) => terminal.runtime(ControllerRuntimeError::DiagnosticSocketRuntime(cause)),
    };
    *destination = Some(AuthenticatedDiagnosticListener::new(listener, 0));
}

pub(super) async fn into_async_diagnostic_listener(
    listener: std::os::unix::net::UnixListener,
) -> Result<AuthenticatedDiagnosticListener, ControllerRuntimeError> {
    into_async_authenticated_listener(listener, 0).await
}

pub(super) async fn into_async_authenticated_listener(
    listener: std::os::unix::net::UnixListener,
    expected_uid: u32,
) -> Result<AuthenticatedDiagnosticListener, ControllerRuntimeError> {
    let listener = tokio::net::UnixListener::from_std(listener)
        .map_err(ControllerRuntimeError::DiagnosticSocketRuntime)?;
    Ok(AuthenticatedDiagnosticListener::new(listener, expected_uid))
}

pub(super) struct AuthenticatedDiagnosticListener {
    listener: tokio::net::UnixListener,
    expected_uid: u32,
}

impl AuthenticatedDiagnosticListener {
    const fn new(listener: tokio::net::UnixListener, expected_uid: u32) -> Self {
        Self {
            listener,
            expected_uid,
        }
    }
}

impl axum::serve::Listener for AuthenticatedDiagnosticListener {
    type Io = tokio::net::UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.listener.accept().await {
                Ok((stream, address)) => match stream.peer_cred() {
                    Ok(credentials) if credentials.uid() == self.expected_uid => {
                        return (stream, address);
                    }
                    Ok(credentials) => {
                        eprintln!(
                            "aos-sandboxd: rejected diagnostic connection from UID {}",
                            credentials.uid()
                        );
                    }
                    Err(error) => {
                        eprintln!(
                            "aos-sandboxd: rejected diagnostic connection without peer credentials: {error}"
                        );
                    }
                },
                Err(error) => {
                    eprintln!("aos-sandboxd: diagnostic socket accept failed: {error}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::serve::Listener as _;

    #[test]
    fn diagnostic_listener_is_registered_inside_the_async_runtime_with_root_policy() {
        let directory = tempfile::tempdir().unwrap();
        let uid = rustix::process::getuid().as_raw();
        let socket = directory.path().join("diagnostics.sock");
        let listener = bind_controller_socket(&socket, uid, 0o660).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let listener = runtime
            .block_on(into_async_diagnostic_listener(listener))
            .unwrap();

        assert_eq!(listener.expected_uid, 0);
        assert_eq!(
            listener.local_addr().unwrap().as_pathname(),
            Some(socket.as_path())
        );
    }

    #[test]
    fn diagnostic_listener_accepts_the_exact_authenticated_uid() {
        let directory = tempfile::tempdir().unwrap();
        let uid = rustix::process::getuid().as_raw();
        let socket = directory.path().join("diagnostics.sock");
        let listener = bind_controller_socket(&socket, uid, 0o660).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut listener = runtime
            .block_on(into_async_authenticated_listener(listener, uid))
            .unwrap();

        runtime.block_on(async {
            let _client = tokio::net::UnixStream::connect(&socket).await.unwrap();
            tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .unwrap();
        });
    }

    #[test]
    fn diagnostic_listener_rejects_every_other_uid() {
        let directory = tempfile::tempdir().unwrap();
        let uid = rustix::process::getuid().as_raw();
        let socket = directory.path().join("diagnostics.sock");
        let listener = bind_controller_socket(&socket, uid, 0o660).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let unexpected_uid = if uid == u32::MAX { uid - 1 } else { uid + 1 };
        let mut listener = runtime
            .block_on(into_async_authenticated_listener(listener, unexpected_uid))
            .unwrap();

        runtime.block_on(async {
            let _client = tokio::net::UnixStream::connect(&socket).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
    }
}
