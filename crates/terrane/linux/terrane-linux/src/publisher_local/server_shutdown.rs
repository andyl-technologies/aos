//! Joins authenticated connection owners before retiring a publisher listener.
//!
//! Transport shutdown wakes blocked I/O while accepted commands retain their
//! original runtimes and physical completion waits. The configured caller then
//! drops domain senders and joins the native publication workers themselves.

use std::{
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use super::{super::socket::Connection, Error, Server};

struct ConnectionOwner {
    connection: Arc<Connection>,
    thread: thread::JoinHandle<()>,
}

#[derive(Default)]
struct ConnectionOwners {
    connections: Vec<ConnectionOwner>,
    stopping: Arc<AtomicBool>,
}

impl ConnectionOwners {
    fn reap(&mut self) -> Result<(), Error> {
        let mut index = 0;
        while index < self.connections.len() {
            if self.connections[index].thread.is_finished() {
                join(self.connections.swap_remove(index).thread)?;
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    fn start(&mut self, connection: Connection, server: &Server) -> Result<(), Error> {
        self.reap()?;
        if self.connections.len() >= server.config.max_connections {
            return Ok(());
        }

        let connection = Arc::new(connection);
        let endpoint = Arc::clone(&connection);
        let domains = Arc::clone(&server.domains);
        let custody = server.custody.clone();
        let metadata = Arc::clone(&server.metadata);
        let stopping = Arc::clone(&self.stopping);
        let thread = thread::Builder::new()
            .name("publisher-local-owner".into())
            .spawn(move || {
                let _custody = custody;
                let _ = super::run_connection(&endpoint, &domains, &metadata, Some(&stopping));
            })?;
        self.connections
            .push(ConnectionOwner { connection, thread });
        Ok(())
    }

    fn finish(mut self) -> Result<(), Error> {
        let mut failure = None;
        self.stopping.store(true, Ordering::Release);
        for owner in &self.connections {
            if let Err(error) = owner.connection.stop_transport() {
                // Disconnection already wakes the reader. Other failures must
                // prevent an acknowledged shutdown, but never skip joining.
                if error.raw_os_error() != Some(rustix::io::Errno::NOTCONN.raw_os_error()) {
                    failure.get_or_insert(Error::Io(error));
                }
            }
        }
        for owner in self.connections.drain(..) {
            if let Err(error) = join(owner.thread) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn join(thread: thread::JoinHandle<()>) -> Result<(), Error> {
    thread
        .join()
        .map_err(|_| Error::Io(io::Error::other("publisher connection owner panicked")))
}

/// Runs the owned listener until shutdown, then joins connections and retires it.
///
/// # Errors
/// Returns readiness, listener, connection-owner or retained-name custody failures.
pub(super) async fn run_until(
    server: Server,
    shutdown: impl Future<Output = io::Result<()>>,
    ready: impl FnOnce() -> io::Result<()>,
) -> Result<(), Error> {
    let mut owners = ConnectionOwners::default();
    let result = async {
        let descriptor = server.listener.nonblocking_descriptor()?;
        let readiness = tokio::io::unix::AsyncFd::new(descriptor)?;
        tokio::pin!(shutdown);
        ready()?;

        loop {
            tokio::select! {
                biased;
                result = &mut shutdown => break result.map_err(Error::Io),
                connection = readiness.async_io(tokio::io::Interest::READABLE, |_| {
                    match server.listener.accept() {
                        Ok(connection) => Ok(Some(connection)),
                        Err(Error::Denied) => Ok(None),
                        Err(Error::Io(error)) => Err(error),
                        Err(error) => Err(io::Error::other(error)),
                    }
                }) => {
                    if let Some(connection) = connection? {
                        owners.start(connection, &server)?;
                    }
                }
            }
        }
    }
    .await;

    // No accept future remains borrowed here. Always finish actual connection
    // work, including on readiness/listener failure; only clean shutdown may
    // remove the retained name. Dropping Server then closes domain senders.
    let completion = owners.finish();
    result?;
    completion?;
    server.listener.retire()
}
