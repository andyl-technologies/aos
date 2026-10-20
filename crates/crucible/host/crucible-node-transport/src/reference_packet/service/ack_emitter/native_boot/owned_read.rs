//! Owns one inherited private stream and its immutable original birth cut.

use crate::client::OriginalNative5BirthCut;
use std::{io, os::fd::AsFd};

pub(super) struct OriginalPrivateBootstrapStream<S> {
    pub(super) original: S,
    pub(super) cut: Option<OriginalNative5BirthCut>,
}

impl<S: AsFd> io::Read for OriginalPrivateBootstrapStream<S> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.cut
            .as_ref()
            .ok_or_else(|| io::Error::other("native original birth cut transferred"))?
            .ensure_current()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.cut
                .as_ref()
                .ok_or_else(|| io::Error::other("native original birth cut transferred"))?
                .ensure_current()?;
            match rustix::net::recv(
                &self.original,
                &mut *bytes,
                rustix::net::RecvFlags::DONTWAIT,
            ) {
                Ok((_, received)) => return Ok(received),
                Err(error) if error == rustix::io::Errno::AGAIN => std::thread::yield_now(),
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}
