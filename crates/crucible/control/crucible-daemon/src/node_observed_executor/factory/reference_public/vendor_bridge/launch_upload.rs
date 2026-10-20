//! Owns the original bootstrap frame and one physical preparation deadline.
//!
//! Frame storage is reserved before Child. The same queue-owned holder keeps
//! the actual pipe, partial cursor and first cut after refusal or unwind. It
//! never resumes an uncertain write or lends another preparation budget.

use std::{
    io::{self, Write},
    process::ChildStdin,
    time::Duration,
};

use crucible_node_transport::{ProviderError, client::ExchangeDeadline};

#[cfg(test)]
#[path = "launch_upload_tests.rs"]
mod tests;

pub(super) struct OriginalLaunchUpload {
    frame: OriginalLaunchFrame,
    pub(super) stdin: Option<ChildStdin>,
}

impl OriginalLaunchUpload {
    pub(super) fn reserve(body: &[u8], maximum_bytes: usize) -> Result<Self, ProviderError> {
        Ok(Self {
            frame: OriginalLaunchFrame::reserve(body, maximum_bytes)?,
            stdin: None,
        })
    }

    pub(super) fn completed_original(&self) -> Result<&[u8], ProviderError> {
        if !self.frame.attempted
            || self.frame.cursor != self.frame.bytes.len()
            || self.frame.deadline.is_none()
            || self.stdin.is_some()
        {
            return Err(ProviderError::Correlation(
                "original launch upload remains unresolved",
            ));
        }
        Ok(&self.frame.bytes)
    }

    pub(super) fn is_unstarted(&self) -> bool {
        !self.frame.attempted && self.stdin.is_none()
    }

    // The pipe is already in this holder before any fallible fcntl or write.
    pub(super) fn upload(&mut self, budget: Duration) -> Result<ExchangeDeadline, ProviderError> {
        self.frame.begin(budget)?;
        let stdin = self.stdin.as_mut().ok_or(ProviderError::Correlation(
            "ordinary private launch pipe absent",
        ))?;
        let flags = rustix::fs::fcntl_getfl(&*stdin).map_err(io::Error::from)?;
        rustix::fs::fcntl_setfl(&*stdin, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(io::Error::from)?;
        self.frame.write_original(stdin)?;

        // EOF is permitted only after all bytes of the original frame were sent.
        self.stdin.take();
        self.frame.deadline()
    }
}

struct OriginalLaunchFrame {
    bytes: Vec<u8>,
    cursor: usize,
    attempted: bool,
    deadline: Option<ExchangeDeadline>,
}

impl OriginalLaunchFrame {
    fn reserve(body: &[u8], maximum_bytes: usize) -> Result<Self, ProviderError> {
        if maximum_bytes == 0 || body.len() > maximum_bytes {
            return Err(ProviderError::ResourceExhausted(
                "ordinary launch frame credit",
            ));
        }
        let length = u32::try_from(body.len())
            .map_err(|_| ProviderError::Frame("ordinary launch length overflow"))?;
        let bytes = body
            .len()
            .checked_add(4)
            .ok_or(ProviderError::ResourceExhausted(
                "ordinary launch frame total overflow",
            ))?;
        let mut frame = Vec::new();
        frame.try_reserve_exact(bytes).map_err(|_| {
            ProviderError::ResourceExhausted("ordinary launch frame storage unavailable")
        })?;
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(body);

        Ok(Self {
            bytes: frame,
            cursor: 0,
            attempted: false,
            deadline: None,
        })
    }

    fn begin(&mut self, budget: Duration) -> Result<(), ProviderError> {
        if self.attempted || self.deadline.is_some() {
            return Err(ProviderError::Correlation(
                "ordinary launch original already attempted",
            ));
        }
        // The attempt latches even if the requested cut itself is invalid.
        self.attempted = true;
        self.deadline = Some(ExchangeDeadline::start(budget)?);
        Ok(())
    }

    fn deadline(&self) -> Result<ExchangeDeadline, ProviderError> {
        self.deadline.clone().ok_or(ProviderError::Correlation(
            "ordinary launch original deadline absent",
        ))
    }

    fn write_original(&mut self, output: &mut impl Write) -> Result<(), ProviderError> {
        let deadline = self.deadline()?;
        while self.cursor < self.bytes.len() {
            deadline.remaining()?;
            let end = self.cursor.saturating_add(16_384).min(self.bytes.len());
            match output.write(&self.bytes[self.cursor..end]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ordinary launch pipe refused original bytes",
                    )
                    .into());
                }
                Ok(written) if written <= end - self.cursor => self.cursor += written,
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ordinary launch writer returned an invalid count",
                    )
                    .into());
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    std::thread::park_timeout(deadline.remaining()?.min(Duration::from_millis(1)));
                }
                Err(error) => return Err(error.into()),
            }
        }
        // A late final write cannot renew the cut or authorize Hello.
        deadline.remaining()?;
        Ok(())
    }
}
