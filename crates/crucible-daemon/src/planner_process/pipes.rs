//! Deadline-bound, nonblocking I/O for one canonical planner process.
//!
//! The supervisor owns all pipe descriptors. No reader thread can outlive the
//! exchange or keep cancellation waiting on EOF from an inherited descriptor.

use std::os::fd::AsFd;

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

use super::*;

pub(super) fn exchange(
    child: &mut Child,
    request: &[u8],
    deadline: Instant,
    canceled: &AtomicBool,
) -> Result<(ExitStatus, CapturedOutput, CapturedOutput), CanonicalPlannerProcessError> {
    let (Some(stdin), Some(mut stdout), Some(mut stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(CanonicalPlannerProcessError::InvalidConfiguration(
            "canonical planner child pipe is unavailable",
        ));
    };
    nonblocking(&stdin)?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;

    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + request.len());
    write_frame(&mut frame, REQUEST_KIND, request)
        .map_err(|source| process_io("frame-canonical-planner-request", source))?;
    let mut stdin = Some(stdin);
    let mut written = 0;
    let mut output = Capture::new(FRAME_HEADER_BYTES + MAX_PLANNER_COMPONENT_MESSAGE_BYTES);
    let mut diagnostic = Capture::new(MAX_STDERR_BYTES);
    let mut status = None;
    loop {
        check_boundary(deadline, canceled)?;
        let mut progressed = false;
        if let Some(pipe) = stdin.as_mut() {
            match pipe.write(&frame[written..]) {
                Ok(0) => {
                    return Err(process_io(
                        "write-canonical-planner-request",
                        io::ErrorKind::WriteZero.into(),
                    ));
                }
                Ok(count) => {
                    written += count;
                    progressed = true;
                    if written == frame.len() {
                        stdin = None;
                    }
                }
                Err(error) if retryable_io(&error) => {}
                Err(source) => return Err(process_io("write-canonical-planner-request", source)),
            }
        }
        progressed |= output
            .read_once(&mut stdout)
            .map_err(|source| process_io("read-canonical-planner-response", source))?;
        progressed |= diagnostic
            .read_once(&mut stderr)
            .map_err(|source| process_io("read-canonical-planner-stderr", source))?;
        if output.output.overflow {
            return Err(CanonicalPlannerProcessError::OutputLimitExceeded);
        }
        if status.is_none() {
            status = owner::observe_exit(child)
                .map_err(|source| process_io("poll-canonical-planner", source))?;
        }
        if let Some(status) = status
            && output.eof
            && diagnostic.eof
            && stdin.is_none()
        {
            return Ok((status, output.output, diagnostic.output));
        }
        if !progressed {
            thread::sleep(
                CHILD_POLL_INTERVAL.min(deadline.saturating_duration_since(process_now())),
            );
        }
    }
}

fn nonblocking(fd: &impl AsFd) -> Result<(), CanonicalPlannerProcessError> {
    fcntl_getfl(fd)
        .and_then(|flags| fcntl_setfl(fd, flags | OFlags::NONBLOCK))
        .map_err(|source| process_io("configure-canonical-planner-pipe", source.into()))
}

fn check_boundary(
    deadline: Instant,
    canceled: &AtomicBool,
) -> Result<(), CanonicalPlannerProcessError> {
    if canceled.load(Ordering::Acquire) {
        return Err(CanonicalPlannerProcessError::Canceled);
    }
    if process_now() >= deadline {
        return Err(CanonicalPlannerProcessError::TimedOut);
    }
    Ok(())
}

fn retryable_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

struct Capture {
    output: CapturedOutput,
    maximum: usize,
    eof: bool,
}

impl Capture {
    fn new(maximum: usize) -> Self {
        Self {
            output: CapturedOutput {
                bytes: Vec::with_capacity(maximum.min(64 * 1024)),
                overflow: false,
            },
            maximum,
            eof: false,
        }
    }

    // One bounded read per pipe keeps a continuously writing peer from
    // starving cancellation, request transmission, or the other pipe.
    fn read_once(&mut self, reader: &mut impl Read) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let mut buffer = [0_u8; 16 * 1024];
        match reader.read(&mut buffer) {
            Ok(0) => {
                self.eof = true;
                Ok(true)
            }
            Ok(count) => {
                let retained = count.min(self.maximum.saturating_sub(self.output.bytes.len()));
                self.output.bytes.extend_from_slice(&buffer[..retained]);
                self.output.overflow |= retained != count;
                Ok(true)
            }
            Err(error) if retryable_io(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
pub(super) mod tests;
