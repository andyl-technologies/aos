//! Shares the population read/parse recipe with retained raw native custody.
//!
//! The actual cgroup.events OFD remains on its monitor. Selected capture keeps
//! the same native read result and bytes through later posts; ordinary state()
//! moves the identical old error out at the original return boundary.

use super::*;
use std::os::unix::fs::FileExt as _;

/// Reports refusal while the same native population observation stays owned.
#[derive(Debug, thiserror::Error)]
#[error("retained cgroup population observation refused")]
pub struct CgroupPopulationObservationRefusalV1;

#[derive(Clone, Copy, Debug)]
enum First { Read, Parsed, Closed }

/// Retains one native read, bounded bytes and its exact parsed disposition.
#[derive(Debug)]
pub struct CgroupPopulationObservationV1 {
    bytes: [u8; 4097],
    read: Option<std::io::Result<usize>>,
    parsed: Option<Result<CgroupPopulationState>>,
    first: Option<First>,
    entered: bool,
}

impl Default for CgroupPopulationObservationV1 {
    fn default() -> Self { Self::new() }
}

impl CgroupPopulationObservationV1 {
    /// Creates fixed empty destinations without allocation or IO.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: [0; 4097], read: None, parsed: None, first: None, entered: false }
    }

    /// Bounds the owner, actual construction frame and two possible errors.
    ///
    /// The raw buffer, parser state and native Results occupy memory. This
    /// observation uses the monitor's already-held cgroup.events OFD and
    /// creates no path, map, index or other namespace entry.
    #[must_use]
    pub fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?.checked_add(2 * 256)
    }

    /// Borrows only the actual successful parsed state.
    #[must_use]
    pub fn state(&self) -> Option<CgroupPopulationState> {
        if self.first.is_some() { return None; }
        self.parsed.as_ref().and_then(|result| result.as_ref().ok()).copied()
    }

    /// Borrows the first native or parser cause, preserving ENODEV retirement.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Read => self.read.as_ref()?.as_ref().err().map(|error| error as _),
            First::Parsed => self.parsed.as_ref()?.as_ref().err().map(|error| error as _),
            First::Closed => Some(&CgroupPopulationObservationRefusalV1),
        }
    }

    fn capture_once(&mut self, events: &File) -> std::result::Result<(), CgroupPopulationObservationRefusalV1> {
        if self.entered {
            self.first.get_or_insert(First::Closed);
            return Err(CgroupPopulationObservationRefusalV1);
        }
        self.entered = true;
        self.read = Some(events.read_at(&mut self.bytes, 0));
        let length = match self.read.as_ref() {
            Some(Ok(length)) => *length,
            Some(Err(error)) if error.raw_os_error() == Some(libc::ENODEV) => {
                self.parsed = Some(Ok(CgroupPopulationState::Retired));
                return Ok(());
            }
            Some(Err(_)) => {
                self.first = Some(First::Read);
                return Err(CgroupPopulationObservationRefusalV1);
            }
            None => std::process::abort(),
        };
        self.parsed = Some(parse_population_record(&self.bytes, length));
        if matches!(self.parsed, Some(Ok(_))) { Ok(()) } else {
            self.first = Some(First::Parsed);
            Err(CgroupPopulationObservationRefusalV1)
        }
    }
}

impl CgroupPopulationMonitor {
    /// Reads this same held OFD into one pre-owned raw observation.
    ///
    /// # Errors
    /// Refuses repeated entry or the original native/parse failure. ENODEV from
    /// this original OFD retains the native result and means exact retirement.
    pub fn observe_state_retaining_v1(&self, observation: &mut CgroupPopulationObservationV1)
        -> std::result::Result<(), CgroupPopulationObservationRefusalV1>
    {
        observation.capture_once(&self.events)
    }
}

pub(super) fn read_population_state(events: &File) -> Result<CgroupPopulationState> {
    let mut observation = CgroupPopulationObservationV1::new();
    let _ = observation.capture_once(events);
    match observation.first {
        Some(First::Read) => {
            let Some(Err(source)) = observation.read.take() else { std::process::abort() };
            Err(Error::Syscall { operation: "read cgroup.events", source })
        }
        Some(First::Closed) => std::process::abort(),
        _ => match observation.parsed.take() {
            Some(result) => result,
            None => std::process::abort(),
        },
    }
}

fn parse_population_record(bytes: &[u8; 4097], length: usize) -> Result<CgroupPopulationState> {
    if length == 0 || length == bytes.len() {
        return Err(Error::MalformedKernelResponse {
            object: "cgroup.events",
            message: "population record is empty or oversized".to_owned(),
        });
    }
    let text = std::str::from_utf8(&bytes[..length]).map_err(|_| Error::MalformedKernelResponse {
        object: "cgroup.events",
        message: "population record is not UTF-8".to_owned(),
    })?;
    match text.lines().find_map(|line| line.strip_prefix("populated ")) {
        Some("0") => Ok(CgroupPopulationState::Empty),
        Some("1") => Ok(CgroupPopulationState::Populated),
        _ => Err(Error::MalformedKernelResponse {
            object: "cgroup.events",
            message: "population field is absent or invalid".to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek as _, Write as _};

    #[test]
    fn malformed_actual_record_keeps_native_bytes_and_refuses_reentry() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"populated broken\n").unwrap();
        let mut observed = CgroupPopulationObservationV1::new();
        assert!(observed.capture_once(&file).is_err());
        assert!(matches!(observed.read, Some(Ok(17))));
        assert_eq!(&observed.bytes[..17], b"populated broken\n");
        let cause = observed.failure().unwrap() as *const dyn std::error::Error as *const ();

        file.set_len(0).unwrap();
        file.rewind().unwrap();
        file.write_all(b"populated 0\n").unwrap();
        assert!(observed.capture_once(&file).is_err());
        assert_eq!(observed.failure().unwrap() as *const dyn std::error::Error as *const (), cause);
        assert_eq!(&observed.bytes[..17], b"populated broken\n");
        assert!(observed.state().is_none());
        assert_eq!(read_population_state(&file).unwrap(), CgroupPopulationState::Empty);
    }

    #[test]
    fn ordinary_and_retained_use_the_existing_first_matching_field_recipe() {
        for (bytes, expected) in [
            (b"populated 0\n".as_slice(), CgroupPopulationState::Empty),
            (b"frozen 0\npopulated 1\n".as_slice(), CgroupPopulationState::Populated),
            (b"populated 0\npopulated 1\n".as_slice(), CgroupPopulationState::Empty),
        ] {
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(bytes).unwrap();
            let ordinary = read_population_state(&file).unwrap();
            let mut retained = CgroupPopulationObservationV1::new();
            retained.capture_once(&file).unwrap();

            assert_eq!(ordinary, expected);
            assert_eq!(retained.state(), Some(expected));
            assert!(retained.failure().is_none());
            assert_eq!(&retained.bytes[..bytes.len()], bytes);
        }
    }
}
