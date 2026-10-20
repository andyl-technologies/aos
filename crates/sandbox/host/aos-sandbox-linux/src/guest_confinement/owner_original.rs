//! Shares the fixed Guest Owner predicate while retaining selected native prefixes.

use super::*;

struct KernelBooleanOriginalV2 {
    file: Option<std::io::Take<File>>,
    opened: Option<Result<()>>,
    filesystem: Option<Result<()>>,
    bytes: Vec<u8>,
    read: Option<std::io::Result<usize>>,
    value: Option<Result<()>>,
}

impl KernelBooleanOriginalV2 {
    fn new() -> Self {
        Self {
            file: None,
            opened: None,
            filesystem: None,
            bytes: Vec::new(),
            read: None,
            value: None,
        }
    }

    fn capture(&mut self, path: &'static str, retained: bool) -> Result<()> {
        match open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => {
                self.file = Some(File::from(descriptor).take(3));
                self.opened = Some(Ok(()));
            }
            Err(source) => self.opened = Some(Err(syscall("open Guest confinement state")(source))),
        }
        if !matches!(self.opened, Some(Ok(()))) {
            return transfer_failure(&mut self.opened, retained);
        }
        let file = self.file.as_mut().ok_or_else(closed)?;
        self.filesystem = Some(require_selinuxfs(file.get_ref().as_fd()));
        if !matches!(self.filesystem, Some(Ok(()))) {
            return transfer_failure(&mut self.filesystem, retained);
        }
        self.read = Some(file.read_to_end(&mut self.bytes));
        if !retained {
            drop(self.file.take());
        }
        if !matches!(self.read, Some(Ok(_))) {
            if !retained {
                if let Some(Err(source)) = self.read.take() {
                    return Err(Error::Syscall {
                        operation: "read Guest confinement state",
                        source,
                    });
                }
            }
            return Err(closed());
        }
        self.value = Some(if self.bytes == b"1" || self.bytes == b"1\n" {
            Ok(())
        } else {
            Err(Error::invalid(
                "Guest confinement",
                "required kernel boolean is false",
            ))
        });
        if matches!(self.value, Some(Ok(()))) {
            Ok(())
        } else {
            transfer_failure(&mut self.value, retained)
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        cause(&self.opened)
            .or_else(|| cause(&self.filesystem))
            .or_else(|| cause(&self.read))
            .or_else(|| cause(&self.value))
    }
}

/// Retains the original context, NNP and two fixed enforcing-policy reads.
///
/// This is the existing predicate, without a caller path or expected label.
/// Its successful comparison creates no Owner role or mutation permission.
pub struct GuestOwnerOriginalV2 {
    subject: CurrentThreadSubjectOriginalV1,
    nnp: Option<rustix::io::Result<bool>>,
    booleans: [KernelBooleanOriginalV2; 2],
    body: Option<Result<()>>,
    entered: bool,
    reentry: Option<Error>,
    disposed: bool,
}

impl Default for GuestOwnerOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestOwnerOriginalV2 {
    /// Creates inert storage before observing the fixed Owner predicate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subject: CurrentThreadSubjectOriginalV1::new(),
            nnp: None,
            booleans: std::array::from_fn(|_| KernelBooleanOriginalV2::new()),
            body: None,
            entered: false,
            reentry: None,
            disposed: false,
        }
    }

    pub(super) fn ordinary() -> Result<()> {
        Self::new().capture(false)
    }

    fn capture(&mut self, retained: bool) -> Result<()> {
        if retained {
            self.subject.observe_once(GUEST_OWNER_CONTEXT)?;
        } else {
            self.subject.observe_recipe(GUEST_OWNER_CONTEXT, false)?;
        }
        self.nnp = Some(rustix::thread::no_new_privs());
        match self.nnp.as_ref() {
            Some(Ok(true)) => {}
            Some(Err(source)) => return Err(syscall("read inherited NNP")(*source)),
            _ => return Err(Error::invalid("Guest owner", "inherited NNP is absent")),
        }
        self.booleans[0].capture("/sys/fs/selinux/enforce", retained)?;
        self.booleans[1].capture(
            "/sys/fs/selinux/policy_capabilities/nnp_nosuid_transition",
            retained,
        )
    }

    /// Observes only the existing fixed predicate, once.
    ///
    /// # Errors
    /// Retains foreign context, missing NNP/enforcement/policy, raw File/read
    /// failures and reentry. No partial native File is released on refusal.
    pub fn capture_once_v2(&mut self) -> Result<()> {
        if self.entered {
            self.reentry.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.body = Some(self.capture(true));
        if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    /// Physically retires only a complete positive predicate's three Files.
    ///
    /// # Errors
    /// Keeps every failed, incomplete or repeated native prefix occupied.
    pub fn dispose_positive_once_v2(&mut self) -> Result<()> {
        if self.disposed || !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            return Err(closed());
        }
        if !self.subject.retire_completed_file_once_v1() {
            return Err(closed());
        }
        for boolean in &mut self.booleans {
            drop(boolean.file.take());
        }
        self.disposed = true;
        Ok(())
    }

    /// Borrows the first original predicate failure without further IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.subject
            .failure()
            .or_else(|| cause(&self.nnp))
            .or_else(|| {
                self.booleans
                    .iter()
                    .find_map(KernelBooleanOriginalV2::failure)
            })
            .or_else(|| cause(&self.body))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    /// Prices actual carriers, bounded byte allocation, three Files and paths.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let subject = CurrentThreadSubjectOriginalV1::receiving_demand_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(subject.0)?
            .checked_add(4 * 32 + 8 * 256)?
            .checked_add(
                2 * (b"/sys/fs/selinux/enforce\0".len()
                    + b"/sys/fs/selinux/policy_capabilities/nnp_nosuid_transition\0".len()),
            )?;
        Some((bytes, 3, 3))
    }
}

fn transfer_failure(value: &mut Option<Result<()>>, retained: bool) -> Result<()> {
    if !retained {
        return value.take().ok_or_else(closed)?;
    }
    Err(closed())
}

fn cause<T, E: std::error::Error + 'static>(
    value: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed() -> Error {
    Error::invalid(
        "Guest Owner predicate",
        "original native predicate remains occupied",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_filesystem_retains_the_actual_open_file_before_refusal() {
        let mut original = KernelBooleanOriginalV2::new();

        assert!(original.capture("/dev/null", true).is_err());

        assert!(original.file.is_some());
        assert!(matches!(original.opened, Some(Ok(()))));
        assert!(matches!(
            original.filesystem,
            Some(Err(Error::WrongDescriptorType { .. }))
        ));
        assert!(original.read.is_none());
        assert!(original.failure().is_some());
        assert!(fstat(original.file.as_ref().unwrap().get_ref()).is_ok());
    }
}
