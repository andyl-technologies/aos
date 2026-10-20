//! Shares the current-service pidfd/namespace probe and its retained prefixes.
//!
//! This observer proves kernel namespace-access DATA only. It cannot issue a
//! role, launch permission or process handle from caller-supplied coordinates.

use aos_sandbox_linux::pidfd::{PidFdInfo, PidFdNamespaceOriginalV2, PidFdOpenAttemptV1};

use super::*;

type Native<T> = std::result::Result<T, aos_sandbox_linux::Error>;

macro_rules! probe_open {
    (Local, $original:ident, $pid:ident) => {
        PidFd::open($pid).map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $pid:ident) => {{
        $original.opening.capture_once($pid).map_err(|_| closed("host pidfd opening failed; original retained"))?;
        $original.process = Some($original.opening.take_validated()
            .ok_or_else(|| closed("host pidfd opening is incomplete"))?);
        $original.process.as_ref().ok_or_else(|| closed("host process pin is absent"))?
    }};
}

macro_rules! probe_native {
    (Local, $original:ident, $field:ident, $expression:expr) => {
        $expression.map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $field:ident, $expression:expr) => {{
        $original.$field = Some($expression);
        match $original.$field.as_ref() {
            Some(Ok(value)) => *value,
            _ => return Err(closed("host namespace probe failed; native cause retained")),
        }
    }};
}

macro_rules! probe_namespace {
    (Local, $original:ident, $field:ident, $slot:expr, $process:ident, $kind:ident) => {
        $process.namespace(NamespaceKind::$kind).map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $field:ident, $slot:expr, $process:ident, $kind:ident) => {{
        $original.namespaces[$slot].capture_once($process, NamespaceKind::$kind)
            .map_err(|_| closed("host namespace ioctl failed; original retained"))?;
        $original.$field = Some($original.namespaces[$slot].take_completed_once()
            .ok_or_else(|| closed("host namespace ioctl is incomplete"))?);
        $original.$field.as_ref().ok_or_else(|| closed("host namespace pin is absent"))?
    }};
}

macro_rules! probe_finish {
    (Local, $original:ident, $process:ident, $mount:ident, $network:ident, $pid:ident, $user:ident) => {
        Ok(PidfdNamespaceAccessProbe { process: $process, mount: $mount, network: $network, pid: $pid, user: $user })
    };
    (Retained, $original:ident, $process:ident, $mount:ident, $network:ident, $pid:ident, $user:ident) => {{
        // All fallible checks precede these exclusive moves of the same pins.
        let (Some(process), Some(mount), Some(network), Some(pid), Some(user)) = (
            $original.process.take(), $original.mount.take(), $original.network.take(),
            $original.pid.take(), $original.user.take(),
        ) else { std::process::abort() };
        Ok(PidfdNamespaceAccessProbe { process, mount, network, pid, user })
    }};
}

macro_rules! probe_recipe {
    ($mode:ident, $original:ident) => {{
        let raw_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| HostError::Worker("host pid does not fit in u32".to_owned()))?;
        let pid = NonZeroU32::new(raw_pid)
            .ok_or_else(|| HostError::Worker("host pid is zero".to_owned()))?;
        let process = probe_open!($mode, $original, pid);
        let before = probe_native!($mode, $original, before, process.info());
        validate_service_probe_identity(raw_pid, before.pid(), before.thread_group_id())?;

        let mount = probe_namespace!($mode, $original, mount, 0, process, Mount);
        let network = probe_namespace!($mode, $original, network, 1, process, Network);
        let pid_namespace = probe_namespace!($mode, $original, pid, 2, process, Pid);
        let user = probe_namespace!($mode, $original, user, 3, process, User);

        let after = probe_native!($mode, $original, after, process.info());
        validate_service_probe_identity(raw_pid, after.pid(), after.thread_group_id())?;
        if before != after {
            return Err(HostError::Worker(
                "host pidfd identity changed during namespace probe".to_owned(),
            ));
        }
        if !probe_native!($mode, $original, alive, process.is_alive()) {
            return Err(HostError::Worker(
                "host process exited during namespace probe".to_owned(),
            ));
        }
        probe_finish!($mode, $original, process, mount, network, pid_namespace, user)
    }};
}

pub(super) fn capture_local() -> Result<PidfdNamespaceAccessProbe> {
    probe_recipe!(Local, unused)
}

pub(in crate::worker) struct ServiceNamespaceProbeOriginalV2 {
    entered: bool,
    opening: PidFdOpenAttemptV1,
    process: Option<PidFd>,
    before: Option<Native<PidFdInfo>>,
    namespaces: [PidFdNamespaceOriginalV2; 4],
    mount: Option<NamespaceFd>,
    network: Option<NamespaceFd>,
    pid: Option<NamespaceFd>,
    user: Option<NamespaceFd>,
    after: Option<Native<PidFdInfo>>,
    alive: Option<Native<bool>>,
    primary: Option<Result<PidfdNamespaceAccessProbe>>,
    refusal: Option<HostError>,
}

impl ServiceNamespaceProbeOriginalV2 {
    pub(in crate::worker) fn new() -> Self {
        Self {
            entered: false,
            opening: PidFdOpenAttemptV1::new(),
            process: None,
            before: None,
            namespaces: std::array::from_fn(|_| PidFdNamespaceOriginalV2::new()),
            mount: None,
            network: None,
            pid: None,
            user: None,
            after: None,
            alive: None,
            primary: None,
            refusal: None,
        }
    }

    pub(in crate::worker) fn capture_once(&mut self) -> Result<()> {
        if self.entered {
            self.refusal.get_or_insert_with(|| closed("host namespace probe cannot reenter"));
            return Err(closed("host namespace probe cannot reenter"));
        }
        self.entered = true;
        self.primary = Some((|| probe_recipe!(Retained, self))());
        if matches!(self.primary, Some(Ok(_))) { Ok(()) } else {
            Err(closed("host namespace probe failed; actual originals retained"))
        }
    }

    pub(in crate::worker) fn completed(&self) -> Option<&PidfdNamespaceAccessProbe> {
        self.primary.as_ref()?.as_ref().ok()
    }

    pub(in crate::worker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opening.failure().map(|cause| cause as _)
            .or_else(|| error(&self.before))
            .or_else(|| self.namespaces.iter().find_map(|original| original.failure().map(|cause| cause as _)))
            .or_else(|| error(&self.after))
            .or_else(|| error(&self.alive))
            .or_else(|| error(&self.primary))
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
    }

    pub(in crate::worker) fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let namespace = PidFdNamespaceOriginalV2::receiving_obligations_v2()?;
        Some((std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<PidFdOpenAttemptV1>())?
            .checked_add(namespace.0.checked_mul(4)?)?, 1_usize.checked_add(namespace.1.checked_mul(4)?)?, 0))
    }
}

fn error<T, E: std::error::Error + 'static>(slot: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed(message: &'static str) -> HostError { HostError::Fence(message) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_service_probe_keeps_actual_pins_through_refused_reentry() {
        let mut original = ServiceNamespaceProbeOriginalV2::new();
        original.capture_once().unwrap();
        let completed = original.completed().unwrap();
        let process = completed.process().info().unwrap();
        let user = completed.user().identity();
        let network = completed.network().identity();
        assert_eq!(process.pid(), std::process::id());

        assert!(original.capture_once().is_err());

        let first = original.failure().unwrap().downcast_ref::<HostError>().unwrap() as *const _;
        let held = original.completed().unwrap();
        assert_eq!(held.process().info().unwrap(), process);
        assert_eq!(held.user().identity(), user);
        assert_eq!(held.network().identity(), network);
        assert!(held.process().is_alive().unwrap());
        assert!(original.capture_once().is_err());
        assert_eq!(original.failure().unwrap().downcast_ref::<HostError>().unwrap() as *const _, first);
    }
}
