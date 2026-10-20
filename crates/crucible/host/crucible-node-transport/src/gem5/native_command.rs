//! Precredits Root command construction independently of runtime and frame budgets.
//!
//! The operational policy buys requested storage only. It grants no native,
//! capture, restoration, or scheduling authority. Clones share a monotone ledger;
//! failures and completed helpers never renew the original construction bank.

use std::{
    ffi::{OsStr, OsString},
    mem::size_of,
    os::unix::ffi::OsStrExt,
    path::Path,
    process::Command,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::ProviderError;

/// Bounds one incarnation's Root launch/restart and retained audit commands.
#[derive(Clone, Copy, Debug)]
pub struct NativeCommandConstructionPolicy {
    /// Bounds cumulative requested construction bytes, including the ledger root.
    pub maximum_requested_bytes: usize,
    /// Bounds independently constructed commands; failed constructions consume a slot.
    pub maximum_commands: usize,
    /// Bounds the complete simultaneous requested geometry of one command.
    pub maximum_command_requested_bytes: usize,
}

impl Default for NativeCommandConstructionPolicy {
    fn default() -> Self {
        // Operational choices, not measurements or execution permissions. The
        // producer measures every actual path/argument/environment first. 65
        // permits one launcher/restarter plus the existing 64 audit-worker slots.
        Self {
            maximum_requested_bytes: 64 * 1024 * 1024,
            maximum_commands: 65,
            maximum_command_requested_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Retains an incarnation's independent, nonrenewable construction reservation.
#[derive(Clone, Debug)]
pub struct NativeCommandConstructionBudget {
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    creator: u32,
    policy: NativeCommandConstructionPolicy,
    requested: usize,
    commands: usize,
}

impl NativeCommandConstructionPolicy {
    /// Reserves a fixed ledger before any native command is constructed.
    ///
    /// The caller retains a clone in its original custody slot before launch.
    /// Fresh restoration requires a separate caller-owned reservation; archives
    /// carry no ledger and cannot manufacture one while importing image bytes.
    ///
    /// # Errors
    /// Refuses a ceiling below the actual fixed ledger, or a zero command limit.
    pub fn reserve(self) -> Result<NativeCommandConstructionBudget, ProviderError> {
        let root = NativeCommandConstructionBudget::root_requested_bytes_data();
        if self.maximum_requested_bytes < root || self.maximum_commands == 0 {
            return Err(exhausted());
        }
        Ok(NativeCommandConstructionBudget {
            state: Arc::new(Mutex::new(State {
                creator: std::process::id(),
                policy: self,
                requested: root,
                commands: 0,
            })),
        })
    }
}

impl NativeCommandConstructionBudget {
    /// Returns the fixed ledger allocation and independent inline handle charge.
    pub fn root_requested_bytes_data() -> usize {
        size_of::<Self>()
            + size_of::<Mutex<State>>()
            + 2 * size_of::<usize>()
            + counter_scratch_bytes_data()
    }

    /// Tests whether two operational loans share the same original ledger.
    pub fn same_reservation_data(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    /// Reports whether original construction credit has been spent.
    ///
    /// Poisoned bookkeeping retains credit conservatively instead of renewing it.
    pub fn has_original_construction_debits_data(&self) -> bool {
        self.state.lock().map_or(true, |state| state.commands != 0)
    }

    fn charge(&self, requested: usize) -> Result<(), ProviderError> {
        let mut state = self.state.lock().map_err(|_| exhausted())?;
        if state.creator != std::process::id()
            || requested > state.policy.maximum_command_requested_bytes
        {
            return Err(exhausted());
        }
        let next = add(state.requested, requested)?;
        let commands = add(state.commands, 1)?;
        if next > state.policy.maximum_requested_bytes || commands > state.policy.maximum_commands {
            return Err(exhausted());
        }
        state.requested = next;
        state.commands = commands;
        Ok(())
    }
}

/// Borrows a closed command atom without allocating its eventual owned buffer.
#[derive(Clone, Copy)]
pub(crate) enum Atom<'a> {
    Borrowed(&'a OsStr),
    Joined(&'a Path, &'a str),
    PrefixedJoin(&'a str, &'a Path, &'a str),
    Mapping(&'a Path, &'a Path),
}

impl<'a> Atom<'a> {
    pub(crate) fn text(value: &'a str) -> Self {
        Self::Borrowed(OsStr::new(value))
    }

    pub(crate) fn path(value: &'a Path) -> Self {
        Self::Borrowed(value.as_os_str())
    }

    fn requested_len(self) -> Result<usize, ProviderError> {
        match self {
            Self::Borrowed(value) => Ok(value.as_bytes().len()),
            Self::Joined(root, leaf) => add(add(root.as_os_str().as_bytes().len(), 1)?, leaf.len()),
            Self::PrefixedJoin(prefix, root, leaf) => {
                add(prefix.len(), Self::Joined(root, leaf).requested_len()?)
            }
            Self::Mapping(source, target) => add(
                add(source.as_os_str().as_bytes().len(), 1)?,
                target.as_os_str().as_bytes().len(),
            ),
        }
    }

    fn owned(self) -> OsString {
        match self {
            Self::Borrowed(value) => value.to_owned(),
            Self::Joined(root, leaf) => root.join(leaf).into_os_string(),
            Self::PrefixedJoin(prefix, root, leaf) => {
                let mut value = OsString::from(prefix);
                value.push(root.join(leaf));
                value
            }
            Self::Mapping(source, target) => {
                let mut value = source.as_os_str().to_owned();
                value.push(":");
                value.push(target);
                value
            }
        }
    }
}

pub(crate) struct CommandSpec<'a> {
    pub(crate) executable: &'a Path,
    pub(crate) temporary_root: &'a Path,
    pub(crate) args: &'a [Atom<'a>],
    pub(crate) environment: &'a [(&'a str, Atom<'a>)],
}

impl<'a> CommandSpec<'a> {
    fn environment(&self) -> [(&'a str, Atom<'a>); 4] {
        [
            ("LC_ALL", Atom::text("C")),
            ("PYTHONHASHSEED", Atom::text("0")),
            ("TMPDIR", Atom::path(self.temporary_root)),
            ("DMTCP_TMPDIR", Atom::path(self.temporary_root)),
        ]
    }

    pub(crate) fn requested_bytes(&self) -> Result<usize, ProviderError> {
        if !self.executable.is_absolute() || !self.temporary_root.is_absolute() {
            return Err(ProviderError::Frame(
                "Root command requires absolute owned routes",
            ));
        }
        // The restart-env ABI and controller buffer are exactly 4096 bytes,
        // including NUL. No later callback may depend on a truncated route.
        if self.temporary_root.as_os_str().as_bytes().len() >= 4096 {
            return Err(ProviderError::Frame(
                "Root operational route exceeds restart ABI",
            ));
        }
        for (key, _) in self.environment {
            if *key == "TMPDIR" || *key == "DMTCP_TMPDIR" {
                return Err(ProviderError::Frame(
                    "Root temporary custody cannot be overridden",
                ));
            }
        }
        let mut bytes = add(self.executable.as_os_str().as_bytes().len(), 1)?;
        bytes = add(
            bytes,
            add(self.temporary_root.as_os_str().as_bytes().len(), 1)?,
        )?;
        for atom in self.args {
            bytes = add(bytes, add(atom.requested_len()?, 1)?)?;
        }
        let common = self.environment();
        for (key, value) in common.iter().chain(self.environment.iter()) {
            if key.is_empty() {
                return Err(ProviderError::Frame("Root command environment key"));
            }
            for byte in key.as_bytes() {
                if *byte == b'=' || *byte == 0 {
                    return Err(ProviderError::Frame("Root command environment key"));
                }
            }
            bytes = add(bytes, add(add(key.len(), value.requested_len()?)?, 2)?)?;
        }
        let env_count = add(common.len(), self.environment.len())?;
        let args_count = add(self.args.len(), 1)?;
        // Command::env owns its map. Spawn's capture_env clones that map, then
        // constructs independent key=value CStrings and an envp pointer vector.
        // No ambient environment is captured after env_clear. One full node per
        // entry overbounds both leaf and internal BTree layouts, including spare.
        let node = crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data::<OsString, Option<OsString>>()?;
        let trees = mul(mul(env_count, node)?, 2)?;
        // Each atom may grow an OsString/PathBuf before Command copies it into
        // its CString. The 16 banks cover grow/copy overlap, both environment
        // maps, key=value conversion, cwd and executable copies. Byte charges
        // include terminators; min-8 growth is charged per independent item.
        let banks = mul(add(bytes, mul(add(args_count, env_count)?, 8)?)?, 16)?;
        // CStringArray argv/envp capacity growth, null terminators, and each
        // independent owned-string header remain separate from their payloads.
        let slots = mul(
            add(add(args_count, env_count)?, 8)?,
            8 * (size_of::<OsString>() + size_of::<usize>()),
        )?;
        add(
            add(add(banks, trees)?, slots)?,
            counter_scratch_bytes_data(),
        )
    }

    pub(crate) fn construct(
        &self,
        budget: &NativeCommandConstructionBudget,
    ) -> Result<Command, ProviderError> {
        let requested = self.requested_bytes()?;
        budget.charge(requested)?;
        // The debit is permanent even if a later atom, OS conversion, spawn or
        // native handshake fails. No Command or owned argument exists before it.
        let mut command = Command::new(self.executable);
        command.env_clear();
        for (key, value) in self.environment().iter().chain(self.environment.iter()) {
            command.env(key, value.owned());
        }
        for atom in self.args {
            command.arg(atom.owned());
        }
        command.current_dir(self.temporary_root);
        Ok(command)
    }
}

pub(crate) fn counter_scratch_bytes_data() -> usize {
    size_of::<NativeCommandConstructionPolicy>()
        + size_of::<NativeCommandConstructionBudget>()
        + size_of::<Result<NativeCommandConstructionBudget, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<(&str, Atom<'static>)>()
        + size_of::<&Atom<'static>>()
        + size_of::<&(&str, Atom<'static>)>()
        + size_of::<Command>()
        + size_of::<Result<Command, ProviderError>>()
        + size_of::<CommandSpec<'static>>()
        + size_of::<Atom<'static>>()
        + size_of::<[(&str, Atom<'static>); 4]>()
        + size_of::<[Atom<'static>; 18]>()
        + size_of::<[Atom<'static>; 10]>()
        + size_of::<[Atom<'static>; 2]>()
        + size_of::<[(&str, Atom<'static>); 3]>()
        + size_of::<[(&str, Atom<'static>); 2]>()
        + size_of::<std::slice::Iter<'static, (&str, Atom<'static>)>>()
        + size_of::<(&&str, &Atom<'static>)>()
        + size_of::<&u8>()
        + size_of::<&CommandSpec<'static>>()
        + size_of::<&NativeCommandConstructionBudget>()
        + size_of::<Option<&NativeCommandConstructionBudget>>()
        + size_of::<Result<&NativeCommandConstructionBudget, ProviderError>>()
        + size_of::<&[(&str, Atom<'static>)]>()
        + size_of::<[(&str, Atom<'static>); 7]>()
        + size_of::<std::slice::Iter<'static, u8>>()
        + size_of::<Result<OsString, ProviderError>>()
        + size_of::<&Path>()
        + size_of::<&OsStr>()
        + size_of::<&[Atom<'static>]>()
        + size_of::<std::slice::Iter<'static, Atom<'static>>>()
        + size_of::<
            std::iter::Chain<
                std::slice::Iter<'static, (&str, Atom<'static>)>,
                std::slice::Iter<'static, (&str, Atom<'static>)>,
            >,
        >()
        + size_of::<MutexGuard<'static, State>>()
        + size_of::<std::sync::LockResult<MutexGuard<'static, State>>>()
        + size_of::<Result<MutexGuard<'static, State>, ProviderError>>()
        + size_of::<std::path::Components<'static>>()
        + size_of::<std::path::Component<'static>>()
        + size_of::<Option<std::path::Component<'static>>>()
        + size_of::<&[u8]>()
        + size_of::<bool>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<std::process::CommandEnvs<'static>>()
        + size_of::<std::process::CommandArgs<'static>>()
        + size_of::<OsString>()
        + size_of::<std::path::PathBuf>()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
        + crate::retained_metadata::serialization_storage::original_serialization_tree_node_counter_scratch_data()
}

fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(exhausted)
}

fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("Root native command construction reservation")
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- These controls inspect actual owned
    // Commands without spawning a Child and assert exact requested boundaries.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn actual_command_aliases_and_exact_credit_precede_allocation() {
        let args = [
            Atom::text("--tmpdir"),
            Atom::path(Path::new("/owned/tmp")),
            Atom::PrefixedJoin("--outdir=", Path::new("/owned/native"), "output"),
        ];
        let environment = [(
            "CRUCIBLE_GEM5_OPERATIONAL_ROOT",
            Atom::path(Path::new("/owned/tmp")),
        )];
        let spec = CommandSpec {
            executable: Path::new("/owned/python"),
            temporary_root: Path::new("/owned/tmp"),
            args: &args,
            environment: &environment,
        };
        let demand = spec.requested_bytes().unwrap();
        let root = NativeCommandConstructionBudget::root_requested_bytes_data();
        let policy = NativeCommandConstructionPolicy {
            maximum_requested_bytes: root + demand,
            maximum_commands: 1,
            maximum_command_requested_bytes: demand,
        };
        let budget = policy.reserve().unwrap();
        let command = spec.construct(&budget).unwrap();
        assert!(budget.same_reservation_data(&budget.clone()));

        assert_eq!(command.get_current_dir(), Some(Path::new("/owned/tmp")));
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == "TMPDIR" && value == Some(OsStr::new("/owned/tmp")))
        );
        assert!(
            command.get_envs().any(
                |(key, value)| key == "DMTCP_TMPDIR" && value == Some(OsStr::new("/owned/tmp"))
            )
        );
        assert_eq!(
            command.get_args().last(),
            Some(OsStr::new("--outdir=/owned/native/output"))
        );
        assert!(spec.construct(&budget.clone()).is_err());
        assert_eq!(budget.state.lock().unwrap().commands, 1);

        let short = NativeCommandConstructionPolicy {
            maximum_requested_bytes: root + demand - 1,
            ..policy
        }
        .reserve()
        .unwrap();
        assert!(spec.construct(&short).is_err());
        assert_eq!(short.state.lock().unwrap().commands, 0);
        let short = NativeCommandConstructionPolicy {
            maximum_command_requested_bytes: demand - 1,
            ..policy
        }
        .reserve()
        .unwrap();
        assert!(spec.construct(&short).is_err());
    }

    #[test]
    fn abandoned_commands_do_not_renew_and_overflow_refuses() {
        let args = [Atom::text("-B")];
        let spec = CommandSpec {
            executable: Path::new("/owned/python"),
            temporary_root: Path::new("/owned/tmp"),
            args: &args,
            environment: &[],
        };
        let budget = NativeCommandConstructionPolicy {
            maximum_commands: 1,
            ..Default::default()
        }
        .reserve()
        .unwrap();
        drop(spec.construct(&budget).unwrap());
        assert!(budget.has_original_construction_debits_data());
        assert!(spec.construct(&budget).is_err());
        assert!(add(usize::MAX, 1).is_err());
        assert!(mul(usize::MAX, 2).is_err());
        assert!(
            NativeCommandConstructionPolicy {
                maximum_requested_bytes: NativeCommandConstructionBudget::root_requested_bytes_data(
                ) - 1,
                ..Default::default()
            }
            .reserve()
            .is_err()
        );
    }

    #[test]
    fn borrowed_spec_cannot_override_owned_temporary_custody() {
        let budget = NativeCommandConstructionPolicy::default()
            .reserve()
            .unwrap();
        let environment = [("TMPDIR", Atom::text("/foreign/tmp"))];
        let spec = CommandSpec {
            executable: Path::new("/owned/python"),
            temporary_root: Path::new("/owned/tmp"),
            args: &[],
            environment: &environment,
        };

        assert!(spec.construct(&budget).is_err());
        assert!(!budget.has_original_construction_debits_data());
        assert_eq!(budget.state.lock().unwrap().commands, 0);
    }
}
