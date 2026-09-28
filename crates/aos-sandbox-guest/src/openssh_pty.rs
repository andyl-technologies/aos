//! Native mode preparation and readback for the originally retained Guest PTY.
//!
//! This module accepts a borrowed descriptor only from the existing execution
//! owner. It neither selects a device pathname nor accepts a new descriptor.
//! Preparing settings is nonmutating; applying them belongs inside the shared
//! original-execution barrier after durable sequence reservation and current
//! Controller/Host rechecks. Unknown RFC modes are ignored, not authorization.

use std::os::fd::BorrowedFd;

use aos_sandbox_agent::openssh_control::{OpenSshPtyGeometryV5, decode_terminal_modes_v5};
use rustix::termios::{
    ControlModes, InputModes, LocalModes, OptionalActions, OutputModes, SpecialCodeIndex, Termios,
    Winsize, tcgetattr, tcgetwinsize, tcsetattr, tcsetwinsize,
};

use crate::GuestProcessEffectErrorV1 as Error;

pub(super) struct PreparedOriginalPtyModes {
    terminal: Termios,
    geometry: Winsize,
}

impl PreparedOriginalPtyModes {
    /// Prepares exact native settings without changing the retained PTY.
    ///
    /// # Errors
    /// Rejects malformed modes, unsupported native values or failed PTY reads.
    pub(super) fn prepare(
        master: BorrowedFd<'_>,
        geometry: OpenSshPtyGeometryV5,
        modes: &[u8],
    ) -> Result<Self, Error> {
        let mut terminal = tcgetattr(master)?;
        for (code, value) in decode_terminal_modes_v5(modes).map_err(|_| Error::InvalidRequest)? {
            if let Some(index) = character_index(code) {
                // SSH's 255 sentinel means disabled; Linux's VDISABLE is zero.
                // Other values must fit the original native control character.
                let character = u8::try_from(value).map_err(|_| Error::InvalidRequest)?;
                terminal.special_codes[index] = if character == 255 { 0 } else { character };
                continue;
            }
            match code {
                30 => terminal.input_modes.set(InputModes::IGNPAR, value != 0),
                31 => terminal.input_modes.set(InputModes::PARMRK, value != 0),
                32 => terminal.input_modes.set(InputModes::INPCK, value != 0),
                33 => terminal.input_modes.set(InputModes::ISTRIP, value != 0),
                34 => terminal.input_modes.set(InputModes::INLCR, value != 0),
                35 => terminal.input_modes.set(InputModes::IGNCR, value != 0),
                36 => terminal.input_modes.set(InputModes::ICRNL, value != 0),
                37 => terminal.input_modes.set(InputModes::IUCLC, value != 0),
                38 => terminal.input_modes.set(InputModes::IXON, value != 0),
                39 => terminal.input_modes.set(InputModes::IXANY, value != 0),
                40 => terminal.input_modes.set(InputModes::IXOFF, value != 0),
                41 => terminal.input_modes.set(InputModes::IMAXBEL, value != 0),
                42 => terminal.input_modes.set(InputModes::IUTF8, value != 0),
                50 => terminal.local_modes.set(LocalModes::ISIG, value != 0),
                51 => terminal.local_modes.set(LocalModes::ICANON, value != 0),
                52 => terminal.local_modes.set(LocalModes::XCASE, value != 0),
                53 => terminal.local_modes.set(LocalModes::ECHO, value != 0),
                54 => terminal.local_modes.set(LocalModes::ECHOE, value != 0),
                55 => terminal.local_modes.set(LocalModes::ECHOK, value != 0),
                56 => terminal.local_modes.set(LocalModes::ECHONL, value != 0),
                57 => terminal.local_modes.set(LocalModes::NOFLSH, value != 0),
                58 => terminal.local_modes.set(LocalModes::TOSTOP, value != 0),
                59 => terminal.local_modes.set(LocalModes::IEXTEN, value != 0),
                60 => terminal.local_modes.set(LocalModes::ECHOCTL, value != 0),
                61 => terminal.local_modes.set(LocalModes::ECHOKE, value != 0),
                62 => terminal.local_modes.set(LocalModes::PENDIN, value != 0),
                70 => terminal.output_modes.set(OutputModes::OPOST, value != 0),
                71 => terminal.output_modes.set(OutputModes::OLCUC, value != 0),
                72 => terminal.output_modes.set(OutputModes::ONLCR, value != 0),
                73 => terminal.output_modes.set(OutputModes::OCRNL, value != 0),
                74 => terminal.output_modes.set(OutputModes::ONOCR, value != 0),
                75 => terminal.output_modes.set(OutputModes::ONLRET, value != 0),
                // Preserve the pinned OpenSSH TTYMODE bit-mask interpretation,
                // including an explicit zero value and ordered repeated modes.
                90 => terminal.control_modes.set(ControlModes::CS7, value != 0),
                91 => terminal.control_modes.set(ControlModes::CS8, value != 0),
                92 => terminal.control_modes.set(ControlModes::PARENB, value != 0),
                93 => terminal.control_modes.set(ControlModes::PARODD, value != 0),
                128 => terminal.set_input_speed(value)?,
                129 => terminal.set_output_speed(value)?,
                _ => {} // RFC 4254 permits ignoring unknown platform modes.
            }
        }
        let mut native_geometry = tcgetwinsize(master)?;
        // A zero initial dimension is the SSH client's unspecified value, not
        // permission to manufacture a PTY or alter original execution topology.
        if geometry.rows != 0 {
            native_geometry.ws_row = geometry.rows;
        }
        if geometry.columns != 0 {
            native_geometry.ws_col = geometry.columns;
        }
        native_geometry.ws_xpixel = geometry.xpixel;
        native_geometry.ws_ypixel = geometry.ypixel;
        Ok(Self {
            terminal,
            geometry: native_geometry,
        })
    }

    /// Applies and reads back prepared settings inside the existing held cut.
    ///
    /// The callback belongs to the actual original-execution owner. Each
    /// separate syscall is preceded/followed by its currentness/deadline check;
    /// partial mode/geometry application is ambiguous, never redispatched.
    ///
    /// # Errors
    /// Rejects owner currentness failure, syscall failure or changed readback.
    pub(super) fn apply(
        &self,
        master: BorrowedFd<'_>,
        mut recheck: impl FnMut() -> Result<(), Error>,
    ) -> Result<(), Error> {
        recheck()?;
        // An attempted kernel mutation cannot be replayed after any later
        // syscall, deadline, currentness or readback failure.
        let attempted = (|| {
            tcsetattr(master, OptionalActions::Now, &self.terminal)?;
            recheck()?;
            tcsetwinsize(master, self.geometry)?;
            recheck()?;
            let terminal = tcgetattr(master)?;
            let geometry = tcgetwinsize(master)?;
            if terminal.input_modes.bits() != self.terminal.input_modes.bits()
                || terminal.output_modes.bits() != self.terminal.output_modes.bits()
                || terminal.control_modes.bits() != self.terminal.control_modes.bits()
                || terminal.local_modes.bits() != self.terminal.local_modes.bits()
                || !same_character_codes(&terminal, &self.terminal)
                || terminal.input_speed() != self.terminal.input_speed()
                || terminal.output_speed() != self.terminal.output_speed()
                || geometry != self.geometry
            {
                return Err(Error::AmbiguousEffect);
            }
            recheck()
        })();
        attempted.map_err(|_| Error::AmbiguousEffect)
    }
}

fn same_character_codes(left: &Termios, right: &Termios) -> bool {
    (1..=18)
        .filter_map(character_index)
        .chain([SpecialCodeIndex::VMIN, SpecialCodeIndex::VTIME])
        .all(|index| left.special_codes[index] == right.special_codes[index])
}

fn character_index(code: u8) -> Option<SpecialCodeIndex> {
    Some(match code {
        1 => SpecialCodeIndex::VINTR,
        2 => SpecialCodeIndex::VQUIT,
        3 => SpecialCodeIndex::VERASE,
        4 => SpecialCodeIndex::VKILL,
        5 => SpecialCodeIndex::VEOF,
        6 => SpecialCodeIndex::VEOL,
        7 => SpecialCodeIndex::VEOL2,
        8 => SpecialCodeIndex::VSTART,
        9 => SpecialCodeIndex::VSTOP,
        10 => SpecialCodeIndex::VSUSP,
        12 => SpecialCodeIndex::VREPRINT,
        13 => SpecialCodeIndex::VWERASE,
        14 => SpecialCodeIndex::VLNEXT,
        16 => SpecialCodeIndex::VSWTC,
        18 => SpecialCodeIndex::VDISCARD,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    //! Actual native PTY settings, not authenticated original execution custody.

    use std::os::fd::AsFd as _;

    use rustix::pty::{OpenptFlags, grantpt, openpt, unlockpt};

    use super::*;

    #[test]
    fn real_pty_settings_are_prepared_then_applied_with_full_pixel_readback() {
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let before = tcgetattr(&master).unwrap();
        let geometry = OpenSshPtyGeometryV5 {
            rows: 24,
            columns: 80,
            xpixel: 640,
            ypixel: 480,
        };
        let prepared = PreparedOriginalPtyModes::prepare(
            master.as_fd(),
            geometry,
            &[1, 0, 0, 0, 3, 53, 0, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(
            tcgetattr(&master).unwrap().local_modes.bits(),
            before.local_modes.bits()
        );

        let mut rechecks = 0;
        prepared
            .apply(master.as_fd(), || {
                rechecks += 1;
                Ok(())
            })
            .unwrap();

        let after = tcgetattr(&master).unwrap();
        let after_geometry = tcgetwinsize(&master).unwrap();
        assert!(!after.local_modes.contains(LocalModes::ECHO));
        assert_eq!(after.special_codes[SpecialCodeIndex::VINTR], 3);
        assert_eq!(after_geometry.ws_row, 24);
        assert_eq!(after_geometry.ws_col, 80);
        assert_eq!(after_geometry.ws_xpixel, 640);
        assert_eq!(after_geometry.ws_ypixel, 480);
        assert_eq!(rechecks, 4);
    }

    #[test]
    fn unsafe_native_character_and_failed_owner_recheck_cannot_apply() {
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let geometry = OpenSshPtyGeometryV5 {
            rows: 0,
            columns: 0,
            xpixel: 0,
            ypixel: 0,
        };
        assert!(
            PreparedOriginalPtyModes::prepare(master.as_fd(), geometry, &[1, 0, 0, 1, 0, 0])
                .is_err()
        );
        let before = tcgetattr(&master).unwrap();
        let prepared =
            PreparedOriginalPtyModes::prepare(master.as_fd(), geometry, &[53, 0, 0, 0, 0, 0])
                .unwrap();

        assert!(
            prepared
                .apply(master.as_fd(), || Err(Error::InvalidRequest))
                .is_err()
        );
        assert_eq!(
            tcgetattr(&master).unwrap().local_modes.bits(),
            before.local_modes.bits()
        );
    }

    #[test]
    fn lost_cut_after_mode_mutation_is_ambiguous_without_geometry_replay() {
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let before_geometry = tcgetwinsize(&master).unwrap();
        let mut original = tcgetattr(&master).unwrap();
        original.local_modes.insert(LocalModes::ECHO);
        tcsetattr(&master, OptionalActions::Now, &original).unwrap();
        let prepared = PreparedOriginalPtyModes::prepare(
            master.as_fd(),
            OpenSshPtyGeometryV5 {
                rows: 33,
                columns: 99,
                xpixel: 640,
                ypixel: 480,
            },
            &[53, 0, 0, 0, 0, 0],
        )
        .unwrap();

        let mut checks = 0;
        let result = prepared.apply(master.as_fd(), || {
            checks += 1;
            if checks == 1 {
                Ok(())
            } else {
                Err(Error::InvalidRequest)
            }
        });

        assert!(matches!(result, Err(Error::AmbiguousEffect)));
        assert_eq!(checks, 2);
        assert!(
            !tcgetattr(&master)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO)
        );
        assert_eq!(tcgetwinsize(&master).unwrap(), before_geometry);
    }
}
