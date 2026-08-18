//! Runs the bounded console application in the dedicated recovery initrd.

use std::error::Error;
use std::fs;
use std::io::{self, BufRead, Write};
use std::process::{Command, ExitCode};

use aos_boot_identity::{BootSlot, parse_recovery};
use aos_recovery::maintenance::MaintenanceSession;
use aos_recovery::restore::verify_offline_bundle;
use aos_recovery::status::{FirmwarePosture, RecoveryCopy, RecoveryStatus, SlotPosture};
use aos_recovery::{Operation, RecoverySession, parse_selection};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-recovery: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    parse_recovery(&cmdline)?;

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let mut stdout = io::stdout().lock();
    let mut session = RecoverySession::new();
    let mut maintenance = MaintenanceSession::new();

    writeln!(stdout, "AOS signed recovery environment")?;
    writeln!(
        stdout,
        "Persistent state is locked. Networking is disabled."
    )?;

    loop {
        writeln!(stdout)?;
        writeln!(stdout, "1) Show bounded status")?;
        writeln!(stdout, "2) Verify immutable slot A")?;
        writeln!(stdout, "3) Verify immutable slot B")?;
        writeln!(stdout, "4) Boot verified slot A once")?;
        writeln!(stdout, "5) Boot verified slot B once")?;
        writeln!(
            stdout,
            "6) Restore inactive slot from authenticated removable media"
        )?;
        writeln!(stdout, "7) Unlock persistent state with recovery key")?;
        writeln!(stdout, "8) Start authenticated maintenance shell")?;
        writeln!(stdout, "9) Lock persistent state")?;
        writeln!(stdout, "p) Power off")?;
        write!(stdout, "> ")?;
        stdout.flush()?;

        let Some(selection) = lines.next() else {
            return Err("recovery console input closed".into());
        };
        let selection = selection?;
        match parse_selection(&selection) {
            Ok(Operation::Status) => show_status(&session, &maintenance, &mut stdout)?,
            Ok(Operation::VerifyA) => verify(&mut session, BootSlot::A, &mut stdout)?,
            Ok(Operation::VerifyB) => verify(&mut session, BootSlot::B, &mut stdout)?,
            Ok(Operation::BootA) => boot(&session, &mut maintenance, BootSlot::A, &mut stdout)?,
            Ok(Operation::BootB) => boot(&session, &mut maintenance, BootSlot::B, &mut stdout)?,
            Ok(Operation::RestoreInactive) => {
                restore_inactive(&session, &mut maintenance, &mut lines, &mut stdout)?
            }
            Ok(Operation::UnlockState) => authenticate(&mut maintenance, &mut stdout)?,
            Ok(Operation::MaintenanceShell) => maintenance_shell(&mut maintenance, &mut stdout)?,
            Ok(Operation::LockState) => lock_state(&mut maintenance, &mut stdout)?,
            Ok(Operation::PowerOff) => power_off(&mut maintenance)?,
            Err(error) => writeln!(stdout, "Unavailable: {error}")?,
        }
    }
}

fn restore_inactive<I>(
    session: &RecoverySession,
    maintenance: &mut MaintenanceSession,
    lines: &mut I,
    output: &mut impl Write,
) -> io::Result<()>
where
    I: Iterator<Item = io::Result<String>>,
{
    let status = match RecoveryStatus::collect(session) {
        Ok(status) => status,
        Err(error) => {
            writeln!(output, "restore refused: {error}")?;
            return Ok(());
        }
    };
    writeln!(output, "verifying fixed AOS-RECOVERY removable media...")?;
    output.flush()?;
    let bundle = match verify_offline_bundle(status.copy) {
        Ok(bundle) => bundle,
        Err(error) => {
            writeln!(output, "restore refused: {error}")?;
            return Ok(());
        }
    };
    let target = match bundle.target {
        BootSlot::A => "A",
        BootSlot::B => "B",
    };
    writeln!(
        output,
        "authenticated bundle release={} will replace immutable slot {target}",
        bundle.release
    )?;
    writeln!(output, "the opposite recovery copy remains untouched")?;
    write!(output, "type RESTORE SLOT {target} to continue: ")?;
    output.flush()?;
    let Some(confirmation) = lines.next() else {
        writeln!(output, "restore cancelled: console input closed")?;
        return Ok(());
    };
    if confirmation? != format!("RESTORE SLOT {target}") {
        writeln!(output, "restore cancelled")?;
        return Ok(());
    }
    let authorization = match maintenance.authorize_restore() {
        Ok(authorization) => authorization,
        Err(error) => {
            writeln!(output, "restore authorization failed: {error}")?;
            return Ok(());
        }
    };
    writeln!(output, "restoring and read-back-verifying slot {target}...")?;
    output.flush()?;
    match bundle.restore(authorization) {
        Ok(()) => writeln!(
            output,
            "slot {target} restored; reboot into its paired recovery entry before verification"
        ),
        Err(error) => writeln!(output, "restore failed closed: {error}"),
    }
}

fn verify(
    session: &mut RecoverySession,
    slot: BootSlot,
    output: &mut impl Write,
) -> io::Result<()> {
    match session.verify(slot) {
        Ok(verified) => writeln!(
            output,
            "slot {slot:?}: verified release={} entry={} counted={}",
            verified.release, verified.entry_id, verified.counted
        ),
        Err(error) => writeln!(output, "slot {slot:?}: rejected: {error}"),
    }
}

fn boot(
    session: &RecoverySession,
    maintenance: &mut MaintenanceSession,
    slot: BootSlot,
    output: &mut impl Write,
) -> io::Result<()> {
    let verified = match session.verified(slot) {
        Ok(verified) => verified,
        Err(error) => {
            writeln!(output, "slot {slot:?}: boot denied: {error}")?;
            return Ok(());
        }
    };
    if let Err(error) = maintenance.lock() {
        writeln!(
            output,
            "slot {slot:?}: boot denied because persistent state could not be locked: {error}"
        )?;
        return Ok(());
    }
    writeln!(output, "booting verified slot {slot:?} once")?;
    output.flush()?;
    if let Err(error) = verified.boot_once() {
        writeln!(output, "slot {slot:?}: one-shot boot failed: {error}")?;
    }
    Ok(())
}

fn show_status(
    session: &RecoverySession,
    maintenance: &MaintenanceSession,
    output: &mut impl Write,
) -> io::Result<()> {
    let status = match RecoveryStatus::collect(session) {
        Ok(status) => status,
        Err(error) => {
            writeln!(output, "status unavailable: {error}")?;
            return Ok(());
        }
    };
    writeln!(output, "mode: signed recovery initrd")?;
    writeln!(
        output,
        "recovery-copy: {}",
        match status.copy {
            RecoveryCopy::A => "A",
            RecoveryCopy::B => "B",
        }
    )?;
    writeln!(
        output,
        "firmware: {}",
        match status.firmware {
            FirmwarePosture::Enforcing => "secure-boot-enforcing",
            FirmwarePosture::NotEnforcing => "not-enforcing",
            FirmwarePosture::Unavailable => "unavailable",
        }
    )?;
    show_slot_status(output, "A", &status.slot_a)?;
    show_slot_status(output, "B", &status.slot_b)?;
    writeln!(
        output,
        "persistent-state: {}",
        if maintenance.is_authenticated() {
            "authenticated"
        } else if maintenance.mapper_is_open() {
            "cleanup-required-mapper-open"
        } else {
            "locked"
        }
    )?;
    writeln!(output, "network: disabled")?;
    writeln!(output, "normal-root: not mounted")
}

fn show_slot_status(output: &mut impl Write, name: &str, slot: &SlotPosture) -> io::Result<()> {
    match slot {
        SlotPosture::Unverified => writeln!(output, "slot-{name}: unverified"),
        SlotPosture::Verified { release, counted } => writeln!(
            output,
            "slot-{name}: verified release={release} counted={counted}"
        ),
    }
}

fn authenticate(maintenance: &mut MaintenanceSession, output: &mut impl Write) -> io::Result<()> {
    match maintenance.authenticate() {
        Ok(()) => writeln!(output, "persistent state authenticated and mounted at /var"),
        Err(error) => writeln!(output, "persistent state remains locked: {error}"),
    }
}

fn maintenance_shell(
    maintenance: &mut MaintenanceSession,
    output: &mut impl Write,
) -> io::Result<()> {
    output.flush()?;
    match maintenance.run_shell() {
        Ok(()) => writeln!(
            output,
            "maintenance session ended; persistent state is locked"
        ),
        Err(error) => writeln!(output, "maintenance session refused or incomplete: {error}"),
    }
}

fn lock_state(maintenance: &mut MaintenanceSession, output: &mut impl Write) -> io::Result<()> {
    match maintenance.lock() {
        Ok(()) => writeln!(output, "persistent state is locked"),
        Err(error) => writeln!(
            output,
            "persistent state could not be fully locked: {error}"
        ),
    }
}

fn power_off(maintenance: &mut MaintenanceSession) -> Result<(), Box<dyn Error>> {
    maintenance.lock()?;
    let status = Command::new("/bin/systemctl").arg("poweroff").status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl poweroff exited with {status}").into())
    }
}
