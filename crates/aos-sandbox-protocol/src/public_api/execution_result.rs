//! Exact terminal-result projection and the closed portable control-signal vocabulary.
//!
//! These models preserve the established public protobuf representation. They
//! validate process-result metadata without granting execution control authority.

use super::grammar_error::InvalidCliGrammar;

/// Identifies portable execution signals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionSignalV1 {
    /// Hangup.
    Hangup,
    /// Interactive interrupt.
    Interrupt,
    /// Interactive quit.
    Quit,
    /// Graceful termination.
    Terminate,
    /// Immediate kill.
    Kill,
    /// User-defined signal one.
    User1,
    /// User-defined signal two.
    User2,
}

impl ExecutionSignalV1 {
    /// Returns the portable POSIX signal number used for shell status projection.
    #[must_use]
    pub const fn posix_number(self) -> u8 {
        match self {
            Self::Hangup => 1,
            Self::Interrupt => 2,
            Self::Quit => 3,
            Self::Kill => 9,
            Self::User1 => 10,
            Self::User2 => 12,
            Self::Terminate => 15,
        }
    }
}

/// Represents an exact terminal execution outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionTerminalOutcomeV1 {
    /// The process exited normally with its exact code.
    ExitCode(i32),
    /// The process terminated from one closed signal.
    Signal(ExecutionSignalV1),
    /// Authority or node loss prevented a process result.
    Lost,
    /// Preserves a genuine original Linux signal/cancellation result.
    OriginalLinux {
        /// Validated original leader waitstatus, including the exact core bit.
        status: aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4,
        /// Reports completed recursive execution-tree cancellation.
        canceled: bool,
    },
}

impl ExecutionTerminalOutcomeV1 {
    /// Converts the exact terminal classification into established public fields.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidArguments`] when the timestamp is
    /// noncanonical, the public reason is unsafe or oversized, or an
    /// `OriginalLinux` value aliases an ordinary noncanceled exit. Ordinary
    /// exits use `ExitCode`; this keeps terminal replay classification canonical.
    pub fn to_proto(
        self,
        exited_at: aos_proto::aos::sandbox::v1::Timestamp,
        safe_reason: String,
    ) -> Result<aos_proto::aos::sandbox::v1::ExecutionResult, InvalidCliGrammar> {
        if !(-62_135_596_800..=253_402_300_799).contains(&exited_at.seconds)
            || exited_at.nanoseconds >= 1_000_000_000
            || safe_reason.len() > 16 * 1024
            || safe_reason.chars().any(char::is_control)
        {
            return Err(InvalidCliGrammar::InvalidArguments);
        }
        let (exit_code, termination_kind, signal, terminal_signal_v2) = match self {
            Self::ExitCode(code) => (code, 1, 0, None),
            Self::Signal(signal) => (0, 2, execution_signal_proto(signal), None),
            Self::Lost => (0, 3, 0, None),
            Self::OriginalLinux { status, canceled } => {
                let number = status.signal();
                if !canceled && number.is_none() {
                    return Err(InvalidCliGrammar::InvalidArguments);
                }
                let exact =
                    number.map(
                        |number| aos_proto::aos::sandbox::v1::ExecutionTerminalSignalV2 {
                            linux_signal_number: u32::from(number),
                            core_dumped: status.core_dumped(),
                            ..Default::default()
                        },
                    );
                (
                    status.exit_code().map(i32::from).unwrap_or(0),
                    if canceled {
                        4
                    } else if number.is_some() {
                        2
                    } else {
                        1
                    },
                    number
                        .and_then(execution_signal_from_linux)
                        .map(execution_signal_proto)
                        .unwrap_or(0),
                    exact,
                )
            }
        };
        Ok(aos_proto::aos::sandbox::v1::ExecutionResult {
            exit_code,
            termination_reason: safe_reason,
            exited_at: exited_at.into(),
            termination_kind: termination_kind.into(),
            signal: signal.into(),
            terminal_signal_v2: terminal_signal_v2.into(),
            ..Default::default()
        })
    }

    /// Decodes the exact public terminal classification without inferring from text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCliGrammar::InvalidArguments`] for an unspecified or
    /// inconsistent termination kind, signal, or exit-code combination.
    pub fn try_from_proto(
        value: &aos_proto::aos::sandbox::v1::ExecutionResult,
    ) -> Result<Self, InvalidCliGrammar> {
        let timestamp = value
            .exited_at
            .as_option()
            .ok_or(InvalidCliGrammar::InvalidArguments)?;
        if !(-62_135_596_800..=253_402_300_799).contains(&timestamp.seconds)
            || timestamp.nanoseconds >= 1_000_000_000
            || value.termination_reason.len() > 16 * 1024
            || value.termination_reason.chars().any(char::is_control)
        {
            return Err(InvalidCliGrammar::InvalidArguments);
        }
        if let Some(terminal) = value.terminal_signal_v2.as_option() {
            let number = u8::try_from(terminal.linux_signal_number)
                .map_err(|_| InvalidCliGrammar::InvalidArguments)?;
            let status = aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4::new(
                u32::from(number) | if terminal.core_dumped { 0x80 } else { 0 },
            )
            .map_err(|_| InvalidCliGrammar::InvalidArguments)?;
            let legacy = execution_signal_from_linux(number)
                .map(execution_signal_proto)
                .unwrap_or(0);
            if status.signal().is_none()
                || value.exit_code != 0
                || value.signal.to_i32() != legacy
                || !matches!(value.termination_kind.to_i32(), 2 | 4)
            {
                return Err(InvalidCliGrammar::InvalidArguments);
            }
            return Ok(Self::OriginalLinux {
                status,
                canceled: value.termination_kind.to_i32() == 4,
            });
        }
        if value.termination_kind.to_i32() == 4 {
            if value.signal.to_i32() != 0 || !(0..=255).contains(&value.exit_code) {
                return Err(InvalidCliGrammar::InvalidArguments);
            }
            let status = aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4::new(
                (value.exit_code as u32) << 8,
            )
            .map_err(|_| InvalidCliGrammar::InvalidArguments)?;
            return Ok(Self::OriginalLinux {
                status,
                canceled: true,
            });
        }
        match (
            value.termination_kind.to_i32(),
            value.signal.to_i32(),
            value.exit_code,
        ) {
            (1, 0, code) => Ok(Self::ExitCode(code)),
            (2, signal, 0) => execution_signal_from_proto(signal)
                .map(Self::Signal)
                .ok_or(InvalidCliGrammar::InvalidArguments),
            (3, 0, 0) => Ok(Self::Lost),
            _ => Err(InvalidCliGrammar::InvalidArguments),
        }
    }
}

const fn execution_signal_from_linux(number: u8) -> Option<ExecutionSignalV1> {
    match number {
        1 => Some(ExecutionSignalV1::Hangup),
        2 => Some(ExecutionSignalV1::Interrupt),
        3 => Some(ExecutionSignalV1::Quit),
        9 => Some(ExecutionSignalV1::Kill),
        10 => Some(ExecutionSignalV1::User1),
        12 => Some(ExecutionSignalV1::User2),
        15 => Some(ExecutionSignalV1::Terminate),
        _ => None,
    }
}

const fn execution_signal_proto(value: ExecutionSignalV1) -> i32 {
    match value {
        ExecutionSignalV1::Hangup => 1,
        ExecutionSignalV1::Interrupt => 2,
        ExecutionSignalV1::Quit => 3,
        ExecutionSignalV1::Terminate => 4,
        ExecutionSignalV1::Kill => 5,
        ExecutionSignalV1::User1 => 6,
        ExecutionSignalV1::User2 => 7,
    }
}

const fn execution_signal_from_proto(value: i32) -> Option<ExecutionSignalV1> {
    match value {
        1 => Some(ExecutionSignalV1::Hangup),
        2 => Some(ExecutionSignalV1::Interrupt),
        3 => Some(ExecutionSignalV1::Quit),
        4 => Some(ExecutionSignalV1::Terminate),
        5 => Some(ExecutionSignalV1::Kill),
        6 => Some(ExecutionSignalV1::User1),
        7 => Some(ExecutionSignalV1::User2),
        _ => None,
    }
}

#[cfg(test)]
mod terminal_v2_tests {
    //! Exact terminal-only signal projection; control vocabulary is unchanged.

    use super::*;
    use aos_sandbox_agent::openssh_session::OriginalExecutionWaitStatusV4;

    #[test]
    fn genuine_fault_and_realtime_status_are_not_guessed_control_signals() {
        for raw in [11 | 0x80, 64, 9] {
            let expected = ExecutionTerminalOutcomeV1::OriginalLinux {
                status: OriginalExecutionWaitStatusV4::new(raw).unwrap(),
                canceled: false,
            };
            let mut value = expected
                .to_proto(
                    aos_proto::aos::sandbox::v1::Timestamp {
                        seconds: 1,
                        ..Default::default()
                    },
                    "Original Guest process terminated".to_owned(),
                )
                .unwrap();
            assert_eq!(
                ExecutionTerminalOutcomeV1::try_from_proto(&value).unwrap(),
                expected
            );
            assert_eq!(
                value
                    .terminal_signal_v2
                    .as_option()
                    .unwrap()
                    .linux_signal_number,
                raw & 0x7f
            );

            value.signal = 3.into();
            assert!(ExecutionTerminalOutcomeV1::try_from_proto(&value).is_err());
            value.signal = 0.into();
            value.termination_kind = 1.into();
            assert!(ExecutionTerminalOutcomeV1::try_from_proto(&value).is_err());
        }
    }

    #[test]
    fn completed_cancellation_retains_original_waitstatus_without_a_sentinel() {
        for raw in [9, 17 << 8] {
            let expected = ExecutionTerminalOutcomeV1::OriginalLinux {
                status: OriginalExecutionWaitStatusV4::new(raw).unwrap(),
                canceled: true,
            };
            let value = expected
                .to_proto(
                    aos_proto::aos::sandbox::v1::Timestamp {
                        seconds: 1,
                        ..Default::default()
                    },
                    "Original execution subtree canceled".to_owned(),
                )
                .unwrap();
            assert_eq!(value.termination_kind.to_i32(), 4);
            assert_eq!(
                ExecutionTerminalOutcomeV1::try_from_proto(&value).unwrap(),
                expected
            );
        }
    }
}
