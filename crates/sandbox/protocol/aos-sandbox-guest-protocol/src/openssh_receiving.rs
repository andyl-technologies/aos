//! Shares fixed source bounds used by the actual Guest SSH installation.
//!
//! These DATA constants convey no execution, file, socket or financial grant.
//! The genuine Host owner pays their actual native suppliers before entry.

mod descendant;
pub use descendant::{
    OPENSSH_DESCENDANT_PLAN_BYTES_V1, OPENSSH_DESCENDANT_PROCESS_CEILING_V1,
    OpenSshDescendantPlanDataErrorV1, OpenSshDescendantPlanDataV1,
    guest_runtime_identity_data_v1,
};

/// Bounds each immutable static login database consumed by the Guest parser.
pub const OPENSSH_LOGIN_FILE_BYTES_V1: usize = 1_048_576;

/// Bounds an installed executable checked by the streaming native SHA256 reader.
pub const OPENSSH_EXECUTABLE_FILE_BYTES_V1: u64 = 128 * 1_048_576;

/// Bounds the actual canonical generated configuration and claim write inputs.
///
/// Each selected writer rejects a larger input before creating its fixed file.
pub const OPENSSH_INSTALL_RECORD_BYTES_V1: usize = 4096;

/// Bounds the selected daemon's temporary native spawn descriptor plane.
///
/// The exact std Unix setup opens three Null stdio descriptors and its Linux
/// exec-status socket pair; one additional slot conservatively covers the
/// optional std Child pidfd. The selected caller uses those three Null streams.
pub const OPENSSH_DAEMON_SPAWN_FILES_V1: usize = 3 + 2 + 1;

/// Names the sole selected SSH daemon image without consulting PATH.
pub const OPENSSH_DAEMON_PROGRAM_V1: &str = "/usr/sbin/sshd";

/// Names the existing fixed selected daemon configuration.
pub const OPENSSH_DAEMON_CONFIGURATION_V1: &str = "/etc/aos/sandbox-attach/sshd_config";

/// Enables the selected daemon's fixed original listener-bootstrap callback.
pub const OPENSSH_DAEMON_BOOTSTRAP_ARGUMENT_V1: &str = "-oAosAttachBootstrapV1=yes";

/// Lists the complete selected daemon arguments, excluding the program name.
///
/// These are the existing fixed monitor/config/session arguments. They carry
/// no tenant environment or new execution permission.
pub const OPENSSH_DAEMON_ARGUMENTS_V1: [&str; 6] = [
    "-D",
    "-e",
    "-f",
    OPENSSH_DAEMON_CONFIGURATION_V1,
    "-oAosAttachMonitorV2=yes",
    "-oSshdSessionPath=/usr/libexec/sshd-session",
];

/// Lists the entire selected daemon environment after inherited entries clear.
pub const OPENSSH_DAEMON_ENVIRONMENT_V1: [(&str, &str); 2] = [("LANG", "C"), ("LC_ALL", "C")];

// Rust1.98.1's actual two-entry CommandEnv/captured environment each fit one
// LeafNode (B=6): parent, parent_idx, len, eleven key and value destinations.
// The selected recipe never imports the process environment or grows either
// map beyond those two rows. This layout is cost DATA, never a map adopter.
#[repr(C)]
struct EnvironmentLeafLayoutV1<V> {
    parent: Option<std::ptr::NonNull<()>>,
    parent_index: std::mem::MaybeUninit<u16>,
    length: u16,
    keys: [std::mem::MaybeUninit<std::ffi::OsString>; 11],
    values: [std::mem::MaybeUninit<V>; 11],
}

/// Prices the actual closed argv/environment models and their spawn capture.
///
/// The two CString arrays have at most eight elements each; sixteen cells
/// cover their old/new allocation overlap. String extents include terminators
/// and constructor/destination copies. No inherited environment is included.
#[must_use]
pub fn openssh_daemon_command_bytes_v1() -> Option<usize> {
    let argument_bytes = OPENSSH_DAEMON_ARGUMENTS_V1.iter().try_fold(
        OPENSSH_DAEMON_PROGRAM_V1.len().checked_add(1)?,
        |sum, argument| sum.checked_add(argument.len().checked_add(1)?),
    )?;
    let argument_bytes = argument_bytes.checked_add(OPENSSH_DAEMON_BOOTSTRAP_ARGUMENT_V1.len().checked_add(1)?)?;
    let environment_bytes = OPENSSH_DAEMON_ENVIRONMENT_V1
        .iter()
        .try_fold(0_usize, |sum, (key, value)| {
            sum.checked_add(key.len().checked_add(value.len())?.checked_add(2)?)
        })?;
    std::mem::size_of::<std::process::Command>()
        .checked_mul(3)?
        .checked_add(std::mem::size_of::<
            EnvironmentLeafLayoutV1<Option<std::ffi::OsString>>,
        >())?
        .checked_add(std::mem::size_of::<
            EnvironmentLeafLayoutV1<std::ffi::OsString>,
        >())?
        .checked_add(std::mem::size_of::<Vec<std::ffi::CString>>().checked_mul(4)?)?
        .checked_add(std::mem::size_of::<Vec<*const u8>>().checked_mul(4)?)?
        .checked_add(
            std::mem::size_of::<std::ffi::CString>()
                .checked_add(std::mem::size_of::<*const u8>())?
                .checked_mul(32)?,
        )?
        .checked_add(argument_bytes.checked_mul(4)?)?
        .checked_add(environment_bytes.checked_mul(4)?)
}

/// Prices source-bound path and pure installation-input overlap.
///
/// Static login bytes are priced by the shared native reader's actual supplier.
/// The two generated records and their constructor/destination copies coexist
/// with fixed absolute paths; native/crypto controls remain separately funded.
#[must_use]
pub fn openssh_install_input_bytes_v1() -> Option<usize> {
    OPENSSH_INSTALL_RECORD_BYTES_V1
        .checked_mul(4)?
        .checked_add(4 * 4096)?
        .checked_add(openssh_daemon_command_bytes_v1()?)
}
