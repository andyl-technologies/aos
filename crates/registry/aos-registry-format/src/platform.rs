//! Target platform spelling used by registry manifests.

/// Returns the Nix system name for the running binary.
///
/// Architecture names are normalized to their Nix spellings and Apple's
/// `macos` operating-system identifier is rendered as `darwin`. Unknown
/// architectures and operating systems retain Rust's spelling so a future
/// port can use registry data without first changing this helper.
///
/// # Examples
///
/// ```
/// let platform = aos_registry_format::platform::native_platform();
/// assert!(platform.contains('-'));
/// ```
pub fn native_platform() -> String {
    platform_name(std::env::consts::ARCH, std::env::consts::OS)
}

/// Converts Rust architecture and operating-system names into a Nix system
/// name.
fn platform_name(architecture: &str, operating_system: &str) -> String {
    let architecture = match architecture {
        "arm" => "armv7l",
        known @ ("x86_64" | "aarch64" | "riscv64") => known,
        other => other,
    };
    let operating_system = match operating_system {
        "macos" => "darwin",
        other => other,
    };

    format!("{architecture}-{operating_system}")
}

#[cfg(test)]
mod tests {
    use super::platform_name;

    #[test]
    fn maps_supported_darwin_platforms_to_nix_names() {
        assert_eq!(platform_name("x86_64", "macos"), "x86_64-darwin");
        assert_eq!(platform_name("aarch64", "macos"), "aarch64-darwin");
    }

    #[test]
    fn preserves_supported_linux_platforms() {
        assert_eq!(platform_name("x86_64", "linux"), "x86_64-linux");
        assert_eq!(platform_name("aarch64", "linux"), "aarch64-linux");
        assert_eq!(platform_name("arm", "linux"), "armv7l-linux");
    }

    #[test]
    fn preserves_unknown_components() {
        assert_eq!(platform_name("mips64", "freebsd"), "mips64-freebsd");
    }
}
