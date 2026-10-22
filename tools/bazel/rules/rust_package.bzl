"""Owns first-party Rust package identity independently of Cargo manifests."""

def _numeric_identifier(value):
    return value and all([character in "0123456789" for character in value.elems()]) and (value == "0" or not value.startswith("0"))

def _identifiers(value, numeric_leading_zeroes):
    for part in value.split("."):
        if not part or not all([character in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-" for character in part.elems()]):
            return False
        if not numeric_leading_zeroes and all([character in "0123456789" for character in part.elems()]) and not _numeric_identifier(part):
            return False
    return True

def _version_parts(version):
    build = version.split("+")
    if len(build) > 2 or (len(build) == 2 and not _identifiers(build[1], True)):
        fail("Rust package version must be SemVer: " + version)
    release = build[0].split("-", 1)
    numbers = release[0].split(".")
    if len(numbers) != 3 or not all([_numeric_identifier(part) for part in numbers]):
        fail("Rust package version must be SemVer: " + version)
    pre = release[1] if len(release) == 2 else ""
    if len(release) == 2 and not _identifiers(pre, False):
        fail("Rust package version must be SemVer: " + version)
    return numbers + [pre]

def aos_rust_package(name, version, license_expression, license_domain = "apache-host", edition = "2024", description = "", authors = [], homepage = "", repository = "", readme = "", rust_version = ""):
    """Declares metadata shared by a package's libraries, binaries, and tests."""
    if not name or not all([character in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_" for character in name.elems()]):
        fail("invalid Rust package name: " + name)
    if edition not in ["2015", "2018", "2021", "2024"]:
        fail("unsupported Rust edition: " + edition)
    if license_domain not in ["apache-host", "permissive-protocol", "gpl-qemu"] or not license_expression:
        fail("Rust package requires an explicit license and known license domain")
    major, minor, patch, pre = _version_parts(version)
    return struct(
        name = name,
        version = version,
        edition = edition,
        license_expression = license_expression,
        license_domain = license_domain,
        rustc_env = {
            "CARGO_PKG_NAME": name,
            "CARGO_PKG_VERSION": version,
            "CARGO_PKG_VERSION_MAJOR": major,
            "CARGO_PKG_VERSION_MINOR": minor,
            "CARGO_PKG_VERSION_PATCH": patch,
            "CARGO_PKG_VERSION_PRE": pre,
            "CARGO_PKG_AUTHORS": ":".join(authors),
            "CARGO_PKG_DESCRIPTION": description,
            "CARGO_PKG_HOMEPAGE": homepage,
            "CARGO_PKG_REPOSITORY": repository,
            "CARGO_PKG_LICENSE": license_expression,
            "CARGO_PKG_LICENSE_FILE": "",
            "CARGO_PKG_README": readme,
            "CARGO_PKG_RUST_VERSION": rust_version,
        },
    )

def rust_package_attributes(package, attributes):
    """Applies declared identity, rejecting per-target metadata overrides."""
    attributes = dict(attributes)
    for key, value in {"version": package.version, "edition": package.edition}.items():
        if key in attributes and attributes[key] != value:
            fail("Rust target conflicts with package " + key + ": " + package.name)
        attributes[key] = value
    environment = dict(attributes.get("rustc_env", {}))
    for key, value in package.rustc_env.items():
        if key in environment and environment[key] != value:
            fail("Rust target overrides package metadata " + key + ": " + package.name)
        environment[key] = value
    attributes["rustc_env"] = environment
    return attributes
