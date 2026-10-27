"""Checks the finite canonical Source machine-role profile in final unit bytes.

This build-side DATA validator creates no native original or runtime authority.
The independent Source consumer validates the same byte contract against actual
PID1-delivered files and their authenticated Parent row commitments.
"""

SOURCE_UNIT = "aos-sandbox-source-signerd.service"
CACHE_UNIT = "aos-sandbox-cache-signerd.service"
MAXIMUM_FILE_BYTES = 65536
EMPTY_SERVICE_DIRECTIVES = {
    "PAMName", "EnvironmentFile", "CapabilityBoundingSet", "AmbientCapabilities",
    "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecReloadPost",
    "ExecStop", "ExecStopPost",
    "RootDirectory", "RootImage", "RootMStack", "MountImages", "ExtensionImages",
    "ExtensionDirectories", "TemporaryFileSystem", "RuntimeDirectory",
    "StateDirectory", "CacheDirectory", "LogsDirectory", "ConfigurationDirectory",
}

DISABLED_HELPER_DIRECTIVES = {"PrivateUsers", "PrivatePIDs", "PrivateBPF", "DynamicUser", "RootEphemeral"}


class _FixedSignerProtectedProfileV1:
    """Checks the one selected command across a bounded canonical file set."""

    def __init__(self, expected_exec, unit, identity, label):
        self.unit = unit
        self.identity = identity
        self.label = label
        if not isinstance(expected_exec, str) or not expected_exec or any(
            ord(char) < 32 or ord(char) > 126 for char in expected_exec
        ):
            raise ValueError(f"protected {self.label} requires one finite literal executable command")
        self.expected_exec = expected_exec
        self.paths = set()
        self.exec_seen = False
        self.identity_seen = set()

    def observe(self, path, content):
        is_base = path == self.unit
        prefix = self.unit + ".d/"
        basename = path[len(prefix):] if path.startswith(prefix) else ""
        is_drop = bool(basename) and "/" not in basename and basename.endswith(".conf")
        if not (is_base or is_drop) or path in self.paths or len(self.paths) >= 5:
            raise ValueError(f"protected {self.label} profile file order or roster changed")
        if is_base != (not self.paths):
            raise ValueError(f"protected {self.label} base must precede its drop-ins")
        if (not content and is_base) or len(content) > MAXIMUM_FILE_BYTES or (content and not content.endswith(b"\n")):
            raise ValueError(f"protected {self.label} base must be nonempty and nonempty files end in LF")
        if any(byte > 126 or (byte < 32 and byte not in (9, 10)) for byte in content):
            raise ValueError(f"protected {self.label} profile requires canonical ASCII and LF")

        section = None
        for raw in content.decode("ascii").split("\n"):
            line = raw.strip(" \t")
            if line.endswith("\\"):
                raise ValueError(f"protected {self.label} profile has no continuation syntax")
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("["):
                if line not in ("[Unit]", "[Service]", "[Install]"):
                    raise ValueError(f"protected {self.label} profile section is unsupported")
                section = line
                continue
            if section is None or "=" not in line:
                raise ValueError(f"protected {self.label} profile requires canonical assignments")
            key, value = line.split("=", 1)
            key = key.strip(" \t")
            value = value.strip(" \t")
            if not key or not all(char.isascii() and (char.isalnum() or char == "-") for char in key):
                raise ValueError(f"protected {self.label} profile key is not canonical")
            if section != "[Service]":
                continue
            if key in DISABLED_HELPER_DIRECTIVES and value.lower() not in ("", "no", "false", "0"):
                raise ValueError(f"protected {self.label} pre-exec profile permits no namespace helper processes")
            if key in ("PrivateTmp", "PrivateVarTmp") and value.lower() not in ("yes", "true", "1", "connected"):
                raise ValueError(f"protected {self.label} requires its connected private temporary directories")
            # An explicit DelegateNamespaces=no still requests PRIVATE_USERS_SELF
            # in the actual executor. Only default/empty resets avoid that path.
            if key in ("UserNamespacePath", "DelegateNamespaces") and value:
                raise ValueError(f"protected {self.label} has no external user namespace")
            if key in EMPTY_SERVICE_DIRECTIVES and value:
                raise ValueError(f"protected {self.label} profile has an unsupported service directive")
            if key in ("User", "Group"):
                if not is_base or key in self.identity_seen or value != self.identity:
                    raise ValueError(f"protected {self.label} requires its fixed signer user and group")
                self.identity_seen.add(key)
            if key == "ExecStart":
                if not is_base or self.exec_seen or value != self.expected_exec:
                    raise ValueError(f"protected {self.label} requires exactly its one selected main command")
                self.exec_seen = True

        self.paths.add(path)

    def require_complete(self):
        if not self.exec_seen or self.identity_seen != {"User", "Group"}:
            raise ValueError(f"protected {self.label} profile lacks its fixed main command or identity")


class SourceProtectedProfileV1(_FixedSignerProtectedProfileV1):
    """Checks the actual Source unit through the shared finite grammar."""

    def __init__(self, expected_exec):
        super().__init__(expected_exec, SOURCE_UNIT, "aos-source-signer", "Source")


class CacheProtectedProfileV1(_FixedSignerProtectedProfileV1):
    """Checks the actual Cache signer unit through the same finite grammar."""

    def __init__(self, expected_exec):
        super().__init__(expected_exec, CACHE_UNIT, "aos-cache-signer", "Cache")
