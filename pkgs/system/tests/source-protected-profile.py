"""Exercises the new image DATA validator without constructing authority."""

import importlib.util
import pathlib
import sys
import unittest

spec = importlib.util.spec_from_file_location(
    "source_protected_profile", pathlib.Path(sys.argv.pop(1))
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
COMMAND = "/nix/store/selected/bin/aos-sandbox-source-signerd 100 100 101 101"
BASE = ("[Unit]\nX-StopIfChanged=false\n[Service]\nExecStart=" + COMMAND + "\nCapabilityBoundingSet=\nUser=aos-source-signer\nGroup=aos-source-signer\n").encode()


class SourceProfileTests(unittest.TestCase):
    def test_actual_command_and_supported_upgrade_marker_with_empty_reset_drop(self):
        profile = module.SourceProtectedProfileV1(COMMAND)
        profile.observe(module.SOURCE_UNIT, BASE)
        profile.observe(module.SOURCE_UNIT + ".d/empty.conf", b"[Service]\nPAMName=\nEnvironmentFile= \n")
        profile.observe(module.SOURCE_UNIT + ".d/inert.conf", b"")
        profile.require_complete()

    def test_nonempty_pam_envfile_and_auxiliary_dropins_are_rejected(self):
        for directive in ("PAMName=login", "EnvironmentFile=-/run/*.env", "ExecStartPre=/store/helper", "AmbientCapabilities=CAP_SYS_RESOURCE"):
            with self.subTest(directive=directive):
                profile = module.SourceProtectedProfileV1(COMMAND)
                profile.observe(module.SOURCE_UNIT, BASE)
                with self.assertRaises(ValueError):
                    profile.observe(module.SOURCE_UNIT + ".d/override.conf", ("[Service]\n" + directive + "\n").encode())

    def test_a_dropin_cannot_reset_or_replace_the_selected_command(self):
        for command in ("", COMMAND, "/store/foreign"):
            with self.subTest(command=command):
                profile = module.SourceProtectedProfileV1(COMMAND)
                profile.observe(module.SOURCE_UNIT, BASE)
                with self.assertRaises(ValueError):
                    profile.observe(module.SOURCE_UNIT + ".d/command.conf", ("[Service]\nExecStart=" + command + "\n").encode())

    def test_continuation_include_and_control_text_fail_before_a_profile_finishes(self):
        for content in (b".include /run/foreign\n", b"[Service]\nEnvironment\\\nFile=/run/input\n", b"[Service]\r\n", b"[Service]\nName=\x00\n"):
            with self.subTest(content=content):
                profile = module.SourceProtectedProfileV1(COMMAND)
                with self.assertRaises(ValueError):
                    profile.observe(module.SOURCE_UNIT, content)

    def test_actual_disabled_helpers_and_connected_tmp_values_are_supported(self):
        for value in ("", "no", "false", "0", "No", "FALSE"):
            for key in ("PrivateUsers", "PrivatePIDs", "PrivateBPF", "DynamicUser", "RootEphemeral"):
                with self.subTest(key=key, value=value):
                    profile = module.SourceProtectedProfileV1(COMMAND)
                    profile.observe(module.SOURCE_UNIT, BASE + (key + "=" + value + "\n").encode())
                    profile.require_complete()
        for value in ("yes", "true", "1", "connected", "TRUE"):
            profile = module.SourceProtectedProfileV1(COMMAND)
            profile.observe(module.SOURCE_UNIT, BASE + ("PrivateTmp=" + value + "\n").encode())
            profile.require_complete()

    def test_delegate_no_is_not_equivalent_to_the_actual_default(self):
        # The actual executor maps every non-INITIAL DelegateNamespaces field,
        # even explicit zero, to PRIVATE_USERS_SELF. Empty restores INITIAL.
        profile = module.SourceProtectedProfileV1(COMMAND)
        profile.observe(module.SOURCE_UNIT, BASE + b"DelegateNamespaces=\n")
        profile.require_complete()

        for value in ("no", "false", "0", "yes", "mnt"):
            with self.subTest(value=value):
                profile = module.SourceProtectedProfileV1(COMMAND)
                with self.assertRaises(ValueError):
                    profile.observe(module.SOURCE_UNIT, BASE + ("DelegateNamespaces=" + value + "\n").encode())

    def test_optional_images_and_disconnected_tmp_are_outside_the_new_profile(self):
        for key in ("RootDirectory", "RootImage", "RootMStack", "MountImages", "ExtensionImages", "ExtensionDirectories", "TemporaryFileSystem"):
            with self.subTest(key=key):
                profile = module.SourceProtectedProfileV1(COMMAND)
                with self.assertRaises(ValueError):
                    profile.observe(module.SOURCE_UNIT, BASE + (key + "=/run/foreign\n").encode())
        for key, value in (("PrivateTmp", "disconnected"), ("PrivateVarTmp", "no"), ("UserNamespacePath", "/run/foreign"), ("RootEphemeral", "true")):
            with self.subTest(key=key):
                profile = module.SourceProtectedProfileV1(COMMAND)
                with self.assertRaises(ValueError):
                    profile.observe(module.SOURCE_UNIT, BASE + (key + "=" + value + "\n").encode())

    def test_execution_directories_are_refused_before_the_new_profile_can_finish(self):
        for key in ("RuntimeDirectory", "StateDirectory", "CacheDirectory", "LogsDirectory", "ConfigurationDirectory"):
            with self.subTest(key=key):
                profile = module.SourceProtectedProfileV1(COMMAND)
                profile.observe(module.SOURCE_UNIT, BASE)
                with self.assertRaises(ValueError):
                    profile.observe(module.SOURCE_UNIT + ".d/directories.conf", ("[Service]\n" + key + "=private\n").encode())

                profile = module.SourceProtectedProfileV1(COMMAND)
                profile.observe(module.SOURCE_UNIT, BASE + (key + "=\n").encode())
                profile.require_complete()


class CacheProfileTests(unittest.TestCase):
    def test_cache_identity_and_command_use_the_same_canonical_profile(self):
        command = "/nix/store/selected/bin/aos-sandbox-cache-signerd 100 100 813 813"
        body = BASE.replace(COMMAND.encode(), command.encode()).replace(
            b"aos-source-signer", b"aos-cache-signer"
        )
        profile = module.CacheProtectedProfileV1(command)
        profile.observe(module.CACHE_UNIT, body)
        profile.observe(module.CACHE_UNIT + ".d/empty.conf", b"")
        profile.require_complete()

        for foreign in (BASE, body + b"PAMName=login\n", body + b"StateDirectory=private\n"):
            with self.subTest(foreign=foreign):
                refused = module.CacheProtectedProfileV1(command)
                with self.assertRaises(ValueError):
                    refused.observe(module.CACHE_UNIT, foreign)

    def test_cache_cannot_accept_the_source_unit_or_a_foreign_dropin(self):
        command = "/nix/store/selected/bin/aos-sandbox-cache-signerd 100 100 813 813"
        for path in (module.SOURCE_UNIT, module.CACHE_UNIT + ".d/nested/foreign.conf"):
            with self.subTest(path=path):
                profile = module.CacheProtectedProfileV1(command)
                with self.assertRaises(ValueError):
                    profile.observe(path, BASE)


if __name__ == "__main__":
    unittest.main()
