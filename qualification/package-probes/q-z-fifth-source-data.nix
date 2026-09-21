##! Exercises fifth-slice Q-through-Z source and policy data contracts.
{testing}: let
  mkDataProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badScript,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files = {};
          steps = [
            {
              argv = ["@python@" "-c" primaryScript];
              exit_code = 0;
              stdout.exact = "${package} operation passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = {};
          steps = [
            {
              argv = ["@python@" "-c" badScript];
              exit_code = 7;
              stdout.exact = "";
              stderr.exact = "${package} rejected invalid input\n";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };

  reject = package: body: ''
    import sys
    ${body}
    sys.stderr.write("${package} rejected invalid input\n")
    raise SystemExit(7)
  '';
in {
  qemu-crucible-source = mkDataProbe {
    package = "qemu-crucible-source";
    primaryInput = "The published corresponding-source manifest for the patched QEMU and Crucible plugin pair.";
    primaryOperation = "Resolve every manifest-named rebuild input beneath the immutable source root.";
    primaryExpected = "The upstream archive, patch series, boundary header, build expression, plugin workspace, and vendor tree are present and nonempty.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@/share/aos/qemu-crucible-source")
      values = dict(line.split("=", 1) for line in (root / "SOURCE-MANIFEST.env").read_text().splitlines() if "=" in line)
      assert values["package"] == "qemu-crucible-source"
      for key in ["qemu_source_file", "qemu_build_expression", "shmem_header_file", "qemu_patch_license_inventory", "plugin_source_root", "plugin_cargo_vendor"]:
          path = root / values[key]
          assert path.exists() and (path.is_dir() or path.stat().st_size > 0)
      assert (root / "patches/_series.nix").stat().st_size > 0
      print("qemu-crucible-source operation passed")
    '';
    badInput = "A request for a native QEMU object file in the corresponding-source artifact.";
    badOperation = "Resolve a compiled object outside the source-only publication contract.";
    badExpected = "The source package rejects the absent binary object.";
    badScript = reject "qemu-crucible-source" ''
      import pathlib
      root = pathlib.Path("@out@/share/aos/qemu-crucible-source")
      assert not (root / "build/qemu-system-x86_64").exists()
    '';
  };

  refpolicy = mkDataProbe {
    package = "refpolicy";
    primaryInput = "The installed SELinux base policy modules and development interface tree.";
    primaryOperation = "Inspect the base module and the policy-development Makefile contract.";
    primaryExpected = "The base policy package and refpolicy include Makefile are nonempty and identify refpolicy.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@/usr/share/selinux/refpolicy")
      assert (root / "base.pp").stat().st_size > 0
      makefile = (root / "include/Makefile").read_text()
      assert "refpolicy" in makefile and (root / "include/support").is_dir()
      print("refpolicy operation passed")
    '';
    badInput = "A request for an uncompiled qualification-invalid policy module.";
    badOperation = "Resolve the nonexistent module from the installed policy store.";
    badExpected = "The policy package rejects the absent module name.";
    badScript = reject "refpolicy" ''
      import pathlib
      assert not pathlib.Path("@out@/usr/share/selinux/refpolicy/qualification-invalid.pp").exists()
    '';
  };
}
