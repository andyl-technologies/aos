##! Owns mergeable VM check specifications for retained package consumers.
{lib, ...}: let
  # `script` is Python source — run by the AOS test driver
  # (pkgs/tools/aos/aos-test-driver) against the guest agent. Each
  # check sees the system under test as the `vm` module global; use
  # `vm.succeed("...")`, `vm.fail("...")`,
  # `vm.wait_until_succeeds("...", timeout=60)`, etc. — see
  # `pkgs/tools/aos/aos-test-driver/aos_test_driver/machine.py` for
  # the full Machine API.
  checkType = lib.types.submodule {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        description = "Check identifier; used in log banners as <group>/<name>.";
      };
      description = lib.mkOption {
        type = lib.types.str;
        description = "Human-readable purpose of the check.";
      };
      script = lib.mkOption {
        type = lib.types.lines;
        description = ''
          Python fragment run by the AOS test driver against the
          guest agent. The VM under test is the `vm` module global.
          See `pkgs/tools/aos/aos-test-driver/aos_test_driver/machine.py`
          for the Machine API (`succeed`, `fail`,
          `wait_until_succeeds`, `wait_for_unit`, `wait_for_file`,
          `execute`).
        '';
      };
    };
  };

  checkSpecType = lib.types.submodule ({name, ...}: {
    options = {
      description = lib.mkOption {
        type = lib.types.str;
        default = name;
        description = "Description shown in the test log banner.";
      };
      checks = lib.mkOption {
        type = lib.types.listOf checkType;
        description = "Flat list of checks run inside one VM.";
      };
      extraDisks = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
          options.sizeMiB = lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value > 0);
            description = "Size of the blank device presented to the guest.";
          };
        });
        default = [];
        description = ''
          Additional blank block devices attached to the VM, appearing as
          /dev/vdb onward in declaration order. Storage checks need real
          devices to build a pool or array on, which the root disk cannot
          provide.
        '';
      };
      kernelParams = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = ''
          Extra kernel command-line arguments for the check VM. The harness
          owns the boot arguments that select a root and console, so a check
          that depends on kernel or module parameters names them here rather
          than relying on the image's own command line.
        '';
      };
      timeoutSeconds = lib.mkOption {
        type = lib.types.nullOr (lib.types.addCheck lib.types.int (value: value > 0));
        default = null;
        description = ''
          Wall-clock budget for the whole check group, covering guest boot as
          well as the checks themselves. Null takes the harness default. Raise
          it for a subject that adds boot-time work, such as storage that has
          to be imported and mounted before the system is usable.
        '';
      };
      memoryMiB = lib.mkOption {
        type = lib.types.nullOr (lib.types.addCheck lib.types.int (value: value > 0));
        default = null;
        description = ''
          Guest memory for this check group. Null takes the harness default.
          Checks that exercise memory policy need enough RAM for the
          proportional caps to leave a usable budget.
        '';
      };
    };
  });
in {
  options.system.checks = lib.mkOption {
    extensible = true;
    type = lib.types.attrsOf checkSpecType;
    default = {};
    description = ''
      VM checks contributed by modules, keyed by check-group name.
      Each entry produces one test derivation at
      `system.build.checks.<name>`.
    '';
  };
}
