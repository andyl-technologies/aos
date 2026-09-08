##! Exercises a seventh H-through-P command slice through offline interfaces.
{testing}: let
  mkCommandProbe = {
    package,
    executable,
    directory ? "bin",
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryArguments,
    primaryCheck,
    badInput,
    badOperation,
    badExpected,
    badArguments,
    badCheck ? "result.returncode != 0",
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
              argv = [
                "@python@"
                "-c"
                ''
                  import subprocess
                  result = subprocess.run(["@out@/${directory}/${executable}"] + ${builtins.toJSON primaryArguments}, capture_output=True, text=True)
                  assert ${primaryCheck}, (result.returncode, result.stdout, result.stderr)
                  print("${package} primary passed")
                ''
              ];
              exit_code = 0;
              stdout.exact = "${package} primary passed\n";
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
              argv = [
                "@python@"
                "-c"
                ''
                  import subprocess, sys
                  result = subprocess.run(["@out@/${directory}/${executable}"] + ${builtins.toJSON badArguments}, capture_output=True, text=True)
                  assert ${badCheck}, (result.returncode, result.stdout, result.stderr)
                  sys.stderr.write("${package} rejected invalid input\n")
                  raise SystemExit(7)
                ''
              ];
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

  mkHelpProbe = {
    package,
    executable,
    primaryArguments ? ["--help"],
    primaryNeedle ? "usage",
    badArguments ? ["aos-invalid-command"],
    badNeedle ? "",
  }:
    mkCommandProbe {
      inherit package executable primaryArguments badArguments;
      primaryInput = "The packaged ${package} command-line interface.";
      primaryOperation = "Request its offline command inventory.";
      primaryExpected = "The command describes its supported invocation contract.";
      primaryCheck = ''result.returncode == 0 and ${builtins.toJSON primaryNeedle} in (result.stdout + result.stderr).lower()'';
      badInput = "A ${package} invocation naming an unsupported command.";
      badOperation = "Parse the unknown command without starting a service.";
      badExpected = "The command rejects the unsupported operation.";
      badCheck = ''result.returncode != 0 and ${builtins.toJSON badNeedle} in (result.stdout + result.stderr).lower()'';
    };
in {
  iperf3 = mkCommandProbe {
    package = "iperf3";
    executable = "iperf3";
    primaryInput = "The packaged iperf3 option inventory.";
    primaryOperation = "Request help without opening a network connection.";
    primaryExpected = "Iperf3 documents its client, server, port, and duration options.";
    primaryArguments = ["--help"];
    primaryCheck = ''result.returncode == 0 and "--client" in result.stdout and "--server" in result.stdout and "--time" in result.stdout'';
    badInput = "An iperf3 invocation containing an unsupported option.";
    badOperation = "Parse the invalid option without opening a network connection.";
    badExpected = "Iperf3 rejects the unsupported option.";
    badArguments = ["--aos-invalid-option"];
    badCheck = ''result.returncode != 0 and "unrecognized option" in result.stderr.lower()'';
  };

  k3s = mkHelpProbe {
    package = "k3s";
    executable = "k3s";
    primaryNeedle = "kubernetes, but small and simple";
    badNeedle = "no help topic";
  };

  libvirt = mkHelpProbe {
    package = "libvirt";
    executable = "virsh";
    primaryNeedle = "hypervisor connection uri";
    badNeedle = "unknown command";
  };

  longhorn-engine = mkHelpProbe {
    package = "longhorn-engine";
    executable = "longhorn-engine";
    primaryNeedle = "controller";
    badNeedle = "unrecognized command";
  };

  longhorn-instance-manager = mkHelpProbe {
    package = "longhorn-instance-manager";
    executable = "longhorn-instance-manager";
    primaryNeedle = "instance-manager";
    badNeedle = "no help topic";
  };

  longhorn-manager = mkHelpProbe {
    package = "longhorn-manager";
    executable = "longhorn-manager";
    primaryNeedle = "longhorn manager";
    badNeedle = "unrecognized command";
  };

  lsof = mkCommandProbe {
    package = "lsof";
    executable = "lsof";
    primaryInput = "The packaged open-file inspector's release identity.";
    primaryOperation = "Request verbose version information without scanning processes.";
    primaryExpected = "Lsof reports its revision and compiler identity.";
    primaryArguments = ["-v"];
    primaryCheck = ''result.returncode == 0 and "revision:" in result.stderr.lower() and "compiler" in result.stderr.lower()'';
    badInput = "An lsof invocation containing an unsupported long option.";
    badOperation = "Parse the invalid option without scanning processes.";
    badExpected = "Lsof rejects the unsupported option.";
    badArguments = ["--aos-invalid-option"];
    badCheck = ''result.returncode != 0 and "illegal option" in result.stderr.lower()'';
  };

  lvm2 = mkCommandProbe {
    package = "lvm2";
    executable = "lvm";
    directory = "sbin";
    primaryInput = "The LVM command inventory.";
    primaryOperation = "Request help without scanning or changing block devices.";
    primaryExpected = "LVM lists its configuration, physical-volume, volume-group, and logical-volume commands.";
    primaryArguments = ["help"];
    primaryCheck = ''result.returncode == 0 and "available lvm commands" in result.stderr.lower() and "pvcreate" in result.stderr and "lvcreate" in result.stderr'';
    badInput = "An LVM invocation naming a command that does not exist.";
    badOperation = "Resolve the unsupported command without scanning block devices.";
    badExpected = "LVM rejects the unknown command.";
    badArguments = ["aos-invalid-command"];
    badCheck = ''result.returncode != 0 and "no such command" in result.stderr.lower()'';
  };

  numad = mkCommandProbe {
    package = "numad";
    executable = "numad";
    primaryInput = "The packaged NUMA placement daemon's option inventory.";
    primaryOperation = "Request usage without starting the daemon.";
    primaryExpected = "Numad documents its interval, logging, and process-placement options.";
    primaryArguments = ["-h"];
    primaryCheck = ''result.returncode == 1 and "usage:" in result.stderr.lower() and "-i" in result.stderr and "-p" in result.stderr'';
    badInput = "A numad invocation containing an unsupported long option.";
    badOperation = "Parse the invalid option without starting the daemon.";
    badExpected = "Numad rejects the unsupported option.";
    badArguments = ["--aos-invalid-option"];
    badCheck = ''result.returncode != 0 and "invalid option" in result.stderr.lower()'';
  };

  pm-utils = mkCommandProbe {
    package = "pm-utils";
    executable = "pm-is-supported";
    primaryInput = "The pm-is-supported power-state option inventory.";
    primaryOperation = "Request help without entering a sleep state.";
    primaryExpected = "Pm-utils documents suspend, hibernate, and hybrid suspend queries.";
    primaryArguments = ["--help"];
    primaryCheck = ''result.returncode == 0 and "--suspend" in result.stdout and "--hibernate" in result.stdout'';
    badInput = "A power-state query naming an unsupported mode.";
    badOperation = "Parse the invalid mode without entering a sleep state.";
    badExpected = "Pm-utils rejects the unsupported mode.";
    badArguments = ["--aos-invalid-mode"];
    badCheck = ''result.returncode != 0 and "pm-is-supported" in result.stderr'';
  };
}
