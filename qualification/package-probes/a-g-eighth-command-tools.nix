##! Exercises eighth-slice A-G commands through deterministic offline paths.
{testing}: let
  mkCliProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryCommand,
    primaryCheck,
    badInput,
    badOperation,
    badExpected,
    badCommand,
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
                  result = subprocess.run(${primaryCommand}, capture_output=True, text=True)
                  assert ${primaryCheck}, (result.returncode, result.stdout, result.stderr)
                  print("${package} operation passed")
                ''
              ];
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
              argv = [
                "@python@"
                "-c"
                ''
                  import subprocess, sys
                  result = subprocess.run(${badCommand}, capture_output=True, text=True)
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
    executable ? package,
    helpArguments ? ["--help"],
    helpNeedle,
    badArguments ? ["--aos-invalid-option"],
  }:
    mkCliProbe {
      inherit package;
      primaryInput = "The packaged ${package} command-line interface.";
      primaryOperation = "Request its offline help text.";
      primaryExpected = "The command returns success and documents ${helpNeedle}.";
      primaryCommand = builtins.toJSON (["@out@/bin/${executable}"] ++ helpArguments);
      primaryCheck = ''result.returncode == 0 and ${builtins.toJSON helpNeedle} in (result.stdout + result.stderr)'';
      badInput = "A ${package} invocation containing an unsupported command-line option.";
      badOperation = "Parse the unknown option without starting a service or contacting a remote endpoint.";
      badExpected = "The command rejects the unsupported option before performing its main operation.";
      badCommand = builtins.toJSON (["@out@/bin/${executable}"] ++ badArguments);
    };

  mkBazelProbe = package:
    mkCliProbe {
      inherit package;
      primaryInput = "The packaged Bazel launcher and embedded release identity.";
      primaryOperation = "Request the launcher version without loading a workspace.";
      primaryExpected = "Bazel returns success and reports its release version.";
      primaryCommand = ''["@out@/bin/bazel", "--version"]'';
      primaryCheck = ''result.returncode == 0 and "bazel" in (result.stdout + result.stderr).lower()'';
      badInput = "A Bazel startup request containing an unknown option.";
      badOperation = "Parse the invalid startup option before loading a workspace.";
      badExpected = "Bazel rejects the unsupported startup option.";
      badCommand = ''["@out@/bin/bazel", "--aos-invalid-startup-option"]'';
    };
in {
  aos = mkHelpProbe {
    package = "aos";
    helpNeedle = "Usage";
  };

  aos-hub = mkHelpProbe {
    package = "aos-hub";
    helpNeedle = "Usage";
  };

  aos-hub-cloudflare = mkHelpProbe {
    package = "aos-hub-cloudflare";
    executable = "aos-hub";
    helpNeedle = "Usage";
  };

  bazel = mkBazelProbe "bazel";
  bazel-7 = mkBazelProbe "bazel-7";
  bazel-8 = mkBazelProbe "bazel-8";
  bazel-9 = mkBazelProbe "bazel-9";
  bazel-bootstrap = mkBazelProbe "bazel-bootstrap";

  cargo-nextest = mkCliProbe {
    package = "cargo-nextest";
    primaryInput = "The packaged nextest runner's release identity.";
    primaryOperation = "Request its version without reading a Cargo workspace.";
    primaryExpected = "Cargo-nextest returns success and identifies its executable.";
    primaryCommand = ''["@out@/bin/cargo-nextest", "--version"]'';
    primaryCheck = ''result.returncode == 0 and "cargo-nextest" in (result.stdout + result.stderr)'';
    badInput = "A cargo-nextest invocation naming an unknown operation.";
    badOperation = "Parse the unknown operation without reading a workspace.";
    badExpected = "Cargo-nextest rejects the unsupported operation.";
    badCommand = ''["@out@/bin/cargo-nextest", "aos-invalid-operation"]'';
  };

  cilium = mkCliProbe {
    package = "cilium";
    primaryInput = "The packaged Cilium debugging client's version command.";
    primaryOperation = "Print local version information without contacting an agent.";
    primaryExpected = "The client returns success and identifies Cilium.";
    primaryCommand = ''["@out@/bin/cilium-dbg", "version"]'';
    primaryCheck = ''result.returncode == 0 and "cilium" in (result.stdout + result.stderr).lower()'';
    badInput = "A cilium-dbg invocation naming an unknown operation.";
    badOperation = "Parse the unsupported operation without contacting an agent.";
    badExpected = "The client rejects the unsupported operation.";
    badCommand = ''["@out@/bin/cilium-dbg", "aos-invalid-operation"]'';
  };

  conntrack-tools = mkCliProbe {
    package = "conntrack-tools";
    primaryInput = "The packaged connection-tracking client's release identity.";
    primaryOperation = "Request its version without opening a netfilter socket.";
    primaryExpected = "Conntrack returns success and reports its userspace version.";
    primaryCommand = ''
      [str(next(path for path in __import__("pathlib").Path("@out@").rglob("conntrack") if path.is_file())), "--version"]
    '';
    primaryCheck = ''result.returncode == 0 and "conntrack" in (result.stdout + result.stderr).lower()'';
    badInput = "A conntrack invocation containing an unknown option.";
    badOperation = "Parse the invalid option without modifying kernel state.";
    badExpected = "Conntrack rejects the unsupported option.";
    badCommand = ''
      [str(next(path for path in __import__("pathlib").Path("@out@").rglob("conntrack") if path.is_file())), "--aos-invalid-option"]
    '';
  };

  containerd = mkCliProbe {
    package = "containerd";
    primaryInput = "The packaged containerd daemon's release identity.";
    primaryOperation = "Request its version without starting the daemon.";
    primaryExpected = "Containerd returns success and reports its packaged version.";
    primaryCommand = ''["@out@/bin/containerd", "--version"]'';
    primaryCheck = ''result.returncode == 0 and "containerd" in (result.stdout + result.stderr).lower()'';
    badInput = "A containerd invocation containing an unknown global option.";
    badOperation = "Parse the invalid option before daemon initialization.";
    badExpected = "Containerd rejects the unsupported option.";
    badCommand = ''["@out@/bin/containerd", "--aos-invalid-option"]'';
  };

  crucible-controller = mkHelpProbe {
    package = "crucible-controller";
    executable = "crucible";
    helpNeedle = "Usage";
  };

  crucible-fleet-store = mkCliProbe {
    package = "crucible-fleet-store";
    primaryInput = "An empty local directory for a deterministic shared DAG-store probe.";
    primaryOperation = "Run the fleet-store's built-in backend probe.";
    primaryExpected = "The probe reports the SharedDagStore backend and location-independent identity.";
    primaryCommand = ''["@out@/bin/crucible-fleet-store", "probe", "fleet-store"]'';
    primaryCheck = ''result.returncode == 0 and "backend=SharedDagStore" in result.stdout and "location_independent_identity=true" in result.stdout'';
    badInput = "A fleet-store invocation naming an unknown operation.";
    badOperation = "Parse the unsupported operation before opening a store.";
    badExpected = "The fleet-store rejects the unsupported operation.";
    badCommand = ''["@out@/bin/crucible-fleet-store", "aos-invalid-operation"]'';
  };

  crucible-guest = mkHelpProbe {
    package = "crucible-guest";
    helpNeedle = "verbs:";
    badArguments = ["aos-invalid-verb"];
  };

  docker = mkCliProbe {
    package = "docker";
    primaryInput = "The packaged Docker client's release identity.";
    primaryOperation = "Request its version without contacting a daemon.";
    primaryExpected = "The Docker client returns success and reports its version.";
    primaryCommand = ''["@out@/bin/docker", "--version"]'';
    primaryCheck = ''result.returncode == 0 and "Docker version" in (result.stdout + result.stderr)'';
    badInput = "A Docker invocation containing an unknown global option.";
    badOperation = "Parse the invalid option before contacting a daemon.";
    badExpected = "The Docker client rejects the unsupported option.";
    badCommand = ''["@out@/bin/docker", "--aos-invalid-option"]'';
  };

  delve = mkCliProbe {
    package = "delve";
    primaryInput = "The packaged Delve debugger's release identity.";
    primaryOperation = "Request its version without attaching to a process.";
    primaryExpected = "Delve returns success and identifies its debugger version.";
    primaryCommand = ''["@out@/bin/dlv", "version"]'';
    primaryCheck = ''result.returncode == 0 and "Delve Debugger" in (result.stdout + result.stderr)'';
    badInput = "A Delve invocation naming an unknown command.";
    badOperation = "Parse the unsupported command without attaching to a process.";
    badExpected = "Delve rejects the unsupported command.";
    badCommand = ''["@out@/bin/dlv", "aos-invalid-command"]'';
  };

  firecracker = mkCliProbe {
    package = "firecracker";
    primaryInput = "The packaged Firecracker monitor's release identity.";
    primaryOperation = "Request its version without creating a virtual machine.";
    primaryExpected = "Firecracker returns success and reports its version.";
    primaryCommand = ''["@out@/bin/firecracker", "--version"]'';
    primaryCheck = ''result.returncode == 0 and "Firecracker" in (result.stdout + result.stderr)'';
    badInput = "A Firecracker invocation containing an unknown option.";
    badOperation = "Parse the invalid option before opening the API socket.";
    badExpected = "Firecracker rejects the unsupported option.";
    badCommand = ''["@out@/bin/firecracker", "--aos-invalid-option"]'';
  };

  fuse-overlayfs = mkCliProbe {
    package = "fuse-overlayfs";
    primaryInput = "The packaged fuse-overlayfs implementation's release identity.";
    primaryOperation = "Request its version without mounting a filesystem.";
    primaryExpected = "Fuse-overlayfs returns success and reports its version.";
    primaryCommand = ''["@out@/bin/fuse-overlayfs", "--version"]'';
    primaryCheck = ''result.returncode == 0 and "fuse-overlayfs" in (result.stdout + result.stderr).lower()'';
    badInput = "A fuse-overlayfs invocation containing an unknown option.";
    badOperation = "Parse the invalid option without mounting a filesystem.";
    badExpected = "Fuse-overlayfs rejects the unsupported option.";
    badCommand = ''["@out@/bin/fuse-overlayfs", "--aos-invalid-option"]'';
  };
}
