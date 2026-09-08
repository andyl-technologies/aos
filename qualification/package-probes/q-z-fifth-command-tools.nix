##! Exercises fifth-slice Q-through-Z command-line tools offline.
{testing}: let
  mkCommandProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badScript,
    primaryFiles ? {},
    badFiles ? {},
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
          files = primaryFiles;
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
          files = badFiles;
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

  workerdProbe = package:
    mkCommandProbe {
      inherit package;
      primaryInput = "The installed workerd runtime build identity.";
      primaryOperation = "Read the runtime version without starting a service or opening a network socket.";
      primaryExpected = "Workerd reports its pinned 2024-09-09 release identity.";
      primaryScript = ''
        import subprocess
        result = subprocess.run(["@out@/bin/workerd", "--version"], capture_output=True, text=True)
        assert result.returncode == 0 and result.stdout.strip() == "workerd 2024-09-09"
        print("${package} operation passed")
      '';
      badInput = "A service configuration containing bytes that are not valid Cap'n Proto source.";
      badOperation = "Parse the malformed configuration before starting the runtime.";
      badExpected = "Workerd rejects the malformed configuration with a parse error.";
      badFiles."invalid.capnp" = "this is not capnp\n";
      badScript = reject package ''
        import subprocess
        result = subprocess.run(["@out@/bin/workerd", "serve", "invalid.capnp"], capture_output=True, text=True)
        output = result.stdout + result.stderr
        assert result.returncode != 0 and ("error" in output.lower() or "failed" in output.lower())
      '';
    };
in {
  tmux = mkCommandProbe {
    package = "tmux";
    primaryInput = "A detached session named qualification with a fixed status-left value.";
    primaryOperation = "Create the session on an isolated socket, set the option, read it back, and stop the server.";
    primaryExpected = "Tmux preserves and reports the exact session option value.";
    primaryScript = ''
      import json, os, pathlib, subprocess
      environment = os.environ.copy()
      environment["TMUX_TMPDIR"] = str(pathlib.Path("socket-dir").resolve())
      closure = json.loads(environment["AOS_QUALIFICATION_PACKAGE_CLOSURE"])
      locale = next(path for path in closure if "-glibc-locales-" in path)
      environment["LOCPATH"] = str(pathlib.Path(locale) / "lib/locale")
      environment["LC_ALL"] = "C.UTF-8"
      pathlib.Path(environment["TMUX_TMPDIR"]).mkdir()
      command = ["@out@/bin/tmux", "-L", "qualification"]
      try:
          created = subprocess.run(command + ["new-session", "-d", "-s", "qualification"], env=environment, capture_output=True)
          assert created.returncode == 0, created.stderr
          assert subprocess.run(command + ["set-option", "-t", "qualification", "status-left", "qualified"], env=environment).returncode == 0
          shown = subprocess.run(command + ["show-option", "-v", "-t", "qualification", "status-left"], env=environment, capture_output=True, text=True)
          assert shown.returncode == 0 and shown.stdout == "qualified\n"
      finally:
          subprocess.run(command + ["kill-server"], env=environment, capture_output=True)
      print("tmux operation passed")
    '';
    badInput = "A tmux command name outside the command table.";
    badOperation = "Dispatch the unsupported command on an isolated socket.";
    badExpected = "Tmux rejects the unknown command before creating a server.";
    badScript = reject "tmux" ''
      import json, os, pathlib, subprocess
      environment = os.environ.copy()
      closure = json.loads(environment["AOS_QUALIFICATION_PACKAGE_CLOSURE"])
      locale = next(path for path in closure if "-glibc-locales-" in path)
      environment["LOCPATH"] = str(pathlib.Path(locale) / "lib/locale")
      environment["LC_ALL"] = "C.UTF-8"
      result = subprocess.run(["@out@/bin/tmux", "qualification-invalid-command"], env=environment, capture_output=True, text=True)
      assert result.returncode != 0 and "unknown command" in result.stderr
    '';
  };

  worker-build = mkCommandProbe {
    package = "worker-build";
    primaryInput = "A request for the worker build command's offline option contract.";
    primaryOperation = "Render the command help before inspecting or building a Rust project.";
    primaryExpected = "Worker-build documents its build mode, target, output-directory, and TypeScript controls.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/worker-build", "--no-typescript", "--help"], capture_output=True, text=True)
      output = result.stdout + result.stderr
      assert "Usage:" in output and "--mode" in output and "--target" in output and "--out-dir" in output
      print("worker-build operation passed")
    '';
    badInput = "A build mode outside worker-build's supported no-install, normal, and force values.";
    badOperation = "Validate the mode selector before resolving project dependencies.";
    badExpected = "Worker-build rejects the unsupported mode value.";
    badScript = reject "worker-build" ''
      import subprocess
      result = subprocess.run(["@out@/bin/worker-build", "--mode", "qualification-invalid"], capture_output=True, text=True)
      assert result.returncode != 0 and "invalid value" in result.stderr.lower()
    '';
  };

  workerd = workerdProbe "workerd";
  workerd-source = workerdProbe "workerd-source";

  zfs = mkCommandProbe {
    package = "zfs";
    primaryInput = "The fixed host identifier 0x12345678 and a work-directory output path.";
    primaryOperation = "Encode the host identifier with zgenhostid without loading a kernel module.";
    primaryExpected = "Zgenhostid writes the identifier as the four native-order bytes 78 56 34 12.";
    primaryScript = ''
      import pathlib, subprocess
      output = pathlib.Path("hostid")
      result = subprocess.run(["@out@/sbin/zgenhostid", "-f", "-o", str(output), "12345678"], capture_output=True)
      assert result.returncode == 0 and output.read_bytes() == bytes.fromhex("78563412")
      print("zfs operation passed")
    '';
    badInput = "A host identifier containing non-hexadecimal characters.";
    badOperation = "Validate the identifier before writing the hostid file.";
    badExpected = "Zgenhostid rejects the malformed identifier and creates no output.";
    badScript = reject "zfs" ''
      import pathlib, subprocess
      output = pathlib.Path("invalid-hostid")
      result = subprocess.run(["@out@/sbin/zgenhostid", "-o", str(output), "not-hex"], capture_output=True, text=True)
      assert result.returncode != 0 and not output.exists()
    '';
  };

  zfstools = mkCommandProbe {
    package = "zfstools";
    primaryInput = "An invocation without a snapshot interval or retention count.";
    primaryOperation = "Request the zfs-auto-snapshot usage contract without accessing a pool.";
    primaryExpected = "Zfs-auto-snapshot prints its interval, retention, dry-run, pool, and UTC controls.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/zfs-auto-snapshot"], capture_output=True, text=True)
      assert result.returncode == 0 and result.stdout.startswith("Usage:") and "INTERVAL" in result.stdout and "KEEP" in result.stdout
      print("zfstools operation passed")
    '';
    badInput = "An option outside zfs-auto-snapshot's supported switch set.";
    badOperation = "Parse the unsupported option before accessing any ZFS pool.";
    badExpected = "Zfs-auto-snapshot rejects the unknown option.";
    badScript = reject "zfstools" ''
      import subprocess
      result = subprocess.run(["@out@/bin/zfs-auto-snapshot", "--qualification-invalid"], capture_output=True, text=True)
      assert result.returncode != 0 and "unrecognized option" in result.stderr
    '';
  };
}
