##! Exercises seventh-slice A-G commands through deterministic offline paths.
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

  reject = package: command: assertion: ''
    import subprocess, sys
    result = subprocess.run(${command}, capture_output=True, text=True)
    assert ${assertion}, (result.returncode, result.stdout, result.stderr)
    sys.stderr.write("${package} rejected invalid input\n")
    raise SystemExit(7)
  '';
in {
  aos-agent-rpc = mkCommandProbe {
    package = "aos-agent-rpc";
    primaryInput = "A local Unix socket server and a fixed command frame.";
    primaryOperation = "Exchange a length-prefixed request and JSON response with the RPC client.";
    primaryExpected = "The client sends the exact command and prints the server's framed JSON response.";
    primaryScript = ''
      import json, pathlib, socket, subprocess, threading
      path = str(pathlib.Path("agent.sock").resolve())
      server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      server.bind(path)
      server.listen(1)
      observed = []
      def serve():
          connection, _ = server.accept()
          with connection:
              length = b""
              while not length.endswith(b"\n"):
                  length += connection.recv(1)
              body = connection.recv(int(length))
              observed.append(body)
              response = b'{"exit_code":0,"stdout":"cXVhbGlmaWVkXG4=","stderr":""}'
              connection.sendall(str(len(response)).encode() + b"\n" + response)
      thread = threading.Thread(target=serve)
      thread.start()
      result = subprocess.run(["@out@/bin/aos-agent-rpc", "--driver", "qemu", path, "printf qualified"], capture_output=True, text=True)
      thread.join()
      server.close()
      assert result.returncode == 0 and json.loads(result.stdout)["exit_code"] == 0
      assert observed == [b"printf qualified"]
      print("aos-agent-rpc operation passed")
    '';
    badInput = "An RPC request naming an unsupported transport driver.";
    badOperation = "Parse the invalid driver before opening a socket.";
    badExpected = "The client rejects the unsupported driver with its command-line error status.";
    badScript = reject "aos-agent-rpc" ''["@out@/bin/aos-agent-rpc", "--driver", "invalid", "agent.sock", "true"]'' ''result.returncode == 2 and "unknown driver" in result.stderr'';
  };

  aos-boot-identity = mkCommandProbe {
    package = "aos-boot-identity";
    primaryInput = "A normal-boot command line with a matching root hash and root-a verity devices.";
    primaryOperation = "Validate the command line through the packaged boot-identity parser.";
    primaryExpected = "The parser accepts the complete fail-closed normal-boot identity.";
    primaryFiles."cmdline" = "root=/dev/mapper/root roothash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef systemd.verity_root_data=/dev/disk/by-partlabel/root-a systemd.verity_root_hash=/dev/disk/by-partlabel/root-a-hash systemd.verity=yes rd.luks=0\n";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/aos-boot-identity", "cmdline"], capture_output=True)
      assert result.returncode == 0, result.stderr
      print("aos-boot-identity operation passed")
    '';
    badInput = "A normal-boot command line whose hash device belongs to the other slot.";
    badOperation = "Validate the inconsistent slot identity.";
    badExpected = "The parser rejects the mismatched data and hash devices.";
    badFiles."cmdline" = "root=/dev/mapper/root roothash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef systemd.verity_root_data=/dev/disk/by-partlabel/root-a systemd.verity_root_hash=/dev/disk/by-partlabel/root-b-hash systemd.verity=yes rd.luks=0\n";
    badScript = reject "aos-boot-identity" ''["@out@/bin/aos-boot-identity", "cmdline"]'' ''result.returncode == 1 and "rejected normal boot" in result.stderr'';
  };

  aos-ebpf-lsm-policy = mkCommandProbe {
    package = "aos-ebpf-lsm-policy";
    primaryInput = "The packaged task-audit policy and matching BPF object.";
    primaryOperation = "Validate the policy-object pair without loading it into the kernel.";
    primaryExpected = "The loader accepts the packaged JSON schema and BPF object metadata.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/aos-ebpf-lsm-policy", "validate", "--policy", "@out@/share/aos/ebpf-lsm/aos-task-audit.json", "--object", "@out@/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"], capture_output=True)
      assert result.returncode == 0, result.stderr
      print("aos-ebpf-lsm-policy operation passed")
    '';
    badInput = "A truncated JSON policy paired with the packaged BPF object.";
    badOperation = "Validate the malformed policy.";
    badExpected = "The loader rejects the malformed JSON before kernel attachment.";
    badFiles."policy.json" = "{\"version\":\n";
    badScript = reject "aos-ebpf-lsm-policy" ''["@out@/bin/aos-ebpf-lsm-policy", "validate", "--policy", "policy.json", "--object", "@out@/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"]'' ''result.returncode != 0'';
  };

  aos-ebpf-net-policy = mkCommandProbe {
    package = "aos-ebpf-net-policy";
    primaryInput = "A version-one private TCP policy and the packaged cgroup BPF object.";
    primaryOperation = "Validate the policy-object pair without attaching it to a cgroup.";
    primaryExpected = "The loader accepts the complete policy and expected BPF maps.";
    primaryFiles."policy.json" = ''
      {"version":1,"package":"sample","mode":"private","securityLabel":"aos-pkg-sample","tcp":{"bind":[8000],"connect":[443]},"fs":{"readOnly":[],"readWrite":[]},"landlock":{"abi":4,"tcp":{"bind":[8000],"connect":[443]},"fs":{"readOnly":[],"readWrite":[]}},"ebpf":{"identity":"aos-pkg-sample","hooks":["socket_bind","socket_connect"],"tcp":{"bind":[8000],"connect":[443]}}}
    '';
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/aos-ebpf-net-policy", "validate", "--policy", "policy.json", "--object", "@out@/lib/bpf/aos-ebpf-net-policy.bpf.o"], capture_output=True)
      assert result.returncode == 0, result.stderr
      print("aos-ebpf-net-policy operation passed")
    '';
    badInput = "A policy with a TCP port outside the unsigned 16-bit range.";
    badOperation = "Validate the out-of-range network policy.";
    badExpected = "The loader rejects the invalid port before kernel attachment.";
    badFiles."policy.json" = "{\"version\":1,\"package\":\"sample\",\"mode\":\"private\",\"securityLabel\":\"aos-pkg-sample\",\"tcp\":{\"bind\":[70000],\"connect\":[]}}\n";
    badScript = reject "aos-ebpf-net-policy" ''["@out@/bin/aos-ebpf-net-policy", "validate", "--policy", "policy.json", "--object", "@out@/lib/bpf/aos-ebpf-net-policy.bpf.o"]'' ''result.returncode != 0'';
  };

  aos-landlock = mkCommandProbe {
    package = "aos-landlock";
    primaryInput = "The Landlock wrapper's command-line interface.";
    primaryOperation = "Request its help without creating a kernel ruleset.";
    primaryExpected = "The wrapper returns success and documents its filesystem and network policy options.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/aos-landlock", "--help"], capture_output=True, text=True)
      assert result.returncode == 0 and "--fs-ro" in result.stdout and "--tcp-connect" in result.stdout
      print("aos-landlock operation passed")
    '';
    badInput = "A request combining unrestricted networking with a restricted TCP bind port.";
    badOperation = "Parse the contradictory network policy.";
    badExpected = "The wrapper rejects mutually incompatible network options before execution.";
    badScript = reject "aos-landlock" ''["@out@/bin/aos-landlock", "--network-unrestricted", "--tcp-bind", "8080", "--", "@bash@", "-c", "exit 0"]'' ''result.returncode != 0'';
  };

  aos-registry-server = mkCommandProbe {
    package = "aos-registry-server";
    primaryInput = "An empty writable AOS root for the registry cache database.";
    primaryOperation = "Initialize the SQLite database and inspect its schema.";
    primaryExpected = "The initializer creates the ValidPaths and Refs tables under the requested root.";
    primaryScript = ''
      import os, pathlib, sqlite3, subprocess
      root = pathlib.Path("registry-root").resolve()
      environment = os.environ.copy()
      environment["AOS_ROOT"] = str(root)
      result = subprocess.run(["@out@/bin/aos-registry-server-init-db"], env=environment, capture_output=True)
      assert result.returncode == 0, result.stderr
      database = root / "var/nix/db/db.sqlite"
      with sqlite3.connect(database) as connection:
          tables = {row[0] for row in connection.execute("select name from sqlite_master where type='table'")}
      assert {"ValidPaths", "Refs"} <= tables
      print("aos-registry-server operation passed")
    '';
    badInput = "An AOS_ROOT path whose parent is a regular file.";
    badOperation = "Attempt to initialize a database below that invalid root.";
    badExpected = "The initializer rejects the non-directory root and creates no database.";
    badScript = ''
      import os, pathlib, subprocess, sys
      pathlib.Path("blocked").write_text("file")
      environment = os.environ.copy()
      environment["AOS_ROOT"] = str(pathlib.Path("blocked/child").resolve())
      result = subprocess.run(["@out@/bin/aos-registry-server-init-db"], env=environment, capture_output=True)
      assert result.returncode != 0
      sys.stderr.write("aos-registry-server rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  aos-service-root = mkCommandProbe {
    package = "aos-service-root";
    primaryInput = "A cleanup request for a unique package with a canonical immutable payload.";
    primaryOperation = "Run the idempotent cleanup path when no overlay root exists.";
    primaryExpected = "The helper accepts the tokens and reports successful no-op cleanup.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/aos-service-root", "cleanup", "qualification-seventh", "@out@", "probe.service"], capture_output=True)
      assert result.returncode == 0, result.stderr
      print("aos-service-root operation passed")
    '';
    badInput = "A cleanup request containing a package token with a slash.";
    badOperation = "Validate the unsafe package token.";
    badExpected = "The helper rejects the token before accessing overlay state.";
    badScript = reject "aos-service-root" ''["@out@/bin/aos-service-root", "cleanup", "bad/package", "@out@", "probe.service"]'' ''result.returncode == 1 and "invalid package token" in result.stderr'';
  };

  aos-test-driver = mkCommandProbe {
    package = "aos-test-driver";
    primaryInput = "The test driver's command-line interface.";
    primaryOperation = "Request its help without booting a virtual machine.";
    primaryExpected = "The driver returns success and documents manifest and test inputs.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/aos-test-driver", "--help"], capture_output=True, text=True)
      assert result.returncode == 0 and "--manifest" in result.stdout and "--test" in result.stdout
      print("aos-test-driver operation passed")
    '';
    badInput = "A driver invocation without its required manifest and test paths.";
    badOperation = "Parse the incomplete invocation.";
    badExpected = "The driver rejects the missing required arguments before VM startup.";
    badScript = reject "aos-test-driver" ''["@out@/bin/aos-test-driver"]'' ''result.returncode != 0 and "required" in result.stderr'';
  };

  aos-var-policy-migrate = mkCommandProbe {
    package = "aos-var-policy-migrate";
    primaryInput = "The installed TPM policy migration script.";
    primaryOperation = "Parse the complete script with its packaged Bash interpreter.";
    primaryExpected = "Bash accepts the installed migration program's syntax.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@bash@", "-n", "@out@/bin/aos-var-policy-migrate"], capture_output=True)
      assert result.returncode == 0, result.stderr
      print("aos-var-policy-migrate operation passed")
    '';
    badInput = "A migration invocation without the five required arguments.";
    badOperation = "Validate the incomplete request.";
    badExpected = "The script rejects the request with its usage status before touching a TPM.";
    badScript = reject "aos-var-policy-migrate" ''["@out@/bin/aos-var-policy-migrate"]'' ''result.returncode == 2 and "usage:" in result.stderr'';
  };

  aos-verity-root-guard = mkCommandProbe {
    package = "aos-verity-root-guard";
    primaryInput = "The installed dm-verity root guard script.";
    primaryOperation = "Parse the complete guard with its packaged Bash interpreter.";
    primaryExpected = "Bash accepts the installed root-verification program's syntax.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@bash@", "-n", "@out@/bin/aos-verity-root-guard"], capture_output=True)
      assert result.returncode == 0, result.stderr
      print("aos-verity-root-guard operation passed")
    '';
    badInput = "A guard invocation without the required root hash and signature.";
    badOperation = "Validate the incomplete request.";
    badExpected = "The script rejects the request before inspecting the mounted root.";
    badScript = reject "aos-verity-root-guard" ''["@out@/bin/aos-verity-root-guard"]'' ''result.returncode != 0 and "missing expected dm-verity root hash" in result.stderr'';
  };

  aos-vm = mkCommandProbe {
    package = "aos-vm";
    primaryInput = "The host VM wrapper's command-line interface.";
    primaryOperation = "Request VM subcommand help without starting an emulator.";
    primaryExpected = "The wrapper returns success and describes its VM operations.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/aos", "vm", "--help"], capture_output=True, text=True)
      assert result.returncode == 0 and "Usage" in result.stdout
      print("aos-vm operation passed")
    '';
    badInput = "A VM wrapper invocation containing an unknown operation.";
    badOperation = "Parse the unknown operation.";
    badExpected = "The wrapper rejects the operation before starting QEMU.";
    badScript = reject "aos-vm" ''["@out@/bin/aos", "vm", "not-an-operation"]'' ''result.returncode != 0'';
  };

  cargo-hakari = mkCommandProbe {
    package = "cargo-hakari";
    primaryInput = "The cargo-hakari command-line interface.";
    primaryOperation = "Request its offline help text.";
    primaryExpected = "Cargo-hakari returns success and lists workspace-hack operations.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/cargo-hakari", "--help"], capture_output=True, text=True)
      assert result.returncode == 0 and "workspace-hack" in result.stdout
      print("cargo-hakari operation passed")
    '';
    badInput = "A cargo-hakari invocation naming an unknown operation.";
    badOperation = "Parse the unknown operation.";
    badExpected = "Cargo-hakari rejects the operation without reading a workspace.";
    badScript = reject "cargo-hakari" ''["@out@/bin/cargo-hakari", "not-an-operation"]'' ''result.returncode != 0'';
  };
}
