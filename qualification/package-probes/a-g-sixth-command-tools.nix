##! Exercises sixth-slice A-G commands through deterministic offline paths.
{testing}: let
  mkPythonCommandProbe = {
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
in {
  aos-selinux-run = mkPythonCommandProbe {
    package = "aos-selinux-run";
    primaryInput = "A request for the SELinux transition wrapper's command contract.";
    primaryOperation = "Invoke its help path without attempting a security transition.";
    primaryExpected = "The wrapper returns success and describes the required context and command boundary.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/aos-selinux-run", "--help"], capture_output=True, text=True)
      assert result.returncode == 0
      assert result.stdout == "usage: aos-selinux-run --context CONTEXT -- COMMAND [ARG...]\n"
      print("aos-selinux-run operation passed")
    '';
    badInput = "A transition request with a context but no command after the separator.";
    badOperation = "Parse the incomplete transition request.";
    badExpected = "The wrapper rejects the request before touching the SELinux process attribute.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/aos-selinux-run", "--context", "aos_test_t", "--"], capture_output=True, text=True)
      assert result.returncode == 2 and "missing command after --" in result.stderr
      sys.stderr.write("aos-selinux-run rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  composefs = mkPythonCommandProbe {
    package = "composefs";
    primaryInput = "A source directory containing one fixed regular file.";
    primaryOperation = "Build a composefs image and inspect its metadata with composefs-info.";
    primaryExpected = "Mkcomposefs creates a nonempty image that composefs-info accepts.";
    primaryFiles."source/answer.txt" = "qualified\n";
    primaryScript = ''
      import pathlib, subprocess
      build = subprocess.run(["@out@/bin/mkcomposefs", "source", "image.cfs"], capture_output=True)
      assert build.returncode == 0, build.stderr
      assert pathlib.Path("image.cfs").stat().st_size > 0
      inspect = subprocess.run(["@out@/bin/composefs-info", "image.cfs"], capture_output=True)
      assert inspect.returncode == 0, inspect.stderr
      print("composefs operation passed")
    '';
    badInput = "A source-directory path that does not exist.";
    badOperation = "Attempt to build a composefs image from the missing tree.";
    badExpected = "Mkcomposefs rejects the missing source path.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/mkcomposefs", "absent", "invalid.cfs"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("composefs rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  crictl = mkPythonCommandProbe {
    package = "crictl";
    primaryInput = "A local crictl configuration naming a Unix CRI endpoint.";
    primaryOperation = "Load and print the configuration without contacting the endpoint.";
    primaryExpected = "Crictl accepts the schema and reports the configured runtime endpoint.";
    primaryFiles."crictl.yaml" = ''
      runtime-endpoint: unix:///run/containerd/containerd.sock
      image-endpoint: unix:///run/containerd/containerd.sock
      timeout: 10
      debug: false
      pull-image-on-create: false
      disable-pull-on-run: false
    '';
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/crictl", "--config", "crictl.yaml", "config"], capture_output=True, text=True)
      assert result.returncode == 0, result.stderr
      assert "runtime-endpoint: unix:///run/containerd/containerd.sock" in result.stdout
      print("crictl operation passed")
    '';
    badInput = "A crictl configuration containing an unterminated sequence.";
    badOperation = "Load the malformed configuration.";
    badExpected = "Crictl rejects the malformed YAML before contacting a runtime.";
    badFiles."crictl.yaml" = "runtime-endpoint: [unterminated\n";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/crictl", "--config", "crictl.yaml", "config"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("crictl rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  dmidecode = mkPythonCommandProbe {
    package = "dmidecode";
    primaryInput = "The packaged SMBIOS decoder executable.";
    primaryOperation = "Request its format-aware decoder version.";
    primaryExpected = "Dmidecode reports version 3.7 without accessing host firmware tables.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/sbin/dmidecode", "--version"], capture_output=True, text=True)
      assert result.returncode == 0 and result.stdout == "3.7\n"
      print("dmidecode operation passed")
    '';
    badInput = "A file that is not a valid dmidecode binary dump.";
    badOperation = "Decode the malformed dump through the from-dump path.";
    badExpected = "Dmidecode rejects the truncated binary input.";
    badFiles."invalid.dump" = "not an SMBIOS dump\n";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/sbin/dmidecode", "--from-dump", "invalid.dump"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("dmidecode rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  dnsutils = mkPythonCommandProbe {
    package = "dnsutils";
    primaryInput = "The packaged DNS query client.";
    primaryOperation = "Request dig's linked BIND version without performing a DNS query.";
    primaryExpected = "Dig identifies its BIND implementation and returns success.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/dig", "-v"], capture_output=True, text=True)
      assert result.returncode == 0 and "DiG" in result.stdout and "9.20" in result.stdout
      print("dnsutils operation passed")
    '';
    badInput = "A DNS server port outside the valid unsigned 16-bit range.";
    badOperation = "Parse the invalid port for an otherwise offline query request.";
    badExpected = "Dig rejects the invalid port before attempting network I/O.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/dig", "-p", "not-a-port", "example.test"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("dnsutils rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  docker-engine = mkPythonCommandProbe {
    package = "docker-engine";
    primaryInput = "A daemon configuration selecting fixed local state directories.";
    primaryOperation = "Validate the configuration without starting the daemon.";
    primaryExpected = "Dockerd accepts the complete JSON configuration and exits after validation.";
    primaryFiles."daemon.json" = ''
      {
        "data-root": "/var/lib/aos-qualification-docker",
        "exec-root": "/run/aos-qualification-docker",
        "debug": false
      }
    '';
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/dockerd", "--validate", "--config-file", "daemon.json"], capture_output=True, text=True)
      assert result.returncode == 0, result.stderr
      assert "configuration OK" in result.stdout
      print("docker-engine operation passed")
    '';
    badInput = "A daemon configuration containing an unknown directive.";
    badOperation = "Validate the malformed configuration without starting the daemon.";
    badExpected = "Dockerd rejects the unknown directive.";
    badFiles."daemon.json" = "{\"aos-unknown-setting\": true}\n";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/dockerd", "--validate", "--config-file", "daemon.json"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("docker-engine rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  etcd = mkPythonCommandProbe {
    package = "etcd";
    primaryInput = "The packaged etcd server and data-file utility suite.";
    primaryOperation = "Request the server's version and confirm its semantic version.";
    primaryExpected = "Etcd reports version 3.7.1 without opening a listener.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/etcd", "--version"], capture_output=True, text=True)
      assert result.returncode == 0 and "etcd Version: 3.7.1" in result.stdout
      print("etcd operation passed")
    '';
    badInput = "A path that is not an etcd snapshot database.";
    badOperation = "Inspect the malformed path with etcdutl snapshot status.";
    badExpected = "Etcdutl rejects the nonexistent snapshot.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/etcdutl", "snapshot", "status", "absent.db"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("etcd rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  getent = mkPythonCommandProbe {
    package = "getent";
    primaryInput = "The TCP protocol key in the files-backed protocols database.";
    primaryOperation = "Resolve the key through getent with the files service selected explicitly.";
    primaryExpected = "Getent returns the protocol number 6 record for TCP.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/getent", "--service=files", "protocols", "tcp"], capture_output=True, text=True)
      assert result.returncode == 0, result.stderr
      fields = result.stdout.split()
      assert fields[0] == "tcp" and fields[1] == "6"
      print("getent operation passed")
    '';
    badInput = "A database name that getent does not support.";
    badOperation = "Resolve a key through the unknown database.";
    badExpected = "Getent rejects the unknown database name.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/getent", "aos-unknown-database", "key"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("getent rejected invalid input\n")
      raise SystemExit(7)
    '';
  };
}
